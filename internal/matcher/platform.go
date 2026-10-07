package matcher

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
	"offline-vulndb/internal/version"
)

// Platform is an operating system a host is known to run (e.g. from the
// Windows build assessment). It decides NVD "running on" conditions: an AND
// configuration whose other node lists the platforms the vulnerable software
// is affected on.
type Platform struct {
	Name       string    // e.g. "Windows Server 2022"
	Family     string    // "windows"
	Identities []cpe.CPE // the OS's NVD identities, e.g. windows_server_2022:- and the generic windows:-
}

// inFamily reports whether an OS criteria belongs to the platform's family.
func (p Platform) inFamily(c cpe.CPE) bool {
	return p.Family == "windows" && c.Part == "o" && c.Vendor == "microsoft" && strings.HasPrefix(c.Product, "windows")
}

type platformOutcome int

const (
	platformUnknown  platformOutcome = iota
	platformMet                      // a platform node lists the host's OS
	platformExcluded                 // the platform nodes list only other operating systems
)

// nodeVerdict is the outcome of one platform node for one host platform.
type nodeVerdict struct {
	outcome platformOutcome
	matched string   // criteria that matched the host
	others  []string // operating systems listed instead (vendor:product)
	family  []string // releases of the host's family listed instead (e.g. windows_7)
}

// ApplyPlatform returns a copy of res in which CONDITIONAL vulnerabilities
// are decided against the host's platform, where their only unevaluated
// condition is the platform node of an AND configuration:
//
//   - the node lists the host's OS (or its family generically, e.g.
//     microsoft:windows:-): the CVE applies unconditionally;
//   - every node lists only other operating systems (e.g. Linux, macOS): the
//     CVE does not apply on this host (PLATFORM_EXCLUDED, kept in the result
//     but not counted as a match);
//   - otherwise it stays CONDITIONAL. In particular, a node that lists other
//     releases of the host's family (Windows 7, 8.1) does not exclude the
//     CVE: NVD's platform lists often predate newer releases.
//
// Several platforms (an ambiguous build) must all agree. res is not
// modified; it may be shared between hosts.
func (e *Engine) ApplyPlatform(ctx context.Context, res *Result, platforms []Platform) (*Result, error) {
	if res == nil || len(platforms) == 0 {
		return res, nil
	}
	byCVE := map[string][]RuleEvaluation{}
	var ruleIDs []int64
	for _, v := range res.Vulnerabilities {
		if v.Applicability == Conditional {
			byCVE[v.CVE] = nil
		}
	}
	if len(byCVE) == 0 {
		return res, nil
	}
	for _, ev := range res.Evaluations {
		if _, ok := byCVE[ev.CVEID]; ok && ev.Status != version.NoMatch {
			byCVE[ev.CVEID] = append(byCVE[ev.CVEID], ev)
			if ev.PlatformCondition {
				ruleIDs = append(ruleIDs, ev.RuleID)
			}
		}
	}
	if len(ruleIDs) == 0 {
		return res, nil
	}
	siblings, err := e.Store.SiblingNodes(ctx, ruleIDs)
	if err != nil {
		return nil, err
	}

	out := *res
	out.Vulnerabilities = slices.Clone(res.Vulnerabilities)
	changed := false
	for i := range out.Vulnerabilities {
		v := &out.Vulnerabilities[i]
		if v.Applicability != Conditional {
			continue
		}
		if decidePlatform(v, byCVE[v.CVE], siblings, platforms) {
			changed = true
		}
	}
	if !changed {
		return res, nil
	}
	out.count()
	sortVulnerabilities(out.Vulnerabilities)
	return &out, nil
}

// decidePlatform updates one CONDITIONAL vulnerability; it reports whether
// anything changed.
func decidePlatform(v *Vulnerability, evs []RuleEvaluation, siblings map[int64][]database.ConfigNode,
	platforms []Platform) bool {
	var chosen []RuleEvaluation
	for _, ev := range evs {
		if ev.Status == v.VersionStatus {
			chosen = append(chosen, ev)
		}
	}
	allExcluded, disagree := len(chosen) > 0, false
	var met, others, family []string
	for _, ev := range chosen {
		nodes, ok := siblings[ev.RuleID]
		if !ev.PlatformCondition || !ok {
			allExcluded = false
			continue
		}
		outcome := platformUnknown
		for i, p := range platforms {
			nv := evalConfig(nodes, p)
			if i == 0 {
				outcome = nv.outcome
			} else if nv.outcome != outcome {
				outcome, disagree = platformUnknown, true // ambiguous host: releases disagree
			}
			others = appendNew(others, nv.others...)
			family = appendNew(family, nv.family...)
			if nv.outcome == platformMet && i == 0 {
				met = append(met, nv.matched)
			}
		}
		switch outcome {
		case platformMet:
			v.Applicability = Unconditional
			v.Platform = fmt.Sprintf("platform condition met: the host runs %s (%s)", platformNames(platforms), met[len(met)-1])
			v.Warnings = slices.DeleteFunc(v.Warnings, func(w string) bool { return strings.HasPrefix(w, "Conditional: ") })
			return true
		case platformExcluded:
		default:
			allExcluded = false
		}
	}
	switch {
	case disagree:
		v.Platform = fmt.Sprintf("the platform condition depends on which release the host runs (%s)", platformNames(platforms))
		return true
	case allExcluded:
		v.Applicability = PlatformExcluded
		v.Platform = fmt.Sprintf("applies only on %s; the host runs %s", strings.Join(others, ", "), platformNames(platforms))
		return true
	case len(family) > 0:
		v.Platform = fmt.Sprintf("NVD lists the platform as %s; the host runs %s, which is not listed (the list may predate it)",
			strings.Join(family, ", "), platformNames(platforms))
		return true
	}
	return false
}

// evalConfig decides the platform nodes of one AND configuration: all must
// hold, and one that cannot hold excludes the configuration.
func evalConfig(nodes []database.ConfigNode, p Platform) nodeVerdict {
	res := nodeVerdict{outcome: platformMet}
	for _, n := range nodes {
		nv := evalNode(n, p)
		res.others = appendNew(res.others, nv.others...)
		res.family = appendNew(res.family, nv.family...)
		switch nv.outcome {
		case platformExcluded:
			res.outcome = platformExcluded
			return res
		case platformUnknown:
			res.outcome = platformUnknown
		case platformMet:
			if res.matched == "" {
				res.matched = nv.matched
			}
		}
	}
	return res
}

// evalNode decides one platform node. Only operating-system rules decide:
// a node naming applications or hardware, a negated node or a second
// vulnerable node stays unknown.
func evalNode(n database.ConfigNode, p Platform) nodeVerdict {
	var res nodeVerdict
	if n.Negate {
		return res
	}
	matched, otherOS := 0, 0
	for _, r := range n.Rules {
		if r.Vulnerable {
			return nodeVerdict{}
		}
		crit, err := cpe.ParsePattern(r.Criteria)
		if err != nil {
			continue
		}
		switch {
		case p.inFamily(crit):
			if matchesAny(crit, r, p.Identities) {
				matched++
				if res.matched == "" {
					res.matched = r.Criteria
				}
			} else {
				res.family = appendNew(res.family, cpe.Unescape(crit.Product)+releaseSuffix(crit))
			}
		case crit.Part == "o":
			otherOS++
			res.others = appendNew(res.others, cpe.Unescape(crit.Vendor)+":"+cpe.Unescape(crit.Product))
		}
	}
	all := len(n.Rules)
	switch {
	case n.Operator == "AND" && all > 0 && matched == all, n.Operator != "AND" && matched > 0:
		res.outcome = platformMet
	case n.Operator == "AND" && otherOS > 0, n.Operator != "AND" && all > 0 && otherOS == all:
		res.outcome = platformExcluded
	}
	return res
}

func matchesAny(crit cpe.CPE, r database.MatchRule, ids []cpe.CPE) bool {
	cmp := version.For(crit.Vendor, crit.Product)
	for _, id := range ids {
		if id.Vendor != crit.Vendor || id.Product != crit.Product {
			continue
		}
		if evaluateParsed(cmp, id, r, crit, nil).Status == version.Match {
			return true
		}
	}
	return false
}

// releaseSuffix names the release in a family criteria, e.g. ":1607" for
// windows_10:1607 (empty for ANY/NA).
func releaseSuffix(c cpe.CPE) string {
	if cpe.IsSpecific(c.Version) {
		return " " + cpe.Unescape(c.Version)
	}
	return ""
}

func platformNames(ps []Platform) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, " or ")
}

func appendNew(list []string, items ...string) []string {
	for _, it := range items {
		if it != "" && !slices.Contains(list, it) {
			list = append(list, it)
		}
	}
	return list
}
