// Package matcher correlates a supplied software identity (currently an
// exact CPE) with candidate vulnerabilities in the local database.
//
// The pipeline is:
//
//	supplied CPE -> candidate rules (indexed by part/vendor/product)
//	             -> per-rule evaluation (attributes + version range)
//	             -> per-CVE aggregation
//	             -> enrichment (CVE details, KEV, exploit evidence)
//	             -> deterministic ordering
//
// A result is a *candidate* vulnerability: the observed product/version
// appears to fall inside an affected range. It is not proof that a target is
// vulnerable.
package matcher

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
	"offline-vulndb/internal/version"
)

// Confidence classifies how certain the software identity is.
type Confidence string

const (
	Exact   Confidence = "EXACT"   // exact CPE with a concrete version was supplied
	High    Confidence = "HIGH"    // deterministic product/version mapping (future)
	Medium  Confidence = "MEDIUM"  // alias/banner mapping with strong evidence (future)
	Low     Confidence = "LOW"     // product only, or ambiguous
	Unknown Confidence = "UNKNOWN" // insufficient evidence
)

// Applicability says whether a matched CVE depends on unevaluated conditions.
type Applicability string

const (
	Unconditional Applicability = "UNCONDITIONAL"
	Conditional   Applicability = "CONDITIONAL"
)

// ErrInsufficientIdentity is returned when the supplied CPE does not name a
// specific product.
var ErrInsufficientIdentity = errors.New("insufficient identity information")

// Warning shown on every result until distro advisory data is supported.
const backportWarning = "Matching is based on upstream product/version data. " +
	"Linux distribution backported security fixes are not evaluated."

// Warning shown for real datasets: since April 2026 NVD adds CPE
// applicability data to only a minority of new CVEs.
const coverageWarning = "NVD provides product (CPE) applicability data for only part of recent CVEs; " +
	"no result does not mean no vulnerability."

// Engine runs queries against an open database.
type Engine struct {
	Store      *database.Store
	Comparator version.Comparator
}

// New returns an Engine using the generic version comparator.
func New(store *database.Store) *Engine {
	return &Engine{Store: store, Comparator: version.Generic{}}
}

// Result is the full outcome of one query.
type Result struct {
	Input              string           `json:"input"`
	NormalizedCPE      string           `json:"normalized_cpe"`
	Part               string           `json:"part"`
	Vendor             string           `json:"vendor"`
	Product            string           `json:"product"`
	Version            string           `json:"version"`
	IdentityConfidence Confidence       `json:"identity_confidence"`
	Comparator         string           `json:"comparator"`
	CandidateRules     int              `json:"candidate_rules"`
	MatchCount         int              `json:"match_count"`
	UnknownCount       int              `json:"unknown_count"`
	Vulnerabilities    []Vulnerability  `json:"vulnerabilities"`
	Warnings           []string         `json:"warnings"`
	Evaluations        []RuleEvaluation `json:"-"` // every rule, for --debug
}

// Vulnerability is one candidate CVE with enrichment and explanation.
type Vulnerability struct {
	CVE             string         `json:"cve"`
	Description     string         `json:"description"`
	CVSS            *float64       `json:"cvss"`
	CVSSVersion     string         `json:"cvss_version,omitempty"`
	CVSSVector      string         `json:"cvss_vector,omitempty"`
	CVSSv3Score     *float64       `json:"cvss_v3_score"`
	CVSSv4Score     *float64       `json:"cvss_v4_score"`
	Severity        string         `json:"severity"`
	CWE             string         `json:"cwe,omitempty"`
	PublishedAt     string         `json:"published_at,omitempty"`
	PublicExploit   bool           `json:"public_exploit"`
	ExploitSources  []string       `json:"exploit_sources"`
	ExploitEvidence []Evidence     `json:"exploit_evidence"`
	KnownExploited  bool           `json:"known_exploited"`
	KnownRansomware bool           `json:"known_ransomware"`
	KEVDateAdded    string         `json:"kev_date_added,omitempty"`
	MatchConfidence Confidence     `json:"match_confidence"`
	VersionStatus   version.Status `json:"version_status"`
	Applicability   Applicability  `json:"applicability"`
	MatchReason     string         `json:"match_reason"`
	MatchedRules    []MatchedRule  `json:"matched_rules"`
	Warnings        []string       `json:"warnings,omitempty"`
}

// Evidence is a public exploit reference.
type Evidence struct {
	Source        string `json:"source"`
	Reference     string `json:"reference"`
	ReferenceType string `json:"reference_type,omitempty"`
	Verified      bool   `json:"verified"`
}

// MatchedRule is a rule that contributed to a vulnerability result.
type MatchedRule struct {
	Criteria string         `json:"criteria"`
	Range    string         `json:"version_range,omitempty"`
	Status   version.Status `json:"status"`
	Reason   string         `json:"reason"`
}

// QueryCPE runs a query for a supplied CPE string (2.2 or 2.3 binding).
func (e *Engine) QueryCPE(ctx context.Context, input string) (*Result, error) {
	c, err := cpe.Parse(input)
	if err != nil {
		return nil, err
	}
	if !cpe.IsSpecific(c.Vendor) || !cpe.IsSpecific(c.Product) {
		return nil, fmt.Errorf("%w: CPE %s must name a specific vendor and product", ErrInsufficientIdentity, c)
	}

	res := &Result{
		Input:              input,
		NormalizedCPE:      c.String(),
		Part:               c.Part,
		Vendor:             cpe.Unescape(c.Vendor),
		Product:            cpe.Unescape(c.Product),
		Version:            cpe.Unescape(c.Version),
		IdentityConfidence: identityConfidence(c),
		Comparator:         e.Comparator.Name(),
		Vulnerabilities:    []Vulnerability{},
	}

	rules, err := e.Store.CandidateRules(ctx, c.Part, c.Vendor, c.Product)
	if err != nil {
		return nil, err
	}
	res.CandidateRules = len(rules)
	for _, r := range rules {
		res.Evaluations = append(res.Evaluations, EvaluateRule(e.Comparator, c, r))
	}

	if err := e.buildVulnerabilities(ctx, res); err != nil {
		return nil, err
	}
	sortVulnerabilities(res.Vulnerabilities)

	res.Warnings = append(res.Warnings, backportWarning)
	if res.IdentityConfidence != Exact {
		res.Warnings = append(res.Warnings,
			"Supplied CPE has no specific version; version-dependent results are UNKNOWN.")
	}
	meta, err := e.Store.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if strings.Contains(meta["dataset"], "synthetic") {
		res.Warnings = append(res.Warnings,
			"Database contains SYNTHETIC test fixture data, not real vulnerability information.")
	} else {
		res.Warnings = append(res.Warnings, coverageWarning)
	}
	return res, nil
}

// identityConfidence: an exact supplied CPE is EXACT when it carries a
// concrete version; without one only the product is known, which is LOW.
func identityConfidence(c cpe.CPE) Confidence {
	if cpe.IsSpecific(c.Version) {
		return Exact
	}
	return Low
}

// buildVulnerabilities aggregates rule evaluations per CVE and enriches the
// CVEs that matched or could not be decided. NO_MATCH CVEs are dropped.
func (e *Engine) buildVulnerabilities(ctx context.Context, res *Result) error {
	byCVE := map[string][]RuleEvaluation{}
	var ids []string
	for _, ev := range res.Evaluations {
		if ev.Status == version.NoMatch {
			continue
		}
		if _, seen := byCVE[ev.CVEID]; !seen {
			ids = append(ids, ev.CVEID)
		}
		byCVE[ev.CVEID] = append(byCVE[ev.CVEID], ev)
	}
	if len(ids) == 0 {
		return nil
	}

	cves, err := e.Store.CVEs(ctx, ids)
	if err != nil {
		return err
	}
	kev, err := e.Store.KEV(ctx, ids)
	if err != nil {
		return err
	}
	exploits, err := e.Store.Exploits(ctx, ids)
	if err != nil {
		return err
	}

	for _, id := range ids {
		v := aggregate(id, byCVE[id], res.IdentityConfidence)
		enrich(&v, cves[id], kev, exploits[id])
		if v.VersionStatus == version.Match {
			res.MatchCount++
		} else {
			res.UnknownCount++
		}
		res.Vulnerabilities = append(res.Vulnerabilities, v)
	}
	return nil
}

// aggregate combines the non-NO_MATCH rule evaluations of one CVE.
//
// A CVE is MATCH if any rule matched, preferring unconditional matches;
// otherwise it is UNKNOWN. It is CONDITIONAL only if every matching rule is
// conditional.
func aggregate(id string, evs []RuleEvaluation, conf Confidence) Vulnerability {
	status := version.Unknown
	for _, ev := range evs {
		if ev.Status == version.Match {
			status = version.Match
		}
	}
	var chosen []RuleEvaluation
	for _, ev := range evs {
		if ev.Status == status {
			chosen = append(chosen, ev)
		}
	}
	// Unconditional rules first so the reason describes the strongest one.
	sort.SliceStable(chosen, func(i, j int) bool { return !chosen[i].Conditional && chosen[j].Conditional })

	v := Vulnerability{
		CVE:             id,
		VersionStatus:   status,
		MatchConfidence: conf,
		Applicability:   Unconditional,
		ExploitSources:  []string{},
		ExploitEvidence: []Evidence{},
	}
	if chosen[0].Conditional {
		v.Applicability = Conditional
		v.Warnings = append(v.Warnings, "Conditional: "+chosen[0].ConditionNote+".")
	}
	for _, ev := range chosen {
		v.MatchedRules = append(v.MatchedRules, MatchedRule{ev.Criteria, ev.Range, ev.Status, ev.Reason})
	}
	v.MatchReason = matchReason(conf, chosen[0])
	return v
}

func matchReason(conf Confidence, ev RuleEvaluation) string {
	who := "Exact supplied CPE"
	if conf != Exact {
		who = "Supplied CPE (no specific version)"
	}
	var b strings.Builder
	if ev.Status == version.Match {
		fmt.Fprintf(&b, "%s matched vulnerability criteria %s and %s.", who, ev.Criteria, describeMatch(ev.Reason))
	} else {
		fmt.Fprintf(&b, "%s matched vulnerability criteria %s but applicability could not be determined: %s.",
			who, ev.Criteria, ev.Reason)
	}
	if ev.Conditional {
		b.WriteString(" Applies only in combination with other configuration conditions that were not evaluated.")
	}
	return b.String()
}

// describeMatch rewords a version.Result reason for use in a sentence.
func describeMatch(reason string) string {
	if strings.HasPrefix(reason, "version ") {
		return "detected " + reason
	}
	return reason
}

func enrich(v *Vulnerability, c database.CVE, kev map[string]database.KEVEntry, evidence []database.ExploitEvidence) {
	v.Description = c.Description
	v.Severity = c.Severity
	v.CWE = c.CWE
	v.PublishedAt = c.PublishedAt
	if c.CVSSv3Score.Valid {
		v.CVSSv3Score = &c.CVSSv3Score.Float64
	}
	if c.CVSSv4Score.Valid {
		v.CVSSv4Score = &c.CVSSv4Score.Float64
	}
	// Prefer CVSS v3 for comparability with most tooling; fall back to v4.
	switch {
	case v.CVSSv3Score != nil:
		v.CVSS, v.CVSSVersion, v.CVSSVector = v.CVSSv3Score, "3", c.CVSSv3Vector
	case v.CVSSv4Score != nil:
		v.CVSS, v.CVSSVersion, v.CVSSVector = v.CVSSv4Score, "4", c.CVSSv4Vector
	}
	if c.CVEID == "" {
		v.Warnings = append(v.Warnings, "CVE record missing from database; only match rule data is available.")
	}

	if k, ok := kev[v.CVE]; ok {
		v.KnownExploited = true
		v.KnownRansomware = strings.EqualFold(k.KnownRansomware, "known")
		v.KEVDateAdded = k.DateAdded
	}
	for _, e := range evidence {
		v.ExploitEvidence = append(v.ExploitEvidence, Evidence{e.Source, e.Reference, e.ReferenceType, e.Verified})
		if !slices.Contains(v.ExploitSources, e.Source) {
			v.ExploitSources = append(v.ExploitSources, e.Source)
		}
	}
	v.PublicExploit = len(v.ExploitEvidence) > 0
}

// sortVulnerabilities applies the transparent priority policy:
//
//  1. version MATCH before UNKNOWN
//  2. KEV and public exploit
//  3. KEV
//  4. public exploit
//  5. CVSS (higher first; missing scores last)
//  6. unconditional before conditional
//  7. CVE ID (for determinism)
func sortVulnerabilities(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if x, y := a.VersionStatus == version.Match, b.VersionStatus == version.Match; x != y {
			return x
		}
		if x, y := priorityTier(a), priorityTier(b); x != y {
			return x < y
		}
		if x, y := cvssOrNeg(a.CVSS), cvssOrNeg(b.CVSS); x != y {
			return x > y
		}
		if x, y := a.Applicability == Unconditional, b.Applicability == Unconditional; x != y {
			return x
		}
		return a.CVE < b.CVE
	})
}

func priorityTier(v Vulnerability) int {
	switch {
	case v.KnownExploited && v.PublicExploit:
		return 0
	case v.KnownExploited:
		return 1
	case v.PublicExploit:
		return 2
	default:
		return 3
	}
}

func cvssOrNeg(s *float64) float64 {
	if s == nil {
		return -1
	}
	return *s
}
