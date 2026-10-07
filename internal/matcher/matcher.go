// Package matcher correlates software identities with candidate
// vulnerabilities in the local database.
//
// The pipeline is:
//
//	observed CPE -> candidate identities (observed + curated aliases)
//	             -> candidate rules per identity (indexed by part/vendor/product)
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
	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/version"
)

// Confidence is the identity confidence attached to results.
type Confidence = identity.Confidence

const (
	Exact   = identity.Exact
	High    = identity.High
	Medium  = identity.Medium
	Low     = identity.Low
	Unknown = identity.Unknown
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
const backportWarning = "Matching is based on upstream product/version data. Distribution backported " +
	"security fixes are only evaluated where a distribution verdict is shown (currently Ubuntu)."

// Warning shown for real datasets: since April 2026 NVD adds CPE
// applicability data to only a minority of new CVEs.
const coverageWarning = "NVD provides product (CPE) applicability data for only part of recent CVEs; " +
	"no result does not mean no vulnerability."

const syntheticWarning = "Database contains SYNTHETIC test fixture data, not real vulnerability information."

// IsGeneralWarning reports whether a result warning is about the dataset or
// method as a whole (rather than one identity), so reports listing many
// results can show it once.
func IsGeneralWarning(w string) bool {
	return w == backportWarning || w == coverageWarning || w == syntheticWarning
}

// Engine runs queries against an open database.
type Engine struct {
	Store      *database.Store
	Resolver   *identity.Resolver
	distroPkgs map[string][]database.DistroPackage // keyed by part:vendor:product
}

// New returns an Engine using the aliases and distribution package map
// stored in the database. Version comparators are chosen per product (see
// version.For).
func New(ctx context.Context, store *database.Store) (*Engine, error) {
	aliases, err := store.Aliases(ctx)
	if err != nil {
		return nil, err
	}
	pkgs, err := store.DistroPackages(ctx)
	if err != nil {
		return nil, err
	}
	e := &Engine{Store: store, Resolver: identity.NewResolver(aliases), distroPkgs: map[string][]database.DistroPackage{}}
	for _, p := range pkgs {
		k := p.Part + ":" + p.Vendor + ":" + p.Product
		e.distroPkgs[k] = append(e.distroPkgs[k], p)
	}
	return e, nil
}

// DistroInput describes distribution packaging observed for the queried
// software, so distribution advisories can be evaluated.
type DistroInput struct {
	Info        identity.DistroInfo
	ReleaseHint string // release established from other evidence on the same host
}

// advisoryDataFor maps distributions without their own advisory data to the
// data that describes their packages.
var advisoryDataFor = map[string]struct{ key, name string }{
	"centos": {"redhat", "Red Hat"},
}

// distroTarget maps the candidate identities to distribution source packages.
func (e *Engine) distroTarget(cands []identity.Candidate, in *DistroInput) (distro.Target, bool) {
	if in == nil || !in.Info.Detected() || in.Info.Key == "" || !cpe.IsSpecific(cands[0].CPE.Version) {
		return distro.Target{}, false
	}
	t := distro.Target{Distro: in.Info.Key, DistroName: in.Info.Name, Upstream: cpe.Unescape(cands[0].CPE.Version),
		Revision: in.Info.Revision, ReleaseHint: in.ReleaseHint, NoHintFallback: in.Info.Inferred}
	if data, ok := advisoryDataFor[t.Distro]; ok {
		t.Note = fmt.Sprintf("%s evaluated with %s advisories", t.DistroName, data.name)
		t.Distro = data.key
	}
	// OpenSSH: a bare OpenBSD release "8.7" (RHEL's banner) is the portable
	// 8.7p1 that distributions package (see version.OpenSSH).
	if cands[0].CPE.Vendor == "openbsd" && cands[0].CPE.Product == "openssh" && !strings.Contains(t.Upstream, "p") {
		t.Upstream += "p1"
	}
	for _, c := range cands {
		for _, p := range e.distroPkgs[c.CPE.Part+":"+c.CPE.Vendor+":"+c.CPE.Product] {
			if p.Distro == t.Distro && !slices.Contains(t.Packages, p.Package) {
				t.Packages = append(t.Packages, p.Package)
			}
		}
	}
	return t, true
}

// ResolveDistro resolves the distribution release/package for candidates
// without running a full query (used to share a host's release between its
// services). It returns nil when no distribution packaging was observed.
func (e *Engine) ResolveDistro(ctx context.Context, cands []identity.Candidate, in *DistroInput) (*distro.Context, error) {
	t, ok := e.distroTarget(cands, in)
	if !ok {
		return nil, nil
	}
	return distro.Resolve(ctx, e.Store, t)
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
	Identities         []IdentityResult `json:"identities"`
	CandidateRules     int              `json:"candidate_rules"`
	MatchCount         int              `json:"match_count"`        // version MATCH, excluding distro-FIXED
	UnknownCount       int              `json:"unknown_count"`      // version UNKNOWN, excluding distro-FIXED
	DistroFixedCount   int              `json:"distro_fixed_count"` // fixed in the distribution package
	Distro             *distro.Context  `json:"distro,omitempty"`
	Vulnerabilities    []Vulnerability  `json:"vulnerabilities"`
	Warnings           []string         `json:"warnings"`
	Evaluations        []RuleEvaluation `json:"-"` // every rule, for --debug
}

// IdentityResult describes one candidate identity that was looked up.
type IdentityResult struct {
	CPE            string     `json:"cpe"`
	Confidence     Confidence `json:"confidence"`
	Source         string     `json:"source"`
	Reason         string     `json:"reason"`
	Comparator     string     `json:"comparator"`
	CandidateRules int        `json:"candidate_rules"`
}

// Vulnerability is one candidate CVE with enrichment and explanation.
type Vulnerability struct {
	CVE             string          `json:"cve"`
	Description     string          `json:"description"`
	CVSS            *float64        `json:"cvss"`
	CVSSVersion     string          `json:"cvss_version,omitempty"`
	CVSSVector      string          `json:"cvss_vector,omitempty"`
	CVSSv3Score     *float64        `json:"cvss_v3_score"`
	CVSSv4Score     *float64        `json:"cvss_v4_score"`
	Severity        string          `json:"severity"`
	CWE             string          `json:"cwe,omitempty"`
	PublishedAt     string          `json:"published_at,omitempty"`
	PublicExploit   bool            `json:"public_exploit"`
	ExploitSources  []string        `json:"exploit_sources"`
	ExploitEvidence []Evidence      `json:"exploit_evidence"`
	KnownExploited  bool            `json:"known_exploited"`
	KnownRansomware bool            `json:"known_ransomware"`
	KEVDateAdded    string          `json:"kev_date_added,omitempty"`
	MatchConfidence Confidence      `json:"match_confidence"`
	MatchedCPE      string          `json:"matched_cpe"`
	VersionStatus   version.Status  `json:"version_status"`
	Applicability   Applicability   `json:"applicability"`
	MatchReason     string          `json:"match_reason"`
	MatchedRules    []MatchedRule   `json:"matched_rules"`
	Distro          *distro.Verdict `json:"distro,omitempty"`
	DistroOnly      bool            `json:"distro_only,omitempty"` // found only via distribution advisories
	Warnings        []string        `json:"warnings,omitempty"`
}

// distroFixed reports whether distribution data shows the CVE fixed.
func (v Vulnerability) distroFixed() bool { return v.Distro != nil && v.Distro.Status == distro.Fixed }

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

// QueryCPE runs a query for a supplied CPE string (2.2 or 2.3 binding),
// including curated alias identities for it.
func (e *Engine) QueryCPE(ctx context.Context, input string, in *DistroInput) (*Result, error) {
	c, err := cpe.Parse(input)
	if err != nil {
		return nil, err
	}
	if !cpe.IsSpecific(c.Vendor) || !cpe.IsSpecific(c.Product) {
		return nil, fmt.Errorf("%w: CPE %s must name a specific vendor and product", ErrInsufficientIdentity, c)
	}
	res, err := e.Query(ctx, e.Resolver.ResolveCPE(c, "supplied"), in)
	if err != nil {
		return nil, err
	}
	res.Input = input
	return res, nil
}

// Query looks up a list of candidate identities. The first candidate is the
// observed identity and populates the top-level identity fields; results
// from all candidates are merged per CVE.
func (e *Engine) Query(ctx context.Context, cands []identity.Candidate, in *DistroInput) (*Result, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("%w: no candidate identities", ErrInsufficientIdentity)
	}
	first := cands[0].CPE
	res := &Result{
		Input:              first.String(),
		NormalizedCPE:      first.String(),
		Part:               first.Part,
		Vendor:             cpe.Unescape(first.Vendor),
		Product:            cpe.Unescape(first.Product),
		Version:            cpe.Unescape(first.Version),
		IdentityConfidence: cands[0].Confidence,
		Vulnerabilities:    []Vulnerability{},
	}
	for i, cand := range cands {
		c := cand.CPE
		cmp := version.For(c.Vendor, c.Product)
		key := ""
		if version.KeySafe(cmp) && cpe.IsSpecific(c.Version) {
			key = version.Key(cpe.Unescape(c.Version))
		}
		rules, err := e.Store.CandidateRules(ctx, c.Part, c.Vendor, c.Product, key)
		if err != nil {
			return nil, err
		}
		res.Identities = append(res.Identities, IdentityResult{
			CPE: c.String(), Confidence: cand.Confidence, Source: cand.Source, Reason: cand.Reason,
			Comparator: cmp.Name(), CandidateRules: len(rules),
		})
		res.CandidateRules += len(rules)
		type parsed struct {
			crit cpe.CPE
			err  error
		}
		cache := map[string]parsed{}
		for _, r := range rules {
			p, ok := cache[r.Criteria]
			if !ok {
				p.crit, p.err = cpe.ParsePattern(r.Criteria)
				cache[r.Criteria] = p
			}
			ev := evaluateParsed(cmp, c, r, p.crit, p.err)
			ev.IdentityCPE, ev.Confidence, ev.who = c.String(), cand.Confidence, describeIdentity(cand)
			ev.order = i
			res.Evaluations = append(res.Evaluations, ev)
		}
	}
	res.Comparator = res.Identities[0].Comparator

	if err := e.buildVulnerabilities(ctx, res); err != nil {
		return nil, err
	}
	if err := e.applyDistro(ctx, res, cands, in); err != nil {
		return nil, err
	}
	res.count()
	sortVulnerabilities(res.Vulnerabilities)

	if res.Distro == nil || (res.Distro.Status != distro.Resolved && res.Distro.Status != distro.Ambiguous) {
		res.Warnings = append(res.Warnings, backportWarning)
	}
	if res.IdentityConfidence != Exact {
		res.Warnings = append(res.Warnings,
			"Supplied CPE has no specific version; version-dependent results are UNKNOWN.")
	}
	res.Warnings = append(res.Warnings, identity.Notes(cands)...)
	meta, err := e.Store.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	if strings.Contains(meta["dataset"], "synthetic") {
		res.Warnings = append(res.Warnings, syntheticWarning)
	} else {
		res.Warnings = append(res.Warnings, coverageWarning)
	}
	return res, nil
}

// describeIdentity is the subject of a match_reason sentence.
func describeIdentity(c identity.Candidate) string {
	switch {
	case strings.HasPrefix(c.Source, "alias:"):
		return fmt.Sprintf("Curated alias identity %s:%s", cpe.Unescape(c.CPE.Vendor), cpe.Unescape(c.CPE.Product))
	case c.Confidence != Exact:
		return "Supplied CPE (no specific version)"
	case c.Source == "supplied":
		return "Exact supplied CPE"
	default:
		return fmt.Sprintf("Exact %s CPE", c.Source)
	}
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

	vs := make([]Vulnerability, 0, len(ids))
	for _, id := range ids {
		vs = append(vs, aggregate(id, byCVE[id]))
	}
	if err := e.enrichAll(ctx, vs); err != nil {
		return err
	}
	res.Vulnerabilities = append(res.Vulnerabilities, vs...)
	return nil
}

// enrichAll adds CVE details, KEV and exploit evidence to vulnerabilities.
func (e *Engine) enrichAll(ctx context.Context, vs []Vulnerability) error {
	if len(vs) == 0 {
		return nil
	}
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.CVE
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
	for i := range vs {
		enrich(&vs[i], cves[vs[i].CVE], kev, exploits[vs[i].CVE])
	}
	return nil
}

// applyDistro annotates every result with the distribution advisory verdict
// and adds definitive findings that only the distribution data reveals.
func (e *Engine) applyDistro(ctx context.Context, res *Result, cands []identity.Candidate, in *DistroInput) error {
	dc, err := e.ResolveDistro(ctx, cands, in)
	if err != nil || dc == nil {
		return err
	}
	res.Distro = dc
	known := map[string]bool{}
	for i := range res.Vulnerabilities {
		v := dc.Verdict(res.Vulnerabilities[i].CVE)
		res.Vulnerabilities[i].Distro = &v
		known[res.Vulnerabilities[i].CVE] = true
	}
	var extra []Vulnerability
	for _, d := range dc.Additional(known) {
		d := d
		extra = append(extra, Vulnerability{
			CVE: d.CVE, VersionStatus: version.Match, Applicability: Unconditional,
			MatchConfidence: cands[0].Confidence, Distro: &d, DistroOnly: true,
			ExploitSources: []string{}, ExploitEvidence: []Evidence{},
			MatchReason: fmt.Sprintf("%s advisory %s: %s. NVD has no applicability rule matching this version.",
				d.Distro, d.Advisory, d.Reason),
		})
	}
	if err := e.enrichAll(ctx, extra); err != nil {
		return err
	}
	res.Vulnerabilities = append(res.Vulnerabilities, extra...)
	return nil
}

// count fills the summary counters. CVEs a distribution has fixed in the
// observed package are counted separately, not as matches.
func (r *Result) count() {
	r.MatchCount, r.UnknownCount, r.DistroFixedCount = 0, 0, 0
	for _, v := range r.Vulnerabilities {
		switch {
		case v.distroFixed():
			r.DistroFixedCount++
		case v.VersionStatus == version.Match:
			r.MatchCount++
		default:
			r.UnknownCount++
		}
	}
}

// aggregate combines the non-NO_MATCH rule evaluations of one CVE, across
// all candidate identities.
//
// A CVE is MATCH if any rule matched, otherwise UNKNOWN. Among the chosen
// rules, unconditional ones come first, then those from the more confident
// identity; the first one supplies match_confidence and match_reason. A CVE
// is CONDITIONAL only if every matching rule is conditional.
func aggregate(id string, evs []RuleEvaluation) Vulnerability {
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
	sort.SliceStable(chosen, func(i, j int) bool {
		a, b := chosen[i], chosen[j]
		if a.Conditional != b.Conditional {
			return !a.Conditional
		}
		if ra, rb := identity.Rank(a.Confidence), identity.Rank(b.Confidence); ra != rb {
			return ra > rb
		}
		return a.order < b.order
	})

	v := Vulnerability{
		CVE:             id,
		VersionStatus:   status,
		MatchConfidence: chosen[0].Confidence,
		MatchedCPE:      chosen[0].IdentityCPE,
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
	v.MatchReason = matchReason(chosen[0])
	return v
}

func matchReason(ev RuleEvaluation) string {
	who := ev.who
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
//  7. identity confidence (higher first)
//  8. CVE ID (for determinism)
func sortVulnerabilities(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if x, y := a.distroFixed(), b.distroFixed(); x != y {
			return y
		}
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
		if x, y := identity.Rank(a.MatchConfidence), identity.Rank(b.MatchConfidence); x != y {
			return x > y
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
