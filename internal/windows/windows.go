// Package windows assesses Windows hosts at build level.
//
// An unauthenticated scan never sees a Windows host's patch level (the
// "UBR", e.g. 20348.2849), but NSE scripts such as rdp-ntlm-info and
// smb-os-discovery do expose its build number (10.0.20348). A curated map
// (data/windows_builds.json, table windows_builds) turns the build into the
// release's NVD CPE identities, which are then matched like any other
// identity. The result is the set of CVEs that apply to the release *unless
// the host is patched*: an inventory of exposure, not proof of vulnerability.
package windows

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/version"
)

// Kind hints.
const (
	Server = "server"
	Client = "client"
)

// Status of a host's build-level assessment.
type Status string

const (
	Assessed Status = "ASSESSED" // build mapped to a release and looked up
	Unmapped Status = "UNMAPPED" // build seen, but not in the curated build map
	Conflict Status = "CONFLICT" // the host reported different builds
)

// Signals is the Windows evidence gathered from one host's scan results.
type Signals struct {
	// ProductVersions are NTLM "Product_Version" values ("10.0.20348").
	ProductVersions []Signal
	// OSStrings are OS descriptions that end in a build number, e.g.
	// smb-os-discovery "Windows Server 2016 Standard Evaluation 14393".
	OSStrings []Signal
	// DomainController is set when the host runs Active Directory services
	// (LDAP/Kerberos), which only Windows Server provides.
	DomainController string // the evidence, e.g. "Active Directory LDAP on 389/tcp"
}

// Signal is one observed value and where it came from.
type Signal struct {
	Value  string
	Source string // e.g. "rdp-ntlm-info on 3389/tcp"
}

// Evidence is the build established for a host.
type Evidence struct {
	Build          int
	ProductVersion string // "10.0.20348"
	Sources        []string
	Kind           string // Server, Client or "" when unknown
	KindSource     string
	Conflict       string // set when sources disagree on the build
}

var (
	productVersionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	// "Windows Server 2016" etc.: the year must not be read as a build.
	serverYearRe = regexp.MustCompile(`(?i)server\s+\d{4}`)
	buildRe      = regexp.MustCompile(`(?:^|\s)(\d{4,5})(?:\s|$)`)
	clientNameRe = regexp.MustCompile(`(?i)\bwindows\s+(?:7|8|8\.1|10|11|vista)\b`)
)

// ntVersion is the NT kernel version of a build, for when only the build
// number was seen (smb-os-discovery).
func ntVersion(build int) string {
	switch {
	case build >= 10240:
		return "10.0"
	case build >= 9600:
		return "6.3"
	case build >= 9200:
		return "6.2"
	case build >= 7600:
		return "6.1"
	default:
		return "6.0"
	}
}

// Detect establishes the host's build from its signals. It returns nil when
// no build is visible.
func Detect(s Signals) *Evidence {
	type seen struct {
		build int
		pv    string
	}
	var builds []seen
	ev := &Evidence{}
	for _, sig := range s.ProductVersions {
		m := productVersionRe.FindStringSubmatch(strings.TrimSpace(sig.Value))
		if m == nil {
			continue
		}
		b, _ := strconv.Atoi(m[3])
		builds = append(builds, seen{b, m[0]})
		ev.Sources = append(ev.Sources, fmt.Sprintf("%s Product_Version %s", sig.Source, m[0]))
	}
	for _, sig := range s.OSStrings {
		os := strings.TrimSpace(sig.Value)
		m := buildRe.FindStringSubmatch(serverYearRe.ReplaceAllString(os, ""))
		if m != nil {
			if b, _ := strconv.Atoi(m[1]); b >= 6000 {
				builds = append(builds, seen{b, ""})
				ev.Sources = append(ev.Sources, fmt.Sprintf("%s %q", sig.Source, os))
			}
		}
		switch {
		case ev.Kind != "":
		case strings.Contains(strings.ToLower(os), "server"):
			ev.Kind, ev.KindSource = Server, fmt.Sprintf("%s %q", sig.Source, os)
		case clientNameRe.MatchString(os):
			ev.Kind, ev.KindSource = Client, fmt.Sprintf("%s %q", sig.Source, os)
		}
	}
	if len(builds) == 0 {
		return nil
	}
	if ev.Kind == "" && s.DomainController != "" {
		ev.Kind, ev.KindSource = Server, s.DomainController+" (domain controllers run Windows Server)"
	}
	ev.Build = builds[0].build
	for _, b := range builds {
		if b.build != ev.Build {
			ev.Conflict = fmt.Sprintf("the host reported different Windows builds (%d and %d)", ev.Build, b.build)
		}
		if ev.ProductVersion == "" && b.pv != "" {
			ev.ProductVersion = b.pv
		}
	}
	if ev.ProductVersion == "" {
		ev.ProductVersion = fmt.Sprintf("%s.%d", ntVersion(ev.Build), ev.Build)
	}
	return ev
}

// Assessment is one Windows release assessed for a host.
type Assessment struct {
	Status         Status              `json:"status"`
	Build          int                 `json:"build"`
	ProductVersion string              `json:"product_version"`
	Evidence       []string            `json:"evidence"`
	Release        string              `json:"release,omitempty"`
	Kind           string              `json:"kind,omitempty"`
	KindEvidence   string              `json:"kind_evidence,omitempty"`
	Confidence     identity.Confidence `json:"confidence,omitempty"`
	CPEs           []string            `json:"cpes,omitempty"` // identities queried
	Support        string              `json:"support,omitempty"`
	EOL            string              `json:"eol,omitempty"`
	EndOfLife      bool                `json:"end_of_life"`
	// Applicable counts CVEs whose rules cover the unpatched build: they
	// apply unless the host has the fixing update installed. Vulnerabilities
	// lists them (version_status MATCH) and the undetermined ones (UNKNOWN,
	// with a reason).
	Applicable      int             `json:"applicable"`
	KnownExploited  int             `json:"known_exploited"`
	PublicExploit   int             `json:"public_exploit"`
	Critical        int             `json:"critical"`
	Undetermined    int             `json:"undetermined"`
	Vulnerabilities []CVERef        `json:"vulnerabilities"`
	Notes           []string        `json:"notes,omitempty"`
	Result          *matcher.Result `json:"-"`
}

// CVERef is a compact CVE entry (a release has thousands).
type CVERef struct {
	CVE             string   `json:"cve"`
	Severity        string   `json:"severity,omitempty"`
	CVSS            *float64 `json:"cvss,omitempty"`
	Published       string   `json:"published_at,omitempty"`
	KnownExploited  bool     `json:"known_exploited,omitempty"`
	KnownRansomware bool     `json:"known_ransomware,omitempty"`
	KEVDateAdded    string   `json:"kev_date_added,omitempty"`
	PublicExploit   bool     `json:"public_exploit,omitempty"`
	VersionStatus   string   `json:"version_status"`
	MatchedCPE      string   `json:"matched_cpe"`
	Reason          string   `json:"reason,omitempty"` // why it is undetermined
}

// PatchNote explains what a build-level result means.
const PatchNote = "Build-level assessment: the patch level is not visible to an unauthenticated scan, so these CVEs apply " +
	"unless the host has the updates that fix them. Use it to see the release's exposure (KEV entries first), " +
	"then confirm with patch data."

// archNote is added for client releases, which ship for several architectures.
const archNote = "Architecture is not visible; x64 was assumed (x86/ARM64-only CVEs are not listed)."

// Assessor assesses builds, caching per release (hosts commonly share one).
type Assessor struct {
	engine *matcher.Engine
	builds map[int][]database.WindowsBuild
	cache  map[string]*Assessment
}

// NewAssessor loads the build map.
func NewAssessor(ctx context.Context, engine *matcher.Engine) (*Assessor, error) {
	rows, err := engine.Store.WindowsBuilds(ctx)
	if err != nil {
		return nil, err
	}
	a := &Assessor{engine: engine, builds: map[int][]database.WindowsBuild{}, cache: map[string]*Assessment{}}
	for _, r := range rows {
		a.builds[r.Build] = append(a.builds[r.Build], r)
	}
	return a, nil
}

// Assess returns the host's assessments: one per candidate release (two when
// the build is shared by a server and a client release and nothing shows
// which one the host runs).
func (a *Assessor) Assess(ctx context.Context, ev *Evidence) ([]Assessment, error) {
	base := Assessment{Build: ev.Build, ProductVersion: ev.ProductVersion, Evidence: ev.Sources,
		Vulnerabilities: []CVERef{}}
	if ev.Conflict != "" {
		base.Status = Conflict
		base.Notes = []string{"Not assessed: " + ev.Conflict + "."}
		return []Assessment{base}, nil
	}
	rows := a.builds[ev.Build]
	if len(rows) == 0 {
		base.Status = Unmapped
		base.Notes = []string{fmt.Sprintf("Not assessed: build %d is not in the Windows build map (data/windows_builds.json).", ev.Build)}
		return []Assessment{base}, nil
	}
	var notes []string
	if ev.Kind != "" {
		var kept []database.WindowsBuild
		for _, r := range rows {
			if r.Kind == ev.Kind {
				kept = append(kept, r)
			}
		}
		if len(kept) > 0 {
			rows = kept
		} else {
			notes = append(notes, fmt.Sprintf("Evidence suggests a %s release (%s), but build %d is only known as a %s release.",
				ev.Kind, ev.KindSource, ev.Build, rows[0].Kind))
		}
	}
	conf := identity.High
	if len(rows) > 1 {
		conf = identity.Medium
		names := make([]string, len(rows))
		for i, r := range rows {
			names[i] = r.Name
		}
		notes = append(notes, fmt.Sprintf("Build %d is used by %s; nothing in the scan shows which one this host runs, so each is listed.",
			ev.Build, strings.Join(names, " and ")))
	}
	var out []Assessment
	for _, r := range rows {
		as, err := a.assessRelease(ctx, r, ev.ProductVersion)
		if err != nil {
			return nil, err
		}
		res := *as // copy: the cached value is shared between hosts
		res.Evidence, res.Confidence = ev.Sources, conf
		if r.Kind == ev.Kind {
			res.KindEvidence = ev.KindSource
		}
		res.Notes = append(slices.Clone(notes), res.Notes...)
		out = append(out, res)
	}
	return out, nil
}

// candidates are the release's NVD identities, each queried twice:
//   - as curated ("windows_server_2016:-"), which matches older rules that
//     name the release itself;
//   - with the version set to the unpatched build ("10.0.14393"), which
//     matches newer rules given as ranges ending at the fixing build
//     ("< 10.0.14393.7428").
//
// target_hw is x64: Windows Server ships only for x64 (since 2008 R2), and
// clients are assumed to be x64 (see archNote).
func candidates(r database.WindowsBuild, productVersion string) ([]identity.Candidate, error) {
	var out []identity.Candidate
	seen := map[string]bool{}
	add := func(attrs []string, reason string) error {
		c, err := cpe.Parse("cpe:2.3:" + strings.Join(attrs, ":"))
		if err != nil {
			return err
		}
		if !seen[c.String()] {
			seen[c.String()] = true
			out = append(out, identity.Candidate{CPE: c, Confidence: identity.High, Source: "windows-build", Reason: reason})
		}
		return nil
	}
	for _, s := range r.CPEs {
		c, err := cpe.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("windows build %d: %w", r.Build, err)
		}
		attrs := c.Attributes()
		attrs[9] = "x64" // target_hw
		if err := add(attrs, fmt.Sprintf("Windows build %d is %s", r.Build, r.Name)); err != nil {
			return nil, err
		}
		attrs[3] = productVersion
		if err := add(attrs, fmt.Sprintf("Windows build %d (%s) before any update", r.Build, r.Name)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *Assessor) assessRelease(ctx context.Context, r database.WindowsBuild, productVersion string) (*Assessment, error) {
	key := fmt.Sprintf("%d|%s|%s", r.Build, r.Kind, productVersion)
	if as, ok := a.cache[key]; ok {
		return as, nil
	}
	cands, err := candidates(r, productVersion)
	if err != nil {
		return nil, err
	}
	res, err := a.engine.Query(ctx, cands, nil)
	if err != nil {
		return nil, err
	}
	if err := refine(res, cands, productVersion); err != nil {
		return nil, err
	}
	if err := a.engine.Reaggregate(ctx, res); err != nil {
		return nil, err
	}
	laterUpdate := 0
	as := &Assessment{Status: Assessed, Build: r.Build, ProductVersion: productVersion, Release: r.Name, Kind: r.Kind,
		Support: r.Support, EOL: r.EOL, Vulnerabilities: []CVERef{}, Result: res}
	for _, c := range cands {
		as.CPEs = append(as.CPEs, c.CPE.String())
	}
	if eol, err := time.Parse("2006-01-02", r.EOL); err == nil && !distro.Now().Before(eol) {
		as.EndOfLife = true
	}
	for _, v := range res.Vulnerabilities {
		ref := CVERef{CVE: v.CVE, Severity: v.Severity, CVSS: v.CVSS, Published: v.PublishedAt,
			KnownExploited: v.KnownExploited, KnownRansomware: v.KnownRansomware, KEVDateAdded: v.KEVDateAdded,
			PublicExploit: v.PublicExploit, VersionStatus: string(v.VersionStatus), MatchedCPE: v.MatchedCPE}
		if v.VersionStatus != version.Match {
			as.Undetermined++
			if len(v.MatchedRules) > 0 {
				ref.Reason = v.MatchedRules[0].Reason
			}
			if strings.Contains(ref.Reason, laterUpdateNote) {
				laterUpdate++
			}
			as.Vulnerabilities = append(as.Vulnerabilities, ref)
			continue
		}
		as.Applicable++
		if v.KnownExploited {
			as.KnownExploited++
		}
		if v.PublicExploit {
			as.PublicExploit++
		}
		if v.Severity == "CRITICAL" {
			as.Critical++
		}
		as.Vulnerabilities = append(as.Vulnerabilities, ref)
	}
	as.Notes = []string{PatchNote}
	if r.Kind == Client {
		as.Notes = append(as.Notes, archNote)
	}
	if laterUpdate > 0 {
		as.Notes = append(as.Notes, fmt.Sprintf("%d undetermined CVEs were introduced by a later update of this build, "+
			"so they apply only at certain patch levels.", laterUpdate))
	}
	if n := as.Undetermined - laterUpdate; n > 0 {
		as.Notes = append(as.Notes, fmt.Sprintf("%d undetermined CVEs name specific editions or other conditions that the scan cannot show.", n))
	}
	a.cache[key] = as
	return as, nil
}

// laterUpdateNote marks rules whose range starts at an update of the host's
// build: the CVE was introduced by that update, so it applies only if the
// host's (unknown) patch level is inside the range.
const laterUpdateNote = "introduced by a later update of this build; applies only if the host's patch level is within"

// refine adjusts rule evaluations with what the engine cannot know:
//   - range rules are decided by the build identity alone: the release
//     identity ("windows_11_22h2:-") cannot evaluate a range and would add an
//     UNKNOWN for every one, including NVD's mistaken ranges that end at
//     another release's builds (22H2 "< 10.0.22000.1413");
//   - a range starting at a later update of the build ("10.0.20348.1000 <=
//     v < 10.0.20348.2000") is a NO_MATCH for the unpatched build but may
//     apply to the host, whose patch level is unknown: UNKNOWN.
func refine(res *matcher.Result, cands []identity.Candidate, productVersion string) error {
	buildIDs := map[string]cpe.CPE{}
	for _, c := range cands {
		if cpe.Unescape(c.CPE.Version) == productVersion {
			buildIDs[c.CPE.String()] = c.CPE
		}
	}
	prefix := productVersion + "."
	for i := range res.Evaluations {
		ev := &res.Evaluations[i]
		build, isBuild := buildIDs[ev.IdentityCPE]
		if !isBuild {
			if !ev.Bounds.IsEmpty() && ev.Status != version.NoMatch {
				ev.Status = version.NoMatch
				ev.Reason = "range rule; decided by the build identity"
			}
			continue
		}
		if ev.Status != version.NoMatch {
			continue
		}
		probe := ev.Bounds.StartIncluding
		if probe == "" && ev.Bounds.StartExcluding != "" {
			probe = ev.Bounds.StartExcluding + ".1" // just above the bound
		}
		if !strings.HasPrefix(probe, prefix) {
			continue
		}
		at := build
		at.Version = probe
		rule := database.MatchRule{ID: ev.RuleID, CVEID: ev.CVEID, Criteria: ev.Criteria, Range: ev.Bounds}
		if matcher.EvaluateRule(version.For(build.Vendor, build.Product), at, rule).Status == version.Match {
			ev.Status = version.Unknown
			ev.Reason = fmt.Sprintf("%s %s", laterUpdateNote, ev.Range)
		}
	}
	return nil
}
