// Package identity turns observed software identities (a supplied CPE, or a
// service reported by a discovery tool such as Nmap) into the candidate CPE
// identities that are looked up in the vulnerability database.
//
// Resolution rules:
//   - the observed application CPE is always a candidate (EXACT with a
//     concrete version, LOW without one);
//   - curated aliases from the database add further candidates for the same
//     software under the vendor/product name NVD uses (e.g. Nmap's
//     igor_sysoev:nginx -> f5:nginx). An alias never replaces the observed
//     identity and never raises confidence above the alias's own;
//   - operating-system and hardware CPEs reported alongside a service are
//     not queried as if they were the service;
//   - distribution package versions (Ubuntu, Debian, RHEL, ...) are detected
//     and reported, because vendors backport fixes without changing the
//     upstream version that matching relies on.
package identity

import (
	"fmt"
	"regexp"
	"strings"

	"bunyip/internal/cpe"
	"bunyip/internal/database"
	"bunyip/internal/version"
)

// Confidence classifies how certain a software identity is.
type Confidence string

const (
	Exact   Confidence = "EXACT"   // observed CPE with a concrete version
	High    Confidence = "HIGH"    // deterministic mapping, e.g. curated vendor alias
	Medium  Confidence = "MEDIUM"  // mapping with strong but indirect evidence
	Low     Confidence = "LOW"     // product only (no version), or ambiguous
	Unknown Confidence = "UNKNOWN" // insufficient evidence
)

var rank = map[Confidence]int{Exact: 4, High: 3, Medium: 2, Low: 1, Unknown: 0}

// Rank orders confidence levels (higher is more certain).
func Rank(c Confidence) int { return rank[c] }

// lower returns the less certain of two confidence levels.
func lower(a, b Confidence) Confidence {
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

// Candidate is one identity to look up.
type Candidate struct {
	CPE        cpe.CPE
	Confidence Confidence
	Source     string // "supplied", "nmap", or "alias:<source>"
	Reason     string
}

// Resolver applies curated aliases and product names.
type Resolver struct {
	aliases    map[string][]database.Alias // keyed by part:vendor:product (canonical values)
	exactNames map[string][]database.ProductName
	regexNames []nameRule // in pattern order; the first matching pattern wins
	httpApps   []httpAppRule
}

type httpAppRule struct {
	app database.HTTPApp
	re  *regexp.Regexp
}

// AddHTTPApps compiles the curated HTTP application fingerprints.
func (r *Resolver) AddHTTPApps(apps []database.HTTPApp) error {
	for _, a := range apps {
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return fmt.Errorf("http app pattern %q: %w", a.Pattern, err)
		}
		r.httpApps = append(r.httpApps, httpAppRule{app: a, re: re})
	}
	return nil
}

// httpAppCandidates matches the observation's HTTP evidence against the
// curated fingerprints, returning web-application identities. They are added
// alongside any web-server CPE, since the application sits behind it.
func (r *Resolver) httpAppCandidates(o Observation) ([]Candidate, []string) {
	if len(o.HTTP) == 0 || len(r.httpApps) == 0 {
		return nil, nil
	}
	var out []Candidate
	var notes []string
	seen := map[string]bool{}
	for _, hr := range r.httpApps {
		key := hr.app.Evidence
		if hr.app.Evidence == "header" {
			key = "header:" + hr.app.Header
		}
		value, ok := o.HTTP[key]
		if !ok || value == "" {
			continue
		}
		m := hr.re.FindStringSubmatch(value)
		if m == nil {
			continue
		}
		ver := ""
		if hr.app.VersionGroup > 0 && hr.app.VersionGroup < len(m) {
			ver = m[hr.app.VersionGroup]
		}
		c := cpe.CPE{Part: "a", Vendor: hr.app.Vendor, Product: hr.app.Product, Version: cpe.EscapeValue(ver),
			Update: cpe.Any, Edition: cpe.Any, Language: cpe.Any, SWEdition: cpe.Any, TargetSW: cpe.Any,
			TargetHW: cpe.Any, Other: cpe.Any}
		if seen[c.String()] {
			continue
		}
		seen[c.String()] = true
		conf := Confidence(hr.app.Confidence)
		reason := fmt.Sprintf("HTTP %s evidence %q -> %s:%s", hr.app.Evidence, value, hr.app.Vendor, hr.app.Product)
		if ver == "" {
			conf = Low
			reason += " (no version in evidence)"
		}
		out = append(out, Candidate{CPE: c, Confidence: conf, Source: "http-app:" + hr.app.Source, Reason: reason})
		if hr.app.Note != "" {
			notes = appendUnique(notes, hr.app.Note)
		}
	}
	return out, notes
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

type nameRule struct {
	re      *regexp.Regexp
	entries []database.ProductName // one per target vendor:product
}

// AddProductNames indexes the curated Nmap product names.
func (r *Resolver) AddProductNames(names []database.ProductName) error {
	if r.exactNames == nil {
		r.exactNames = map[string][]database.ProductName{}
	}
	byPattern := map[string]int{}
	for _, n := range names {
		if n.Match != "regex" {
			r.exactNames[n.Pattern] = append(r.exactNames[n.Pattern], n)
			continue
		}
		i, ok := byPattern[n.Pattern]
		if !ok {
			re, err := regexp.Compile(n.Pattern)
			if err != nil {
				return fmt.Errorf("product name pattern %q: %w", n.Pattern, err)
			}
			i = len(r.regexNames)
			byPattern[n.Pattern] = i
			r.regexNames = append(r.regexNames, nameRule{re: re})
		}
		r.regexNames[i].entries = append(r.regexNames[i].entries, n)
	}
	return nil
}

// lookupName returns the curated entries for an Nmap product string: exact
// names first, otherwise the first matching pattern.
func (r *Resolver) lookupName(product string) []database.ProductName {
	if n := r.exactNames[product]; len(n) > 0 {
		return n
	}
	for _, rule := range r.regexNames {
		if rule.re.MatchString(product) {
			return rule.entries
		}
	}
	return nil
}

// nameCandidates turns curated product-name entries into identities. The
// version comes from Nmap's version field only where the curation says it
// is the product version.
func nameCandidates(o Observation, entries []database.ProductName) ([]Candidate, []string) {
	var out []Candidate
	var notes []string
	product := strings.TrimSpace(o.Product)
	for _, n := range entries {
		if n.Kind != "product" {
			continue
		}
		ver := ""
		if f := strings.Fields(o.Version); n.Version == "nmap" && len(f) > 0 {
			ver = f[0]
		}
		c := cpe.CPE{Part: n.Part, Vendor: n.Vendor, Product: n.Product, Version: cpe.EscapeValue(ver),
			Update: cpe.Any, Edition: cpe.Any, Language: cpe.Any, SWEdition: cpe.Any, TargetSW: cpe.Any,
			TargetHW: cpe.Any, Other: cpe.Any}
		conf, reason := Confidence(n.Confidence), fmt.Sprintf("Curated product name %q -> %s:%s", product, n.Vendor, n.Product)
		if ver == "" {
			conf = Low
			reason += " (no product version)"
		}
		out = append(out, Candidate{CPE: c, Confidence: conf, Source: "product-name:" + n.Source, Reason: reason})
	}
	if len(out) == 0 {
		return nil, nil
	}
	if entries[0].Version == "none" && strings.TrimSpace(o.Version) != "" {
		notes = append(notes, fmt.Sprintf("Nmap's version %q for %q is not the product version, so it was not used.",
			strings.TrimSpace(o.Version), product))
	}
	if entries[0].Note != "" {
		notes = append(notes, entries[0].Note)
	}
	return out, notes
}

// NewResolver indexes vendor/product aliases. Product-name aliases (no
// observed vendor) are reserved for future banner resolution and ignored.
func NewResolver(aliases []database.Alias) *Resolver {
	r := &Resolver{aliases: map[string][]database.Alias{}}
	for _, a := range aliases {
		if a.ObservedVendor == "" || a.Part == "" {
			continue
		}
		k := key(a.Part, a.ObservedVendor, a.ObservedProduct)
		r.aliases[k] = append(r.aliases[k], a)
	}
	return r
}

func key(part, vendor, product string) string { return part + ":" + vendor + ":" + product }

// baseConfidence is the confidence of an observed CPE on its own.
func baseConfidence(c cpe.CPE) Confidence {
	if cpe.IsSpecific(c.Version) {
		return Exact
	}
	return Low
}

// ResolveCPE returns the observed CPE followed by any alias candidates.
func (r *Resolver) ResolveCPE(c cpe.CPE, source string) []Candidate {
	base := baseConfidence(c)
	reason := "Observed CPE"
	if base == Low {
		reason = "Observed CPE without a specific version"
	}
	out := []Candidate{{CPE: c, Confidence: base, Source: source, Reason: reason}}
	for _, a := range r.aliases[key(c.Part, c.Vendor, c.Product)] {
		alt := c
		alt.Vendor, alt.Product = a.CanonicalVendor, a.CanonicalProduct
		out = append(out, Candidate{
			CPE:        alt,
			Confidence: lower(base, Confidence(a.Confidence)),
			Source:     "alias:" + a.Source,
			Reason: fmt.Sprintf("Curated alias %s:%s -> %s:%s (NVD records this software under %s)",
				c.Vendor, c.Product, a.CanonicalVendor, a.CanonicalProduct, a.CanonicalVendor),
		})
	}
	return out
}

// productNotes are caveats about how NVD records specific products.
var productNotes = map[string]string{
	"microsoft:internet_information_services": "NVD has recorded IIS vulnerabilities against Microsoft Windows " +
		"CPEs since about 2017, so results for the IIS CPE are incomplete. Assess the Windows host itself.",
}

// Notes returns caveats for the products among the candidates.
func Notes(cands []Candidate) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		k := c.CPE.Vendor + ":" + c.CPE.Product
		if n, ok := productNotes[k]; ok && !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	return out
}

// BackportNotePrefix starts the note attached to distribution-packaged
// services; reports drop it once distribution advisories were evaluated.
const BackportNotePrefix = "Distribution package detected"

// Observation is a service as reported by a discovery tool.
type Observation struct {
	Product   string
	Version   string
	ExtraInfo string
	OSType    string
	CPEs      []string
	// HTTP evidence keyed by source: "server", "generator", "title",
	// "x_powered_by", or "header:<lower-case name>". Populated for HTTP
	// services from NSE script output, used to identify the web application
	// behind a generic web server (see AddHTTPApps).
	HTTP map[string]string
}

// Resolution is the outcome of resolving an Observation.
type Resolution struct {
	// OSComponent is set ("windows") when the service is an operating-system
	// built-in whose vulnerabilities NVD records against the OS itself.
	OSComponent  string
	Candidates   []Candidate
	PlatformCPEs []string   // OS/hardware CPEs reported with the service, not queried
	Distro       DistroInfo // detected distribution packaging (zero value: none)
	Notes        []string
}

// DistroInfo describes distribution packaging evident from an observation.
type DistroInfo struct {
	Name     string // display name, e.g. "Ubuntu"
	Key      string // advisory data key, e.g. "ubuntu"
	Revision string // Debian package revision when visible, e.g. "3ubuntu13.18"
	// Inferred: not seen on this service itself but on other services of the
	// same host (e.g. RHEL's OpenSSH banner names no distribution).
	Inferred bool
}

// Detected reports whether any distribution packaging was seen.
func (d DistroInfo) Detected() bool { return d.Name != "" }

// Label is a short description, e.g. "Ubuntu package 3ubuntu13.18".
func (d DistroInfo) Label() string {
	if d.Revision != "" {
		return d.Name + " package " + d.Revision
	}
	if d.Inferred {
		return d.Name + " (inferred from other services on the host)"
	}
	return d.Name
}

// ResolveObservation derives candidate identities from a reported service.
func (r *Resolver) ResolveObservation(o Observation, source string) Resolution {
	var res Resolution
	for _, raw := range o.CPEs {
		c, err := cpe.Parse(raw)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("Ignored malformed CPE %q: %v", raw, err))
			continue
		}
		if c.Part != "a" {
			res.PlatformCPEs = append(res.PlatformCPEs, c.String())
			continue
		}
		if !cpe.IsSpecific(c.Vendor) || !cpe.IsSpecific(c.Product) {
			res.Notes = append(res.Notes, fmt.Sprintf("Ignored CPE %s without a specific vendor and product", c))
			continue
		}
		res.Candidates = append(res.Candidates, r.ResolveCPE(c, source)...)
	}
	// HTTP evidence identifies the web application behind the server; these
	// are additive (the web-server CPE, if any, is kept) and, when present,
	// mean the service is identified rather than falling to a name guess.
	if appCands, appNotes := r.httpAppCandidates(o); len(appCands) > 0 {
		res.Candidates = append(res.Candidates, appCands...)
		res.Notes = append(res.Notes, appNotes...)
	}
	var named []database.ProductName
	if p := strings.TrimSpace(o.Product); p != "" {
		named = r.lookupName(p)
	}
	for _, n := range named {
		if n.Kind == "os_component" {
			res.OSComponent = n.OS
			note := "Windows component: covered by the host's Windows build assessment " +
				"(NVD records its vulnerabilities against Windows itself)."
			if len(res.Candidates) > 0 {
				note = "Windows component: NVD records most of its vulnerabilities against Windows itself, so results " +
					"for this CPE are incomplete; see the host's Windows build assessment."
			}
			if n.Note != "" {
				note += " " + n.Note
			}
			res.Notes = append(res.Notes, note)
			break
		}
	}
	if len(res.Candidates) == 0 && res.OSComponent == "" {
		cands, notes := nameCandidates(o, named)
		res.Candidates = append(res.Candidates, cands...)
		res.Notes = append(res.Notes, notes...)
	}
	switch {
	case res.OSComponent != "":
	case len(res.Candidates) == 0 && o.Product != "":
		res.Notes = append(res.Notes, fmt.Sprintf(
			"No application CPE reported for %q and the name is not in the curated product-name map, so it was not assessed.",
			strings.TrimSpace(o.Product+" "+o.Version)))
	case len(res.Candidates) == 0:
		res.Notes = append(res.Notes, "Service responded but was not identified (no product or CPE), so it was not assessed.")
	}
	res.Distro = DetectDistro(o, res.PlatformCPEs)
	stripDebRevision(res.Candidates, res.Distro.Revision)
	if res.Distro.Detected() {
		res.Notes = append(res.Notes, fmt.Sprintf(
			BackportNotePrefix+" (%s): the vendor may have backported security fixes without "+
				"changing the upstream version, so upstream-version matches may be false positives.", res.Distro.Label()))
	}
	res.Notes = append(res.Notes, Notes(res.Candidates)...)
	return res
}

// distroMarkers maps lower-case markers in version/extra-info text to a
// distribution. Order matters: the first match wins.
var distroMarkers = []struct{ marker, name, key string }{
	{"ubuntu", "Ubuntu", "ubuntu"},
	{"debian", "Debian", "debian"},
	{"deb1", "Debian", "debian"}, // e.g. OpenSSH "9.2p1 Debian 2+deb12u3"
	{"red hat", "Red Hat", "redhat"},
	{"rhel", "Red Hat", "redhat"},
	{"centos", "CentOS", "centos"},
	{"rocky", "Rocky Linux", "rocky"},
	{"almalinux", "AlmaLinux", "almalinux"},
	{"fedora", "Fedora", "fedora"},
	{"suse", "SUSE", "suse"},
	{"alpine", "Alpine", "alpine"},
	{"freebsd", "FreeBSD", "freebsd"},
	{".el7", "Red Hat", "redhat"}, {".el8", "Red Hat", "redhat"}, {".el9", "Red Hat", "redhat"},
}

// distroCPEs maps OS CPE vendor:product to a distribution.
var distroCPEs = map[string]struct{ name, key string }{
	"canonical:ubuntu_linux":       {"Ubuntu", "ubuntu"},
	"debian:debian_linux":          {"Debian", "debian"},
	"redhat:enterprise_linux":      {"Red Hat", "redhat"},
	"redhat:linux":                 {"Red Hat", "redhat"},
	"centos:centos":                {"CentOS", "centos"},
	"fedoraproject:fedora":         {"Fedora", "fedora"},
	"suse:linux_enterprise_server": {"SUSE", "suse"},
	"opensuse:opensuse":            {"openSUSE", "opensuse"},
	"alpinelinux:alpine_linux":     {"Alpine", "alpine"},
	"freebsd:freebsd":              {"FreeBSD", "freebsd"},
}

// dpkgDistros use Debian package versions, so a visible revision can be
// compared with advisory fixed versions.
var dpkgDistros = map[string]bool{"ubuntu": true, "debian": true}

// DetectDistro reports distribution packaging evident from the service's
// version/extra-info text or its OS CPEs.
func DetectDistro(o Observation, platformCPEs []string) DistroInfo {
	text := strings.ToLower(o.Version + " " + o.ExtraInfo)
	for _, m := range distroMarkers {
		if strings.Contains(text, m.marker) {
			d := DistroInfo{Name: m.name, Key: m.key}
			if dpkgDistros[m.key] {
				d.Revision = debRevision(o.Version)
			}
			return d
		}
	}
	for _, raw := range platformCPEs {
		c, err := cpe.Parse(raw)
		if err != nil {
			continue
		}
		if d, ok := distroCPEs[c.Vendor+":"+c.Product]; ok {
			return DistroInfo{Name: d.name, Key: d.key}
		}
	}
	return DistroInfo{}
}

// debRevision extracts the Debian/Ubuntu package revision from an observed
// version, whether the banner gives it space-separated as Nmap does for
// OpenSSH ("8.4p1 Debian 5+deb11u7") or bakes the whole package version into
// one token ("9.18.39-0ubuntu0.24.04.7", "1:9.6p1-3ubuntu13.18"). It returns
// "" when there is no revision. A revision must contain a digit, so an
// upstream hyphen suffix like "1.0-beta" is not mistaken for one.
func debRevision(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	if len(f) >= 3 {
		if r := f[len(f)-1]; validRevision(r) && hasDigit(r) {
			return r
		}
	}
	if evr, err := version.ParseDeb(f[0]); err == nil && evr.Revision != "" && hasDigit(evr.Revision) {
		return evr.Revision
	}
	return ""
}

func hasDigit(s string) bool {
	return strings.ContainsAny(s, "0123456789")
}

func validRevision(rev string) bool {
	_, err := version.ParseDeb("0-" + rev)
	return err == nil
}

// stripDebRevision rewrites application candidate CPE versions that carry the
// detected Debian/Ubuntu package revision (e.g. Nmap's single-token
// "9.18.39-0ubuntu0.24.04.7") down to the clean upstream version ("9.18.39").
// The full package version is neither a valid upstream for NVD rule matching
// (the comparator rejects it) nor a release key for advisory lookup; the
// revision is kept separately on the DistroInfo. Only a candidate whose
// version carries exactly this revision is touched, so clean CPEs (OpenSSH's
// "9.6p1") and unrelated versions are left alone.
func stripDebRevision(cands []Candidate, revision string) {
	if revision == "" {
		return
	}
	for i := range cands {
		c := &cands[i].CPE
		if c.Part != "a" || !cpe.IsSpecific(c.Version) {
			continue
		}
		evr, err := version.ParseDeb(cpe.Unescape(c.Version))
		if err != nil || evr.Revision != revision {
			continue
		}
		cands[i].CPE.Version = cpe.EscapeValue(evr.Upstream)
	}
}
