// Package distro evaluates candidate vulnerabilities against distribution
// security advisories (e.g. Ubuntu's), which record when a distribution
// shipped a fix in its own package versions. Upstream version matching
// cannot see backported fixes; this package can, as far as the observed
// evidence allows:
//
//   - with the package revision visible (Nmap shows it for OpenSSH:
//     "9.6p1 Ubuntu 3ubuntu13.18") the installed version is compared with
//     the fixed version: FIXED or VULNERABLE;
//   - with only the distribution name visible, the release is inferred from
//     the upstream version and the verdict is about the release: FIXED (no
//     package of that upstream version in the release is affected),
//     FIX_AVAILABLE (fixed in a later package; patched only if updated) or
//     NO_FIX;
//   - a CVE the distribution does not list for the package and release is
//     NO_DATA. Absence usually means "not affected" but is never treated
//     as proof.
package distro

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"bunyip/internal/database"
	"bunyip/internal/version"
)

// Status is a distribution advisory verdict for one CVE.
type Status string

const (
	Fixed        Status = "FIXED"         // the installed/observed package includes the fix
	Vulnerable   Status = "VULNERABLE"    // installed package is older than the fixed version
	FixAvailable Status = "FIX_AVAILABLE" // fixed in this release; installed revision not visible
	NoFix        Status = "NO_FIX"        // distribution lists the release as affected, no fix released
	NoData       Status = "NO_DATA"       // no usable advisory data for this CVE/package/release
)

// Verdict is the distribution view of one CVE.
type Verdict struct {
	Status           Status `json:"status"`
	Distro           string `json:"distro"`
	Release          string `json:"release,omitempty"`
	Package          string `json:"package,omitempty"`
	Channel          string `json:"channel,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	Advisory         string `json:"advisory,omitempty"`
	CVE              string `json:"-"`
	Reason           string `json:"reason"`
}

// Store is the advisory data the evaluation needs.
type Store interface {
	HasDistroData(ctx context.Context, distro string) (bool, error)
	PackageVersionsByUpstream(ctx context.Context, distro string, packages []string, upstream string) ([]database.PackageVersion, error)
	DistroAdvisories(ctx context.Context, distro, pkg, release string) ([]database.DistroAdvisory, error)
	PackagesInRelease(ctx context.Context, distro, release string, packages []string) ([]string, error)
	ReleaseLifecycle(ctx context.Context, distro, release string) (*database.Lifecycle, error)
}

// Now is the clock used for end-of-life decisions (replaceable in tests).
var Now = time.Now

// releaseInRevision extracts a release encoded in package revisions:
// Debian security/point updates ("2+deb12u3" -> "12") and Ubuntu
// per-release uploads ("0ubuntu0.22.04.2" -> "22.04").
var releaseInRevision = map[string]*regexp.Regexp{
	"debian":    regexp.MustCompile(`[+~]deb(\d+)u\d+`),
	"ubuntu":    regexp.MustCompile(`ubuntu0\.(\d\d\.\d\d)`),
	"redhat":    regexp.MustCompile(`[._+]el(\d+)`), // "38.el9_4.1", "module+el8.4.0"
	"rocky":     regexp.MustCompile(`[._+]el(\d+)`),
	"almalinux": regexp.MustCompile(`[._+]el(\d+)`),
}

// Scheme orders package versions of one packaging system.
type Scheme struct {
	Parse   func(string) (version.EVR, error)
	Compare func(a, b version.EVR) int
}

var (
	dpkgScheme = Scheme{version.ParseDeb, version.CompareDeb}
	rpmScheme  = Scheme{version.ParseRPM, version.CompareRPM}
)

// schemes maps advisory data keys to their package version ordering.
var schemes = map[string]Scheme{
	"debian": dpkgScheme, "ubuntu": dpkgScheme,
	"redhat": rpmScheme, "rocky": rpmScheme, "almalinux": rpmScheme,
}

func schemeFor(distro string) Scheme {
	if s, ok := schemes[distro]; ok {
		return s
	}
	return dpkgScheme
}

func (s Scheme) compare(a, b string) (int, error) {
	va, err := s.Parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := s.Parse(b)
	if err != nil {
		return 0, err
	}
	return s.Compare(va, vb), nil
}

// streamOf is the module stream (major.minor) of an upstream version.
func streamOf(upstream string) string {
	parts := strings.SplitN(upstream, ".", 3)
	if len(parts) < 2 {
		return upstream
	}
	return parts[0] + "." + parts[1]
}

// ReleaseFromRevision returns the release a package revision encodes, if any.
func ReleaseFromRevision(distro, revision string) string {
	if re := releaseInRevision[distro]; re != nil {
		if m := re.FindStringSubmatch(revision); m != nil {
			return m[1]
		}
	}
	return ""
}

// Target describes the observed software for advisory lookup.
type Target struct {
	Distro      string   // advisory data key, e.g. "ubuntu"
	DistroName  string   // display name, e.g. "Ubuntu"
	Upstream    string   // observed upstream version, e.g. "9.6p1"
	Revision    string   // package revision if visible, e.g. "3ubuntu13.18"
	Packages    []string // candidate source packages (curated map)
	ReleaseHint string   // release established from other evidence on the same host
	// NoHintFallback: do not assume the host's release when the observed
	// version is unknown to the data (used when the distribution itself was
	// only inferred from other services: the software may be self-built).
	NoHintFallback bool
	Note           string // extra context shown in reasons, e.g. CentOS evaluated as Red Hat
	// LifecycleDistro is the distribution whose lifecycle applies (e.g.
	// "centos" while advisories come from "redhat"); defaults to Distro.
	LifecycleDistro string
}

// Resolution states.
const (
	Resolved       = "RESOLVED"        // exactly one release/package
	Ambiguous      = "AMBIGUOUS"       // several candidate releases
	UnknownRelease = "UNKNOWN_RELEASE" // upstream version not known in any release
	Unmapped       = "UNMAPPED"        // product has no source package mapping
	NoDataSource   = "NO_DATA_SOURCE"  // no advisories loaded for the distribution
)

type candidate struct {
	release, pkg string
	installed    string // full installed version when the revision is known
	advisories   map[string][]database.DistroAdvisory
}

// Context is a resolved advisory context for one observed service.
type Context struct {
	Target    Target   `json:"-"`
	Status    string   `json:"status"`
	Releases  []string `json:"releases,omitempty"`
	Package   string   `json:"package,omitempty"`
	Installed string   `json:"installed_version,omitempty"`
	Reason    string   `json:"reason"`
	// Lifecycle of the resolved release; EndOfLife is set (to the date) when
	// regular security support has ended, so missing advisory data and
	// unfixed issues should be read in that light.
	Lifecycle    *database.Lifecycle `json:"lifecycle,omitempty"`
	EndOfLife    string              `json:"end_of_life,omitempty"`
	candidates   []candidate
	exact        bool   // release established from an exact package version or revision
	fromRevision string // release encoded in the package revision, if that is how it was found
}

// Resolve determines the release and package the observation belongs to and
// loads the relevant advisories.
func Resolve(ctx context.Context, store Store, t Target) (*Context, error) {
	c := &Context{Target: t}
	if len(t.Packages) == 0 {
		c.Status, c.Reason = Unmapped, "no distribution source package is mapped for this product"
		return c, nil
	}
	ok, err := store.HasDistroData(ctx, t.Distro)
	if err != nil {
		return nil, err
	}
	if !ok {
		c.Status, c.Reason = NoDataSource, fmt.Sprintf("no %s advisory data in this database", t.DistroName)
		return c, nil
	}
	vers, err := store.PackageVersionsByUpstream(ctx, t.Distro, t.Packages, t.Upstream)
	if err != nil {
		return nil, err
	}
	// With a visible revision, prefer releases that published that exact
	// version; otherwise any release that shipped the upstream version.
	byExact := false
	if t.Revision != "" {
		var exact []database.PackageVersion
		for _, v := range vers {
			if stripEpoch(v.Version) == t.Upstream+"-"+t.Revision {
				exact = append(exact, v)
			}
		}
		if len(exact) > 0 {
			vers, byExact = exact, true
		}
	}
	if byExact {
		c.exact = true
	}
	// One candidate per release; if several mapped packages (e.g. mariadb and
	// mariadb-server) match, prefer the earliest in the curated order.
	slices.SortStableFunc(vers, func(a, b database.PackageVersion) int {
		return slices.Index(t.Packages, a.Package) - slices.Index(t.Packages, b.Package)
	})
	seen := map[string]bool{}
	var cands []candidate
	for _, v := range vers {
		if seen[v.Release] {
			continue
		}
		seen[v.Release] = true
		cd := candidate{release: v.Release, pkg: v.Package}
		if t.Revision != "" {
			cd.installed = epochOf(v.Version) + t.Upstream + "-" + t.Revision
		}
		cands = append(cands, cd)
	}
	// A revision that encodes its release ("+deb12u3") is definitive, even
	// when that exact version is missing from the advisory data.
	if rel := ReleaseFromRevision(t.Distro, t.Revision); rel != "" {
		var inRel []candidate
		for _, cd := range cands {
			if cd.release == rel {
				inRel = append(inRel, cd)
			}
		}
		if len(inRel) == 0 {
			pkgs, err := store.PackagesInRelease(ctx, t.Distro, rel, t.Packages)
			if err != nil {
				return nil, err
			}
			if p := firstInOrder(t.Packages, pkgs); p != "" {
				inRel = append(inRel, candidate{release: rel, pkg: p})
			}
		}
		if len(inRel) > 0 {
			cands, byExact, c.exact = inRel, true, true
			c.fromRevision = rel
		}
	}
	if t.ReleaseHint != "" {
		var hinted []candidate
		for _, cd := range cands {
			if cd.release == t.ReleaseHint {
				hinted = append(hinted, cd)
			}
		}
		if len(hinted) == 0 && len(cands) == 0 && !t.NoHintFallback {
			// The observed version is not in the data, but the host's release
			// is known from another service: use the package in that release.
			pkgs, err := store.PackagesInRelease(ctx, t.Distro, t.ReleaseHint, t.Packages)
			if err != nil {
				return nil, err
			}
			if p := firstInOrder(t.Packages, pkgs); p != "" {
				hinted = append(hinted, candidate{release: t.ReleaseHint, pkg: p})
			}
		}
		if len(hinted) > 0 {
			cands = hinted
		}
	}
	for i := range cands {
		rows, err := store.DistroAdvisories(ctx, t.Distro, cands[i].pkg, cands[i].release)
		if err != nil {
			return nil, err
		}
		cands[i].advisories = map[string][]database.DistroAdvisory{}
		for _, r := range rows {
			cands[i].advisories[r.CVEID] = append(cands[i].advisories[r.CVEID], r)
			if t.Revision != "" && cands[i].installed == "" && r.FixedVersion != "" {
				// Epoch from the distribution's own versions of the package.
				cands[i].installed = epochOf(r.FixedVersion) + t.Upstream + "-" + t.Revision
			}
		}
		c.Releases = append(c.Releases, cands[i].release)
	}
	c.candidates = cands
	switch len(cands) {
	case 0:
		c.Status = UnknownRelease
		c.Reason = fmt.Sprintf("%s advisory data does not list %s %s in any release",
			t.DistroName, strings.Join(t.Packages, "/"), t.Upstream)
	case 1:
		c.Status, c.Package, c.Installed = Resolved, cands[0].pkg, cands[0].installed
		if err := c.lifecycle(ctx, store, cands[0].release); err != nil {
			return nil, err
		}
		how := fmt.Sprintf("%s %s ships in %s %s", cands[0].pkg, t.Upstream, t.DistroName, cands[0].release)
		switch {
		case c.fromRevision != "":
			how = fmt.Sprintf("package revision %s encodes %s %s", t.Revision, t.DistroName, c.fromRevision)
		case byExact:
			how = fmt.Sprintf("package version %s is published in %s %s", stripEpoch(cands[0].installed), t.DistroName, cands[0].release)
		case t.ReleaseHint == cands[0].release:
			how += " (release confirmed by another service on the host)"
		}
		c.Reason = how
	default:
		c.Status = Ambiguous
		c.Reason = fmt.Sprintf("%s %s ships in several %s releases (%s)", strings.Join(t.Packages, "/"), t.Upstream,
			t.DistroName, strings.Join(c.Releases, ", "))
	}
	return c, nil
}

// lifecycle records whether the resolved release is past end of life.
func (c *Context) lifecycle(ctx context.Context, store Store, release string) error {
	key := c.Target.LifecycleDistro
	if key == "" {
		key = c.Target.Distro
	}
	l, err := store.ReleaseLifecycle(ctx, key, release)
	if err != nil || l == nil {
		return err
	}
	c.Lifecycle = l
	if eol, err := time.Parse("2006-01-02", l.EOL); err == nil && Now().After(eol.Add(24*time.Hour)) {
		c.EndOfLife = l.EOL
	}
	return nil
}

// EOLNote describes an end-of-life release for operators.
func (c *Context) EOLNote() string {
	if c.EndOfLife == "" {
		return ""
	}
	s := fmt.Sprintf("%s %s reached end of life on %s: no further regular security updates or advisory data",
		c.Target.DistroName, c.Releases[0], c.EndOfLife)
	if l := c.Lifecycle; l.Extended != "" {
		s += " (fixes only via " + l.Extended
		if l.ExtendedUntil != "" {
			s += " until " + l.ExtendedUntil
		}
		s += ")"
	}
	return s
}

// DefinitiveRelease returns the release when it was established from an
// exact package version (strong enough to inform other services on the host).
func (c *Context) DefinitiveRelease() string {
	if c.Status == Resolved && c.exact {
		return c.candidates[0].release
	}
	return ""
}

// Verdict evaluates one CVE.
func (c *Context) Verdict(cve string) Verdict {
	base := Verdict{Distro: c.Target.DistroName, CVE: cve}
	switch c.Status {
	case Unmapped, NoDataSource, UnknownRelease:
		base.Status, base.Reason = NoData, c.Reason
		return base
	}
	var vs []Verdict
	for _, cd := range c.candidates {
		vs = append(vs, c.evaluate(cd, cve))
	}
	if len(vs) == 1 {
		return vs[0]
	}
	// Ambiguous release: only conclude when every candidate release agrees.
	for _, v := range vs[1:] {
		if v.Status != vs[0].Status {
			var parts []string
			for _, x := range vs {
				parts = append(parts, x.Release+": "+string(x.Status))
			}
			base.Status = NoData
			base.Reason = "release ambiguous and the releases disagree (" + strings.Join(parts, ", ") + ")"
			return base
		}
	}
	v := vs[0]
	v.Release = strings.Join(c.Releases, "|")
	v.Reason = "all candidate releases agree: " + v.Reason
	return v
}

func (c *Context) evaluate(cd candidate, cve string) Verdict {
	v := Verdict{Distro: c.Target.DistroName, Release: cd.release, Package: cd.pkg, CVE: cve,
		InstalledVersion: cd.installed}
	rows := cd.advisories[cve]
	row, ok := pickRow(rows, c.Target.Revision, c.Target.Upstream)
	if !ok {
		v.Status = NoData
		if streams := moduleStreams(rows); len(streams) > 0 {
			v.Reason = fmt.Sprintf("%s fixed %s only in other module streams of %s in %s (%s); the observed %s "+
				"is in stream %s", c.Target.DistroName, cve, cd.pkg, cd.release, strings.Join(streams, ", "),
				c.Target.Upstream, streamOf(c.Target.Upstream))
		} else {
			v.Reason = fmt.Sprintf("%s has no entry for %s in %s/%s (usually not affected, or not yet assessed)",
				c.Target.DistroName, cve, cd.release, cd.pkg)
		}
		if c.EndOfLife != "" {
			v.Reason += "; " + c.EOLNote()
		}
		return v
	}
	v.Channel, v.Advisory, v.FixedVersion = row.Channel, row.AdvisoryID, row.FixedVersion
	where := fmt.Sprintf("%s %s", c.Target.DistroName, cd.release)
	if row.Channel == "pro" {
		where += " (Ubuntu Pro/ESM)"
	}
	if row.Stream != "" {
		where += " module stream " + row.Stream
	}
	if c.Target.Note != "" {
		where += " [" + c.Target.Note + "]"
	}
	scheme := schemeFor(c.Target.Distro)
	if row.FixedVersion == "" {
		v.Status = NoFix
		v.Reason = fmt.Sprintf("%s lists %s as affected with no fix released", where, cd.pkg) + urgencyNote(row.Urgency)
		return v
	}
	if cd.installed != "" {
		cmp, err := scheme.compare(cd.installed, row.FixedVersion)
		switch {
		case err != nil:
			v.Status, v.Reason = NoData, fmt.Sprintf("cannot compare %s with %s: %v", cd.installed, row.FixedVersion, err)
		case cmp >= 0:
			v.Status = Fixed
			v.Reason = fmt.Sprintf("installed %s includes the fix (fixed in %s in %s)", cd.installed, row.FixedVersion, where)
		default:
			v.Status = Vulnerable
			v.Reason = fmt.Sprintf("installed %s is older than the fixed version %s in %s", cd.installed, row.FixedVersion, where)
		}
		return v
	}
	// Revision not visible: decide from the upstream versions where that is
	// conclusive for every package of the observed upstream version.
	fixed, err := scheme.Parse(row.FixedVersion)
	if err != nil {
		v.Status, v.Reason = NoData, fmt.Sprintf("cannot parse fixed version %s: %v", row.FixedVersion, err)
		return v
	}
	cmp := scheme.Compare(version.EVR{Epoch: fixed.Epoch, Upstream: c.Target.Upstream},
		version.EVR{Epoch: fixed.Epoch, Upstream: fixed.Upstream})
	switch {
	case cmp > 0:
		v.Status = Fixed
		v.Reason = fmt.Sprintf("%s fixed this in %s; every %s %s package is newer", where, row.FixedVersion, cd.pkg, c.Target.Upstream)
	case cmp < 0:
		v.Status = Vulnerable
		v.Reason = fmt.Sprintf("%s fixed this in %s, a newer upstream version than the observed %s",
			where, row.FixedVersion, c.Target.Upstream)
	case len(row.AffectedUpstreams) > 0 && !slices.Contains(row.AffectedUpstreams, c.Target.Upstream):
		v.Status = Fixed
		v.Reason = fmt.Sprintf("%s lists no affected %s %s package (fixed from %s)", where, cd.pkg, c.Target.Upstream, row.FixedVersion)
	default:
		v.Status = FixAvailable
		v.Reason = fmt.Sprintf("fixed in %s in %s; the installed package revision is not visible, so the host "+
			"is patched only if it runs %s or later", where, row.FixedVersion, row.FixedVersion)
	}
	return v
}

// urgencyNote explains a distribution's own rating of an unfixed issue.
func urgencyNote(u string) string {
	switch u {
	case "":
		return " (may still be awaiting triage)"
	case "unimportant":
		return "; rated unimportant by the distribution, which does not plan to fix it"
	case "end-of-life":
		return "; the package is no longer supported by the distribution in this release"
	case "not yet assigned":
		return " (urgency not yet assigned; may still be awaiting triage)"
	default:
		return fmt.Sprintf(" (distribution urgency: %s)", u)
	}
}

// Additional returns definitive findings the distribution data adds beyond
// the given CVEs, for a single resolved release: every advisory whose fixed
// version is newer than the installed package (or, with the revision not
// visible, whose fix came in a newer upstream version than observed).
// "No fix" rows are not added on their own, because they include CVEs still
// awaiting triage and issues the distribution chose not to fix.
func (c *Context) Additional(known map[string]bool) []Verdict {
	if c.Status != Resolved {
		return nil
	}
	var out []Verdict
	cd := c.candidates[0]
	cves := make([]string, 0, len(cd.advisories))
	for cve := range cd.advisories {
		cves = append(cves, cve)
	}
	slices.Sort(cves)
	for _, cve := range cves {
		if known[cve] {
			continue
		}
		if v := c.evaluate(cd, cve); v.Status == Vulnerable {
			out = append(out, v)
		}
	}
	return out
}

// pickRow chooses the advisory row that applies to the observation:
//   - module-stream rows (RHEL AppStream) apply only to the same stream;
//   - the host's channel: Ubuntu Pro (ESM) when the installed revision is an
//     ESM build or no standard row exists.
func pickRow(rows []database.DistroAdvisory, revision, upstream string) (database.DistroAdvisory, bool) {
	var applicable []database.DistroAdvisory
	for _, r := range rows {
		if r.Stream == "" || r.Stream == streamOf(upstream) {
			applicable = append(applicable, r)
		}
	}
	// Prefer the matching module stream over a stream-less row.
	for _, r := range applicable {
		if r.Stream != "" {
			return r, true
		}
	}
	rows = applicable
	wantPro := strings.Contains(revision, "esm")
	var std, pro *database.DistroAdvisory
	for i := range rows {
		switch rows[i].Channel {
		case "pro":
			pro = &rows[i]
		default:
			std = &rows[i]
		}
	}
	switch {
	case wantPro && pro != nil:
		return *pro, true
	case std != nil:
		return *std, true
	case pro != nil:
		return *pro, true
	}
	return database.DistroAdvisory{}, false
}

// moduleStreams lists the module streams present in rows.
func moduleStreams(rows []database.DistroAdvisory) []string {
	var out []string
	for _, r := range rows {
		if r.Stream != "" && !slices.Contains(out, r.Stream) {
			out = append(out, r.Stream)
		}
	}
	slices.Sort(out)
	return out
}

func firstInOrder(order, have []string) string {
	for _, p := range order {
		if slices.Contains(have, p) {
			return p
		}
	}
	return ""
}

func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

func epochOf(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i+1]
	}
	return ""
}
