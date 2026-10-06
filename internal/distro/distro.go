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
	"slices"
	"strings"

	"offline-vulndb/internal/database"
	"offline-vulndb/internal/version"
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
}

// Target describes the observed software for advisory lookup.
type Target struct {
	Distro      string   // advisory data key, e.g. "ubuntu"
	DistroName  string   // display name, e.g. "Ubuntu"
	Upstream    string   // observed upstream version, e.g. "9.6p1"
	Revision    string   // package revision if visible, e.g. "3ubuntu13.18"
	Packages    []string // candidate source packages (curated map)
	ReleaseHint string   // release established from other evidence on the same host
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
	Target     Target   `json:"-"`
	Status     string   `json:"status"`
	Releases   []string `json:"releases,omitempty"`
	Package    string   `json:"package,omitempty"`
	Installed  string   `json:"installed_version,omitempty"`
	Reason     string   `json:"reason"`
	candidates []candidate
	exact      bool // release established from an exact published package version
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
	seen := map[string]bool{}
	var cands []candidate
	for _, v := range vers {
		k := v.Release + "/" + v.Package
		if seen[k] {
			continue
		}
		seen[k] = true
		cd := candidate{release: v.Release, pkg: v.Package}
		if t.Revision != "" {
			cd.installed = epochOf(v.Version) + t.Upstream + "-" + t.Revision
		}
		cands = append(cands, cd)
	}
	if t.ReleaseHint != "" {
		var hinted []candidate
		for _, cd := range cands {
			if cd.release == t.ReleaseHint {
				hinted = append(hinted, cd)
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
		how := fmt.Sprintf("%s %s ships in %s %s", cands[0].pkg, t.Upstream, t.DistroName, cands[0].release)
		switch {
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
	row, ok := pickRow(cd.advisories[cve], c.Target.Revision)
	if !ok {
		v.Status = NoData
		v.Reason = fmt.Sprintf("%s has no entry for %s in %s/%s (usually not affected, or not yet assessed)",
			c.Target.DistroName, cve, cd.release, cd.pkg)
		return v
	}
	v.Channel, v.Advisory, v.FixedVersion = row.Channel, row.AdvisoryID, row.FixedVersion
	where := fmt.Sprintf("%s %s", c.Target.DistroName, cd.release)
	if row.Channel == "pro" {
		where += " (Ubuntu Pro/ESM)"
	}
	if row.FixedVersion == "" {
		v.Status = NoFix
		v.Reason = fmt.Sprintf("%s lists %s as affected with no fix released (may still be awaiting triage)", where, cd.pkg)
		return v
	}
	if cd.installed != "" {
		cmp, err := (version.Dpkg{}).Compare(cd.installed, row.FixedVersion)
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
	if slices.Contains(row.AffectedUpstreams, c.Target.Upstream) {
		v.Status = FixAvailable
		v.Reason = fmt.Sprintf("fixed in %s in %s; the installed package revision is not visible, so the host "+
			"is patched only if it runs %s or later", where, row.FixedVersion, row.FixedVersion)
	} else {
		v.Status = Fixed
		v.Reason = fmt.Sprintf("%s lists no affected %s %s package (fixed from %s)", where, cd.pkg, c.Target.Upstream, row.FixedVersion)
	}
	return v
}

// Additional returns definitive findings the distribution data adds beyond
// the given CVEs: with the installed version known and a single release,
// every advisory whose fixed version is newer than the installed package.
// "No fix" rows are not added on their own, because they include CVEs still
// awaiting triage.
func (c *Context) Additional(known map[string]bool) []Verdict {
	if c.Status != Resolved || c.Installed == "" {
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

// pickRow chooses the advisory row for the host's channel: Ubuntu Pro (ESM)
// when the installed revision is an ESM build or no standard row exists.
func pickRow(rows []database.DistroAdvisory, revision string) (database.DistroAdvisory, bool) {
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
