package build

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/version"
)

// Distribution security advisories from OSV.dev ecosystem exports, ported from
// the Python updater's osv.py. Only packages in the curated CPE->package map
// are stored; releases absent from a record mean "no data", never "not
// affected".

// Distro describes one distribution's OSV ecosystem and how to read it.
type Distro struct {
	Name               string // our key, e.g. "ubuntu"
	Ecosystem          string // OSV export name, e.g. "Ubuntu"
	RecordPrefix       string // per-CVE record id prefix (primary source); "" if none
	standard           *regexp.Regexp
	pro                *regexp.Regexp
	AdvisoryPrefixes   []string
	unfixedRelSpecific bool // no-fix `versions` list only that release (Ubuntu) vs whole archive (Debian)
	fixedInRelease     bool // a per-CVE fixed version is always a package of that release
	releaseInVersion   *regexp.Regexp
	urgencyKey         string
	scheme             string // "dpkg" or "rpm"
}

func (d Distro) compare(a, b string) (int, error) {
	if d.scheme == "rpm" {
		va, err := version.ParseRPM(a)
		if err != nil {
			return 0, err
		}
		vb, err := version.ParseRPM(b)
		if err != nil {
			return 0, err
		}
		return version.CompareRPM(va, vb), nil
	}
	va, err := version.ParseDeb(a)
	if err != nil {
		return 0, err
	}
	vb, err := version.ParseDeb(b)
	if err != nil {
		return 0, err
	}
	return version.CompareDeb(va, vb), nil
}

// Distros is the supported set, keyed by our distro name.
var Distros = map[string]Distro{
	"ubuntu": {
		Name: "ubuntu", Ecosystem: "Ubuntu", RecordPrefix: "UBUNTU-CVE-",
		standard:           regexp.MustCompile(`^Ubuntu:(\d\d\.\d\d)(?::LTS)?$`),
		pro:                regexp.MustCompile(`^Ubuntu:Pro:(\d\d\.\d\d):LTS$`),
		releaseInVersion:   regexp.MustCompile(`ubuntu0\.(\d\d\.\d\d)`),
		urgencyKey:         "ubuntu_priority",
		unfixedRelSpecific: true, fixedInRelease: true, scheme: "dpkg",
	},
	"debian": {
		Name: "debian", Ecosystem: "Debian", RecordPrefix: "DEBIAN-CVE-",
		standard:           regexp.MustCompile(`^Debian:(\d+(?:\.\d+)?)$`),
		AdvisoryPrefixes:   []string{"DSA-", "DLA-"},
		releaseInVersion:   regexp.MustCompile(`[+~]deb(\d+)u\d+`),
		urgencyKey:         "urgency",
		unfixedRelSpecific: false, fixedInRelease: false, scheme: "dpkg",
	},
	"redhat": {
		Name: "redhat", Ecosystem: "Red Hat", RecordPrefix: "",
		standard:           regexp.MustCompile(`^Red Hat:enterprise_linux:(\d+)(?:\.\d+)?(?:::\w+)?$`),
		AdvisoryPrefixes:   []string{"RHSA-", "RHBA-", "RHEA-"},
		releaseInVersion:   regexp.MustCompile(`[._+]el(\d+)`),
		unfixedRelSpecific: true, fixedInRelease: true, scheme: "rpm",
	},
	"rocky": {
		Name: "rocky", Ecosystem: "Rocky Linux", RecordPrefix: "",
		standard:           regexp.MustCompile(`^Rocky Linux:(\d+)$`),
		AdvisoryPrefixes:   []string{"RLSA-", "RLBA-", "RLEA-", "RXSA-"},
		releaseInVersion:   regexp.MustCompile(`[._+]el(\d+)`),
		unfixedRelSpecific: true, fixedInRelease: true, scheme: "rpm",
	},
	"almalinux": {
		Name: "almalinux", Ecosystem: "AlmaLinux", RecordPrefix: "",
		standard:           regexp.MustCompile(`^AlmaLinux:(\d+)$`),
		AdvisoryPrefixes:   []string{"ALSA-", "ALBA-", "ALEA-"},
		releaseInVersion:   regexp.MustCompile(`[._+]el(\d+)`),
		unfixedRelSpecific: true, fixedInRelease: true, scheme: "rpm",
	},
}

// AdvisoryRow is one distro_advisories row.
type AdvisoryRow struct {
	Source, AdvisoryID, CVEID, DistroName, Release, Channel string
	Codename                                                string // "" = NULL
	Package                                                 string
	FixedVersion                                            string // "" = NULL
	AffectedUpstreams                                       string
	ModifiedAt                                              string // "" = NULL
	Urgency                                                 string // "" = NULL
	Stream                                                  string
}

func (r AdvisoryRow) key() [5]string {
	return [5]string{r.CVEID, r.Release, r.Channel, r.Package, r.Stream}
}

// PackageVersion is one distro_package_versions row.
type PackageVersion struct {
	DistroName, Release, Package, Version, Upstream string
}

func upstreamOf(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i]
	}
	return v
}

func moduleStream(fixed string) string {
	if fixed == "" || !strings.Contains(fixed, ".module") {
		return ""
	}
	parts := strings.Split(upstreamOf(fixed), ".")
	if len(parts) < 2 {
		return strings.Join(parts, ".")
	}
	return parts[0] + "." + parts[1]
}

func parseEcosystem(d Distro, eco string) (release, channel string, ok bool) {
	if m := d.standard.FindStringSubmatch(eco); m != nil {
		return m[1], "standard", true
	}
	if d.pro != nil {
		if m := d.pro.FindStringSubmatch(eco); m != nil {
			return m[1], "pro", true
		}
	}
	return "", "", false
}

func codenameOf(purl string) string {
	if purl == "" {
		return ""
	}
	u, err := url.Parse(strings.Replace(purl, "pkg:", "pkg://", 1))
	if err != nil {
		return ""
	}
	return u.Query().Get("distro")
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d+$`)
var cveSearch = regexp.MustCompile(`CVE-\d{4}-\d+`)

func cveIDs(rec osvRecord, perCVE bool) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(xs []string) {
		for _, a := range xs {
			if cveRe.MatchString(a) && !seen[a] {
				seen[a] = true
				ids = append(ids, a)
			}
		}
	}
	add(rec.Upstream)
	add(rec.Aliases)
	add(rec.Related)
	if len(ids) == 0 {
		if m := cveSearch.FindString(rec.ID); m != "" {
			ids = []string{m}
		}
	}
	if perCVE && len(ids) > 1 {
		return ids[:1]
	}
	return ids
}

func (d Distro) olderThan(v, fixed string) bool {
	c, err := d.compare(v, fixed)
	return err == nil && c < 0
}

func (d Distro) versionRelease(v string) string {
	if d.releaseInVersion != nil {
		if m := d.releaseInVersion.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// --- OSV record JSON shape (fields used) ---

type osvRecord struct {
	ID        string        `json:"id"`
	Modified  string        `json:"modified"`
	Withdrawn string        `json:"withdrawn"`
	Upstream  []string      `json:"upstream"`
	Aliases   []string      `json:"aliases"`
	Related   []string      `json:"related"`
	Affected  []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	Versions          []string       `json:"versions"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

// Transformed is the result of transforming one OSV record.
type Transformed struct {
	Rows      []AdvisoryRow
	Versions  []PackageVersion
	Withdrawn bool
}

// transformOSV turns one OSV record into advisory rows for the mapped packages.
func transformOSV(rec osvRecord, d Distro, packages map[string]bool, perCVE bool) Transformed {
	var out Transformed
	if rec.Withdrawn != "" {
		out.Withdrawn = true
		return out
	}
	cves := cveIDs(rec, perCVE)
	if len(cves) == 0 {
		return out
	}
	for _, a := range rec.Affected {
		name := a.Package.Name
		if name == "" || !packages[name] {
			continue
		}
		release, channel, ok := parseEcosystem(d, a.Package.Ecosystem)
		if !ok {
			continue
		}
		fixed := ""
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if f, has := ev["fixed"]; has {
					fixed = f
				}
			}
		}
		var affected []string
		if fixed != "" {
			for _, v := range a.Versions {
				if d.olderThan(v, fixed) {
					affected = append(affected, v)
				}
			}
		} else if d.unfixedRelSpecific {
			affected = append(affected, a.Versions...)
		}
		urgency := ""
		if d.urgencyKey != "" && a.EcosystemSpecific != nil {
			if u, ok := a.EcosystemSpecific[d.urgencyKey].(string); ok {
				urgency = u
			}
		}
		for _, cve := range cves {
			out.Rows = append(out.Rows, AdvisoryRow{
				Source: "osv:" + d.Ecosystem, AdvisoryID: rec.ID, CVEID: cve, DistroName: d.Name,
				Release: release, Channel: channel, Codename: codenameOf(a.Package.Purl), Package: name,
				FixedVersion: fixed, AffectedUpstreams: joinUpstreams(affected), ModifiedAt: rec.Modified,
				Urgency: urgency, Stream: moduleStream(fixed),
			})
		}
		if channel == "standard" {
			known := append([]string(nil), affected...)
			if fixed != "" && (d.fixedInRelease || !perCVE || d.versionRelease(fixed) == release) {
				known = append(known, fixed)
			}
			for _, v := range known {
				out.Versions = append(out.Versions, PackageVersion{d.Name, release, name, v, upstreamOf(v)})
			}
		}
	}
	return out
}

func joinUpstreams(versions []string) string {
	seen := map[string]bool{}
	var ups []string
	for _, v := range versions {
		u := upstreamOf(v)
		if !seen[u] {
			seen[u] = true
			ups = append(ups, u)
		}
	}
	sort.Strings(ups)
	return strings.Join(ups, " ")
}

// iterRecords yields OSV records in a zip whose basename starts with one of
// the prefixes and ends with .json.
func iterRecords(zipPath string, prefixes []string, fn func(osvRecord) error) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		base := f.Name
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if !strings.HasSuffix(base, ".json") || !hasAnyPrefix(base, prefixes) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// --- curated package map & releases ---

// PackageMapRow is one data/distro_packages.json entry (CPE -> source package).
type PackageMapRow struct {
	Part, Vendor, Product, DistroName, Package, Source string
}

// LoadPackageMap reads data/distro_packages.json.
func LoadPackageMap(path string) ([]PackageMapRow, error) {
	data, err := curatedData(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Source   string           `json:"source"`
		Packages []map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []PackageMapRow
	seen := map[[5]string]bool{}
	for i, e := range doc.Packages {
		bits := strings.Split(asString(e["cpe"]), ":")
		if len(bits) != 3 {
			return nil, fmt.Errorf("%s: packages[%d]: cpe must be part:vendor:product", path, i)
		}
		c, err := cpe.ParsePattern(fmt.Sprintf("cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*", bits[0], bits[1], bits[2]))
		if err != nil {
			return nil, fmt.Errorf("%s: packages[%d]: %w", path, i, err)
		}
		for distro, v := range e {
			if distro == "cpe" {
				continue
			}
			if _, ok := Distros[distro]; !ok {
				return nil, fmt.Errorf("%s: packages[%d]: unknown distro %q", path, i, distro)
			}
			for _, p := range toStringSlice(v) {
				key := [5]string{c.Part, c.Vendor, c.Product, distro, p}
				if seen[key] {
					return nil, fmt.Errorf("%s: packages[%d]: duplicate %v", path, i, key)
				}
				seen[key] = true
				rows = append(rows, PackageMapRow{c.Part, c.Vendor, c.Product, distro, p, doc.Source})
			}
		}
	}
	return rows, nil
}

// ReleaseRow is one data/distro_releases.json entry.
type ReleaseRow struct {
	DistroName, Release, Codename, EOL, ExtendedUntil, Extended, Source string
}

// LoadReleases reads data/distro_releases.json (eol required, ISO dates).
func LoadReleases(path string) ([]ReleaseRow, error) {
	data, err := curatedData(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Source   string           `json:"source"`
		Releases []map[string]any `json:"releases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []ReleaseRow
	seen := map[[2]string]bool{}
	for i, r := range doc.Releases {
		distro, rel := asString(r["distro"]), asString(r["release"])
		key := [2]string{distro, rel}
		if distro == "" || rel == "" || seen[key] {
			return nil, fmt.Errorf("%s: releases[%d]: missing or duplicate distro/release", path, i)
		}
		seen[key] = true
		if asString(r["eol"]) == "" {
			return nil, fmt.Errorf("%s: releases[%d]: eol is required", path, i)
		}
		for _, f := range []string{"eol", "extended_until"} {
			if s := asString(r[f]); s != "" {
				if !isISODate(s) {
					return nil, fmt.Errorf("%s: releases[%d]: %s not YYYY-MM-DD", path, i, f)
				}
			}
		}
		rows = append(rows, ReleaseRow{distro, rel, asString(r["codename"]), asString(r["eol"]),
			asString(r["extended_until"]), asString(r["extended"]), doc.Source})
	}
	return rows, nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func toStringSlice(v any) []string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func isISODate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, c := range s {
		if i == 4 || i == 7 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
