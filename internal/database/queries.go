package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"offline-vulndb/internal/version"
)

// MatchRule is one vulnerable CPE match rule together with the structure of
// the NVD configuration it belongs to.
type MatchRule struct {
	ID         int64
	CVEID      string
	Criteria   string
	Vulnerable bool
	Range      version.Range

	// Configuration context. HasNode is false for rules imported without
	// configuration structure, which are treated as standalone.
	HasNode        bool
	NodeOperator   string // "AND" or "OR"
	NodeNegate     bool
	ConfigOperator string // "AND" or "OR"
	// AndNodeSiblings: the rule's node is AND and contains other rules.
	// AndConfigSiblings: the configuration is AND and contains other nodes.
	// Only existence matters to the matcher, so these are EXISTS checks
	// rather than counts (counting is quadratic on huge nodes such as
	// linux_kernel's).
	AndNodeSiblings   bool
	AndConfigSiblings bool
}

// CandidateRules returns vulnerable match rules whose criteria share the
// given part, vendor and product (canonical CPE values). This is only an
// indexed pre-filter; callers must still evaluate each rule in full.
//
// versionKey (version.Key of the observed version) skips exact-version rules
// for other version series; "" reads every rule.
func (s *Store) CandidateRules(ctx context.Context, part, vendor, product, versionKey string) ([]MatchRule, error) {
	// A single scan of idx_cve_matches_lookup: configuration context was
	// copied onto each rule when the database was built.
	const q = `
SELECT m.id, m.cve_id, m.criteria, m.vulnerable,
       COALESCE(m.version_start_including, ''), COALESCE(m.version_start_excluding, ''),
       COALESCE(m.version_end_including, ''),   COALESCE(m.version_end_excluding, ''),
       m.node_id IS NOT NULL, m.node_operator, m.node_negate, m.config_operator,
       m.and_node_siblings, m.and_config_siblings
FROM cve_matches m
WHERE m.criteria_part = ? AND m.criteria_vendor = ? AND m.criteria_product = ?
  AND m.vulnerable = 1 AND (? = '' OR m.version_key IN ('', ?))
ORDER BY m.cve_id, m.id`
	rows, err := s.db.QueryContext(ctx, q, part, vendor, product, versionKey, versionKey)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []MatchRule
	for rows.Next() {
		var r MatchRule
		if err := rows.Scan(&r.ID, &r.CVEID, &r.Criteria, &r.Vulnerable,
			&r.Range.StartIncluding, &r.Range.StartExcluding,
			&r.Range.EndIncluding, &r.Range.EndExcluding,
			&r.HasNode, &r.NodeOperator, &r.NodeNegate, &r.ConfigOperator,
			&r.AndNodeSiblings, &r.AndConfigSiblings); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, wrapQueryErr(rows.Err())
}

// CVE is the descriptive record for one vulnerability.
type CVE struct {
	CVEID        string
	PublishedAt  string
	ModifiedAt   string
	Description  string
	CVSSv3Score  sql.NullFloat64
	CVSSv3Vector string
	CVSSv4Score  sql.NullFloat64
	CVSSv4Vector string
	Severity     string
	CWE          string
}

// KEVEntry is a CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVEID             string
	VendorProject     string
	Product           string
	VulnerabilityName string
	DateAdded         string
	DueDate           string
	KnownRansomware   string
	Notes             string
}

// ExploitEvidence is a reference indicating a public exploit exists.
type ExploitEvidence struct {
	CVEID         string
	Source        string
	Reference     string
	ReferenceType string
	Verified      bool
}

// CVEs loads CVE records keyed by CVE ID.
func (s *Store) CVEs(ctx context.Context, ids []string) (map[string]CVE, error) {
	out := map[string]CVE{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, COALESCE(published_at, ''), COALESCE(modified_at, ''), description,
		             cvss_v3_score, COALESCE(cvss_v3_vector, ''), cvss_v4_score, COALESCE(cvss_v4_vector, ''),
		             COALESCE(severity, ''), COALESCE(cwe, '')
		      FROM cves WHERE cve_id IN (` + placeholders(len(chunk)) + `)`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var c CVE
			if err := rows.Scan(&c.CVEID, &c.PublishedAt, &c.ModifiedAt, &c.Description,
				&c.CVSSv3Score, &c.CVSSv3Vector, &c.CVSSv4Score, &c.CVSSv4Vector,
				&c.Severity, &c.CWE); err != nil {
				return err
			}
			out[c.CVEID] = c
			return nil
		})
	})
	return out, err
}

// KEV loads KEV entries keyed by CVE ID.
func (s *Store) KEV(ctx context.Context, ids []string) (map[string]KEVEntry, error) {
	out := map[string]KEVEntry{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, COALESCE(vendor_project, ''), COALESCE(product, ''),
		             COALESCE(vulnerability_name, ''), COALESCE(date_added, ''), COALESCE(due_date, ''),
		             COALESCE(known_ransomware, ''), COALESCE(notes, '')
		      FROM kev WHERE cve_id IN (` + placeholders(len(chunk)) + `)`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var k KEVEntry
			if err := rows.Scan(&k.CVEID, &k.VendorProject, &k.Product, &k.VulnerabilityName,
				&k.DateAdded, &k.DueDate, &k.KnownRansomware, &k.Notes); err != nil {
				return err
			}
			out[k.CVEID] = k
			return nil
		})
	})
	return out, err
}

// Exploits loads exploit evidence grouped by CVE ID.
func (s *Store) Exploits(ctx context.Context, ids []string) (map[string][]ExploitEvidence, error) {
	out := map[string][]ExploitEvidence{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, source, reference, COALESCE(reference_type, ''), verified
		      FROM exploit_evidence WHERE cve_id IN (` + placeholders(len(chunk)) + `)
		      ORDER BY cve_id, source, reference`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var e ExploitEvidence
			if err := rows.Scan(&e.CVEID, &e.Source, &e.Reference, &e.ReferenceType, &e.Verified); err != nil {
				return err
			}
			out[e.CVEID] = append(out[e.CVEID], e)
			return nil
		})
	})
	return out, err
}

// each runs a parameterised query and calls fn for every row.
func (s *Store) each(ctx context.Context, q string, args []string, fn func(*sql.Rows) error) error {
	anyArgs := make([]any, len(args))
	for i, a := range args {
		anyArgs[i] = a
	}
	rows, err := s.db.QueryContext(ctx, q, anyArgs...)
	if err != nil {
		return wrapQueryErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return wrapQueryErr(rows.Err())
}

// chunkSize keeps IN lists well below SQLite's bound-parameter limit.
const chunkSize = 500

func forChunks(ids []string, fn func([]string) error) error {
	for len(ids) > 0 {
		n := min(chunkSize, len(ids))
		if err := fn(ids[:n]); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// Alias maps an observed vendor/product to the name NVD uses for the same
// software. Values are canonical CPE attribute values; Part comes from
// canonical_cpe_prefix ("cpe:2.3:<part>:<vendor>:<product>").
type Alias struct {
	Part             string
	ObservedVendor   string
	ObservedProduct  string
	CanonicalVendor  string
	CanonicalProduct string
	Source           string
	Confidence       string
}

// Aliases loads every alias row (the table is small).
func (s *Store) Aliases(ctx context.Context) ([]Alias, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(observed_vendor, ''), observed_product, canonical_vendor, canonical_product,
       canonical_cpe_prefix, source, confidence
FROM aliases ORDER BY id`)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		var prefix string
		if err := rows.Scan(&a.ObservedVendor, &a.ObservedProduct, &a.CanonicalVendor, &a.CanonicalProduct,
			&prefix, &a.Source, &a.Confidence); err != nil {
			return nil, err
		}
		if f := strings.Split(prefix, ":"); len(f) >= 3 && f[0] == "cpe" && f[1] == "2.3" {
			a.Part = f[2]
		}
		out = append(out, a)
	}
	return out, wrapQueryErr(rows.Err())
}

// DistroPackage maps a CPE identity to a distribution source package.
type DistroPackage struct {
	Part, Vendor, Product string
	Distro, Package       string
}

// DistroPackages loads the curated CPE -> source package map (small table).
func (s *Store) DistroPackages(ctx context.Context) ([]DistroPackage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT cpe_part, cpe_vendor, cpe_product, distro, package FROM distro_packages ORDER BY id`)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []DistroPackage
	for rows.Next() {
		var p DistroPackage
		if err := rows.Scan(&p.Part, &p.Vendor, &p.Product, &p.Distro, &p.Package); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, wrapQueryErr(rows.Err())
}

// HasDistroData reports whether any advisories for the distribution are loaded.
func (s *Store) HasDistroData(ctx context.Context, distro string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM distro_advisories WHERE distro = ? LIMIT 1`, distro).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, wrapQueryErr(err)
}

// PackageVersion is a package version known to have shipped in a release.
type PackageVersion struct {
	Release, Package, Version string
}

// PackageVersionsByUpstream returns known versions of the given packages
// whose upstream part equals upstream, across all releases.
func (s *Store) PackageVersionsByUpstream(ctx context.Context, distro string, packages []string, upstream string) ([]PackageVersion, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	args := []any{distro, upstream}
	for _, p := range packages {
		args = append(args, p)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT release, package, version FROM distro_package_versions
WHERE distro = ? AND upstream = ? AND package IN (`+placeholders(len(packages))+`)
ORDER BY release, package, version`, args...)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []PackageVersion
	for rows.Next() {
		var v PackageVersion
		if err := rows.Scan(&v.Release, &v.Package, &v.Version); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, wrapQueryErr(rows.Err())
}

// DistroAdvisory is one distribution advisory row.
type DistroAdvisory struct {
	AdvisoryID        string
	CVEID             string
	Distro            string
	Release           string
	Channel           string
	Codename          string
	Package           string
	FixedVersion      string // "" when no fix has been released
	AffectedUpstreams []string
	Urgency           string // distribution's rating, e.g. Debian "unimportant"; "" if none
	Stream            string // module stream (RHEL AppStream, e.g. "1.20"); "" if none
}

// DistroAdvisories returns every advisory row for a package in a release.
func (s *Store) DistroAdvisories(ctx context.Context, distro, pkg, release string) ([]DistroAdvisory, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT advisory_id, cve_id, distro, release, channel, COALESCE(codename, ''), package,
       COALESCE(fixed_version, ''), affected_upstreams, COALESCE(urgency, ''), stream
FROM distro_advisories WHERE distro = ? AND package = ? AND release = ?
ORDER BY cve_id, channel`, distro, pkg, release)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []DistroAdvisory
	for rows.Next() {
		var a DistroAdvisory
		var ups string
		if err := rows.Scan(&a.AdvisoryID, &a.CVEID, &a.Distro, &a.Release, &a.Channel, &a.Codename,
			&a.Package, &a.FixedVersion, &ups, &a.Urgency, &a.Stream); err != nil {
			return nil, err
		}
		a.AffectedUpstreams = strings.Fields(ups)
		out = append(out, a)
	}
	return out, wrapQueryErr(rows.Err())
}

// PackagesInRelease returns which of the given packages have advisory data
// for a release.
func (s *Store) PackagesInRelease(ctx context.Context, distro, release string, packages []string) ([]string, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	args := []any{distro, release}
	for _, p := range packages {
		args = append(args, p)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT package FROM distro_advisories
WHERE distro = ? AND release = ? AND package IN (`+placeholders(len(packages))+`) ORDER BY package`, args...)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, wrapQueryErr(rows.Err())
}

// Lifecycle is a distribution release's support lifecycle.
type Lifecycle struct {
	EOL           string `json:"eol"`                      // end of regular security support (YYYY-MM-DD)
	ExtendedUntil string `json:"extended_until,omitempty"` // end of extended support, if known
	Extended      string `json:"extended,omitempty"`       // e.g. "Ubuntu Pro (ESM)"
}

// ReleaseLifecycle returns the lifecycle of a release, or nil if unknown.
func (s *Store) ReleaseLifecycle(ctx context.Context, distro, release string) (*Lifecycle, error) {
	var l Lifecycle
	err := s.db.QueryRowContext(ctx, `
SELECT eol, COALESCE(extended_until, ''), COALESCE(extended, '') FROM distro_releases
WHERE distro = ? AND release = ?`, distro, release).Scan(&l.EOL, &l.ExtendedUntil, &l.Extended)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	return &l, nil
}

// WindowsBuild maps a Windows build number to a release and its NVD CPEs.
type WindowsBuild struct {
	Build   int
	Kind    string // "server" or "client"
	Name    string
	CPEs    []string
	EOL     string // end of support for every edition
	Support string
}

// WindowsBuilds loads the curated build map (small table).
func (s *Store) WindowsBuilds(ctx context.Context) ([]WindowsBuild, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT build, kind, name, cpes, eol, support FROM windows_builds ORDER BY build, kind`)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []WindowsBuild
	for rows.Next() {
		var b WindowsBuild
		var cpes string
		if err := rows.Scan(&b.Build, &b.Kind, &b.Name, &cpes, &b.EOL, &b.Support); err != nil {
			return nil, err
		}
		b.CPEs = strings.Fields(cpes)
		out = append(out, b)
	}
	return out, wrapQueryErr(rows.Err())
}
