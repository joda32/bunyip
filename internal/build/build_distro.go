package build

import (
	"context"
	"database/sql"
	"sort"
)

// DistroInput is one distribution's OSV export to load.
type DistroInput struct {
	Distro       Distro
	ZipPath      string
	LastModified string
}

// loadDistro loads one distribution's advisories for the mapped packages,
// mirroring the Python _load_distro: per-CVE records are primary; per-advisory
// records (DSA/DLA, RHSA, ...) fill only CVE/release/package/stream
// combinations no per-CVE record covers, keeping the earliest fix when several
// advisories list the same one. Returns the advisory-row count.
func loadDistro(ctx context.Context, tx *sql.Tx, di DistroInput, mapped []PackageMapRow) (int, error) {
	d := di.Distro
	packages := map[string]bool{}
	for _, m := range mapped {
		packages[m.Package] = true
	}
	for _, m := range mapped {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO distro_packages (cpe_part, cpe_vendor, cpe_product, distro, package, source) VALUES (?, ?, ?, ?, ?, ?)",
			m.Part, m.Vendor, m.Product, m.DistroName, m.Package, m.Source); err != nil {
			return 0, err
		}
	}

	rows := map[[5]string]AdvisoryRow{}
	versions := map[PackageVersion]bool{}
	collectVersions := func(vs []PackageVersion) {
		for _, v := range vs {
			versions[v] = true
		}
	}
	if d.RecordPrefix != "" {
		if err := iterRecords(di.ZipPath, []string{d.RecordPrefix}, func(rec osvRecord) error {
			t := transformOSV(rec, d, packages, true)
			collectVersions(t.Versions)
			for _, r := range t.Rows {
				rows[r.key()] = r
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	primary := map[[5]string]bool{}
	for k := range rows {
		primary[k] = true
	}
	if len(d.AdvisoryPrefixes) > 0 {
		if err := iterRecords(di.ZipPath, d.AdvisoryPrefixes, func(rec osvRecord) error {
			t := transformOSV(rec, d, packages, false)
			collectVersions(t.Versions)
			for _, r := range t.Rows {
				if primary[r.key()] {
					continue
				}
				if old, ok := rows[r.key()]; !ok || earlierFix(d, r.FixedVersion, old.FixedVersion) {
					rows[r.key()] = r
				}
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}

	// Deterministic insert order (ids are not compared, but stability helps).
	keys := make([][5]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessKey(keys[i], keys[j]) })
	for _, k := range keys {
		r := rows[k]
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO distro_advisories (source, advisory_id, cve_id, distro, release, channel, codename,"+
				" package, fixed_version, affected_upstreams, urgency, stream, modified_at)"+
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			r.Source, r.AdvisoryID, r.CVEID, r.DistroName, r.Release, r.Channel, nullStr(r.Codename),
			r.Package, nullStr(r.FixedVersion), r.AffectedUpstreams, nullStr(r.Urgency), r.Stream,
			nullStr(r.ModifiedAt)); err != nil {
			return 0, err
		}
	}

	pvs := make([]PackageVersion, 0, len(versions))
	for v := range versions {
		pvs = append(pvs, v)
	}
	sort.Slice(pvs, func(i, j int) bool { return lessPV(pvs[i], pvs[j]) })
	for _, v := range pvs {
		if _, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO distro_package_versions (distro, release, package, version, upstream) VALUES (?, ?, ?, ?, ?)",
			v.DistroName, v.Release, v.Package, v.Version, v.Upstream); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// earlierFix reports whether fixed version a is an earlier fix point than b.
// A row with no fix never replaces a fixed one.
func earlierFix(d Distro, a, b string) bool {
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	c, err := d.compare(a, b)
	return err == nil && c < 0
}

func lessKey(a, b [5]string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func lessPV(a, b PackageVersion) bool {
	ax := [5]string{a.DistroName, a.Release, a.Package, a.Version, a.Upstream}
	bx := [5]string{b.DistroName, b.Release, b.Package, b.Version, b.Upstream}
	return lessKey(ax, bx)
}

// loadReleases inserts distro_releases rows.
func loadReleases(ctx context.Context, tx *sql.Tx, releases []ReleaseRow) error {
	for _, r := range releases {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO distro_releases (distro, release, codename, eol, extended_until, extended, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
			r.DistroName, r.Release, nullStr(r.Codename), r.EOL, nullStr(r.ExtendedUntil), nullStr(r.Extended), r.Source); err != nil {
			return err
		}
	}
	return nil
}

// loadDistros loads all distro inputs, the package map and release lifecycle
// in one transaction. Returns the total advisory-row count.
func loadDistros(ctx context.Context, db *sql.DB, inputs []DistroInput, packageMap []PackageMapRow,
	releases []ReleaseRow, log func(string, ...any)) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, di := range inputs {
		var mapped []PackageMapRow
		for _, m := range packageMap {
			if m.DistroName == di.Distro.Name {
				mapped = append(mapped, m)
			}
		}
		n, err := loadDistro(ctx, tx, di, mapped)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		total += n
		log("  %s advisories: %d rows", di.Distro.Name, n)
	}
	if err := loadReleases(ctx, tx, releases); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}
