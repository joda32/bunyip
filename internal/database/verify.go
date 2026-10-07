package database

import (
	"context"
	"fmt"
	"os"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/version"
)

// CheckStatus is the outcome of one verification check.
type CheckStatus string

const (
	CheckOK   CheckStatus = "OK"
	CheckWarn CheckStatus = "WARN"
	CheckFail CheckStatus = "FAIL"
)

// Check is one verification result.
type Check struct {
	Name   string
	Status CheckStatus
	Detail string
}

// requiredTables are the tables this schema version must contain.
var requiredTables = []string{
	"database_metadata", "cves", "cve_configurations", "cve_config_nodes",
	"cve_matches", "exploit_evidence", "kev", "aliases",
	"distro_advisories", "distro_package_versions", "distro_packages",
}

// Verify runs integrity and consistency checks. It returns an error only if
// the checks themselves could not run.
func (s *Store) Verify(ctx context.Context) ([]Check, error) {
	var checks []Check
	add := func(name string, st CheckStatus, detail string) {
		checks = append(checks, Check{name, st, detail})
	}

	// SQLite page-level integrity.
	var integrity string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return nil, wrapQueryErr(err)
	}
	if integrity == "ok" {
		add("sqlite integrity", CheckOK, "")
	} else {
		add("sqlite integrity", CheckFail, integrity)
	}

	add("schema version", CheckOK, SchemaVersion) // Open already enforced it.

	missing, err := s.missingTables(ctx)
	if err != nil {
		return nil, err
	}
	if len(missing) == 0 {
		add("required tables", CheckOK, "")
	} else {
		add("required tables", CheckFail, "missing: "+strings.Join(missing, ", "))
		return checks, nil // remaining checks would fail on missing tables
	}

	fk, err := s.count(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_check`)
	if err != nil {
		return nil, err
	}
	addCount(add, "foreign keys", fk, CheckFail, "violations")

	orphanKEV, err := s.count(ctx, `SELECT COUNT(*) FROM kev WHERE cve_id NOT IN (SELECT cve_id FROM cves)`)
	if err != nil {
		return nil, err
	}
	addCount(add, "kev entries reference known CVEs", orphanKEV, CheckWarn, "KEV entries without a CVE record")

	orphanExp, err := s.count(ctx, `SELECT COUNT(*) FROM exploit_evidence WHERE cve_id NOT IN (SELECT cve_id FROM cves)`)
	if err != nil {
		return nil, err
	}
	addCount(add, "exploit evidence references known CVEs", orphanExp, CheckWarn, "evidence rows without a CVE record")

	bad, err := s.badCriteria(ctx)
	if err != nil {
		return nil, err
	}
	if len(bad) == 0 {
		add("match criteria parse and index columns", CheckOK, "")
	} else {
		detail := fmt.Sprintf("%d bad rule(s), e.g. %s", len(bad), bad[0])
		add("match criteria parse and index columns", CheckFail, detail)
	}
	return checks, nil
}

func addCount(add func(string, CheckStatus, string), name string, n int64, failStatus CheckStatus, what string) {
	if n == 0 {
		add(name, CheckOK, "")
		return
	}
	add(name, failStatus, fmt.Sprintf("%d %s", n, what))
}

func (s *Store) missingTables(ctx context.Context) ([]string, error) {
	var missing []string
	for _, t := range requiredTables {
		n, err := s.count(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, t)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			missing = append(missing, t)
		}
	}
	return missing, nil
}

// badCriteria re-parses every criteria string and confirms the derived lookup
// columns agree with it, since a mismatch would silently hide rules.
func (s *Store) badCriteria(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, criteria, criteria_part, criteria_vendor, criteria_product, version_key,
		        COALESCE(version_start_including, version_start_excluding, version_end_including,
		                 version_end_excluding) IS NOT NULL
		 FROM cve_matches`)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var bad []string
	for rows.Next() {
		var id int64
		var crit, part, vendor, product, key string
		var ranged bool
		if err := rows.Scan(&id, &crit, &part, &vendor, &product, &key, &ranged); err != nil {
			return nil, err
		}
		c, err := cpe.ParsePattern(crit)
		wantKey := ""
		if err == nil && !ranged {
			wantKey = version.Key(cpe.Unescape(c.Version))
		}
		switch {
		case err != nil:
			bad = append(bad, fmt.Sprintf("rule %d: %v", id, err))
		case c.Part != part || c.Vendor != vendor || c.Product != product:
			bad = append(bad, fmt.Sprintf("rule %d: index columns disagree with criteria %q", id, crit))
		case key != wantKey:
			// A wrong key would silently hide the rule from matching queries.
			bad = append(bad, fmt.Sprintf("rule %d: version_key %q, want %q", id, key, wantKey))
		}
	}
	return bad, wrapQueryErr(rows.Err())
}

func (s *Store) count(ctx context.Context, q string, args ...any) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, wrapQueryErr(err)
}

// TableCount is a row count for one table.
type TableCount struct {
	Table string
	Rows  int64
}

// Stats holds database size and per-table row counts.
type Stats struct {
	FileBytes int64
	Tables    []TableCount
	// CVEsWithoutConfigurations counts CVEs that have no applicability data
	// at all, so no CPE query can ever return them.
	CVEsWithoutConfigurations int64
}

// Stats returns row counts for every required table and the file size.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	if fi, err := os.Stat(s.Path); err == nil {
		st.FileBytes = fi.Size()
	}
	for _, t := range requiredTables {
		// Table names come from the fixed list above, never from input.
		n, err := s.count(ctx, `SELECT COUNT(*) FROM `+t)
		if err != nil {
			return st, err
		}
		st.Tables = append(st.Tables, TableCount{t, n})
	}
	n, err := s.count(ctx, `SELECT COUNT(*) FROM cves
		WHERE NOT EXISTS (SELECT 1 FROM cve_configurations c WHERE c.cve_id = cves.cve_id)`)
	if err != nil {
		return st, err
	}
	st.CVEsWithoutConfigurations = n
	return st, nil
}

// QuickCheck runs SQLite's quick_check (structural integrity, faster than a
// full integrity_check) and fails if it reports problems.
func (s *Store) QuickCheck(ctx context.Context) error {
	var res string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&res); err != nil {
		return wrapQueryErr(err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: quick_check: %s", ErrCorrupt, res)
	}
	return nil
}
