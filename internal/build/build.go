package build

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"offline-vulndb/internal/database"

	_ "modernc.org/sqlite"
)

// DATASET is recorded in metadata; the NVD+KEV core (distro sources add to it).
const DATASET = "nvd+kev"

// Options tunes a build.
type Options struct {
	AllowSmall bool // skip the completeness floors (tests/partial builds)
	Log        func(string, ...any)
	// Optional distribution data. When Distros is non-empty, the package map
	// and release lifecycle are loaded too.
	PackageMap []PackageMapRow
	Releases   []ReleaseRow
	Distros    []DistroInput
	// Curated first-party data + webappanalyzer-derived http_tech.
	Aliases       []AliasRow
	WindowsBuilds []WindowsBuildRow
	ProductNames  []ProductNameRow
	HTTPApps      []HTTPAppRow
	HTTPTech      []HTTPTechRow
}

// Stats summarises a build.
type Stats struct {
	Loaded, Replaced, Unchanged, Rejected int
	SkippedRules                          []string
}

// BuildNVDKEV creates a database at out from NVD feeds and the KEV catalogue
// (phase 2: the NVD+KEV core, no distro/curated data yet). Feeds are loaded
// in FeedOrder — yearly ascending, then the modified feed as an overlay that
// replaces a CVE whose lastModified is newer and drops rejected CVEs. The
// build writes to out+".building" and renames on success, after a self-check.
func BuildNVDKEV(ctx context.Context, out string, feeds []Feed, kevPath string, opts Options) (Stats, error) {
	log := opts.Log
	if log == nil {
		log = func(string, ...any) {}
	}
	var stats Stats
	tmp := out + ".building"
	_ = os.Remove(tmp)

	// Create the schema via the shared embedded schema.sql, then reopen for
	// bulk loading with durability off (the file is private until renamed).
	st, err := database.Create(ctx, tmp)
	if err != nil {
		return stats, err
	}
	st.Close()

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return stats, err
	}
	committed := false
	defer func() {
		db.Close()
		if !committed {
			os.Remove(tmp)
		}
	}()
	for _, pragma := range []string{"PRAGMA journal_mode=OFF", "PRAGMA synchronous=OFF",
		"PRAGMA temp_store=MEMORY", "PRAGMA cache_size=-262144"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return stats, err
		}
	}
	// Indexes used only while loading (the overlay deletes a CVE's rows).
	for _, idx := range []string{
		"CREATE INDEX build_cve_matches_cve ON cve_matches (cve_id)",
		"CREATE INDEX build_exploit_cve ON exploit_evidence (cve_id)"} {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return stats, err
		}
	}

	ordered := FeedOrder(feeds)
	if len(ordered) == 0 {
		return stats, fmt.Errorf("no NVD feeds to load")
	}
	for _, feed := range ordered {
		start, count := time.Now(), 0
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return stats, err
		}
		ldr := &loader{ctx: ctx, tx: tx}
		err = streamFeed(feed.GzPath, func(raw json.RawMessage) error {
			rec, err := Transform(raw)
			if err != nil {
				return err
			}
			count++
			return ldr.apply(rec, &stats)
		})
		if err != nil {
			tx.Rollback()
			return stats, err
		}
		if err := tx.Commit(); err != nil {
			return stats, err
		}
		log("  %s: %d records in %.1fs", feed.GzPath, count, time.Since(start).Seconds())
	}

	cat, err := LoadKEV(kevPath)
	if err != nil {
		return stats, err
	}
	if err := insertKEV(ctx, db, cat); err != nil {
		return stats, err
	}
	log("  KEV %s: %d entries", cat.CatalogVersion, len(cat.Rows))

	if len(opts.Distros) > 0 || len(opts.PackageMap) > 0 || len(opts.Releases) > 0 {
		if _, err := loadDistros(ctx, db, opts.Distros, opts.PackageMap, opts.Releases, log); err != nil {
			return stats, err
		}
	}

	if err := insertCurated(ctx, db, opts); err != nil {
		return stats, err
	}

	if err := writeMetadata(ctx, db, ordered, cat, &stats); err != nil {
		return stats, err
	}

	for _, idx := range []string{"DROP INDEX build_cve_matches_cve", "DROP INDEX build_exploit_cve"} {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return stats, err
		}
	}
	if _, err := db.ExecContext(ctx, "ANALYZE"); err != nil {
		return stats, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA temp_store=FILE"); err != nil {
		return stats, err
	}
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return stats, err
	}
	if err := db.Close(); err != nil {
		return stats, err
	}

	if err := selfCheck(ctx, tmp, opts.AllowSmall); err != nil {
		return stats, err
	}
	if err := os.Rename(tmp, out); err != nil {
		return stats, err
	}
	committed = true
	return stats, nil
}

// loader applies transformed records within one feed transaction.
type loader struct {
	ctx context.Context
	tx  *sql.Tx
}

// apply inserts a record, replacing an older copy (overlay) and removing a
// CVE that has since been rejected. Mirrors the Python _apply.
func (l *loader) apply(r Record, stats *Stats) error {
	var existing sql.NullString
	err := l.tx.QueryRowContext(l.ctx, "SELECT modified_at FROM cves WHERE cve_id = ?", r.CVEID).Scan(&existing)
	have := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if r.Rejected {
		if have {
			if err := l.delete(r.CVEID); err != nil {
				return err
			}
		}
		stats.Rejected++
		return nil
	}
	if have {
		if existing.String >= r.ModifiedAt {
			stats.Unchanged++
			return nil
		}
		if err := l.delete(r.CVEID); err != nil {
			return err
		}
		stats.Replaced++
	} else {
		stats.Loaded++
	}
	stats.SkippedRules = append(stats.SkippedRules, r.SkippedRules...)
	return l.insert(r)
}

func (l *loader) delete(cveID string) error {
	for _, q := range []string{
		"DELETE FROM cve_matches WHERE cve_id = ?",
		"DELETE FROM cve_config_nodes WHERE configuration_id IN (SELECT id FROM cve_configurations WHERE cve_id = ?)",
		"DELETE FROM cve_configurations WHERE cve_id = ?",
	} {
		if _, err := l.tx.ExecContext(l.ctx, q, cveID); err != nil {
			return err
		}
	}
	if _, err := l.tx.ExecContext(l.ctx, "DELETE FROM exploit_evidence WHERE cve_id = ? AND source = ?",
		cveID, exploitSource); err != nil {
		return err
	}
	_, err := l.tx.ExecContext(l.ctx, "DELETE FROM cves WHERE cve_id = ?", cveID)
	return err
}

func (l *loader) insert(r Record) error {
	if _, err := l.tx.ExecContext(l.ctx,
		"INSERT INTO cves (cve_id, published_at, modified_at, description, cvss_v3_score, cvss_v3_vector,"+
			" cvss_v4_score, cvss_v4_vector, severity, cwe) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		r.CVEID, nullStr(r.PublishedAt), nullStr(r.ModifiedAt), r.Description, r.CVSSv3Score,
		nullStr(r.CVSSv3Vector), r.CVSSv4Score, nullStr(r.CVSSv4Vector), nullStr(r.Severity),
		nullStr(r.CWE)); err != nil {
		return err
	}
	for _, cfg := range r.Configs {
		res, err := l.tx.ExecContext(l.ctx, "INSERT INTO cve_configurations (cve_id, operator) VALUES (?, ?)",
			r.CVEID, cfg.Operator)
		if err != nil {
			return err
		}
		cfgID, _ := res.LastInsertId()
		andConfig := b2i(cfg.Operator == "AND" && len(cfg.Nodes) > 1)
		for _, node := range cfg.Nodes {
			res, err := l.tx.ExecContext(l.ctx,
				"INSERT INTO cve_config_nodes (configuration_id, operator, negate) VALUES (?, ?, ?)",
				cfgID, node.Operator, b2i(node.Negate))
			if err != nil {
				return err
			}
			nodeID, _ := res.LastInsertId()
			andNode := b2i(node.Operator == "AND" && len(node.Matches) > 1)
			for _, m := range node.Matches {
				if _, err := l.tx.ExecContext(l.ctx,
					"INSERT INTO cve_matches (cve_id, node_id, criteria, criteria_part, criteria_vendor,"+
						" criteria_product, vulnerable, version_start_including, version_start_excluding,"+
						" version_end_including, version_end_excluding, node_operator, node_negate,"+
						" config_operator, and_node_siblings, and_config_siblings, version_key)"+
						" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
					r.CVEID, nodeID, m.Criteria, m.Part, m.Vendor, m.Product, b2i(m.Vulnerable),
					nullStr(m.StartIncluding), nullStr(m.StartExcluding), nullStr(m.EndIncluding),
					nullStr(m.EndExcluding), node.Operator, b2i(node.Negate), cfg.Operator,
					andNode, andConfig, m.VersionKey); err != nil {
					return err
				}
			}
		}
	}
	for _, e := range r.Exploits {
		if _, err := l.tx.ExecContext(l.ctx,
			"INSERT INTO exploit_evidence (cve_id, source, reference, reference_type, verified, metadata_json)"+
				" VALUES (?, ?, ?, 'exploit-reference', 0, ?)",
			r.CVEID, exploitSource, e.Reference, e.MetadataJSON); err != nil {
			return err
		}
	}
	return nil
}

func insertKEV(ctx context.Context, db *sql.DB, cat KEVCatalogue) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, r := range cat.Rows {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, due_date,"+
				" known_ransomware, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			r.CVEID, nullStr(r.VendorProject), nullStr(r.Product), nullStr(r.VulnerabilityName),
			nullStr(r.DateAdded), nullStr(r.DueDate), nullStr(r.KnownRansomware), nullStr(r.Notes)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func writeMetadata(ctx context.Context, db *sql.DB, feeds []Feed, cat KEVCatalogue, stats *Stats) error {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	feedNames := ""
	lastMod := ""
	for i, f := range feeds {
		if i > 0 {
			feedNames += ","
		}
		feedNames += f.Name
		if f.LastModified > lastMod {
			lastMod = f.LastModified
		}
	}
	meta := [][2]string{
		{"dataset", DATASET}, {"database_version", now}, {"created_at", now},
		{"nvd_last_modified", lastMod}, {"nvd_feeds", feedNames},
		{"kev_catalog_version", cat.CatalogVersion}, {"kev_date_released", cat.DateReleased},
		{"nvd_cves_total", countStr(ctx, db, "SELECT COUNT(*) FROM cves")},
		{"nvd_cves_without_configurations", countStr(ctx, db,
			"SELECT COUNT(*) FROM cves WHERE NOT EXISTS (SELECT 1 FROM cve_configurations c WHERE c.cve_id = cves.cve_id)")},
		{"nvd_rules_skipped", fmt.Sprintf("%d", len(stats.SkippedRules))},
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, kv := range meta {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO database_metadata (key, value) VALUES (?, ?)",
			kv[0], kv[1]); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// selfCheck opens the built database read-only and runs the shared Verify
// checks, plus completeness floors unless allowSmall. It never ships a
// database that fails.
func selfCheck(ctx context.Context, path string, allowSmall bool) error {
	st, err := database.Open(ctx, path)
	if err != nil {
		return fmt.Errorf("self-check open: %w", err)
	}
	defer st.Close()
	checks, err := st.Verify(ctx)
	if err != nil {
		return err
	}
	for _, c := range checks {
		if c.Status == database.CheckFail {
			return fmt.Errorf("self-check failed: %s: %s", c.Name, c.Detail)
		}
	}
	if !allowSmall {
		stats, err := st.Stats(ctx)
		if err != nil {
			return err
		}
		counts := map[string]int64{}
		for _, t := range stats.Tables {
			counts[t.Table] = t.Rows
		}
		if counts["cves"] < 200000 {
			return fmt.Errorf("self-check failed: only %d CVEs (expected >= 200000); incomplete feeds?", counts["cves"])
		}
		if counts["kev"] < 1000 {
			return fmt.Errorf("self-check failed: only %d KEV entries (expected >= 1000)", counts["kev"])
		}
	}
	return nil
}

func countStr(ctx context.Context, db *sql.DB, q string) string {
	var n int64
	_ = db.QueryRowContext(ctx, q).Scan(&n)
	return fmt.Sprintf("%d", n)
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// insertCurated loads the curated first-party tables in one transaction.
func insertCurated(ctx context.Context, db *sql.DB, opts Options) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, a := range opts.Aliases {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO aliases (observed_vendor, observed_product, canonical_vendor, canonical_product,"+
				" canonical_cpe_prefix, source, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
			a.ObservedVendor, a.ObservedProduct, a.CanonicalVendor, a.CanonicalProduct, a.prefix(), a.Source, a.Confidence); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, w := range opts.WindowsBuilds {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO windows_builds (build, kind, name, cpes, eol, support, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
			w.Build, w.Kind, w.Name, w.CPEs, w.EOL, w.Support, w.Source); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, n := range opts.ProductNames {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO product_names (pattern, match, kind, part, vendor, product, os, version, confidence, note, source)"+
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			n.Pattern, n.Match, n.Kind, n.Part, n.Vendor, n.Product, n.OS, n.Version, n.Confidence, n.Note, n.Source); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, a := range opts.HTTPApps {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO http_apps (evidence, header, pattern, vendor, product, version_group, confidence, note, source)"+
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			a.Evidence, a.Header, a.Pattern, a.Vendor, a.Product, a.VersionGroup, a.Confidence, a.Note, a.Source); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, t := range opts.HTTPTech {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO http_tech (name, vendor, product, source) VALUES (?, ?, ?, ?)",
			t.Name, t.Vendor, t.Product, t.Source); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
