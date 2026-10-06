package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const fixturePath = "../../testdata/fixtures/synthetic.json"

// newFixtureDB creates a temporary database loaded with the synthetic fixture
// and returns its path.
func newFixtureDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.sqlite")
	s, err := Create(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := LoadFixture(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportFixture(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func openFixtureDB(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), newFixtureDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenMissing(t *testing.T) {
	_, err := Open(context.Background(), filepath.Join(t.TempDir(), "nope.sqlite"))
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("got %v, want ErrMissing", err)
	}
}

func TestOpenDirectory(t *testing.T) {
	_, err := Open(context.Background(), t.TempDir())
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("got %v, want ErrMissing", err)
	}
}

func TestOpenCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.sqlite")
	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database, just text padding it out......"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), path)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

func TestOpenForeignSQLite(t *testing.T) {
	// A valid SQLite file that is not an Offline VulnDB database.
	path := filepath.Join(t.TempDir(), "other.sqlite")
	s, err := Create(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE database_metadata`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = Open(context.Background(), path)
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("got %v, want ErrIncompatible", err)
	}
}

func TestOpenWrongSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	s, err := Create(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE database_metadata SET value = '999' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = Open(context.Background(), path)
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("got %v, want ErrIncompatible", err)
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	path := newFixtureDB(t)
	if _, err := Create(context.Background(), path); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

func TestOpenIsReadOnly(t *testing.T) {
	s := openFixtureDB(t)
	if _, err := s.db.Exec(`DELETE FROM cves`); err == nil {
		t.Fatal("write succeeded on read-only store")
	}
}

func TestMetadata(t *testing.T) {
	s := openFixtureDB(t)
	m, err := s.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m["schema_version"] != SchemaVersion || m["dataset"] != "synthetic-fixture" || m["created_at"] == "" {
		t.Errorf("unexpected metadata: %v", m)
	}
}

func TestCandidateRules(t *testing.T) {
	s := openFixtureDB(t)
	ctx := context.Background()
	rules, err := s.CandidateRules(ctx, "a", "apache", "http_server")
	if err != nil {
		t.Fatal(err)
	}
	// CVE-0000-0001..0006 each have one vulnerable apache rule.
	if len(rules) != 6 {
		t.Fatalf("got %d apache rules, want 6", len(rules))
	}
	byCVE := map[string]MatchRule{}
	for _, r := range rules {
		byCVE[r.CVEID] = r
	}
	r1 := byCVE["CVE-0000-0001"]
	if r1.Range.StartIncluding != "2.4.49" || r1.Range.EndExcluding != "2.4.51" || !r1.Vulnerable {
		t.Errorf("unexpected rule for 0001: %+v", r1)
	}
	r5 := byCVE["CVE-0000-0005"]
	if !r5.HasNode || r5.ConfigOperator != "AND" || r5.ConfigNodeCount != 2 || r5.NodeRuleCount != 1 {
		t.Errorf("unexpected configuration context for 0005: %+v", r5)
	}

	// Non-vulnerable platform rules are not candidates.
	win, err := s.CandidateRules(ctx, "o", "microsoft", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(win) != 0 {
		t.Errorf("got %d windows rules, want 0 (vulnerable=false only)", len(win))
	}

	none, err := s.CandidateRules(ctx, "a", "nobody", "nothing")
	if err != nil || len(none) != 0 {
		t.Errorf("got %v, %v; want no rules", none, err)
	}
}

func TestEnrichmentQueries(t *testing.T) {
	s := openFixtureDB(t)
	ctx := context.Background()
	ids := []string{"CVE-0000-0001", "CVE-0000-0003", "CVE-0000-0301", "CVE-9999-0000"}

	cves, err := s.CVEs(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 3 || cves["CVE-0000-0001"].CVSSv3Score.Float64 != 9.8 {
		t.Errorf("unexpected CVEs: %+v", cves)
	}

	kev, err := s.KEV(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kev["CVE-0000-0001"]; !ok || len(kev) != 2 || kev["CVE-0000-0301"].KnownRansomware != "Known" {
		t.Errorf("unexpected KEV: %+v", kev)
	}

	exp, err := s.Exploits(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp["CVE-0000-0001"]) != 2 || len(exp["CVE-0000-0003"]) != 0 || len(exp["CVE-0000-0301"]) != 0 {
		t.Errorf("unexpected exploit evidence: %+v", exp)
	}
}

func TestChunkedLookup(t *testing.T) {
	s := openFixtureDB(t)
	ids := make([]string, 0, 1201)
	for range 1200 {
		ids = append(ids, "CVE-9999-0000")
	}
	ids = append(ids, "CVE-0000-0001")
	cves, err := s.CVEs(context.Background(), ids)
	if err != nil || len(cves) != 1 {
		t.Fatalf("got %d, %v", len(cves), err)
	}
}

func TestVerifyFixture(t *testing.T) {
	s := openFixtureDB(t)
	checks, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Status != CheckOK {
			t.Errorf("check %q = %s: %s", c.Name, c.Status, c.Detail)
		}
	}
}

func TestVerifyDetectsBadIndexColumns(t *testing.T) {
	path := newFixtureDB(t)
	rw, err := openRW(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Exec(`UPDATE cve_matches SET criteria_vendor = 'wrong' WHERE cve_id = 'CVE-0000-0001'`); err != nil {
		t.Fatal(err)
	}
	rw.Close()

	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checks, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasStatus(checks, "match criteria parse and index columns", CheckFail) {
		t.Errorf("index column mismatch not detected: %+v", checks)
	}
}

func TestStats(t *testing.T) {
	s := openFixtureDB(t)
	st, err := s.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, tc := range st.Tables {
		counts[tc.Table] = tc.Rows
	}
	if counts["cves"] != 12 || counts["kev"] != 2 || counts["exploit_evidence"] != 5 || counts["aliases"] != 2 {
		t.Errorf("unexpected counts: %v", counts)
	}
	if st.FileBytes == 0 {
		t.Error("file size not reported")
	}
}

func TestImportRejectsBadCriteria(t *testing.T) {
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "bad.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f := &Fixture{CVEs: []FixtureCVE{{
		CVEID: "CVE-0000-9999",
		Configurations: []FixtureConfig{{Nodes: []FixtureNode{{
			CPEMatch: []FixtureMatch{{Criteria: "not-a-cpe", Vulnerable: true}},
		}}}},
	}}}
	if err := s.ImportFixture(ctx, f); err == nil {
		t.Fatal("import accepted malformed criteria")
	}
	// The transaction must have rolled back.
	n, _ := s.count(ctx, `SELECT COUNT(*) FROM cves`)
	if n != 0 {
		t.Errorf("partial import left %d CVEs", n)
	}
}

func TestLoadFixtureRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	os.WriteFile(path, []byte(`{"cves": [], "surprise": 1}`), 0o600)
	if _, err := LoadFixture(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func hasStatus(checks []Check, name string, st CheckStatus) bool {
	for _, c := range checks {
		if c.Name == name && c.Status == st {
			return true
		}
	}
	return false
}

func openRW(path string) (*sql.DB, error) {
	return sql.Open("sqlite", dsn(path, "rw"))
}
