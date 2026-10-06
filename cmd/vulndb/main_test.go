package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixture = "../../testdata/fixtures/synthetic.json"

type cliResult struct {
	code           int
	stdout, stderr string
}

func cli(args ...string) cliResult {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return cliResult{code, out.String(), errOut.String()}
}

// initDB creates a fixture database through the CLI and returns its path.
func initDB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "vulndb.sqlite")
	r := cli("--db", db, "db", "init", "--fixture", fixture)
	if r.code != exitOK {
		t.Fatalf("db init failed (%d): %s", r.code, r.stderr)
	}
	return db
}

func TestQueryText(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "query", "--cpe", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"Product:             apache http_server",
		"Identity confidence: EXACT",
		"CVE-0000-0001",
		"Public exploit: YES",
		"CISA KEV:       YES",
		"Version status: MATCH",
		"Match reason:   Exact supplied CPE matched vulnerability criteria",
		"backported security",
		"SYNTHETIC",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(r.stdout, "CVE-0000-0004") {
		t.Error("NO_MATCH CVE-0000-0004 shown")
	}
	if r.stderr != "" {
		t.Errorf("unexpected stderr without --debug: %s", r.stderr)
	}
}

// jsonDoc is the subset of the JSON document the tests inspect.
type jsonDoc struct {
	OutputVersion string `json:"output_version"`
	Database      struct {
		SchemaVersion string `json:"schema_version"`
		Dataset       string `json:"dataset"`
	} `json:"database"`
	Result struct {
		NormalizedCPE      string `json:"normalized_cpe"`
		Version            string `json:"version"`
		IdentityConfidence string `json:"identity_confidence"`
		Vulnerabilities    []struct {
			CVE            string  `json:"cve"`
			CVSS           float64 `json:"cvss"`
			Severity       string  `json:"severity"`
			PublicExploit  bool    `json:"public_exploit"`
			KnownExploited bool    `json:"known_exploited"`
			VersionStatus  string  `json:"version_status"`
			Applicability  string  `json:"applicability"`
			MatchReason    string  `json:"match_reason"`
		} `json:"vulnerabilities"`
	} `json:"result"`
	RuleEvaluations []json.RawMessage `json:"rule_evaluations"`
}

func TestQueryJSONFromCPE22(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "query", "--cpe", "cpe:/a:apache:http_server:2.4.49", "--format", "json")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var doc jsonDoc
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
	}
	if doc.OutputVersion != "1" || doc.Database.SchemaVersion != "1" || doc.Database.Dataset != "synthetic-fixture" {
		t.Errorf("unexpected envelope: %+v", doc)
	}
	res := doc.Result
	if res.NormalizedCPE != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" || res.IdentityConfidence != "EXACT" {
		t.Errorf("unexpected identity: %+v", res)
	}
	got := map[string]string{}
	var order []string
	for _, v := range res.Vulnerabilities {
		got[v.CVE] = v.VersionStatus
		order = append(order, v.CVE)
		if v.MatchReason == "" {
			t.Errorf("%s: empty match_reason", v.CVE)
		}
	}
	want := map[string]string{
		"CVE-0000-0001": "MATCH", "CVE-0000-0002": "MATCH", "CVE-0000-0003": "MATCH",
		"CVE-0000-0005": "MATCH", "CVE-0000-0006": "UNKNOWN",
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for id, st := range want {
		if got[id] != st {
			t.Errorf("%s = %q, want %q", id, got[id], st)
		}
	}
	if order[0] != "CVE-0000-0001" {
		t.Errorf("KEV+exploit CVE not first: %v", order)
	}
	v := res.Vulnerabilities[0]
	if !v.KnownExploited || !v.PublicExploit || v.CVSS != 9.8 || v.Severity != "CRITICAL" {
		t.Errorf("unexpected enrichment: %+v", v)
	}
	if len(doc.RuleEvaluations) != 0 {
		t.Error("rule_evaluations present without --debug")
	}
}

func TestQueryJSONIsDeterministic(t *testing.T) {
	db := initDB(t)
	a := cli("--db", db, "query", "--cpe", "cpe:/a:apache:http_server:2.4.49", "--format", "json")
	b := cli("--db", db, "query", "--cpe", "cpe:/a:apache:http_server:2.4.49", "--format", "json")
	if a.stdout != b.stdout {
		t.Error("JSON output differs between identical queries")
	}
}

func TestQueryDebug(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "--debug", "query", "--cpe", "cpe:/a:apache:http_server:2.4.49", "--format", "json")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"Input CPE: cpe:/a:apache:http_server:2.4.49",
		"Normalized CPE: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		"Candidate match rules: 6",
		"Comparator: generic",
		"Rule 1: MATCH",
		"NO_MATCH",
		"Applicable CVEs: 4",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("debug output missing %q:\n%s", want, r.stderr)
		}
	}
	var doc jsonDoc
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("debug must not corrupt JSON stdout: %v", err)
	}
	if len(doc.RuleEvaluations) != 6 {
		t.Errorf("rule_evaluations = %d, want 6", len(doc.RuleEvaluations))
	}
}

func TestFlagsAfterCommand(t *testing.T) {
	db := initDB(t)
	r := cli("query", "--cpe", "cpe:/a:f5:nginx:1.20.1", "--db", db)
	if r.code != exitOK || !strings.Contains(r.stdout, "CVE-0000-0101") {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestDBFromEnvironment(t *testing.T) {
	db := initDB(t)
	t.Setenv("VULNDB_DB", db)
	r := cli("info")
	if r.code != exitOK || !strings.Contains(r.stdout, db) {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestNoResults(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "query", "--cpe", "cpe:/a:f5:nginx:1.20.2")
	if r.code != exitOK || !strings.Contains(r.stdout, "No candidate vulnerabilities found") {
		t.Fatalf("exit %d: %s", r.code, r.stdout)
	}
}

func TestInfoVerifyStats(t *testing.T) {
	db := initDB(t)

	r := cli("--db", db, "info")
	if r.code != exitOK || !strings.Contains(r.stdout, "Schema version:    1") ||
		!strings.Contains(r.stdout, "synthetic-fixture") || !strings.Contains(r.stdout, "Age:") {
		t.Errorf("info: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	r = cli("--db", db, "db", "verify")
	if r.code != exitOK || !strings.Contains(r.stdout, "Database OK") || strings.Contains(r.stdout, "FAIL") {
		t.Errorf("verify: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	r = cli("--db", db, "db", "stats")
	if r.code != exitOK || !strings.Contains(r.stdout, "cve_matches") {
		t.Errorf("stats: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestInitRefusesOverwriteUnlessForced(t *testing.T) {
	db := initDB(t)
	if r := cli("--db", db, "db", "init"); r.code != exitError || !strings.Contains(r.stderr, "already exists") {
		t.Errorf("overwrite not refused: %d %s", r.code, r.stderr)
	}
	// --force without a fixture replaces it with an empty database.
	if r := cli("--db", db, "db", "init", "--force"); r.code != exitOK {
		t.Fatalf("forced init failed: %s", r.stderr)
	}
	r := cli("--db", db, "query", "--cpe", "cpe:/a:apache:http_server:2.4.49")
	if r.code != exitOK || !strings.Contains(r.stdout, "No candidate vulnerabilities") {
		t.Errorf("database not replaced: %s", r.stdout)
	}
}

func TestInitBadFixtureLeavesNoDatabase(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "vulndb.sqlite")
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"cves":[{"cve_id":"CVE-0000-1","configurations":[{"nodes":[{"cpe_match":[{"criteria":"nope","vulnerable":true}]}]}]}]}`), 0o600)
	r := cli("--db", db, "db", "init", "--fixture", bad)
	if r.code != exitError {
		t.Fatalf("exit %d, want %d", r.code, exitError)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "bad.json" {
		t.Errorf("leftover files after failed init: %v", names)
	}
}

func TestErrors(t *testing.T) {
	db := initDB(t)
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.sqlite")
	os.WriteFile(corrupt, bytes.Repeat([]byte("not sqlite "), 20), 0o600)

	tests := []struct {
		name     string
		args     []string
		code     int
		inStderr string
	}{
		{"missing database", []string{"--db", filepath.Join(dir, "missing.sqlite"), "query", "--cpe", "cpe:/a:a:b:1"},
			exitError, "database not found"},
		{"corrupt database", []string{"--db", corrupt, "info"}, exitError, "corrupt"},
		{"corrupt database verify", []string{"--db", corrupt, "db", "verify"}, exitError, "corrupt"},
		{"malformed cpe", []string{"--db", db, "query", "--cpe", "apache httpd 2.4.49"}, exitError, "malformed CPE"},
		{"malformed 2.3 cpe", []string{"--db", db, "query", "--cpe", "cpe:2.3:a:apache"}, exitError, "malformed CPE"},
		{"insufficient identity", []string{"--db", db, "query", "--cpe", "cpe:/a:apache"}, exitError, "insufficient identity"},
		{"unsupported format", []string{"--db", db, "query", "--cpe", "cpe:/a:a:b:1", "--format", "xml"}, exitUsage, "unsupported format"},
		{"missing --cpe", []string{"--db", db, "query"}, exitUsage, "--cpe is required"},
		{"unknown command", []string{"--db", db, "scan"}, exitUsage, "unknown command"},
		{"unknown db subcommand", []string{"--db", db, "db", "drop"}, exitUsage, "unknown subcommand"},
		{"missing db subcommand", []string{"--db", db, "db"}, exitUsage, "subcommand required"},
		{"stray argument", []string{"--db", db, "info", "extra"}, exitUsage, "unexpected argument"},
		{"unknown flag", []string{"--db", db, "query", "--nope"}, exitUsage, "flag provided but not defined"},
		{"no command", []string{}, exitUsage, "Usage:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cli(tt.args...)
			if r.code != tt.code {
				t.Errorf("exit %d, want %d (stderr: %s)", r.code, tt.code, r.stderr)
			}
			if !strings.Contains(r.stderr, tt.inStderr) {
				t.Errorf("stderr missing %q:\n%s", tt.inStderr, r.stderr)
			}
		})
	}
}

// TestBinary builds the real executable and runs it, covering main/os.Exit.
func TestBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vulndb")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	db := filepath.Join(dir, "vulndb.sqlite")
	if out, err := exec.Command(bin, "--db", db, "db", "init", "--fixture", fixture).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--db", db, "query", "--cpe", "cpe:/a:microsoft:internet_information_services:10.0",
		"--format", "json").Output()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var doc jsonDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Result.Vulnerabilities) != 1 || doc.Result.Vulnerabilities[0].CVE != "CVE-0000-0301" {
		t.Errorf("unexpected result: %s", out)
	}

	cmd := exec.Command(bin, "--db", db, "query", "--cpe", "garbage")
	if err := cmd.Run(); err == nil {
		t.Error("malformed CPE exited 0")
	} else if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != exitError {
		t.Errorf("malformed CPE exit = %v, want %d", err, exitError)
	}
}
