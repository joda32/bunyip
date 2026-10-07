package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
		"Distribution backported",
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
	if doc.OutputVersion != "1" || doc.Database.SchemaVersion != "9" || doc.Database.Dataset != "synthetic-fixture" {
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
	if r.code != exitOK || !strings.Contains(r.stdout, "Schema version:    9") ||
		!strings.Contains(r.stdout, "synthetic-fixture") || !strings.Contains(r.stdout, "Data age:") ||
		!strings.Contains(r.stdout, "CVEs without CPE applicability data: 1 of 13") {
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

// TestInfoRealDatasetStaleness uses a non-synthetic dataset with an old NVD
// timestamp: staleness must be judged from the source data, not the build
// time, and queries must carry the NVD coverage warning.
func TestInfoRealDatasetStaleness(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "real.sqlite")
	fx := filepath.Join(dir, "real.json")
	os.WriteFile(fx, []byte(`{
	  "metadata": {"dataset": "nvd+kev", "nvd_last_modified": "2026-01-01T00:00:00Z"},
	  "cves": [{"cve_id": "CVE-0000-0001", "description": "no configurations"}]
	}`), 0o600)
	if r := cli("--db", db, "db", "init", "--fixture", fx); r.code != exitOK {
		t.Fatal(r.stderr)
	}

	r := cli("--db", db, "info")
	for _, want := range []string{
		"NVD data as of:    2026-01-01T00:00:00Z",
		"WARNING: data is older than 7 days",
		"CVEs without CPE applicability data: 1 of 1 (100.0%)",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("info missing %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "SYNTHETIC") {
		t.Error("real dataset labelled synthetic")
	}

	q := cli("--db", db, "query", "--cpe", "cpe:/a:apache:http_server:2.4.49")
	if !strings.Contains(q.stdout, "no result does not") {
		t.Errorf("coverage warning missing:\n%s", q.stdout)
	}

	s := cli("--db", db, "db", "stats")
	if !strings.Contains(s.stdout, "cves w/o config") {
		t.Errorf("stats missing coverage row:\n%s", s.stdout)
	}
}

const sampleScan = "../../testdata/nmap/sample.xml"

func TestNmapText(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "nmap", sampleScan)
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"Hosts up 2, down 1 | open ports 6: assessed 4, unidentified 1, not probed 1",
		"8 version matches (2 in CISA KEV, 3 with public exploit evidence), 1 undetermined",
		"Distribution advisories: 1 upstream matches already fixed in the installed/released package, 1 findings only",
		"Distribution release (from an exact package version on this host): 22.04",
		"installed 1:8.9p1-3ubuntu0.10",
		"CVE-0000-0203    HIGH      CVSS 7.1  exploit:NO  KEV:NO  MATCH  [Ubuntu: VULNERABLE, advisory only]",
		"[Ubuntu: NO_FIX]",
		"+ 1 fixed in the Ubuntu package: CVE-0000-0201",
		"192.0.2.20 (web01.example.test)",
		"22/tcp ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.10",
		"CVE-0000-0001    CRITICAL  CVSS 9.8  exploit:YES KEV:YES MATCH",
		"[CONDITIONAL]",
		"cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:* [HIGH] (curated alias)",
		"CVE-0000-0101    HIGH      CVSS 7.7  exploit:YES KEV:NO  MATCH  [via alias, HIGH]",
		"25/tcp smtp\n    Not assessed: service guessed from port number",
		`No application CPE reported for "Mystery httpd 1.2"`,
		"against Microsoft Windows",
		"[ransomware]",
		"OS (Nmap guess, not assessed): cpe:/o:microsoft:windows_server_2016",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("nmap text output missing %q", want)
		}
	}
	if strings.Contains(r.stdout, "3306") || strings.Contains(r.stdout, "192.0.2.22") {
		t.Error("closed ports and down hosts must not be listed")
	}
	if strings.Count(r.stdout, "Matching is based on upstream") != 1 {
		t.Error("general warnings should appear once")
	}
}

func TestNmapJSONFlagsAfterFileAndStdin(t *testing.T) {
	db := initDB(t)
	r := cli("nmap", sampleScan, "--format", "json", "--db", db)
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var doc struct {
		OutputVersion string `json:"output_version"`
		Report        struct {
			Summary struct {
				Assessed       int `json:"assessed"`
				VersionMatches int `json:"version_matches"`
			} `json:"summary"`
			Hosts []struct {
				Address  string `json:"address"`
				Services []struct {
					Port       int      `json:"port"`
					Assessment string   `json:"assessment"`
					Distro     string   `json:"distro"`
					Platform   []string `json:"platform_cpes"`
					Result     *struct {
						Identities []struct {
							CPE        string `json:"cpe"`
							Confidence string `json:"confidence"`
						} `json:"identities"`
						Vulnerabilities []struct {
							CVE             string `json:"cve"`
							MatchedCPE      string `json:"matched_cpe"`
							MatchConfidence string `json:"match_confidence"`
						} `json:"vulnerabilities"`
					} `json:"result"`
				} `json:"services"`
			} `json:"hosts"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.OutputVersion != "1" || doc.Report.Summary.Assessed != 4 || doc.Report.Summary.VersionMatches != 8 {
		t.Errorf("summary: %+v", doc.Report.Summary)
	}
	svcs := doc.Report.Hosts[0].Services
	ssh, nginx := svcs[0], svcs[3]
	if ssh.Port != 22 || ssh.Distro != "Ubuntu package 3ubuntu0.10" ||
		len(ssh.Platform) != 1 || ssh.Platform[0] != "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*" {
		t.Errorf("ssh: %+v", ssh)
	}
	if nginx.Port != 443 || len(nginx.Result.Identities) != 2 ||
		nginx.Result.Vulnerabilities[0].MatchedCPE != "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*" ||
		nginx.Result.Vulnerabilities[0].MatchConfidence != "HIGH" {
		t.Errorf("nginx alias attribution: %+v", nginx.Result)
	}
	if svcs[1].Assessment != "NOT_PROBED" || svcs[4].Assessment != "UNIDENTIFIED" || svcs[1].Result != nil {
		t.Errorf("assessments: %+v %+v", svcs[1], svcs[4])
	}

	// Same scan from stdin.
	data, _ := os.ReadFile(sampleScan)
	var out, errOut bytes.Buffer
	g := []string{"--db", db, "nmap", "-", "--format", "json"}
	code := runWithStdin(g, bytes.NewReader(data), &out, &errOut)
	if code != exitOK || out.String() != r.stdout {
		t.Errorf("stdin result differs (exit %d): %s", code, errOut.String())
	}
}

func TestNmapRealLocalScan(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "nmap", "../../testdata/nmap/local-ubuntu-ssh.xml")
	if r.code != exitOK || !strings.Contains(r.stdout, "OpenSSH 9.6p1 Ubuntu 3ubuntu13.18") ||
		!strings.Contains(r.stdout, "Ubuntu package 3ubuntu13.18") {
		t.Fatalf("exit %d:\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestNmapErrors(t *testing.T) {
	db := initDB(t)
	dir := t.TempDir()
	html := filepath.Join(dir, "x.xml")
	os.WriteFile(html, []byte("<html></html>"), 0o600)
	tests := []struct {
		args     []string
		code     int
		inStderr string
	}{
		{[]string{"--db", db, "nmap"}, exitUsage, "exactly one Nmap XML file"},
		{[]string{"--db", db, "nmap", "a.xml", "b.xml"}, exitUsage, "exactly one Nmap XML file"},
		{[]string{"--db", db, "nmap", sampleScan, "--format", "csv"}, exitUsage, "unsupported format"},
		{[]string{"--db", db, "nmap", filepath.Join(dir, "missing.xml")}, exitError, "no such file"},
		{[]string{"--db", db, "nmap", html}, exitError, "not an Nmap XML document"},
		{[]string{"--db", filepath.Join(dir, "none.sqlite"), "nmap", sampleScan}, exitError, "database not found"},
	}
	for _, tt := range tests {
		r := cli(tt.args...)
		if r.code != tt.code || !strings.Contains(r.stderr, tt.inStderr) {
			t.Errorf("%v: exit %d stderr %q, want %d %q", tt.args, r.code, r.stderr, tt.code, tt.inStderr)
		}
	}
}

func TestQueryDistro(t *testing.T) {
	db := initDB(t)
	r := cli("--db", db, "query", "--cpe", "cpe:/a:openbsd:openssh:8.9p1", "--distro", "ubuntu",
		"--package-version", "1:8.9p1-3ubuntu0.10")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"Distribution:        Ubuntu: RESOLVED (openssh 22.04, installed 1:8.9p1-3ubuntu0.10)",
		"1 fixed in the distribution package",
		"Fixed in the Ubuntu package (upstream version matches, fix backported):\n  CVE-0000-0201",
		"Ubuntu:         VULNERABLE (found only via Ubuntu advisory data)",
		"Ubuntu:         NO_FIX",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "Matching is based on upstream") {
		t.Error("backport warning shown although distribution advisories were evaluated")
	}

	// Without the revision: release inferred from the upstream version.
	r = cli("--db", db, "query", "--cpe", "cpe:/a:openbsd:openssh:8.9p1", "--distro", "ubuntu", "--format", "json")
	var doc struct {
		Result struct {
			Distro struct {
				Status   string   `json:"status"`
				Releases []string `json:"releases"`
			} `json:"distro"`
			Vulnerabilities []struct {
				CVE    string `json:"cve"`
				Distro struct {
					Status string `json:"status"`
				} `json:"distro"`
				DistroOnly bool `json:"distro_only"`
			} `json:"vulnerabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range doc.Result.Vulnerabilities {
		got[v.CVE] = v.Distro.Status
		if v.DistroOnly {
			t.Errorf("%s: no distro-only findings without a package revision", v.CVE)
		}
	}
	if doc.Result.Distro.Status != "RESOLVED" || got["CVE-0000-0201"] != "FIX_AVAILABLE" || got["CVE-0000-0202"] != "NO_FIX" {
		t.Errorf("revision unknown: %+v %v", doc.Result.Distro, got)
	}

	for _, bad := range [][]string{
		{"--distro", "gentoo"},
		{"--package-version", "1:8.9p1-3ubuntu0.10"},
		{"--distro", "ubuntu", "--package-version", "8.9p1"},
	} {
		args := append([]string{"--db", db, "query", "--cpe", "cpe:/a:openbsd:openssh:8.9p1"}, bad...)
		if r := cli(args...); r.code != exitUsage {
			t.Errorf("%v: exit %d, want usage error", bad, r.code)
		}
	}
}

func TestBundleCLI(t *testing.T) {
	dir := t.TempDir()
	db := initDB(t)
	key, pub := filepath.Join(dir, "k.key"), filepath.Join(dir, "k.pub")
	out := filepath.Join(dir, "vulndb.tar.gz")
	target := filepath.Join(dir, "offline.sqlite")

	steps := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"bundle", "keygen", "--key", key, "--pub", pub}, exitOK, "key ID"},
		{[]string{"--db", db, "bundle", "create", "--out", out, "--key", key}, exitOK, "Signature:         valid"},
		{[]string{"bundle", "verify", out, "--pubkey", pub}, exitOK, "Bundle OK"},
		{[]string{"bundle", "verify", out}, exitError, "public key is required"},
		{[]string{"--db", target, "bundle", "import", out, "--pubkey", pub}, exitOK, "Installed"},
		{[]string{"--db", target, "bundle", "import", out, "--pubkey", pub}, exitOK, "Nothing to do"},
		{[]string{"--db", target, "info"}, exitOK, "synthetic-fixture"},
		{[]string{"bundle", "import"}, exitUsage, "exactly one bundle file"},
		{[]string{"bundle", "keygen", "--key", key, "--pub", pub}, exitError, "exists"},
		{[]string{"bundle", "explode"}, exitUsage, "unknown subcommand"},
	}
	for _, s := range steps {
		r := cli(s.args...)
		if r.code != s.code || !strings.Contains(r.stdout+r.stderr, s.want) {
			t.Errorf("%v: exit %d, want %d with %q\n%s%s", s.args, r.code, s.code, s.want, r.stdout, r.stderr)
		}
	}
}

func TestNSECommand(t *testing.T) {
	db := initDB(t)
	dir := t.TempDir()
	req := filepath.Join(dir, "req.json")
	os.WriteFile(req, []byte(`{"version":1,"host":{"address":"192.0.2.9","hostnames":[],"os_cpes":[]},
 "ports":[{"protocol":"tcp","port":443,"state":"open","name":"http","product":"nginx","version":"1.20.1","extrainfo":"",
   "ostype":"","tunnel":"ssl","method":"probed","conf":10,"cpes":["cpe:/a:igor_sysoev:nginx:1.20.1"]}],
 "target":{"protocol":"tcp","port":443},"options":{"max":10,"mincvss":0,"show_undetermined":false,"show_distro_fixed":false}}`), 0o600)
	r := cli("--db", db, "nse", "--request", req)
	if r.code != exitOK || !strings.Contains(r.stdout, `"id":"CVE-0000-0101"`) || !strings.Contains(r.stdout, "via-alias") {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	os.WriteFile(req, []byte(`{"version":9}`), 0o600)
	r = cli("--db", db, "nse", "--request", req)
	if r.code != exitError || !strings.Contains(r.stdout, `"error":"unsupported nse request version 9`) {
		t.Errorf("error JSON: exit %d %s", r.code, r.stdout)
	}
}

// TestNSEScriptWithNmap runs the real nse/vulndb.nse in Nmap against a local
// listener that presents a genuine-format Ubuntu OpenSSH banner. No external
// network access; skipped when Nmap is not installed.
func TestNSEScriptWithNmap(t *testing.T) {
	nmapPath, err := exec.LookPath("nmap")
	if err != nil || testing.Short() {
		t.Skip("nmap not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vulndb")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	db := initDB(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"))
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	script, _ := filepath.Abs("../../nse/vulndb.nse")
	out, err := exec.Command(nmapPath, "-sV", "-Pn", "-n", "-p", port, "--script", script,
		"--script-args", "vulndb.bin="+bin+",vulndb.db="+db, "-oX", "-", "127.0.0.1").CombinedOutput()
	if err != nil {
		t.Fatalf("nmap: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{
		`product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.10"`, // Nmap fingerprinted the banner
		"2 candidate CVEs",
		"Distribution: Ubuntu 22.04 installed 1:8.9p1-3ubuntu0.10; 1 more fixed in the package",
		"CVE-0000-0203", "Ubuntu: VULNERABLE",
		`<elem key="id">CVE-0000-0203</elem>`, // structured -oX output
	} {
		if !strings.Contains(s, want) {
			t.Errorf("nmap output missing %q:\n%s", want, s)
		}
	}
}

func TestNmapWindowsBuilds(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vulndb.sqlite")
	if r := cli("--db", db, "db", "init", "--fixture", "../../testdata/fixtures/windows.json"); r.code != exitOK {
		t.Fatalf("db init: %s", r.stderr)
	}
	r := cli("--db", db, "nmap", "../../testdata/nmap/windows-hosts.xml")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	// Windows built-ins are listed once per host, not as per-port notes.
	if strings.Contains(r.stdout, "Note: Windows component: covered") || strings.Contains(r.stdout, "\n  389/tcp") {
		t.Errorf("OS component ports printed individually:\n%s", r.stdout)
	}
	// CVE-0000-0909 is in KEV but undetermined: counted and listed only as undetermined.
	if strings.Contains(r.stdout, "CVE-0000-0909") {
		t.Errorf("undetermined KEV entry listed:\n%s", r.stdout)
	}
	for _, want := range []string{
		"Hosts up 7, down 0 | open ports 10: assessed 2, OS components 8, unidentified 0, not probed 0",
		"Windows: 4 host(s) assessed at build level (patch level not visible; CVEs apply unless patched)",
		"  Windows components, covered by the build assessment above:\n    389/tcp ldap, 3389/tcp ms-wbt-server\n",
		"  Windows components, not assessed: the Windows build could not be used (see above):\n    3389/tcp ms-wbt-server\n",
		"Identity: cpe:2.3:a:clamav:clamav:0.103.2:*:*:*:*:*:*:* [HIGH] (curated product name)",
		"CVE-0000-0911    HIGH      CVSS 7.5  exploit:NO  KEV:NO  MATCH",
		"Windows: Windows Server 2022 (build 10.0.20348) [HIGH]",
		"Evidence: rdp-ntlm-info on 3389/tcp Product_Version 10.0.20348",
		"Server release because: Microsoft Windows Kerberos on 88/tcp (domain controllers run Windows Server)",
		"1 CVEs apply unless patched: 1 in CISA KEV, 0 with public exploit evidence, 1 critical; 2 undetermined",
		"CVE-0000-0904    CRITICAL  CVSS 9.8  KEV added 2024-05-14  [ransomware]",
		"Windows: Windows 10 1607 (build 10.0.14393) [MEDIUM]",
		"Windows: Windows 11 22H2 (build 10.0.22621) [HIGH]",
		"END OF SUPPORT: support ended 2025-10-14",
		"Not assessed: the host reported different Windows builds (17763 and 14393).",
		"Not assessed: build 29999 is not in the Windows build map",
		"Build-level assessment: the patch level is not visible",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}

	r = cli("--db", db, "nmap", "--format", "json", "../../testdata/nmap/windows-hosts.xml")
	if r.code != exitOK || !strings.Contains(r.stdout, `"windows_hosts": 4`) ||
		!strings.Contains(r.stdout, `"release": "Windows Server 2016"`) || !strings.Contains(r.stdout, `"cve": "CVE-0000-0901"`) {
		t.Errorf("json: exit %d\n%s", r.code, r.stdout)
	}
}
