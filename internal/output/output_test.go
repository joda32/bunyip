package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"bunyip/internal/matcher"
	"bunyip/internal/version"
)

func sampleResult() *matcher.Result {
	score := 9.8
	return &matcher.Result{
		Input:              "cpe:/a:apache:http_server:2.4.49",
		NormalizedCPE:      "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		Part:               "a",
		Vendor:             "apache",
		Product:            "http_server",
		Version:            "2.4.49",
		IdentityConfidence: matcher.Exact,
		Comparator:         "generic",
		CandidateRules:     2,
		MatchCount:         1,
		UnknownCount:       1,
		Vulnerabilities: []matcher.Vulnerability{
			{CVE: "CVE-0000-0001", Severity: "CRITICAL", CVSS: &score, CVSSVersion: "3",
				PublicExploit: true, ExploitSources: []string{"exploit-db"},
				ExploitEvidence: []matcher.Evidence{{Source: "exploit-db", Reference: "x", Verified: true}},
				KnownExploited:  true, KEVDateAdded: "2021-11-03",
				MatchConfidence: matcher.Exact, VersionStatus: version.Match, Applicability: matcher.Unconditional,
				MatchReason: "Exact supplied CPE matched vulnerability criteria."},
			{CVE: "CVE-0000-0006", Severity: "MEDIUM",
				ExploitSources: []string{}, ExploitEvidence: []matcher.Evidence{},
				MatchConfidence: matcher.Exact, VersionStatus: version.Unknown, Applicability: matcher.Unconditional,
				MatchReason: "could not be determined"},
		},
		Warnings: []string{"backport warning"},
		Evaluations: []matcher.RuleEvaluation{
			{RuleID: 1, CVEID: "CVE-0000-0001", Status: version.Match, Reason: "inside"},
			{RuleID: 2, CVEID: "CVE-0000-0006", Status: version.Unknown, Reason: "target_hw"},
		},
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"text", "json", "JSON"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q): %v", ok, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("xml accepted")
	}
}

func TestWriteText(t *testing.T) {
	var b bytes.Buffer
	if err := WriteText(&b, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Product:             apache http_server",
		"Version:             2.4.49",
		"Normalized CPE:      cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		"Identity confidence: EXACT",
		"CVE-0000-0001    CRITICAL  CVSS 9.8 (v3)",
		"Public exploit: YES (exploit-db)",
		"CISA KEV:       YES (added 2021-11-03)",
		"Version status: MATCH",
		"Match reason:",
		"Undetermined (version applicability UNKNOWN",
		"Public exploit: NO",
		"backport warning",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	// The undetermined section must come after the matched CVE.
	if strings.Index(out, "Undetermined") < strings.Index(out, "CVE-0000-0001") {
		t.Error("undetermined section precedes matched results")
	}
}

func TestWriteJSONStable(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, sampleResult(), DatabaseInfo{Path: "x", SchemaVersion: "1"}, false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["output_version"] != OutputVersion {
		t.Errorf("output_version = %v", doc["output_version"])
	}
	if _, ok := doc["rule_evaluations"]; ok {
		t.Error("rule_evaluations present without debug")
	}
	res := doc["result"].(map[string]any)
	vulns := res["vulnerabilities"].([]any)
	v := vulns[0].(map[string]any)
	for _, key := range []string{"cve", "description", "cvss", "severity", "public_exploit", "exploit_sources",
		"known_exploited", "known_ransomware", "match_confidence", "match_reason", "version_status", "applicability"} {
		if _, ok := v[key]; !ok {
			t.Errorf("vulnerability JSON missing %q", key)
		}
	}
	// Empty lists must encode as [] not null for consumers.
	if v2 := vulns[1].(map[string]any); v2["exploit_sources"] == nil {
		t.Error("exploit_sources encoded as null")
	}

	b.Reset()
	if err := WriteJSON(&b, sampleResult(), DatabaseInfo{}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"rule_evaluations"`) {
		t.Error("debug JSON lacks rule_evaluations")
	}
}

func TestWriteDebug(t *testing.T) {
	var b bytes.Buffer
	if err := WriteDebug(&b, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Input CPE: cpe:/a:apache:http_server:2.4.49",
		"Candidate match rules: 2",
		"Comparator: generic",
		"Rule 1: MATCH",
		"Rule 2: UNKNOWN",
		"Applicable CVEs: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("debug output missing %q:\n%s", want, out)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("aaa bbb ccc", 2, 9)
	if got != "aaa bbb\n  ccc" {
		t.Errorf("wrap = %q", got)
	}
}
