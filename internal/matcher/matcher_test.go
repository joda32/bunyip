package matcher

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"bunyip/internal/cpe"
	"bunyip/internal/database"
	"bunyip/internal/version"
)

const fixturePath = "../../testdata/fixtures/synthetic.json"

func mustCPE(t *testing.T, s string) cpe.CPE {
	t.Helper()
	c, err := cpe.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEvaluateRule(t *testing.T) {
	apacheAny := "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
	tests := []struct {
		name     string
		supplied string
		rule     database.MatchRule
		want     version.Status
		wantCond bool
	}{
		{"range match", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny, Range: version.Range{StartIncluding: "2.4.49", EndExcluding: "2.4.51"}},
			version.Match, false},
		{"range below", "cpe:/a:apache:http_server:2.4.48",
			database.MatchRule{Criteria: apacheAny, Range: version.Range{StartIncluding: "2.4.49", EndExcluding: "2.4.51"}},
			version.NoMatch, false},
		{"no range means all versions", "cpe:/a:apache:http_server:1.0",
			database.MatchRule{Criteria: apacheAny}, version.Match, false},
		{"no range, no supplied version", "cpe:/a:apache:http_server",
			database.MatchRule{Criteria: apacheAny}, version.Match, false},
		{"range, no supplied version", "cpe:/a:apache:http_server",
			database.MatchRule{Criteria: apacheAny, Range: version.Range{EndExcluding: "2.4.51"}},
			version.Unknown, false},
		{"range, NA supplied version", "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*",
			database.MatchRule{Criteria: apacheAny, Range: version.Range{EndExcluding: "2.4.51"}},
			version.Unknown, false},
		{"malformed supplied version", "cpe:/a:apache:http_server:2.4.49-r0",
			database.MatchRule{Criteria: apacheAny, Range: version.Range{EndExcluding: "2.4.51"}},
			version.Unknown, false},
		{"exact version match", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
			version.Match, false},
		{"exact version differs", "cpe:/a:apache:http_server:2.4.50",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
			version.NoMatch, false},
		{"exact version, no supplied version", "cpe:/a:apache:http_server",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
			version.Unknown, false},
		{"exact version plus range unsupported", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
				Range: version.Range{EndExcluding: "2.4.51"}},
			version.Unknown, false},
		{"version pattern", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*"},
			version.Match, false},
		{"vendor differs", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "cpe:2.3:a:other:http_server:*:*:*:*:*:*:*:*"},
			version.NoMatch, false},
		{"part differs", "cpe:/o:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny}, version.NoMatch, false},
		{"criteria target_hw more specific", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:x64:*",
				Range: version.Range{EndExcluding: "2.4.60"}},
			version.Unknown, false},
		{"criteria target_hw more specific but version outside", "cpe:/a:apache:http_server:2.4.61",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:x64:*",
				Range: version.Range{EndExcluding: "2.4.60"}},
			version.NoMatch, false},
		{"supplied target_hw matches", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:x64:*",
			database.MatchRule{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:x64:*",
				Range: version.Range{EndExcluding: "2.4.60"}},
			version.Match, false},
		{"openssh update split, generic comparator", "cpe:/a:openbsd:openssh:8.9p1",
			database.MatchRule{Criteria: "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"},
			version.Unknown, false},
		{"openssh update split, both given", "cpe:/a:openbsd:openssh:8.9:p1",
			database.MatchRule{Criteria: "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"},
			version.Match, false},
		{"unparseable criteria", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: "garbage"}, version.Unknown, false},
		{"AND configuration is conditional", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny, HasNode: true, ConfigOperator: "AND", AndConfigSiblings: true,
				NodeOperator: "OR"},
			version.Match, true},
		{"AND node is conditional", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny, HasNode: true, ConfigOperator: "OR",
				NodeOperator: "AND", AndNodeSiblings: true},
			version.Match, true},
		{"OR configuration is unconditional", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny, HasNode: true, ConfigOperator: "OR",
				NodeOperator: "OR"},
			version.Match, false},
		{"negated node never matches", "cpe:/a:apache:http_server:2.4.49",
			database.MatchRule{Criteria: apacheAny, HasNode: true, NodeNegate: true, ConfigOperator: "OR",
				NodeOperator: "OR"},
			version.Unknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := EvaluateRule(version.Generic{}, mustCPE(t, tt.supplied), tt.rule)
			if ev.Status != tt.want {
				t.Errorf("status = %s (%s), want %s", ev.Status, ev.Reason, tt.want)
			}
			if ev.Conditional != tt.wantCond {
				t.Errorf("conditional = %v, want %v", ev.Conditional, tt.wantCond)
			}
			if ev.Reason == "" {
				t.Error("empty reason")
			}
		})
	}
}

// fixtureEngine builds a temporary fixture database and returns an engine.
func fixtureEngine(t *testing.T) *Engine {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bunyip.sqlite")
	s, err := database.Create(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := database.LoadFixture(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportFixture(ctx, f); err != nil {
		t.Fatal(err)
	}
	s.Close()
	ro, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	e, err := New(ctx, ro)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// statuses maps CVE ID to version status for a result.
func statuses(r *Result) map[string]version.Status {
	m := map[string]version.Status{}
	for _, v := range r.Vulnerabilities {
		m[v.CVE] = v.VersionStatus
	}
	return m
}

func TestQueryFixtureScenarios(t *testing.T) {
	e := fixtureEngine(t)
	type want map[string]version.Status // absent CVE = not returned (NO_MATCH)
	tests := []struct {
		name     string
		cpe      string
		identity Confidence
		want     want
	}{
		{"apache 2.4.49 exact match + inclusive lower bound", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", Exact,
			want{"CVE-0000-0001": version.Match, "CVE-0000-0002": version.Match, "CVE-0000-0003": version.Match,
				"CVE-0000-0005": version.Match, "CVE-0000-0006": version.Unknown}},
		{"apache 2.2-style input normalised identically", "cpe:/a:apache:http_server:2.4.49", Exact,
			want{"CVE-0000-0001": version.Match, "CVE-0000-0002": version.Match, "CVE-0000-0003": version.Match,
				"CVE-0000-0005": version.Match, "CVE-0000-0006": version.Unknown}},
		{"apache 2.4.48 immediately below range; exclusive lower bound", "cpe:/a:apache:http_server:2.4.48", Exact,
			want{"CVE-0000-0005": version.Match, "CVE-0000-0006": version.Unknown}},
		{"apache 2.4.50 inclusive upper bound", "cpe:/a:apache:http_server:2.4.50", Exact,
			want{"CVE-0000-0001": version.Match, "CVE-0000-0003": version.Match,
				"CVE-0000-0005": version.Match, "CVE-0000-0006": version.Unknown}},
		{"apache 2.4.51 exclusive upper bound", "cpe:/a:apache:http_server:2.4.51", Exact,
			want{"CVE-0000-0005": version.Match, "CVE-0000-0006": version.Unknown}},
		{"apache no version", "cpe:/a:apache:http_server", Low,
			want{"CVE-0000-0001": version.Unknown, "CVE-0000-0002": version.Unknown, "CVE-0000-0003": version.Unknown,
				"CVE-0000-0004": version.Unknown, "CVE-0000-0005": version.Unknown, "CVE-0000-0006": version.Unknown}},
		{"apache malformed version", "cpe:/a:apache:http_server:2.4.49-r0", Exact,
			want{"CVE-0000-0001": version.Unknown, "CVE-0000-0002": version.Unknown, "CVE-0000-0003": version.Unknown,
				"CVE-0000-0004": version.Unknown, "CVE-0000-0005": version.Unknown, "CVE-0000-0006": version.Unknown}},
		{"nginx inclusive upper bound", "cpe:/a:f5:nginx:1.20.1", Exact,
			want{"CVE-0000-0101": version.Match}},
		{"nginx above inclusive upper bound", "cpe:/a:f5:nginx:1.20.2", Exact, want{}},
		{"nginx 1.9 inside, numeric ordering", "cpe:/a:f5:nginx:1.9.15", Exact,
			want{"CVE-0000-0102": version.Match}},
		{"nginx 1.10.0 exclusive upper bound", "cpe:/a:f5:nginx:1.10.0", Exact, want{}},
		{"nginx legacy nmap vendor resolved by alias", "cpe:/a:igor_sysoev:nginx:1.20.1", Exact,
			want{"CVE-0000-0101": version.Match}},
		{"openssh p-suffix range", "cpe:/a:openbsd:openssh:8.9p1", Exact,
			want{"CVE-0000-0201": version.Match, "CVE-0000-0202": version.Match}}, // 8.9p1 == 8.9 + update p1
		{"openssh range upper exclusive", "cpe:/a:openbsd:openssh:9.3p2", Exact, want{}},
		{"iis exact version, KEV, no exploit", "cpe:/a:microsoft:internet_information_services:10.0", Exact,
			want{"CVE-0000-0301": version.Match}},
		{"iis old version", "cpe:/a:microsoft:internet_information_services:7.5", Exact,
			want{"CVE-0000-0302": version.Match}},
		{"unknown product", "cpe:/a:nobody:nothing:1.0", Exact, want{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := e.QueryCPE(context.Background(), tt.cpe, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.IdentityConfidence != tt.identity {
				t.Errorf("identity = %s, want %s", r.IdentityConfidence, tt.identity)
			}
			got := statuses(r)
			for id, st := range tt.want {
				if got[id] != st {
					t.Errorf("%s: status %q, want %q", id, got[id], st)
				}
			}
			for id, st := range got {
				if _, ok := tt.want[id]; !ok {
					t.Errorf("unexpected result %s (%s)", id, st)
				}
			}
			for _, v := range r.Vulnerabilities {
				if v.MatchReason == "" {
					t.Errorf("%s has no match_reason", v.CVE)
				}
				if v.VersionStatus == version.NoMatch {
					t.Errorf("%s returned with NO_MATCH", v.CVE)
				}
			}
		})
	}
}

func TestQueryEnrichment(t *testing.T) {
	e := fixtureEngine(t)
	r, err := e.QueryCPE(context.Background(), "cpe:/a:apache:http_server:2.4.49", nil)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Vulnerability{}
	for _, v := range r.Vulnerabilities {
		by[v.CVE] = v
	}

	v1 := by["CVE-0000-0001"]
	if !v1.KnownExploited || !v1.PublicExploit || len(v1.ExploitSources) != 2 || v1.Severity != "CRITICAL" ||
		v1.CVSS == nil || *v1.CVSS != 9.8 || v1.MatchConfidence != Exact || v1.Applicability != Unconditional {
		t.Errorf("unexpected enrichment for 0001: %+v", v1)
	}
	if !strings.Contains(v1.MatchReason, "Exact supplied CPE matched vulnerability criteria") ||
		!strings.Contains(v1.MatchReason, "within affected range") {
		t.Errorf("unexpected match reason: %s", v1.MatchReason)
	}

	v2 := by["CVE-0000-0002"]
	if v2.KnownExploited || !v2.PublicExploit || v2.ExploitEvidence[0].Verified {
		t.Errorf("0002 should have unverified exploit evidence and no KEV: %+v", v2)
	}

	v3 := by["CVE-0000-0003"]
	if v3.KnownExploited || v3.PublicExploit || len(v3.ExploitSources) != 0 {
		t.Errorf("0003 should have no exploit/KEV evidence: %+v", v3)
	}

	v5 := by["CVE-0000-0005"]
	if v5.Applicability != Conditional || len(v5.Warnings) == 0 {
		t.Errorf("0005 should be conditional with a warning: %+v", v5)
	}

	iis, err := e.QueryCPE(context.Background(), "cpe:/a:microsoft:internet_information_services:10.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	vi := iis.Vulnerabilities[0]
	if !vi.KnownExploited || !vi.KnownRansomware || vi.PublicExploit {
		t.Errorf("IIS KEV enrichment wrong: %+v", vi)
	}
}

func TestQueryOrdering(t *testing.T) {
	e := fixtureEngine(t)
	r, err := e.QueryCPE(context.Background(), "cpe:/a:apache:http_server:2.4.49", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range r.Vulnerabilities {
		got = append(got, v.CVE)
	}
	// KEV+exploit, then exploit, then by CVSS (0005 8.1 > 0003 5.3), then UNKNOWN last.
	want := []string{"CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0005", "CVE-0000-0003", "CVE-0000-0006"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", got, want)
	}
	if r.MatchCount != 4 || r.UnknownCount != 1 || r.CandidateRules != 6 {
		t.Errorf("counts: match=%d unknown=%d rules=%d", r.MatchCount, r.UnknownCount, r.CandidateRules)
	}
	if len(r.Evaluations) != 6 {
		t.Errorf("evaluations = %d, want 6", len(r.Evaluations))
	}
}

func TestQueryWarnings(t *testing.T) {
	e := fixtureEngine(t)
	r, err := e.QueryCPE(context.Background(), "cpe:/a:apache:http_server:2.4.49", nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Warnings, "\n")
	if !strings.Contains(joined, "backported") || !strings.Contains(joined, "SYNTHETIC") {
		t.Errorf("missing warnings: %v", r.Warnings)
	}
}

func TestQueryErrors(t *testing.T) {
	e := fixtureEngine(t)
	tests := []struct {
		in   string
		want error
	}{
		{"not a cpe", cpe.ErrMalformed},
		{"cpe:/a", ErrInsufficientIdentity},
		{"cpe:/a:apache", ErrInsufficientIdentity},
		{"cpe:2.3:a:*:http_server:2.4.49:*:*:*:*:*:*:*", ErrInsufficientIdentity},
		{"cpe:2.3:a:apache:-:2.4.49:*:*:*:*:*:*:*", ErrInsufficientIdentity},
	}
	for _, tt := range tests {
		_, err := e.QueryCPE(context.Background(), tt.in, nil)
		if !errors.Is(err, tt.want) {
			t.Errorf("QueryCPE(%q) error = %v, want %v", tt.in, err, tt.want)
		}
	}
}

func TestEvaluateRuleOpenSSHJoin(t *testing.T) {
	var o version.OpenSSH
	tests := []struct {
		supplied, criteria string
		r                  version.Range
		want               version.Status
	}{
		// The real CVE-2023-38408 rule set: < 9.3, 9.3:-, 9.3:p1 (fixed in 9.3p2).
		{"cpe:/a:openbsd:openssh:9.3p1", "cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", version.Range{}, version.Match},
		{"cpe:/a:openbsd:openssh:9.3p1", "cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", version.Range{}, version.Match},
		{"cpe:/a:openbsd:openssh:9.3p2", "cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", version.Range{}, version.NoMatch},
		{"cpe:/a:openbsd:openssh:9.3p2", "cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", version.Range{}, version.NoMatch},
		{"cpe:/a:openbsd:openssh:9.3p1", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", version.Range{EndExcluding: "9.3"}, version.NoMatch},
		{"cpe:/a:openbsd:openssh:9.6p1", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
			version.Range{StartIncluding: "8.5p1", EndExcluding: "9.8p1"}, version.Match}, // regreSSHion
		// Supplied split form is joined too.
		{"cpe:/a:openbsd:openssh:9.3:p1", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", version.Range{EndExcluding: "9.3p2"}, version.Match},
		// Distro version strings remain undecidable.
		{"cpe:/a:openbsd:openssh:9.6p1-3ubuntu13", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", version.Range{EndExcluding: "9.8p1"}, version.Unknown},
	}
	for _, tt := range tests {
		ev := EvaluateRule(o, mustCPE(t, tt.supplied), database.MatchRule{Criteria: tt.criteria, Range: tt.r})
		if ev.Status != tt.want {
			t.Errorf("%s vs %s %v = %s (%s), want %s", tt.supplied, tt.criteria, tt.r, ev.Status, ev.Reason, tt.want)
		}
	}
}

func TestQueryAliasIdentity(t *testing.T) {
	e := fixtureEngine(t)
	r, err := e.QueryCPE(context.Background(), "cpe:/a:igor_sysoev:nginx:1.20.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Identities) != 2 || r.Identities[0].Confidence != Exact || r.Identities[1].Confidence != High ||
		r.Identities[1].CPE != "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected identities: %+v", r.Identities)
	}
	v := r.Vulnerabilities[0]
	if v.MatchConfidence != High || v.MatchedCPE != r.Identities[1].CPE ||
		!strings.HasPrefix(v.MatchReason, "Curated alias identity f5:nginx matched") {
		t.Errorf("alias match not attributed: %+v", v)
	}
	if r.IdentityConfidence != Exact || r.NormalizedCPE != "cpe:2.3:a:igor_sysoev:nginx:1.20.1:*:*:*:*:*:*:*" {
		t.Errorf("top-level identity should be the observed CPE: %+v", r)
	}
}

func TestQueryComparatorPerProduct(t *testing.T) {
	e := fixtureEngine(t)
	r, err := e.QueryCPE(context.Background(), "cpe:/a:openbsd:openssh:8.9p1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Comparator != "openssh" {
		t.Errorf("comparator = %s, want openssh", r.Comparator)
	}
}
