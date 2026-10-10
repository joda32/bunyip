package matcher

import (
	"strings"
	"testing"

	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/version"
)

func f64(v float64) *float64 { return &v }

func TestAssignPriority(t *testing.T) {
	match := version.Match
	cases := []struct {
		name string
		v    Vulnerability
		want Priority
	}{
		{"kev is act", Vulnerability{VersionStatus: match, KnownExploited: true}, PriorityAct},
		{"exploit is attend", Vulnerability{VersionStatus: match, PublicExploit: true}, PriorityAttend},
		{"high epss is attend", Vulnerability{VersionStatus: match, EPSSScore: f64(0.6)}, PriorityAttend},
		{"low epss is track", Vulnerability{VersionStatus: match, EPSSScore: f64(0.4)}, PriorityTrack},
		{"nothing is track", Vulnerability{VersionStatus: match}, PriorityTrack},
		{"unknown match is track", Vulnerability{VersionStatus: version.Unknown, KnownExploited: true}, PriorityTrack},
	}
	for _, c := range cases {
		v := c.v
		assignPriority(&v)
		if v.Priority != c.want {
			t.Errorf("%s: got %q, want %q", c.name, v.Priority, c.want)
		}
		if v.PriorityReason == "" {
			t.Errorf("%s: empty reason", c.name)
		}
	}
}

func TestAssignPriorityDistroFixedDemotes(t *testing.T) {
	v := Vulnerability{VersionStatus: version.Match, KnownExploited: true,
		Distro: &distro.Verdict{Status: distro.Fixed}}
	assignPriority(&v)
	if v.Priority != PriorityTrack {
		t.Errorf("distro-fixed KEV should be track, got %q", v.Priority)
	}
}

func TestAssignPriorityConditionalNote(t *testing.T) {
	v := Vulnerability{VersionStatus: version.Match, KnownExploited: true, Applicability: Conditional}
	assignPriority(&v)
	if v.Priority != PriorityAct {
		t.Fatalf("want act, got %q", v.Priority)
	}
	if !strings.Contains(v.PriorityReason, "unevaluated condition") {
		t.Errorf("missing conditional note: %q", v.PriorityReason)
	}
}
