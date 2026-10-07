package version

import "testing"

func TestGenericCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.49", 0},
		{"2.4.48", "2.4.49", -1},
		{"2.4.50", "2.4.49", 1},
		{"2.4.51", "2.4.50", 1},
		{"1.9", "1.10", -1},
		{"1.10", "1.9", 1},
		{"1.10", "1.10.0", 0},
		{"2.4", "2.4.1", -1},
		{"2.4.0", "2.4", 0},
		{"01.2", "1.2", 0},
		{"8.9p1", "8.9p2", -1},
		{"8.9p2", "8.9p1", 1},
		{"8.9p1", "8.9p1", 0},
		{"8.9p1", "9.3p2", -1},
		{"8.9P1", "8.9p1", 0},
		{"7.4p1", "8.9", -1},
		{"10.0.19045", "10.0.17763", 1},
		{"1.1.1k", "1.1.1k", 0},
		{"99999999999999999999999.1", "99999999999999999999998.9", 1},
	}
	var g Generic
	for _, tt := range tests {
		got, err := g.Compare(tt.a, tt.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tt.a, tt.b, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestGenericIncomparable(t *testing.T) {
	tests := []struct{ a, b string }{
		{"9.3", "9.3p2"},              // suffix on one side only
		{"1.0rc1", "1.0p1"},           // differing suffix letters
		{"1.1.1k", "1.1.1m"},          // letter ordering not assumed
		{"7.4.33-1ubuntu1", "7.4.33"}, // distro revision
		{"2.4.49-r0", "2.4.49"},       // Alpine revision
		{"1.2.3.RELEASE", "1.2.3"},    // qualifier segment
		{"v1.2", "1.2"},               // leading v
		{"", "1.2"},                   // empty
		{"1..2", "1.2"},               // empty segment
		{"1.2.", "1.2"},               // trailing dot
		{"abc", "1.2"},                // not a version
		{"1.2p1x", "1.2p1"},           // trailing letters after suffix number
		{"2.4.49", "2.4.x"},           // bound malformed
	}
	var g Generic
	for _, tt := range tests {
		if c, err := g.Compare(tt.a, tt.b); err == nil {
			t.Errorf("Compare(%q, %q) = %d, want error", tt.a, tt.b, c)
		}
	}
}

func TestEvaluateRange(t *testing.T) {
	tests := []struct {
		name     string
		detected string
		r        Range
		want     Status
	}{
		// No bounds.
		{"empty range affects all", "1.0", Range{}, Match},

		// Start including.
		{"start incl: below", "2.4.47", Range{StartIncluding: "2.4.48"}, NoMatch},
		{"start incl: at boundary", "2.4.48", Range{StartIncluding: "2.4.48"}, Match},
		{"start incl: above", "2.4.49", Range{StartIncluding: "2.4.48"}, Match},

		// Start excluding.
		{"start excl: below", "2.4.47", Range{StartExcluding: "2.4.48"}, NoMatch},
		{"start excl: at boundary", "2.4.48", Range{StartExcluding: "2.4.48"}, NoMatch},
		{"start excl: just above", "2.4.49", Range{StartExcluding: "2.4.48"}, Match},

		// End including.
		{"end incl: below", "2.4.49", Range{EndIncluding: "2.4.50"}, Match},
		{"end incl: at boundary", "2.4.50", Range{EndIncluding: "2.4.50"}, Match},
		{"end incl: above", "2.4.51", Range{EndIncluding: "2.4.50"}, NoMatch},

		// End excluding.
		{"end excl: below", "2.4.50", Range{EndExcluding: "2.4.51"}, Match},
		{"end excl: at boundary", "2.4.51", Range{EndExcluding: "2.4.51"}, NoMatch},
		{"end excl: above", "2.4.52", Range{EndExcluding: "2.4.51"}, NoMatch},

		// Combined bounds.
		{"incl/excl: immediately below", "2.4.47", Range{StartIncluding: "2.4.48", EndExcluding: "2.4.51"}, NoMatch},
		{"incl/excl: lower edge", "2.4.48", Range{StartIncluding: "2.4.48", EndExcluding: "2.4.51"}, Match},
		{"incl/excl: inside", "2.4.49", Range{StartIncluding: "2.4.48", EndExcluding: "2.4.51"}, Match},
		{"incl/excl: upper edge", "2.4.51", Range{StartIncluding: "2.4.48", EndExcluding: "2.4.51"}, NoMatch},
		{"excl/incl: lower edge", "1.9", Range{StartExcluding: "1.9", EndIncluding: "1.10"}, NoMatch},
		{"excl/incl: upper edge", "1.10", Range{StartExcluding: "1.9", EndIncluding: "1.10"}, Match},
		{"numeric not lexical", "1.10", Range{EndExcluding: "1.9"}, NoMatch},

		// OpenSSH-style suffixes.
		{"ssh p-suffix inside", "8.9p1", Range{StartIncluding: "8.5p1", EndExcluding: "9.3p2"}, Match},
		{"ssh p-suffix upper excl", "9.3p2", Range{EndExcluding: "9.3p2"}, NoMatch},
		{"ssh p-suffix below upper", "9.3p1", Range{EndExcluding: "9.3p2"}, Match},
		{"ssh bare vs suffix", "9.3", Range{EndExcluding: "9.3p2"}, Unknown},

		// Uncertainty is never a match.
		{"malformed detected", "2.4.49-r0", Range{EndExcluding: "2.4.51"}, Unknown},
		{"distro version", "7.4.33-1ubuntu1", Range{StartIncluding: "7.4.0"}, Unknown},
		{"one bound violated wins over unknown", "1.0", Range{StartIncluding: "2.0", EndExcluding: "2.x"}, NoMatch},
		{"one bound satisfied one unknown", "2.1", Range{StartIncluding: "2.0", EndExcluding: "2.x"}, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateRange(Generic{}, tt.detected, tt.r)
			if got.Status != tt.want {
				t.Errorf("EvaluateRange(%q, %v) = %s (%s), want %s", tt.detected, tt.r, got.Status, got.Reason, tt.want)
			}
			if got.Reason == "" {
				t.Error("empty reason")
			}
		})
	}
}

func TestEvaluateExact(t *testing.T) {
	tests := []struct {
		detected, affected string
		want               Status
	}{
		{"2.4.49", "2.4.49", Match},
		{"2.4", "2.4.0", Match},
		{"2.4.50", "2.4.49", NoMatch},
		{"2.4.49-r0", "2.4.49", Unknown},
		{"weird-1", "weird-1", Match}, // identical strings match without parsing
	}
	for _, tt := range tests {
		got := EvaluateExact(Generic{}, tt.detected, tt.affected)
		if got.Status != tt.want {
			t.Errorf("EvaluateExact(%q, %q) = %s (%s), want %s", tt.detected, tt.affected, got.Status, got.Reason, tt.want)
		}
	}
}

func TestForSelectsPEP440(t *testing.T) {
	for _, vp := range []struct{ vendor, product string }{
		{"djangoproject", "django"}, {"python", "requests"}, {"palletsprojects", "werkzeug"},
		{"cryptography.io", "cryptography"}, {"aiohttp", "aiohttp"},
	} {
		if got := For(vp.vendor, vp.product).Name(); got != "pep440" {
			t.Errorf("For(%s:%s) = %q, want pep440", vp.vendor, vp.product, got)
		}
	}
	// Unlisted products stay on the generic comparator.
	if got := For("apache", "http_server").Name(); got != "generic" {
		t.Errorf("For(apache:http_server) = %q, want generic", got)
	}
}
