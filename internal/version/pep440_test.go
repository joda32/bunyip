package version

import "testing"

func TestPEP440Compare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// equality and trailing zeros
		{"1.0", "1.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.0.0", "1.0", 0},
		{"4.2.1", "4.2.1", 0},
		// numeric, not lexical
		{"1.9", "1.10", -1},
		{"2.2.28", "2.2.3", 1},
		// normalisation: leading v, case, separators, aliases
		{"v1.0", "1.0", 0},
		{"1.0A1", "1.0a1", 0},
		{"1.0-a1", "1.0a1", 0},
		{"1.0.alpha1", "1.0a1", 0},
		{"1.0beta2", "1.0b2", 0},
		{"1.0c1", "1.0rc1", 0},
		{"1.0preview1", "1.0rc1", 0},
		// the canonical PEP 440 ordering within a release
		{"1.0.dev1", "1.0a1", -1},
		{"1.0a1", "1.0a2", -1},
		{"1.0a2", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.post1", "1.0.post2", -1},
		{"1.0.post1.dev1", "1.0.post1", -1}, // dev qualifies the post
		{"1.0.dev1", "1.0", -1},
		{"1.0a1.dev1", "1.0a1", -1}, // dev qualifies the pre
		// implicit post-release and aliases
		{"1.0-1", "1.0.post1", 0},
		{"1.0.rev2", "1.0.post2", 0},
		{"1.0.r3", "1.0.post3", 0},
		// epoch
		{"1!1.0", "2.0", 1},
		{"2.0", "1!1.0", -1},
		{"1!1.0", "1!1.0", 0},
		// local versions sort after the public version
		{"1.0", "1.0+local", -1},
		{"1.0+1", "1.0+1.1", -1},
		{"1.0+1", "1.0+abc", 1}, // numeric local segment sorts above alphanumeric
		// realistic Django-style line
		{"3.2", "4.2.1", -1},
		{"4.2", "4.2.1", -1},
		{"4.0rc1", "4.0", -1},
		// big numbers
		{"1.0.99999999999999999", "1.0.1", 1},
	}
	var p PEP440
	for _, tt := range tests {
		got, err := p.Compare(tt.a, tt.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tt.a, tt.b, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		// antisymmetry
		if rev, err := p.Compare(tt.b, tt.a); err != nil || rev != -tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, rev, -tt.want)
		}
	}
}

func TestPEP440Rejects(t *testing.T) {
	for _, tt := range []struct{ a, b string }{
		{"2.2.1-1ubuntu0.1", "2.2.1"}, // distro revision (handled by the distro path)
		{"1.0.1k", "1.0.1"},           // OpenSSL-style letter suffix
		{"1.2.3.RELEASE", "1.2.3"},    // Java qualifier
		{"", "1.0"},                   // empty
		{"1..0", "1.0"},               // empty release segment
		{"not-a-version", "1.0"},      // junk
		{"1.0.post1x", "1.0"},         // trailing junk after post
	} {
		if _, err := (PEP440{}).Compare(tt.a, tt.b); err == nil {
			t.Errorf("Compare(%q, %q): expected error, got none", tt.a, tt.b)
		}
	}
}
