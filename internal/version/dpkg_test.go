package version

import "testing"

func TestDpkgCompare(t *testing.T) {
	// Vectors follow dpkg's own test suite (lib/dpkg/t/t-version.c) plus real
	// Ubuntu/Debian security versions.
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"0:1.0", "1.0", 0},
		{"1.0-0", "1.0", 0},
		{"1.0", "1.0-1", -1},
		{"1:0.1", "2.0", 1}, // epoch wins
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0+b1", -1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0+", -1}, // letters sort before non-letters
		{"1.2.3-1~deb12u1", "1.2.3-1", -1},
		{"1.9", "1.10", -1},
		{"1.001", "1.1", 0},
		{"2.4.52-1ubuntu4.3", "2.4.52-1ubuntu4.12", -1},
		{"1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.18", -1},
		{"1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.7", 1},
		{"1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1},
		{"1:6.6p1-2ubuntu2.13+esm4", "1:6.6p1-2ubuntu2.13", 1},
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"1.0-1build1", "1.0-1ubuntu1", -1},
	}
	var d Dpkg
	for _, tt := range tests {
		got, err := d.Compare(tt.a, tt.b)
		if err != nil || got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", tt.a, tt.b, got, err, tt.want)
		}
		if back, _ := d.Compare(tt.b, tt.a); back != -tt.want {
			t.Errorf("Compare(%q, %q) not antisymmetric", tt.b, tt.a)
		}
	}
}

func TestParseDeb(t *testing.T) {
	v, err := ParseDeb("1:9.6p1-3ubuntu13.18")
	if err != nil || v.Epoch != "1" || v.Upstream != "9.6p1" || v.Revision != "3ubuntu13.18" {
		t.Fatalf("%+v %v", v, err)
	}
	if v.String() != "1:9.6p1-3ubuntu13.18" {
		t.Errorf("String = %q", v.String())
	}
	v, _ = ParseDeb("2.4.52-1ubuntu4.3-extra") // last '-' splits the revision
	if v.Upstream != "2.4.52-1ubuntu4.3" || v.Revision != "extra" {
		t.Errorf("%+v", v)
	}
	for _, bad := range []string{"", "x:1.0", "abc", "1.0-", "1.0_1", "1.0 1"} {
		if _, err := ParseDeb(bad); err == nil {
			t.Errorf("ParseDeb(%q) accepted", bad)
		}
	}
}
