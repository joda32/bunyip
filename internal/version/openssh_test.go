package version

import "testing"

func TestOpenSSHCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"9.3p1", "9.3p2", -1},
		{"9.3p2", "9.3p1", 1},
		{"9.3", "9.3p1", 0}, // OpenBSD release == first portable release
		{"9.3", "9.3p2", -1},
		{"8.9p1", "9.3", -1},
		{"9.6p1", "9.8p1", -1},
		{"9.6p1", "8.5p1", 1},
		{"3.9.1p1", "3.9p1", 1},
		{"6.6.1p1", "6.6p1", 1},
		{"7.10", "7.9", 1},
		{"7.4P1", "7.4p1", 0},
	}
	var o OpenSSH
	for _, tt := range tests {
		got, err := o.Compare(tt.a, tt.b)
		if err != nil || got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", tt.a, tt.b, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "9.3p", "9.3p1x", "9.3-1ubuntu1", "v9.3", "9..3", "9.3 Ubuntu"} {
		if _, err := o.Compare(bad, "9.3"); err == nil {
			t.Errorf("Compare(%q) accepted", bad)
		}
	}
}

func TestOpenSSHJoinUpdate(t *testing.T) {
	tests := []struct {
		version, update, want string
		ok                    bool
	}{
		{"9.3", "p1", "9.3p1", true},
		{"9.3", "-", "9.3", true},
		{"9.3", "*", "9.3", false},
		{"9.3", "beta", "9.3", false},
		{"9.3p1", "p1", "9.3p1", false}, // already joined: don't double up
	}
	var o OpenSSH
	for _, tt := range tests {
		got, ok := o.JoinUpdate(tt.version, tt.update)
		if got != tt.want || ok != tt.ok {
			t.Errorf("JoinUpdate(%q, %q) = %q, %v; want %q, %v", tt.version, tt.update, got, ok, tt.want, tt.ok)
		}
	}
}

// TestOpenSSHRealRules evaluates the actual NVD rules for CVE-2023-38408
// (fixed in 9.3p2): "< 9.3", "9.3:-", "9.3:p1".
func TestOpenSSHRealRules(t *testing.T) {
	affected := func(detected string) bool {
		var o OpenSSH
		if EvaluateRange(o, detected, Range{EndExcluding: "9.3"}).Status == Match {
			return true
		}
		for _, crit := range []string{"9.3", "9.3p1"} { // 9.3:- and 9.3:p1 joined
			if EvaluateExact(o, detected, crit).Status == Match {
				return true
			}
		}
		return false
	}
	for v, want := range map[string]bool{"8.9p1": true, "9.2p1": true, "9.3p1": true, "9.3p2": false, "9.4p1": false} {
		if got := affected(v); got != want {
			t.Errorf("CVE-2023-38408 affects %s = %v, want %v", v, got, want)
		}
	}
}

func TestFor(t *testing.T) {
	if For("openbsd", "openssh").Name() != "openssh" || For("apache", "http_server").Name() != "generic" {
		t.Error("registry selection wrong")
	}
}
