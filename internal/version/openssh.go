package version

import (
	"fmt"
	"strings"
)

// OpenSSH compares OpenSSH versions, including portable releases ("9.3p1").
//
// NVD encodes portable releases two ways: inside the version attribute
// ("versionEndExcluding 9.3p2", criteria version "8.9p1") or split across
// version and update ("cpe:...:openssh:9.3:p1"). Nmap always reports the
// joined form. OpenSSH therefore also implements UpdateJoiner, so the
// matcher compares one effective version on both sides.
//
// Ordering: dotted numeric base first, then the portable level. A bare
// OpenBSD release "X.Y" is treated as equal to its portable counterpart
// "X.Yp1", which is the code it corresponds to. So "9.3p1" is not below a
// "< 9.3" fix boundary and is affected by "<= 9.3", while "9.3p2" > "9.3p1".
type OpenSSH struct{}

func (OpenSSH) Name() string { return "openssh" }

func (OpenSSH) Compare(a, b string) (int, error) {
	pa, err := parseOpenSSH(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseOpenSSH(b)
	if err != nil {
		return 0, err
	}
	n := max(len(pa.base), len(pb.base))
	for i := range n {
		x, y := "0", "0"
		if i < len(pa.base) {
			x = pa.base[i]
		}
		if i < len(pb.base) {
			y = pb.base[i]
		}
		if c := compareDigits(x, y); c != 0 {
			return c, nil
		}
	}
	return compareDigits(pa.portable, pb.portable), nil
}

// JoinUpdate folds an NVD update attribute into the version: ("9.3", "p1")
// -> "9.3p1"; ("9.3", "-") -> "9.3" (the OpenBSD release itself). Other
// update values are not portable levels and are left alone (ok = false).
func (OpenSSH) JoinUpdate(version, update string) (string, bool) {
	switch {
	case update == "-":
		return version, true
	case len(update) > 1 && update[0] == 'p' && allDigits(update[1:]) && !strings.Contains(version, "p"):
		return version + update, true
	}
	return version, false
}

type opensshVersion struct {
	base     []string // numeric segments, leading zeros trimmed
	portable string   // portable level digits; "1" when absent
}

func parseOpenSSH(v string) (opensshVersion, error) {
	s := strings.ToLower(v)
	var out opensshVersion
	out.portable = "1"
	if i := strings.IndexByte(s, 'p'); i >= 0 {
		if !allDigits(s[i+1:]) || i+1 == len(s) {
			return out, fmt.Errorf("unsupported OpenSSH version %q", v)
		}
		out.portable = trimZeros(s[i+1:])
		s = s[:i]
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" || !allDigits(seg) {
			return out, fmt.Errorf("unsupported OpenSSH version %q", v)
		}
		out.base = append(out.base, trimZeros(seg))
	}
	return out, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}
