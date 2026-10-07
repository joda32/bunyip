package version

import (
	"fmt"
	"strings"
)

// Dpkg compares Debian/Ubuntu package versions ([epoch:]upstream[-revision])
// with the dpkg algorithm (deb-version(7)): epochs numerically, then
// upstream and revision with verrevcmp, where "~" sorts before everything,
// even the end of the string ("1.0~rc1" < "1.0").
type Dpkg struct{}

func (Dpkg) Name() string { return "dpkg" }

// EVR is a parsed distribution package version: [epoch:]upstream[-revision]
// (Debian upstream/revision, RPM version/release).
type EVR struct {
	Epoch    string // digits; "0" when absent
	Upstream string
	Revision string // "" when absent
}

// DebVersion is a parsed Debian package version.
type DebVersion = EVR

func (v EVR) String() string {
	s := v.Upstream
	if v.Epoch != "0" {
		s = v.Epoch + ":" + s
	}
	if v.Revision != "" {
		s += "-" + v.Revision
	}
	return s
}

// ParseDeb parses a Debian package version.
func ParseDeb(s string) (DebVersion, error) {
	v := DebVersion{Epoch: "0"}
	rest := s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		v.Epoch, rest = rest[:i], rest[i+1:]
		if !allDigits(v.Epoch) {
			return v, fmt.Errorf("invalid epoch in Debian version %q", s)
		}
		v.Epoch = trimZeros(v.Epoch)
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Upstream, v.Revision = rest[:i], rest[i+1:]
		if v.Revision == "" {
			return v, fmt.Errorf("empty revision in Debian version %q", s)
		}
	} else {
		v.Upstream = rest
	}
	if v.Upstream == "" || !isDigit(v.Upstream[0]) {
		return v, fmt.Errorf("Debian upstream version must start with a digit: %q", s)
	}
	for _, part := range []string{v.Upstream, v.Revision} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte(".+~-:", c) >= 0) {
				return v, fmt.Errorf("invalid character %q in Debian version %q", c, s)
			}
		}
	}
	return v, nil
}

func (Dpkg) Compare(a, b string) (int, error) {
	va, err := ParseDeb(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseDeb(b)
	if err != nil {
		return 0, err
	}
	return CompareDeb(va, vb), nil
}

// CompareDeb orders two parsed Debian versions.
func CompareDeb(a, b DebVersion) int {
	if c := compareDigits(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := verrevcmp(a.Upstream, b.Upstream); c != 0 {
		return c
	}
	return verrevcmp(a.Revision, b.Revision)
}

// order is dpkg's character weight: digits 0 (handled separately), letters
// by ASCII value, '~' before everything, other characters after letters.
func order(c byte, ok bool) int {
	switch {
	case !ok:
		return 0
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's comparison of an upstream version or revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) (byte, bool) {
		if k < len(s) {
			return s[k], true
		}
		return 0, false
	}
	for i < len(a) || j < len(b) {
		// Non-digit prefix, character by character.
		for {
			ca, oka := at(a, i)
			cb, okb := at(b, j)
			if !(oka && !isDigit(ca)) && !(okb && !isDigit(cb)) {
				break
			}
			if wa, wb := order(ca, oka), order(cb, okb); wa != wb {
				return sign(wa - wb)
			}
			i++
			j++
		}
		// Numeric part, compared as numbers.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
