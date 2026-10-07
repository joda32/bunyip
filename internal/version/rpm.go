package version

import (
	"fmt"
	"strings"
)

// RPM compares RPM package versions ([epoch:]version-release) with rpm's
// rpmvercmp algorithm: alternating numeric and alphabetic segments,
// separators ignored, numeric segments newer than alphabetic ones, "~"
// sorting before everything (pre-releases) and "^" after the end of a
// version but before any further segment (post-release snapshots).
type RPM struct{}

func (RPM) Name() string { return "rpm" }

func (RPM) Compare(a, b string) (int, error) {
	va, err := ParseRPM(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseRPM(b)
	if err != nil {
		return 0, err
	}
	return CompareRPM(va, vb), nil
}

// ParseRPM splits "[epoch:]version[-release]". The release is everything
// after the last '-'.
func ParseRPM(s string) (EVR, error) {
	v := EVR{Epoch: "0"}
	rest := s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		v.Epoch, rest = rest[:i], rest[i+1:]
		if !allDigits(v.Epoch) {
			return v, fmt.Errorf("invalid epoch in RPM version %q", s)
		}
		v.Epoch = trimZeros(v.Epoch)
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Upstream, v.Revision = rest[:i], rest[i+1:]
	} else {
		v.Upstream = rest
	}
	if v.Upstream == "" {
		return v, fmt.Errorf("empty RPM version %q", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return v, fmt.Errorf("invalid character in RPM version %q", s)
		}
	}
	return v, nil
}

// CompareRPM orders two parsed RPM versions.
func CompareRPM(a, b EVR) int {
	if c := compareDigits(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := rpmvercmp(a.Upstream, b.Upstream); c != 0 {
		return c
	}
	return rpmvercmp(a.Revision, b.Revision)
}

func isAlnum(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// rpmvercmp is a port of rpm's lib/rpmvercmp.c.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// Tilde: sorts before everything, including the end of the string.
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i++
			j++
			continue
		}
		// Caret: sorts after the end of the string, before anything else.
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !ca {
				return 1
			}
			if !cb {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		// Take the next segment: digits, or letters, from a; the same kind from b.
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA, segB := a[si:i], b[sj:j]
		if segB == "" {
			// Different segment kinds: numeric is newer than alphabetic.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			if c := compareDigits(trimZeros(segA), trimZeros(segB)); c != 0 {
				return c
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	// Whichever has segments left is newer.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}
