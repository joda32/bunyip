package version

import (
	"fmt"
	"strings"
)

// Generic is a deliberately conservative comparator for dotted versions.
//
// Accepted grammar: one or more '.'-separated segments, each made of digits
// optionally followed by a letter run and optional digits:
//
//	2.4.49   1.10   8.9p1   1.1.1k   10.0.19045
//
// Ordering rules:
//   - segments compare numerically (1.9 < 1.10);
//   - missing trailing segments count as 0 (2.4 == 2.4.0 < 2.4.1);
//   - suffixes compare only when both sides have the same letter run
//     (8.9p1 < 8.9p2); different letter runs such as 1.1.1k vs 1.1.1m are
//     not ordered alphabetically;
//   - a suffix on one side only, or differing letter runs, is incomparable
//     (9.3 vs 9.3p2, 1.0rc1 vs 1.0p1) because schemes disagree on whether a
//     suffix sorts before or after the bare release.
//
// Anything else (distro revisions such as 7.4.33-1ubuntu1, 2.4.49-r0,
// 1.2.3.RELEASE, leading "v") is rejected so the caller reports UNKNOWN.
type Generic struct{}

func (Generic) Name() string { return "generic" }

type segment struct {
	num    string // digits, leading zeros stripped ("0" for zero)
	letter string // suffix letters, lower case, may be empty
	sufnum string // digits after the letters, leading zeros stripped, may be empty
}

func (Generic) Compare(a, b string) (int, error) {
	sa, err := parseGeneric(a)
	if err != nil {
		return 0, err
	}
	sb, err := parseGeneric(b)
	if err != nil {
		return 0, err
	}
	n := max(len(sa), len(sb))
	for i := range n {
		x, y := segAt(sa, i), segAt(sb, i)
		if c := compareDigits(x.num, y.num); c != 0 {
			return c, nil
		}
		if x.letter == "" && y.letter == "" {
			continue
		}
		if x.letter != y.letter {
			return 0, fmt.Errorf("generic comparator cannot order suffixes %q and %q", a, b)
		}
		if c := compareDigits(orZero(x.sufnum), orZero(y.sufnum)); c != 0 {
			return c, nil
		}
	}
	return 0, nil
}

func segAt(s []segment, i int) segment {
	if i < len(s) {
		return s[i]
	}
	return segment{num: "0"}
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// parseGeneric splits a version into segments, rejecting anything outside the
// accepted grammar.
func parseGeneric(v string) ([]segment, error) {
	if v == "" {
		return nil, fmt.Errorf("empty version")
	}
	var segs []segment
	for _, part := range strings.Split(v, ".") {
		s, ok := parseSegment(strings.ToLower(part))
		if !ok {
			return nil, fmt.Errorf("unsupported version format %q for generic comparator", v)
		}
		segs = append(segs, s)
	}
	return segs, nil
}

func parseSegment(p string) (segment, bool) {
	i := 0
	for i < len(p) && isDigit(p[i]) {
		i++
	}
	if i == 0 {
		return segment{}, false // must start with a digit
	}
	j := i
	for j < len(p) && p[j] >= 'a' && p[j] <= 'z' {
		j++
	}
	k := j
	for k < len(p) && isDigit(p[k]) {
		k++
	}
	if k != len(p) || (j == i && k != j) {
		return segment{}, false
	}
	s := segment{num: trimZeros(p[:i]), letter: p[i:j]}
	if k > j {
		s.sufnum = trimZeros(p[j:k])
	}
	return s, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func trimZeros(d string) string {
	d = strings.TrimLeft(d, "0")
	if d == "" {
		return "0"
	}
	return d
}

// compareDigits compares two non-negative decimal strings without leading
// zeros, avoiding integer overflow on very long build numbers.
func compareDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
