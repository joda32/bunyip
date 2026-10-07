package version

import "strings"

// Key is the exact-version lookup key: the first two dot-separated segments,
// each reduced to its leading digits without leading zeros, a missing
// second segment counting as 0 ("5" -> "5.0", "8.9p1" -> "8.9"). It returns
// "" for versions that cannot be keyed (ANY "*", NA "-", wildcards, or a
// segment without leading digits).
//
// Versions equal under the Generic and OpenSSH comparators always share a
// key, so a rule for an exact version whose key differs from the observed
// version's key can never match. The database stores each exact-version
// rule's key so such rules are not even read (most Linux kernel rules are
// exact versions of other kernel series). See KeySafe.
func Key(v string) string {
	if v == "" || v == "*" || v == "-" || strings.ContainsAny(v, "*?") {
		return ""
	}
	segs := strings.SplitN(v, ".", 3)
	if len(segs) == 1 {
		segs = append(segs, "0")
	}
	out := make([]string, 2)
	for i := range 2 {
		j := 0
		for j < len(segs[i]) && isDigit(segs[i][j]) {
			j++
		}
		if j == 0 {
			return ""
		}
		out[i] = trimZeros(segs[i][:j])
	}
	return out[0] + "." + out[1]
}

// KeySafe reports whether exact-version rules may be filtered by Key for a
// comparator: equality must imply equal leading numeric segments.
func KeySafe(c Comparator) bool {
	switch c.(type) {
	case Generic, OpenSSH:
		return true
	}
	return false
}
