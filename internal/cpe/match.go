package cpe

// Relation describes how a supplied (observed) attribute value relates to a
// criteria attribute value, following the CPE Name Matching specification
// (NISTIR 7696) in simplified form.
type Relation int

const (
	// RelMatch: the criteria value covers the supplied value
	// (criteria ANY, equal values, or a wildcard pattern that matches).
	RelMatch Relation = iota
	// RelDisjoint: the values cannot refer to the same thing.
	RelDisjoint
	// RelUnknown: the supplied value is less specific than the criteria
	// (e.g. supplied ANY, criteria "sp1"), so applicability cannot be decided
	// from the supplied name alone. This must never be treated as a match.
	RelUnknown
)

func (r Relation) String() string {
	switch r {
	case RelMatch:
		return "match"
	case RelDisjoint:
		return "disjoint"
	default:
		return "unknown"
	}
}

// CompareAttribute relates a supplied attribute value to a criteria value.
// Both must be canonical values as produced by Parse / ParsePattern.
func CompareAttribute(criteria, supplied string) Relation {
	switch {
	case criteria == Any:
		return RelMatch
	case criteria == supplied:
		return RelMatch
	case supplied == Any:
		return RelUnknown
	case criteria == NA || supplied == NA:
		return RelDisjoint
	case hasWildcard(criteria) && globMatch(criteria, supplied):
		return RelMatch
	default:
		return RelDisjoint
	}
}

// HasWildcard reports whether a canonical value contains an unescaped
// '*' or '?' wildcard (other than being the whole-value ANY).
func HasWildcard(v string) bool {
	return v != Any && hasWildcard(v)
}

func hasWildcard(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}

// globMatch matches canonical value s against pattern p where unescaped '*'
// matches any sequence and '?' matches exactly one character. Escaped
// characters ("\x") are compared as two-byte units on both sides, which is
// correct because both values are canonically escaped.
func globMatch(p, s string) bool {
	if p == "" {
		return s == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		if s == "" {
			return false
		}
		n := 1
		if s[0] == '\\' && len(s) > 1 {
			n = 2
		}
		return globMatch(p[1:], s[n:])
	case '\\':
		if len(p) < 2 || len(s) < 2 || s[0] != '\\' || s[1] != p[1] {
			return false
		}
		return globMatch(p[2:], s[2:])
	default:
		if s == "" || s[0] != p[0] {
			return false
		}
		return globMatch(p[1:], s[1:])
	}
}
