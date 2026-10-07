package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PEP440 compares Python package versions per PEP 440.
//
// It parses epoch, release, pre-release (a/b/rc), post-release, dev-release
// and local version, applying PEP 440 normalisation (case-insensitive, a
// leading "v" allowed, alpha/beta/c/pre/preview and rev/r aliases, flexible
// separators, an implicit "-N" post-release). Ordering follows PEP 440:
//
//	1.0.dev1 < 1.0a1 < 1.0b2 < 1.0rc1 < 1.0 < 1.0.post1 < 1.0.post1.dev2? no
//
// More precisely, for the same release: a dev release sorts before any
// pre-release, pre-releases sort before the final release, the final release
// sorts before post-releases, and a dev segment sorts before the pre/post/
// final it qualifies. Trailing zeros in the release are insignificant
// (1.0 == 1.0.0). A local version (``+abc``) sorts after the same public
// version.
//
// A version outside PEP 440 grammar (e.g. a distro revision like
// "2.2.1-1ubuntu0.1", which the distribution-advisory path handles instead)
// is rejected, so the caller reports UNKNOWN rather than guessing.
type PEP440 struct{}

func (PEP440) Name() string { return "pep440" }

// pep440Re is the canonical PEP 440 pattern (from the specification), made
// case-insensitive and anchored.
var pep440Re = regexp.MustCompile(`(?i)^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?` +
	`(?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?` +
	`\s*$`)

// letter ranks: dev sorts below all, then a < b < rc, then the final
// release, then post. Encoded so pre-release tuples compare correctly.
const (
	phaseDev   = -1 // pure dev release (no pre, no post)
	phaseFinal = 3  // no pre-release (final or post)
)

type pep440 struct {
	epoch   int
	release []int
	// pre: (rank, num). rank is phaseDev/phaseFinal or a letter rank 0..2.
	preRank int
	preNum  int
	post    int // -1 when absent
	dev     int // large sentinel when absent
	local   []localSeg
}

type localSeg struct {
	num   int    // >= 0 for a numeric segment, -1 for alphanumeric
	str   string // set when not numeric
	isNum bool
}

const devAbsent = 1 << 30 // sentinel: no dev segment sorts after any dev

func (PEP440) Compare(a, b string) (int, error) {
	pa, err := parsePEP440(a)
	if err != nil {
		return 0, err
	}
	pb, err := parsePEP440(b)
	if err != nil {
		return 0, err
	}
	return comparePEP440(pa, pb), nil
}

func parsePEP440(v string) (pep440, error) {
	m := pep440Re.FindStringSubmatch(v)
	if m == nil {
		return pep440{}, fmt.Errorf("unsupported version format %q for PEP 440 comparator", v)
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }
	atoi := func(s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("version %q: number %q out of range", v, s)
		}
		return n, nil
	}

	p := pep440{post: -1, dev: devAbsent}
	if e := g("epoch"); e != "" {
		var err error
		if p.epoch, err = atoi(e); err != nil {
			return pep440{}, err
		}
	}
	for _, r := range strings.Split(g("release"), ".") {
		n, err := atoi(r)
		if err != nil {
			return pep440{}, err
		}
		p.release = append(p.release, n)
	}

	hasPre, hasPost, hasDev := g("pre") != "", g("post") != "", g("dev") != ""
	if hasPre {
		p.preRank = preLetterRank(strings.ToLower(g("pre_l")))
		p.preNum = numOrZero(g("pre_n"))
	}
	if hasPost {
		if n1 := g("post_n1"); n1 != "" { // implicit "-N"
			p.post = numOrZero(n1)
		} else {
			p.post = numOrZero(g("post_n2"))
		}
	}
	if hasDev {
		p.dev = numOrZero(g("dev_n"))
	}
	// A pure dev release (no pre, no post) sorts before pre-releases;
	// otherwise a version with no pre-release sorts after them.
	switch {
	case !hasPre && !hasPost && hasDev:
		p.preRank = phaseDev
	case !hasPre:
		p.preRank = phaseFinal
	}
	if loc := g("local"); loc != "" {
		for _, seg := range strings.FieldsFunc(strings.ToLower(loc), func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		}) {
			if n, err := strconv.Atoi(seg); err == nil {
				p.local = append(p.local, localSeg{num: n, isNum: true})
			} else {
				p.local = append(p.local, localSeg{num: -1, str: seg})
			}
		}
	}
	return p, nil
}

func comparePEP440(a, b pep440) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < max(len(a.release), len(b.release)); i++ {
		if c := cmpInt(relAt(a.release, i), relAt(b.release, i)); c != 0 {
			return c
		}
	}
	if c := cmpInt(a.preRank, b.preRank); c != 0 {
		return c
	}
	if c := cmpInt(a.preNum, b.preNum); c != 0 {
		return c
	}
	if c := cmpInt(a.post, b.post); c != 0 {
		return c
	}
	if c := cmpInt(a.dev, b.dev); c != 0 {
		return c
	}
	return cmpLocal(a.local, b.local)
}

func relAt(r []int, i int) int {
	if i < len(r) {
		return r[i]
	}
	return 0
}

// cmpLocal orders local version labels: no local sorts before any local, a
// numeric segment sorts above an alphanumeric one, numerics compare
// numerically and alphanumerics lexically (PEP 440).
func cmpLocal(a, b []localSeg) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		if i >= len(a) {
			return -1
		}
		if i >= len(b) {
			return 1
		}
		x, y := a[i], b[i]
		switch {
		case x.isNum && y.isNum:
			if c := cmpInt(x.num, y.num); c != 0 {
				return c
			}
		case x.isNum != y.isNum:
			if x.isNum {
				return 1
			}
			return -1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return 0
}

func preLetterRank(l string) int {
	switch l {
	case "alpha", "a":
		return 0
	case "beta", "b":
		return 1
	case "c", "pre", "preview", "rc":
		return 2
	}
	return phaseFinal
}

func numOrZero(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
