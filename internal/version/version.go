// Package version compares software versions and evaluates them against
// vulnerability version ranges.
//
// Version semantics differ between ecosystems (Debian, RPM, PEP 440, Windows
// builds, OpenSSH "p" releases, ...), so comparison is behind the Comparator
// interface. A comparator must return an error rather than guess when it
// cannot order two versions; the error becomes an UNKNOWN applicability
// status, never a match.
package version

import (
	"fmt"
	"strings"
)

// Comparator orders two version strings of a particular scheme.
type Comparator interface {
	// Name identifies the comparator in diagnostics (e.g. "generic").
	Name() string
	// Compare returns -1, 0 or +1 when a is less than, equal to or greater
	// than b. It returns an error if either version cannot be parsed or the
	// two cannot be ordered with confidence.
	Compare(a, b string) (int, error)
}

// Status is the outcome of evaluating a detected version against a rule.
type Status string

const (
	Match   Status = "MATCH"    // version is inside the affected range
	NoMatch Status = "NO_MATCH" // version is outside the affected range
	Unknown Status = "UNKNOWN"  // applicability could not be determined
)

// Range holds the NVD-style bounds of an affected version range. Empty
// strings mean "no bound". A range with no bounds at all affects every
// version.
type Range struct {
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// IsEmpty reports whether the range has no bounds.
func (r Range) IsEmpty() bool {
	return r.StartIncluding == "" && r.StartExcluding == "" &&
		r.EndIncluding == "" && r.EndExcluding == ""
}

func (r Range) String() string {
	var parts []string
	if r.StartIncluding != "" {
		parts = append(parts, ">= "+r.StartIncluding)
	}
	if r.StartExcluding != "" {
		parts = append(parts, "> "+r.StartExcluding)
	}
	if r.EndIncluding != "" {
		parts = append(parts, "<= "+r.EndIncluding)
	}
	if r.EndExcluding != "" {
		parts = append(parts, "< "+r.EndExcluding)
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, ", ")
}

// Result is a Status plus a human-readable explanation.
type Result struct {
	Status Status
	Reason string
}

// bound is one side of a range check.
type bound struct {
	value string
	op    string           // for messages: ">=", ">", "<=", "<"
	ok    func(c int) bool // whether Compare(detected, value) satisfies the bound
}

// EvaluateRange checks a detected version against every bound in r.
//
// The detected version must be a concrete version (the caller handles CPE
// ANY/NA). Every bound must be satisfied for MATCH; any violated bound gives
// NO_MATCH; if no bound is violated but at least one could not be compared,
// the result is UNKNOWN.
func EvaluateRange(cmp Comparator, detected string, r Range) Result {
	if r.IsEmpty() {
		return Result{Match, "rule affects all versions"}
	}
	bounds := []bound{
		{r.StartIncluding, ">=", func(c int) bool { return c >= 0 }},
		{r.StartExcluding, ">", func(c int) bool { return c > 0 }},
		{r.EndIncluding, "<=", func(c int) bool { return c <= 0 }},
		{r.EndExcluding, "<", func(c int) bool { return c < 0 }},
	}
	var unknown []string
	for _, b := range bounds {
		if b.value == "" {
			continue
		}
		c, err := cmp.Compare(detected, b.value)
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("cannot compare %q with bound %s %q: %v", detected, b.op, b.value, err))
			continue
		}
		if !b.ok(c) {
			return Result{NoMatch, fmt.Sprintf("version %s is outside affected range (%s): fails %s %s",
				detected, r, b.op, b.value)}
		}
	}
	if len(unknown) > 0 {
		return Result{Unknown, strings.Join(unknown, "; ")}
	}
	return Result{Match, fmt.Sprintf("version %s is within affected range (%s)", detected, r)}
}

// EvaluateExact checks a detected version against a single affected version
// (an NVD criteria with a concrete version and no range bounds).
func EvaluateExact(cmp Comparator, detected, affected string) Result {
	if detected == affected {
		return Result{Match, fmt.Sprintf("version %s equals affected version %s", detected, affected)}
	}
	c, err := cmp.Compare(detected, affected)
	if err != nil {
		return Result{Unknown, fmt.Sprintf("cannot compare %q with affected version %q: %v", detected, affected, err)}
	}
	if c == 0 {
		return Result{Match, fmt.Sprintf("version %s is equivalent to affected version %s", detected, affected)}
	}
	return Result{NoMatch, fmt.Sprintf("version %s is not affected version %s", detected, affected)}
}
