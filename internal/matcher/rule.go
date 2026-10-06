package matcher

import (
	"fmt"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
	"offline-vulndb/internal/version"
)

// versionIndex is the position of the version attribute in cpe.Attributes().
const versionIndex = 3

// RuleEvaluation is the outcome of checking one match rule against the
// supplied CPE.
type RuleEvaluation struct {
	RuleID   int64          `json:"rule_id"`
	CVEID    string         `json:"cve"`
	Criteria string         `json:"criteria"`
	Range    string         `json:"version_range,omitempty"` // empty when the rule has no bounds
	Status   version.Status `json:"status"`
	Reason   string         `json:"reason"`
	// Conditional is set when the rule only applies together with other
	// configuration conditions (e.g. "running on Windows") that a single
	// supplied CPE cannot satisfy or refute.
	Conditional   bool   `json:"conditional"`
	ConditionNote string `json:"condition_note,omitempty"`
}

// EvaluateRule decides whether a vulnerable match rule applies to the
// supplied CPE.
//
// Semantics:
//   - every non-version attribute is compared with CPE name-matching rules:
//     a disjoint attribute means NO_MATCH; a criteria value more specific than
//     the supplied value (e.g. criteria target_hw "x64", supplied ANY) means
//     UNKNOWN;
//   - the version is checked against either the criteria's concrete version
//     or the rule's range bounds using the comparator;
//   - NO_MATCH from any check wins; otherwise any UNKNOWN wins; only when
//     every check passes is the rule a MATCH.
func EvaluateRule(cmp version.Comparator, supplied cpe.CPE, rule database.MatchRule) RuleEvaluation {
	ev := RuleEvaluation{
		RuleID:   rule.ID,
		CVEID:    rule.CVEID,
		Criteria: rule.Criteria,
	}
	if !rule.Range.IsEmpty() {
		ev.Range = rule.Range.String()
	}
	ev.Conditional, ev.ConditionNote = conditionality(rule)

	crit, err := cpe.ParsePattern(rule.Criteria)
	if err != nil {
		ev.Status, ev.Reason = version.Unknown, fmt.Sprintf("criteria could not be parsed: %v", err)
		return ev
	}

	critAttrs, supAttrs := crit.Attributes(), supplied.Attributes()
	var undecided []string
	for i := range critAttrs {
		if i == versionIndex {
			continue
		}
		switch cpe.CompareAttribute(critAttrs[i], supAttrs[i]) {
		case cpe.RelDisjoint:
			ev.Status = version.NoMatch
			ev.Reason = fmt.Sprintf("%s differs (criteria %q, supplied %q)",
				cpe.AttributeName(i), critAttrs[i], supAttrs[i])
			return ev
		case cpe.RelUnknown:
			undecided = append(undecided, fmt.Sprintf("criteria requires %s %q but supplied CPE does not specify it",
				cpe.AttributeName(i), critAttrs[i]))
		}
	}

	vr := evaluateVersion(cmp, crit.Version, supplied.Version, rule.Range)
	switch {
	case vr.Status == version.NoMatch:
		ev.Status, ev.Reason = version.NoMatch, vr.Reason
	case len(undecided) > 0:
		ev.Status = version.Unknown
		ev.Reason = strings.Join(append(undecided, vr.Reason), "; ")
	default:
		ev.Status, ev.Reason = vr.Status, vr.Reason
	}

	// A vulnerable rule inside a negated node means "affected when NOT this
	// CPE". That cannot be turned into a positive result for this CPE.
	if rule.NodeNegate && ev.Status == version.Match {
		ev.Status = version.Unknown
		ev.Reason += "; rule is in a negated configuration node, which is not evaluated"
	}
	return ev
}

// evaluateVersion checks the supplied version attribute against the
// criteria version attribute and the rule's range bounds.
func evaluateVersion(cmp version.Comparator, critV, supV string, r version.Range) version.Result {
	switch {
	case critV == cpe.Any:
		if r.IsEmpty() {
			return version.Result{Status: version.Match, Reason: "rule affects all versions"}
		}
		if !cpe.IsSpecific(supV) {
			return version.Result{Status: version.Unknown,
				Reason: fmt.Sprintf("no version supplied; rule affects %s", r)}
		}
		return version.EvaluateRange(cmp, cpe.Unescape(supV), r)

	case !r.IsEmpty():
		// NVD does not combine a concrete criteria version with range bounds;
		// refuse to guess what such a rule means.
		return version.Result{Status: version.Unknown,
			Reason: fmt.Sprintf("rule has both criteria version %q and range bounds (%s); unsupported", critV, r)}

	case supV == cpe.Any:
		return version.Result{Status: version.Unknown,
			Reason: fmt.Sprintf("no version supplied; rule affects version %s only", critV)}

	case critV == cpe.NA || supV == cpe.NA:
		if critV == supV {
			return version.Result{Status: version.Match, Reason: "version is not applicable (NA) on both sides"}
		}
		return version.Result{Status: version.NoMatch,
			Reason: fmt.Sprintf("version differs (criteria %q, supplied %q)", critV, supV)}

	case cpe.HasWildcard(critV):
		if cpe.CompareAttribute(critV, supV) == cpe.RelMatch {
			return version.Result{Status: version.Match,
				Reason: fmt.Sprintf("version %s matches criteria pattern %s", supV, critV)}
		}
		return version.Result{Status: version.NoMatch,
			Reason: fmt.Sprintf("version %s does not match criteria pattern %s", supV, critV)}

	default:
		return version.EvaluateExact(cmp, cpe.Unescape(supV), cpe.Unescape(critV))
	}
}

// conditionality reports whether a rule depends on other configuration
// conditions. With only one supplied CPE we cannot evaluate sibling rules
// combined by AND (typically "application X running on platform Y").
func conditionality(r database.MatchRule) (bool, string) {
	if !r.HasNode {
		return false, ""
	}
	if r.NodeNegate {
		return true, "rule is in a negated configuration node"
	}
	if r.AndConfigSiblings {
		return true, "configuration requires other conditions as well (AND), e.g. a specific platform; these were not evaluated"
	}
	if r.AndNodeSiblings {
		return true, "configuration node requires several CPEs together (AND); the others were not evaluated"
	}
	return false, ""
}
