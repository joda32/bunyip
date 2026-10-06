// Package output renders query results as human-readable text or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/version"
)

// Format is an output format name accepted by the CLI.
type Format string

const (
	Text Format = "text"
	JSON Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case Text:
		return Text, nil
	case JSON:
		return JSON, nil
	}
	return "", fmt.Errorf("unsupported format %q (use text or json)", s)
}

// OutputVersion identifies the JSON document layout. Bump it on breaking
// changes so consumers (e.g. a future NSE adapter) can detect them.
const OutputVersion = "1"

// DatabaseInfo is the database provenance included in JSON output.
type DatabaseInfo struct {
	Path            string `json:"path"`
	SchemaVersion   string `json:"schema_version"`
	DatabaseVersion string `json:"database_version"`
	CreatedAt       string `json:"created_at"`
	Dataset         string `json:"dataset,omitempty"`
}

type jsonDocument struct {
	OutputVersion   string                   `json:"output_version"`
	Database        DatabaseInfo             `json:"database"`
	Result          *matcher.Result          `json:"result"`
	RuleEvaluations []matcher.RuleEvaluation `json:"rule_evaluations,omitempty"`
}

// WriteJSON writes the result as an indented JSON document. Rule-level
// evaluations are included only when debug is set.
func WriteJSON(w io.Writer, r *matcher.Result, db DatabaseInfo, debug bool) error {
	doc := jsonDocument{OutputVersion: OutputVersion, Database: db, Result: r}
	if debug {
		doc.RuleEvaluations = r.Evaluations
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep ">= 2.4.49" readable
	return enc.Encode(doc)
}

// WriteText writes a human-readable report.
func WriteText(w io.Writer, r *matcher.Result) error {
	p := &printer{w: w}
	p.f("Product:             %s %s\n", r.Vendor, r.Product)
	p.f("Version:             %s\n", displayVersion(r.Version))
	p.f("Normalized CPE:      %s\n", r.NormalizedCPE)
	p.f("Identity confidence: %s\n", r.IdentityConfidence)
	for _, id := range r.Identities[min(1, len(r.Identities)):] {
		p.f("Also queried:        %s [%s] (%s)\n", id.CPE, id.Confidence, id.Source)
	}
	p.f("\n")

	if len(r.Vulnerabilities) == 0 {
		p.f("No candidate vulnerabilities found (%d match rules evaluated).\n", r.CandidateRules)
	} else {
		p.f("Candidate vulnerabilities: %d version match, %d undetermined\n", r.MatchCount, r.UnknownCount)
		shownUnknownHeader := false
		for _, v := range r.Vulnerabilities {
			if v.VersionStatus != version.Match && !shownUnknownHeader {
				p.f("\nUndetermined (version applicability UNKNOWN; review manually):\n")
				shownUnknownHeader = true
			}
			first := ""
			if len(r.Identities) > 0 {
				first = r.Identities[0].CPE
			}
			writeVuln(p, v, first)
		}
	}

	if len(r.Warnings) > 0 {
		p.f("\nNotes:\n")
		for _, warn := range r.Warnings {
			p.f("  - %s\n", wrap(warn, 4, 100))
		}
	}
	return p.err
}

func writeVuln(p *printer, v matcher.Vulnerability, firstIdentity string) {
	p.f("\n%-16s %-9s %s\n", v.CVE, orDash(v.Severity), cvssLabel(v))
	p.f("  Public exploit: %s\n", exploitLabel(v))
	p.f("  CISA KEV:       %s\n", kevLabel(v))
	p.f("  Version status: %s\n", v.VersionStatus)
	p.f("  Confidence:     %s\n", v.MatchConfidence)
	if v.MatchedCPE != "" && v.MatchedCPE != firstIdentity {
		p.f("  Matched via:    %s\n", v.MatchedCPE)
	}
	if v.Applicability != matcher.Unconditional {
		p.f("  Applicability:  %s\n", v.Applicability)
	}
	p.f("  Match reason:   %s\n", wrap(v.MatchReason, 18, 100))
	if v.Description != "" {
		p.f("  Description:    %s\n", wrap(v.Description, 18, 100))
	}
	for _, warn := range v.Warnings {
		p.f("  Warning:        %s\n", wrap(warn, 18, 100))
	}
}

// WriteDebug writes the rule-by-rule diagnostic trace.
func WriteDebug(w io.Writer, r *matcher.Result) error {
	p := &printer{w: w}
	p.f("Input CPE: %s\n", r.Input)
	p.f("Normalized CPE: %s\n", r.NormalizedCPE)
	p.f("Vendor: %s\n", r.Vendor)
	p.f("Product: %s\n", r.Product)
	p.f("Version: %s\n", displayVersion(r.Version))
	p.f("Identity confidence: %s\n", r.IdentityConfidence)
	for _, id := range r.Identities {
		p.f("Identity: %s [%s] source=%s comparator=%s rules=%d\n", id.CPE, id.Confidence, id.Source,
			id.Comparator, id.CandidateRules)
	}
	p.f("Candidate match rules: %d\n", r.CandidateRules)
	p.f("Comparator: %s\n", r.Comparator)
	for i, ev := range r.Evaluations {
		cond := ""
		if ev.Conditional {
			cond = " [CONDITIONAL]"
		}
		rng := ""
		if ev.Range != "" {
			rng = " (" + ev.Range + ")"
		}
		p.f("Rule %d: %s%s %s %s%s\n", i+1, ev.Status, cond, ev.CVEID, ev.Criteria, rng)
		p.f("    %s\n", ev.Reason)
	}
	p.f("Applicable CVEs: %d\n", r.MatchCount)
	p.f("Undetermined CVEs: %d\n", r.UnknownCount)
	return p.err
}

// printer accumulates the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func displayVersion(v string) string {
	switch v {
	case "*":
		return "(not specified)"
	case "-":
		return "(not applicable)"
	}
	return v
}

func cvssLabel(v matcher.Vulnerability) string {
	if v.CVSS == nil {
		return "CVSS n/a"
	}
	return fmt.Sprintf("CVSS %.1f (v%s)", *v.CVSS, v.CVSSVersion)
}

func exploitLabel(v matcher.Vulnerability) string {
	if !v.PublicExploit {
		return "NO"
	}
	verified := 0
	for _, e := range v.ExploitEvidence {
		if e.Verified {
			verified++
		}
	}
	s := fmt.Sprintf("YES (%s", strings.Join(v.ExploitSources, ", "))
	if verified == 0 {
		s += "; unverified"
	}
	return s + ")"
}

func kevLabel(v matcher.Vulnerability) string {
	if !v.KnownExploited {
		return "NO"
	}
	s := "YES"
	if v.KEVDateAdded != "" {
		s += " (added " + v.KEVDateAdded
		if v.KnownRansomware {
			s += "; known ransomware use"
		}
		s += ")"
	} else if v.KnownRansomware {
		s += " (known ransomware use)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// wrap word-wraps s to width columns, indenting continuation lines.
func wrap(s string, indent, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	col := indent
	for i, word := range words {
		if i > 0 {
			if col+1+len(word) > width {
				b.WriteString("\n" + strings.Repeat(" ", indent))
				col = indent
			} else {
				b.WriteByte(' ')
				col++
			}
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}
