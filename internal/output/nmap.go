package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/nmap"
	"offline-vulndb/internal/version"
)

type nmapDocument struct {
	OutputVersion string       `json:"output_version"`
	Database      DatabaseInfo `json:"database"`
	Report        *nmap.Report `json:"report"`
}

// WriteNmapJSON writes a scan report as an indented JSON document.
func WriteNmapJSON(w io.Writer, r *nmap.Report, db DatabaseInfo) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(nmapDocument{OutputVersion: OutputVersion, Database: db, Report: r})
}

// WriteNmapText writes a compact, prioritised per-host/per-port report.
func WriteNmapText(w io.Writer, r *nmap.Report) error {
	p := &printer{w: w}
	s := r.Summary
	p.f("Nmap scan: %s\n", orDash(r.Scan.Args))
	p.f("Hosts up %d, down %d | open ports %d: assessed %d, unidentified %d, not probed %d\n",
		s.HostsUp, s.HostsDown, s.OpenPorts, s.Assessed, s.Unidentified, s.NotProbed)
	p.f("Candidate vulnerabilities: %d version matches (%d in CISA KEV, %d with public exploit evidence), %d undetermined\n",
		s.VersionMatches, s.KnownExploited, s.PublicExploit, s.Undetermined)

	for _, h := range r.Hosts {
		p.f("\n%s", h.Address)
		if len(h.Hostnames) > 0 {
			p.f(" (%s)", strings.Join(h.Hostnames, ", "))
		}
		p.f("\n")
		if len(h.OSCPEs) > 0 {
			p.f("  OS (Nmap guess, not assessed): %s\n", strings.Join(h.OSCPEs, ", "))
		}
		if len(h.Services) == 0 {
			p.f("  no open ports\n")
		}
		for _, sr := range h.Services {
			writeServiceText(p, sr)
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

func writeServiceText(p *printer, sr nmap.ServiceReport) {
	desc := strings.TrimSpace(strings.Join([]string{sr.Product, sr.Version}, " "))
	if sr.Tunnel != "" {
		desc = strings.TrimSpace(desc + " (" + sr.Tunnel + ")")
	}
	p.f("  %s\n", strings.TrimSpace(fmt.Sprintf("%d/%s %s %s", sr.Port, sr.Protocol, orDash(sr.Service), desc)))

	if sr.Assessment == nmap.NotProbed {
		p.f("    Not assessed: service guessed from port number (no -sV fingerprint)\n")
		return
	}
	if res := sr.Result; res != nil {
		for _, id := range res.Identities {
			p.f("    Identity: %s [%s]", id.CPE, id.Confidence)
			if strings.HasPrefix(id.Source, "alias:") {
				p.f(" (curated alias)")
			}
			p.f("\n")
		}
	}
	for _, n := range sr.Notes {
		p.f("    Note: %s\n", wrap(n, 10, 100))
	}
	if sr.Result == nil {
		return
	}
	unknown := 0
	for _, v := range sr.Result.Vulnerabilities {
		if v.VersionStatus != version.Match {
			unknown++
			continue
		}
		p.f("    %-16s %-9s %-9s exploit:%-3s KEV:%-3s %s%s\n", v.CVE, orDash(v.Severity), cvssShort(v),
			yesNo(v.PublicExploit), yesNo(v.KnownExploited), v.VersionStatus, flags(v, sr.Result))
	}
	if unknown > 0 {
		p.f("    + %d undetermined (version could not be evaluated; see --format json)\n", unknown)
	}
	if len(sr.Result.Vulnerabilities) == 0 {
		p.f("    No candidate vulnerabilities found\n")
	}
}

func cvssShort(v matcher.Vulnerability) string {
	if v.CVSS == nil {
		return "CVSS n/a"
	}
	return fmt.Sprintf("CVSS %.1f", *v.CVSS)
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

// flags marks results that need a second look: conditional applicability,
// ransomware use, or a match found only through a less certain identity.
func flags(v matcher.Vulnerability, r *matcher.Result) string {
	var f []string
	if v.KnownRansomware {
		f = append(f, "ransomware")
	}
	if v.Applicability == matcher.Conditional {
		f = append(f, "CONDITIONAL")
	}
	if v.MatchedCPE != "" && len(r.Identities) > 0 && v.MatchedCPE != r.Identities[0].CPE {
		f = append(f, "via alias, "+string(v.MatchConfidence))
	}
	if len(f) == 0 {
		return ""
	}
	return "  [" + strings.Join(f, "; ") + "]"
}
