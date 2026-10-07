package output

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/nmap"
	"offline-vulndb/internal/version"
	"offline-vulndb/internal/windows"
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
	p.f("Hosts up %d, down %d | open ports %d: assessed %d, ", s.HostsUp, s.HostsDown, s.OpenPorts, s.Assessed)
	if s.OSComponents > 0 {
		p.f("OS components %d, ", s.OSComponents)
	}
	p.f("unidentified %d, not probed %d\n", s.Unidentified, s.NotProbed)
	p.f("Candidate vulnerabilities: %d version matches (%d in CISA KEV, %d with public exploit evidence), %d undetermined\n",
		s.VersionMatches, s.KnownExploited, s.PublicExploit, s.Undetermined)
	if s.EndOfLife > 0 {
		p.f("END OF LIFE: %d service(s) run on a distribution release past its end of life (no further security updates)\n", s.EndOfLife)
	}
	if s.WindowsHosts > 0 {
		p.f("Windows: %d host(s) assessed at build level (patch level not visible; CVEs apply unless patched)", s.WindowsHosts)
		if s.WindowsEOL > 0 {
			p.f(", %d on a release past its end of support", s.WindowsEOL)
		}
		p.f("\n")
	}
	if s.DistroFixed > 0 || s.DistroOnly > 0 {
		p.f("Distribution advisories: %d upstream matches already fixed in the installed/released package, "+
			"%d findings only the distribution data shows\n", s.DistroFixed, s.DistroOnly)
	}

	for _, h := range r.Hosts {
		p.f("\n%s", h.Address)
		if len(h.Hostnames) > 0 {
			p.f(" (%s)", strings.Join(h.Hostnames, ", "))
		}
		p.f("\n")
		if len(h.OSCPEs) > 0 {
			p.f("  OS (Nmap guess, not assessed): %s\n", strings.Join(h.OSCPEs, ", "))
		}
		if h.DistroRelease != "" {
			p.f("  Distribution release (from an exact package version on this host): %s\n", h.DistroRelease)
		}
		for _, a := range h.Windows {
			writeWindowsText(p, a)
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
			switch {
			case strings.HasPrefix(id.Source, "alias:"):
				p.f(" (curated alias)")
			case strings.HasPrefix(id.Source, "product-name:"):
				p.f(" (curated product name)")
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
	if d := sr.Result.Distro; d != nil {
		p.f("    Distribution: %s\n", wrap(distroContextLabel(sr.Result), 18, 100))
	}
	unknown := 0
	var fixed []string
	for _, v := range sr.Result.Vulnerabilities {
		if v.Distro != nil && v.Distro.Status == distro.Fixed {
			fixed = append(fixed, v.CVE)
			continue
		}
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
	if len(fixed) > 0 {
		p.f("    + %d fixed in the %s package: %s\n", len(fixed), sr.Result.Distro.Target.DistroName,
			wrap(strings.Join(fixed, ", "), 6, 100))
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
	if d := v.Distro; d != nil && d.Status != distro.NoData {
		label := d.Distro + ": " + string(d.Status)
		if v.DistroOnly {
			label += ", advisory only"
		}
		f = append(f, label)
	}
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

// windowsKEVListed is how many KEV entries the text report lists per release.
const windowsKEVListed = 10

func writeWindowsText(p *printer, a windows.Assessment) {
	switch a.Status {
	case windows.Assessed:
		p.f("  Windows: %s (build %s) [%s]\n", a.Release, a.ProductVersion, a.Confidence)
	default:
		p.f("  Windows: build %s\n", a.ProductVersion)
	}
	p.f("    Evidence: %s\n", wrap(strings.Join(a.Evidence, "; "), 14, 100))
	if a.KindEvidence != "" {
		p.f("    %s: %s\n", kindLabel(a.Kind), wrap(a.KindEvidence, 6, 100))
	}
	if a.Status != windows.Assessed {
		for _, n := range a.Notes {
			p.f("    %s\n", wrap(n, 4, 100))
		}
		return
	}
	if a.EndOfLife {
		p.f("    END OF SUPPORT: %s\n", wrap(a.Support, 6, 100))
	} else {
		p.f("    Support: %s\n", wrap(a.Support, 6, 100))
	}
	p.f("    %d CVEs apply unless patched: %d in CISA KEV, %d with public exploit evidence, %d critical",
		a.Applicable, a.KnownExploited, a.PublicExploit, a.Critical)
	if a.Undetermined > 0 {
		p.f("; %d undetermined", a.Undetermined)
	}
	p.f("\n")
	var kev []windows.CVERef
	for _, v := range a.Vulnerabilities {
		if v.KnownExploited && v.VersionStatus == string(version.Match) {
			kev = append(kev, v)
		}
	}
	// Most recently added first: older entries are more likely patched.
	slices.SortStableFunc(kev, func(x, y windows.CVERef) int { return strings.Compare(y.KEVDateAdded, x.KEVDateAdded) })
	if len(kev) > 0 {
		p.f("    KEV, most recently added first:\n")
	}
	for i, v := range kev {
		if i == windowsKEVListed {
			p.f("    ... %d more KEV entries (see --format json)\n", len(kev)-i)
			break
		}
		cvss := "CVSS n/a"
		if v.CVSS != nil {
			cvss = fmt.Sprintf("CVSS %.1f", *v.CVSS)
		}
		extra := ""
		if v.KnownRansomware {
			extra = "  [ransomware]"
		}
		p.f("    %-16s %-9s %-9s KEV added %s%s\n", v.CVE, orDash(v.Severity), cvss, orDash(v.KEVDateAdded), extra)
	}
	for _, n := range a.Notes {
		if n == windows.PatchNote {
			continue // stated once in the report notes
		}
		p.f("    Note: %s\n", wrap(n, 10, 100))
	}
}

func kindLabel(kind string) string {
	if kind == windows.Server {
		return "Server release because"
	}
	return "Client release because"
}
