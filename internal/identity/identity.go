// Package identity turns observed software identities (a supplied CPE, or a
// service reported by a discovery tool such as Nmap) into the candidate CPE
// identities that are looked up in the vulnerability database.
//
// Resolution rules:
//   - the observed application CPE is always a candidate (EXACT with a
//     concrete version, LOW without one);
//   - curated aliases from the database add further candidates for the same
//     software under the vendor/product name NVD uses (e.g. Nmap's
//     igor_sysoev:nginx -> f5:nginx). An alias never replaces the observed
//     identity and never raises confidence above the alias's own;
//   - operating-system and hardware CPEs reported alongside a service are
//     not queried as if they were the service;
//   - distribution package versions (Ubuntu, Debian, RHEL, ...) are detected
//     and reported, because vendors backport fixes without changing the
//     upstream version that matching relies on.
package identity

import (
	"fmt"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
)

// Confidence classifies how certain a software identity is.
type Confidence string

const (
	Exact   Confidence = "EXACT"   // observed CPE with a concrete version
	High    Confidence = "HIGH"    // deterministic mapping, e.g. curated vendor alias
	Medium  Confidence = "MEDIUM"  // mapping with strong but indirect evidence
	Low     Confidence = "LOW"     // product only (no version), or ambiguous
	Unknown Confidence = "UNKNOWN" // insufficient evidence
)

var rank = map[Confidence]int{Exact: 4, High: 3, Medium: 2, Low: 1, Unknown: 0}

// Rank orders confidence levels (higher is more certain).
func Rank(c Confidence) int { return rank[c] }

// lower returns the less certain of two confidence levels.
func lower(a, b Confidence) Confidence {
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

// Candidate is one identity to look up.
type Candidate struct {
	CPE        cpe.CPE
	Confidence Confidence
	Source     string // "supplied", "nmap", or "alias:<source>"
	Reason     string
}

// Resolver applies curated aliases.
type Resolver struct {
	aliases map[string][]database.Alias // keyed by part:vendor:product (canonical values)
}

// NewResolver indexes vendor/product aliases. Product-name aliases (no
// observed vendor) are reserved for future banner resolution and ignored.
func NewResolver(aliases []database.Alias) *Resolver {
	r := &Resolver{aliases: map[string][]database.Alias{}}
	for _, a := range aliases {
		if a.ObservedVendor == "" || a.Part == "" {
			continue
		}
		k := key(a.Part, a.ObservedVendor, a.ObservedProduct)
		r.aliases[k] = append(r.aliases[k], a)
	}
	return r
}

func key(part, vendor, product string) string { return part + ":" + vendor + ":" + product }

// baseConfidence is the confidence of an observed CPE on its own.
func baseConfidence(c cpe.CPE) Confidence {
	if cpe.IsSpecific(c.Version) {
		return Exact
	}
	return Low
}

// ResolveCPE returns the observed CPE followed by any alias candidates.
func (r *Resolver) ResolveCPE(c cpe.CPE, source string) []Candidate {
	base := baseConfidence(c)
	reason := "Observed CPE"
	if base == Low {
		reason = "Observed CPE without a specific version"
	}
	out := []Candidate{{CPE: c, Confidence: base, Source: source, Reason: reason}}
	for _, a := range r.aliases[key(c.Part, c.Vendor, c.Product)] {
		alt := c
		alt.Vendor, alt.Product = a.CanonicalVendor, a.CanonicalProduct
		out = append(out, Candidate{
			CPE:        alt,
			Confidence: lower(base, Confidence(a.Confidence)),
			Source:     "alias:" + a.Source,
			Reason: fmt.Sprintf("Curated alias %s:%s -> %s:%s (NVD records this software under %s)",
				c.Vendor, c.Product, a.CanonicalVendor, a.CanonicalProduct, a.CanonicalVendor),
		})
	}
	return out
}

// productNotes are caveats about how NVD records specific products.
var productNotes = map[string]string{
	"microsoft:internet_information_services": "NVD has recorded IIS vulnerabilities against Microsoft Windows " +
		"CPEs since about 2017, so results for the IIS CPE are incomplete. Assess the Windows host itself.",
}

// Notes returns caveats for the products among the candidates.
func Notes(cands []Candidate) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		k := c.CPE.Vendor + ":" + c.CPE.Product
		if n, ok := productNotes[k]; ok && !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	return out
}

// Observation is a service as reported by a discovery tool.
type Observation struct {
	Product   string
	Version   string
	ExtraInfo string
	OSType    string
	CPEs      []string
}

// Resolution is the outcome of resolving an Observation.
type Resolution struct {
	Candidates   []Candidate
	PlatformCPEs []string // OS/hardware CPEs reported with the service, not queried
	Distro       string   // detected distribution packaging, e.g. "Ubuntu package 3ubuntu13.18"
	Notes        []string
}

// ResolveObservation derives candidate identities from a reported service.
func (r *Resolver) ResolveObservation(o Observation, source string) Resolution {
	var res Resolution
	for _, raw := range o.CPEs {
		c, err := cpe.Parse(raw)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("Ignored malformed CPE %q: %v", raw, err))
			continue
		}
		if c.Part != "a" {
			res.PlatformCPEs = append(res.PlatformCPEs, c.String())
			continue
		}
		if !cpe.IsSpecific(c.Vendor) || !cpe.IsSpecific(c.Product) {
			res.Notes = append(res.Notes, fmt.Sprintf("Ignored CPE %s without a specific vendor and product", c))
			continue
		}
		res.Candidates = append(res.Candidates, r.ResolveCPE(c, source)...)
	}
	if len(res.Candidates) == 0 && o.Product != "" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"No application CPE reported for %q; product-name resolution is not supported yet, so it was not assessed.",
			strings.TrimSpace(o.Product+" "+o.Version)))
	}
	res.Distro = DetectDistro(o, res.PlatformCPEs)
	if res.Distro != "" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Distribution package detected (%s): the vendor may have backported security fixes without "+
				"changing the upstream version, so upstream-version matches may be false positives.", res.Distro))
	}
	res.Notes = append(res.Notes, Notes(res.Candidates)...)
	return res
}

// distroMarkers maps lower-case markers in version/extra-info text to a
// distribution name. Order matters: the first match wins.
var distroMarkers = []struct{ marker, name string }{
	{"ubuntu", "Ubuntu"},
	{"debian", "Debian"},
	{"deb1", "Debian"}, // e.g. OpenSSH "9.2p1 Debian 2+deb12u3"
	{"red hat", "Red Hat"},
	{"rhel", "Red Hat"},
	{"centos", "CentOS"},
	{"rocky", "Rocky Linux"},
	{"almalinux", "AlmaLinux"},
	{"fedora", "Fedora"},
	{"suse", "SUSE"},
	{"alpine", "Alpine"},
	{"freebsd", "FreeBSD"},
	{".el7", "Red Hat"}, {".el8", "Red Hat"}, {".el9", "Red Hat"},
}

// distroCPEs maps OS CPE vendor:product prefixes to a distribution name.
var distroCPEs = map[string]string{
	"canonical:ubuntu_linux":       "Ubuntu",
	"debian:debian_linux":          "Debian",
	"redhat:enterprise_linux":      "Red Hat",
	"redhat:linux":                 "Red Hat",
	"centos:centos":                "CentOS",
	"fedoraproject:fedora":         "Fedora",
	"suse:linux_enterprise_server": "SUSE",
	"opensuse:opensuse":            "openSUSE",
	"alpinelinux:alpine_linux":     "Alpine",
	"freebsd:freebsd":              "FreeBSD",
}

// DetectDistro reports distribution packaging evident from the service's
// version/extra-info text or its OS CPEs. It returns "" when none is seen.
func DetectDistro(o Observation, platformCPEs []string) string {
	text := strings.ToLower(o.Version + " " + o.ExtraInfo)
	for _, m := range distroMarkers {
		if strings.Contains(text, m.marker) {
			if pkg := packageSuffix(o.Version); pkg != "" {
				return fmt.Sprintf("%s package %s", m.name, pkg)
			}
			return m.name
		}
	}
	for _, raw := range platformCPEs {
		c, err := cpe.Parse(raw)
		if err != nil {
			continue
		}
		if name, ok := distroCPEs[c.Vendor+":"+c.Product]; ok {
			return name
		}
	}
	return ""
}

// packageSuffix returns the distribution part of a version string such as
// "9.6p1 Ubuntu 3ubuntu13.18" -> "3ubuntu13.18".
func packageSuffix(v string) string {
	f := strings.Fields(v)
	if len(f) >= 3 {
		return f[len(f)-1]
	}
	return ""
}
