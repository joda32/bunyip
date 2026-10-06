package nmap

import (
	"context"
	"slices"
	"strings"

	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/version"
)

// Assessment says what happened to an open port.
type Assessment string

const (
	Assessed     Assessment = "ASSESSED"     // identity resolved and looked up
	Unidentified Assessment = "UNIDENTIFIED" // service probed, but no usable application CPE
	NotProbed    Assessment = "NOT_PROBED"   // service only guessed from the port number
)

// Report is the vulnerability assessment of one Nmap scan.
type Report struct {
	Scan     ScanInfo     `json:"scan"`
	Summary  Summary      `json:"summary"`
	Hosts    []HostReport `json:"hosts"`
	Warnings []string     `json:"warnings"`
}

type ScanInfo struct {
	Scanner string `json:"scanner"`
	Version string `json:"version"`
	Args    string `json:"args"`
	Start   string `json:"start"`
}

type Summary struct {
	HostsUp        int `json:"hosts_up"`
	HostsDown      int `json:"hosts_down"`
	OpenPorts      int `json:"open_ports"`
	Assessed       int `json:"assessed"`
	Unidentified   int `json:"unidentified"`
	NotProbed      int `json:"not_probed"`
	VersionMatches int `json:"version_matches"` // (service, CVE) pairs with version MATCH
	KnownExploited int `json:"known_exploited"` // ... of which in CISA KEV
	PublicExploit  int `json:"public_exploit"`  // ... of which with exploit evidence
	Undetermined   int `json:"undetermined"`    // (service, CVE) pairs with version UNKNOWN
	DistroPackages int `json:"distro_packages"` // assessed services with distro packaging
}

type HostReport struct {
	Address   string          `json:"address"`
	Addresses []string        `json:"addresses"`
	Hostnames []string        `json:"hostnames"`
	Status    string          `json:"status"`
	OSCPEs    []string        `json:"os_cpes"`
	Services  []ServiceReport `json:"services"`
}

type ServiceReport struct {
	Port         int             `json:"port"`
	Protocol     string          `json:"protocol"`
	State        string          `json:"state"`
	Service      string          `json:"service"`
	Product      string          `json:"product,omitempty"`
	Version      string          `json:"version,omitempty"`
	ExtraInfo    string          `json:"extra_info,omitempty"`
	Tunnel       string          `json:"tunnel,omitempty"`
	Method       string          `json:"method,omitempty"`
	NmapCPEs     []string        `json:"nmap_cpes"`
	Assessment   Assessment      `json:"assessment"`
	Distro       string          `json:"distro,omitempty"`
	PlatformCPEs []string        `json:"platform_cpes,omitempty"`
	Notes        []string        `json:"notes,omitempty"`
	Result       *matcher.Result `json:"result,omitempty"`
}

// Analyse assesses every open, probed service in the scan. Services with the
// same candidate identities are looked up once.
func Analyse(ctx context.Context, scan *Scan, engine *matcher.Engine) (*Report, error) {
	rep := &Report{
		Scan:  ScanInfo{scan.Scanner, scan.Version, scan.Args, scan.StartTime},
		Hosts: []HostReport{},
	}
	cache := map[string]*matcher.Result{}
	for _, h := range scan.Hosts {
		if h.Status != "up" {
			rep.Summary.HostsDown++
			continue
		}
		rep.Summary.HostsUp++
		hr := HostReport{Address: h.Address(), Addresses: h.Addresses, Hostnames: h.Hostnames,
			Status: h.Status, OSCPEs: h.OSCPEs, Services: []ServiceReport{}}
		for _, p := range h.Ports {
			if !p.Open() {
				continue
			}
			rep.Summary.OpenPorts++
			sr, err := assessPort(ctx, p, engine, cache)
			if err != nil {
				return nil, err
			}
			rep.Summary.add(sr)
			hr.Services = append(hr.Services, sr)
		}
		rep.Hosts = append(rep.Hosts, hr)
	}
	for _, r := range cache {
		for _, w := range r.Warnings {
			if !slices.Contains(rep.Warnings, w) && matcher.IsGeneralWarning(w) {
				rep.Warnings = append(rep.Warnings, w)
			}
		}
	}
	slices.Sort(rep.Warnings)
	return rep, nil
}

func assessPort(ctx context.Context, p Port, engine *matcher.Engine, cache map[string]*matcher.Result) (ServiceReport, error) {
	sr := ServiceReport{Port: p.PortID, Protocol: p.Protocol, State: p.State, NmapCPEs: []string{}}
	s := p.Service
	if s != nil {
		sr.Service, sr.Product, sr.Version, sr.ExtraInfo = s.Name, s.Product, s.Version, s.ExtraInfo
		sr.Tunnel, sr.Method = s.Tunnel, s.Method
		sr.NmapCPEs = append(sr.NmapCPEs, s.CPEs...)
	}
	if !s.Probed() {
		sr.Assessment = NotProbed
		sr.Notes = []string{"Service was only guessed from the port number (no -sV fingerprint), so it was not assessed."}
		return sr, nil
	}
	res := engine.Resolver.ResolveObservation(identity.Observation{
		Product: s.Product, Version: s.Version, ExtraInfo: s.ExtraInfo, OSType: s.OSType, CPEs: s.CPEs,
	}, "Nmap")
	sr.Distro, sr.PlatformCPEs, sr.Notes = res.Distro, res.PlatformCPEs, res.Notes
	if len(res.Candidates) == 0 {
		sr.Assessment = Unidentified
		return sr, nil
	}
	sr.Assessment = Assessed

	k := cacheKey(res.Candidates)
	result, ok := cache[k]
	if !ok {
		var err error
		if result, err = engine.Query(ctx, res.Candidates); err != nil {
			return sr, err
		}
		cache[k] = result
	}
	sr.Result = result
	return sr, nil
}

func cacheKey(cands []identity.Candidate) string {
	var b strings.Builder
	for _, c := range cands {
		b.WriteString(c.CPE.String())
		b.WriteString("|")
		b.WriteString(string(c.Confidence))
		b.WriteString(";")
	}
	return b.String()
}

func (s *Summary) add(sr ServiceReport) {
	switch sr.Assessment {
	case Assessed:
		s.Assessed++
		if sr.Distro != "" {
			s.DistroPackages++
		}
	case Unidentified:
		s.Unidentified++
	case NotProbed:
		s.NotProbed++
	}
	if sr.Result == nil {
		return
	}
	for _, v := range sr.Result.Vulnerabilities {
		if v.VersionStatus != version.Match {
			s.Undetermined++
			continue
		}
		s.VersionMatches++
		if v.KnownExploited {
			s.KnownExploited++
		}
		if v.PublicExploit {
			s.PublicExploit++
		}
	}
}
