package nmap

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/version"
	"offline-vulndb/internal/windows"
)

// Assessment says what happened to an open port.
type Assessment string

const (
	Assessed     Assessment = "ASSESSED"     // identity resolved and looked up
	Unidentified Assessment = "UNIDENTIFIED" // service probed, but no usable application CPE
	NotProbed    Assessment = "NOT_PROBED"   // service only guessed from the port number
	// OSComponent: an operating-system built-in (e.g. Windows RPC) whose
	// vulnerabilities NVD records against the OS; covered by the host's
	// Windows build assessment, not per port.
	OSComponent Assessment = "OS_COMPONENT"
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
	OSComponents   int `json:"os_components"`
	VersionMatches int `json:"version_matches"` // (service, CVE) pairs with version MATCH
	KnownExploited int `json:"known_exploited"` // ... of which in CISA KEV
	PublicExploit  int `json:"public_exploit"`  // ... of which with exploit evidence
	Undetermined   int `json:"undetermined"`    // (service, CVE) pairs with version UNKNOWN
	DistroPackages int `json:"distro_packages"` // assessed services with distro packaging
	DistroFixed    int `json:"distro_fixed"`    // (service, CVE) pairs fixed in the distribution package
	DistroOnly     int `json:"distro_only"`     // (service, CVE) pairs found only via distribution advisories
	EndOfLife      int `json:"end_of_life"`     // assessed services on an end-of-life distribution release
	WindowsHosts   int `json:"windows_hosts"`   // hosts assessed at Windows build level
	WindowsEOL     int `json:"windows_eol"`     // ... whose release is past its end of support
}

type HostReport struct {
	Address   string   `json:"address"`
	Addresses []string `json:"addresses"`
	Hostnames []string `json:"hostnames"`
	Status    string   `json:"status"`
	OSCPEs    []string `json:"os_cpes"`
	// Distro is the distribution all distribution-marked services agree on.
	Distro string `json:"distro,omitempty"`
	// DistroRelease is a distribution release established for the host from a
	// service that exposes its exact package version (e.g. OpenSSH).
	DistroRelease string          `json:"distro_release,omitempty"`
	Services      []ServiceReport `json:"services"`
	// Windows is the build-level assessment of a Windows host (see package
	// windows); two entries when the build is shared by a server and a
	// client release and the scan does not show which.
	Windows []windows.Assessment `json:"windows,omitempty"`
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
	var winAssessor *windows.Assessor
	for _, h := range scan.Hosts {
		if h.Status != "up" {
			rep.Summary.HostsDown++
			continue
		}
		rep.Summary.HostsUp++
		hr := HostReport{Address: h.Address(), Addresses: h.Addresses, Hostnames: h.Hostnames,
			Status: h.Status, OSCPEs: h.OSCPEs, Services: []ServiceReport{}}
		var open []Port
		for _, p := range h.Ports {
			if p.Open() {
				open = append(open, p)
			}
		}
		hostDistro := hostDistribution(open, engine)
		hint, err := hostRelease(ctx, open, engine)
		if err != nil {
			return nil, err
		}
		hr.DistroRelease = hint
		if hostDistro.Detected() {
			hr.Distro = hostDistro.Name
		}
		for _, p := range open {
			rep.Summary.OpenPorts++
			sr, err := assessPort(ctx, p, engine, cache, hint, hostDistro)
			if err != nil {
				return nil, err
			}
			rep.Summary.add(sr)
			hr.Services = append(hr.Services, sr)
		}
		if ev := windows.Detect(windowsSignals(h, open)); ev != nil {
			if winAssessor == nil {
				if winAssessor, err = windows.NewAssessor(ctx, engine); err != nil {
					return nil, err
				}
			}
			if hr.Windows, err = winAssessor.Assess(ctx, ev); err != nil {
				return nil, err
			}
			rep.Summary.addWindows(hr.Windows)
			if !slices.Contains(rep.Warnings, windows.PatchNote) {
				rep.Warnings = append(rep.Warnings, windows.PatchNote)
			}
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

// windowsSignals collects the Windows build evidence that NSE scripts and
// service fingerprints expose.
func windowsSignals(h Host, open []Port) windows.Signals {
	var sig windows.Signals
	for _, p := range open {
		where := fmt.Sprintf("%d/%s", p.PortID, p.Protocol)
		for _, sc := range p.Scripts {
			if pv := sc.Elems["Product_Version"]; strings.HasSuffix(sc.ID, "-ntlm-info") && pv != "" {
				sig.ProductVersions = append(sig.ProductVersions, windows.Signal{Value: pv, Source: sc.ID + " on " + where})
			}
		}
		s := p.Service
		if !s.Probed() {
			continue
		}
		// e.g. "Windows Server 2016 Standard Evaluation 14393 microsoft-ds"
		if s.Name == "microsoft-ds" && strings.HasPrefix(s.Product, "Windows ") {
			sig.OSStrings = append(sig.OSStrings, windows.Signal{
				Value: strings.TrimSuffix(s.Product, " microsoft-ds"), Source: "SMB fingerprint on " + where})
		}
		if sig.DomainController == "" && (s.Product == "Microsoft Windows Active Directory LDAP" || s.Product == "Microsoft Windows Kerberos") {
			sig.DomainController = s.Product + " on " + where
		}
	}
	for _, sc := range h.Scripts {
		if os := sc.Elems["os"]; sc.ID == "smb-os-discovery" && os != "" {
			sig.OSStrings = append(sig.OSStrings, windows.Signal{Value: os, Source: "smb-os-discovery"})
		}
	}
	return sig
}

// observe resolves a probed service's identity.
func observe(p Port, engine *matcher.Engine) identity.Resolution {
	s := p.Service
	return engine.Resolver.ResolveObservation(identity.Observation{
		Product: s.Product, Version: s.Version, ExtraInfo: s.ExtraInfo, OSType: s.OSType, CPEs: s.CPEs,
	}, "Nmap")
}

// hostDistribution returns the distribution that every service showing one
// agrees on (e.g. Apache "(Red Hat Enterprise Linux)"), so services that name
// none (RHEL's "OpenSSH_8.7") can be evaluated against it. Conflicting
// evidence yields none.
func hostDistribution(ports []Port, engine *matcher.Engine) identity.DistroInfo {
	var found identity.DistroInfo
	for _, p := range ports {
		if !p.Service.Probed() {
			continue
		}
		d := observe(p, engine).Distro
		if !d.Detected() {
			continue
		}
		if found.Detected() && found.Key != d.Key {
			return identity.DistroInfo{}
		}
		found = identity.DistroInfo{Name: d.Name, Key: d.Key}
	}
	return found
}

// hostRelease returns the distribution release that services exposing an
// exact package version agree on, so services that only show a distribution
// name (Apache "(Ubuntu)") can be evaluated against the right release.
func hostRelease(ctx context.Context, ports []Port, engine *matcher.Engine) (string, error) {
	release := ""
	for _, p := range ports {
		if !p.Service.Probed() {
			continue
		}
		res := observe(p, engine)
		if len(res.Candidates) == 0 || res.Distro.Revision == "" {
			continue
		}
		dc, err := engine.ResolveDistro(ctx, res.Candidates, &matcher.DistroInput{Info: res.Distro})
		if err != nil {
			return "", err
		}
		if dc == nil {
			continue
		}
		if r := dc.DefinitiveRelease(); r != "" {
			if release != "" && release != r {
				return "", nil // conflicting evidence: no hint
			}
			release = r
		}
	}
	return release, nil
}

func assessPort(ctx context.Context, p Port, engine *matcher.Engine, cache map[string]*matcher.Result, hint string,
	hostDistro identity.DistroInfo) (ServiceReport, error) {
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
	res := observe(p, engine)
	sr.Distro, sr.PlatformCPEs, sr.Notes = res.Distro.Label(), res.PlatformCPEs, res.Notes
	if len(res.Candidates) == 0 {
		sr.Assessment = Unidentified
		if res.OSComponent != "" {
			sr.Assessment = OSComponent
		}
		return sr, nil
	}
	sr.Assessment = Assessed

	var din *matcher.DistroInput
	switch {
	case res.Distro.Detected():
		din = &matcher.DistroInput{Info: res.Distro, ReleaseHint: hint}
	case hostDistro.Detected():
		// The service names no distribution, but the host does. Assume the
		// distribution's package only if its data knows this upstream
		// version (NoHintFallback), since the software may be self-built.
		inf := hostDistro
		inf.Inferred = true
		din = &matcher.DistroInput{Info: inf, ReleaseHint: hint}
		sr.Distro = inf.Label()
	}
	k := cacheKey(res.Candidates, din)
	result, ok := cache[k]
	if !ok {
		var err error
		if result, err = engine.Query(ctx, res.Candidates, din); err != nil {
			return sr, err
		}
		cache[k] = result
	}
	sr.Result = result
	if d := result.Distro; d != nil && (d.Status == distro.Resolved || d.Status == distro.Ambiguous) {
		// Backports were evaluated; the generic "may be false positives" note no longer applies.
		sr.Notes = slices.DeleteFunc(sr.Notes, func(n string) bool { return strings.HasPrefix(n, identity.BackportNotePrefix) })
	}
	return sr, nil
}

func cacheKey(cands []identity.Candidate, din *matcher.DistroInput) string {
	var b strings.Builder
	if din != nil {
		b.WriteString(din.Info.Key + "|" + din.Info.Revision + "|" + din.ReleaseHint + ";")
	}
	for _, c := range cands {
		b.WriteString(c.CPE.String())
		b.WriteString("|")
		b.WriteString(string(c.Confidence))
		b.WriteString(";")
	}
	return b.String()
}

func (s *Summary) addWindows(as []windows.Assessment) {
	eol, assessed := true, false
	for _, a := range as {
		if a.Status == windows.Assessed {
			assessed = true
			eol = eol && a.EndOfLife
		}
	}
	if assessed {
		s.WindowsHosts++
		if eol {
			s.WindowsEOL++
		}
	}
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
	case OSComponent:
		s.OSComponents++
	}
	if sr.Result == nil {
		return
	}
	if d := sr.Result.Distro; d != nil && d.EndOfLife != "" {
		s.EndOfLife++
	}
	for _, v := range sr.Result.Vulnerabilities {
		if v.Distro != nil && v.Distro.Status == distro.Fixed {
			s.DistroFixed++
			continue
		}
		if v.DistroOnly {
			s.DistroOnly++
		}
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
