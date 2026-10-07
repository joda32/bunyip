package nmap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/version"
)

// NSE support: nse/vulndb.nse writes one request per port (with the host's
// other open ports, for host-level distribution evidence) to a file and runs
// `vulndb nse --request FILE`. Requests carry banner-derived data, so they
// travel in a file and never on a command line.

// NSERequestVersion is the request/response format version.
const NSERequestVersion = 1

const maxNSERequestBytes = 4 << 20

// NSERequest is what the NSE script sends.
type NSERequest struct {
	Version int        `json:"version"`
	Host    NSEHost    `json:"host"`
	Ports   []NSEPort  `json:"ports"`
	Target  NSETarget  `json:"target"`
	Options NSEOptions `json:"options"`
}

type NSEHost struct {
	Address   string   `json:"address"`
	Hostnames []string `json:"hostnames"`
	OSCPEs    []string `json:"os_cpes"`
}

type NSEPort struct {
	Protocol  string   `json:"protocol"`
	Port      int      `json:"port"`
	State     string   `json:"state"`
	Name      string   `json:"name"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	ExtraInfo string   `json:"extrainfo"`
	OSType    string   `json:"ostype"`
	Tunnel    string   `json:"tunnel"`
	Method    string   `json:"method"`
	Conf      int      `json:"conf"`
	CPEs      []string `json:"cpes"`
}

type NSETarget struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type NSEOptions struct {
	Max             int     `json:"max"`     // CVEs to list (0: default 10)
	MinCVSS         float64 `json:"mincvss"` // hide CVEs scored below this
	ShowUnknown     bool    `json:"show_undetermined"`
	ShowDistroFixed bool    `json:"show_distro_fixed"`
}

// NSEVuln is one CVE as shown by the script (structured -oX output).
type NSEVuln struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity,omitempty"`
	CVSS          *float64 `json:"cvss,omitempty"`
	KEV           bool     `json:"kev"`
	Exploit       bool     `json:"exploit"`
	VersionStatus string   `json:"version_status"`
	Confidence    string   `json:"confidence"`
	Distro        string   `json:"distro,omitempty"` // e.g. "Ubuntu: VULNERABLE"
	Flags         []string `json:"flags,omitempty"`
}

// NSEResponse is what the script prints.
type NSEResponse struct {
	Version     int       `json:"version"`
	Assessment  string    `json:"assessment"`
	Identity    []string  `json:"identity,omitempty"`
	Distro      string    `json:"distro,omitempty"`
	Counts      NSECounts `json:"counts"`
	Vulns       []NSEVuln `json:"vulns"`
	DistroFixed []string  `json:"distro_fixed,omitempty"`
	Notes       []string  `json:"notes,omitempty"`
	Lines       []string  `json:"lines"` // human-readable rendering
}

type NSECounts struct {
	Matches      int `json:"matches"`
	KEV          int `json:"kev"`
	Exploit      int `json:"exploit"`
	Undetermined int `json:"undetermined"`
	DistroFixed  int `json:"distro_fixed"`
	Shown        int `json:"shown"`
}

// ParseNSERequest decodes and validates a request.
func ParseNSERequest(r io.Reader) (*NSERequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxNSERequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxNSERequestBytes {
		return nil, fmt.Errorf("nse request exceeds %d bytes", maxNSERequestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req NSERequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid nse request: %w", err)
	}
	if req.Version != NSERequestVersion {
		return nil, fmt.Errorf("unsupported nse request version %d (want %d)", req.Version, NSERequestVersion)
	}
	if req.Options.Max <= 0 {
		req.Options.Max = 10
	}
	return &req, nil
}

// scan turns a request into a single-host scan for Analyse.
func (req *NSERequest) scan() *Scan {
	h := Host{Status: "up", Hostnames: req.Host.Hostnames, OSCPEs: req.Host.OSCPEs}
	if req.Host.Address != "" {
		h.Addresses = []string{req.Host.Address}
	}
	for _, p := range req.Ports {
		state := p.State
		if state == "" {
			state = "open"
		}
		h.Ports = append(h.Ports, Port{Protocol: p.Protocol, PortID: p.Port, State: state, Service: &Service{
			Name: p.Name, Product: p.Product, Version: p.Version, ExtraInfo: p.ExtraInfo, OSType: p.OSType,
			Tunnel: p.Tunnel, Method: p.Method, Conf: p.Conf, CPEs: p.CPEs,
		}})
	}
	return &Scan{Scanner: "nmap-nse", Hosts: []Host{h}}
}

// AnswerNSE assesses the request's host and returns the target port's result.
func AnswerNSE(ctx context.Context, req *NSERequest, engine *matcher.Engine) (*NSEResponse, error) {
	rep, err := Analyse(ctx, req.scan(), engine)
	if err != nil {
		return nil, err
	}
	var sr *ServiceReport
	if len(rep.Hosts) == 1 {
		for i, s := range rep.Hosts[0].Services {
			if s.Port == req.Target.Port && s.Protocol == req.Target.Protocol {
				sr = &rep.Hosts[0].Services[i]
			}
		}
	}
	if sr == nil {
		return nil, fmt.Errorf("target port %d/%s is not among the request's open ports", req.Target.Port, req.Target.Protocol)
	}
	return buildNSEResponse(sr, req.Options), nil
}

func buildNSEResponse(sr *ServiceReport, opts NSEOptions) *NSEResponse {
	resp := &NSEResponse{Version: NSERequestVersion, Assessment: string(sr.Assessment), Distro: sr.Distro,
		Vulns: []NSEVuln{}, Notes: sr.Notes}
	res := sr.Result
	if res == nil {
		resp.Lines = append(resp.Lines, notAssessedLine(sr))
		for _, n := range sr.Notes {
			resp.Lines = append(resp.Lines, "  "+n)
		}
		return resp
	}
	for _, id := range res.Identities {
		resp.Identity = append(resp.Identity, fmt.Sprintf("%s [%s]", id.CPE, id.Confidence))
	}
	for _, v := range res.Vulnerabilities {
		switch {
		case v.Distro != nil && v.Distro.Status == distro.Fixed:
			resp.Counts.DistroFixed++
			resp.DistroFixed = append(resp.DistroFixed, v.CVE)
			if !opts.ShowDistroFixed {
				continue
			}
		case v.VersionStatus != version.Match:
			resp.Counts.Undetermined++
			if !opts.ShowUnknown {
				continue
			}
		default:
			resp.Counts.Matches++
			if v.KnownExploited {
				resp.Counts.KEV++
			}
			if v.PublicExploit {
				resp.Counts.Exploit++
			}
		}
		if v.CVSS != nil && *v.CVSS < opts.MinCVSS || v.CVSS == nil && opts.MinCVSS > 0 {
			continue
		}
		if len(resp.Vulns) >= opts.Max {
			continue
		}
		nv := NSEVuln{ID: v.CVE, Severity: v.Severity, CVSS: v.CVSS, KEV: v.KnownExploited, Exploit: v.PublicExploit,
			VersionStatus: string(v.VersionStatus), Confidence: string(v.MatchConfidence)}
		if v.Distro != nil && v.Distro.Status != distro.NoData {
			nv.Distro = v.Distro.Distro + ": " + string(v.Distro.Status)
		}
		if v.DistroOnly {
			nv.Flags = append(nv.Flags, "distro-advisory-only")
		}
		if v.Applicability == matcher.Conditional {
			nv.Flags = append(nv.Flags, "conditional")
		}
		if v.KnownRansomware {
			nv.Flags = append(nv.Flags, "ransomware")
		}
		if len(res.Identities) > 0 && v.MatchedCPE != "" && v.MatchedCPE != res.Identities[0].CPE {
			nv.Flags = append(nv.Flags, "via-alias")
		}
		resp.Vulns = append(resp.Vulns, nv)
	}
	resp.Counts.Shown = len(resp.Vulns)
	resp.Lines = renderNSE(resp, res)
	return resp
}

func notAssessedLine(sr *ServiceReport) string {
	if sr.Assessment == NotProbed {
		return "not assessed: service guessed from the port number (run with -sV)"
	}
	return "not assessed: no application CPE for this service"
}

// renderNSE produces the concise script output (design doc section 17).
func renderNSE(resp *NSEResponse, res *matcher.Result) []string {
	c := resp.Counts
	head := fmt.Sprintf("%d candidate CVEs (%d in CISA KEV, %d with public exploit evidence)", c.Matches, c.KEV, c.Exploit)
	switch {
	case c.Undetermined > 0 && res.IdentityConfidence == matcher.Low:
		head = fmt.Sprintf("version not detected: %d CVEs recorded for %s %s could not be evaluated",
			c.Undetermined, res.Vendor, res.Product)
	case c.Undetermined > 0:
		head += fmt.Sprintf(", %d undetermined", c.Undetermined)
	}
	lines := []string{head}
	if d := res.Distro; d != nil && (d.Status == distro.Resolved || d.Status == distro.Ambiguous) {
		s := d.Target.DistroName + " " + strings.Join(d.Releases, "|")
		if d.Installed != "" {
			s += " installed " + d.Installed
		}
		if c.DistroFixed > 0 {
			s += fmt.Sprintf("; %d more fixed in the package", c.DistroFixed)
		}
		lines = append(lines, "Distribution: "+s)
		if d.EndOfLife != "" {
			lines = append(lines, "END OF LIFE: "+d.EOLNote())
		}
	}
	for _, v := range resp.Vulns {
		cvss := "CVSS n/a"
		if v.CVSS != nil {
			cvss = fmt.Sprintf("CVSS %.1f", *v.CVSS)
		}
		var tags []string
		if v.KEV {
			tags = append(tags, "KEV")
		}
		if v.Exploit {
			tags = append(tags, "exploit")
		}
		if v.VersionStatus != "MATCH" {
			tags = append(tags, "version "+v.VersionStatus)
		}
		if v.Distro != "" {
			tags = append(tags, v.Distro)
		}
		tags = append(tags, v.Flags...)
		line := fmt.Sprintf("%-16s %-9s %s", v.ID, orDashStr(v.Severity), cvss)
		if len(tags) > 0 {
			line += "  " + strings.Join(tags, ", ")
		}
		lines = append(lines, line)
	}
	if hidden := c.Matches - countMatches(resp.Vulns); hidden > 0 {
		lines = append(lines, fmt.Sprintf("... %d more (vulndb.max / vulndb.mincvss limit the list; full detail: vulndb nmap on -oX output)", hidden))
	}
	for _, n := range resp.Notes {
		lines = append(lines, "Note: "+n)
	}
	return lines
}

func countMatches(vs []NSEVuln) int {
	n := 0
	for _, v := range vs {
		if v.VersionStatus == "MATCH" && !strings.HasSuffix(v.Distro, ": FIXED") {
			n++
		}
	}
	return n
}

func orDashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
