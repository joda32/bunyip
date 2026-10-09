// Package ingest adapts the output of web technology fingerprinters (httpx
// -td, webanalyze) into the engine's scan model. Web applications sit behind
// a generic web server, so these tools name the application where Nmap names
// only the server. Each detected technology is mapped to an NVD CPE through
// the curated http_tech table and assessed like any other identity.
//
// The name->CPE map is derived from the webappanalyzer corpus and is a lead,
// not an authoritative identity: callers surface ingested results at reduced
// trust and verify the product.
package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"offline-vulndb/internal/database"
	"offline-vulndb/internal/nmap"
)

// IngestNote is attached to every ingested report: the identities are
// fingerprint-derived leads from a corpus with occasional mis-mappings.
const IngestNote = "Identities were supplied by an HTTP fingerprint ingest (webappanalyzer-derived name->CPE map), " +
	"not observed CPEs. Treat them as leads: verify the product is correct, and note that most web fingerprints " +
	"carry no version, so version-dependent CVEs stay UNDETERMINED."

// TechMap resolves a fingerprinter's technology name (case-insensitive) to a
// CPE identity.
type TechMap map[string]database.HTTPTechEntry

// BuildTechMap indexes the http_tech rows by lower-case name.
func BuildTechMap(rows []database.HTTPTechEntry) TechMap {
	m := make(TechMap, len(rows))
	for _, r := range rows {
		m[strings.ToLower(r.Name)] = r
	}
	return m
}

// Tech is one detected technology.
type Tech struct {
	Name    string
	Version string
}

// Target is a fingerprinted host:port and the technologies found on it.
type Target struct {
	Address  string
	Hostname string
	Port     int
	TLS      bool
	Techs    []Tech
}

// Format identifies the fingerprinter whose output is being read.
type Format string

const (
	HTTPX      Format = "httpx"
	Webanalyze Format = "webanalyze"
)

// Parse reads targets from a fingerprinter's output.
func Parse(r io.Reader, f Format) ([]Target, error) {
	switch f {
	case HTTPX:
		return parseHTTPX(r)
	case Webanalyze:
		return parseWebanalyze(r)
	default:
		return nil, fmt.Errorf("unknown ingest format %q (want httpx or webanalyze)", f)
	}
}

// httpx -json -td: one JSON object per line.
type httpxLine struct {
	URL    string   `json:"url"`
	Input  string   `json:"input"`
	Host   string   `json:"host"`
	Port   string   `json:"port"`
	Scheme string   `json:"scheme"`
	Tech   []string `json:"tech"`
}

func parseHTTPX(r io.Reader) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var h httpxLine
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			return nil, fmt.Errorf("invalid httpx json line: %w", err)
		}
		t := Target{Address: firstNonEmpty(h.Host, h.Input), Hostname: h.Input, Port: atoiSafe(h.Port),
			TLS: h.Scheme == "https"}
		for _, name := range h.Tech {
			// httpx may append a version as "Name:1.2.3".
			n, v, _ := strings.Cut(name, ":")
			t.Techs = append(t.Techs, Tech{Name: strings.TrimSpace(n), Version: strings.TrimSpace(v)})
		}
		if len(t.Techs) > 0 {
			out = append(out, t)
		}
	}
	return out, sc.Err()
}

// webanalyze -output json: a JSON array (or JSONL) of host results.
type webanalyzeHost struct {
	Hostname string `json:"hostname"`
	Matches  []struct {
		App     string `json:"app"`
		AppName string `json:"app_name"`
		Version string `json:"version"`
	} `json:"matches"`
}

func parseWebanalyze(r io.Reader) ([]Target, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var hosts []webanalyzeHost
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &hosts); err != nil {
			return nil, fmt.Errorf("invalid webanalyze json: %w", err)
		}
	} else { // JSONL
		dec := json.NewDecoder(strings.NewReader(trimmed))
		for dec.More() {
			var h webanalyzeHost
			if err := dec.Decode(&h); err != nil {
				return nil, fmt.Errorf("invalid webanalyze json: %w", err)
			}
			hosts = append(hosts, h)
		}
	}
	var out []Target
	for _, h := range hosts {
		addr, port, tls := splitHost(h.Hostname)
		t := Target{Address: addr, Hostname: h.Hostname, Port: port, TLS: tls}
		for _, m := range h.Matches {
			t.Techs = append(t.Techs, Tech{Name: firstNonEmpty(m.App, m.AppName), Version: strings.TrimSpace(m.Version)})
		}
		if len(t.Techs) > 0 {
			out = append(out, t)
		}
	}
	return out, nil
}

// Scan synthesises a scan: one host per target address, one port entry per
// technology that maps to a CPE, so each product is assessed independently.
// Unmapped technologies are returned as a second list for reporting.
func Scan(targets []Target, tm TechMap) (*nmap.Scan, []string) {
	byAddr := map[string]int{}
	scan := &nmap.Scan{Scanner: "ingest"}
	var unmapped []string
	seenUnmapped := map[string]bool{}
	for _, t := range targets {
		addr := t.Address
		if addr == "" {
			addr = t.Hostname
		}
		idx, ok := byAddr[addr]
		if !ok {
			idx = len(scan.Hosts)
			byAddr[addr] = idx
			h := nmap.Host{Status: "up", Addresses: []string{addr}}
			if t.Hostname != "" && t.Hostname != addr {
				h.Hostnames = []string{t.Hostname}
			}
			scan.Hosts = append(scan.Hosts, h)
		}
		port := t.Port
		if port == 0 {
			if t.TLS {
				port = 443
			} else {
				port = 80
			}
		}
		tunnel := ""
		if t.TLS {
			tunnel = "ssl"
		}
		for _, tech := range t.Techs {
			e, ok := tm[strings.ToLower(tech.Name)]
			if !ok {
				if !seenUnmapped[tech.Name] {
					seenUnmapped[tech.Name] = true
					unmapped = append(unmapped, tech.Name)
				}
				continue
			}
			svc := &nmap.Service{Name: "http", Product: tech.Name, Version: tech.Version, Method: "probed",
				Tunnel: tunnel, CPEs: []string{techCPE(e, tech.Version)}}
			scan.Hosts[idx].Ports = append(scan.Hosts[idx].Ports,
				nmap.Port{Protocol: "tcp", PortID: port, State: "open", Service: svc})
		}
	}
	return scan, unmapped
}

// techCPE builds a CPE 2.2 string for a mapped technology, carrying the
// version when the fingerprinter reported one.
func techCPE(e database.HTTPTechEntry, version string) string {
	c := "cpe:/a:" + e.Vendor + ":" + e.Product
	if version != "" {
		c += ":" + version
	}
	return c
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// splitHost splits a webanalyze "hostname" (a URL or host:port) into address,
// port and TLS.
func splitHost(h string) (addr string, port int, tls bool) {
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		tls = strings.HasPrefix(h, "https://")
		h = h[strings.Index(h, "//")+2:]
		h = strings.TrimRight(strings.SplitN(h, "/", 2)[0], "/")
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		if p := atoiSafe(h[i+1:]); p > 0 {
			return h[:i], p, tls
		}
	}
	return h, 0, tls
}
