// Package nmap reads Nmap XML output (-oX) into service observations.
//
// It is an input adapter only: it knows nothing about vulnerabilities. The
// parser streams the document and decodes one <host> element at a time.
// Input is size-capped, and Go's encoding/xml does not expand DTD-defined
// entities, so entity-expansion ("billion laughs") input cannot amplify.
package nmap

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DefaultMaxBytes caps how much XML is read (1 GiB is far beyond any
// ordinary internal scan).
const DefaultMaxBytes int64 = 1 << 30

// ErrNotNmap is returned for XML that is not Nmap output.
var ErrNotNmap = errors.New("not an Nmap XML document")

// Scan is a parsed Nmap run.
type Scan struct {
	Scanner   string
	Version   string
	Args      string
	StartTime string
	Hosts     []Host
}

// Host is one scanned host.
type Host struct {
	Status    string   `json:"status"`
	Addresses []string `json:"addresses"`
	Hostnames []string `json:"hostnames"`
	OSCPEs    []string `json:"os_cpes"` // from -O OS detection
	Ports     []Port   `json:"-"`
	Scripts   []Script `json:"-"` // host script results (e.g. smb-os-discovery)
}

// Script is an NSE script result: its text output and top-level elements
// (e.g. rdp-ntlm-info's Product_Version).
type Script struct {
	ID     string
	Output string
	Elems  map[string]string
}

// Address returns the preferred address (IPv4, then IPv6, then any).
func (h Host) Address() string {
	if len(h.Addresses) > 0 {
		return h.Addresses[0]
	}
	return ""
}

// Port is one scanned port.
type Port struct {
	Protocol string
	PortID   int
	State    string
	Service  *Service
	Scripts  []Script
}

// Open reports whether the port state is open (including "open|filtered").
func (p Port) Open() bool { return strings.HasPrefix(p.State, "open") }

// Service is Nmap's service detection result for a port.
type Service struct {
	Name      string
	Product   string
	Version   string
	ExtraInfo string
	OSType    string
	Tunnel    string
	Method    string // "probed" (-sV fingerprint) or "table" (port-number guess)
	Conf      int
	CPEs      []string
}

// Probed reports whether the service was identified by probing rather than
// guessed from the port number.
func (s *Service) Probed() bool { return s != nil && s.Method == "probed" }

// XML shapes (only the parts used).
type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
	Elems  []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	} `xml:"elem"`
}

func (x xmlScript) script() Script {
	s := Script{ID: x.ID, Output: x.Output, Elems: map[string]string{}}
	for _, e := range x.Elems {
		if e.Key != "" {
			s.Elems[e.Key] = strings.TrimSpace(e.Value)
		}
	}
	return s
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service *struct {
			Name      string   `xml:"name,attr"`
			Product   string   `xml:"product,attr"`
			Version   string   `xml:"version,attr"`
			ExtraInfo string   `xml:"extrainfo,attr"`
			OSType    string   `xml:"ostype,attr"`
			Tunnel    string   `xml:"tunnel,attr"`
			Method    string   `xml:"method,attr"`
			Conf      int      `xml:"conf,attr"`
			CPEs      []string `xml:"cpe"`
		} `xml:"service"`
		Scripts []xmlScript `xml:"script"`
	} `xml:"ports>port"`
	OSCPEs      []string    `xml:"os>osmatch>osclass>cpe"`
	HostScripts []xmlScript `xml:"hostscript>script"`
}

// Parse reads an Nmap XML document of at most maxBytes bytes.
func Parse(r io.Reader, maxBytes int64) (*Scan, error) {
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	dec := xml.NewDecoder(lr)
	scan := &Scan{}
	sawRoot := false
	// Hitting the cap truncates the input mid-document, so any error after
	// that point is reported as the size limit rather than a syntax error.
	fail := func(what string, err error) error {
		if lr.N <= 0 {
			return fmt.Errorf("nmap XML exceeds %d bytes", maxBytes)
		}
		return fmt.Errorf("parsing nmap %s: %w", what, err)
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fail("XML", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case !sawRoot:
			if se.Name.Local != "nmaprun" {
				return nil, fmt.Errorf("%w: root element is <%s>", ErrNotNmap, se.Name.Local)
			}
			sawRoot = true
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "scanner":
					scan.Scanner = a.Value
				case "version":
					scan.Version = a.Value
				case "args":
					scan.Args = a.Value
				case "startstr":
					scan.StartTime = a.Value
				}
			}
		case se.Name.Local == "host":
			var xh xmlHost
			if err := dec.DecodeElement(&xh, &se); err != nil {
				return nil, fail("<host>", err)
			}
			scan.Hosts = append(scan.Hosts, convertHost(xh))
		}
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("nmap XML exceeds %d bytes", maxBytes)
	}
	if !sawRoot {
		return nil, fmt.Errorf("%w: no <nmaprun> element", ErrNotNmap)
	}
	return scan, nil
}

func convertHost(xh xmlHost) Host {
	h := Host{Status: xh.Status.State}
	// IPv4 first, then IPv6, then others (e.g. MAC).
	for _, want := range []string{"ipv4", "ipv6", ""} {
		for _, a := range xh.Addresses {
			if (want == "" && a.AddrType != "ipv4" && a.AddrType != "ipv6") || a.AddrType == want {
				h.Addresses = append(h.Addresses, a.Addr)
			}
		}
	}
	for _, hn := range xh.Hostnames {
		if hn.Name != "" {
			h.Hostnames = append(h.Hostnames, hn.Name)
		}
	}
	seen := map[string]bool{}
	for _, c := range xh.OSCPEs {
		if c = strings.TrimSpace(c); c != "" && !seen[c] {
			seen[c] = true
			h.OSCPEs = append(h.OSCPEs, c)
		}
	}
	for _, xp := range xh.Ports {
		p := Port{Protocol: xp.Protocol, PortID: xp.PortID, State: xp.State.State}
		if s := xp.Service; s != nil {
			svc := &Service{Name: s.Name, Product: s.Product, Version: s.Version, ExtraInfo: s.ExtraInfo,
				OSType: s.OSType, Tunnel: s.Tunnel, Method: s.Method, Conf: s.Conf}
			for _, c := range s.CPEs {
				if c = strings.TrimSpace(c); c != "" {
					svc.CPEs = append(svc.CPEs, c)
				}
			}
			p.Service = svc
		}
		for _, xs := range xp.Scripts {
			p.Scripts = append(p.Scripts, xs.script())
		}
		h.Ports = append(h.Ports, p)
	}
	for _, xs := range xh.HostScripts {
		h.Scripts = append(h.Scripts, xs.script())
	}
	return h
}
