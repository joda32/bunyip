package nmap

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func parseFile(t *testing.T, path string) *Scan {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := Parse(f, DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseRealLocalScan(t *testing.T) {
	s := parseFile(t, "../../testdata/nmap/local-ubuntu-ssh.xml")
	if s.Version != "7.94SVN" || !strings.Contains(s.Args, "-sV") || len(s.Hosts) != 1 {
		t.Fatalf("unexpected scan: %+v", s)
	}
	h := s.Hosts[0]
	if h.Status != "up" || h.Address() != "127.0.0.1" || h.Hostnames[0] != "localhost" || len(h.Ports) != 3 {
		t.Fatalf("unexpected host: %+v", h)
	}
	ssh := h.Ports[0]
	if !ssh.Open() || ssh.PortID != 22 || ssh.Protocol != "tcp" || !ssh.Service.Probed() {
		t.Errorf("unexpected port: %+v", ssh)
	}
	svc := ssh.Service
	if svc.Product != "OpenSSH" || svc.Version != "9.6p1 Ubuntu 3ubuntu13.18" || svc.ExtraInfo != "Ubuntu Linux; protocol 2.0" ||
		strings.Join(svc.CPEs, ",") != "cpe:/a:openbsd:openssh:9.6p1,cpe:/o:linux:linux_kernel" {
		t.Errorf("unexpected service: %+v", svc)
	}
	if h.Ports[2].Open() || h.Ports[2].Service != nil {
		t.Errorf("closed port without service expected: %+v", h.Ports[2])
	}
}

func TestParseSample(t *testing.T) {
	s := parseFile(t, "../../testdata/nmap/sample.xml")
	if len(s.Hosts) != 3 {
		t.Fatalf("hosts = %d", len(s.Hosts))
	}
	web := s.Hosts[0]
	if web.Address() != "192.0.2.20" || len(web.Addresses) != 2 || web.Addresses[1] != "00:11:22:33:44:55" {
		t.Errorf("addresses: %v", web.Addresses)
	}
	if len(web.Ports) != 6 || strings.Join(web.OSCPEs, ",") != "cpe:/o:linux:linux_kernel:5" {
		t.Errorf("ports/os: %d %v", len(web.Ports), web.OSCPEs)
	}
	smtp := web.Ports[1].Service
	if smtp.Probed() || smtp.Product != "" {
		t.Errorf("table-guessed service should not count as probed: %+v", smtp)
	}
	if web.Ports[3].Service.Tunnel != "ssl" {
		t.Errorf("tunnel not parsed")
	}
	if s.Hosts[2].Status != "down" || len(s.Hosts[2].Ports) != 0 {
		t.Errorf("down host: %+v", s.Hosts[2])
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, doc string
		is        error
	}{
		{"not xml", "hello", nil},
		{"other root", `<?xml version="1.0"?><html><body/></html>`, ErrNotNmap},
		{"empty", ``, ErrNotNmap},
		{"truncated", `<nmaprun><host><ports><port portid="22">`, nil},
		{"bad portid", `<nmaprun><host><ports><port protocol="tcp" portid="x"/></ports></host></nmaprun>`, nil},
		{"undefined entity", `<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]><nmaprun args="&a;"></nmaprun>`, nil},
	}
	for _, tt := range tests {
		_, err := Parse(strings.NewReader(tt.doc), DefaultMaxBytes)
		if err == nil {
			t.Errorf("%s: accepted", tt.name)
			continue
		}
		if tt.is != nil && !errors.Is(err, tt.is) {
			t.Errorf("%s: error %v, want %v", tt.name, err, tt.is)
		}
	}
}

func TestParseSizeLimit(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nmap/sample.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("exact-size document rejected: %v", err)
	}
	_, err = Parse(bytes.NewReader(data), int64(len(data)/2))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized document: %v", err)
	}
}
