package ingest

import (
	"strings"
	"testing"

	"bunyip/internal/database"
)

func testMap() TechMap {
	return BuildTechMap([]database.HTTPTechEntry{
		{Name: "WordPress", Vendor: "wordpress", Product: "wordpress"},
		{Name: "PHP", Vendor: "php", Product: "php"},
		{Name: "Apache Tomcat", Vendor: "apache", Product: "tomcat"},
	})
}

func TestParseHTTPX(t *testing.T) {
	in := `{"url":"https://a.test","input":"a.test","host":"192.0.2.1","port":"443","scheme":"https","tech":["WordPress","PHP:8.2.7"]}
not json, ignored
{"url":"http://b.test","input":"b.test","host":"192.0.2.2","port":"8080","scheme":"http","tech":["Apache Tomcat"]}`
	ts, err := Parse(strings.NewReader(in), HTTPX)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0].Address != "192.0.2.1" || !ts[0].TLS || ts[0].Port != 443 {
		t.Fatalf("targets: %+v", ts)
	}
	if len(ts[0].Techs) != 2 || ts[0].Techs[1].Name != "PHP" || ts[0].Techs[1].Version != "8.2.7" {
		t.Errorf("techs: %+v", ts[0].Techs)
	}
}

func TestParseWebanalyze(t *testing.T) {
	in := `[{"hostname":"https://a.test:443","matches":[{"app":"WordPress","version":""},{"app":"PHP","version":"8.2.7"}]}]`
	ts, err := Parse(strings.NewReader(in), Webanalyze)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Address != "a.test" || ts[0].Port != 443 || !ts[0].TLS {
		t.Fatalf("target: %+v", ts[0])
	}
	if len(ts[0].Techs) != 2 || ts[0].Techs[1].Version != "8.2.7" {
		t.Errorf("techs: %+v", ts[0].Techs)
	}
}

func TestScanSynthesisAndMapping(t *testing.T) {
	ts := []Target{{Address: "192.0.2.1", Hostname: "a.test", Port: 443, TLS: true, Techs: []Tech{
		{Name: "WordPress"}, {Name: "PHP", Version: "8.2.7"}, {Name: "Nope"}}}}
	scan, unmapped := Scan(ts, testMap())
	if len(scan.Hosts) != 1 || len(scan.Hosts[0].Ports) != 2 { // Nope is unmapped
		t.Fatalf("hosts/ports: %+v", scan.Hosts)
	}
	if unmapped[0] != "Nope" {
		t.Errorf("unmapped: %v", unmapped)
	}
	p0 := scan.Hosts[0].Ports[0]
	if p0.PortID != 443 || p0.Service.Tunnel != "ssl" || p0.Service.CPEs[0] != "cpe:/a:wordpress:wordpress" {
		t.Errorf("wordpress port: %+v / %+v", p0, p0.Service)
	}
	// versioned tech carries the version into the CPE
	if scan.Hosts[0].Ports[1].Service.CPEs[0] != "cpe:/a:php:php:8.2.7" {
		t.Errorf("php cpe: %s", scan.Hosts[0].Ports[1].Service.CPEs[0])
	}
}

func TestScanDefaultPort(t *testing.T) {
	scan, _ := Scan([]Target{{Address: "h", Techs: []Tech{{Name: "WordPress"}}}}, testMap())
	if scan.Hosts[0].Ports[0].PortID != 80 {
		t.Errorf("default port = %d, want 80", scan.Hosts[0].Ports[0].PortID)
	}
}
