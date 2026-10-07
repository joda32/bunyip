package nmap

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"offline-vulndb/internal/database"
	"offline-vulndb/internal/matcher"
)

func fixtureEngine(t *testing.T) *matcher.Engine {
	t.Helper()
	return fixtureEngineFrom(t, "../../testdata/fixtures/synthetic.json")
}

func fixtureEngineFrom(t *testing.T, fixture string) *matcher.Engine {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v.sqlite")
	s, err := database.Create(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := database.LoadFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportFixture(ctx, f); err != nil {
		t.Fatal(err)
	}
	s.Close()
	ro, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	e, err := matcher.New(ctx, ro)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A request as nse/vulndb.nse builds it for an Ubuntu 22.04 host.
const ubuntuRequest = `{"version": 1,
 "host": {"address": "192.0.2.20", "hostnames": ["web01"], "os_cpes": []},
 "ports": [
  {"protocol": "tcp", "port": 22, "state": "open", "name": "ssh", "product": "OpenSSH",
   "version": "8.9p1 Ubuntu 3ubuntu0.10", "extrainfo": "Ubuntu Linux; protocol 2.0", "ostype": "Linux",
   "tunnel": "", "method": "probed", "conf": 10, "cpes": ["cpe:\/a:openbsd:openssh:8.9p1", "cpe:\/o:linux:linux_kernel"]},
  {"protocol": "tcp", "port": 80, "state": "open", "name": "http", "product": "Apache httpd", "version": "2.4.49",
   "extrainfo": "(Unix)", "ostype": "", "tunnel": "", "method": "probed", "conf": 10, "cpes": ["cpe:/a:apache:http_server:2.4.49"]}],
 "target": {"protocol": "tcp", "port": 22},
 "options": {"max": 10, "mincvss": 0, "show_undetermined": false, "show_distro_fixed": false}}`

func answer(t *testing.T, e *matcher.Engine, body string, edit func(*NSERequest)) *NSEResponse {
	t.Helper()
	req, err := ParseNSERequest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(req)
	}
	resp, err := AnswerNSE(context.Background(), req, e)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestNSEUbuntuSSH(t *testing.T) {
	resp := answer(t, fixtureEngine(t), ubuntuRequest, nil)
	if resp.Assessment != "ASSESSED" || resp.Counts.Matches != 2 || resp.Counts.DistroFixed != 1 || resp.Counts.Shown != 2 {
		t.Fatalf("counts: %+v", resp.Counts)
	}
	got := map[string]NSEVuln{}
	for _, v := range resp.Vulns {
		got[v.ID] = v
	}
	if got["CVE-0000-0203"].Distro != "Ubuntu: VULNERABLE" || got["CVE-0000-0203"].Flags[0] != "distro-advisory-only" {
		t.Errorf("0203: %+v", got["CVE-0000-0203"])
	}
	if got["CVE-0000-0202"].Distro != "Ubuntu: NO_FIX" {
		t.Errorf("0202: %+v", got["CVE-0000-0202"])
	}
	if _, listed := got["CVE-0000-0201"]; listed || resp.DistroFixed[0] != "CVE-0000-0201" {
		t.Errorf("distro-fixed CVE must be summarised, not listed: %+v", resp)
	}
	text := strings.Join(resp.Lines, "\n")
	for _, want := range []string{"2 candidate CVEs", "Distribution: Ubuntu 22.04 installed 1:8.9p1-3ubuntu0.10; 1 more fixed in the package",
		"CVE-0000-0203    HIGH      CVSS 7.1  Ubuntu: VULNERABLE, distro-advisory-only"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestNSEOptions(t *testing.T) {
	e := fixtureEngine(t)
	apache := func(r *NSERequest) { r.Target.Port = 80 }
	all := answer(t, e, ubuntuRequest, apache)
	if all.Counts.Matches != 4 || all.Counts.Undetermined != 1 || len(all.Vulns) != 4 {
		t.Fatalf("apache: %+v", all.Counts)
	}
	limited := answer(t, e, ubuntuRequest, func(r *NSERequest) { apache(r); r.Options.Max = 2 })
	if len(limited.Vulns) != 2 || !strings.Contains(strings.Join(limited.Lines, "\n"), "... 2 more") {
		t.Errorf("max: %+v", limited.Lines)
	}
	high := answer(t, e, ubuntuRequest, func(r *NSERequest) { apache(r); r.Options.MinCVSS = 8 })
	for _, v := range high.Vulns {
		if v.CVSS == nil || *v.CVSS < 8 {
			t.Errorf("mincvss let %s through", v.ID)
		}
	}
	showall := answer(t, e, ubuntuRequest, func(r *NSERequest) { apache(r); r.Options.ShowUnknown = true })
	if len(showall.Vulns) != 5 {
		t.Errorf("showall: %d", len(showall.Vulns))
	}
}

func TestNSERequestErrors(t *testing.T) {
	for _, body := range []string{
		`{"version": 2, "target": {}}`,
		`{"version": 1, "surprise": true}`,
		`not json`,
	} {
		if _, err := ParseNSERequest(strings.NewReader(body)); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
	if _, err := ParseNSERequest(strings.NewReader(`{"version":1,"host":{"address":"` + strings.Repeat("a", maxNSERequestBytes) + `"}}`)); err == nil {
		t.Error("oversized request accepted")
	}
	req, _ := ParseNSERequest(strings.NewReader(ubuntuRequest))
	req.Target.Port = 443
	if _, err := AnswerNSE(context.Background(), req, fixtureEngine(t)); err == nil {
		t.Error("missing target port accepted")
	}
}
