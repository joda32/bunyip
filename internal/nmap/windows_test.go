package nmap

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"offline-vulndb/internal/distro"
	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/windows"
)

func TestParseScripts(t *testing.T) {
	s := parseFile(t, "../../testdata/nmap/windows-hosts.xml")
	h := s.Hosts[1]
	if len(h.Scripts) != 1 || h.Scripts[0].ID != "smb-os-discovery" ||
		h.Scripts[0].Elems["os"] != "Windows Server 2016 Standard Evaluation 14393" {
		t.Errorf("host scripts: %+v", h.Scripts)
	}
	rdp := h.Ports[1].Scripts
	if len(rdp) != 1 || rdp[0].ID != "rdp-ntlm-info" || rdp[0].Elems["Product_Version"] != "10.0.14393" ||
		!strings.Contains(rdp[0].Output, "Product_Version: 10.0.14393") {
		t.Errorf("port scripts: %+v", rdp)
	}
}

// cveIDs lists the assessment's CVEs with the given version status.
func cveIDs(a windows.Assessment, status ...string) []string {
	want := "MATCH"
	if len(status) > 0 {
		want = status[0]
	}
	var ids []string
	for _, v := range a.Vulnerabilities {
		if v.VersionStatus == want {
			ids = append(ids, v.CVE)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestAnalyseWindowsBuilds(t *testing.T) {
	old := distro.Now
	distro.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { distro.Now = old })

	e := fixtureEngineFrom(t, "../../testdata/fixtures/windows.json")
	rep, err := Analyse(context.Background(), parseFile(t, "../../testdata/nmap/windows-hosts.xml"), e)
	if err != nil {
		t.Fatal(err)
	}
	byAddr := map[string]HostReport{}
	for _, h := range rep.Hosts {
		byAddr[h.Address] = h
	}

	// Domain controller: build from RDP, server from AD services.
	dc := byAddr["192.0.2.10"].Windows
	if len(dc) != 1 || dc[0].Status != windows.Assessed || dc[0].Release != "Windows Server 2022" ||
		dc[0].Confidence != identity.High || !strings.Contains(dc[0].KindEvidence, "domain controllers run Windows Server") {
		t.Fatalf("dc: %+v", dc)
	}
	// 0904 is a range ending at a later build (KEV). Undetermined: 0905 needs
	// the Datacenter edition; 0909 was introduced by a later update.
	if got := cveIDs(dc[0]); !slices.Equal(got, []string{"CVE-0000-0904"}) || dc[0].KnownExploited != 1 ||
		dc[0].EndOfLife || !dc[0].Vulnerabilities[0].KnownRansomware {
		t.Errorf("dc CVEs %v: %+v", got, dc[0])
	}
	if got := cveIDs(dc[0], "UNKNOWN"); !slices.Equal(got, []string{"CVE-0000-0905", "CVE-0000-0909"}) || dc[0].Undetermined != 2 {
		t.Errorf("dc undetermined %v: %+v", got, dc[0])
	}
	for _, v := range dc[0].Vulnerabilities {
		if v.CVE == "CVE-0000-0909" && !strings.Contains(v.Reason, "introduced by a later update") {
			t.Errorf("0909 reason: %q", v.Reason)
		}
	}

	// Server named by SMB: the release itself (0901, KEV) and a range (0902,
	// exploit), never the Semi-Annual Channel release 1903 (0903).
	web := byAddr["192.0.2.11"].Windows
	if len(web) != 1 || web[0].Release != "Windows Server 2016" || web[0].Confidence != identity.High {
		t.Fatalf("web: %+v", web)
	}
	if got := cveIDs(web[0]); !slices.Equal(got, []string{"CVE-0000-0901", "CVE-0000-0902"}) ||
		web[0].KnownExploited != 1 || web[0].PublicExploit != 1 || web[0].Critical != 1 {
		t.Errorf("web CVEs %v: %+v", got, web[0])
	}
	if len(web[0].Evidence) != 3 { // RDP, SMB fingerprint, smb-os-discovery
		t.Errorf("web evidence: %v", web[0].Evidence)
	}

	// Build 14393 alone: Server 2016 or Windows 10 1607, both listed at MEDIUM.
	amb := byAddr["192.0.2.12"].Windows
	if len(amb) != 2 || amb[0].Confidence != identity.Medium || amb[1].Confidence != identity.Medium {
		t.Fatalf("ambiguous: %+v", amb)
	}
	if amb[0].Release != "Windows 10 1607" || amb[1].Release != "Windows Server 2016" {
		t.Fatalf("ambiguous releases: %s, %s", amb[0].Release, amb[1].Release)
	}
	// Client: x64 is assumed, so the x86-only 0906 is not listed.
	if got := cveIDs(amb[0]); !slices.Equal(got, []string{"CVE-0000-0907"}) {
		t.Errorf("client CVEs %v", got)
	}
	if got := cveIDs(amb[1]); !slices.Equal(got, cveIDs(web[0])) {
		t.Errorf("server CVEs %v", got)
	}
	if !slices.ContainsFunc(amb[0].Notes, func(n string) bool { return strings.Contains(n, "nothing in the scan shows") }) {
		t.Errorf("ambiguity not explained: %v", amb[0].Notes)
	}

	// Windows 11 22H2: past end of support at the pinned date.
	wk := byAddr["192.0.2.13"].Windows
	// 0910's range ends at another release's build: decided NO_MATCH by the
	// build identity, not left UNKNOWN by the release identity.
	if len(wk) != 1 || wk[0].Release != "Windows 11 22H2" || !wk[0].EndOfLife ||
		!slices.Equal(cveIDs(wk[0]), []string{"CVE-0000-0908"}) || wk[0].Undetermined != 0 {
		t.Errorf("workstation: %+v", wk)
	}

	if c := byAddr["192.0.2.14"].Windows; len(c) != 1 || c[0].Status != windows.Conflict || len(c[0].Vulnerabilities) != 0 {
		t.Errorf("conflict: %+v", c)
	}
	if u := byAddr["192.0.2.15"].Windows; len(u) != 1 || u[0].Status != windows.Unmapped {
		t.Errorf("unmapped: %+v", u)
	}

	if rep.Summary.WindowsHosts != 4 || rep.Summary.WindowsEOL != 1 {
		t.Errorf("summary: %+v", rep.Summary)
	}
	if !slices.Contains(rep.Warnings, windows.PatchNote) {
		t.Errorf("patch-level note missing: %v", rep.Warnings)
	}
	// Windows built-ins are OS components, covered by the build assessment;
	// Kerberos keeps its (LOW) application CPE. ClamAV is identified through
	// its curated product name, since Nmap reports no CPE for it.
	if rep.Summary.OSComponents != 8 || rep.Summary.VersionMatches != 1 {
		t.Errorf("summary: %+v", rep.Summary)
	}
	svc := map[int]ServiceReport{}
	for _, s := range byAddr["192.0.2.10"].Services {
		svc[s.Port] = s
	}
	if svc[389].Assessment != OSComponent || svc[3389].Assessment != OSComponent || svc[88].Assessment != Assessed {
		t.Errorf("dc services: 88=%s 389=%s 3389=%s", svc[88].Assessment, svc[389].Assessment, svc[3389].Assessment)
	}
	av := byAddr["192.0.2.16"].Services[0]
	if av.Assessment != Assessed || av.Result == nil || len(av.Result.Vulnerabilities) != 1 ||
		av.Result.Vulnerabilities[0].CVE != "CVE-0000-0911" || av.Result.Identities[0].Confidence != identity.High ||
		!strings.HasPrefix(av.Result.Identities[0].Source, "product-name:") {
		t.Errorf("clamav: %+v", av)
	}
	if len(byAddr["192.0.2.16"].Windows) != 0 {
		t.Errorf("non-Windows host assessed as Windows")
	}
}
