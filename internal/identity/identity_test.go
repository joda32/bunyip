package identity

import (
	"strings"
	"testing"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/database"
)

var testAliases = []database.Alias{
	{Part: "a", ObservedVendor: "igor_sysoev", ObservedProduct: "nginx", CanonicalVendor: "f5",
		CanonicalProduct: "nginx", Source: "test", Confidence: "HIGH"},
	{Part: "a", ObservedVendor: "igor_sysoev", ObservedProduct: "nginx", CanonicalVendor: "nginx",
		CanonicalProduct: "nginx", Source: "test", Confidence: "HIGH"},
	{Part: "a", ObservedVendor: "zyxel", ObservedProduct: "rompager", CanonicalVendor: "allegrosoft",
		CanonicalProduct: "rompager", Source: "test", Confidence: "MEDIUM"},
	{Part: "a", ObservedVendor: "", ObservedProduct: "Apache httpd", CanonicalVendor: "apache",
		CanonicalProduct: "http_server", Source: "test", Confidence: "HIGH"}, // product-name alias: ignored
}

func mustParse(t *testing.T, s string) cpe.CPE {
	t.Helper()
	c, err := cpe.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResolveCPE(t *testing.T) {
	r := NewResolver(testAliases)
	tests := []struct {
		in   string
		want []string // "cpe|confidence"
	}{
		{"cpe:/a:igor_sysoev:nginx:1.20.0", []string{
			"cpe:2.3:a:igor_sysoev:nginx:1.20.0:*:*:*:*:*:*:*|EXACT",
			"cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*|HIGH",
			"cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*|HIGH",
		}},
		{"cpe:/a:igor_sysoev:nginx", []string{ // no version: aliases cannot be more certain than LOW
			"cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*|LOW",
			"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*|LOW",
			"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*|LOW",
		}},
		{"cpe:/a:zyxel:rompager:4.07", []string{
			"cpe:2.3:a:zyxel:rompager:4.07:*:*:*:*:*:*:*|EXACT",
			"cpe:2.3:a:allegrosoft:rompager:4.07:*:*:*:*:*:*:*|MEDIUM",
		}},
		{"cpe:/a:apache:http_server:2.4.49", []string{"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*|EXACT"}},
		{"cpe:/o:igor_sysoev:nginx:1.0", []string{"cpe:2.3:o:igor_sysoev:nginx:1.0:*:*:*:*:*:*:*|EXACT"}}, // part must match
	}
	for _, tt := range tests {
		var got []string
		for _, c := range r.ResolveCPE(mustParse(t, tt.in), "nmap") {
			got = append(got, c.CPE.String()+"|"+string(c.Confidence))
			if c.Reason == "" {
				t.Errorf("%s: empty reason", tt.in)
			}
		}
		if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
			t.Errorf("ResolveCPE(%s):\n got %v\nwant %v", tt.in, got, tt.want)
		}
	}
}

// The service observed by a real `nmap -sV` scan of an Ubuntu host.
var realUbuntuSSH = Observation{
	Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.18", ExtraInfo: "Ubuntu Linux; protocol 2.0",
	OSType: "Linux", CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"},
}

func TestResolveObservationRealUbuntuSSH(t *testing.T) {
	res := NewResolver(nil).ResolveObservation(realUbuntuSSH, "nmap")
	if len(res.Candidates) != 1 || res.Candidates[0].CPE.String() != "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*" ||
		res.Candidates[0].Confidence != Exact {
		t.Fatalf("candidates: %+v", res.Candidates)
	}
	if len(res.PlatformCPEs) != 1 || res.PlatformCPEs[0] != "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*" {
		t.Errorf("OS CPE must be recorded, not queried: %v", res.PlatformCPEs)
	}
	if res.Distro != (DistroInfo{Name: "Ubuntu", Key: "ubuntu", Revision: "3ubuntu13.18"}) ||
		res.Distro.Label() != "Ubuntu package 3ubuntu13.18" {
		t.Errorf("distro = %+v", res.Distro)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "backported") {
		t.Errorf("missing backport note: %v", res.Notes)
	}
}

func TestResolveObservationEdgeCases(t *testing.T) {
	r := NewResolver(testAliases)

	noCPE := r.ResolveObservation(Observation{Product: "Mystery httpd", Version: "1.2"}, "nmap")
	if len(noCPE.Candidates) != 0 || !strings.Contains(strings.Join(noCPE.Notes, " "), "Mystery httpd 1.2") {
		t.Errorf("unidentified product not reported: %+v", noCPE)
	}

	// Two unusable CPEs and no product: both CPEs are reported, plus "not identified".
	bad := r.ResolveObservation(Observation{CPEs: []string{"cpe:/a:bad vendor:x", "cpe:/a:apache"}}, "nmap")
	if len(bad.Candidates) != 0 || len(bad.Notes) != 3 || !strings.Contains(bad.Notes[2], "not identified") {
		t.Errorf("malformed/insufficient CPEs not reported: %+v", bad)
	}

	iis := r.ResolveObservation(Observation{Product: "Microsoft IIS httpd", Version: "10.0", OSType: "Windows",
		CPEs: []string{"cpe:/a:microsoft:internet_information_services:10.0", "cpe:/o:microsoft:windows"}}, "nmap")
	if len(iis.Candidates) != 1 || !strings.Contains(strings.Join(iis.Notes, " "), "against Microsoft Windows") {
		t.Errorf("IIS note missing: %+v", iis)
	}
	if iis.Distro.Detected() {
		t.Errorf("Windows is not a backporting distro here: %+v", iis.Distro)
	}

	alias := r.ResolveObservation(Observation{Product: "nginx", Version: "1.20.0",
		CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.20.0"}}, "nmap")
	if len(alias.Candidates) != 3 {
		t.Errorf("aliases not applied to observations: %+v", alias.Candidates)
	}
}

func TestDetectDistro(t *testing.T) {
	tests := []struct {
		o    Observation
		cpes []string
		want string
	}{
		{Observation{Version: "9.2p1 Debian 2+deb12u3", ExtraInfo: "protocol 2.0"}, nil, "Debian package 2+deb12u3"},
		{Observation{Version: "2.4.37", ExtraInfo: "Red Hat Enterprise Linux"}, nil, "Red Hat"},
		{Observation{Version: "2.4.6", ExtraInfo: "CentOS"}, nil, "CentOS"},
		{Observation{Version: "7.4"}, []string{"cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"}, "Ubuntu"},
		{Observation{Version: "9.8p1", ExtraInfo: "protocol 2.0"}, nil, ""},
		{Observation{Version: "2.4.49"}, []string{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}, ""},
		{Observation{Version: "8.0.33-0ubuntu0.22.04.2 Ubuntu weird!rev"}, nil, "Ubuntu"}, // invalid revision ignored
	}
	for _, tt := range tests {
		if got := DetectDistro(tt.o, tt.cpes).Label(); got != tt.want {
			t.Errorf("DetectDistro(%+v, %v) = %q, want %q", tt.o, tt.cpes, got, tt.want)
		}
	}
}
