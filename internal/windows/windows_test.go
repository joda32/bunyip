package windows

import (
	"strings"
	"testing"

	"offline-vulndb/internal/database"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name     string
		sig      Signals
		build    int
		pv       string
		kind     string
		conflict bool
	}{
		{name: "nothing", sig: Signals{}},
		{name: "ntlm product version",
			sig:   Signals{ProductVersions: []Signal{{"10.0.20348", "rdp-ntlm-info on 3389/tcp"}}},
			build: 20348, pv: "10.0.20348"},
		{name: "malformed product version ignored",
			sig: Signals{ProductVersions: []Signal{{"10.0", "rdp-ntlm-info on 3389/tcp"}}}},
		{name: "smb os string: year is not the build",
			sig:   Signals{OSStrings: []Signal{{"Windows Server 2016 Standard Evaluation 14393", "smb-os-discovery"}}},
			build: 14393, pv: "10.0.14393", kind: Server},
		{name: "windows 7 with service pack",
			sig:   Signals{OSStrings: []Signal{{"Windows 7 Professional 7601 Service Pack 1", "smb-os-discovery"}}},
			build: 7601, pv: "6.1.7601", kind: Client},
		{name: "server 2008 R2",
			sig:   Signals{OSStrings: []Signal{{"Windows Server 2008 R2 Standard 7601 Service Pack 1", "smb-os-discovery"}}},
			build: 7601, pv: "6.1.7601", kind: Server},
		{name: "os string without build gives kind only, no evidence",
			sig: Signals{OSStrings: []Signal{{"Windows Server 2016 Standard", "smb-os-discovery"}}}},
		{name: "domain controller implies server",
			sig: Signals{ProductVersions: []Signal{{"10.0.14393", "rdp-ntlm-info on 3389/tcp"}},
				DomainController: "Microsoft Windows Kerberos on 88/tcp"},
			build: 14393, pv: "10.0.14393", kind: Server},
		{name: "ntlm and smb agree",
			sig: Signals{ProductVersions: []Signal{{"10.0.14393", "rdp-ntlm-info on 3389/tcp"}},
				OSStrings: []Signal{{"Windows 10 Enterprise 2016 LTSB 14393", "smb-os-discovery"}}},
			build: 14393, pv: "10.0.14393", kind: Client},
		{name: "conflicting builds",
			sig: Signals{ProductVersions: []Signal{{"10.0.17763", "rdp-ntlm-info on 3389/tcp"}},
				OSStrings: []Signal{{"Windows Server 2016 Standard 14393", "smb-os-discovery"}}},
			build: 17763, pv: "10.0.17763", kind: Server, conflict: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := Detect(tc.sig)
			if tc.build == 0 {
				if ev != nil {
					t.Fatalf("expected no evidence, got %+v", ev)
				}
				return
			}
			if ev == nil {
				t.Fatal("no evidence")
			}
			if ev.Build != tc.build || ev.ProductVersion != tc.pv || ev.Kind != tc.kind || (ev.Conflict != "") != tc.conflict {
				t.Errorf("got %+v", ev)
			}
		})
	}
}

func TestCandidates(t *testing.T) {
	r := database.WindowsBuild{Build: 14393, Kind: Client, Name: "Windows 10 1607",
		CPEs: []string{"cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"}}
	cands, err := candidates(r, "10.0.14393")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cands {
		got = append(got, c.CPE.String())
	}
	want := []string{
		`cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`,
		`cpe:2.3:o:microsoft:windows_10_1607:10.0.14393:*:*:*:*:*:x64:*`,
		`cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:x64:*`,
		`cpe:2.3:o:microsoft:windows_10:10.0.14393:*:*:*:*:*:x64:*`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("candidates:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
