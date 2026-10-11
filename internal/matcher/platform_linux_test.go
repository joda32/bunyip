package matcher

import (
	"testing"

	"bunyip/internal/database"
	"bunyip/internal/version"
)

// osNode builds a platform node (non-vulnerable OS rules) under OR.
func osNode(id int64, criteria ...string) database.ConfigNode {
	n := database.ConfigNode{ID: id, Operator: "OR"}
	for _, c := range criteria {
		n.Rules = append(n.Rules, database.MatchRule{Criteria: c, Vulnerable: false})
	}
	return n
}

func decideOne(platform Platform, nodes []database.ConfigNode) Applicability {
	v := &Vulnerability{CVE: "CVE-0000-0001", VersionStatus: version.Match, Applicability: Conditional}
	evs := []RuleEvaluation{{RuleID: 1, Status: version.Match, PlatformCondition: true}}
	decidePlatform(v, evs, map[int64][]database.ConfigNode{1: nodes}, []Platform{platform})
	return v.Applicability
}

func TestLinuxPlatformDecisions(t *testing.T) {
	deb, ok := LinuxPlatform("debian", "Debian")
	if !ok {
		t.Fatal("LinuxPlatform(debian)")
	}
	tests := []struct {
		name     string
		platform Platform
		nodes    []database.ConfigNode
		want     Applicability
	}{
		{"runs on generic Linux -> confirmed", deb,
			[]database.ConfigNode{osNode(10, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")}, Unconditional},
		{"runs on Debian itself -> confirmed", deb,
			[]database.ConfigNode{osNode(10, "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*")}, Unconditional},
		{"RHEL-only (Red Hat OpenSSH backdoor shape) -> excluded on Debian", deb,
			[]database.ConfigNode{osNode(10,
				"cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*",
				"cpe:2.3:o:redhat:enterprise_linux_desktop:5:*:*:*:*:*:*:*")}, PlatformExcluded},
		{"Windows-only -> excluded on Debian", deb,
			[]database.ConfigNode{osNode(10, "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*")}, PlatformExcluded},
		{"same distro, specific version we can't match -> stays conditional", deb,
			[]database.ConfigNode{osNode(10, "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*")}, Conditional},
	}
	for _, tt := range tests {
		if got := decideOne(tt.platform, tt.nodes); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestLinuxPlatformConstructor(t *testing.T) {
	p, ok := LinuxPlatform("ubuntu", "Ubuntu")
	if !ok || p.Family != "linux" || len(p.Identities) != 2 {
		t.Fatalf("ubuntu platform: %+v ok=%v", p, ok)
	}
	// generic kernel + the distro's own OS identity
	var kernel, distro bool
	for _, id := range p.Identities {
		if id.Vendor == "linux" && id.Product == "linux_kernel" {
			kernel = true
		}
		if id.Vendor == "canonical" && id.Product == "ubuntu_linux" {
			distro = true
		}
	}
	if !kernel || !distro {
		t.Errorf("ubuntu identities = %+v", p.Identities)
	}
	// an unknown distro still gets the generic kernel identity
	if p, _ := LinuxPlatform("rocky", "Rocky Linux"); len(p.Identities) != 1 {
		t.Errorf("rocky identities = %+v", p.Identities)
	}
	if _, ok := LinuxPlatform("", ""); ok {
		t.Error("empty distro should not yield a platform")
	}
}
