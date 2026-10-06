package distro

import (
	"context"
	"slices"
	"strings"
	"testing"

	"offline-vulndb/internal/database"
)

// fakeStore holds rows copied from the real Ubuntu OSV records in
// testdata/osv/ubuntu (UBUNTU-CVE-2024-6387, -2023-38408, -2016-20012,
// -2025-61984, -2021-44790, -2022-26377).
type fakeStore struct {
	versions []database.PackageVersion
	adv      []database.DistroAdvisory
}

func (f fakeStore) HasDistroData(ctx context.Context, d string) (bool, error) {
	return d == "ubuntu" || d == "debian", nil
}

func (f fakeStore) PackageVersionsByUpstream(ctx context.Context, d string, pkgs []string, up string) ([]database.PackageVersion, error) {
	var out []database.PackageVersion
	for _, v := range f.versions {
		for _, p := range pkgs {
			if v.Package == p && stripEpoch(strings.SplitN(v.Version, "-", 2)[0]) == up {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (f fakeStore) DistroAdvisories(ctx context.Context, d, pkg, rel string) ([]database.DistroAdvisory, error) {
	var out []database.DistroAdvisory
	for _, a := range f.adv {
		if a.Package == pkg && a.Release == rel {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f fakeStore) PackagesInRelease(ctx context.Context, d, rel string, pkgs []string) ([]string, error) {
	var out []string
	for _, a := range f.adv {
		if a.Distro == d && a.Release == rel && slices.Contains(pkgs, a.Package) && !slices.Contains(out, a.Package) {
			out = append(out, a.Package)
		}
	}
	return out, nil
}

func adv(cve, rel, pkg, channel, fixed string, ups ...string) database.DistroAdvisory {
	distro := "ubuntu"
	if !strings.Contains(rel, ".") {
		distro = "debian"
	}
	return database.DistroAdvisory{AdvisoryID: "OSV-" + cve, CVEID: cve, Distro: distro, Release: rel,
		Channel: channel, Package: pkg, FixedVersion: fixed, AffectedUpstreams: ups}
}

var store = fakeStore{
	versions: []database.PackageVersion{
		{Release: "22.04", Package: "openssh", Version: "1:8.9p1-3ubuntu0.1"},
		{Release: "22.04", Package: "openssh", Version: "1:8.9p1-3ubuntu0.10"},
		{Release: "22.04", Package: "openssh", Version: "1:8.9p1-3ubuntu0.14"},
		{Release: "24.04", Package: "openssh", Version: "1:9.6p1-3ubuntu13.3"},
		{Release: "22.04", Package: "apache2", Version: "2.4.52-1ubuntu4.1"},
		{Release: "20.04", Package: "nginx", Version: "1.18.0-0ubuntu1.4"},
		{Release: "22.04", Package: "nginx", Version: "1.18.0-6ubuntu14.4"},
	},
	adv: []database.DistroAdvisory{
		adv("CVE-2024-6387", "22.04", "openssh", "standard", "1:8.9p1-3ubuntu0.10", "8.9p1"),
		adv("CVE-2024-6387", "24.04", "openssh", "standard", "1:9.6p1-3ubuntu13.3", "9.6p1"),
		adv("CVE-2023-38408", "22.04", "openssh", "standard", "1:8.9p1-3ubuntu0.3", "8.9p1"),
		adv("CVE-2016-20012", "22.04", "openssh", "standard", "", "8.9p1"),
		adv("CVE-2025-61984", "22.04", "openssh", "standard", "1:8.9p1-3ubuntu0.14", "8.9p1"),
		adv("CVE-2021-44790", "22.04", "apache2", "standard", "2.4.52-1ubuntu1", "2.4.48"),
		adv("CVE-2022-26377", "22.04", "apache2", "standard", "2.4.52-1ubuntu4.1", "2.4.52"),
		adv("CVE-2099-0001", "20.04", "nginx", "standard", "1.18.0-0ubuntu1.5", "1.18.0"),
		adv("CVE-2099-0001", "22.04", "nginx", "standard", "1.18.0-6ubuntu14.5", "1.18.0"),
		adv("CVE-2099-0002", "20.04", "nginx", "standard", "", "1.18.0"),
		adv("CVE-2099-0002", "22.04", "nginx", "standard", "1.18.0-6ubuntu14.1", "1.17.10"), // no 1.18.0 listed as affected
		adv("CVE-2099-0003", "22.04", "openssh", "pro", "1:8.9p1-3ubuntu0.13+esm1", "8.9p1"),
		// Debian, from the real DEBIAN-CVE-* records in testdata/osv/debian.
		adv("CVE-2024-6387", "12", "openssh", "standard", "1:9.2p1-2+deb12u3", "9.2p1"),
		adv("CVE-2024-6387", "13", "openssh", "standard", "1:9.7p1-7"),
		adv("CVE-2025-26465", "12", "openssh", "standard", "1:9.2p1-2+deb12u5", "9.2p1"),
		adv("CVE-2025-61984", "12", "openssh", "standard", "1:9.2p1-2+deb12u8", "9.2p1"),
		adv("CVE-2025-61984", "13", "openssh", "standard", "1:10.0p1-7+deb13u1", "10.0p1"),
		{AdvisoryID: "OSV-CVE-2007-2243", CVEID: "CVE-2007-2243", Distro: "debian", Release: "13", Channel: "standard",
			Package: "openssh", Urgency: "unimportant"},
		adv("CVE-2099-0004", "13", "openssh", "standard", "1:10.2p1-1"), // fixed by a newer upstream
	},
}

func resolve(t *testing.T, tg Target) *Context {
	t.Helper()
	tg.Distro, tg.DistroName = "ubuntu", "Ubuntu"
	c, err := Resolve(context.Background(), store, tg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRevisionKnown(t *testing.T) {
	// A fully patched-at-the-time jammy host: 8.9p1-3ubuntu0.10.
	c := resolve(t, Target{Upstream: "8.9p1", Revision: "3ubuntu0.10", Packages: []string{"openssh"}})
	if c.Status != Resolved || c.Installed != "1:8.9p1-3ubuntu0.10" || c.DefinitiveRelease() != "22.04" {
		t.Fatalf("context: %+v", c)
	}
	want := map[string]Status{
		"CVE-2024-6387":  Fixed,      // fixed exactly in 0.10
		"CVE-2023-38408": Fixed,      // fixed in 0.3
		"CVE-2016-20012": NoFix,      // no fix released
		"CVE-2025-61984": Vulnerable, // fixed later, in 0.14
		"CVE-2099-9999":  NoData,     // not listed
	}
	for cve, st := range want {
		if v := c.Verdict(cve); v.Status != st || v.Reason == "" {
			t.Errorf("%s: %s (%s), want %s", cve, v.Status, v.Reason, st)
		}
	}
	// Ubuntu fixed CVE-2025-61984 in a later package; CVE-2099-0003 is fixed
	// only in Ubuntu Pro, so a standard host is still vulnerable to it.
	add := c.Additional(map[string]bool{"CVE-2024-6387": true})
	if len(add) != 2 || add[0].CVE != "CVE-2025-61984" || add[0].FixedVersion != "1:8.9p1-3ubuntu0.14" ||
		add[1].CVE != "CVE-2099-0003" || add[1].Channel != "pro" {
		t.Errorf("additional findings: %+v", add)
	}
}

func TestOlderRevision(t *testing.T) {
	c := resolve(t, Target{Upstream: "8.9p1", Revision: "3ubuntu0.1", Packages: []string{"openssh"}})
	for _, cve := range []string{"CVE-2024-6387", "CVE-2023-38408", "CVE-2025-61984"} {
		if v := c.Verdict(cve); v.Status != Vulnerable {
			t.Errorf("%s: %s", cve, v.Status)
		}
	}
}

func TestUnpublishedRevisionFallsBackToUpstream(t *testing.T) {
	// 3ubuntu0.20 is newer than anything in the advisory data.
	c := resolve(t, Target{Upstream: "8.9p1", Revision: "3ubuntu0.20", Packages: []string{"openssh"}})
	if c.Status != Resolved || c.DefinitiveRelease() != "" {
		t.Fatalf("context: %+v", c)
	}
	if v := c.Verdict("CVE-2025-61984"); v.Status != Fixed {
		t.Errorf("0.20 >= 0.14 should be fixed: %+v", v)
	}
}

func TestRevisionUnknown(t *testing.T) {
	c := resolve(t, Target{Upstream: "2.4.52", Packages: []string{"apache2"}})
	if c.Status != Resolved || c.Installed != "" {
		t.Fatalf("context: %+v", c)
	}
	if v := c.Verdict("CVE-2021-44790"); v.Status != Fixed {
		t.Errorf("fixed in the release's initial package: %+v", v)
	}
	if v := c.Verdict("CVE-2022-26377"); v.Status != FixAvailable || !strings.Contains(v.Reason, "not visible") {
		t.Errorf("fix in a later revision: %+v", v)
	}
	if add := c.Additional(nil); add != nil {
		t.Errorf("no additional findings without a revision: %+v", add)
	}
}

func TestAmbiguousRelease(t *testing.T) {
	c := resolve(t, Target{Upstream: "1.18.0", Packages: []string{"nginx"}})
	if c.Status != Ambiguous || len(c.Releases) != 2 {
		t.Fatalf("context: %+v", c)
	}
	if v := c.Verdict("CVE-2099-0001"); v.Status != FixAvailable || v.Release != "20.04|22.04" {
		t.Errorf("agreeing releases: %+v", v)
	}
	if v := c.Verdict("CVE-2099-0002"); v.Status != NoData || !strings.Contains(v.Reason, "disagree") {
		t.Errorf("disagreeing releases: %+v", v)
	}
	// Another service on the host (e.g. OpenSSH) established 22.04.
	h := resolve(t, Target{Upstream: "1.18.0", Packages: []string{"nginx"}, ReleaseHint: "22.04"})
	if h.Status != Resolved || h.Verdict("CVE-2099-0002").Status != Fixed {
		t.Errorf("hinted: %+v %+v", h, h.Verdict("CVE-2099-0002"))
	}
}

func TestProChannel(t *testing.T) {
	esm := resolve(t, Target{Upstream: "8.9p1", Revision: "3ubuntu0.13+esm1", Packages: []string{"openssh"}})
	if v := esm.Verdict("CVE-2099-0003"); v.Status != Fixed || v.Channel != "pro" {
		t.Errorf("ESM host: %+v", v)
	}
	std := resolve(t, Target{Upstream: "8.9p1", Revision: "3ubuntu0.10", Packages: []string{"openssh"}})
	if v := std.Verdict("CVE-2099-0003"); v.Status != Vulnerable || !strings.Contains(v.Reason, "Pro/ESM") {
		t.Errorf("standard host, fix only in Pro: %+v", v)
	}
}

func TestNoDataCases(t *testing.T) {
	for _, tc := range []struct {
		tg   Target
		want string
	}{
		{Target{Upstream: "1.0"}, Unmapped},
		{Target{Upstream: "7.0p1", Packages: []string{"openssh"}}, UnknownRelease},
	} {
		c := resolve(t, tc.tg)
		if c.Status != tc.want || c.Verdict("CVE-2024-6387").Status != NoData {
			t.Errorf("%+v: %+v", tc.tg, c)
		}
	}
	c, _ := Resolve(context.Background(), store, Target{Distro: "redhat", DistroName: "Red Hat", Upstream: "8.7p1",
		Packages: []string{"openssh"}})
	if c.Status != NoDataSource {
		t.Errorf("distribution without data: %+v", c)
	}
}

func resolveDebian(t *testing.T, tg Target) *Context {
	t.Helper()
	tg.Distro, tg.DistroName, tg.Packages = "debian", "Debian", []string{"openssh"}
	c, err := Resolve(context.Background(), store, tg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDebianReleaseFromRevision(t *testing.T) {
	if r := ReleaseFromRevision("debian", "2+deb12u3"); r != "12" {
		t.Errorf("deb12u3 -> %q", r)
	}
	if r := ReleaseFromRevision("ubuntu", "0ubuntu0.22.04.2"); r != "22.04" {
		t.Errorf("ubuntu0.22.04 -> %q", r)
	}
	// Nmap "9.2p1 Debian 2+deb12u6": the version is absent from the data, but the
	// revision names the release, which is enough.
	c := resolveDebian(t, Target{Upstream: "9.2p1", Revision: "2+deb12u6"})
	if c.Status != Resolved || c.DefinitiveRelease() != "12" || c.Installed != "1:9.2p1-2+deb12u6" ||
		!strings.Contains(c.Reason, "encodes Debian 12") {
		t.Fatalf("context: %+v", c)
	}
	want := map[string]Status{"CVE-2024-6387": Fixed, "CVE-2025-26465": Fixed, "CVE-2025-61984": Vulnerable}
	for cve, st := range want {
		if v := c.Verdict(cve); v.Status != st {
			t.Errorf("%s: %s (%s)", cve, v.Status, v.Reason)
		}
	}
}

func TestDebianRevisionUnknownUpstreamComparison(t *testing.T) {
	// Debian 13 OpenSSH 10.0p1 seen as "(Debian)" only.
	c := resolveDebian(t, Target{Upstream: "10.0p1", ReleaseHint: "13"})
	if c.Status != Resolved {
		t.Fatalf("context: %+v", c)
	}
	// Fixed in 9.7p1-7 before trixie was released: every 10.0p1 package is newer.
	if v := c.Verdict("CVE-2024-6387"); v.Status != Fixed || !strings.Contains(v.Reason, "every openssh 10.0p1 package is newer") {
		t.Errorf("CVE-2024-6387: %+v", v)
	}
	// Same upstream, fixed in a later revision: can't tell without the revision.
	if v := c.Verdict("CVE-2025-61984"); v.Status != FixAvailable {
		t.Errorf("CVE-2025-61984: %+v", v)
	}
	// Fixed only by a newer upstream (10.2p1): every 10.0p1 package is older.
	if v := c.Verdict("CVE-2099-0004"); v.Status != Vulnerable {
		t.Errorf("CVE-2099-0004: %+v", v)
	}
	if add := c.Additional(map[string]bool{"CVE-2024-6387": true}); len(add) != 1 || add[0].CVE != "CVE-2099-0004" {
		t.Errorf("definitive findings without a revision: %+v", add)
	}
	if v := c.Verdict("CVE-2007-2243"); v.Status != NoFix || !strings.Contains(v.Reason, "rated unimportant") {
		t.Errorf("unimportant: %+v", v)
	}
}
