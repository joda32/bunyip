package build

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCuratedRealFiles(t *testing.T) {
	if a, err := LoadAliases("../../data/aliases.json"); err != nil || len(a) == 0 {
		t.Fatalf("aliases: %d %v", len(a), err)
	} else if a[0].prefix() == "" {
		t.Error("alias prefix empty")
	}
	wb, err := LoadWindowsBuilds("../../data/windows_builds.json")
	if err != nil || len(wb) == 0 {
		t.Fatalf("windows: %d %v", len(wb), err)
	}
	for _, w := range wb {
		if w.CPEs == "" || w.CPEs[:8] != "cpe:2.3:" {
			t.Errorf("windows cpe not expanded: %q", w.CPEs)
		}
	}
	if pn, err := LoadProductNames("../../data/product_names.json"); err != nil || len(pn) == 0 {
		t.Fatalf("product_names: %d %v", len(pn), err)
	}
	if ha, err := LoadHTTPApps("../../data/http_apps.json"); err != nil || len(ha) == 0 {
		t.Fatalf("http_apps: %d %v", len(ha), err)
	}
}

// TestLoadCuratedEmbedded verifies the "embedded:<name>" default source loads
// the first-party data compiled into the binary, with the same results as the
// on-disk copy — this is what makes bunyip a single self-contained binary.
func TestLoadCuratedEmbedded(t *testing.T) {
	embN, err := LoadAliases("embedded:aliases.json")
	if err != nil || len(embN) == 0 {
		t.Fatalf("embedded aliases: %d %v", len(embN), err)
	}
	diskN, err := LoadAliases("../../data/aliases.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(embN) != len(diskN) {
		t.Errorf("embedded vs disk aliases count: %d != %d", len(embN), len(diskN))
	}
	for _, src := range []string{
		"embedded:distro_packages.json", "embedded:distro_releases.json",
		"embedded:windows_builds.json", "embedded:product_names.json",
		"embedded:http_apps.json",
	} {
		if _, err := curatedData(src); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
	if _, err := curatedData("embedded:nope.json"); err == nil {
		t.Error("unknown embedded name accepted")
	}
	if _, err := LoadPackageMap("embedded:distro_packages.json"); err != nil {
		t.Errorf("embedded package map: %v", err)
	}
	if _, err := LoadReleases("embedded:distro_releases.json"); err != nil {
		t.Errorf("embedded releases: %v", err)
	}
}

func TestLoadAliasesRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "a.json")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	for _, bad := range []string{
		`{"aliases":[{"observed":"a:x:y","canonical":["a:p:q"],"confidence":"HIGH"}]}`,               // missing source
		`{"source":"s","aliases":[{"observed":"a:x:y","canonical":["o:p:q"],"confidence":"HIGH"}]}`,  // part change
		`{"source":"s","aliases":[{"observed":"a:x:y","canonical":["a:x:y"],"confidence":"HIGH"}]}`,  // self
		`{"source":"s","aliases":[{"observed":"a:x:y","canonical":["a:p:q"],"confidence":"BOGUS"}]}`, // confidence
	} {
		if _, err := LoadAliases(write(bad)); err == nil {
			t.Errorf("accepted bad aliases: %s", bad)
		}
	}
}

func TestDeriveHTTPTech(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{
	 "WordPress":{"cpe":"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
	 "NoCPE":{"cats":[1]},
	 "BadPart":{"cpe":"cpe:2.3:o:ms:windows:*:*:*:*:*:*:*:*"}}`), 0o644)
	rows, err := DeriveHTTPTech(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "WordPress" || rows[0].Vendor != "wordpress" || rows[0].Product != "wordpress" {
		t.Errorf("derive: %+v", rows)
	}
}

func TestLoadWindowsBuildsAllowsWholeValueUpdateWildcard(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	os.WriteFile(p, []byte(`{"source":"s","builds":[
	 {"build":9200,"kind":"server","name":"WS2012","cpes":["windows_server_2012:-:*"],"eol":"2023-10-10","support":"x"}]}`), 0o644)
	rows, err := LoadWindowsBuilds(p)
	if err != nil || len(rows) != 1 || rows[0].CPEs != "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*" {
		t.Fatalf("whole-value update wildcard: %v %+v", err, rows)
	}
	// embedded wildcard rejected
	os.WriteFile(p, []byte(`{"source":"s","builds":[
	 {"build":1,"kind":"server","name":"x","cpes":["windows_*:-:*"],"eol":"2020-01-01","support":"x"}]}`), 0o644)
	if _, err := LoadWindowsBuilds(p); err == nil {
		t.Error("embedded wildcard accepted")
	}
}
