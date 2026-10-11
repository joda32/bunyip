package build

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bunyip/internal/database"
)

func writeFeed(t *testing.T, dir, name string, items []string, lastMod string) {
	t.Helper()
	body := `{"version":"2.0","vulnerabilities":[` + joinJSON(items) + `]}`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(body))
	gz.Close()
	base := filepath.Join(dir, "nvdcve-2.0-"+name)
	os.WriteFile(base+".json.gz", buf.Bytes(), 0o644)
	os.WriteFile(base+".meta", []byte("lastModifiedDate:"+lastMod+"\r\nsize:0\r\n"), 0o644)
}

func joinJSON(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func cve(id, modified string, extra string) string {
	return `{"cve":{"id":"` + id + `","lastModified":"` + modified +
		`","descriptions":[{"lang":"en","value":"d"}]` + extra + `}}`
}

func TestBuildNVDKEVOverlayAndReject(t *testing.T) {
	dir := t.TempDir()
	apacheCfg := `,"configurations":[{"nodes":[{"cpeMatch":[` +
		`{"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*","vulnerable":true}]}]}]`
	// yearly feed: three CVEs, one with a config
	writeFeed(t, dir, "2021", []string{
		cve("CVE-2021-0001", "2021-01-01T00:00:00.000", apacheCfg),
		cve("CVE-2021-0002", "2021-01-01T00:00:00.000", ""),
		cve("CVE-2021-0003", "2021-01-01T00:00:00.000", ""),
	}, "2021-01-01T00:00:00Z")
	// modified overlay: bump 0001 (replace), reject 0002 (delete), stale 0003 (ignored)
	writeFeed(t, dir, "modified", []string{
		cve("CVE-2021-0001", "2099-01-01T00:00:00.000", ""), // newer: replaces, drops the config
		`{"cve":{"id":"CVE-2021-0002","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"x"}]}}`,
		cve("CVE-2021-0003", "2000-01-01T00:00:00.000", apacheCfg), // older: ignored, keeps original (no config)
	}, "2099-01-01T00:00:00Z")

	kev := filepath.Join(dir, "kev.json")
	os.WriteFile(kev, []byte(`{"catalogVersion":"TEST","dateReleased":"2026-01-01","vulnerabilities":[`+
		`{"cveID":"CVE-2021-0001","vendorProject":"Apache","product":"httpd"}]}`), 0o644)

	out := filepath.Join(dir, "out.sqlite")
	st, err := BuildNVDKEV(context.Background(), out,
		[]Feed{{Name: "2021", GzPath: filepath.Join(dir, "nvdcve-2.0-2021.json.gz")},
			{Name: "modified", GzPath: filepath.Join(dir, "nvdcve-2.0-modified.json.gz")}},
		kev, Options{AllowSmall: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if st.Loaded != 3 || st.Replaced != 1 || st.Rejected != 1 || st.Unchanged != 1 {
		t.Errorf("stats: %+v", st)
	}

	store, err := database.Open(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stats, _ := store.Stats(context.Background())
	counts := map[string]int64{}
	for _, tb := range stats.Tables {
		counts[tb.Table] = tb.Rows
	}
	if counts["cves"] != 2 { // 0001 (replaced) + 0003; 0002 rejected
		t.Errorf("cves=%d, want 2", counts["cves"])
	}
	// 0001 was replaced by a config-less record; 0003 kept its original (no config). So no matches.
	if counts["cve_matches"] != 0 {
		t.Errorf("cve_matches=%d, want 0 (overlay dropped the config)", counts["cve_matches"])
	}
	if counts["kev"] != 1 {
		t.Errorf("kev=%d, want 1", counts["kev"])
	}
	if v, _ := store.Verify(context.Background()); !allOK(v) {
		t.Errorf("verify not clean: %+v", v)
	}
}

func allOK(checks []database.Check) bool {
	for _, c := range checks {
		if c.Status == database.CheckFail {
			return false
		}
	}
	return true
}

var _ = json.Marshal
