package build

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gzMeta(t *testing.T, body string) (gz []byte, meta string) {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(body))
	w.Close()
	h := sha256.Sum256([]byte(body))
	meta = fmt.Sprintf("lastModifiedDate:2026-10-06T01:00:06-04:00\r\nsize:%d\r\nsha256:%s\r\n",
		len(body), hex.EncodeToString(h[:]))
	return buf.Bytes(), meta
}

// testFetcher points a Fetcher at an httptest server and allows its host.
func testFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()
	f := NewFetcher("test", nil)
	f.FeedBase = srv.URL + "/feeds/"
	f.KEVURL = srv.URL + "/kev.json"
	u, _ := url.Parse(srv.URL)
	f.Allowed = map[string]bool{u.Hostname(): true}
	f.Client = srv.Client()
	f.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	return f
}

func TestParseMeta(t *testing.T) {
	m, err := ParseMeta("lastModifiedDate:2026-10-06T01:00:06-04:00\r\nsize:42\r\nsha256:ABCDEF\r\n")
	if err != nil || m.Size != 42 || m.SHA256 != "abcdef" || m.LastModified != "2026-10-06T01:00:06-04:00" {
		t.Fatalf("meta=%+v err=%v", m, err)
	}
	if _, err := ParseMeta("size:x"); err == nil {
		t.Error("malformed meta accepted")
	}
}

func TestVerifyFeed(t *testing.T) {
	dir := t.TempDir()
	gz, metaText := gzMeta(t, `{"version":"2.0","vulnerabilities":[]}`)
	os.WriteFile(filepath.Join(dir, "f.json.gz"), gz, 0o644)
	meta, _ := ParseMeta(metaText)
	if err := verifyFeed(filepath.Join(dir, "f.json.gz"), meta); err != nil {
		t.Errorf("verify: %v", err)
	}
	meta.SHA256 = "deadbeef"
	if err := verifyFeed(filepath.Join(dir, "f.json.gz"), meta); err == nil {
		t.Error("checksum mismatch not detected")
	}
}

func TestSyncNVDCacheAndVerify(t *testing.T) {
	gz, metaText := gzMeta(t, `{"version":"2.0","vulnerabilities":[]}`)
	hits := map[string]int{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		switch {
		case r.URL.Path == "/feeds/nvdcve-2.0-modified.meta":
			w.Write([]byte(metaText))
		case r.URL.Path == "/feeds/nvdcve-2.0-modified.json.gz":
			w.Write(gz)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	cache := t.TempDir()

	feeds, err := f.SyncNVD(cache, []string{"modified"})
	if err != nil || len(feeds) != 1 || feeds[0].LastModified == "" {
		t.Fatalf("sync: %v feeds=%+v", err, feeds)
	}
	if hits["/feeds/nvdcve-2.0-modified.json.gz"] != 1 {
		t.Fatalf("expected one gz download, got %d", hits["/feeds/nvdcve-2.0-modified.json.gz"])
	}
	// Second sync: same .meta sha256 -> gz is NOT re-downloaded.
	if _, err := f.SyncNVD(cache, []string{"modified"}); err != nil {
		t.Fatal(err)
	}
	if hits["/feeds/nvdcve-2.0-modified.json.gz"] != 1 {
		t.Errorf("cache miss: gz downloaded again (%d)", hits["/feeds/nvdcve-2.0-modified.json.gz"])
	}
}

func TestSyncNVDRejectsBadChecksum(t *testing.T) {
	_, metaText := gzMeta(t, `{"a":1}`)
	badGz, _ := gzMeta(t, `{"different":"content"}`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".meta" {
			w.Write([]byte(metaText))
		} else {
			w.Write(badGz) // body does not match the .meta sha256
		}
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	if _, err := f.SyncNVD(t.TempDir(), []string{"modified"}); err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestDownloadStallAborts(t *testing.T) {
	_, metaText := gzMeta(t, `{"version":"2.0","vulnerabilities":[]}`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".meta" {
			w.Write([]byte(metaText))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		time.Sleep(400 * time.Millisecond) // idle well past the stall timeout
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	f.StallTimeout = 50 * time.Millisecond
	_, err := f.SyncNVD(t.TempDir(), []string{"modified"})
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("expected stall error, got %v", err)
	}
}

func TestDownloadSlowButSteadySucceeds(t *testing.T) {
	body := `{"version":"2.0","vulnerabilities":[]}`
	gz, metaText := gzMeta(t, body)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".meta" {
			w.Write([]byte(metaText))
			return
		}
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < len(gz); i += 4 { // drip in chunks, each gap < stall
			end := i + 4
			if end > len(gz) {
				end = len(gz)
			}
			w.Write(gz[i:end])
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	f.StallTimeout = 200 * time.Millisecond // each 10ms gap resets the watchdog
	feeds, err := f.SyncNVD(t.TempDir(), []string{"modified"})
	if err != nil || len(feeds) != 1 {
		t.Fatalf("slow steady download failed: %v feeds=%d", err, len(feeds))
	}
}

func TestCheckURLAllowList(t *testing.T) {
	f := NewFetcher("test", nil)
	if f.checkURL("http://nvd.nist.gov/x") == nil {
		t.Error("http accepted")
	}
	if f.checkURL("https://evil.example/x") == nil {
		t.Error("off-allowlist host accepted")
	}
	if err := f.checkURL("https://nvd.nist.gov/feeds/x.meta"); err != nil {
		t.Errorf("allowed host rejected: %v", err)
	}
}

func TestSyncWebappanalyzer(t *testing.T) {
	hits := map[string]int{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		fmt.Fprintf(w, `{"%s-tech":{"cpe":"cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}}`, filepath.Base(r.URL.Path))
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	f.WappBase = srv.URL + "/wapp/"
	cache := t.TempDir()

	dir, err := f.SyncWebappanalyzer(cache)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// _.json plus a.json..z.json = 27 files.
	if hits["/wapp/_.json"] != 1 || hits["/wapp/a.json"] != 1 || hits["/wapp/z.json"] != 1 {
		t.Errorf("missing expected downloads: %v", hits)
	}
	if got := len(hits); got != 27 {
		t.Errorf("expected 27 fingerprint files, downloaded %d", got)
	}
	for _, n := range []string{"_.json", "a.json", "z.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("file not written: %s", n)
		}
	}
}

func TestSyncEPSS(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("#model_version:v1,score_date:2026-10-10T00:00:00+0000\ncve,epss,percentile\nCVE-2021-41773,0.9,0.99\n"))
	gw.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(buf.Bytes())
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	f.EPSSURL = srv.URL + "/epss_scores-current.csv.gz"
	cache := t.TempDir()
	p, err := f.SyncEPSS(cache)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	d, err := LoadEPSS(p)
	if err != nil || len(d.Rows) != 1 || d.Rows[0].CVEID != "CVE-2021-41773" {
		t.Fatalf("load fetched EPSS: %v rows=%+v", err, d.Rows)
	}
	if LocalEPSS(cache) == "" {
		t.Error("LocalEPSS did not find the cached file")
	}
}

func TestSyncExploitSources(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".json" {
			w.Write([]byte(`{"m":{"fullname":"exploit/x","references":["CVE-2021-41773"]}}`))
		} else {
			w.Write([]byte("id,codes\n1,CVE-2021-41773\n"))
		}
	}))
	defer srv.Close()
	f := testFetcher(t, srv)
	f.MSFURL = srv.URL + "/modules_metadata_base.json"
	f.EDBURL = srv.URL + "/files_exploits.csv"
	cache := t.TempDir()

	mp, err := f.SyncMetasploit(cache)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := LoadMetasploit(mp); err != nil || len(rows) != 1 {
		t.Fatalf("msf: %v rows=%d", err, len(rows))
	}
	ep, err := f.SyncExploitDB(cache)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := LoadExploitDB(ep); err != nil || len(rows) != 1 {
		t.Fatalf("edb: %v rows=%d", err, len(rows))
	}
	if LocalMetasploit(cache) == "" || LocalExploitDB(cache) == "" {
		t.Error("Local* did not find the cached files")
	}
	if LocalMetasploit(t.TempDir()) != "" {
		t.Error("LocalMetasploit found a nonexistent file")
	}
}

func TestVerifyLocalOSV(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "osv-Debian-all.zip")
	os.WriteFile(zipPath, []byte("fake-zip-bytes"), 0o644)
	sum, _ := md5Base64(zipPath)

	// Missing export: skipped, no error.
	if p, err := VerifyLocalOSV(dir, "Ubuntu"); err != nil || p != "" {
		t.Errorf("absent export: p=%q err=%v", p, err)
	}
	// Export present but no .meta.json: error.
	if _, err := VerifyLocalOSV(dir, "Debian"); err == nil {
		t.Error("missing meta accepted")
	}
	// Matching MD5: returns the zip path.
	os.WriteFile(filepath.Join(dir, "osv-Debian-all.meta.json"), []byte(`{"md5":"`+sum+`"}`), 0o644)
	if p, err := VerifyLocalOSV(dir, "Debian"); err != nil || p != zipPath {
		t.Errorf("good md5: p=%q err=%v", p, err)
	}
	// Wrong MD5: error.
	os.WriteFile(filepath.Join(dir, "osv-Debian-all.meta.json"), []byte(`{"md5":"AAAA"}`), 0o644)
	if _, err := VerifyLocalOSV(dir, "Debian"); err == nil {
		t.Error("md5 mismatch not detected")
	}
}

func TestFeedNames(t *testing.T) {
	n := FeedNames(2024)
	if n[0] != "2002" || n[len(n)-1] != "modified" || n[len(n)-2] != "2024" {
		t.Errorf("feed names: %v ... %v", n[:2], n[len(n)-2:])
	}
}
