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

func TestFeedNames(t *testing.T) {
	n := FeedNames(2024)
	if n[0] != "2002" || n[len(n)-1] != "modified" || n[len(n)-2] != "2024" {
		t.Errorf("feed names: %v ... %v", n[:2], n[len(n)-2:])
	}
}
