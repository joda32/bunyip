package build

import (
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Network fetch — the only part of the builder that touches the network.
// Only HTTPS on allow-listed hosts is fetched, downloads are size-capped, and
// NVD feeds are verified against the sha256 in their .meta (computed over the
// uncompressed JSON) before being accepted into the cache. Ported from the
// Python updater's fetch.py.

const (
	nvdFeedBase      = "https://nvd.nist.gov/feeds/json/cve/2.0/"
	kevURL           = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevFile          = "known_exploited_vulnerabilities.json"
	firstFeedYear    = 2002
	maxDownloadBytes = 1 << 30
	fetchTimeout     = 120 * time.Second
	fetchRetries     = 4
)

// Meta is a feed's .meta sidecar.
type Meta struct {
	LastModified string // RFC 3339 as published
	Size         int64  // uncompressed bytes
	SHA256       string // of the uncompressed JSON, lower-case hex
}

// Fetcher downloads source data. The zero value is not usable; call
// NewFetcher. Fields are exported so tests can retarget it at a local server.
type Fetcher struct {
	FeedBase     string
	KEVURL       string
	OSVBase      string
	Allowed      map[string]bool
	Client       *http.Client
	UserAgent    string
	RetryBackoff func(attempt int) time.Duration
	Log          func(string, ...any)
}

// NewFetcher returns a fetcher configured for the real NVD and CISA hosts.
func NewFetcher(ua string, log func(string, ...any)) *Fetcher {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Fetcher{
		FeedBase:     nvdFeedBase,
		KEVURL:       kevURL,
		Allowed:      map[string]bool{"nvd.nist.gov": true, "www.cisa.gov": true, "osv-vulnerabilities.storage.googleapis.com": true},
		Client:       &http.Client{Timeout: fetchTimeout},
		UserAgent:    ua,
		RetryBackoff: func(attempt int) time.Duration { return time.Duration(1<<attempt) * time.Second },
		Log:          log,
	}
}

func (f *Fetcher) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad url %q: %w", raw, err)
	}
	if u.Scheme != "https" || !f.Allowed[u.Hostname()] {
		return fmt.Errorf("refusing to fetch %q: only HTTPS on allow-listed hosts", raw)
	}
	return nil
}

// download fetches url to dest atomically, with retries and a size cap.
func (f *Fetcher) download(raw, dest string) error {
	if err := f.checkURL(raw); err != nil {
		return err
	}
	part := dest + ".part"
	var lastErr error
	for attempt := 1; attempt <= fetchRetries; attempt++ {
		err := f.try(raw, part)
		if err == nil {
			return os.Rename(part, dest)
		}
		os.Remove(part)
		if isFatal(err) {
			return err
		}
		lastErr = err
		if attempt == fetchRetries {
			break
		}
		wait := f.RetryBackoff(attempt)
		f.Log("  retry %d/%d for %s in %s: %v", attempt, fetchRetries-1, raw, wait, err)
		time.Sleep(wait)
	}
	return fmt.Errorf("%s: %w", raw, lastErr)
}

// isFatal reports policy violations that must not be retried.
func isFatal(err error) bool {
	m := err.Error()
	return strings.Contains(m, "refusing to fetch") || strings.Contains(m, "exceeds")
}

func (f *Fetcher) try(raw, part string) error {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := f.checkURL(resp.Request.URL.String()); err != nil { // covers redirects
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(part)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return err
	}
	if n > maxDownloadBytes {
		return fmt.Errorf("%s: exceeds %d bytes", raw, maxDownloadBytes)
	}
	return out.Close()
}

// ParseMeta parses a .meta sidecar.
func ParseMeta(text string) (Meta, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			fields[k] = v
		}
	}
	size, err := strconv.ParseInt(fields["size"], 10, 64)
	if fields["lastModifiedDate"] == "" || fields["sha256"] == "" || err != nil {
		return Meta{}, fmt.Errorf("malformed .meta file")
	}
	return Meta{LastModified: fields["lastModifiedDate"], Size: size, SHA256: strings.ToLower(fields["sha256"])}, nil
}

// verifyFeed checks a gzipped feed's decompressed size and sha256 against its
// .meta (NVD computes the hash over the uncompressed JSON).
func verifyFeed(gzPath string, meta Meta) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", gzPath, err)
	}
	defer gz.Close()
	h := sha256.New()
	n, err := io.Copy(h, gz)
	if err != nil {
		return fmt.Errorf("%s: %w", gzPath, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); n != meta.Size || got != meta.SHA256 {
		return fmt.Errorf("%s: checksum/size mismatch with .meta (got %d bytes sha256 %s, want %d %s)",
			gzPath, n, got, meta.Size, meta.SHA256)
	}
	return nil
}

// FeedNames returns the yearly feed names (2002..year) plus "modified".
func FeedNames(year int) []string {
	var names []string
	for y := firstFeedYear; y <= year; y++ {
		names = append(names, strconv.Itoa(y))
	}
	return append(names, "modified")
}

// SyncNVD brings cached NVD feeds up to date, re-downloading a feed only when
// its published .meta sha256 differs from the cached copy.
func (f *Fetcher) SyncNVD(cache string, names []string) ([]Feed, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	var feeds []Feed
	for _, name := range names {
		base := "nvdcve-2.0-" + name
		metaPath := cache + "/" + base + ".meta"
		gzPath := cache + "/" + base + ".json.gz"
		freshMeta := metaPath + ".new"
		if err := f.download(f.FeedBase+base+".meta", freshMeta); err != nil {
			return nil, err
		}
		freshText, _ := os.ReadFile(freshMeta)
		fresh, err := ParseMeta(string(freshText))
		if err != nil {
			os.Remove(freshMeta)
			return nil, err
		}
		cached := Meta{}
		if t, err := os.ReadFile(metaPath); err == nil {
			cached, _ = ParseMeta(string(t))
		}
		if cached.SHA256 == fresh.SHA256 && fileExists(gzPath) {
			os.Remove(freshMeta)
			f.Log("  %s: unchanged", base)
		} else {
			f.Log("  %s: downloading", base)
			if err := f.download(f.FeedBase+base+".json.gz", gzPath); err != nil {
				os.Remove(freshMeta)
				return nil, err
			}
			if err := verifyFeed(gzPath, fresh); err != nil {
				os.Remove(gzPath)
				os.Remove(freshMeta)
				return nil, err
			}
			os.Rename(freshMeta, metaPath)
		}
		feeds = append(feeds, Feed{Name: name, GzPath: gzPath, LastModified: fresh.LastModified})
	}
	return feeds, nil
}

// SyncKEV downloads the KEV catalogue (CISA publishes no checksum; the loader
// validates its structure).
func (f *Fetcher) SyncKEV(cache string) (string, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return "", err
	}
	dest := cache + "/" + kevFile
	f.Log("  %s: downloading", kevFile)
	if err := f.download(f.KEVURL, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// LocalFeeds uses already-downloaded feeds, verifying each against its .meta
// exactly as after a download (ported from local_feeds).
func LocalFeeds(dir string) ([]Feed, error) {
	metas, _ := filepath.Glob(filepath.Join(dir, "nvdcve-2.0-*.meta"))
	var feeds []Feed
	for _, metaPath := range metas {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(metaPath), "nvdcve-2.0-"), ".meta")
		gzPath := dir + "/nvdcve-2.0-" + base + ".json.gz"
		if !fileExists(gzPath) {
			return nil, fmt.Errorf("%s has no matching %s", metaPath, gzPath)
		}
		t, err := os.ReadFile(metaPath)
		if err != nil {
			return nil, err
		}
		meta, err := ParseMeta(string(t))
		if err != nil {
			return nil, err
		}
		if err := verifyFeed(gzPath, meta); err != nil {
			return nil, err
		}
		feeds = append(feeds, Feed{Name: base, GzPath: gzPath, LastModified: meta.LastModified})
	}
	return feeds, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

const osvBase = "https://osv-vulnerabilities.storage.googleapis.com/"

// SyncOSV brings a cached OSV ecosystem export up to date, re-downloading only
// when the bucket's published MD5 (x-goog-hash) changes, and verifying every
// download against it. Returns the local zip path.
func (f *Fetcher) SyncOSV(cache, ecosystem string) (string, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return "", err
	}
	base := f.osvBase()
	rawURL := base + url.PathEscape(ecosystem) + "/all.zip"
	zipPath := filepath.Join(cache, "osv-"+ecosystem+"-all.zip")
	metaPath := filepath.Join(cache, "osv-"+ecosystem+"-all.meta.json")

	md5b64, err := f.osvMD5(rawURL)
	if err != nil {
		return "", err
	}
	if md5b64 == "" {
		return "", fmt.Errorf("%s: no MD5 published; refusing unverifiable download", rawURL)
	}
	var cached struct {
		MD5 string `json:"md5"`
	}
	if t, err := os.ReadFile(metaPath); err == nil {
		_ = jsonUnmarshal(t, &cached)
	}
	if cached.MD5 == md5b64 && fileExists(zipPath) {
		f.Log("  OSV %s: unchanged", ecosystem)
		return zipPath, nil
	}
	f.Log("  OSV %s: downloading", ecosystem)
	if err := f.download(rawURL, zipPath); err != nil {
		return "", err
	}
	got, err := md5Base64(zipPath)
	if err != nil {
		return "", err
	}
	if got != md5b64 {
		os.Remove(zipPath)
		return "", fmt.Errorf("%s: MD5 mismatch with published x-goog-hash", rawURL)
	}
	os.WriteFile(metaPath, []byte(`{"md5":`+jsonString(md5b64)+`}`), 0o644)
	return zipPath, nil
}

func (f *Fetcher) osvBase() string {
	if f.OSVBase != "" {
		return f.OSVBase
	}
	return osvBase
}

// osvMD5 issues a HEAD and returns the base64 MD5 from the x-goog-hash header.
func (f *Fetcher) osvMD5(raw string) (string, error) {
	if err := f.checkURL(raw); err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodHead, raw, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	resp, err := f.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := f.checkURL(resp.Request.URL.String()); err != nil {
		return "", err
	}
	for _, h := range resp.Header.Values("x-goog-hash") {
		for _, part := range strings.Split(h, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "md5=") {
				return part[len("md5="):], nil
			}
		}
	}
	return "", nil
}

// LocalOSV returns the cached export zip for an ecosystem, or "" if absent.
func LocalOSV(dir, ecosystem string) string {
	p := filepath.Join(dir, "osv-"+ecosystem+"-all.zip")
	if fileExists(p) {
		return p
	}
	return ""
}

func md5Base64(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func jsonString(s string) string {
	b, _ := jsonMarshal(s)
	return string(b)
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
