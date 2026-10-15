// Package release downloads a prebuilt database bundle published to the
// project's GitHub releases, so most users can update straight from GitHub
// instead of rebuilding the database from upstream sources themselves.
//
// The database is rebuilt daily by CI and published as the single rolling
// release tagged "db-latest"; DefaultBundleURL points at its bundle asset.
// Download only fetches the bundle to a local file — integrity (SHA-256),
// schema compatibility and rollback protection are enforced afterwards by
// internal/bundle on import.
package release

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// DefaultBundleURL is the stable download URL for the latest prebuilt database
// bundle. GitHub serves the asset with a redirect to its object store; the
// client follows it (both hops are HTTPS).
const DefaultBundleURL = "https://github.com/joda32/bunyip/releases/download/db-latest/bunyip-db.tar.gz"

const (
	maxBundleBytes        = 4 << 30 // generous cap for a gzip-compressed DB bundle
	dialStallTimeout      = 90 * time.Second
	tlsHandshakeTimeout   = 30 * time.Second
	responseHeaderTimeout = 60 * time.Second
)

// Download fetches a bundle from an HTTPS url to destPath, writing atomically
// (via destPath+".part") and bounding progress with a stall watchdog: the
// attempt is aborted only when no bytes arrive for 90s, so a slow-but-steady
// download of a few hundred megabytes runs to completion. Redirects are
// followed but must stay HTTPS. log, if non-nil, receives progress lines.
func Download(ctx context.Context, raw, destPath string, log func(string, ...any)) error {
	return download(ctx, newClient(), raw, destPath, log)
}

// newClient builds the HTTPS client Download uses: connection-phase timeouts
// bound a dead connection without capping a large, slow-but-steady body read,
// and every redirect hop (including GitHub's to its object store) must be HTTPS.
func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return requireHTTPS(req.URL.String())
		},
	}
}

// download is Download with an injectable client (tests supply one that trusts
// a local TLS test server).
func download(ctx context.Context, client *http.Client, raw, destPath string, log func(string, ...any)) error {
	if log == nil {
		log = func(string, ...any) {}
	}
	if err := requireHTTPS(raw); err != nil {
		return err
	}

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("no database bundle found at %s (HTTP 404) — has the daily build published one yet?", raw)
		}
		return fmt.Errorf("fetching %s: HTTP %d", raw, resp.StatusCode)
	}

	part := destPath + ".part"
	out, err := os.Create(part)
	if err != nil {
		return err
	}
	defer func() { out.Close(); os.Remove(part) }() // Remove is a no-op once renamed

	total := resp.ContentLength
	if total > 0 {
		log("Downloading %.0f MB from %s ...", float64(total)/1e6, raw)
	} else {
		log("Downloading %s ...", raw)
	}
	// Abort if no bytes arrive for dialStallTimeout; each read resets the timer.
	watchdog := time.AfterFunc(dialStallTimeout, cancel)
	defer watchdog.Stop()
	body := &progressReader{r: io.LimitReader(resp.Body, maxBundleBytes+1), onRead: func() { watchdog.Reset(dialStallTimeout) }}
	n, err := io.Copy(out, body)
	if err != nil {
		if reqCtx.Err() != nil && ctx.Err() == nil {
			return fmt.Errorf("download stalled: no data for %s", dialStallTimeout)
		}
		return err
	}
	if n > maxBundleBytes {
		return fmt.Errorf("%s: bundle exceeds %d bytes", raw, maxBundleBytes)
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(part, destPath)
}

// requireHTTPS rejects anything that is not a well-formed HTTPS URL.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad url %q: %w", raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("refusing to fetch %q: only HTTPS URLs are allowed", raw)
	}
	return nil
}

// progressReader feeds the stall watchdog so an idle (not merely slow)
// download is aborted while a steady one runs to completion.
type progressReader struct {
	r      io.Reader
	onRead func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.onRead()
	}
	return n, err
}
