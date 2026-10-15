package release

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bunyip/internal/bundle"
	"bunyip/internal/database"

	_ "modernc.org/sqlite"
)

var ctx = context.Background()

func TestDownloadRejectsNonHTTPS(t *testing.T) {
	for _, u := range []string{"http://example.test/x", "ftp://example.test/x", "not a url"} {
		if err := Download(ctx, u, filepath.Join(t.TempDir(), "x"), nil); err == nil {
			t.Errorf("Download(%q) = nil, want error", u)
		}
	}
}

func TestDownloadSuccess(t *testing.T) {
	const payload = "a tiny bundle's worth of bytes"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := download(ctx, srv.Client(), srv.URL, dest, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Errorf("got %q, want %q", got, payload)
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Errorf(".part file left behind")
	}
}

func TestDownloadFollowsHTTPSRedirect(t *testing.T) {
	const payload = "redirected payload"
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(payload)) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/final", http.StatusFound)
	})

	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := download(ctx, srv.Client(), srv.URL+"/start", dest, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != payload {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestDownload404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	err := download(ctx, srv.Client(), srv.URL, filepath.Join(t.TempDir(), "x"), nil)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want a 404 error, got %v", err)
	}
}

// TestPullRoundTrip serves a real bundle over HTTPS, downloads it, and imports
// it — the whole pull pathway minus the CLI wiring.
func TestPullRoundTrip(t *testing.T) {
	dir := t.TempDir()
	bundlePath := makeBundle(t, dir)
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	tmp := filepath.Join(dir, "incoming.tar.gz")
	if err := download(ctx, srv.Client(), srv.URL+"/bunyip-db.tar.gz", tmp, nil); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "bunyip.sqlite")
	res, err := bundle.Import(ctx, tmp, target, bundle.Options{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("fresh install reported as skipped")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("database not installed: %v", err)
	}
}

// makeBundle builds a database from the synthetic fixture and packages it as an
// unsigned bundle, returning the bundle path.
func makeBundle(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "src.sqlite")
	s, err := database.Create(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := database.LoadFixture("../../testdata/fixtures/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportFixture(ctx, f); err != nil {
		t.Fatal(err)
	}
	s.Close()
	out := filepath.Join(dir, "bundle.tar.gz")
	if _, err := bundle.Create(ctx, dbPath, out, nil); err != nil {
		t.Fatal(err)
	}
	return out
}
