package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bunyip/internal/database"

	_ "modernc.org/sqlite"
)

var ctx = context.Background()

// fixtureDB builds a database from the synthetic fixture; createdAt lets
// tests produce "older" and "newer" databases.
func fixtureDB(t *testing.T, dir, name, createdAt string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	s, err := database.Create(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := database.LoadFixture("../../testdata/fixtures/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Metadata["database_version"] = createdAt
	if err := s.ImportFixture(ctx, f); err != nil {
		t.Fatal(err)
	}
	s.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE database_metadata SET value = ? WHERE key = 'created_at'`, createdAt); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return path
}

func keys(t *testing.T, dir string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv, pub := filepath.Join(dir, "k.key"), filepath.Join(dir, "k.pub")
	if _, err := GenerateKeys(priv, pub); err != nil {
		t.Fatal(err)
	}
	sk, err := LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sk, pk := keys(t, dir)
	db := fixtureDB(t, dir, "src.sqlite", "2026-10-01T00:00:00Z")
	out := filepath.Join(dir, "b.tar.gz")
	m, err := Create(ctx, db, out, sk)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Signed || m.KeyID != KeyID(pk) || m.Database.Metadata["schema_version"] != database.SchemaVersion {
		t.Fatalf("manifest: %+v", m)
	}

	v, err := Verify(out, Options{PublicKey: pk})
	if err != nil || v.KeyID != KeyID(pk) || v.Database.SHA256 != m.Database.SHA256 {
		t.Fatalf("verify: %+v %v", v, err)
	}

	target := filepath.Join(dir, "installed", "bunyip.sqlite")
	os.Mkdir(filepath.Dir(target), 0o755)
	res, err := Import(ctx, out, target, Options{PublicKey: pk})
	if err != nil || res.Previous != "" {
		t.Fatalf("import: %+v %v", res, err)
	}
	if _, sum, _ := fileSHA256(target); sum != m.Database.SHA256 {
		t.Error("installed database differs")
	}
	// Same version again: nothing to do.
	if res, err := Import(ctx, out, target, Options{PublicKey: pk}); err != nil || !res.Skipped {
		t.Errorf("re-import: %+v %v", res, err)
	}

	// A newer database replaces it; the old one is kept as .previous.
	newer := fixtureDB(t, dir, "newer.sqlite", "2026-10-07T00:00:00Z")
	out2 := filepath.Join(dir, "b2.tar.gz")
	if _, err := Create(ctx, newer, out2, sk); err != nil {
		t.Fatal(err)
	}
	res, err = Import(ctx, out2, target, Options{PublicKey: pk})
	if err != nil || res.Previous != target+".previous" {
		t.Fatalf("upgrade: %+v %v", res, err)
	}
	if _, sum, _ := fileSHA256(target + ".previous"); sum != m.Database.SHA256 {
		t.Error(".previous is not the replaced database")
	}

	// Rollback to the older bundle is refused unless explicitly allowed.
	if _, err := Import(ctx, out, target, Options{PublicKey: pk}); !errors.Is(err, ErrRollback) {
		t.Errorf("rollback: %v", err)
	}
	if _, err := Import(ctx, out, target, Options{PublicKey: pk, AllowDowngrade: true}); err != nil {
		t.Errorf("allowed downgrade: %v", err)
	}
	assertNoTemp(t, filepath.Dir(target))
}

func TestSignatureChecks(t *testing.T) {
	dir := t.TempDir()
	sk, pk := keys(t, dir)
	_, otherPK := keys(t, t.TempDir())
	db := fixtureDB(t, dir, "src.sqlite", "2026-10-01T00:00:00Z")
	signed, unsigned := filepath.Join(dir, "s.tar.gz"), filepath.Join(dir, "u.tar.gz")
	if _, err := Create(ctx, db, signed, sk); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, db, unsigned, nil); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		opts Options
		ok   bool
	}{
		"wrong key":                  {signed, Options{PublicKey: otherPK}, false},
		"signed, no key given":       {signed, Options{}, false},
		"signed, no key, allowed":    {signed, Options{AllowUnsigned: true}, true},
		"unsigned":                   {unsigned, Options{PublicKey: pk}, false},
		"unsigned, allowed":          {unsigned, Options{AllowUnsigned: true}, true},
		"unsigned, allowed with key": {unsigned, Options{PublicKey: pk, AllowUnsigned: true}, true},
	} {
		_, err := Verify(tc.path, tc.opts)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v", name, err)
		}
		if !tc.ok && !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
}

// member is one tar entry for hand-built (malicious/broken) bundles.
type member struct {
	name     string
	data     []byte
	typeflag byte
	size     int64 // header size override (-1: len(data))
}

func writeBundle(t *testing.T, path string, ms []member) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.data)), Typeflag: m.typeflag, ModTime: time.Now()}
		if m.typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if m.typeflag == tar.TypeSymlink {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write(m.data)
		}
	}
	tw.Close()
	gz.Close()
	os.WriteFile(path, buf.Bytes(), 0o600)
}

func TestMaliciousAndBrokenBundles(t *testing.T) {
	dir := t.TempDir()
	sk, pk := keys(t, dir)
	db := fixtureDB(t, dir, "src.sqlite", "2026-10-01T00:00:00Z")
	good := filepath.Join(dir, "good.tar.gz")
	m, err := Create(ctx, db, good, sk)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.MarshalIndent(m, "", "  ")
	sig := ed25519.Sign(sk, manifest)
	dbBytes, _ := os.ReadFile(db)
	tampered := append([]byte{}, dbBytes...)
	tampered[len(tampered)/2] ^= 0xff
	// A manifest re-signed by the attacker's own key.
	evilSK, _ := keys(t, t.TempDir())
	evilSig := ed25519.Sign(evilSK, manifest)
	// A manifest edited after signing.
	edited := bytes.Replace(manifest, []byte(m.Database.SHA256), []byte(strings.Repeat("0", 64)), 1)

	cases := map[string][]member{
		"tampered database":       {{name: manifestName, data: manifest}, {name: sigName, data: sig}, {name: dbName, data: tampered}},
		"attacker signature":      {{name: manifestName, data: manifest}, {name: sigName, data: evilSig}, {name: dbName, data: dbBytes}},
		"manifest edited":         {{name: manifestName, data: edited}, {name: sigName, data: sig}, {name: dbName, data: dbBytes}},
		"database first":          {{name: dbName, data: dbBytes}, {name: manifestName, data: manifest}, {name: sigName, data: sig}},
		"path traversal":          {{name: manifestName, data: manifest}, {name: sigName, data: sig}, {name: "../bunyip.sqlite", data: dbBytes}},
		"symlink member":          {{name: manifestName, data: manifest}, {name: sigName, data: sig}, {name: dbName, typeflag: tar.TypeSymlink}},
		"extra member after db":   {{name: manifestName, data: manifest}, {name: sigName, data: sig}, {name: dbName, data: dbBytes}, {name: "x.sh", data: []byte("x")}},
		"missing database":        {{name: manifestName, data: manifest}, {name: sigName, data: sig}},
		"truncated database":      {{name: manifestName, data: manifest}, {name: sigName, data: sig}, {name: dbName, data: dbBytes[:len(dbBytes)/2]}},
		"not json manifest":       {{name: manifestName, data: []byte("<xml/>")}, {name: sigName, data: sig}, {name: dbName, data: dbBytes}},
		"unknown manifest fields": {{name: manifestName, data: []byte(`{"format":"bunyip-bundle","format_version":1,"x":1}`)}},
	}
	target := filepath.Join(dir, "installed", "bunyip.sqlite")
	os.Mkdir(filepath.Dir(target), 0o755)
	if _, err := Import(ctx, good, target, Options{PublicKey: pk}); err != nil {
		t.Fatal(err)
	}
	_, before, _ := fileSHA256(target)
	for name, ms := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".tar.gz")
		writeBundle(t, path, ms)
		if _, err := Verify(path, Options{PublicKey: pk}); err == nil {
			t.Errorf("%s: verified", name)
		}
		if _, err := Import(ctx, path, target, Options{PublicKey: pk, AllowDowngrade: true}); err == nil {
			t.Errorf("%s: imported", name)
		}
		if _, after, _ := fileSHA256(target); after != before {
			t.Fatalf("%s: installed database was modified", name)
		}
	}
	os.WriteFile(filepath.Join(dir, "garbage.tar.gz"), []byte("not gzip"), 0o600)
	if _, err := Verify(filepath.Join(dir, "garbage.tar.gz"), Options{PublicKey: pk}); !errors.Is(err, ErrInvalid) {
		t.Errorf("garbage: %v", err)
	}
	assertNoTemp(t, filepath.Dir(target))
	if _, err := os.Stat(filepath.Join(dir, "bunyip.sqlite")); err == nil {
		t.Error("path traversal wrote outside the target directory")
	}
}

func TestKeys(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.key"), filepath.Join(dir, "k.pub")
	if _, err := GenerateKeys(priv, pub); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(priv); fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v", fi.Mode().Perm())
	}
	if _, err := GenerateKeys(priv, pub); err == nil {
		t.Error("existing keys overwritten")
	}
	if _, err := LoadPublicKey(priv); err == nil {
		t.Error("private key accepted as public key")
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".importing-") {
			t.Errorf("leftover temporary file %s", e.Name())
		}
	}
}
