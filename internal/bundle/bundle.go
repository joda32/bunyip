// Package bundle packages a built database for transport into a restricted
// network and installs it there.
//
// A bundle is a gzip-compressed tar archive with exactly these members, in
// this order:
//
//	manifest.json   what the bundle contains (database size, SHA-256, metadata)
//	manifest.sig    Ed25519 signature over the exact manifest.json bytes (optional)
//	vulndb.sqlite   the database
//
// Import checks, before anything replaces the installed database: archive
// layout and member types, the signature (before the database is even
// extracted), the database's size and SHA-256 while it streams to a
// temporary file, schema compatibility and SQLite's quick_check, and that the
// bundle is not older than the installed database (rollback protection).
// The previous database is kept as <db>.previous.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"offline-vulndb/internal/database"
)

const (
	Format        = "offline-vulndb-bundle"
	FormatVersion = 1

	manifestName = "manifest.json"
	sigName      = "manifest.sig"
	dbName       = "vulndb.sqlite"

	maxManifestBytes = 1 << 20
	maxDatabaseBytes = 16 << 30
)

// Errors callers may want to distinguish.
var (
	ErrInvalid   = errors.New("invalid bundle")
	ErrSignature = errors.New("bundle signature")
	ErrRollback  = errors.New("bundle is older than the installed database")
)

// Manifest describes a bundle's content.
type Manifest struct {
	Format        string        `json:"format"`
	FormatVersion int           `json:"format_version"`
	CreatedAt     string        `json:"created_at"`
	Database      DatabaseEntry `json:"database"`
	Signed        bool          `json:"-"` // set when read: a signature was present
	KeyID         string        `json:"-"` // set when read: key that verified it
}

// DatabaseEntry is the database file inside a bundle.
type DatabaseEntry struct {
	File     string            `json:"file"`
	Size     int64             `json:"size"`
	SHA256   string            `json:"sha256"`
	Metadata map[string]string `json:"metadata"` // copy of database_metadata
}

// --- keys ---------------------------------------------------------------

// GenerateKeys writes a new Ed25519 key pair as PEM (PKCS#8 private key with
// mode 0600, PKIX public key). Existing files are not overwritten.
func GenerateKeys(privPath, pubPath string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	if err := writeNew(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return "", err
	}
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		os.Remove(privPath)
		return "", err
	}
	return KeyID(pub), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// KeyID is a short fingerprint of a public key for display.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// LoadPrivateKey reads a PEM PKCS#8 Ed25519 private key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 private key", path)
	}
	return priv, nil
}

// LoadPublicKey reads a PEM PKIX Ed25519 public key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 public key", path)
	}
	return pub, nil
}

func readPEM(path, typ string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("%s: no PEM %q block", path, typ)
	}
	return block.Bytes, nil
}

// --- create -------------------------------------------------------------

// Create writes a bundle of the database at dbPath to outPath, signing the
// manifest when key is not nil. The output is written to a temporary file
// and renamed into place.
func Create(ctx context.Context, dbPath, outPath string, key ed25519.PrivateKey) (*Manifest, error) {
	store, err := database.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	meta, err := store.Metadata(ctx)
	if err == nil {
		err = store.QuickCheck(ctx)
	}
	store.Close()
	if err != nil {
		return nil, err
	}
	size, sum, err := fileSHA256(dbPath)
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		Format: Format, FormatVersion: FormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Database:  DatabaseEntry{File: dbName, Size: size, SHA256: sum, Metadata: meta},
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}

	tmp := outPath + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Manifest, error) {
		out.Close()
		os.Remove(tmp)
		return nil, err
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	if err := addBytes(tw, manifestName, manifest); err != nil {
		return fail(err)
	}
	if key != nil {
		if err := addBytes(tw, sigName, ed25519.Sign(key, manifest)); err != nil {
			return fail(err)
		}
		m.Signed, m.KeyID = true, KeyID(key.Public().(ed25519.PublicKey))
	}
	db, err := os.Open(dbPath)
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	if err := tw.WriteHeader(&tar.Header{Name: dbName, Mode: 0o644, Size: size, ModTime: time.Now(),
		Typeflag: tar.TypeReg}); err != nil {
		return fail(err)
	}
	if _, err := io.CopyN(tw, db, size); err != nil {
		return fail(fmt.Errorf("database changed while bundling: %w", err))
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	// The database must not have changed while it was being copied.
	if _, again, err := fileSHA256(dbPath); err != nil || again != sum {
		os.Remove(tmp)
		return nil, fmt.Errorf("database changed while bundling")
	}
	if err := os.Rename(tmp, outPath); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return m, nil
}

func addBytes(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Now(),
		Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func fileSHA256(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// --- read / verify ------------------------------------------------------

// Options controls verification.
type Options struct {
	PublicKey      ed25519.PublicKey // required unless AllowUnsigned
	AllowUnsigned  bool              // accept bundles without (or without checking) a signature
	AllowDowngrade bool              // install a bundle older than the installed database
}

// reader walks a bundle's members in the required order.
type reader struct {
	tr *tar.Reader
}

func open(path string) (*reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%w: not gzip: %v", ErrInvalid, err)
	}
	return &reader{tr: tar.NewReader(gz)}, func() { gz.Close(); f.Close() }, nil
}

// next returns the next member, which must be a regular file with one of the
// expected names.
func (r *reader) next(names ...string) (*tar.Header, error) {
	h, err := r.tr.Next()
	if err == io.EOF {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalid, names[0])
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if h.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%w: member %q is not a regular file", ErrInvalid, h.Name)
	}
	for _, n := range names {
		if h.Name == n {
			return h, nil
		}
	}
	return nil, fmt.Errorf("%w: unexpected member %q (want %v)", ErrInvalid, h.Name, names)
}

// readHead reads and authenticates manifest.json (and manifest.sig) and
// returns the manifest plus the database member header.
func (r *reader) readHead(opts Options) (*Manifest, *tar.Header, error) {
	h, err := r.next(manifestName)
	if err != nil {
		return nil, nil, err
	}
	if h.Size > maxManifestBytes {
		return nil, nil, fmt.Errorf("%w: manifest too large", ErrInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(r.tr, maxManifestBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("%w: manifest: %v", ErrInvalid, err)
	}
	if m.Format != Format || m.FormatVersion != FormatVersion {
		return nil, nil, fmt.Errorf("%w: unsupported format %q version %d", ErrInvalid, m.Format, m.FormatVersion)
	}
	if m.Database.File != dbName || m.Database.Size <= 0 || m.Database.Size > maxDatabaseBytes || len(m.Database.SHA256) != 64 {
		return nil, nil, fmt.Errorf("%w: manifest database entry is invalid", ErrInvalid)
	}

	h, err = r.next(sigName, dbName)
	if err != nil {
		return nil, nil, err
	}
	if h.Name == sigName {
		if h.Size != ed25519.SignatureSize {
			return nil, nil, fmt.Errorf("%w: malformed signature", ErrSignature)
		}
		sig, err := io.ReadAll(io.LimitReader(r.tr, ed25519.SignatureSize))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		m.Signed = true
		if opts.PublicKey != nil {
			if !ed25519.Verify(opts.PublicKey, raw, sig) {
				return nil, nil, fmt.Errorf("%w: does not verify with key %s", ErrSignature, KeyID(opts.PublicKey))
			}
			m.KeyID = KeyID(opts.PublicKey)
		}
		if h, err = r.next(dbName); err != nil {
			return nil, nil, err
		}
	}
	switch {
	case m.Signed && m.KeyID != "":
	case opts.AllowUnsigned:
	case !m.Signed:
		return nil, nil, fmt.Errorf("%w: bundle is not signed (use --allow-unsigned to accept it)", ErrSignature)
	default:
		return nil, nil, fmt.Errorf("%w: a public key is required to verify it", ErrSignature)
	}
	if h.Size != m.Database.Size {
		return nil, nil, fmt.Errorf("%w: database member size %d does not match manifest %d", ErrInvalid, h.Size, m.Database.Size)
	}
	return &m, h, nil
}

// copyDatabase streams the database member to w, checking size and SHA-256,
// and requires it to be the archive's last member.
func (r *reader) copyDatabase(w io.Writer, m *Manifest) error {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(r.tr, m.Database.Size))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if n != m.Database.Size || hex.EncodeToString(h.Sum(nil)) != m.Database.SHA256 {
		return fmt.Errorf("%w: database SHA-256 or size does not match the manifest", ErrInvalid)
	}
	if _, err := r.tr.Next(); err != io.EOF {
		return fmt.Errorf("%w: unexpected data after the database", ErrInvalid)
	}
	return nil
}

// Verify checks a bundle completely without installing it.
func Verify(path string, opts Options) (*Manifest, error) {
	r, closeFn, err := open(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	m, _, err := r.readHead(opts)
	if err != nil {
		return nil, err
	}
	return m, r.copyDatabase(io.Discard, m)
}

// --- import -------------------------------------------------------------

// Result describes an installation.
type Result struct {
	Manifest *Manifest
	Previous string // path the replaced database was moved to ("" if none)
	Skipped  bool   // the same database version was already installed
}

// Import verifies a bundle and atomically installs its database at target.
func Import(ctx context.Context, path, target string, opts Options) (*Result, error) {
	r, closeFn, err := open(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	m, _, err := r.readHead(opts)
	if err != nil {
		return nil, err
	}

	current, err := installedMetadata(ctx, target)
	if err != nil {
		return nil, err
	}
	if current != nil {
		if current["database_version"] == m.Database.Metadata["database_version"] &&
			current["created_at"] == m.Database.Metadata["created_at"] {
			// Nothing to install, but still verify the whole bundle: a
			// tampered bundle must never be reported as fine.
			if err := r.copyDatabase(io.Discard, m); err != nil {
				return nil, err
			}
			return &Result{Manifest: m, Skipped: true}, nil
		}
		if older(m.Database.Metadata["created_at"], current["created_at"]) && !opts.AllowDowngrade {
			return nil, fmt.Errorf("%w: bundle database created %s, installed %s (use --allow-downgrade)",
				ErrRollback, m.Database.Metadata["created_at"], current["created_at"])
		}
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".importing-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	fail := func(err error) (*Result, error) {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, err
	}
	if err := r.copyDatabase(tmp, m); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := checkInstalled(ctx, tmpPath, m); err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	res := &Result{Manifest: m}
	if current != nil {
		res.Previous = target + ".previous"
		if err := os.Rename(target, res.Previous); err != nil {
			os.Remove(tmpPath)
			return nil, err
		}
	}
	if err := os.Rename(tmpPath, target); err != nil {
		if res.Previous != "" {
			os.Rename(res.Previous, target) // put the old database back
		}
		os.Remove(tmpPath)
		return nil, err
	}
	syncDir(dir)
	return res, nil
}

// checkInstalled opens the extracted database as the query engine would.
func checkInstalled(ctx context.Context, path string, m *Manifest) error {
	store, err := database.Open(ctx, path)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.QuickCheck(ctx); err != nil {
		return err
	}
	meta, err := store.Metadata(ctx)
	if err != nil {
		return err
	}
	for _, k := range []string{"schema_version", "database_version", "created_at"} {
		if meta[k] != m.Database.Metadata[k] {
			return fmt.Errorf("%w: database %s %q does not match manifest %q", ErrInvalid, k, meta[k], m.Database.Metadata[k])
		}
	}
	return nil
}

// installedMetadata returns the installed database's metadata, nil if there
// is none. An unreadable or incompatible installed database does not block a
// fresh install.
func installedMetadata(ctx context.Context, target string) (map[string]string, error) {
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	store, err := database.Open(ctx, target)
	if err != nil {
		return map[string]string{}, nil
	}
	defer store.Close()
	m, err := store.Metadata(ctx)
	if err != nil {
		return map[string]string{}, nil
	}
	return m, nil
}

func older(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	return errA == nil && errB == nil && ta.Before(tb)
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
