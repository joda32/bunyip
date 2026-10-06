// Package database provides explicit, parameterised access to the Offline
// VulnDB SQLite database. No ORM: every query is visible in this package.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"offline-vulndb/schema"

	_ "modernc.org/sqlite" // pure-Go SQLite driver ("sqlite")
)

// SchemaVersion is the schema version this build understands.
const SchemaVersion = "2"

// Sentinel errors so the CLI can report failures clearly.
var (
	ErrMissing      = errors.New("database not found")
	ErrIncompatible = errors.New("database schema incompatible")
	ErrCorrupt      = errors.New("database unreadable or corrupt")
	ErrExists       = errors.New("database already exists")
)

// Store is an open Offline VulnDB database.
type Store struct {
	db   *sql.DB
	Path string
}

// Open opens an existing database read-only and checks schema compatibility.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := checkFile(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path, "ro"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}
	s := &Store{db: db, Path: path}
	if err := s.checkSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Create creates a new database at path containing the empty schema and
// base metadata. It refuses to overwrite an existing file.
func Create(ctx context.Context, path string) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, path)
	}
	db, err := sql.Open("sqlite", dsn(path, "rwc"))
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, Path: path}
	if err := s.initSchema(ctx); err != nil {
		db.Close()
		os.Remove(path)
		return nil, fmt.Errorf("initialising schema: %w", err)
	}
	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schema.SQL); err != nil {
		return err
	}
	// schema_version comes from schema.sql itself; checkSchema validates it.
	meta := map[string]string{
		"database_version": "0",
		"created_at":       time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range meta {
		if err := setMetadata(ctx, tx, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func checkFile(path string) error {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s (use --db or VULNDB_DB, or create one with 'vulndb db init')", ErrMissing, path)
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMissing, path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s is a directory", ErrMissing, path)
	}
	return nil
}

// dsn builds a SQLite URI filename. Characters with meaning in URIs are
// percent-encoded so arbitrary paths are safe.
func dsn(path, mode string) string {
	r := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")
	return "file:" + r.Replace(path) + "?mode=" + mode + "&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// checkSchema verifies the file is an Offline VulnDB database whose schema
// version this build supports.
func (s *Store) checkSchema(ctx context.Context) error {
	var v string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM database_metadata WHERE key = 'schema_version'`).Scan(&v)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: %s has no schema_version metadata", ErrIncompatible, s.Path)
	case isNotADatabase(err):
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, s.Path, err)
	case strings.Contains(err.Error(), "no such table"):
		return fmt.Errorf("%w: %s is not an Offline VulnDB database (no database_metadata table)", ErrIncompatible, s.Path)
	default:
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, s.Path, err)
	}
	if v != SchemaVersion {
		return fmt.Errorf("%w: %s has schema version %q, this build requires %q", ErrIncompatible, s.Path, v, SchemaVersion)
	}
	return nil
}

func isNotADatabase(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "file is not a database") ||
		strings.Contains(msg, "database disk image is malformed")
}

// Metadata returns all database_metadata entries.
func (s *Store) Metadata(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM database_metadata`)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, wrapQueryErr(rows.Err())
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func setMetadata(ctx context.Context, e execer, key, value string) error {
	_, err := e.ExecContext(ctx,
		`INSERT INTO database_metadata (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// wrapQueryErr marks corruption errors encountered mid-query.
func wrapQueryErr(err error) error {
	if err != nil && isNotADatabase(err) {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return err
}
