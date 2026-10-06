// Command vulndb is the Offline VulnDB query CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"offline-vulndb/internal/database"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/output"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1 // runtime failure (missing DB, malformed CPE, failed verify, ...)
	exitUsage = 2 // bad command line
)

// Data age after which `info` warns. Real source data is judged by the NVD
// feed timestamp; databases without one (e.g. fixtures) by creation time.
const (
	staleAfterSource  = 7 * 24 * time.Hour
	staleAfterCreated = 30 * 24 * time.Hour
)

const usage = `Offline VulnDB - offline CPE to candidate CVE correlation

Usage:
  vulndb [--db PATH] [--debug] <command> [options]

Commands:
  query --cpe CPE [--format text|json]   find candidate CVEs for a CPE (2.2 or 2.3)
  info                                   show database provenance and age
  db init [--fixture FILE] [--force]     create a new database (optionally loading a fixture)
  db verify                              check database integrity and consistency
  db stats                               show table row counts

Global options (may also follow the command):
  --db PATH   database file (default $VULNDB_DB, else ./vulndb.sqlite)
  --debug     explain matching decisions on stderr

Results are CANDIDATE vulnerabilities based on product/version data; they do
not prove a target is vulnerable. Distro backported fixes are not evaluated.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// globals holds options accepted both before and after the command name.
type globals struct {
	db    string
	debug bool
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.db, "db", g.db, "database file")
	fs.BoolVar(&g.debug, "debug", g.debug, "explain matching decisions")
}

// usageError marks errors that should print usage and exit 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(args []string, stdout, stderr io.Writer) int {
	g := &globals{db: defaultDBPath()}
	fs := newFlagSet("vulndb", stderr)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	ctx := context.Background()
	var err error
	switch rest[0] {
	case "query":
		err = cmdQuery(ctx, g, rest[1:], stdout, stderr)
	case "info":
		err = cmdInfo(ctx, g, rest[1:], stdout, stderr)
	case "db":
		err = cmdDB(ctx, g, rest[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		err = usageError{fmt.Sprintf("unknown command %q", rest[0])}
	}

	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "vulndb: %v\n\n%s", err, usage)
		return exitUsage
	case errors.Is(err, flag.ErrHelp):
		return exitUsage
	default:
		fmt.Fprintf(stderr, "vulndb: %v\n", err)
		return exitError
	}
}

func defaultDBPath() string {
	if p := os.Getenv("VULNDB_DB"); p != "" {
		return p
	}
	return "vulndb.sqlite"
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseSub parses subcommand flags and rejects stray positional arguments.
func parseSub(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Sprintf("%s: unexpected argument %q", fs.Name(), fs.Arg(0))}
	}
	return nil
}

func cmdQuery(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("query", stderr)
	g.register(fs)
	cpeArg := fs.String("cpe", "", "CPE 2.3 formatted string or CPE 2.2 URI")
	formatArg := fs.String("format", "text", "output format: text or json")
	if err := parseSub(fs, args); err != nil {
		return err
	}
	format, err := output.ParseFormat(*formatArg)
	if err != nil {
		return usageError{err.Error()}
	}
	if strings.TrimSpace(*cpeArg) == "" {
		return usageError{"query: --cpe is required"}
	}

	store, err := database.Open(ctx, g.db)
	if err != nil {
		return err
	}
	defer store.Close()

	start := time.Now()
	res, err := matcher.New(store).QueryCPE(ctx, *cpeArg)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	if g.debug {
		output.WriteDebug(stderr, res)
		fmt.Fprintf(stderr, "Query time: %s\n\n", elapsed.Round(time.Microsecond))
	}
	if format == output.JSON {
		info, err := databaseInfo(ctx, store)
		if err != nil {
			return err
		}
		return output.WriteJSON(stdout, res, info, g.debug)
	}
	return output.WriteText(stdout, res)
}

func databaseInfo(ctx context.Context, s *database.Store) (output.DatabaseInfo, error) {
	m, err := s.Metadata(ctx)
	if err != nil {
		return output.DatabaseInfo{}, err
	}
	return output.DatabaseInfo{
		Path:            s.Path,
		SchemaVersion:   m["schema_version"],
		DatabaseVersion: m["database_version"],
		CreatedAt:       m["created_at"],
		Dataset:         m["dataset"],
	}, nil
}

func cmdInfo(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("info", stderr)
	g.register(fs)
	if err := parseSub(fs, args); err != nil {
		return err
	}
	store, err := database.Open(ctx, g.db)
	if err != nil {
		return err
	}
	defer store.Close()
	m, err := store.Metadata(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Database:          %s\n", store.Path)
	fmt.Fprintf(stdout, "Schema version:    %s\n", m["schema_version"])
	fmt.Fprintf(stdout, "Database version:  %s\n", m["database_version"])
	fmt.Fprintf(stdout, "Created at:        %s\n", m["created_at"])
	reportAge(stdout, m)
	// Any other metadata (source timestamps, dataset, notices) in stable order.
	shown := map[string]bool{"schema_version": true, "database_version": true, "created_at": true,
		"nvd_last_modified": true}
	var keys []string
	for k := range m {
		if !shown[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(stdout, "%-18s %s\n", k+":", m[k])
	}
	if strings.Contains(m["dataset"], "synthetic") {
		fmt.Fprintln(stdout, "WARNING: this database contains SYNTHETIC test data, not real vulnerability information.")
	}
	return reportCoverage(ctx, store, stdout)
}

// reportAge prints how old the data is and warns when it is stale. The NVD
// feed timestamp is preferred because it reflects the data itself, not
// when the database file happened to be built.
func reportAge(w io.Writer, m map[string]string) {
	key, limit := "created_at", staleAfterCreated
	if m["nvd_last_modified"] != "" {
		key, limit = "nvd_last_modified", staleAfterSource
		fmt.Fprintf(w, "NVD data as of:    %s\n", m["nvd_last_modified"])
	}
	t, err := time.Parse(time.RFC3339, m[key])
	if err != nil {
		fmt.Fprintf(w, "WARNING: cannot parse %s %q; data age unknown.\n", key, m[key])
		return
	}
	age := time.Since(t)
	fmt.Fprintf(w, "Data age:          %d days\n", int(age.Hours()/24))
	if age > limit {
		fmt.Fprintf(w, "WARNING: data is older than %d days; vulnerability data may be stale.\n",
			int(limit.Hours()/24))
	}
}

// reportCoverage shows how many CVEs carry no applicability data and can
// therefore never be returned by a CPE query.
func reportCoverage(ctx context.Context, store *database.Store, w io.Writer) error {
	st, err := store.Stats(ctx)
	if err != nil {
		return err
	}
	var total int64
	for _, t := range st.Tables {
		if t.Table == "cves" {
			total = t.Rows
		}
	}
	if total == 0 {
		return nil
	}
	fmt.Fprintf(w, "CVEs without CPE applicability data: %d of %d (%.1f%%) - these can never match a query\n",
		st.CVEsWithoutConfigurations, total, 100*float64(st.CVEsWithoutConfigurations)/float64(total))
	return nil
}

func cmdDB(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"db: subcommand required (init, verify, stats)"}
	}
	switch args[0] {
	case "init":
		return cmdDBInit(ctx, g, args[1:], stdout, stderr)
	case "verify":
		return cmdDBVerify(ctx, g, args[1:], stdout, stderr)
	case "stats":
		return cmdDBStats(ctx, g, args[1:], stdout, stderr)
	}
	return usageError{fmt.Sprintf("db: unknown subcommand %q", args[0])}
}

// cmdDBInit builds the new database in a temporary file next to the target
// and renames it into place only after a successful import, so a failed
// init never leaves a half-built database at the target path.
func cmdDBInit(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("db init", stderr)
	g.register(fs)
	fixture := fs.String("fixture", "", "JSON fixture file to load")
	force := fs.Bool("force", false, "replace an existing database")
	if err := parseSub(fs, args); err != nil {
		return err
	}
	if _, err := os.Stat(g.db); err == nil && !*force {
		return fmt.Errorf("%w: %s (use --force to replace it)", database.ErrExists, g.db)
	}

	var f *database.Fixture
	if *fixture != "" {
		var err error
		if f, err = database.LoadFixture(*fixture); err != nil {
			return err
		}
	}

	tmp := filepath.Join(filepath.Dir(g.db), "."+filepath.Base(g.db)+".building")
	os.Remove(tmp)
	store, err := database.Create(ctx, tmp)
	if err != nil {
		return err
	}
	if f != nil {
		if err := store.ImportFixture(ctx, f); err != nil {
			store.Close()
			os.Remove(tmp)
			return fmt.Errorf("importing fixture: %w", err)
		}
	}
	if err := store.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, g.db); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Fprintf(stdout, "Created %s", g.db)
	if *fixture != "" {
		fmt.Fprintf(stdout, " from fixture %s", *fixture)
	}
	fmt.Fprintln(stdout)
	return nil
}

func cmdDBVerify(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("db verify", stderr)
	g.register(fs)
	if err := parseSub(fs, args); err != nil {
		return err
	}
	store, err := database.Open(ctx, g.db)
	if err != nil {
		return err
	}
	defer store.Close()
	checks, err := store.Verify(ctx)
	if err != nil {
		return err
	}
	failed := 0
	for _, c := range checks {
		line := fmt.Sprintf("[%-4s] %s", c.Status, c.Name)
		if c.Detail != "" {
			line += ": " + c.Detail
		}
		fmt.Fprintln(stdout, line)
		if c.Status == database.CheckFail {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d verification check(s) failed", database.ErrCorrupt, failed)
	}
	fmt.Fprintln(stdout, "Database OK")
	return nil
}

func cmdDBStats(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("db stats", stderr)
	g.register(fs)
	if err := parseSub(fs, args); err != nil {
		return err
	}
	store, err := database.Open(ctx, g.db)
	if err != nil {
		return err
	}
	defer store.Close()
	st, err := store.Stats(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Database: %s (%.1f KiB)\n", store.Path, float64(st.FileBytes)/1024)
	for _, t := range st.Tables {
		fmt.Fprintf(stdout, "  %-20s %10d\n", t.Table, t.Rows)
	}
	fmt.Fprintf(stdout, "  %-20s %10d\n", "cves w/o config", st.CVEsWithoutConfigurations)
	return nil
}
