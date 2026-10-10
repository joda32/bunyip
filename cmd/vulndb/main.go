// Command vulndb is the Offline VulnDB query CLI.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"offline-vulndb/internal/build"
	"offline-vulndb/internal/bundle"
	"offline-vulndb/internal/database"
	"offline-vulndb/internal/identity"
	"offline-vulndb/internal/ingest"
	"offline-vulndb/internal/matcher"
	"offline-vulndb/internal/nmap"
	"offline-vulndb/internal/output"
	"offline-vulndb/internal/version"
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
        [--distro NAME [--package-version VER]]  also evaluate distribution advisories
                                         (ubuntu, debian, redhat, rocky, almalinux, centos)
  nmap FILE [--format text|json]         assess services in Nmap XML output (-oX); FILE "-" = stdin
  nse --request FILE                     answer a request from nse/vulndb.nse (JSON in, JSON out)
  info                                   show database provenance and age
  update                                 fetch all sources and (re)build --db (auto-runs on first
                                         query when --db is the default and no database exists yet)
  build (--cache DIR | --offline-from DIR) --out FILE
                                         build a database from fetched/cached sources (see --help)
  db init [--fixture FILE] [--force]     create a new database (optionally loading a fixture)
  db verify                              check database integrity and consistency
  db stats                               show table row counts
  bundle keygen --key FILE --pub FILE    create an Ed25519 signing key pair
  bundle create --out FILE [--key FILE]  package the database (--db) as a signed transport bundle
  bundle verify FILE --pubkey FILE       check a bundle's signature and contents
  bundle import FILE --pubkey FILE       verify and atomically install a bundle as --db
        [--allow-unsigned] [--allow-downgrade]
  version                                print the vulndb version and build details

Global options (may also follow the command):
  --db PATH   database file (default $VULNDB_DB, else ./vulndb.sqlite)
  --debug     explain matching decisions on stderr
  --version   print the vulndb version and exit

Results are CANDIDATE vulnerabilities based on product/version data; they do
not prove a target is vulnerable. Distribution backported fixes are evaluated
only where a distribution verdict is shown (Ubuntu, Debian, RHEL family).
`

// buildVersion is the release version, set at link time with
//
//	-ldflags "-X main.buildVersion=v1.2.3".
//
// When unset it falls back to the VCS revision the Go toolchain stamps in.
var buildVersion = "dev"

func main() {
	os.Exit(runWithStdin(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// versionLine reports the vulndb version, preferring the link-time value and
// otherwise the embedded VCS revision (short, with a "-dirty" suffix if the
// build tree was modified).
func versionLine() string {
	v := buildVersion
	if v == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			rev, dirty := "", false
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if len(s.Value) >= 12 {
						rev = s.Value[:12]
					} else {
						rev = s.Value
					}
				case "vcs.modified":
					dirty = s.Value == "true"
				}
			}
			if rev != "" {
				v = rev
				if dirty {
					v += "-dirty"
				}
			}
		}
	}
	return fmt.Sprintf("vulndb %s (%s/%s, %s)", v, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithStdin(args, os.Stdin, stdout, stderr)
}

// globals holds options accepted both before and after the command name.
type globals struct {
	db string
	// dbExplicit is true when --db (or $VULNDB_DB) chose the path, so a
	// missing file is an error rather than a trigger to auto-build.
	dbExplicit bool
	debug      bool
	version    bool
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.db, "db", g.db, "database file")
	fs.BoolVar(&g.debug, "debug", g.debug, "explain matching decisions")
	fs.BoolVar(&g.version, "version", g.version, "print the vulndb version and exit")
}

// usageError marks errors that should print usage and exit 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func runWithStdin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	g := &globals{db: defaultDBPath(), dbExplicit: os.Getenv("VULNDB_DB") != ""}
	fs := newFlagSet("vulndb", stderr)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "db" {
			g.dbExplicit = true
		}
	})
	if g.version {
		fmt.Fprintln(stdout, versionLine())
		return exitOK
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
	case "nmap":
		err = cmdNmap(ctx, g, rest[1:], stdin, stdout, stderr)
	case "ingest":
		err = cmdIngest(ctx, g, rest[1:], stdin, stdout, stderr)
	case "build":
		err = cmdBuild(ctx, g, rest[1:], stdout, stderr)
	case "update":
		err = cmdUpdate(ctx, g, rest[1:], stdout, stderr)
	case "nse":
		err = cmdNSE(ctx, g, rest[1:], stdout, stderr)
	case "info":
		err = cmdInfo(ctx, g, rest[1:], stdout, stderr)
	case "db":
		err = cmdDB(ctx, g, rest[1:], stdout, stderr)
	case "bundle":
		err = cmdBundle(ctx, g, rest[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, versionLine())
		return exitOK
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
	distroArg := fs.String("distro", "", "distribution the software was installed from (ubuntu, debian, redhat, rocky, almalinux, centos)")
	pkgVerArg := fs.String("package-version", "", "installed distribution package version, e.g. 1:9.6p1-3ubuntu13.18")
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
	din, err := distroInput(*distroArg, *pkgVerArg)
	if err != nil {
		return usageError{err.Error()}
	}

	store, err := g.openStore(ctx, stderr)
	if err != nil {
		return err
	}
	defer store.Close()

	start := time.Now()
	engine, err := matcher.New(ctx, store)
	if err != nil {
		return err
	}
	res, err := engine.QueryCPE(ctx, *cpeArg, din)
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

// cmdNmap assesses every open, fingerprinted service in an Nmap XML file.
func cmdNmap(ctx context.Context, g *globals, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("nmap", stderr)
	g.register(fs)
	formatArg := fs.String("format", "text", "output format: text or json")
	// Allow flags both before and after the file name.
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return usageError{err.Error()}
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 1 {
		return usageError{"nmap: exactly one Nmap XML file is required (use - for stdin)"}
	}
	format, err := output.ParseFormat(*formatArg)
	if err != nil {
		return usageError{err.Error()}
	}

	in := stdin
	if files[0] != "-" {
		f, err := os.Open(files[0])
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	scan, err := nmap.Parse(in, nmap.DefaultMaxBytes)
	if err != nil {
		return err
	}

	store, err := g.openStore(ctx, stderr)
	if err != nil {
		return err
	}
	defer store.Close()
	engine, err := matcher.New(ctx, store)
	if err != nil {
		return err
	}
	start := time.Now()
	report, err := nmap.Analyse(ctx, scan, engine)
	if err != nil {
		return err
	}
	if g.debug {
		fmt.Fprintf(stderr, "Assessed %d services in %s\n", report.Summary.Assessed, time.Since(start).Round(time.Millisecond))
	}
	if format == output.JSON {
		info, err := databaseInfo(ctx, store)
		if err != nil {
			return err
		}
		return output.WriteNmapJSON(stdout, report, info)
	}
	return output.WriteNmapText(stdout, report)
}

func cmdIngest(ctx context.Context, g *globals, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("ingest", stderr)
	g.register(fs)
	fromArg := fs.String("from", "httpx", "fingerprinter whose output to read: httpx or webanalyze")
	formatArg := fs.String("format", "text", "output format: text or json")
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return usageError{err.Error()}
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 1 {
		return usageError{"ingest: exactly one input file is required (use - for stdin)"}
	}
	format, err := output.ParseFormat(*formatArg)
	if err != nil {
		return usageError{err.Error()}
	}
	in := stdin
	if files[0] != "-" {
		f, err := os.Open(files[0])
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	targets, err := ingest.Parse(in, ingest.Format(*fromArg))
	if err != nil {
		return err
	}

	store, err := g.openStore(ctx, stderr)
	if err != nil {
		return err
	}
	defer store.Close()
	techRows, err := store.HTTPTech(ctx)
	if err != nil {
		return err
	}
	scan, unmapped := ingest.Scan(targets, ingest.BuildTechMap(techRows))
	scan.Args = *fromArg + " ingest"
	engine, err := matcher.New(ctx, store)
	if err != nil {
		return err
	}
	report, err := nmap.Analyse(ctx, scan, engine)
	if err != nil {
		return err
	}
	report.Warnings = append([]string{ingest.IngestNote}, report.Warnings...)
	if len(unmapped) > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d detected technologies have no CPE mapping and were skipped (e.g. %s).",
			len(unmapped), strings.Join(firstN(unmapped, 5), ", ")))
	}
	if format == output.JSON {
		info, err := databaseInfo(ctx, store)
		if err != nil {
			return err
		}
		return output.WriteNmapJSON(stdout, report, info)
	}
	return output.WriteNmapText(stdout, report)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func cmdBuild(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("build", stderr)
	out := fs.String("out", "vulndb.sqlite", "database file to create")
	offlineFrom := fs.String("offline-from", "", "build from already-downloaded feeds + KEV in this directory")
	cache := fs.String("cache", "", "download cache; fetch NVD feeds + KEV into it over the network")
	allowSmall := fs.Bool("allow-small", false, "skip completeness floors (tests/partial builds)")
	noDistro := fs.Bool("no-distro", false, "build without distribution advisories")
	pkgMapPath := fs.String("distro-packages", "embedded:distro_packages.json", "curated CPE -> distro package map")
	releasesPath := fs.String("distro-releases", "embedded:distro_releases.json", "curated distribution release lifecycle")
	aliasesPath := fs.String("aliases", "embedded:aliases.json", "curated Nmap->NVD aliases")
	windowsPath := fs.String("windows-builds", "embedded:windows_builds.json", "curated Windows build map")
	productNamesPath := fs.String("product-names", "embedded:product_names.json", "curated Nmap product names")
	httpAppsPath := fs.String("http-apps", "embedded:http_apps.json", "curated HTTP application fingerprints")
	webappanalyzer := fs.String("webappanalyzer", "", "webappanalyzer technologies dir (derive http_tech); empty to skip")
	noEPSS := fs.Bool("no-epss", false, "build without FIRST EPSS scores")
	epssPath := fs.String("epss", "", "EPSS CSV snapshot (gzipped); default: fetched (--cache) or found in --offline-from")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	if (*offlineFrom == "") == (*cache == "") {
		return usageError{"build: give exactly one of --offline-from DIR or --cache DIR"}
	}
	logf := func(f string, a ...any) { fmt.Fprintf(stderr, f+"\n", a...) }
	var feeds []build.Feed
	var kev string
	var err error
	if *cache != "" {
		fetcher := build.NewFetcher("offline-vulndb-builder", logf)
		if feeds, err = fetcher.SyncNVD(*cache, build.FeedNames(time.Now().UTC().Year())); err != nil {
			return err
		}
		if kev, err = fetcher.SyncKEV(*cache); err != nil {
			return err
		}
		if *webappanalyzer == "" {
			if *webappanalyzer, err = fetcher.SyncWebappanalyzer(*cache); err != nil {
				return err
			}
		}
		if !*noEPSS && *epssPath == "" {
			if *epssPath, err = fetcher.SyncEPSS(*cache); err != nil {
				return err
			}
		}
	} else {
		if feeds, err = build.LocalFeeds(*offlineFrom); err != nil {
			return err
		}
		if len(feeds) == 0 {
			return usageError{"build: no nvdcve-2.0-*.meta feeds in " + *offlineFrom}
		}
		kev = filepath.Join(*offlineFrom, "known_exploited_vulnerabilities.json")
		if !*noEPSS && *epssPath == "" {
			*epssPath = build.LocalEPSS(*offlineFrom)
		}
	}
	bopts := build.Options{AllowSmall: *allowSmall, Log: logf}
	if bopts.Aliases, err = build.LoadAliases(*aliasesPath); err != nil {
		return err
	}
	if bopts.WindowsBuilds, err = build.LoadWindowsBuilds(*windowsPath); err != nil {
		return err
	}
	if bopts.ProductNames, err = build.LoadProductNames(*productNamesPath); err != nil {
		return err
	}
	if bopts.HTTPApps, err = build.LoadHTTPApps(*httpAppsPath); err != nil {
		return err
	}
	if *webappanalyzer != "" {
		if bopts.HTTPTech, err = build.DeriveHTTPTech(*webappanalyzer); err != nil {
			return err
		}
	}
	if *epssPath != "" {
		epss, err := build.LoadEPSS(*epssPath)
		if err != nil {
			return err
		}
		bopts.EPSS, bopts.EPSSModel, bopts.EPSSDate = epss.Rows, epss.ModelVersion, epss.ScoreDate
	}
	if !*noDistro {
		if bopts.PackageMap, err = build.LoadPackageMap(*pkgMapPath); err != nil {
			return err
		}
		if bopts.Releases, err = build.LoadReleases(*releasesPath); err != nil {
			return err
		}
		for _, name := range []string{"ubuntu", "debian", "redhat", "rocky", "almalinux"} {
			d := build.Distros[name]
			var zipPath string
			if *cache != "" {
				osv := build.NewFetcher("offline-vulndb-builder", logf)
				exp, ferr := osv.SyncOSV(*cache, d.Ecosystem)
				if ferr != nil {
					return ferr
				}
				zipPath = exp
			} else {
				if zipPath, err = build.VerifyLocalOSV(*offlineFrom, d.Ecosystem); err != nil {
					return err
				}
				if zipPath == "" {
					continue // this distro's export not present offline
				}
			}
			bopts.Distros = append(bopts.Distros, build.DistroInput{Distro: d, ZipPath: zipPath})
		}
	}
	stats, err := build.BuildNVDKEV(ctx, *out, feeds, kev, bopts)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Built %s: %d loaded, %d replaced, %d unchanged, %d rejected, %d rules skipped\n",
		*out, stats.Loaded, stats.Replaced, stats.Unchanged, stats.Rejected, len(stats.SkippedRules))
	return nil
}

// cmdUpdate fetches all sources over the network and (re)builds the database
// at the configured path. It reuses cmdBuild, defaulting --cache and --out.
func cmdUpdate(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	hasCache, hasOffline, hasOut := false, false, false
	for _, a := range args {
		switch {
		case a == "--cache" || strings.HasPrefix(a, "--cache="):
			hasCache = true
		case a == "--offline-from" || strings.HasPrefix(a, "--offline-from="):
			hasOffline = true
		case a == "--out" || strings.HasPrefix(a, "--out="):
			hasOut = true
		}
	}
	forward := append([]string{}, args...)
	if !hasCache && !hasOffline {
		cacheDir := defaultCacheDir()
		fmt.Fprintf(stderr, "Fetching sources into %s and building %s ...\n", cacheDir, g.db)
		forward = append(forward, "--cache", cacheDir)
	}
	if !hasOut {
		forward = append(forward, "--out", g.db)
	}
	return cmdBuild(ctx, g, forward, stdout, stderr)
}

// defaultCacheDir is the per-user cache location for downloaded sources.
func defaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "vulndb")
	}
	return ".vulndb-cache"
}

// distroInput builds the distribution context for `query`. The package
// version's revision (after the last '-') is what advisories compare against.
func distroInput(name, pkgVersion string) (*matcher.DistroInput, error) {
	if name == "" {
		if pkgVersion != "" {
			return nil, errors.New("query: --package-version requires --distro")
		}
		return nil, nil
	}
	names := map[string]string{"ubuntu": "Ubuntu", "debian": "Debian", "redhat": "Red Hat", "rocky": "Rocky Linux",
		"almalinux": "AlmaLinux", "centos": "CentOS"}
	display, ok := names[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("query: unsupported --distro %q (supported: almalinux, centos, debian, redhat, rocky, ubuntu)", name)
	}
	info := identity.DistroInfo{Name: display, Key: strings.ToLower(name)}
	if pkgVersion != "" {
		parse := version.ParseDeb
		if info.Key != "ubuntu" && info.Key != "debian" {
			parse = version.ParseRPM
		}
		v, err := parse(pkgVersion)
		if err != nil || v.Revision == "" {
			return nil, fmt.Errorf("query: --package-version %q must be a package version with a revision/release", pkgVersion)
		}
		info.Revision = v.Revision
	}
	return &matcher.DistroInput{Info: info}, nil
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
	store, err := g.openStore(ctx, stderr)
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
	width := 0
	for _, k := range keys {
		width = max(width, len(k)+1)
	}
	if len(keys) > 0 {
		fmt.Fprintln(stdout, "Source metadata:")
	}
	for _, k := range keys {
		fmt.Fprintf(stdout, "  %-*s %s\n", width, k+":", m[k])
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

// parseWithFile parses flags that may appear before or after one positional
// file argument.
func parseWithFile(fs *flag.FlagSet, args []string) (string, error) {
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return "", err
			}
			return "", usageError{err.Error()}
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 1 {
		return "", usageError{fs.Name() + ": exactly one bundle file is required"}
	}
	return files[0], nil
}

func cmdBundle(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"bundle: subcommand required (keygen, create, verify, import)"}
	}
	fs := newFlagSet("bundle "+args[0], stderr)
	g.register(fs)
	switch args[0] {
	case "keygen":
		key := fs.String("key", "", "private key file to create (keep it on the build machine)")
		pub := fs.String("pub", "", "public key file to create (copy it to the offline side)")
		if err := parseSub(fs, args[1:]); err != nil {
			return err
		}
		if *key == "" || *pub == "" {
			return usageError{"bundle keygen: --key and --pub are required"}
		}
		id, err := bundle.GenerateKeys(*key, *pub)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Created signing key %s (private) and %s (public), key ID %s\n", *key, *pub, id)
		return nil

	case "create":
		out := fs.String("out", "", "bundle file to write, e.g. vulndb-2026-10-07.tar.gz")
		key := fs.String("key", "", "private key to sign with (omit for an unsigned bundle)")
		if err := parseSub(fs, args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return usageError{"bundle create: --out is required"}
		}
		var sk ed25519.PrivateKey
		if *key != "" {
			var err error
			if sk, err = bundle.LoadPrivateKey(*key); err != nil {
				return err
			}
		}
		start := time.Now()
		m, err := bundle.Create(ctx, g.db, *out, sk)
		if err != nil {
			return err
		}
		fi, _ := os.Stat(*out)
		fmt.Fprintf(stdout, "Created %s (%.0f MB from a %.0f MB database) in %s\n", *out,
			float64(fi.Size())/1e6, float64(m.Database.Size)/1e6, time.Since(start).Round(time.Second))
		writeManifest(stdout, m)
		if !m.Signed {
			fmt.Fprintln(stdout, "WARNING: bundle is not signed; importing it will require --allow-unsigned.")
		}
		return nil

	case "verify", "import":
		pub := fs.String("pubkey", "", "trusted public key")
		allowUnsigned := fs.Bool("allow-unsigned", false, "accept a bundle without a verified signature")
		allowDowngrade := fs.Bool("allow-downgrade", false, "install a database older than the installed one")
		file, err := parseWithFile(fs, args[1:])
		if err != nil {
			return err
		}
		opts := bundle.Options{AllowUnsigned: *allowUnsigned, AllowDowngrade: *allowDowngrade}
		if *pub != "" {
			if opts.PublicKey, err = bundle.LoadPublicKey(*pub); err != nil {
				return err
			}
		}
		if args[0] == "verify" {
			m, err := bundle.Verify(file, opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Bundle OK: %s\n", file)
			writeManifest(stdout, m)
			return nil
		}
		res, err := bundle.Import(ctx, file, g.db, opts)
		if err != nil {
			return err
		}
		switch {
		case res.Skipped:
			fmt.Fprintf(stdout, "Bundle verified; %s already has this database version. Nothing to do.\n", g.db)
		default:
			fmt.Fprintf(stdout, "Installed %s from %s\n", g.db, file)
			if res.Previous != "" {
				fmt.Fprintf(stdout, "Previous database kept as %s\n", res.Previous)
			}
		}
		writeManifest(stdout, res.Manifest)
		return nil
	}
	return usageError{fmt.Sprintf("bundle: unknown subcommand %q", args[0])}
}

func writeManifest(w io.Writer, m *bundle.Manifest) {
	md := m.Database.Metadata
	sig := "not signed"
	switch {
	case m.Signed && m.KeyID != "":
		sig = "valid, key ID " + m.KeyID
	case m.Signed:
		sig = "present, NOT checked"
	}
	fmt.Fprintf(w, "  Signature:         %s\n", sig)
	fmt.Fprintf(w, "  Database version:  %s (schema %s)\n", md["database_version"], md["schema_version"])
	if md["nvd_last_modified"] != "" {
		fmt.Fprintf(w, "  NVD data as of:    %s\n", md["nvd_last_modified"])
	}
	if md["kev_catalog_version"] != "" {
		fmt.Fprintf(w, "  KEV catalogue:     %s\n", md["kev_catalog_version"])
	}
	if md["distro_sources"] != "" {
		fmt.Fprintf(w, "  Distributions:     %s\n", md["distro_sources"])
	}
	fmt.Fprintf(w, "  SHA-256:           %s\n", m.Database.SHA256)
}

// cmdNSE answers one request from nse/vulndb.nse. Requests arrive in a file
// (never on the command line: they contain banner text from the target).
// Failures are reported as JSON {"error": ...} on stdout as well, so the
// script can show them; the exit code is still non-zero.
func cmdNSE(ctx context.Context, g *globals, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("nse", stderr)
	g.register(fs)
	reqPath := fs.String("request", "", "request file written by the NSE script")
	if err := parseSub(fs, args); err != nil {
		return err
	}
	if *reqPath == "" {
		return usageError{"nse: --request is required"}
	}
	resp, err := answerNSE(ctx, g, *reqPath)
	if err != nil {
		json.NewEncoder(stdout).Encode(map[string]any{"version": nmap.NSERequestVersion, "error": err.Error()})
		return err
	}
	return json.NewEncoder(stdout).Encode(resp)
}

func answerNSE(ctx context.Context, g *globals, reqPath string) (*nmap.NSEResponse, error) {
	f, err := os.Open(reqPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	req, err := nmap.ParseNSERequest(f)
	if err != nil {
		return nil, err
	}
	store, err := database.Open(ctx, g.db)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	engine, err := matcher.New(ctx, store)
	if err != nil {
		return nil, err
	}
	return nmap.AnswerNSE(ctx, req, engine)
}

// openStore opens the configured database, first fetching sources and
// building it (vulndb update) when no database exists yet — the auto-bootstrap
// so a fresh install works on first query.
func (g *globals) openStore(ctx context.Context, stderr io.Writer) (*database.Store, error) {
	if _, err := os.Stat(g.db); errors.Is(err, os.ErrNotExist) && !g.dbExplicit {
		fmt.Fprintf(stderr, "No database at %s; fetching sources and building it (vulndb update)...\n", g.db)
		if err := cmdUpdate(ctx, g, nil, io.Discard, stderr); err != nil {
			return nil, fmt.Errorf("auto-update failed: %w", err)
		}
	}
	return database.Open(ctx, g.db)
}
