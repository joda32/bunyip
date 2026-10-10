# Offline VulnDB

Offline VulnDB is a lightweight vulnerability **correlation** engine for
isolated and restricted networks. Given a software identity — a CPE, an Nmap
service fingerprint, or a web technology detected by httpx — it looks up
**candidate CVEs** in a local SQLite database, evaluates the affected version
ranges, and annotates each result with CISA KEV status and public-exploit
evidence. No Internet access is needed at query time, and it never touches a
target.

```text
  CPE 2.2/2.3 ─┐
  Nmap -oX     ├─▶ normalise & resolve identity ─▶ candidate rules (SQLite)
  httpx -td    ─┘                                        │
                                                         ▼
                              version-range evaluation (MATCH / UNKNOWN)
                                                         │
                    KEV + exploit + distro-backport + Windows-build enrichment
                                                         │
                                                         ▼
                                             text  |  JSON  |  NSE output
```

It ships as a **single static binary** with its curated data embedded. The same
binary builds the database (`vulndb update`, on an Internet-connected machine)
and answers queries (`vulndb query` / `nmap` / `ingest`, on the offline side).

- Matching semantics: [`docs/matching.md`](docs/matching.md)
- Design rationale: [`offline_vulndb_design.md`](offline_vulndb_design.md)
- Data-source coverage and decisions: [`docs/data-sources.md`](docs/data-sources.md)
- Build → signed bundle → offline import: [`docs/deployment.md`](docs/deployment.md)

## What it is not

- **Not a scanner.** It never connects to a target; it reads data someone else
  collected (an Nmap XML file, httpx output, or a single CPE).
- **Not proof of vulnerability.** A version/banner match is a *candidate*: the
  version only *appears* to fall in an affected range. Confirm before acting.
- **Not a patch-state audit.** Distribution backports are evaluated for Ubuntu,
  Debian, RHEL, Rocky Linux, AlmaLinux and CentOS, and only as far as the scan
  reveals the installed package. Other distributions (SUSE, Alpine, …) can show
  false positives.
- **Never runs, downloads or ships exploit code.** It only records that exploit
  *references* exist.
- **Not complete.** NVD provides CPE applicability data for only part of recent
  CVEs (see [coverage](#a-note-on-nvd-coverage)), so an empty result is not
  evidence of "no vulnerability".

## Features

- **Query engine (Go).** CPE 2.2/2.3 parsing and normalisation; per-product
  version comparators (generic, OpenSSH, dpkg, RPM, PEP 440); range evaluation
  (`MATCH` / `NO_MATCH` / `UNKNOWN`); awareness of NVD AND/OR configuration
  structure; KEV and exploit enrichment; text, JSON and debug output.
- **Nmap input.** `vulndb nmap scan.xml` assesses every open, fingerprinted
  service in Nmap `-oX` output. `nse/vulndb.nse` shows the same results inline
  during a scan (`nmap -sV --script vulndb`).
- **Web-fingerprinter ingest.** `vulndb ingest` consumes httpx (`-td -json`) or
  webanalyze output and assesses the web applications they detect, mapping
  technology names to CPEs — so specialised web fingerprinting feeds the same
  engine instead of being forced through Nmap.
- **Identity resolution.** Curated aliases map the vendor/product names Nmap
  reports to the names NVD uses (e.g. `mysql:mysql` → `oracle:mysql`). A curated
  product-name map identifies services Nmap names but gives no CPE (ClamAV,
  CouchDB, cPanel, …). A curated HTTP app map identifies web apps behind a
  generic web server (WordPress, Drupal, Jenkins, …) from HTTP evidence.
- **Distribution security advisories** (Ubuntu, Debian, RHEL, Rocky Linux,
  AlmaLinux; CentOS via RHEL). Each candidate CVE for a distro-packaged service
  is checked against the distribution's own fix data
  (`FIXED` / `VULNERABLE` / `FIX_AVAILABLE` / `NO_FIX`), removing backport false
  positives and adding CVEs NVD lacks data for.
- **Windows build-level assessment.** `vulndb nmap` reads the build that
  `rdp-ntlm-info` / `smb-os-discovery` report (e.g. `10.0.20348`), maps it to
  the release's NVD identities, and lists the CVEs that apply *unless patched*,
  KEV first, with end-of-support status.
- **Self-contained builder.** `vulndb update` fetches all real sources and
  builds the database locally; curated first-party data is embedded in the
  binary, so no repository checkout is needed on the build machine.
- **Signed transport bundles.** Package a built database, verify its signature,
  schema and integrity, and install it atomically on the offline side.

Not yet: SUSE/Alpine advisories, and the official CVE List as a second
applicability source (evaluated and deferred — see
[`docs/data-sources.md`](docs/data-sources.md)).

## Architecture

The engine is a set of small, single-purpose Go packages. A query flows through
them in order; [`docs/matching.md`](docs/matching.md) documents each step.

```text
cmd/vulndb/          CLI, command dispatch, end-to-end tests
internal/cpe/        CPE 2.2/2.3 parsing, normalisation, attribute matching
internal/identity/   candidate identities: aliases, product names, platform CPEs, distro detection
internal/database/   SQLite access, schema checks, candidate lookup, verify/stats, fixture import
internal/version/    comparator interface; generic, OpenSSH, dpkg, RPM, PEP 440 comparators; range eval
internal/matcher/    rule evaluation, per-CVE aggregation, enrichment, ordering, platform conditions
internal/distro/     distribution advisory verdicts (release inference, dpkg/rpm comparison)
internal/windows/    Windows build-level assessment (build evidence → release CPEs)
internal/nmap/       Nmap XML parser and whole-scan assessment
internal/ingest/     httpx / webanalyze adapters → scan model
internal/output/     text and JSON rendering
internal/build/      the builder: fetch, NVD transform, OSV distros, curated loaders, embed
internal/bundle/     signed transport bundles (create, verify, atomic import)
data/                curated first-party JSON, embedded via data/embed.go
schema/schema.sql    database schema (embedded in the binary)
```

**How a single query is evaluated** (`internal/matcher`):

1. **Normalise** the input to a canonical CPE 2.3 and derive its
   part/vendor/product (`internal/cpe`).
2. **Resolve identities** — the CPE itself plus any curated aliases, and, for a
   scan, product-name and HTTP-app identities (`internal/identity`).
3. **Look up candidate rules**: every `cve_match` whose part/vendor/product
   matches, scoped by indexed columns so the read stays small
   (`internal/database`).
4. **Evaluate each rule's version range** with the comparator chosen for the
   product. The engine *never turns uncertainty into a match*: anything it can't
   decide is `UNKNOWN`, and `NO_MATCH` CVEs are dropped (`internal/version`).
5. **Aggregate per CVE**, take the strongest status, and **enrich** with KEV,
   exploit references, distribution verdicts and (for Windows hosts) platform
   conditions (`internal/matcher`, `internal/distro`, `internal/windows`).
6. **Order and render**: KEV first, then exploit evidence, then severity
   (`internal/output`).

**The database** is one SQLite file (~0.8 GB for a full build, ~385k CVEs). It
is produced by `internal/build` from public sources and read-only at query
time. The schema is embedded, so `db verify` can re-check every stored match
criterion against its index columns.

## Install

### Release binary

Download the archive for your platform, verify it, and run it. Each release
archive contains the `vulndb` binary plus the licenses and this README, and a
`SHA256SUMS` covers the archives.

```bash
sha256sum -c SHA256SUMS                         # verify the download
tar xzf vulndb_v0.1.0_linux_amd64.tar.gz
./vulndb_v0.1.0_linux_amd64/vulndb version      # vulndb v0.1.0 (linux/amd64, go1.27.1)
```

The binary is statically linked (no CGO, pure-Go SQLite) and self-contained.

### Build from source

Requires Go 1.27+.

```bash
make build          # -> bin/vulndb
make test           # go test ./...   (no network access needed)
make test-all       # Go tests + Python updater tests (incl. a real-data end-to-end test)

# release archives into dist/ (override VERSION / PLATFORMS):
make release VERSION=v0.1.0 PLATFORMS="linux/amd64 linux/arm64 darwin/arm64 windows/amd64"
```

`vulndb version` / `vulndb --version` prints the stamped version plus the
OS/arch and Go version.

## Updating the database

The database path is chosen as `--db PATH`, else `$VULNDB_DB`, else
`./vulndb.sqlite`.

### Build it on an Internet-connected machine

```bash
vulndb --db ./vulndb.sqlite update              # fetch everything, build ./vulndb.sqlite
make real-db                                    # same thing, caching sources in .cache/feeds
```

`vulndb update` fetches, over HTTPS from an allow-list of hosts only:

- **NVD CVE JSON 2.0 feeds** — every yearly feed plus the `modified` overlay,
  each verified against the sha256 in its `.meta` sidecar;
- the **CISA KEV** catalogue;
- **OSV.dev** distribution exports for Ubuntu, Debian, Red Hat, Rocky and
  AlmaLinux, each verified against its published MD5;
- the **webappanalyzer** technology corpus, from which the technology→CPE map
  (`http_tech`) is derived at build time.

Curated first-party data (aliases, the distro package map and release
lifecycle, Windows builds, product names, HTTP app fingerprints) is embedded in
the binary, so nothing else is needed on the build machine.

Useful flags:

```bash
vulndb update --cache DIR         # cache downloads in DIR (default: ~/.cache/vulndb);
                                  #   unchanged feeds are not re-downloaded
vulndb update --out FILE          # write to FILE instead of --db
vulndb build --offline-from DIR   # build from files already downloaded into DIR (no network)
vulndb build --no-distro          # skip distribution advisories
vulndb build --webappanalyzer DIR # use a local webappanalyzer checkout instead of fetching
```

The build is atomic: it writes to a temporary file, runs integrity and
completeness self-checks, and only then renames over the target — so an
interrupted or failed build never corrupts an existing database. Downloads are
cached per feed, so a throttled or interrupted `update` can simply be re-run and
resumes where it left off.

> **Note on NVD throttling.** NVD rate-limits its feed host aggressively; a full
> first build can take a long time (mostly download time). This is server-side
> and not fixable client-side; an NVD API key does not help, because the feeds
> are static files, not the rate-limited REST API. The fetcher aborts an attempt
> only if a download *stalls* (no bytes for a while), never because it is merely
> slow, and re-runs resume from cache.

### First-run auto-bootstrap

If you run a query-facing command (`query`, `nmap`, `ingest`, `info`) and the
**default** database does not exist yet, the binary runs `update` automatically
to create it. Pointing `--db` at an explicit path that is missing is an error
instead, so scripts fail loudly rather than silently downloading hundreds of MB.

### Deploy into an air-gapped network

Build on the connected side, sign a bundle, carry it across, and import it. The
import verifies the Ed25519 signature, checksum, schema version and SQLite
integrity, refuses downgrades, and replaces the database atomically.

```bash
make keygen         # once: vulndb-signing.key (keep secret) + vulndb-signing.pub (copy across)
make bundle         # vulndb-YYYY-MM-DD.tar.gz (a ~0.8 GB database compresses to ~140 MB)

# on the offline side:
vulndb --db /opt/vulndb/vulndb.sqlite bundle import vulndb-2026-10-10.tar.gz --pubkey vulndb-signing.pub
```

See [`docs/deployment.md`](docs/deployment.md) for the full procedure.

### Check freshness

```bash
vulndb info      # schema/data versions, NVD data age (warns after 7 days), KEV version, coverage
```

### A note on NVD coverage

Since April 2026 NIST fully enriches only a minority of new CVEs (KEV, US
federal-use and EO 14028 "critical software"). Many recent CVEs therefore have
**no CPE applicability data and can never match a query**. `vulndb info` reports
the exact share, and query output carries a warning. This is a property of the
upstream data, surfaced honestly rather than hidden. See
[`docs/data-sources.md`](docs/data-sources.md) for measurements.

### Synthetic fixture (development only)

```bash
make fixture-db     # builds ./vulndb.sqlite from a small SYNTHETIC fixture
```

Its CVE IDs (`CVE-0000-*`), scores and KEV/exploit entries are invented so tests
are deterministic. They are not real vulnerabilities, and the CLI warns whenever
this data is loaded.

## Usage

### Query a single CPE

```bash
vulndb query --cpe 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
vulndb query --cpe 'cpe:/a:apache:http_server:2.4.49' --format json   # Nmap-style CPE 2.2
vulndb --debug query --cpe 'cpe:/a:openbsd:openssh:8.9p1'             # explain every rule, on stderr
```

```text
Product:             apache http_server
Version:             2.4.49
Normalized CPE:      cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Identity confidence: EXACT

Candidate vulnerabilities: 88 version match, 0 undetermined

CVE-2021-41773   CRITICAL  CVSS 9.8 (v3)
  Public exploit: YES (nvd-reference; unverified)
  CISA KEV:       YES (added 2021-11-03; known ransomware use)
  Version status: MATCH
  Confidence:     EXACT
  Match reason:   Exact supplied CPE matched vulnerability criteria
                  cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:* and detected version 2.4.49
                  equals affected version 2.4.49.
...
```

The JSON form (`--format json`) is a stable document — `output_version` only
changes on a breaking layout change — carrying every field below plus CVSS
vectors, CWEs, exploit evidence and matched rules. With `--debug` a rule-by-rule
trace goes to stderr and the JSON gains a `rule_evaluations` array; stdout stays
valid JSON.

**Result fields that matter:**

- `version_status` — `MATCH` (version inside the affected range) or `UNKNOWN`
  (could not decide: no version, unparseable version, or criteria more specific
  than the input). `UNKNOWN` is never promoted to a match; `NO_MATCH` CVEs are
  not returned.
- `applicability: CONDITIONAL` — NVD says the CVE applies only with another
  condition (typically a specific OS) that was not evaluated.
- `identity_confidence` / `match_confidence` — `EXACT` (concrete version),
  `HIGH` (via a curated alias), `LOW` (product only, no version).
- `match_reason` — a human-readable explanation, always present.

For a distribution-packaged service, pass the distro and the installed package
version to get a backport-aware verdict:

```bash
vulndb query --cpe cpe:/a:openbsd:openssh:9.6p1 --distro ubuntu --package-version 1:9.6p1-3ubuntu13.18
vulndb query --cpe cpe:/a:openbsd:openssh:9.2p1 --distro debian --package-version 1:9.2p1-2+deb12u3
vulndb query --cpe cpe:/a:openbsd:openssh:8.7p1 --distro redhat --package-version 0:8.7p1-34.el9_3
```

### Assess an Nmap scan

`-sV` (service/version detection) is required. Add `-sC` (or
`--script rdp-ntlm-info,smb-os-discovery`) to enable Windows build assessment
and HTTP app fingerprinting.

```bash
nmap -sV -oX scan.xml 10.0.0.0/24
vulndb nmap scan.xml                   # compact per-host/per-port report
vulndb nmap scan.xml --format json     # full structured report
nmap -sV -oX - 10.0.0.5 | vulndb nmap - # read from stdin
```

```text
Nmap scan: nmap -sV -O -oX sample.xml 192.0.2.0/29
Hosts up 2, down 1 | open ports 6: assessed 4, unidentified 1, not probed 1
Candidate vulnerabilities: 8 version matches (2 in CISA KEV, 4 with public exploit evidence), 1 undetermined

192.0.2.20 (web01.example.test)
  22/tcp ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
    Identity: cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:* [EXACT]
    Note: Distribution package detected (Ubuntu package 3ubuntu0.10): the vendor may have
          backported security fixes without changing the upstream version, ...
    CVE-0000-0201    HIGH      CVSS 8.1  exploit:YES KEV:NO  MATCH
  443/tcp http nginx 1.20.1 (ssl)
    Identity: cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:* [HIGH] (curated alias)
    CVE-0000-0101    HIGH      CVSS 7.7  exploit:YES KEV:NO  MATCH  [via alias, HIGH]
  8080/tcp http Mystery httpd 1.2
    Note: No application CPE reported for "Mystery httpd 1.2"; ... not assessed.
```

Each open port is `ASSESSED`, `OS_COMPONENT` (a Windows built-in, covered by the
build assessment), `UNIDENTIFIED` (fingerprinted but no CPE and not in the
curated map), or `NOT_PROBED` (guessed from the port number). OS and hardware
CPEs are listed but never queried as if they were the service.

Windows hosts are assessed at build level when the scan includes NTLM/SMB OS
evidence:

```text
192.0.2.10 (dc01.example.test)
  Windows: Windows Server 2022 (build 10.0.20348) [HIGH]
    Evidence: rdp-ntlm-info on 3389/tcp Product_Version 10.0.20348
    Support: mainstream support until 2026-10-13; extended support until 2031-10-14
    3957 CVEs apply unless patched: 107 in CISA KEV, 29 with public exploit evidence, 129 critical
    CVE-2026-85880   HIGH      CVSS 7.8  KEV added 2026-09-08
    ...
```

The patch level is invisible to an unauthenticated scan, so these are the
release's CVEs that apply *unless patched*, not findings.

#### Distribution-packaged hosts

For a distro-packaged service, candidate CVEs are checked against the
distribution's own advisory data. Example from a real Ubuntu 24.04 host
(`OpenSSH 9.6p1 Ubuntu 3ubuntu13.18`):

```text
  22/tcp ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
    Distribution: Ubuntu: RESOLVED (openssh 24.04, installed 1:9.6p1-3ubuntu13.18)
    CVE-2026-73282   MEDIUM    CVSS 4.8  exploit:NO  KEV:NO  MATCH  [Ubuntu: VULNERABLE]
    + 16 fixed in the Ubuntu package: CVE-2024-6387, CVE-2026-60002, ...
```

Upstream matching alone reported 22 CVEs; Ubuntu's data shows 16 of them fixed
in the installed package. Debian works the same way (a revision like `2+deb12u3`
pins the release). Red Hat-family hosts have no visible package release, so
verdicts are by upstream version (`FIXED` / `FIX_AVAILABLE` / `VULNERABLE`), with
AppStream module streams judged per stream.

#### Inline in Nmap (NSE)

```bash
nmap -sV --script /opt/vulndb/vulndb.nse \
     --script-args vulndb.bin=/opt/vulndb/vulndb,vulndb.db=/opt/vulndb/vulndb.sqlite 10.0.0.0/24
```

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
| vulndb:
|   6 candidate CVEs (0 in CISA KEV, 0 with public exploit evidence)
|   Distribution: Ubuntu 24.04 installed 1:9.6p1-3ubuntu13.18; 16 more fixed in the package
|   CVE-2023-51767   HIGH      CVSS 7.0
|   CVE-2026-73282   MEDIUM    CVSS 4.8  Ubuntu: VULNERABLE
```

The script is a thin adapter: per port it writes the fingerprint and the host's
other open ports to a temp file, runs `vulndb nse --request FILE`, and prints the
answer. Target-controlled banner text never reaches a command line. Script args:
`vulndb.bin`, `vulndb.db`, `vulndb.max` (CVEs per port, default 10),
`vulndb.mincvss`, `vulndb.showall`. Unix-like systems only.

### Ingest web fingerprints (httpx / webanalyze)

Web applications sit behind a web server, so a port-and-banner scan usually sees
only the server. A web fingerprinter identifies the apps; `vulndb ingest` maps
each detected technology to a CPE (via the curated `http_tech` map) and assesses
it like any other identity.

**httpx** — run with tech detection and JSON output, then ingest:

```bash
httpx -l hosts.txt -td -json -o httpx.jsonl     # -td = tech detect, -json = one object per line
vulndb ingest --from httpx httpx.jsonl
# or stream it straight through:
httpx -l hosts.txt -td -json | vulndb ingest --from httpx -
```

Each httpx line looks like
`{"input":"blog.test","host":"192.0.2.80","port":"443","scheme":"https","tech":["WordPress","PHP:8.2.7"]}`
(a `Name:version` entry carries a version). The report:

```text
192.0.2.80 (blog.test)
  443/tcp http PHP 8.2.7
    Identity: cpe:2.3:a:php:php:8.2.7:*:*:*:*:*:*:* [EXACT]
    CVE-0000-0940   HIGH   CVSS 7.5   MATCH
  443/tcp http WordPress
    Identity: cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:* [LOW]
    ...
Note: Identities were supplied by an HTTP fingerprint ingest; verify before acting.
      1 technology had no CPE mapping and was skipped.
```

Versionless technologies resolve to a product-only (`LOW`) identity and are
listed; technologies with no CPE mapping are skipped and counted. `--format json`
gives the structured report.

**webanalyze** — ingest its JSON output the same way:

```bash
webanalyze -hosts hosts.txt -output json > webanalyze.json
vulndb ingest --from webanalyze webanalyze.json
```

### Utility commands

```bash
vulndb info      # versions, NVD data age, KEV version, coverage; warns if stale or synthetic
vulndb db verify # SQLite integrity, foreign keys, every criterion re-parsed vs its index columns
vulndb db stats  # row counts and file size
vulndb bundle keygen|create|verify|import   # signed transport bundles (docs/deployment.md)
vulndb version   # version, OS/arch, Go version
```

**Exit codes:** `0` success (including "no results"); `1` runtime error (missing
or corrupt database, incompatible schema, malformed CPE, insufficient identity,
failed verify); `2` usage error (unknown command/flag, unsupported `--format`).

## Current limitations

- **Coverage.** NVD is the only applicability source and covers only part of
  recent CVEs (see above). An empty result is not evidence of "no vulnerability".
- **Version comparison.** OpenSSH, dpkg, RPM and PEP 440 have dedicated
  comparators; other schemes use a conservative generic comparator and give
  `UNKNOWN` rather than guessing.
- **NVD configurations.** AND/negated configurations are flagged, not evaluated
  (one CPE can't satisfy several conditions). The exception is "running on"
  platform conditions on Windows hosts whose build was assessed; Linux hosts'
  platform conditions are not evaluated yet.
- **Distro scope.** Backport-aware verdicts cover Ubuntu, Debian, RHEL, Rocky,
  AlmaLinux and CentOS only, and only as far as the scan reveals the installed
  package. Only OpenSSH on Debian/Ubuntu exposes its package revision in the
  banner; other services show just "(Ubuntu)"/"(Debian)", so their verdicts are
  about the release. End-of-life releases (e.g. Debian 11) no longer publish
  advisory data and are flagged.
- **Windows.** Assessed per build, not per patch level — the result is the
  release's exposure ("applies unless patched"), not a finding. Needs `-sC` and
  works in `vulndb nmap` only, not the NSE adapter. Windows services themselves
  (SMB, RDP, LDAP) are reported as OS components, not assessed individually.
- **OS-attributed components.** Vulnerabilities NVD files against an OS CPE are
  invisible to a product CPE (e.g. recent IIS CVEs are listed against Windows,
  so `cpe:/a:microsoft:internet_information_services:10.0` finds none).
- **Exploit evidence** is limited to references NVD tagged `Exploit`, and none of
  it is verified.
- **Large rule sets** are slower: a `linux_kernel` query reads tens of thousands
  of rules (~0.7 s) versus a few ms for typical services.
- **Upstream data quirks.** A handful of NVD criteria are malformed (e.g.
  unescaped parentheses in Cisco IOS versions); they are skipped and counted in
  `nvd_rules_skipped`.

## Acknowledgements — third-party data sources

Offline VulnDB is a correlation layer over public vulnerability data. All of the
following is **fetched at build/update time** and is **not** redistributed in
this source tree. With gratitude to the maintainers of these datasets:

| Source | Used for | License / terms |
|---|---|---|
| [**NVD** CVE JSON 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) (NIST) | CVEs, CPE applicability, CVSS, CWE, exploit references | U.S. Government work — public domain |
| [**CISA KEV** catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited / ransomware flags | U.S. Government work — public domain |
| [**OSV.dev**](https://osv.dev) distribution exports (Ubuntu, Debian, Red Hat, Rocky, AlmaLinux) | Distribution backport / fix verdicts | Each advisory under its upstream distribution's license |
| [**webappanalyzer**](https://github.com/enthec/webappanalyzer) | Web technology → CPE map (`http_tech`), for `vulndb ingest` | **GPL-3.0** — the derived map is generated at build time and is **not** shipped in this repo (gitignored) |
| [**Nmap**](https://nmap.org) service-probe database | `review-products` candidate proposals (curation only) | Read from the local Nmap install; not redistributed |

These tools pair naturally with Offline VulnDB and are acknowledged with thanks:
[Nmap](https://nmap.org) (service/version detection and the NSE adapter),
[httpx](https://github.com/projectdiscovery/httpx) and
[webanalyze](https://github.com/rverton/webanalyze) (web fingerprinting feeding
`vulndb ingest`).

The curated first-party data in `data/` (aliases, the distro package map and
release lifecycle, Windows builds, product names, HTTP app fingerprints) is part
of this project and embedded in the binary. See [NOTICE](NOTICE) for the
authoritative attribution.

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you state otherwise, any contribution you submit for
inclusion is dual-licensed as above, without additional terms.

Vulnerability and fingerprint **data** is fetched under its own license and is
not part of this source tree — see [NOTICE](NOTICE) and
[Acknowledgements](#acknowledgements--third-party-data-sources). In particular,
the web technology → CPE map is derived from the GPL-3.0
[webappanalyzer](https://github.com/enthec/webappanalyzer) corpus and is
generated at build time, never committed.
