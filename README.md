# Offline VulnDB

Offline VulnDB is a lightweight vulnerability correlation engine for isolated
and restricted networks. Given a software identity — currently a CPE, such as
the ones Nmap reports — it looks up **candidate CVEs** in a local SQLite
database, evaluates the affected version ranges, and annotates each result
with CISA KEV and public-exploit evidence. No Internet access is needed at
query time.

```text
CPE (2.2 or 2.3) -> normalise -> candidate rules in SQLite -> version range evaluation
                 -> KEV / exploit enrichment -> text or JSON
```

The design is in [`offline_vulndb_design.md`](offline_vulndb_design.md); the
exact matching rules are in [`docs/matching.md`](docs/matching.md).

## What it is not

- Not a vulnerability scanner: it never touches a target.
- Not proof of vulnerability: a version/banner match is a **candidate
  vulnerability**. The version only *appears* to fall in an affected range.
- Not a patch-state audit. Distribution backports (fixes shipped without
  changing the upstream version) are evaluated for Ubuntu, Debian, RHEL, Rocky
  Linux, AlmaLinux and CentOS, only as far as the scan reveals the installed
  package. Results for other distributions (SUSE, Alpine, …) can be false
  positives.
- Does not run, download or ship exploit code; it only records that exploit
  references exist.

## Status: milestone 9

Implemented:
- **Query engine (Go):** CPE 2.2/2.3 parsing and normalisation, version
  comparators chosen per product (generic, OpenSSH), range evaluation
  (MATCH / NO_MATCH / UNKNOWN), awareness of NVD AND/OR configuration
  structure, KEV and exploit enrichment, text and JSON output, a debug trace,
  and `db init/verify/stats`.
- **Nmap input:** `vulndb nmap scan.xml` assesses every open, fingerprinted
  service in Nmap `-oX` output; `nse/vulndb.nse` shows the same results inline
  during a scan (`nmap -sV --script vulndb`).
- **Identity resolution:** curated aliases map the vendor/product names Nmap
  reports to the names NVD uses (e.g. `mysql:mysql` → `oracle:mysql`).
  Distribution packages (Ubuntu, Debian, RHEL, …) are detected.
- **Distribution security advisories (Ubuntu, Debian, RHEL, Rocky Linux,
  AlmaLinux; CentOS via RHEL):** for distribution-packaged services,
  each candidate CVE is checked against the distribution's own fix data (FIXED /
  VULNERABLE / FIX_AVAILABLE / NO_FIX). This removes backport false positives
  and adds CVEs NVD lacks data for. See [docs/matching.md](docs/matching.md#9-distribution-advisories-internaldistro).
- **Web-fingerprinter ingest (`vulndb ingest`):** consumes httpx (`-td -json`)
  or webanalyze output and assesses the web applications they detect, mapping
  ~450 technology names to CPEs (`data/http_tech.json`, derived from the
  webappanalyzer corpus). Specialised web fingerprinting feeds the same engine
  instead of forcing everything through Nmap. Identities are leads (verify).
- **HTTP application fingerprints:** a curated map (`data/http_apps.json`)
  identifies web apps behind a generic web server (WordPress, Drupal, Joomla,
  Jenkins, …) from HTTP evidence — Server header, `<meta generator>`, response
  headers, title — adding the app as an identity beside the web-server CPE.
  Needs `nmap -sC` (http-* scripts) and `vulndb nmap`.
- **Product names without a CPE:** a curated map (`data/product_names.json`)
  identifies services Nmap names but gives no application CPE (ClamAV,
  CouchDB, cPanel, Apache JAMES, …), and marks Windows built-ins (RPC, LDAP,
  SMB, RDP) as OS components covered by the Windows assessment.
  `vulndb-update review-products` proposes further candidates for review.
- **Windows hosts at build level:** `vulndb nmap` reads the build that
  `rdp-ntlm-info` / `smb-os-discovery` report (`10.0.20348`), maps it to the
  release's NVD identities (`data/windows_builds.json`) and lists the CVEs that
  apply unless the host is patched, KEV entries first, with end-of-support
  status. See [docs/matching.md](docs/matching.md#10-windows-build-level-assessment-internalwindows).
  The release also decides NVD "running on" conditions for the host's
  services: CVEs that need Windows are confirmed, and CVEs that apply only on
  other operating systems are excluded.
- **Self-contained builder (`vulndb update` / `vulndb build`):** the binary
  itself fetches the real sources — NVD CVE JSON 2.0 feeds, the CISA KEV
  catalogue, five distributions' advisories (OSV.dev exports) and the
  webappanalyzer corpus — and loads them with the curated first-party data
  compiled into the binary (aliases, distro package map and lifecycle, Windows
  builds, product names, HTTP app fingerprints). No repository checkout or
  separate updater is needed on the build machine. `vulndb update` also runs
  automatically the first time you query a default database that does not exist
  yet.
- **Updater (Python, [`updater/`](updater/README.md)):** the original builder,
  kept as the porting oracle (byte-for-byte parity is checked against it) and
  for its curation commands `review-aliases` and `review-products`, which
  propose new `data/aliases.json` / `data/product_names.json` entries for human
  review.

Not yet: SUSE/Alpine advisories, the CVE List as a second source (evaluated and deferred,
see [docs/data-sources.md](docs/data-sources.md)).

## Build

Requires Go 1.27+. No CGO; the result is one static binary with the curated
first-party data embedded, so it builds a database without the repository on
disk.

```bash
make build          # -> bin/vulndb
make test           # go test ./...  (no network access needed)
make venv           # Python venv for the updater (stdlib-only) + pytest
make test-all       # Go tests + updater tests, incl. real-data end-to-end test
```

## Build a real database (Internet-connected machine)

```bash
make real-db        # bin/vulndb update: fetch NVD + KEV + OSV + webappanalyzer -> ./vulndb.sqlite
# or directly, to any path:
bin/vulndb --db ./vulndb.sqlite update          # sources cached in ~/.cache/vulndb
bin/vulndb --db ./vulndb.sqlite update --cache .cache/feeds   # choose the cache dir
make real-db-python # the Python updater (NVD + KEV core), kept as the oracle
```

Package it as a signed bundle and install it in the restricted network with
`vulndb bundle import`. The import verifies the signature, checksum, schema and
SQLite integrity, refuses rollbacks, and replaces the database atomically. See
[docs/deployment.md](docs/deployment.md).

```bash
make keygen                 # once: vulndb-signing.key (keep) + vulndb-signing.pub (copy to offline side)
make bundle                 # vulndb-YYYY-MM-DD.tar.gz (835 MB database -> 140 MB)
vulndb --db /opt/vulndb/vulndb.sqlite bundle import vulndb-2026-10-07.tar.gz --pubkey vulndb-signing.pub
```
- `vulndb info` shows how old the NVD data is, and warns after 7 days.
- It also shows how many CVEs have no CPE applicability data. Since April 2026
  NVD adds that data to only a minority of new CVEs, so recent vulnerabilities
  are under-represented. See [`updater/README.md`](updater/README.md).

## Create the synthetic fixture database

For development and tests there is a small **synthetic** fixture
(`testdata/fixtures/synthetic.json`). Its CVE IDs (`CVE-0000-*`), scores, KEV
and exploit entries are made up so tests are deterministic. They do not
describe real vulnerabilities, and the CLI warns whenever this data is loaded.

```bash
make fixture-db                     # creates ./vulndb.sqlite
# or
bin/vulndb --db ./vulndb.sqlite db init --fixture testdata/fixtures/synthetic.json
```

The database path is chosen as: `--db PATH`, else `$VULNDB_DB`, else
`./vulndb.sqlite`.

## Query a CPE

```bash
bin/vulndb query --cpe 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
bin/vulndb query --cpe 'cpe:/a:apache:http_server:2.4.49' --format json   # Nmap-style CPE 2.2
bin/vulndb --debug query --cpe 'cpe:/a:openbsd:openssh:8.9p1'              # explain every rule
```

Text output (abridged):

```text
Product:             apache http_server
Version:             2.4.49
Normalized CPE:      cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Identity confidence: EXACT

Candidate vulnerabilities: 4 version match, 1 undetermined

CVE-0000-0001    CRITICAL  CVSS 9.8 (v3)
  Public exploit: YES (exploit-db, metasploit)
  CISA KEV:       YES (added 2021-11-03)
  Version status: MATCH
  Confidence:     EXACT
  Match reason:   Exact supplied CPE matched vulnerability criteria
                  cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:* and detected version 2.4.49 is within
                  affected range (>= 2.4.49, < 2.4.51).
...
Undetermined (version applicability UNKNOWN; review manually):

CVE-0000-0006    MEDIUM    CVSS 4.3 (v3)
  ...
  Match reason:   ... applicability could not be determined: criteria requires target_hw "x64"
                  but supplied CPE does not specify it; ...
```

JSON output (abridged). `output_version` changes only when the layout breaks
compatibility:

```json
{
  "output_version": "1",
  "database": {
    "path": "vulndb.sqlite",
    "schema_version": "1",
    "database_version": "fixture-1",
    "created_at": "2026-10-06T06:06:00Z",
    "dataset": "synthetic-fixture"
  },
  "result": {
    "input": "cpe:/a:apache:http_server:2.4.49",
    "normalized_cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    "part": "a", "vendor": "apache", "product": "http_server", "version": "2.4.49",
    "identity_confidence": "EXACT",
    "comparator": "generic",
    "candidate_rules": 6,
    "match_count": 4,
    "unknown_count": 1,
    "vulnerabilities": [
      {
        "cve": "CVE-0000-0001",
        "description": "[SYNTHETIC] Path traversal in Apache HTTP Server. ...",
        "cvss": 9.8,
        "cvss_version": "3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_v3_score": 9.8,
        "cvss_v4_score": null,
        "severity": "CRITICAL",
        "cwe": "CWE-22",
        "published_at": "2021-10-05T00:00:00Z",
        "public_exploit": true,
        "exploit_sources": ["exploit-db", "metasploit"],
        "exploit_evidence": [
          {"source": "exploit-db", "reference": "EDB-ID:00001 (synthetic)", "reference_type": "exploit", "verified": true},
          {"source": "metasploit", "reference": "exploit/multi/http/synthetic_fixture", "reference_type": "module", "verified": true}
        ],
        "known_exploited": true,
        "known_ransomware": false,
        "kev_date_added": "2021-11-03",
        "match_confidence": "EXACT",
        "version_status": "MATCH",
        "applicability": "UNCONDITIONAL",
        "match_reason": "Exact supplied CPE matched vulnerability criteria cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:* and detected version 2.4.49 is within affected range (>= 2.4.49, < 2.4.51).",
        "matched_rules": [
          {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "version_range": ">= 2.4.49, < 2.4.51",
           "status": "MATCH", "reason": "version 2.4.49 is within affected range (>= 2.4.49, < 2.4.51)"}
        ]
      }
    ],
    "warnings": [
      "Matching is based on upstream product/version data. Distribution backported security fixes are only evaluated where a distribution verdict is shown (Ubuntu, Debian and Red Hat-family packages).",
      "Database contains SYNTHETIC test fixture data, not real vulnerability information."
    ]
  }
}
```

With `--debug`, a rule-by-rule trace goes to stderr and the JSON gains a
`rule_evaluations` array. stdout stays valid JSON.

### Result fields that matter

- `version_status`
  - `MATCH`: the version is inside the affected range.
  - `UNKNOWN`: the engine could not decide, e.g. no version supplied, an
    unparseable version, or criteria more specific than the supplied CPE.
    UNKNOWN is never turned into a match. NO_MATCH CVEs are not returned.
- `applicability: CONDITIONAL`: NVD says the CVE applies only together with
  another condition (typically a specific OS). That condition was not
  evaluated.
- `match_confidence` / `identity_confidence`
  - `EXACT`: the supplied CPE has a concrete version.
  - `LOW`: product only, no version.
- `match_reason`: a human-readable explanation, always present.

## Assess an Nmap scan

```bash
nmap -sV -oX scan.xml 10.0.0.0/24        # -sV is required; -O adds OS guesses (shown, not assessed)
bin/vulndb nmap scan.xml                  # compact per-host/per-port report
bin/vulndb nmap scan.xml --format json    # full structured report
nmap -sV -oX - 10.0.0.5 | bin/vulndb nmap -
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
    Identity: cpe:2.3:a:igor_sysoev:nginx:1.20.1:*:*:*:*:*:*:* [EXACT]
    Identity: cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:* [HIGH] (curated alias)
    CVE-0000-0101    HIGH      CVSS 7.7  exploit:YES KEV:NO  MATCH  [via alias, HIGH]
  8080/tcp http Mystery httpd 1.2
    Note: No application CPE reported for "Mystery httpd 1.2"; ... not assessed.
```

Each open port is one of:
- `ASSESSED`: an application CPE (reported by Nmap, or from a curated product
  name) was looked up, plus any curated aliases.
- `OS_COMPONENT`: a Windows built-in (RPC, LDAP, SMB, RDP, …), covered by the
  host's Windows build assessment. The text report lists these ports once per
  host ("Windows components, covered by the build assessment above: 135/tcp
  msrpc, 389/tcp ldap, …") instead of repeating a note for each.
- `UNIDENTIFIED`: the service was fingerprinted but has no application CPE and
  its name is not in the curated map.
- `NOT_PROBED`: Nmap only guessed the service from the port number.

OS and hardware CPEs are listed but never queried as if they were the service.
Windows hosts are assessed separately, at build level, when the scan includes
`rdp-ntlm-info` or `smb-os-discovery` output (`nmap -sV -sC`):

```text
192.0.2.10 (dc01.example.test)
  Windows: Windows Server 2022 (build 10.0.20348) [HIGH]
    Evidence: rdp-ntlm-info on 3389/tcp Product_Version 10.0.20348
    Server release because: Microsoft Windows Kerberos on 88/tcp (domain controllers run Windows Server)
    Support: mainstream support until 2026-10-13; extended support until 2031-10-14
    3957 CVEs apply unless patched: 107 in CISA KEV, 29 with public exploit evidence, 129 critical; 11 undetermined
    KEV, most recently added first:
    CVE-2026-85880   HIGH      CVSS 7.8  KEV added 2026-09-08
    CVE-2026-33824   CRITICAL  CVSS 9.8  KEV added 2026-08-18
    ...
```

The patch level (the update revision) is not visible to an unauthenticated
scan, so these are the release's CVEs that apply *unless patched*, not
findings. When a build is shared (14393 is Windows Server 2016 and Windows 10
1607) and nothing on the host tells them apart, both are listed with `MEDIUM`
confidence.

Flags on a CVE line mark results to review: `CONDITIONAL` (another condition,
such as a specific OS, was not evaluated), `ransomware` (known use per KEV), and
`via alias` (found only through a curated alias identity).

### Inline in Nmap (NSE)

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
|   ...
```

How it works:
- The script is a thin adapter. Per port, it writes the service fingerprint
  and the host's other open ports (for distribution evidence) to a temporary
  file, runs `vulndb nse --request FILE`, and prints the answer.
- Target-controlled banner text never appears on a command line.
- Each port takes about 12 ms.
- With `-oX`, the results are also stored as structured `<elem>` data.

Script arguments:
- `vulndb.bin`, `vulndb.db`: paths to the binary and database;
- `vulndb.max` (default 10): CVEs listed per port;
- `vulndb.mincvss`: hide lower-scored CVEs;
- `vulndb.showall`: also list undetermined CVEs and ones fixed in the
  distribution package.

Ports with nothing to report print nothing. Configuration errors (wrong binary
or database path) are always shown. Unix-like systems only.

### Distribution-packaged hosts

A real scan of an Ubuntu 24.04 machine (`OpenSSH 9.6p1 Ubuntu 3ubuntu13.18`):

```text
  Distribution release (from an exact package version on this host): 24.04
  22/tcp ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
    Distribution: Ubuntu: RESOLVED (openssh 24.04, installed 1:9.6p1-3ubuntu13.18) - ...
    CVE-2026-73282   MEDIUM    CVSS 4.8  exploit:NO  KEV:NO  MATCH  [Ubuntu: VULNERABLE]
    ...
    + 16 fixed in the Ubuntu package: CVE-2024-6387, CVE-2026-60002, ...
```

Upstream matching alone reported 22 CVEs, including regreSSHion.
- Ubuntu's data shows 16 of them fixed in the installed package.
- Three are fixed only in the newer `3ubuntu13.19`, which `apt` on that
  machine confirmed as the pending update.

Debian works the same way. A revision such as `2+deb12u3` pins Debian 12 even
when that exact version is not in the data. Debian 11 (LTS) fixes come from
DLA advisories.

Red Hat-family hosts (RHEL, Rocky Linux, AlmaLinux, CentOS):
- **Distribution inferred per host.** Their OpenSSH banner names no
  distribution (`OpenSSH_8.7`), so it is taken from other services on the host
  (Apache `(Red Hat Enterprise Linux)`). It is used only if the advisory data
  knows that upstream version, because the software might be self-built.
- **No package release is visible,** so verdicts are `FIX_AVAILABLE`, `FIXED`
  or `VULNERABLE` by upstream version.
- **AppStream module streams** (nginx 1.16 / 1.18 / 1.20 on RHEL 8) are judged
  only by their own stream's fixes.
- **Red Hat-family advisories contain only fixes**, so there is no `NO_FIX`;
  missing data is `NO_DATA`.

Only OpenSSH on Debian/Ubuntu shows the package revision in its banner. Apache, nginx, Postfix
and others show only "(Ubuntu)" or "(Debian)", so their verdicts are about the
release:
- `FIXED` when no package of that upstream version in the release is affected;
- `FIX_AVAILABLE` when the fix came in a later package revision, so the host is
  patched only if it is up to date.

For a single CPE, pass the distribution yourself:

```bash
bin/vulndb query --cpe cpe:/a:openbsd:openssh:9.6p1 --distro ubuntu --package-version 1:9.6p1-3ubuntu13.18
bin/vulndb query --cpe cpe:/a:openbsd:openssh:9.2p1 --distro debian --package-version 1:9.2p1-2+deb12u3
bin/vulndb query --cpe cpe:/a:openbsd:openssh:8.7p1 --distro redhat --package-version 0:8.7p1-34.el9_3
```

## Utility commands

```bash
bin/vulndb info        # versions, NVD data age, KEV version, coverage; warns if stale or synthetic
bin/vulndb db verify   # SQLite integrity, foreign keys, criteria re-parse vs index columns
bin/vulndb db stats    # row counts and file size
bin/vulndb bundle keygen|create|verify|import   # signed transport bundles (docs/deployment.md)
```

Exit codes: `0` success (including "no results"), `1` runtime error (missing
or corrupt database, incompatible schema, malformed CPE, insufficient identity,
failed verify), `2` usage error (unknown command or flag, unsupported
`--format`).

## Current limitations

- Services are assessed only through the CPEs Nmap reports. A service with a
  product name but no CPE is reported as `UNIDENTIFIED` (product-name
  resolution is planned).
- Aliases cover 74 hand-reviewed Nmap identities. Others that NVD records under
  a different vendor are missed until reviewed (`vulndb-update review-aliases`
  lists candidates).
- Version comparison: OpenSSH has its own comparator; everything else uses a
  conservative generic one. Distro (`-1ubuntu1`), RPM, PEP 440 and similar
  schemes give UNKNOWN.
- AND/negated NVD configurations are flagged, not evaluated, because one CPE
  can't satisfy several conditions. The exception is "running on" platform
  conditions on Windows hosts whose build was assessed; Linux hosts' platform
  conditions are not evaluated yet.
- Distro backports are not evaluated (see above).
- NVD is currently the only applicability source, and it covers only part of
  recent CVEs (see above). An empty result is not evidence of no vulnerability.
- Exploit evidence is limited to references NVD tagged `Exploit`, and none of it
  is verified.
- Releases past end of life are flagged (`data/distro_releases.json`): their
  distributions no longer publish advisory data. Example: Debian 11, whose LTS
  ended 2026-08-31.
- Windows hosts are assessed per build, not per patch level. An
  unauthenticated scan cannot see installed updates, so the result is the
  release's exposure ("applies unless patched"), not a vulnerability finding.
  It needs `-sC` (or `--script rdp-ntlm-info,smb-os-discovery`) and works in
  `vulndb nmap` only, not in the NSE adapter. Windows services themselves
  (SMB, RDP, LDAP) are still `UNIDENTIFIED`.
- Debian 11 (LTS) verdicts exist only for CVEs with a DLA/DSA advisory.
  Debian's per-CVE data barely covers LTS, so most other CVEs are `NO_DATA`
  there. On a real bookworm OpenSSH, 26 upstream matches split into FIXED,
  VULNERABLE and NO_FIX; on bullseye, 24 of 28 are `NO_DATA`.
- Components that NVD attributes to an operating system are invisible to a
  product CPE. For example, IIS vulnerabilities since about 2017 are listed
  against Windows CPEs, so `cpe:/a:microsoft:internet_information_services:10.0`
  finds none of them.
- Products with enormous rule sets are slower. A `linux_kernel` 5.15 query
  reads 53k of the kernel's 163k rules and takes about 0.7 s, versus 4–13 ms
  for typical services.
- NVD itself contains a handful of malformed criteria (e.g. unescaped
  parentheses in Cisco IOS versions). They are skipped and counted in
  `nvd_rules_skipped`.

## Layout

```text
cmd/vulndb/          CLI and end-to-end tests
internal/cpe/        CPE 2.2/2.3 parsing, normalisation, attribute matching
internal/version/    comparator interface, generic comparator, range evaluation
internal/database/   SQLite access, schema checks, verify/stats, fixture import
internal/identity/   candidate identities: aliases, platform CPEs, distro detection
internal/distro/     distribution advisory verdicts (release inference, dpkg comparison)
internal/matcher/    rule evaluation, per-CVE aggregation, enrichment, ordering
internal/nmap/       Nmap XML parser and scan assessment
internal/windows/    Windows build-level assessment (build evidence -> release CPEs)
internal/output/     text and JSON rendering
internal/bundle/     signed transport bundles (create, verify, atomic import)
data/                curated first-party data, embedded in the binary (data/embed.go)
data/aliases.json    curated vendor/product aliases (loaded into the database)
data/distro_packages.json  curated CPE -> distribution source package map
data/distro_releases.json  curated distribution release lifecycle (end of life)
data/windows_builds.json   curated Windows build -> release, NVD CPEs, lifecycle
data/product_names.json    curated Nmap product names (no CPE) -> NVD identity or OS component
data/http_apps.json        curated HTTP fingerprints (Server/generator/header/title) -> web-app CPE
data/http_tech.json        web-fingerprinter tech name -> CPE for `vulndb ingest`; NOT embedded,
                           GPL-3.0-derived and gitignored, built from the webappanalyzer corpus
scripts/gen_http_tech.py   regenerates data/http_tech.json from a webappanalyzer checkout
schema/schema.sql    database schema (embedded in the binary)
updater/             Python updater: porting oracle + curation (review-aliases, review-products)
testdata/fixtures/   synthetic test data
testdata/nvd/        real NVD/KEV records for updater and end-to-end tests
testdata/contract/   shared Go/Python vectors (CPE canonicalisation, RPM ordering, version keys)
testdata/nmap/       a real Nmap scan and hand-written multi-host samples
testdata/osv/        real Ubuntu, Debian, Red Hat, Rocky and AlmaLinux OSV advisory records
docs/matching.md     matching semantics
docs/data-sources.md source coverage measurements and decisions
docs/deployment.md   build -> signed bundle -> offline import
nse/vulndb.nse       Nmap script adapter (nmap -sV --script vulndb)
```

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you state otherwise, any contribution you submit for
inclusion is dual-licensed as above, without additional terms.

Vulnerability and fingerprint **data** is fetched at build/update time under
its own license and is not part of this source tree — see [NOTICE](NOTICE).
In particular the web technology → CPE map is derived from the GPL-3.0
[webappanalyzer](https://github.com/enthec/webappanalyzer) corpus by
`scripts/gen_http_tech.py`.
