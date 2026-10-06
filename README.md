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
- Does not evaluate Linux distribution backported fixes yet. Ubuntu, Debian,
  RHEL, etc. often patch while keeping the upstream version string, so
  upstream-based matches on distro packages can be false positives.
- Does not run, download or ship exploit code; it only records that exploit
  references exist.

## Status: milestone 1

Implemented: CPE 2.2/2.3 parsing and normalisation, generic version
comparator, range evaluation (MATCH / NO_MATCH / UNKNOWN), NVD configuration
structure (AND/OR) awareness, KEV and exploit enrichment, text and JSON
output, debug trace, database init/verify/stats, synthetic fixture dataset.

Not yet: real NVD/KEV data (Python updater), Nmap XML input, product-name /
alias resolution, distro advisories, NSE adapter.

## Build

Requires Go 1.27+. No CGO; the result is one static binary.

```bash
make build          # -> bin/vulndb
make test           # go test ./...  (no network access needed)
```

## Create the fixture database

The only data available in milestone 1 is a small **synthetic** fixture
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
      "Matching is based on upstream product/version data. Linux distribution backported security fixes are not evaluated.",
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

## Utility commands

```bash
bin/vulndb info        # schema/database version, creation time, age, dataset; warns if stale (>30 days) or synthetic
bin/vulndb db verify   # SQLite integrity, foreign keys, criteria re-parse vs index columns
bin/vulndb db stats    # row counts and file size
```

Exit codes: `0` success (including "no results"), `1` runtime error (missing
or corrupt database, incompatible schema, malformed CPE, insufficient identity,
failed verify), `2` usage error (unknown command or flag, unsupported
`--format`).

## Current limitations

- Only exact CPE input. Nmap product strings (`Apache httpd`) and Nmap's
  legacy vendor names (e.g. `igor_sysoev:nginx` vs NVD `f5:nginx`) are not
  resolved yet. The `aliases` table exists, but nothing uses it so far.
- One conservative, generic version comparator. Distro (`-1ubuntu1`), RPM,
  PEP 440 and other schemes give UNKNOWN.
- OpenSSH patch levels: Nmap reports `8.9p1`, while some NVD rules use version
  `8.9` with update `p1`. Those rules come back as UNKNOWN, not as a match.
- AND/negated NVD configurations are flagged, not evaluated, because one CPE
  can't satisfy several conditions.
- Distro backports are not evaluated (see above).
- No real vulnerability data until the updater (next milestone) exists.

## Layout

```text
cmd/vulndb/          CLI and end-to-end tests
internal/cpe/        CPE 2.2/2.3 parsing, normalisation, attribute matching
internal/version/    comparator interface, generic comparator, range evaluation
internal/database/   SQLite access, schema checks, verify/stats, fixture import
internal/matcher/    rule evaluation, per-CVE aggregation, enrichment, ordering
internal/output/     text and JSON rendering
schema/schema.sql    database schema (embedded in the binary)
testdata/fixtures/   synthetic test data
docs/matching.md     matching semantics
```
