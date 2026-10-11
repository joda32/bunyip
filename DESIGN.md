# Bunyip — Design Specification

## 1. Purpose

Bunyip is a lightweight, offline vulnerability correlation engine intended for internal and restricted networks where Internet access is unavailable.

The system consumes software/service observations—initially from Nmap—and correlates detected CPEs, products, versions, and banners against a locally stored vulnerability database built from free/open vulnerability intelligence.

The primary question it answers is:

> Given this detected product and version, which CVEs plausibly apply, and is there evidence of a public exploit or known exploitation in the wild?

It is **not** intended to become a general-purpose vulnerability scanner or to reproduce the full Vulners platform.

---

## 2. Design Goals

1. Fully functional without Internet connectivity during scanning/querying.
2. Consume Nmap CPE, product, version, banner, service, and port information.
3. Prefer exact CPE-based correlation where available.
4. Fall back to normalized product/version matching when CPE data is unavailable.
5. Preserve vulnerability version-range semantics rather than flattening everything into simple product-to-CVE mappings.
6. Identify whether public exploit evidence exists.
7. Identify vulnerabilities present in CISA KEV / known exploitation datasets.
8. Return a transparent match confidence and explanation.
9. Be easy to transport into isolated networks: ideally one executable plus one database file.
10. Keep Nmap integration thin so the correlation engine can later support other discovery tools.

---

## 3. Non-Goals for MVP

The MVP will **not**:

- exploit vulnerabilities;
- validate that a public exploit works against the target;
- automatically execute exploit code;
- perform authenticated patch assessment;
- guarantee patch state from banners alone;
- initially resolve all Linux distribution backport cases;
- use AI/LLMs for vulnerability matching;
- require Neo4j, Elasticsearch, PostgreSQL, Redis, or other infrastructure;
- provide a web UI;
- attempt to replace Nmap service fingerprinting;
- produce a proprietary risk score presented as objective truth.

---

## 4. High-Level Architecture

```text
                 INTERNET-CONNECTED UPDATE SYSTEM

 NVD CVE/CPE/Match ─┐
 CISA KEV ──────────┼──> ETL / Normalisation ──> SQLite Database
 Exploit Sources ───┘                                  │
                                                      │
                                      Signed/hashed update bundle
                                                      │
======================================================│====
                 OFFLINE / RESTRICTED NETWORK         │
                                                      ▼
                                                Local SQLite DB
                                                      │
                                             Vulnerability Engine
                                              /       |        \
                                           CLI      Nmap NSE   future API
```

The core engine must not depend on Nmap. Nmap is simply the first input adapter/client.

---

## 5. Proposed Technology Stack

### Runtime / Query Engine

**Go** is preferred for the query engine because it provides:

- simple deployment;
- a single compiled executable;
- good performance;
- straightforward JSON output;
- good SQLite support;
- easy integration with future tooling.

### Updater / ETL

**Python** is preferred initially for ingestion because parsing and transforming large JSON datasets is faster to develop and easier to iterate.

The updater is expected to run on an Internet-connected system, so deployment simplicity is less important than for the offline query engine.

### Database

**SQLite** for MVP.

Reasons:

- no database server;
- portable single-file database;
- mature indexing/query capabilities;
- simple backup/import/update process;
- sufficient scale for the intended workload.

---

## 6. Primary Data Sources

Initial sources should be limited to trustworthy, freely accessible datasets.

### Required

- NVD CVE data
- NVD CPE Dictionary
- NVD CPE Match Criteria
- CISA Known Exploited Vulnerabilities (KEV)

### Exploit Evidence

Add sources incrementally. Candidate evidence sources include:

- exploit references already present in vulnerability records;
- Exploit-DB metadata where licensing/distribution permits;
- Metasploit module metadata;
- other curated open-source exploit references.

The database should record **evidence that an exploit exists**, not ingest or redistribute exploit source code unless explicitly added as a later feature with appropriate licensing review.

---

## 7. Core Data Flow

```text
Nmap scan
   │
   ├─ CPE available ───────────────┐
   │                               │
   └─ product/version/banner ──> Identity Resolver
                                   │
                                   ▼
                             Canonical Product/CPE
                                   │
                                   ▼
                           Version Applicability
                                   │
                                   ▼
                              Matching CVEs
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                   Exploit Evidence       CISA KEV
                         │                   │
                         └─────────┬─────────┘
                                   ▼
                           Ranked/annotated result
```

---

## 8. Nmap Input Model

The first integration should consume Nmap XML because it contains structured service fingerprinting information.

Relevant fields include:

- host/IP;
- protocol;
- port;
- service name;
- product;
- version;
- extra info;
- operating system hints where useful;
- CPE values;
- tunnel/SSL metadata;
- raw service/banner information where available.

Example conceptual observation:

```json
{
  "host": "10.10.10.20",
  "port": 443,
  "protocol": "tcp",
  "service": "https",
  "product": "Apache httpd",
  "version": "2.4.49",
  "extra_info": "Ubuntu",
  "cpes": [
    "cpe:/a:apache:http_server:2.4.49"
  ]
}
```

---

## 9. Software Identity Resolution

This is expected to be one of the hardest and most important components.

### Resolution Order

1. Exact CPE supplied by Nmap.
2. Normalized CPE equivalent / CPE 2.2-to-2.3 conversion.
3. Exact vendor + product + version mapping.
4. Known alias mapping.
5. Product/version mapping without vendor.
6. Banner-derived candidate mapping.
7. Fuzzy candidate mapping only when explicitly enabled.

### Alias Examples

```text
Nmap                    Canonical
-----                    ---------
Apache httpd             apache:http_server
Microsoft IIS httpd      microsoft:internet_information_services
OpenSSH                  openbsd:openssh
nginx                    f5:nginx / nginx:nginx depending canonical dataset
```

Aliases should be data-driven rather than embedded throughout application code.

### Confidence

Every result must include a confidence classification and match reason.

Suggested levels:

| Level | Example |
|---|---|
| EXACT | Nmap supplied an exact CPE and version |
| HIGH | deterministic product/version mapping to one canonical CPE |
| MEDIUM | alias/banner mapping with strong product/version evidence |
| LOW | product-only or ambiguous candidate |
| UNKNOWN | insufficient evidence |

Do not silently convert an ambiguous identity into a high-confidence vulnerability result.

---

## 10. CPE Handling

Internally normalize CPE values into a canonical representation, preferably CPE 2.3 formatted strings plus parsed components.

Store at minimum:

- part;
- vendor;
- product;
- version;
- update;
- edition;
- language;
- remaining CPE attributes where applicable.

Support input from older Nmap CPE 2.2-style values.

---

## 11. Vulnerability Applicability

A CVE must not be considered applicable simply because the vendor/product names match.

The engine must evaluate version constraints such as:

```text
versionStartIncluding
versionStartExcluding
versionEndIncluding
versionEndExcluding
```

Preserve these conditions from source data.

Example:

```text
product: apache:http_server
start including: 2.4.0
end excluding:    2.4.51
```

A detected version should be evaluated against the complete applicability rule.

---

## 12. Version Comparison

Version handling must be implemented behind a pluggable comparator interface.

Initial comparators may include:

- generic dotted/numeric versions;
- semantic versions where applicable;
- Debian/dpkg versions;
- RPM versions;
- PEP 440;
- Windows build versions;
- OpenSSH-style versions;
- conservative generic token comparator.

The engine must support:

```text
MATCH
NO_MATCH
UNKNOWN
```

`UNKNOWN` is preferable to an unsafe guess.

Example problematic versions:

```text
1.9
1.10
8.9p1
8.9p2
7.4.33-1ubuntu1
2.4.49-r0
10.0.19045
1.2.3.RELEASE
```

---

## 13. Linux Distribution Backports

This is an explicit accuracy limitation for the MVP.

A Linux distribution may backport a security fix while retaining an upstream-looking product version. Therefore:

```text
OpenSSH 8.x on Ubuntu != necessarily vulnerable upstream OpenSSH 8.x
```

MVP results should clearly indicate when matching is based on upstream product/version information and distro patch state has not been evaluated.

Future enrichment may include:

- Ubuntu USN;
- Debian DSA/security tracker;
- Red Hat RHSA/OVAL;
- Alpine SecDB;
- other vendor advisory datasets.

---

## 14. Proposed Database Schema

This is a logical schema; implementation may adjust names and normalization.

### `cves`

```text
id
cve_id UNIQUE
published_at
modified_at
description
cvss_v3_score
cvss_v3_vector
cvss_v4_score
cvss_v4_vector
severity
cwe
```

### `cpe_products`

```text
id
cpe23 UNIQUE
part
vendor
product
version
update_value
edition
language
title
```

### `cve_matches`

```text
id
cve_id
criteria
vulnerable
version_start_including
version_start_excluding
version_end_including
version_end_excluding
```

### `cve_match_products`

Maps match criteria/rules to concrete CPE product records where appropriate.

```text
match_id
cpe_product_id
```

### `exploit_evidence`

```text
id
cve_id
source
reference
reference_type
verified
metadata_json
```

### `kev`

```text
cve_id UNIQUE
vendor_project
product
vulnerability_name
date_added
due_date
known_ransomware
notes
```

### `aliases`

```text
id
observed_vendor
observed_product
canonical_vendor
canonical_product
canonical_cpe_prefix
source
confidence
```

### `database_metadata`

```text
key
value
```

Examples:

```text
database_version
created_at
nvd_last_modified
kev_last_modified
schema_version
```

---

## 15. Query Engine

The core query engine should expose internal functions roughly equivalent to:

```text
ResolveObservation(observation) -> []ProductCandidate
FindApplicableCVEs(candidate) -> []VulnerabilityMatch
EnrichVulnerabilities(matches) -> []EnrichedVulnerability
```

A vulnerability result should contain:

```json
{
  "cve": "CVE-YYYY-NNNN",
  "description": "...",
  "cvss": 9.8,
  "severity": "CRITICAL",
  "public_exploit": true,
  "exploit_sources": ["..."],
  "known_exploited": true,
  "known_ransomware": false,
  "match_confidence": "EXACT",
  "match_reason": "Exact Nmap CPE and applicable version range",
  "version_status": "MATCH"
}
```

---

## 16. CLI Design

Suggested executable:

```text
bunyip
```

### Query Exact CPE

```bash
bunyip query --cpe 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
```

### Query Product

```bash
bunyip query --product 'Apache httpd' --version '2.4.49'
```

### Query Nmap XML

```bash
bunyip nmap scan.xml
```

### JSON Output

```bash
bunyip nmap scan.xml --format json
```

### Useful Utility Commands

```bash
bunyip info
bunyip db verify
bunyip db stats
```

`info` should show database age/source metadata so an operator immediately knows whether an offline database is stale.

---

## 17. Nmap Integration

Do not put the vulnerability engine into Lua.

The NSE should be a thin adapter that uses Nmap service information and queries the local engine.

Potential deployment:

```text
bunyip
bunyip.sqlite
bunyip.nse
```

Possible usage:

```bash
nmap -sV --script bunyip <target>
```

The NSE output should remain concise and prioritised.

Example:

```text
443/tcp open https Apache httpd 2.4.49
| bunyip:
|   CVE-2021-XXXXX  CRITICAL  CVSS 9.8
|     Public exploit: YES
|     CISA KEV: YES
|     Match: EXACT
|   CVE-2021-YYYYY  HIGH      CVSS 7.5
|     Public exploit: YES
|     CISA KEV: NO
|     Match: EXACT
```

Consider whether invoking an external binary from NSE is reliable/portable enough. If not, the first Nmap integration can instead consume Nmap XML after scanning. The core engine must remain independent either way.

---

## 18. Prioritisation

Do not hide prioritisation behind an opaque proprietary score in the MVP.

Expose useful factors:

- CVSS/severity;
- public exploit evidence;
- CISA KEV;
- known ransomware use where supplied;
- remote/network attack vector;
- authentication/privileges required;
- user interaction;
- match confidence.

The CLI may sort using a transparent policy such as:

1. KEV + public exploit;
2. KEV;
3. public exploit;
4. CVSS/severity;
5. confidence.

Later, an optional documented priority score can be added.

---

## 19. Update Architecture

Updater commands could be provided by a separate utility:

```text
bunyip-update
```

### Online Update

```bash
bunyip-update sync
```

Responsibilities:

1. fetch source datasets;
2. validate downloads;
3. normalize data;
4. build a fresh SQLite database;
5. run integrity checks;
6. generate metadata;
7. package the database into a transport bundle.

### Bundle

Example:

```text
bunyip-2026-10-06.tar.zst
  manifest.json
  bunyip.sqlite
  checksums.sha256
  signature.sig       # optional initially, recommended later
```

### Offline Import

```bash
bunyip-update import bunyip-2026-10-06.tar.zst
```

The import process should:

- verify checksum;
- verify schema compatibility;
- verify signature when signing is enabled;
- display source/database age;
- atomically replace the existing database only after validation succeeds.

---

## 20. Security Considerations

Although the application is defensive/research tooling, the update pipeline should be treated as a supply-chain boundary.

Requirements:

- HTTPS for source retrieval;
- source allow-list;
- checksum verification where upstream provides hashes;
- generated bundle checksums;
- optional signing of offline bundles;
- strict parsing of untrusted JSON/XML;
- no execution of exploit code;
- no automatic fetching of arbitrary URLs referenced by CVEs during offline query;
- parameterized SQLite queries;
- bounded parsing/resource limits for Nmap XML.

---

## 21. Performance Requirements

MVP targets:

- exact CPE lookup: typically <100 ms on a normal workstation;
- product/version query: typically <250 ms;
- process an ordinary internal Nmap XML scan without excessive memory consumption;
- database size should remain practical for copying into restricted networks;
- updater may take minutes because it is an offline preparation operation rather than an interactive query.

Indexes should be designed around:

- CPE;
- vendor/product;
- CVE ID;
- match criteria;
- KEV CVE ID;
- exploit evidence CVE ID.

---

## 22. Result Accuracy and False Positives

Every result should distinguish:

```text
Detected software identity confidence
        +
Version applicability confidence/status
        +
Known data limitations
```

Example:

```text
CVE-XXXX-YYYY
Match confidence: HIGH
Version status: MATCH
Reason: Product/version uniquely resolved to canonical CPE and version is inside affected range.
Warning: Ubuntu package backport status was not evaluated.
```

Never imply that banner-based matching proves a host is vulnerable.

Use language such as:

- "potentially affected";
- "version appears within affected range";
- "candidate vulnerability".

---

## 23. Testing Strategy

### Unit Tests

Must cover:

- CPE 2.2 parsing;
- CPE 2.3 parsing;
- CPE normalization;
- aliases;
- exact identity resolution;
- ambiguous identity resolution;
- inclusive/exclusive version boundaries;
- unknown version handling;
- each implemented version comparator;
- exploit/KEV enrichment;
- database migrations/schema checks.

### Golden Test Fixtures

Create small static fixtures containing known examples such as:

- Apache HTTP Server;
- nginx;
- OpenSSH;
- Microsoft IIS;
- one Windows service/product;
- one intentionally ambiguous banner;
- one distro-backport warning case.

Tests should not require Internet access.

### Integration Tests

Provide sample Nmap XML and expected JSON results.

---

## 24. Logging and Diagnostics

Support a verbose/debug mode:

```bash
bunyip --debug query ...
```

Useful diagnostic information:

```text
Observed: Apache httpd 2.4.49
CPE supplied: cpe:/a:apache:http_server:2.4.49
Normalized: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Identity confidence: EXACT
Comparator: generic
Matched criteria: ...
Applicable CVEs: 4
```

This will be critical for troubleshooting false positives and identity mappings.

---

## 25. Suggested Repository Structure

```text
bunyip/
├── README.md
├── LICENSE
├── Makefile
├── docs/
│   ├── architecture.md
│   ├── data-sources.md
│   └── matching.md
├── cmd/
│   └── bunyip/
├── internal/
│   ├── cpe/
│   ├── database/
│   ├── identity/
│   ├── matcher/
│   ├── version/
│   ├── nmap/
│   └── output/
├── updater/
│   ├── README.md
│   ├── requirements.txt or pyproject.toml
│   ├── sources/
│   ├── transform/
│   └── build_db.py
├── nse/
│   └── bunyip.nse
├── schema/
│   ├── schema.sql
│   └── migrations/
├── testdata/
│   ├── nmap/
│   └── fixtures/
└── tests/
```

---

## 26. MVP Delivery Phases

### Phase 1 — Database Foundation

- define SQLite schema;
- ingest a small static NVD fixture;
- CPE normalization;
- exact CPE lookup;
- version-range evaluation;
- CLI JSON/text output.

**Exit criterion:** an exact CPE/version can be queried offline and return correct candidate CVEs.

### Phase 2 — Real Data Updater

- ingest NVD CVE data;
- ingest CPE dictionary/match data;
- ingest CISA KEV;
- build complete SQLite DB;
- metadata/staleness reporting.

**Exit criterion:** reproducible database build from current public datasets.

### Phase 3 — Nmap XML Integration

- parse Nmap XML;
- query all detected services;
- output host/port/service vulnerability results;
- support JSON and human-readable formats.

**Exit criterion:** `bunyip nmap scan.xml` provides useful offline results.

### Phase 4 — Identity Resolver

- alias table;
- product/version fallback when CPE absent;
- confidence levels;
- ambiguity handling;
- diagnostic output.

### Phase 5 — Exploit Enrichment

- add public exploit evidence sources;
- retain provenance/source references;
- sort/prioritize KEV/exploit-backed vulnerabilities.

### Phase 6 — NSE Adapter

- investigate safe/reliable NSE-to-engine integration;
- implement only if it improves usability over XML post-processing.

---

## 27. Future Enhancements

Only after the MVP is reliable:

- Linux distro advisory correlation;
- EPSS enrichment if an offline redistribution/update model is suitable;
- SBOM input (CycloneDX/SPDX);
- CMDB/EDR software inventory input;
- Masscan/httpx/custom scanner adapters;
- REST API mode;
- richer reporting/export;
- local web UI;
- operator-maintained aliases;
- signed incremental/delta updates;
- confidence tuning based on real scan datasets.

---

## 28. Key Engineering Risks

### 1. Product Identity Mapping

Likely the largest source of incorrect results. Solve transparently with aliases, candidate lists, confidence, and diagnostics.

### 2. Version Semantics

Vendor-specific version schemes can make generic comparisons incorrect. Unknown must be a first-class result.

### 3. Distribution Backports

Upstream version matching creates Linux false positives. Clearly communicate the limitation before adding distro-specific advisory logic.

### 4. NVD Applicability Complexity

Configuration/applicability data can contain logical relationships more complicated than one CPE range. Avoid prematurely simplifying source semantics in ways that produce incorrect matches.

### 5. Data Volume

The updater must stream/batch data where possible instead of assuming complete source datasets fit comfortably in memory.

### 6. Exploit Evidence Quality

A GitHub repository mentioning a CVE is not equivalent to a verified exploit. Track source/provenance and avoid binary claims unsupported by good evidence.

---

## 29. Definition of Success

The MVP is successful when an operator can:

```bash
nmap -sV -oX scan.xml 10.0.0.0/24
bunyip nmap scan.xml
```

on an isolated network and receive useful output similar to:

```text
10.0.0.20:443/tcp
Apache httpd 2.4.49
Identity: EXACT

CVE-2021-XXXXX  CRITICAL  CVSS 9.8
  Public exploit: YES
  CISA KEV: YES
  Version: MATCH

CVE-2021-YYYYY  HIGH      CVSS 7.5
  Public exploit: YES
  CISA KEV: NO
  Version: MATCH
```

with no Internet dependency and with enough match explanation to understand why each CVE was returned.

---

## 30. Guiding Principle

Keep the project focused:

> **Identify software well, evaluate vulnerability applicability correctly, enrich with useful prioritisation evidence, and work completely offline.**

Do not add complexity until those four things are reliable.
