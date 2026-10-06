# vulndb-update

This tool builds the Offline VulnDB SQLite database from public data. It runs
on an **Internet-connected** machine; you then copy the resulting
`vulndb.sqlite` into the restricted network next to the `vulndb` binary.

It uses only the Python standard library (3.11+); pytest is needed only for
the tests.

```bash
make venv                       # .venv with the updater installed + pytest
make real-db                    # download/refresh feeds, build ./vulndb.sqlite
# or directly:
.venv/bin/vulndb-update build --out vulndb.sqlite --cache .cache/feeds
.venv/bin/vulndb-update build --out vulndb.sqlite --offline-from .cache/feeds   # rebuild, no network
```

## Sources

| Source | URL | Upstream refresh |
|---|---|---|
| NVD CVE JSON 2.0 yearly feeds (2002–current) | `https://nvd.nist.gov/feeds/json/cve/2.0/` | daily |
| NVD `modified` feed (changes in the last 8 days) | same | about every 2 hours |
| CISA KEV catalogue | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | when CISA adds entries (typically several times a week) |

How the build uses them:
- The yearly feeds are loaded first. The `modified` feed is then applied on top:
  a newer copy of a CVE replaces the older one, and CVEs that have since been
  rejected are removed. The result is at most about 2 hours behind NVD at build
  time.
- The age of an offline database therefore depends on how often you rebuild it
  and carry it across. `vulndb info` warns when the NVD data is older than 7 days.
- Feeds are cached. A feed is downloaded again only when the sha256 in its
  `.meta` file changes, so a daily refresh mostly downloads the current year and
  `modified`.

## Coverage warning

Since April 2026 NIST fully analyses only a minority of new CVEs (those in KEV,
software used by the US federal government, and EO 14028 "critical software").
Many recent CVEs therefore have **no CPE configurations** and can never be
returned by a query.
- The build records this as `nvd_cves_without_configurations`, and `vulndb info`
  shows the percentage.
- Adding the CVE List (`cvelistV5`, including CISA Vulnrichment CPEs) is the
  planned next source.

## What gets stored

- **CVE descriptions:** English text.
- **CVSS:** v3.1 is preferred over v3.0, and v4.0 is stored too. Within a version,
  the `Primary` score wins, then NVD's own. Severity comes from v3, else v4, else v2.
- **CWE:** identifiers, comma-joined.
- **Applicability:** the full configuration → node → rule tree, with `criteria`
  stored verbatim. The lookup columns are derived by `cpe.py`, which must match
  the Go engine; both are tested against `testdata/contract/cpe_vectors.json`.
  Rules whose criteria can't be parsed are skipped and counted, not fatal.
- **Exploit evidence:** reference URLs that NVD tagged `Exploit`, stored as
  `source=nvd-reference` and `verified=0`. That a reference exists does not mean
  the exploit works.
- **KEV:** every catalogue entry; unknown new fields are ignored.

## Aliases

`data/aliases.json` lists hand-reviewed aliases from identities that Nmap
reports to the vendor/product names NVD uses. Examples:
- `igor_sysoev:nginx` → `f5:nginx`, `nginx:nginx`;
- `mysql:mysql` → `oracle:mysql`.

Every build loads them into the `aliases` table, so they travel with the
database. The build reports any alias target that has no NVD rules.

To propose new aliases, e.g. after an Nmap upgrade:

```bash
.venv/bin/vulndb-update review-aliases --db vulndb.sqlite --nmap-probes /usr/share/nmap/nmap-service-probes
```

This lists two kinds of candidate, skipping identities that are already
curated or rejected:
- Nmap identities whose product NVD records only under another vendor;
- Nmap identities where NVD has newer CVEs under another vendor.

**Review each one by hand.** Product-name similarity is wrong about a third
of the time (e.g. `microsoft:kerberos` is not MIT Kerberos). Add genuine
renames or acquisitions to `aliases`, and record false matches under
`rejected` so they aren't proposed again.

## Safety

- Downloads use HTTPS only and only from `nvd.nist.gov` and `www.cisa.gov`
  (redirects included). Each file is size-capped and retried with backoff.
- Every NVD feed is checked against the sha256 and size in its `.meta` file
  (computed over the uncompressed JSON) before it is cached or used, including
  with `--offline-from`.
- The KEV catalogue has no published checksum; its structure is validated
  instead.
- The database is built in `.<name>.building`. Before it replaces the target, it
  must pass these self-checks:
  - SQLite integrity and foreign keys;
  - lookup columns agree with criteria;
  - completeness floors (≥ 200k CVEs, ≥ 1k KEV entries).
  
  A failed build leaves the existing database untouched.
- The updater never fetches URLs referenced inside CVE records.

## Tests

```bash
make updater-test   # offline; any network access fails the test run
```

The tests use real NVD/KEV records from `testdata/nvd/`. The end-to-end test
builds a database from them and queries it with the Go binary (skipped if Go is
not installed; set `GO=/path/to/go`).
