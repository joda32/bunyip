# Data sources

Measurements from 2026-10-06 against the full NVD dataset and the CVE List
snapshot of the same day. Re-measure before making a source decision; these
numbers change quickly.

## NVD CVE JSON 2.0 feeds (in use)

- 383,102 published CVEs; 3.23M CPE match rules; 770k configurations, 58% of
  them AND ("X running on Y").
- Refresh: the yearly feeds daily; the `modified` feed (last 8 days) about every
  2 hours.
- **Coverage gap.** Since April 2026 NIST fully enriches only KEV, US
  federal-use and EO 14028 "critical software" CVEs. CVEs with no CPE
  applicability data (they can never match a query):

  | Published | Without applicability data |
  |---|---|
  | 2020–2023 | 0% |
  | 2024 | 19.4% |
  | 2025 | 37.3% |
  | 2026 | 51.9% |
  | KEV CVEs | 0% (all 1,734 have data) |

- Upstream data quality: 4 rules in the build had unescaped `(` in Cisco IOS
  versions (e.g. `15.2(7)e13`). They are skipped and counted.

## CISA KEV (in use)

- 1,734 entries (catalogue `2026.10.04`); 361 marked "Known" ransomware use.
- The JSON is updated when CISA adds entries (typically several times a week).
  New fields appear over time (e.g. `forensicTriage`); unknown fields are
  ignored.

## Ubuntu security tracker via OSV.dev (in use)

Export: `osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`.
- 770 MB; 7.8 GB uncompressed; MD5 published in `x-goog-hash`.
- 69,712 records: 61,497 per-CVE (`UBUNTU-CVE-*`) covering 60,912 CVEs, plus
  per-USN records; 3,648 withdrawn.

Ecosystems:
- standard releases `Ubuntu:<rel>:LTS` and interim releases `Ubuntu:25.10`;
- `Ubuntu:Pro:<rel>:LTS` (ESM);
- FIPS, Realtime and Nvidia-BlueField streams, which are not used.

Semantics:
- One `fixed` event per release, or none: affected, no fix released.
- `versions` lists the affected package versions.
- About 80% of affected entries have no fix. These are dominated by kernel
  packages, and also include not-yet-triaged CVEs, because OSV does not
  distinguish "needed" from "needs-triage".
- Releases that are not affected are absent.

Network-visible packages: of Nmap's probes, **only OpenSSH exposes the
distribution package revision** (`9.6p1 Ubuntu 3ubuntu13.18`). Apache, nginx,
BIND, Postfix, ProFTPD, Dovecot and others expose only "(Ubuntu)".

In the build: 16,547 rows for the 75 mapped packages that have data; about 5 MB
of database.

Real result on an Ubuntu 24.04 host (OpenSSH `3ubuntu13.18`): 22 upstream
matches became 6.
- 16 are fixed in the installed package, including CVE-2024-6387.
- 3 are VULNERABLE: fixed in `3ubuntu13.19`, which `apt` on the host confirmed
  as the pending update.

## Debian security tracker via OSV.dev (in use)

Export: `osv-vulnerabilities.storage.googleapis.com/Debian/all.zip`.
- 240 MB uncompressed.
- 69,801 records: 58,357 `DEBIAN-CVE-*`, 6,246 DSA, 4,701 DLA, 207 DTSA,
  290 `CVE-*`; 657 withdrawn.

Coverage of `DEBIAN-CVE-*` by release:
- Debian 12 (bookworm), 13 (trixie) and 14 (testing): about 57k entries each;
- Debian 11 (bullseye, LTS): only 1,198. Bullseye fixes are mainly in DLA
  (684) and DSA (706) records, which are used to fill the gaps.

Quirks found in real data:
- `versions` on no-fix entries spans the whole archive. For example, bookworm
  lists `10.0p1` and backports versions, but bookworm ships OpenSSH 9.2p1.
- A fixed version can be an unstable upload that predates the release. For
  example, trixie's fix for CVE-2024-6387 is `1:9.7p1-7`, with no affected
  trixie versions.
- 3 `affected` entries have no `package`, only git ranges.
- `ecosystem_specific.urgency`: `not yet assigned`, `unimportant` (4,607 no-fix
  entries), `low`, `medium`, `high`, `end-of-life`.

Revisions encode the release (`+deb12u3`), which pins Debian hosts even when
the exact package version is absent from the data.

Other OSV.dev exports in the same format: Red Hat, Rocky Linux, AlmaLinux,
SUSE and Alpine. They use RPM/apk versions, which need their own comparators.

## CVE List V5 / CISA Vulnrichment (evaluated, deferred)

Source: `github.com/CVEProject/cvelistV5` releases. There is a daily
`*_all_CVEs_at_midnight.zip.zip` (620 MB) plus hourly delta zips; downloads
redirect to `release-assets.githubusercontent.com`.

How much of the NVD gap it fills (64,367 CVEs without NVD applicability data):

| | CVEs |
|---|---|
| Gap filled by any CVE List CPE | 8,267 (12.8%) |
| … by CISA ADP CPEs | 3,407 |
| … by CNA-provided CPEs | 4,862 (many are Red Hat platform CPEs without versions) |
| … whose vendor:product already exists in NVD | 2,583 |
| 2025 gap filled | 276 of 17,478 (1.6%) |
| 2026 gap filled | 4,398 of 34,668 (12.7%) |

Where NVD and CISA ADP both describe a CVE, they **disagree on vendor:product
for 38%** of them (6,485 of 16,770).

Version data: `versionType` is mostly `custom` or absent (others: rpm, semver,
git). Ranges are `version` (often `"0"`) plus `lessThan` or `lessThanOrEqual`,
with `defaultStatus` affected, unaffected or unknown.

The 2025–2026 gap is mostly not software that network scanning sees:

| Kind | CVEs |
|---|---|
| Package-ecosystem libraries | 13,261 |
| Linux kernel (`Linux / Linux`, git and semver versions with backport "unaffected" entries) | 5,547 |
| WordPress plugins and other web applications | most of the remaining ~40,000 |
| Recognisably network/service products | ~1,800 |

**Decision (2026-10-06):** defer. For Nmap-driven use, identity resolution gave
far more (see below). Revisit for the Linux kernel CNA data (needs a
`Linux/Linux` → `linux:linux_kernel` mapping and git/semver/backport
semantics), or if CISA ADP coverage grows.

## Nmap identities vs NVD names (`vulndb-update review-aliases`)

Nmap 7.94 `nmap-service-probes`: 11,917 match lines and 2,052 distinct CPE
vendor:product templates.
- 701 match NVD exactly; 957 are not in NVD at all; 234 are templated.
- 160 have the product in NVD under a different vendor. About a third of those
  are different software with a similar name, which is why aliases are
  curated by hand.
- A worse class: Nmap's vendor exists in NVD only for **old** CVEs. For example,
  `mysql:mysql` has 92 CVEs up to 2017, while `oracle:mysql` has 1,328 up to
  2026.

Effect of the 74 curated aliases on real queries:

| Nmap reports | Matches before | Matches after |
|---|---|---|
| `mysql:mysql:8.0.30` | 0 | 147 |
| `igor_sysoev:nginx:1.20.0` | 0 | 4 (1 KEV) |
| `redislabs:redis:6.0.5` | 4 | 33 |
| `mortbay:jetty:9.4.30` | 0 | 26 (1 KEV) |

IIS is a special case. NVD has recorded IIS vulnerabilities against Windows
CPEs since about 2017, so an IIS CPE cannot find them. This is reported as a
note rather than "solved" with a mapping, since an IIS version does not
identify a Windows build.
