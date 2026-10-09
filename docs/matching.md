# Matching semantics

This document describes exactly how Offline VulnDB decides whether a CVE is a
candidate for a supplied CPE. When a result looks wrong, run the query with
`--debug` and compare the per-rule trace against these rules.

## 1. Input normalisation (`internal/cpe`)

Both CPE bindings are accepted and normalised to the same internal value:

| Input | Normalised |
|---|---|
| `cpe:/a:apache:http_server:2.4.49` (2.2 URI, Nmap) | `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` |
| `cpe:2.3:a:Apache:HTTP_Server:2.4.49:*:*:*:*:*:*:*` | same |

- All values are lower-cased.
- CPE 2.2: omitted trailing components and empty components become ANY (`*`);
  percent-encoding is decoded; a packed edition (`~ed~sw~tsw~thw~other`) is
  unpacked into the CPE 2.3 extended attributes.
- Values are re-escaped canonically: every character other than `[a-z0-9._-]`
  is backslash-escaped (e.g. `1.0(beta)` → `1.0\(beta\)`), so equality is a
  plain string comparison.
- A supplied CPE may not contain wildcards inside a value (`2.4.*`); criteria
  strings from vulnerability data may.
- A query requires specific `part`, `vendor` and `product`; otherwise it fails
  with "insufficient identity information".

## 1a. Identity resolution (`internal/identity`)

An observed identity turns into one or more **candidate identities**, and each
is looked up:

1. The observed application CPE is always a candidate: EXACT with a concrete
   version, LOW without one.
2. Each curated alias for that `part:vendor:product` (from `data/aliases.json`,
   stored in the `aliases` table) adds the same CPE under the vendor/product
   NVD uses. Its confidence is the alias's (HIGH or MEDIUM) and never more than
   the observed identity's.
3. Results from all candidates are merged per CVE (section 6). Each CVE
   reports the identity that matched it (`matched_cpe`, `match_confidence`).

Aliases only ever **add** candidates. The observed identity is never replaced:
both old and new vendors can hold CVEs (e.g. `mysql:mysql` up to 2017,
`oracle:mysql` after).

For Nmap services, `vulndb nmap` also:
- does not query OS/hardware CPEs reported alongside a service
  (`cpe:/o:linux:linux_kernel`) as the service;
- does not assess services Nmap only guessed from the port number
  (`method="table"`);
- resolves services that have a product name but no application CPE through
  the curated product-name map (below); names not in it are `UNIDENTIFIED`
  (no guessing);
- detects distribution packaging from the version or extra-info text
  (`9.6p1 Ubuntu 3ubuntu13.18`) or from OS CPEs, and attaches a backport
  warning;
- attaches product caveats (IIS vulnerabilities are recorded against Windows
  CPEs).

### HTTP application fingerprints

Web applications sit behind a generic web server (nginx, Apache, Jetty), so
Nmap's service product names the server, not the application. The curated map
`data/http_apps.json` (table `http_apps`) identifies the application from HTTP
evidence the scan carries, and adds it as an extra candidate identity
*alongside* the web-server CPE (both are assessed). Evidence sources, from NSE
script output (`http-server-header`, `http-generator`, `http-title`,
`http-headers`):

- `server` — the Server header or the HTTP service banner (`Jetty(9.4.51...)`);
- `generator` — a `<meta name=generator>` tag (`WordPress 6.4.2`, `Drupal 10`);
- `header` — a named response header (`X-Jenkins: 2.426`);
- `x_powered_by` — the X-Powered-By header (`PHP/8.2.7`);
- `title` — the page title.

Each row is an anchored RE2 regex over one source, mapping to an NVD
vendor:product with an optional capture group for the version. With a captured
version the identity takes the row's confidence (HIGH/MEDIUM); without one it
is LOW (the application is named but version-dependent results are UNKNOWN).
Seeded with WordPress, Joomla, Drupal, TYPO3, Jenkins, Jetty, Tomcat (via the
Apache-Coyote banner) and PHP. The evidence is only available in `vulndb nmap`
on a scan that ran the relevant `http-*` scripts (`-sC`); the NSE adapter does
not see other scripts' output.

### Product names without a CPE

Nmap fingerprints many services without an application CPE. Automatic
matching of their names against NVD mostly finds the wrong software
(`Amazon S3 httpd` → a WordPress plugin, `Catwalk` → a theme vendor), so the
map (`data/product_names.json`, table `product_names`) is curated entry by
entry. `vulndb-update review-products` proposes candidates from Nmap's probe
database. A name is matched exactly, or by an anchored regular expression for
Nmap's per-protocol variants (`hMailServer smtpd|pop3d|imapd`). The map is
consulted only when Nmap reported no application CPE.

- **Products** map the name to one or more NVD vendor:product identities.
  Each entry also records whether Nmap's version field is the product version
  (`version: nmap`) or something else, such as a protocol, API or library
  version (`version: none`; SLURM's "API 2.7", MOVEit DMZ's SSH library).
  Only the first word of the version field is used (`0.103.2 (27019)` →
  `0.103.2`), escaped as a literal. Confidence is the entry's (HIGH or
  MEDIUM) with a version, and LOW without one.
- **OS components** are operating-system built-ins whose vulnerabilities NVD
  records against the OS itself (Windows RPC, Active Directory LDAP, Terminal
  Services, SMB, Kerberos, HTTP.sys): no application product exists to look
  up. Such ports are reported as `OS_COMPONENT` and covered by the host's
  Windows build assessment (section 10). If Nmap does report an application
  CPE for one (Kerberos → `microsoft:kerberos`), that CPE is still queried
  and the note says its results are incomplete.

## 2. Candidate lookup (`internal/database`)

`cve_matches.criteria` is stored verbatim. The importer also derives
`criteria_part`, `criteria_vendor`, `criteria_product` (canonical values) and
indexes them. The query fetches every **vulnerable** rule with the same
part/vendor/product. This is only a pre-filter; the decision is made by
re-parsing `criteria` in full.

Non-vulnerable rules (`vulnerable = 0`, e.g. "running on Windows" platform
rules) are never candidates by themselves.

**Version key.** Rules for one exact version (no range bounds) carry a key: the
version's major.minor, from `version.Key`. For example, `2.6.32` → `2.6`, `5`
→ `5.0`, `8.9p1` → `8.9`. Every other rule has the key `''`.
- A query reads only rules whose key is `''` or the observed version's key.
  Versions equal under the generic and OpenSSH comparators always share a key,
  so no rule that could match is skipped. The filter is used only for those
  comparators (`version.KeySafe`).
- 68% of Linux kernel rules are exact versions of other kernel series, so a
  5.15 query reads 53k instead of 163k rules.
- One visible effect: exact-version rules for another series that the
  comparator could not parse no longer show up as UNKNOWN. For example, Apache
  2.4.49 used to list CVE-2017-12171 as UNKNOWN because of its rule for
  `2.2.15-60`, a RHEL package version from the 2.2 series. Such a rule can
  never be the observed version.

**Configuration context on each rule.** The rule's node and configuration
operators, negation and AND-sibling flags are copied onto the rule at build
time, so the lookup is one indexed scan with no joins.

## 3. Rule evaluation (`internal/matcher/rule.go`)

Each non-version attribute is related to the criteria value:

| Criteria | Supplied | Relation |
|---|---|---|
| `*` (ANY) | anything | match |
| `x` | `x` | match |
| `x` or `-` (NA) | `*` (ANY) | **unknown** – criteria is more specific than what we know |
| `x` | `y` | disjoint → NO_MATCH |
| `-` (NA) | `x` | disjoint → NO_MATCH |
| `x` | `-` (NA) | disjoint → NO_MATCH |
| pattern `x*` | value matching the pattern | match |

The version attribute:

| Criteria version | Range bounds | Supplied version | Result |
|---|---|---|---|
| `*` | none | anything | MATCH (all versions affected) |
| `*` | present | ANY / NA | UNKNOWN |
| `*` | present | concrete | comparator range check |
| concrete | none | ANY | UNKNOWN |
| concrete | none | concrete | comparator equality (identical strings always match) |
| concrete | present | — | UNKNOWN (unsupported combination) |
| `-` | none | `-` / other | MATCH / NO_MATCH |

Combination: any disjoint attribute or a version NO_MATCH gives **NO_MATCH**;
otherwise any unknown gives **UNKNOWN**; only when everything passes is the
rule a **MATCH**.

### Range bounds

`version_start_including` (`>=`), `version_start_excluding` (`>`),
`version_end_including` (`<=`), `version_end_excluding` (`<`). Every present
bound must hold. A bound that cannot be compared makes the result UNKNOWN,
unless another bound is definitely violated (then NO_MATCH).

## 4. Version comparison (`internal/version`)

Comparators are chosen per product by `version.For` (`internal/version/registry.go`):
OpenSSH for `openbsd:openssh`, PEP 440 for a verified set of Python packages
(Django, Flask/Werkzeug/Jinja, CPython, requests, urllib3, cryptography,
paramiko, aiohttp, numpy, …), and the conservative Generic comparator for
everything else. A comparator returns an error — surfaced as UNKNOWN, never a
match — when it cannot order two versions, so distro-revisioned versions
(`2.2.1-1ubuntu0.1`) fall to the distribution-advisory path rather than being
guessed.

Comparators implement `Compare(a, b) (int, error)`. An error means "cannot
order these" and always becomes UNKNOWN. The comparator is chosen per
canonical vendor:product (`version.For`):

**`openssh`** (for `openbsd:openssh`):
- Versions are dotted numbers with an optional portable level `pN`.
- A bare OpenBSD release `X.Y` equals the first portable release `X.Yp1`, the
  code it corresponds to.
- It also implements `UpdateJoiner`. NVD sometimes splits `9.3p1` into version
  `9.3` + update `p1` (and uses `9.3` + update `-` for the OpenBSD release), so
  version and update are folded into one effective version on both sides
  before comparing.

For the real CVE-2023-38408 rules (`< 9.3`, `9.3:-`, `9.3:p1`; fixed in
9.3p2): 8.9p1 and 9.3p1 → MATCH, 9.3p2 → no match.

**`generic`** (everything else):

- dotted segments, each `digits[letters[digits]]`: `2.4.49`, `8.9p1`, `1.1.1k`;
- numeric segment ordering (`1.9 < 1.10`), missing trailing segments are 0;
- suffixes only compare when the letters are identical (`8.9p1 < 8.9p2`);
- `9.3` vs `9.3p2`, `1.0rc1` vs `1.0p1`, `1.1.1k` vs `1.1.1m`: incomparable;
- distro/qualifier versions (`7.4.33-1ubuntu1`, `2.4.49-r0`, `1.2.3.RELEASE`,
  `v1.2`) are rejected.

## 5. NVD configuration structure

NVD applicability is a tree: CVE → configurations (AND/OR over nodes) →
nodes (AND/OR over CPE rules, optionally negated). The tree is stored in
`cve_configurations` / `cve_config_nodes`, and each rule records its `node_id`.

With a single supplied CPE we can only evaluate one rule at a time, so:

- a rule in an **AND configuration with other nodes** (typically "application
  X running on platform Y"), or in an **AND node with other rules**, is
  reported with `applicability: CONDITIONAL` and a warning;
- a vulnerable rule in a **negated node** is never reported as MATCH (it is
  downgraded to UNKNOWN).

### Platform conditions ("running on" an OS)

In `vulndb nmap`, a host with a known operating system — a Windows build
(section 10) or a detected Linux distribution — can decide a service's
CONDITIONAL CVE whose only open condition is the other node of an AND
configuration ("Tomcat running on Windows", "OpenSSH running on Red Hat").
The host platform is matched against that node (`matcher.ApplyPlatform`); the
sibling nodes are read through two indexes added in schema v10.

| Platform node lists | Result |
|---|---|
| the host's OS (`windows_server_2016:-`; `linux:linux_kernel`; the host's own distro, `debian:debian_linux`), or Windows generically (`microsoft:windows:-`) | `UNCONDITIONAL`, flagged "platform confirmed" |
| only other operating systems — a different OS family (Windows vs Linux, macOS) **or a different Linux distribution** (RHEL-only on a Debian host) | `PLATFORM_EXCLUDED`: kept in the output, not counted as a match |
| another release of the host's own OS (other Windows releases; the host's distro at a specific version) | stays `CONDITIONAL`, with a note naming them |
| hardware, applications, a negated node, or a second vulnerable node | stays `CONDITIONAL` |

Different Windows *releases* do not exclude a CVE (they are the same OS at
different versions, and NVD's platform lists are written at publication and
not extended for later releases — software listed "on Windows 7 and 8.1" may
well be affected on Server 2022). Different Linux *distributions*, by
contrast, are distinct operating systems, so a RHEL-only condition excludes on
a Debian host (e.g. CVE-2008-3844, the Red Hat OpenSSH package backdoor).

When the build is shared and the kind unknown (Server 2016 or Windows 10
1607), both releases must agree; otherwise the CVE stays CONDITIONAL with a
note. A Linux host platform comes from the distribution detected across the
host's services (generic `linux:linux_kernel` plus the distro's own OS
identity). Results are copied before they are changed, since identical
services on different hosts share one lookup.

Measured on the 2026-10-07 database: of AND configurations whose vulnerable
side is a product Nmap can report a CPE for, about 980 CVEs list Windows
among their platforms (IBM DB2/WebSphere, .NET, Apache httpd, PHP, Oracle,
Splunk, PostgreSQL, …) and about 380 list only other operating systems (JBoss,
Tomcat, OpenSSH, CUPS, …). Most "running on Windows" configurations concern
desktop software (Flash, Acrobat, iTunes, browsers) that a network scan does
not see.

Spot check on a synthetic Windows Server 2022 host with Tomcat, Apache httpd,
PostgreSQL, IBM DB2 and OpenSSH for Windows: 118 conditions confirmed (e.g.
Tomcat CVE-2019-0232, CGI on Windows; PostgreSQL CVE-2019-10211, the Windows
installer's OpenSSL), 9 excluded (e.g. OpenSSH CVE-2008-3844, trojaned Red Hat
packages; DB2 CVEs limited to Linux/AIX/HP-UX), 5 left CONDITIONAL.

## 6. Aggregation per CVE

Rules are grouped by CVE. A CVE is MATCH if any rule matched, otherwise
UNKNOWN if any rule was undecided; CVEs whose rules are all NO_MATCH are not
returned. A CVE is CONDITIONAL only if every matching rule is conditional.

Rules from all candidate identities are pooled. Among the chosen rules,
unconditional ones come first, then rules from the more confident identity. The
first one supplies `match_confidence`, `matched_cpe` and `match_reason`.

## 7. Confidence

`match_confidence` is the confidence of the identity that matched:

| Level | When |
|---|---|
| EXACT | observed CPE with a concrete version |
| HIGH | curated alias: the same product under a renamed or acquired vendor |
| MEDIUM | curated alias: the same product embedded or rebranded by another vendor |
| HIGH / MEDIUM | curated product name with a version: as curated (MEDIUM when the version is indirect, e.g. cPanel's cpsrvd) |
| LOW | observed CPE without a version (product only), any alias of one, or a curated product name without a usable version |
| UNKNOWN | not used for candidates |

Version applicability is reported separately as `version_status`.

## 8. Ordering

0. CVEs the distribution package has fixed (section 9) last
1. version MATCH before UNKNOWN
2. CISA KEV **and** public exploit
3. KEV
4. public exploit
5. CVSS (v3 preferred, else v4), higher first
6. unconditional before conditional
7. identity confidence, higher first
8. CVE ID

## 9. Distribution advisories (`internal/distro`)

Upstream version matching cannot see fixes a distribution has backported into
its own packages. When a service shows distribution packaging (e.g. Nmap's
`OpenSSH 9.6p1 Ubuntu 3ubuntu13.18`, `Apache httpd 2.4.52 (Ubuntu)`), each
candidate CVE is also evaluated against that distribution's security
advisories: Ubuntu, Debian, Red Hat Enterprise Linux, Rocky Linux and
AlmaLinux, from the OSV.dev exports of their security data. CentOS is
evaluated with Red Hat's advisories, and the verdict says so.

**Package.** The candidate CPEs map to distribution source packages through
the curated `distro_packages` table (`data/distro_packages.json`), e.g.
`openbsd:openssh` → `openssh` and `postgresql:postgresql` → `postgresql-14`.

**Release.** Inferred from the published package versions:
- a revision that encodes its release is decisive: Debian `+deb12u3` → 12,
  Ubuntu `0ubuntu0.22.04.2` → 22.04, RPM `38.el9_4.1` → 9;
- with the package revision visible, a release that published exactly
  `<upstream>-<revision>` is preferred;
- otherwise, any release that shipped the observed upstream version;
- in `vulndb nmap`, a release established from an exact package version on a
  host (usually from OpenSSH) is used as a hint for that host's other
  services, including when the service's own version is not in the data;
- several candidate releases → `AMBIGUOUS`. A verdict is given only when all
  candidate releases agree.

**Verdict per CVE** (`distro.status`):

| Status | When |
|---|---|
| `FIXED` | revision visible and installed ≥ fixed version; or revision not visible and either the observed upstream version is newer than the fix's upstream, or no package of the observed upstream version in that release is listed as affected |
| `VULNERABLE` | revision visible and installed < fixed version (including fixes only in Ubuntu Pro/ESM, for a standard host); or revision not visible and the fix came in a newer upstream version than observed |
| `FIX_AVAILABLE` | revision not visible; the release fixed it in a later package revision of the same upstream version. Patched only if the host is up to date |
| `NO_FIX` | the release is listed as affected with no fix released. The reason carries the distribution's urgency, e.g. Debian `unimportant` (no fix planned) or not yet triaged |
| `NO_DATA` | no row for the CVE/package/release (usually not affected, or not yet assessed); unmapped product; no data for that distribution; or ambiguous releases that disagree |

`FIXED` results stay in the output, but they are excluded from match counts
and listed separately ("fixed in the Ubuntu package").

**Host-level distribution.** In `vulndb nmap`, when the distribution-marked
services on a host agree (e.g. Apache `(Red Hat Enterprise Linux)`), services
showing no distribution (RHEL's `OpenSSH_8.7`) are evaluated against it. This
happens only when the advisory data knows the observed upstream version,
because the software could be self-built. OpenSSH's bare `8.7` is read as
`8.7p1`, the portable release distributions package.

**Module streams (RHEL AppStream).** Fixed versions built as modules
(`1:1.16.1-2.module+el8.4.0+…`) belong to a stream, the upstream major.minor
(`1.16`). A fix applies only to an observation in the same stream. If only
other streams were fixed, the verdict is `NO_DATA`, naming those streams. On
RHEL 8, CVE-2021-23017 was fixed separately in the nginx 1.16, 1.18 and 1.20
streams.

**Distribution-only findings.** For a single resolved release, any advisory
whose verdict is `VULNERABLE` is reported as a finding (`distro_only: true`),
even when NVD has no matching rule. Such a verdict needs either an installed
version older than the fix, or a fix in a newer upstream version. `NO_FIX` rows never add findings on their own: Ubuntu marks
new CVEs as affected before triage.

**End of life.** `distro_releases` (`data/distro_releases.json`, curated from
vendor lifecycle pages) records each release's end of regular security
support, plus any extended offering (Ubuntu Pro ESM, RHEL ELS, Debian ELTS).
Distributions stop publishing advisory data for releases past end of life; the
Debian Security Tracker no longer contains Debian 11 at all.

So when the resolved release is past its EOL date:
- the distribution context carries `end_of_life`;
- `NO_DATA` verdicts say the release reached end of life (and how fixes are
  still available, if they are);
- reports count the services on such releases.

A real scan of Debian 11 routers (LTS ended 2026-08-31) showed why this is
needed. Before the change, CVEs Debian had fixed in 2023 looked like ordinary
data gaps.

**Data trust.** Affected-version lists are used only where they describe the
release:
- Ubuntu's lists;
- Debian's lists for fixed entries, keeping versions older than the fix;
- not Debian's no-fix lists, which span the whole archive.

Debian 11 (LTS) rows come from DLA advisories where no per-CVE record covers
them.

**Channels.** Rows come from standard releases and Ubuntu Pro (ESM). An
installed revision containing `esm` uses Pro rows; otherwise standard rows,
falling back to Pro when the release has only those. FIPS, Realtime and
vendor-kernel streams are not loaded.

Version comparison uses dpkg ordering for Debian/Ubuntu (`version.Dpkg`) and
rpmvercmp for the Red Hat family (`version.RPM`: epoch, version, release, `~`
and `^`). The installed epoch is taken from the distribution's own versions of
the package.

**Per-advisory sources** (Debian DSA/DLA; RHSA/RLSA/ALSA) can list the same CVE
in several advisories. The earliest fixed version per release and stream is
kept, because later advisories re-list CVEs. For example, AlmaLinux
`ALSA-2026:69266` re-lists CVE-2023-38408, which was fixed in `ALSA-2023:4419`.

## 10. Windows build-level assessment (`internal/windows`)

Windows services carry only `cpe:/o:microsoft:windows` (or no CPE), so they
cannot be assessed per port. An unauthenticated scan can, however, see the
host's **build**. It cannot see the **patch level** (the update revision, or
UBR, as in `20348.2849`). `vulndb nmap` uses the build to list the CVEs of the
host's release, which apply *unless the host is patched*. This is an inventory
of exposure, not a finding of vulnerability.

**Evidence** (per host, from `-sC`/`--script` output in the XML):
- `Product_Version` from any `*-ntlm-info` script (`rdp-ntlm-info`,
  `http-ntlm-info`, `smtp-ntlm-info`, …), e.g. `10.0.20348`;
- the build at the end of `smb-os-discovery`'s `os` string or of the SMB
  service fingerprint, e.g. `Windows Server 2016 Standard Evaluation 14393`
  (the release year is not mistaken for a build);
- server or client: the word "Server" (or a client name such as "Windows 10")
  in those strings, or Active Directory LDAP/Kerberos services on the host,
  since domain controllers run only on Windows Server.

If the host reports different builds, it is `CONFLICT` and not assessed. A
build missing from the map is `UNMAPPED`.

**Release.** The curated `windows_builds` table (`data/windows_builds.json`)
maps build and kind to a release name, its NVD CPEs, and lifecycle dates.
Several builds are shared: 14393 is Windows Server 2016 and Windows 10 1607,
17763 is Server 2019 and Windows 10 1809, 26100 is Server 2025 and Windows 11
24H2. When the scan shows no kind, each release is listed with `MEDIUM`
confidence; a single release is `HIGH`.

**Identities.** NVD encodes the release in the CPE *version*, and the curated
map pins it:
- `windows_server_2016:-` is the Long-Term Servicing Channel release, which
  build 14393 runs. The same product also holds Semi-Annual Channel releases
  (`1709` … `20h2`), which a 14393 host must not inherit;
- clients use both NVD spellings, e.g. `windows_10_1607:-` and
  `windows_10:1607`.

Each identity is queried twice:
1. as curated, which matches older rules that name the release
   (`windows_server_2016:-`, no range);
2. with the version set to the unpatched build (`10.0.14393`), which matches
   newer rules written as ranges ending at the fixing update
   (`< 10.0.14393.7428`).

A CVE is listed when either query matches it, with two refinements:
- range rules are decided by the build query alone. The release query cannot
  evaluate a range, so it would mark every one UNKNOWN, including NVD's
  occasional mistaken ranges (some `windows_11_22h2` rules end at 21H2 builds,
  `< 10.0.22000.1413`, which a 22621 build is not in);
- a range that *starts* at an update of the observed build
  (`10.0.20348.3270 < v < 10.0.20348.3328`) is a CVE introduced by that
  update. The unpatched build is outside it, but the host's unknown patch
  level may be inside, so it is UNKNOWN rather than NO_MATCH.

`target_hw` is `x64`: Windows
Server has shipped only for x64 since 2008 R2, and clients are assumed to be
x64 (stated in the output), since otherwise the x64/x86/ARM64 rule variants
would all be undetermined. Rules that name a specific edition (`datacenter`,
`azure`) are counted as undetermined.

**Output.** Per host:
- release, build, confidence and evidence;
- support status from the map; a release whose `eol` date has passed is
  flagged `END OF SUPPORT`;
- the number of applicable CVEs, with KEV, exploit and critical counts;
- KEV entries, most recently added first, since older ones are more likely
  patched.

JSON lists every applicable CVE compactly under `hosts[].windows[]`.

The NSE adapter does not do this: a port script cannot read other scripts'
results. Run `vulndb nmap` on the `-oX` output of a scan that included
`rdp-ntlm-info` or `smb-os-discovery` (both are in Nmap's `default` category,
so `-sC` is enough).
