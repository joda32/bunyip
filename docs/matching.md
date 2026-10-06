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
- reports services that have a product name but no application CPE as
  `UNIDENTIFIED` (no guessing);
- detects distribution packaging from the version or extra-info text
  (`9.6p1 Ubuntu 3ubuntu13.18`) or from OS CPEs, and attaches a backport
  warning;
- attaches product caveats (IIS vulnerabilities are recorded against Windows
  CPEs).

## 2. Candidate lookup (`internal/database`)

`cve_matches.criteria` is stored verbatim. The importer also derives
`criteria_part`, `criteria_vendor`, `criteria_product` (canonical values) and
indexes them. The query fetches every **vulnerable** rule with the same
part/vendor/product. This is only a pre-filter; the decision is made by
re-parsing `criteria` in full.

Non-vulnerable rules (`vulnerable = 0`, e.g. "running on Windows" platform
rules) are never candidates by themselves.

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
| LOW | observed CPE without a version (product only), or any alias of one |
| UNKNOWN | reserved for product-name resolution (later milestone) |

Version applicability is reported separately as `version_status`.

## 8. Ordering

1. version MATCH before UNKNOWN
2. CISA KEV **and** public exploit
3. KEV
4. public exploit
5. CVSS (v3 preferred, else v4), higher first
6. unconditional before conditional
7. identity confidence, higher first
8. CVE ID
