# vFeed: concepts worth borrowing

An investigation (2026-10-10) of [vFeed](https://github.com/vfeedio/pyvfeed), a
"correlated vulnerability and threat-intelligence database" by Nabil (NJ) Ouchn
/ ToolsWatch, to decide which of its ideas are worth bringing into Offline
VulnDB and whether they still hold up today.

## What vFeed was, and what happened to it

- **Free, shipped database (≤2017):** an open-source Python API plus a
  downloadable **SQLite** vulnerability database on GitHub. The OSS repo has been
  frozen since release `0.7.2.1` (Nov 2017).
- **Paid service:** it became vFeed.io with Community/demo vs **Pro/Enterprise**
  editions; database updates moved behind subscription keys pulling from S3, with
  JSON feeds sold for SIEM/GRC ingestion (Splunk, RSA Archer). vFeed obtained a
  **US patent** on the method of compiling and distributing a correlated
  vulnerability database.
- **Sold and wound down:** vFeed, Inc. was **acquired by Zetafence.io** (~2024,
  per Crunchbase) and the open-source side is effectively dead. `pyvfeed` is now a
  thin CLI over the licensed database.

**Meta-lesson for this project.** What got captured and then killed was the
*curated correlation*, delivered as a downloadable database. Offline VulnDB's
model — a self-contained binary that **rebuilds** from first-party public
sources, dual-licensed, with third-party data *fetched/derived at build time and
never shipped* — is deliberately resistant to that failure mode. The vFeed arc
validates the direction; the open question is only which of its *ideas* to
absorb.

> **Patent note (awareness, not legal advice).** vFeed holds a US patent on
> compiling/distributing a correlated vulnerability database. Our approach —
> joining public datasets by CVE/CPE — is prior-art-heavy and non-commercial, but
> the patent's existence is worth knowing.

## vFeed's core idea

"Ingest hundreds of sources, normalise to open standards." It cross-linked a CVE
to CPE, CWE, CAPEC, ATT&CK, CVSS v2/v3/v4, EPSS, KEV, OVAL, scanner signatures
(Nessus, OpenVAS, Nmap), IDS/IPS rules (Snort, Suricata, Juniper), exploits
(Metasploit, ExploitDB) and vendor patches/bulletins. `pyvfeed` groups these as
`information / classification / risk / advisory / mitre / inspection /
exploitation / defense`.

## Concept-by-concept assessment

Legend: 🟢 adopt · 🟡 optional · 🔴 skip.

### 🟢 1. EPSS — exploitation probability — **IMPLEMENTED**

vFeed surfaced **EPSS** next to CVSS and KEV. We have KEV + CVSS but no
probabilistic prioritisation. The 2025 practitioner consensus is firmly: *KEV
first (confirmed exploitation) → EPSS to rank the rest → CVSS/asset context for
impact.* CVSS alone over-flags (~40% of CVEs are High/Critical).

- **Viability: high.** EPSS is published by FIRST as a **free daily CSV**,
  permissive usage (attribution requested), covering ~all CVEs, and tiny. It fits
  our offline snapshot-at-build model exactly.
- **Status: shipped (schema v13).** `vulndb update`/`build` fetches the FIRST
  EPSS snapshot (`epss.cyentia.com`, `--no-epss` to skip, `--epss FILE` to
  override) into an `epss` table; the score and percentile appear in query output
  (text + JSON `epss_score`/`epss_percentile`) and rank results immediately after
  KEV/exploit, ahead of CVSS. Metadata keys `epss_model_version` /
  `epss_score_date` / `epss_scores` record the snapshot.

### 🟢 2. Explicit triage flags + an explainable priority — **IMPLEMENTED**

vFeed's `--information` returns `has_exploits / has_kev / has_patches /
has_advisory` plus a `risk_score` (e.g. 0.94). The booleans are cheap and useful;
the **opaque 0–1 score is the anti-pattern** — nobody can explain it, the same
critique levelled at CVSS.

- **Viability: high for the flags.** We already compute most signals.
- **Status: shipped.** The query engine assigns each result a `priority` —
  **act** (CISA KEV), **attend** (public exploit, or EPSS ≥ 0.5), or **track**
  (no signal, undetermined, or already fixed in the installed distro package) —
  plus a `priority_reason`. It is derived only from exploitation evidence and
  likelihood (KEV + exploit + EPSS), **not** asset exposure/mission impact (the
  operator adds those), and is always explainable — the opaque score is
  deliberately avoided. Shown in text output and JSON (`priority` /
  `priority_reason`); the existing `known_exploited` / `public_exploit` booleans
  remain. It is a query-time computation, so there is nothing to build into the
  database or port to the Python updater.

### 🟢 3. Enriched exploit / PoC evidence — **IMPLEMENTED**

Our `public_exploit` was only "NVD tagged a reference `Exploit`, unverified" — a
known weak signal. vFeed correlated **Exploit-DB + Metasploit**; other modern
sources are Nuclei templates and GitHub PoC indexes (nomi-sec/PoC-in-GitHub,
trickest/cve).

- **Viability: medium-high.** Materially strengthens a weak signal.
- **Status: shipped (no schema change).** `vulndb update`/`build` fetches
  Metasploit's `modules_metadata_base.json` (`raw.githubusercontent.com`) and the
  Exploit-DB `files_exploits.csv` (`gitlab.com`), derives one `exploit_evidence`
  row per (CVE, module/exploit) — source `metasploit` / `exploit-db`, references
  only, `verified = 0` — and inserts only for CVEs already in the database (no
  orphans). `--no-exploits` / `--metasploit FILE` / `--exploitdb FILE` control it;
  metadata records `exploit_metasploit` / `exploit_exploitdb` counts. This feeds
  the existing `public_exploit` flag, the exploit-source list, and the **attend**
  priority, so a CVE with a Metasploit module but no KEV now surfaces correctly.
- **Licensing:** Exploit-DB is **GPL-2.0** and Metasploit **BSD-3-Clause**; like
  `data/http_tech.json` both are **fetched at build time and not shipped**. The
  bright line holds — we record references only, never exploit code. Ported to
  the Python updater too (Go/Python parity verified). Nuclei templates and GitHub
  PoC indexes remain as possible future additions.

### 🟡 4. CVE → CWE → CAPEC → ATT&CK chain

vFeed's `--mitre` adds "what weakness / how attacked / which ATT&CK technique" —
useful for **report narrative and threat-informed defence**. We already store
CWE, so we are one hop in.

- **Viability: partial.** MITRE CWE/CAPEC/ATT&CK are free and maintained
  (`mitre/cti` STIX repos; CVE2CAPEC precomputes the chain daily, GPL). But the
  chain is **lossy** — only ~112/546 CAPECs map to ATT&CK — so it is context, not
  a reliable per-CVE technique. Nice-to-have for reporting; not core to a
  network-scan correlator.

### 🟡 5. "Defense indicators" — CVE → detection/verification signatures

vFeed's `--inspection`/`--defense` mapped a CVE to **Snort/Suricata rules,
OpenVAS/Nessus plugins, Nmap NSE**. This flips output from *"here is your
exposure"* to *"here is how to detect or verify it"* — a real blue-team/pentest
win, and **we already ship an NSE integration**.

- **Viability: selective.** Open sources exist: **Greenbone/OpenVAS NVT feed**
  (GPL, NVT→CVE), Emerging Threats/Snort community rules (reference CVEs), Nmap
  NSE. Nessus is proprietary — skip. Same GPL → fetch/derive, don't ship.
- **Verdict: medium value, medium effort; a differentiator if we want the
  "verify this" angle.**

### 🔴 6. Vendor patch/bulletin correlation, `--pkgs`, `--lang`

Generic vendor patch/bulletin linking overlaps what we already do better for
Linux (OSV backport verdicts) and Windows (build-level). `--pkgs` overlaps our
distro package handling; `--lang` (CVEs by programming language) is SCA territory,
out of scope for a network-identity correlator. Mostly skip (possibly MS KB
linking for the Windows path later).

## Recommended roadmap (priority order)

1. ~~**EPSS**~~ — **done** (schema v13; see above).
2. ~~**Explicit triage booleans + SSVC-style explainable priority**~~ — **done**
   (query-time `priority`/`priority_reason`; see above).
3. ~~**Enriched exploit intel**~~ — **done** (Metasploit + Exploit-DB references,
   fetch-at-build; see above). Nuclei/GitHub-PoC remain optional extensions.
4. *(Optional)* **Defense indicators** (NSE/Suricata/OpenVAS verification mapping).
5. *(Optional, reporting)* **CWE → CAPEC → ATT&CK** context.

**Risk to avoid:** the "hundreds of sources" maintenance treadmill is part of what
killed vFeed's OSS. Adopt selectively, favouring free, stable, machine-readable
feeds (EPSS, MITRE CTI) over brittle scraping.

## Sources

- vFeed/Zetafence acquisition — <https://www.crunchbase.com/organization/vfeed-io>
- toolswatch/vFeed (frozen OSS) — <https://github.com/toolswatch/vFeed/commits/master>
- vFeed "ingest & correlate hundreds of sources" — <https://vfeed.io/how-it-works>
- vFeed correlated-DB US patent — <https://vfeed.io/vfeed-io-awarded-u-s-patent-for-compiling-and-distributing-correlated-vulnerability-database/>
- FIRST EPSS (usage agreement + daily data) — <https://first.org/epss/>
- KEV + EPSS vs CVSS prioritisation — <https://nhimg.org/articles/cve-prioritization-needs-kev-and-epss-not-cvss-alone/>
- CVSS vs EPSS vs SSVC vs KEV — <https://www.defendermate.com/dmate-blog/cvss-vs-epss-vs-ssvc-vs-kev>
- ProjectDiscovery cvemap (CVE→Nuclei/EPSS/KEV/PoC) — <https://pkg.go.dev/github.com/projectdiscovery/cvemap>
- MITRE CTI STIX repos — <https://github.com/mitre/cti>
- CVE2CAPEC (daily CVE→CWE→CAPEC→ATT&CK) — <https://github.com/Galeax/CVE2CAPEC>
