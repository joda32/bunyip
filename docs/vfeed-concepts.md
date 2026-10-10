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

### 🟢 1. EPSS — exploitation probability

vFeed surfaced **EPSS** next to CVSS and KEV. We have KEV + CVSS but no
probabilistic prioritisation. The 2025 practitioner consensus is firmly: *KEV
first (confirmed exploitation) → EPSS to rank the rest → CVSS/asset context for
impact.* CVSS alone over-flags (~40% of CVEs are High/Critical).

- **Viability: high.** EPSS is published by FIRST as a **free daily CSV**,
  permissive usage (attribution requested), covering ~all CVEs, and tiny. It fits
  our offline snapshot-at-build model exactly.
- **Effort: low.** An `epss` table + join, a field in JSON/text output, and a
  factor in result ordering.
- **This is the recommended first addition.**

### 🟢 2. Explicit triage flags + an explainable priority

vFeed's `--information` returns `has_exploits / has_kev / has_patches /
has_advisory` plus a `risk_score` (e.g. 0.94). The booleans are cheap and useful;
the **opaque 0–1 score is the anti-pattern** — nobody can explain it, the same
critique levelled at CVSS.

- **Viability: high for the flags.** We already compute most signals.
- **Do the score the modern way:** an **SSVC-style, explainable** priority tier
  (e.g. Act / Attend / Track) driven by KEV + EPSS + exposure, consistent with our
  existing "always give a `match_reason`" ethos — not a magic number.

### 🟡 3. Enriched exploit / PoC evidence

Our `public_exploit` today is only "NVD tagged a reference `Exploit`, unverified"
— a known weak signal. vFeed correlated **ExploitDB + Metasploit**; the modern
equivalents are **Nuclei templates (CVE→template), Metasploit module CVE refs,
and GitHub PoC indexes** (nomi-sec/PoC-in-GitHub, trickest/cve). ProjectDiscovery
`cvemap` (MIT) demonstrates the join (CVE→Nuclei+EPSS+KEV+PoC).

- **Viability: medium-high.** Materially strengthens a weak signal and can point
  to an *actionable verification* (a Nuclei template) without us running anything.
- **Licensing:** ExploitDB is **GPLv2**, Nuclei templates vary, Metasploit is
  BSD. Treat like `data/http_tech.json`: **fetch/derive at build, do not ship.**
  Keep the bright line — record references/detection only, never download or run
  exploit code.

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

1. **EPSS** — cheapest, most defensible prioritisation upgrade; clean offline fit.
2. **Explicit triage booleans + SSVC-style explainable priority** (not an opaque
   score).
3. **Enriched exploit intel** (Nuclei/Metasploit/PoC; fetch-at-build, GPL-safe) to
   fix our weakest signal.
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
