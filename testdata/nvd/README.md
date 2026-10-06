# Real NVD / CISA KEV test data

Unlike `testdata/fixtures/synthetic.json`, everything here is **real, unmodified**
public data. NVD data is in the public domain, and the KEV catalogue is published by CISA.

- `records/*.json`: single NVD CVE API 2.0 records (one `vulnerabilities[]`
  element each), fetched 2026-10-06 from `services.nvd.nist.gov` or taken from the
  `nvdcve-2.0-modified` feed:
  - `CVE-2021-41773`, `CVE-2021-42013`: Apache HTTP Server 2.4.49/2.4.50, exact
    version criteria, in KEV, with Exploit-tagged references
  - `CVE-2021-44790`: Apache HTTP Server `< 2.4.52` range
  - `CVE-2023-38408`: OpenSSH `< 9.3` plus `9.3` with update `-` / `p1` (the
    version/update split)
  - `CVE-2016-1019`: Adobe Flash, AND configurations ("running on" platform
    nodes with `vulnerable: false`), in KEV
  - `CVE-1999-1598`: `vulnStatus: Rejected`
  - `CVE-2024-34393`: unenriched (`Deferred`, no configurations)
- `known_exploited_vulnerabilities.json`: KEV catalogue `2026.10.04` trimmed to
  the three entries above (envelope unchanged except `count`).

The updater tests (`updater/tests/conftest.py`) assemble these into feed files
(`nvdcve-2.0-YYYY.json.gz` plus `.meta` with real sha256/size). Overlay test
cases (an updated description, a later rejection) are derived in that test code
at runtime; the stored records are never edited.
