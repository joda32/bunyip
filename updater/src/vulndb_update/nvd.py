"""Transform NVD CVE API 2.0 / JSON 2.0 feed records into database rows.

Applicability data is kept with its structure: configurations (AND/OR over
nodes) -> nodes (AND/OR over CPE match rules, optionally negated) -> rules.
`criteria` strings are stored verbatim; only the lookup columns are derived.
"""

import json
from dataclasses import dataclass, field

from . import cpe

NVD_SOURCE = "nvd@nist.gov"
EXPLOIT_SOURCE = "nvd-reference"


@dataclass
class Match:
    criteria: str
    part: str
    vendor: str
    product: str
    vulnerable: bool
    start_including: str | None
    start_excluding: str | None
    end_including: str | None
    end_excluding: str | None


@dataclass
class Node:
    operator: str
    negate: bool
    matches: list[Match]


@dataclass
class Configuration:
    operator: str
    nodes: list[Node]


@dataclass
class Exploit:
    reference: str
    metadata_json: str


@dataclass
class Record:
    cve_id: str
    published_at: str | None
    modified_at: str | None
    description: str
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_vector: str | None
    severity: str | None
    cwe: str | None
    configurations: list[Configuration]
    exploits: list[Exploit]
    rejected: bool = False
    skipped_rules: list[str] = field(default_factory=list)


def transform(item: dict) -> Record:
    """Convert one element of a feed's "vulnerabilities" array.

    Rejected CVEs are returned with rejected=True and no other data so the
    loader can remove any earlier copy. Criteria that cannot be parsed are
    reported in skipped_rules rather than aborting the build.
    """
    c = item["cve"]
    cve_id = c["id"]
    if c.get("vulnStatus") == "Rejected":
        return Record(cve_id, None, None, "", None, None, None, None, None, None, [], [], rejected=True)

    metrics = c.get("metrics") or {}
    v3 = _pick_metric(metrics, ("cvssMetricV31", "cvssMetricV30"))
    v4 = _pick_metric(metrics, ("cvssMetricV40",))
    v2 = _pick_metric(metrics, ("cvssMetricV2",))
    severity = _severity(v3) or _severity(v4) or _severity(v2)

    rec = Record(
        cve_id=cve_id,
        published_at=c.get("published"),
        modified_at=c.get("lastModified"),
        description=_english(c.get("descriptions") or []),
        cvss_v3_score=_score(v3),
        cvss_v3_vector=_vector(v3),
        cvss_v4_score=_score(v4),
        cvss_v4_vector=_vector(v4),
        severity=severity,
        cwe=_cwes(c.get("weaknesses") or []),
        configurations=[],
        exploits=_exploits(c.get("references") or []),
    )
    for cfg in c.get("configurations") or []:
        nodes = []
        for n in cfg.get("nodes") or []:
            matches = []
            for m in n.get("cpeMatch") or []:
                criteria = m.get("criteria", "")
                try:
                    part, vendor, product = cpe.lookup_key(criteria)
                except cpe.CPEError as e:
                    rec.skipped_rules.append(f"{cve_id}: {criteria!r}: {e}")
                    continue
                matches.append(Match(
                    criteria=criteria, part=part, vendor=vendor, product=product,
                    vulnerable=bool(m.get("vulnerable")),
                    start_including=m.get("versionStartIncluding"),
                    start_excluding=m.get("versionStartExcluding"),
                    end_including=m.get("versionEndIncluding"),
                    end_excluding=m.get("versionEndExcluding"),
                ))
            nodes.append(Node(_operator(n.get("operator")), bool(n.get("negate")), matches))
        rec.configurations.append(Configuration(_operator(cfg.get("operator")), nodes))
    return rec


def _operator(op) -> str:
    return op if op in ("AND", "OR") else "OR"


def _pick_metric(metrics: dict, keys: tuple[str, ...]) -> dict | None:
    """Choose one CVSS metric: earlier keys win (v3.1 before v3.0), and within
    a key the Primary entry wins, then NVD's own, then the first listed.
    Entries without cvssData (e.g. other metric types) are ignored."""
    for key in keys:
        entries = [e for e in metrics.get(key) or [] if isinstance(e.get("cvssData"), dict)]
        if not entries:
            continue
        def rank(e):
            return (e.get("type") != "Primary", e.get("source") != NVD_SOURCE)
        return min(entries, key=rank)
    return None


def _score(m: dict | None) -> float | None:
    if m is None:
        return None
    s = m["cvssData"].get("baseScore")
    return float(s) if isinstance(s, (int, float)) else None


def _vector(m: dict | None) -> str | None:
    return m["cvssData"].get("vectorString") if m else None


def _severity(m: dict | None) -> str | None:
    if m is None:
        return None
    # CVSS v3/v4 keep severity in cvssData; v2 keeps it on the metric itself.
    return m["cvssData"].get("baseSeverity") or m.get("baseSeverity")


def _english(descriptions: list) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _cwes(weaknesses: list) -> str | None:
    seen = []
    for w in weaknesses:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in seen:
                seen.append(v)
    return ",".join(seen) or None


def _exploits(references: list) -> list[Exploit]:
    """References NVD tagged "Exploit". This is evidence that exploit
    material was referenced, not that it was verified to work."""
    out, seen = [], set()
    for r in references:
        tags = r.get("tags") or []
        url = r.get("url")
        if "Exploit" in tags and url and url not in seen:
            seen.add(url)
            out.append(Exploit(url, json.dumps({"reference_source": r.get("source"), "tags": tags},
                                               sort_keys=True)))
    return out
