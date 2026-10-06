"""Curated identity aliases (data/aliases.json) and the review helper that
proposes new ones.

An alias maps an observed vendor/product (as reported by Nmap) to the name NVD
uses for the same software. The query engine always queries the observed
identity too; aliases only add candidates. Every alias is reviewed by a
person: product-name similarity alone is wrong about a third of the time.
"""

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import cpe

CONFIDENCES = ("HIGH", "MEDIUM", "LOW")


class AliasError(ValueError):
    """Raised for an invalid aliases file."""


@dataclass(frozen=True)
class AliasRow:
    part: str
    observed_vendor: str
    observed_product: str
    canonical_vendor: str
    canonical_product: str
    source: str
    confidence: str

    @property
    def canonical_cpe_prefix(self) -> str:
        return f"cpe:2.3:{self.part}:{self.canonical_vendor}:{self.canonical_product}"


def _triple(s: str, where: str) -> tuple[str, str, str]:
    """Parse and canonicalise "part:vendor:product"."""
    bits = s.split(":")
    if len(bits) != 3:
        raise AliasError(f"{where}: {s!r} must be part:vendor:product")
    try:
        v = cpe.parse_pattern(f"cpe:2.3:{bits[0]}:{bits[1]}:{bits[2]}:*:*:*:*:*:*:*:*")
    except cpe.CPEError as e:
        raise AliasError(f"{where}: {s!r}: {e}") from None
    if cpe.ANY in v[1:3] or cpe.NA in v[1:3]:
        raise AliasError(f"{where}: {s!r} needs a specific vendor and product")
    return v[0], v[1], v[2]


def load(path: Path) -> tuple[list[AliasRow], set[tuple[str, str, str]]]:
    """Read and validate the aliases file. Returns the alias rows and the set
    of rejected observed identities."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise AliasError(f"{path}: missing source")
    rows, observed_seen = [], set()
    for i, a in enumerate(doc.get("aliases", [])):
        where = f"{path}: aliases[{i}]"
        obs = _triple(a.get("observed", ""), where)
        if obs in observed_seen:
            raise AliasError(f"{where}: duplicate observed {a['observed']!r}")
        observed_seen.add(obs)
        conf = a.get("confidence")
        if conf not in CONFIDENCES:
            raise AliasError(f"{where}: confidence must be one of {CONFIDENCES}")
        targets = a.get("canonical") or []
        if not targets:
            raise AliasError(f"{where}: no canonical targets")
        for t in targets:
            can = _triple(t, where)
            if can[0] != obs[0]:
                raise AliasError(f"{where}: alias may not change CPE part ({obs[0]} -> {can[0]})")
            if can == obs:
                raise AliasError(f"{where}: alias maps {a['observed']!r} to itself")
            rows.append(AliasRow(obs[0], obs[1], obs[2], can[1], can[2], source, conf))
    rejected = set()
    for i, r in enumerate(doc.get("rejected", [])):
        rej = _triple(r.get("observed", ""), f"{path}: rejected[{i}]")
        if rej in observed_seen:
            raise AliasError(f"{path}: {r['observed']!r} is both aliased and rejected")
        rejected.add(rej)
    return rows, rejected


# --- review helper ---------------------------------------------------------

_NMAP_CPE = re.compile(r"cpe:/([aoh]):([^:\s|/$]+):([^:\s|/$]+)")
_NMAP_PRODUCT = re.compile(r" p/([^/]*)/")


def nmap_templates(probes: Path) -> dict[tuple[str, str, str], str]:
    """Literal application (part "a") CPE templates in nmap-service-probes,
    with an example Nmap product name for each. OS/hardware CPEs are not
    queried from service output, so they are not reviewed."""
    out = {}
    for line in Path(probes).read_text(encoding="latin-1").splitlines():
        if not line.startswith(("match ", "softmatch ")):
            continue
        pm = _NMAP_PRODUCT.search(line)
        for part, vendor, product in _NMAP_CPE.findall(line):
            if part != "a":
                continue
            try:
                key = _triple(f"{part}:{vendor}:{product}", "nmap")
            except AliasError:
                continue
            out.setdefault(key, pm.group(1) if pm else "?")
    return out


@dataclass
class Candidate:
    kind: str           # "vendor-mismatch" or "newer-vendor"
    observed: str
    nmap_product: str
    targets: list[str]  # "vendor (CVE count, newest year)"
    weight: int


def review(db_path: Path, probes: Path, aliases_path: Path) -> list[Candidate]:
    """Propose aliases for human review: Nmap identities whose product NVD
    records under a different vendor, either exclusively ("vendor-mismatch")
    or for newer CVEs ("newer-vendor"). Already curated or rejected
    identities are skipped. Output is a starting point, not a decision."""
    rows, rejected = load(aliases_path)
    curated = {(r.part, r.observed_vendor, r.observed_product) for r in rows}
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    stats = defaultdict(dict)  # (part, product) -> vendor -> (cves, newest year)
    for part, vendor, product, n, year in db.execute(
            "SELECT m.criteria_part, m.criteria_vendor, m.criteria_product, COUNT(DISTINCT m.cve_id),"
            " MAX(substr(c.published_at, 1, 4)) FROM cve_matches m JOIN cves c USING (cve_id)"
            " WHERE m.vulnerable = 1 GROUP BY 1, 2, 3"):
        stats[(part, product)][vendor] = (n, year or "")
    out = []
    for (part, vendor, product), nmap_product in nmap_templates(probes).items():
        if (part, vendor, product) in curated | rejected:
            continue
        vendors = stats.get((part, product), {})
        mine = vendors.get(vendor)
        others = {v: s for v, s in vendors.items() if v != vendor}
        if mine is None:
            pick, kind = others, "vendor-mismatch"
        else:
            pick = {v: s for v, s in others.items() if s[1] > mine[1] and s[0] >= 5}
            kind = "newer-vendor"
        if not pick:
            continue
        ranked = sorted(pick.items(), key=lambda kv: -kv[1][0])[:3]
        out.append(Candidate(kind, f"{part}:{vendor}:{product}", nmap_product,
                             [f"{v} ({n} CVEs, newest {y})" for v, (n, y) in ranked],
                             sum(n for _, (n, _) in ranked)))
    return sorted(out, key=lambda c: -c.weight)
