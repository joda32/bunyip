"""Curated Nmap product names (data/product_names.json).

Nmap fingerprints many services without an application CPE. This map gives
reviewed names an NVD identity (kind 'product') or marks them as
operating-system built-ins (kind 'os_component'). Automatic name matching is
not used: it mostly finds the wrong software. `review` only proposes
candidates for a person to decide.
"""

import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import cpe

CONFIDENCE = ("HIGH", "MEDIUM")
VERSION = ("nmap", "none")
# Constructs that Go's RE2 does not support; patterns must work in both.
_UNPORTABLE = re.compile(r"\(\?[=!<]|\\[1-9]")


@dataclass(frozen=True)
class ProductName:
    pattern: str
    match: str  # 'exact' or 'regex'
    kind: str  # 'product' or 'os_component'
    part: str
    vendor: str
    product: str
    os: str
    version: str
    confidence: str
    note: str
    source: str


def _pattern(where: str, e: dict) -> tuple[str, str]:
    pattern, match = e.get("pattern"), e.get("match", "exact")
    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError(f"{where}: pattern is required")
    if match not in ("exact", "regex"):
        raise ValueError(f"{where}: match must be 'exact' or 'regex'")
    if match == "regex":
        if _UNPORTABLE.search(pattern):
            raise ValueError(f"{where}: lookaround and back-references are not portable to Go: {pattern!r}")
        if not (pattern.startswith("^") and pattern.endswith("$")):
            raise ValueError(f"{where}: regex must be anchored with ^...$: {pattern!r}")
        re.compile(pattern)
    return pattern, match


def load(path: Path) -> list[ProductName]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise ValueError(f"{path}: missing source")
    rows: list[ProductName] = []
    seen = set()

    def add(row: ProductName, where: str):
        key = (row.pattern, row.kind, row.vendor, row.product)
        if key in seen:
            raise ValueError(f"{where}: duplicate entry {key}")
        seen.add(key)
        rows.append(row)

    for i, e in enumerate(doc.get("os_components", [])):
        where = f"{path}: os_components[{i}]"
        pattern, match = _pattern(where, e)
        if e.get("os") != "windows":
            raise ValueError(f"{where}: os must be 'windows' (the only OS with a host-level assessment)")
        add(ProductName(pattern, match, "os_component", "", "", "", "windows", "none", "HIGH",
                        e.get("note", ""), source), where)

    for i, e in enumerate(doc.get("products", [])):
        where = f"{path}: products[{i}]"
        pattern, match = _pattern(where, e)
        if e.get("version") not in VERSION:
            raise ValueError(f"{where}: version must be one of {VERSION}")
        if e.get("confidence") not in CONFIDENCE:
            raise ValueError(f"{where}: confidence must be one of {CONFIDENCE}")
        targets = e.get("cpes") or []
        if not targets:
            raise ValueError(f"{where}: at least one vendor:product is required")
        for t in targets:
            parts = t.split(":")
            if len(parts) != 2 or not all(parts):
                raise ValueError(f"{where}: {t!r} must be vendor:product")
            p = cpe.parse_pattern(f"cpe:2.3:a:{parts[0]}:{parts[1]}:*:*:*:*:*:*:*:*")
            add(ProductName(pattern, match, "product", p[0], p[1], p[2], "", e["version"],
                            e["confidence"], e.get("note", ""), source), where)
    return rows


def targets_without_rules(conn: sqlite3.Connection, rows: list[ProductName]) -> list[str]:
    """Product targets NVD has no vulnerable rules for (likely a typo)."""
    out = []
    for vp in sorted({(r.vendor, r.product) for r in rows if r.kind == "product"}):
        n = conn.execute("SELECT 1 FROM cve_matches WHERE criteria_part = 'a' AND criteria_vendor = ?"
                         " AND criteria_product = ? AND vulnerable = 1 LIMIT 1", vp).fetchone()
        if n is None:
            out.append(":".join(vp))
    return out


# --- review ---------------------------------------------------------------

_P = re.compile(r" p/([^/]*)/")
_V = re.compile(r" v/([^/]*)/")


# Role words Nmap appends to a product name ("hMailServer smtpd").
_ROLE_SUFFIXES = {"smtpd", "pop3d", "imapd", "ftpd", "httpd", "sshd", "telnetd", "nntpd", "ldapd", "daemon"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


@dataclass
class Candidate:
    nmap_product: str
    versions: list[str]  # Nmap version templates, e.g. ['$1', '<none>']
    targets: list[tuple[str, str, int]]  # (vendor, product, CVE count)


def review(db: Path, probes: Path, curated: Path) -> list[Candidate]:
    """Nmap product names without an application CPE whose normalised name is
    an NVD product (alone or after a vendor-like prefix). Only proposals:
    each needs a human decision, including whether Nmap's version field is
    the product version."""
    names: dict[str, Counter] = defaultdict(Counter)
    with_cpe = set()
    for line in Path(probes).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith(("match ", "softmatch ")):
            continue
        m = _P.search(line)
        if not m or "$" in m.group(1):
            continue
        if " cpe:/a:" in line:
            with_cpe.add(m.group(1))
            continue
        v = _V.search(line)
        names[m.group(1)][v.group(1) if v else "<none>"] += 1
    rows = load(curated) if Path(curated).exists() else []
    done = {r.pattern for r in rows if r.match == "exact"}
    done_regex = [r.pattern for r in rows if r.match == "regex"]
    doc = json.loads(Path(curated).read_text(encoding="utf-8")) if Path(curated).exists() else {}
    done |= set(doc.get("rejected", []))

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        prods: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for v, p, n in conn.execute(
                "SELECT criteria_vendor, criteria_product, COUNT(DISTINCT cve_id) FROM cve_matches"
                " WHERE criteria_part = 'a' AND vulnerable = 1 GROUP BY 1, 2"):
            prods[p].append((v, n))
    finally:
        conn.close()

    out = []
    def covered(name: str) -> bool:
        return name in done or any(re.fullmatch(p, name) for p in done_regex)

    for name in sorted(n for n in names if n not in with_cpe and not covered(n)):
        full = _norm(name).split("_")
        variants = [full]
        if len(full) > 1 and full[-1] in _ROLE_SUFFIXES:
            variants.append(full[:-1])
        targets = []
        for toks in variants:
            for i in range(len(toks)):
                p, prefix = "_".join(toks[i:]), "_".join(toks[:i])
                for v, n in prods.get(p, []):
                    if i == 0 or prefix in (v, v.replace("_", "")):
                        targets.append((v, p, n))
        if targets:
            out.append(Candidate(name, [t for t, _ in names[name].most_common()], sorted(set(targets))))
    return out
