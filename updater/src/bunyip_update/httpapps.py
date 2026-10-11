"""Curated HTTP application fingerprints (data/http_apps.json).

Web applications sit behind a generic web server, so Nmap's service product
does not name them; their identity is in HTTP evidence (Server header, a
generator meta tag, a telltale response header, the page title). Each row maps
a regex over one evidence source to an NVD vendor:product, optionally
capturing the version.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import cpe

EVIDENCE = ("server", "generator", "header", "title", "x_powered_by")
CONFIDENCE = ("HIGH", "MEDIUM")
# Go's RE2 does not support lookaround or back-references; keep patterns portable.
_UNPORTABLE = re.compile(r"\(\?[=!<]|\\[1-9]")


@dataclass(frozen=True)
class HTTPApp:
    evidence: str
    header: str
    pattern: str
    vendor: str
    product: str
    version_group: int
    confidence: str
    note: str
    source: str


def load(path: Path) -> list[HTTPApp]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise ValueError(f"{path}: missing source")
    rows: list[HTTPApp] = []
    seen = set()
    for i, a in enumerate(doc.get("apps", [])):
        where = f"{path}: apps[{i}]"
        ev = a.get("evidence")
        if ev not in EVIDENCE:
            raise ValueError(f"{where}: evidence must be one of {EVIDENCE}")
        header = (a.get("header") or "").lower()
        if (ev == "header") != bool(header):
            raise ValueError(f"{where}: 'header' is required iff evidence='header'")
        pattern = a.get("pattern")
        if not pattern:
            raise ValueError(f"{where}: pattern is required")
        if _UNPORTABLE.search(pattern):
            raise ValueError(f"{where}: lookaround/back-references are not portable to Go: {pattern!r}")
        compiled = re.compile(pattern)  # validity
        vendor, product = a.get("vendor"), a.get("product")
        if not vendor or not product:
            raise ValueError(f"{where}: vendor and product are required")
        cpe.parse_pattern(f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*")  # canonical check
        vg = a.get("version_group", 0)
        if not isinstance(vg, int) or vg < 0 or vg > compiled.groups:
            raise ValueError(f"{where}: version_group {vg} out of range (pattern has {compiled.groups} groups)")
        if a.get("confidence") not in CONFIDENCE:
            raise ValueError(f"{where}: confidence must be one of {CONFIDENCE}")
        key = (ev, header, pattern, vendor, product)
        if key in seen:
            raise ValueError(f"{where}: duplicate entry {key}")
        seen.add(key)
        rows.append(HTTPApp(ev, header, pattern, vendor, product, vg, a["confidence"], a.get("note", ""), source))
    return rows
