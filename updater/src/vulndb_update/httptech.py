"""Web technology name -> NVD CPE map (data/http_tech.json).

Generated from the GPL-3.0 webappanalyzer fingerprint corpus; feeds the
`bunyip ingest` adapter, which maps a web fingerprinter's detected technology
names to CPE identities. Mappings are leads (the corpus has occasional
errors), so ingested matches are reported at reduced confidence.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from . import cpe


@dataclass(frozen=True)
class HTTPTech:
    name: str
    vendor: str
    product: str
    source: str


def load(path: Path) -> list[HTTPTech]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise ValueError(f"{path}: missing source")
    rows, seen = [], set()
    for i, t in enumerate(doc.get("tech", [])):
        where = f"{path}: tech[{i}]"
        name, vendor, product = t.get("name"), t.get("vendor"), t.get("product")
        if not name or not vendor or not product:
            raise ValueError(f"{where}: name, vendor and product are required")
        cpe.parse_pattern(f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*")
        key = (name.lower(), vendor, product)
        if key in seen:
            raise ValueError(f"{where}: duplicate {key}")
        seen.add(key)
        rows.append(HTTPTech(name, vendor, product, source))
    return rows


def targets_without_rules(conn, rows: list[HTTPTech]) -> list[str]:
    out = []
    for vp in sorted({(r.vendor, r.product) for r in rows}):
        if conn.execute("SELECT 1 FROM cve_matches WHERE criteria_part='a' AND criteria_vendor=?"
                        " AND criteria_product=? AND vulnerable=1 LIMIT 1", vp).fetchone() is None:
            out.append(":".join(vp))
    return out
