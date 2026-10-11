"""Transform the CISA Known Exploited Vulnerabilities catalogue."""

import json
from dataclasses import dataclass
from pathlib import Path


class KEVError(ValueError):
    """Raised when the catalogue is not in the expected shape."""


@dataclass
class KEVRow:
    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str | None
    due_date: str | None
    known_ransomware: str | None
    notes: str | None


@dataclass
class Catalogue:
    catalog_version: str
    date_released: str
    rows: list[KEVRow]


def load(path: Path) -> Catalogue:
    """Read and validate the KEV JSON file. Unknown fields are ignored so new
    CISA additions (e.g. forensicTriage) do not break the build."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise KEVError(f"{path}: not a KEV catalogue (no vulnerabilities list)")
    version = doc.get("catalogVersion")
    if not version:
        raise KEVError(f"{path}: missing catalogVersion")
    rows, seen = [], set()
    for v in doc["vulnerabilities"]:
        cve_id = v.get("cveID")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        rows.append(KEVRow(
            cve_id=cve_id,
            vendor_project=v.get("vendorProject"),
            product=v.get("product"),
            vulnerability_name=v.get("vulnerabilityName"),
            date_added=v.get("dateAdded"),
            due_date=v.get("dueDate"),
            known_ransomware=v.get("knownRansomwareCampaignUse"),
            notes=v.get("notes"),
        ))
    return Catalogue(version, doc.get("dateReleased", ""), rows)
