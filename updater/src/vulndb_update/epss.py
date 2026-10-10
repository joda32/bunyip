"""FIRST EPSS (Exploit Prediction Scoring System) snapshot parsing.

The daily file is a gzipped CSV: a leading comment line carries the model
version and score date, then a `cve,epss,percentile` header, then one row per
CVE. Mirrors internal/build/epss.go in the Go builder.

    #model_version:v2025.03.14,score_date:2026-10-10T00:00:00+0000
    cve,epss,percentile
    CVE-1999-0001,0.01234,0.54321
"""

import gzip
from dataclasses import dataclass, field
from pathlib import Path


class EPSSError(RuntimeError):
    """Raised when an EPSS snapshot cannot be parsed."""


@dataclass
class EPSSRow:
    cve_id: str
    score: float
    percentile: float


@dataclass
class EPSSData:
    model_version: str = ""
    score_date: str = ""
    rows: list = field(default_factory=list)


def load(path) -> EPSSData:
    """Parse an EPSS CSV snapshot (gzipped when the path ends in .gz)."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return _parse(f, str(path))


def _parse(lines, where: str) -> EPSSData:
    data = EPSSData()
    seen_header = False
    seen: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            data.model_version, data.score_date = _parse_comment(line)
            continue
        if not seen_header:  # the "cve,epss,percentile" header line
            seen_header = True
            if line.lower().startswith("cve,"):
                continue
            # No header present: fall through and treat this as a data row.
        parts = line.split(",")
        if len(parts) < 3:
            continue
        cve = parts[0].strip().upper()
        if not cve.startswith("CVE-") or cve in seen:
            continue
        try:
            score = float(parts[1].strip())
            percentile = float(parts[2].strip())
        except ValueError:
            continue
        seen.add(cve)
        data.rows.append(EPSSRow(cve, score, percentile))
    if not data.rows:
        raise EPSSError(f"{where}: no EPSS rows parsed")
    return data


def _parse_comment(line: str) -> tuple[str, str]:
    """Extract model_version and score_date from the leading "#key:value,..."
    comment. A value may itself contain colons (the date), so each field is
    split on its first colon only."""
    model = date = ""
    for part in line.lstrip("#").split(","):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip()
        if key == "model_version":
            model = value.strip()
        elif key == "score_date":
            date = value.strip()
    return model, date
