"""Curated Windows build map (data/windows_builds.json)."""

import datetime
import json
from dataclasses import dataclass
from pathlib import Path

from . import cpe


@dataclass(frozen=True)
class WindowsBuild:
    build: int
    kind: str
    name: str
    cpes: str  # space-separated CPE 2.3 names
    eol: str
    support: str
    source: str


def load(path: Path) -> list[WindowsBuild]:
    """Read and validate the build map: every CPE must parse and name a
    Microsoft operating system; dates must be YYYY-MM-DD."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise ValueError(f"{path}: missing source")
    rows, seen = [], set()
    for i, b in enumerate(doc.get("builds", [])):
        where = f"{path}: builds[{i}]"
        key = (b.get("build"), b.get("kind"))
        if not isinstance(key[0], int) or key[1] not in ("server", "client") or key in seen:
            raise ValueError(f"{where}: missing, invalid or duplicate build/kind {key}")
        seen.add(key)
        datetime.date.fromisoformat(b["eol"])
        names = []
        for short in b.get("cpes") or []:
            parts = short.split(":")
            if len(parts) != 3:
                raise ValueError(f"{where}: cpe {short!r} must be product:version:update")
            # The engine queries these as concrete identities: no embedded
            # wildcards, and the version names the release ("-" or e.g. "1607").
            if parts[1] == "*" or any(c in v for v in parts for c in "*?" if v != "*"):
                raise ValueError(f"{where}: cpe {short!r} must not use wildcards (except a whole-value update)")
            full = f"cpe:2.3:o:microsoft:{parts[0]}:{parts[1]}:{parts[2]}:*:*:*:*:*:*"
            cpe.parse_pattern(full)
            names.append(full)
        if not names or not b.get("name") or not b.get("support"):
            raise ValueError(f"{where}: name, support and at least one cpe are required")
        rows.append(WindowsBuild(key[0], key[1], b["name"], " ".join(names), b["eol"], b["support"], source))
    return rows
