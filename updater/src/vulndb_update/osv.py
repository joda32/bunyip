"""Distribution security advisories from OSV.dev ecosystem exports.

OSV.dev republishes distribution data (Ubuntu, Debian, Red Hat, ...) in one
format, one zip per ecosystem. For Ubuntu, the per-CVE records
(UBUNTU-CVE-*) list, per release and source package:
  - a `fixed` version (or none: affected, no fix released), and
  - `versions`: the package versions known to be affected.
Releases that are not affected are simply absent, so a missing row means
"no data", never "not affected".

Only packages in the curated CPE -> package map are stored; the export is
dominated by kernel packages that a network scan can never observe.
"""

import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class Distro:
    name: str           # our distro key, e.g. "ubuntu"
    ecosystem: str      # OSV ecosystem export name, e.g. "Ubuntu"
    record_prefix: str  # per-CVE record id prefix
    standard: re.Pattern
    pro: re.Pattern | None


DISTROS = {
    "ubuntu": Distro(
        name="ubuntu", ecosystem="Ubuntu", record_prefix="UBUNTU-CVE-",
        # "Ubuntu:24.04:LTS", "Ubuntu:25.10". Pro (ESM) streams are kept;
        # FIPS / Realtime / vendor kernels cannot be told apart by a network
        # scan and are skipped.
        standard=re.compile(r"Ubuntu:(\d\d\.\d\d)(?::LTS)?"),
        pro=re.compile(r"Ubuntu:Pro:(\d\d\.\d\d):LTS"),
    ),
}


@dataclass
class AdvisoryRow:
    source: str
    advisory_id: str
    cve_id: str
    distro: str
    release: str
    channel: str
    codename: str | None
    package: str
    fixed_version: str | None
    affected_upstreams: str
    modified_at: str | None


@dataclass(frozen=True)
class PackageVersion:
    distro: str
    release: str
    package: str
    version: str
    upstream: str


def upstream_of(version: str) -> str:
    """Debian version -> upstream part: "1:9.6p1-3ubuntu13.3" -> "9.6p1"."""
    v = version.split(":", 1)[1] if ":" in version else version
    return v.rsplit("-", 1)[0] if "-" in v else v


def parse_ecosystem(d: Distro, eco: str) -> tuple[str, str] | None:
    if m := d.standard.fullmatch(eco):
        return m.group(1), "standard"
    if d.pro and (m := d.pro.fullmatch(eco)):
        return m.group(1), "pro"
    return None


def _codename(purl: str | None) -> str | None:
    if not purl:
        return None
    q = parse_qs(urlsplit(purl.replace("pkg:", "pkg://", 1)).query)
    return (q.get("distro") or [None])[0]


def _cve_id(record: dict) -> str | None:
    for a in (record.get("upstream") or []) + (record.get("aliases") or []):
        if a.startswith("CVE-"):
            return a
    rid = record.get("id", "")
    m = re.search(r"CVE-\d{4}-\d+", rid)
    return m.group(0) if m else None


@dataclass
class Transformed:
    rows: list[AdvisoryRow]
    versions: set[PackageVersion]
    withdrawn: bool = False


def transform(record: dict, d: Distro, packages: set[str]) -> Transformed:
    out = Transformed([], set())
    if record.get("withdrawn"):
        out.withdrawn = True
        return out
    cve = _cve_id(record)
    if not cve:
        return out
    for a in record.get("affected") or []:
        pkg = a.get("package") or {}
        name = pkg.get("name")
        if name not in packages:
            continue
        rc = parse_ecosystem(d, pkg.get("ecosystem", ""))
        if rc is None:
            continue
        release, channel = rc
        fixed = None
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed = ev["fixed"]  # Ubuntu publishes one fix point per release
        affected = [v for v in a.get("versions") or [] if isinstance(v, str)]
        out.rows.append(AdvisoryRow(
            source=f"osv:{d.ecosystem}", advisory_id=record["id"], cve_id=cve, distro=d.name,
            release=release, channel=channel, codename=_codename(pkg.get("purl")), package=name,
            fixed_version=fixed,
            affected_upstreams=" ".join(sorted({upstream_of(v) for v in affected})),
            modified_at=record.get("modified"),
        ))
        if channel == "standard":
            for v in affected + ([fixed] if fixed else []):
                out.versions.add(PackageVersion(d.name, release, name, v, upstream_of(v)))
    return out


def iter_records(zip_path: Path, prefix: str):
    """Yield the decoded per-CVE records of an OSV ecosystem zip."""
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.rsplit("/", 1)[-1]
            if name.startswith(prefix) and name.endswith(".json"):
                yield json.loads(z.read(info))


# --- curated package map ----------------------------------------------------

@dataclass(frozen=True)
class PackageMapRow:
    part: str
    vendor: str
    product: str
    distro: str
    package: str
    source: str


def load_package_map(path: Path) -> list[PackageMapRow]:
    from . import cpe  # local import: cpe has no dependency on this module
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    source = doc.get("source")
    if not source:
        raise ValueError(f"{path}: missing source")
    rows, seen = [], set()
    for i, e in enumerate(doc.get("packages", [])):
        bits = (e.get("cpe") or "").split(":")
        if len(bits) != 3:
            raise ValueError(f"{path}: packages[{i}]: cpe must be part:vendor:product")
        v = cpe.parse_pattern(f"cpe:2.3:{bits[0]}:{bits[1]}:{bits[2]}:*:*:*:*:*:*:*:*")
        for distro, pkgs in e.items():
            if distro == "cpe":
                continue
            if distro not in DISTROS:
                raise ValueError(f"{path}: packages[{i}]: unknown distro {distro!r}")
            for p in pkgs:
                key = (v[0], v[1], v[2], distro, p)
                if key in seen:
                    raise ValueError(f"{path}: packages[{i}]: duplicate {key}")
                seen.add(key)
                rows.append(PackageMapRow(v[0], v[1], v[2], distro, p, source))
    return rows
