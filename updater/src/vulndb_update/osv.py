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

from . import debversion, rpmversion


@dataclass(frozen=True)
class Distro:
    name: str                 # our distro key, e.g. "ubuntu"
    ecosystem: str            # OSV ecosystem export name, e.g. "Ubuntu"
    record_prefix: str        # per-CVE record id prefix (primary source)
    standard: re.Pattern
    pro: re.Pattern | None
    # Per-advisory records (Debian DSA/DLA) used only where no per-CVE row
    # exists for a CVE/release/package, e.g. Debian 11 (LTS) fixes.
    advisory_prefixes: tuple[str, ...] = ()
    # Whether `versions` of no-fix entries list only that release's versions
    # (Ubuntu) or the whole archive (Debian), which would be misleading.
    unfixed_versions_release_specific: bool = True
    # Whether a per-CVE fixed version is always a package of that release.
    # Debian's may be an unstable version that predates the release.
    fixed_version_in_release: bool = True
    # Release encoded in package versions, e.g. Debian "+deb12u3" -> "12".
    release_in_version: re.Pattern | None = None
    urgency_key: str | None = None
    scheme: str = "dpkg"  # package version ordering: "dpkg" or "rpm"

    def compare(self, a: str, b: str) -> int:
        return (rpmversion if self.scheme == "rpm" else debversion).compare(a, b)


DISTROS = {
    "ubuntu": Distro(
        name="ubuntu", ecosystem="Ubuntu", record_prefix="UBUNTU-CVE-",
        # "Ubuntu:24.04:LTS", "Ubuntu:25.10". Pro (ESM) streams are kept;
        # FIPS / Realtime / vendor kernels cannot be told apart by a network
        # scan and are skipped.
        standard=re.compile(r"Ubuntu:(\d\d\.\d\d)(?::LTS)?"),
        pro=re.compile(r"Ubuntu:Pro:(\d\d\.\d\d):LTS"),
        release_in_version=re.compile(r"ubuntu0\.(\d\d\.\d\d)"),
        urgency_key="ubuntu_priority",
    ),
    "debian": Distro(
        name="debian", ecosystem="Debian", record_prefix="DEBIAN-CVE-",
        standard=re.compile(r"Debian:(\d+(?:\.\d+)?)"),  # "Debian:12" (bookworm)
        pro=None,
        advisory_prefixes=("DSA-", "DLA-"),
        unfixed_versions_release_specific=False,
        fixed_version_in_release=False,
        release_in_version=re.compile(r"[+~]deb(\d+)u\d+"),
        urgency_key="urgency",
    ),
    # Red Hat family: per-advisory records only (RHSA/RLSA/ALSA ...), fixed
    # entries only, no affected-version lists. Release = major version;
    # RHEL extended-support streams (EUS/AUS/TUS/E4S) and other Red Hat
    # products (OpenShift, JBoss, Satellite, ...) are not loaded.
    "redhat": Distro(
        name="redhat", ecosystem="Red Hat", record_prefix="",
        standard=re.compile(r"Red Hat:enterprise_linux:(\d+)(?:\.\d+)?(?:::\w+)?"), pro=None,
        advisory_prefixes=("RHSA-", "RHBA-", "RHEA-"),
        release_in_version=re.compile(r"[._+]el(\d+)"), scheme="rpm",
    ),
    "rocky": Distro(
        name="rocky", ecosystem="Rocky Linux", record_prefix="",
        standard=re.compile(r"Rocky Linux:(\d+)"), pro=None,
        advisory_prefixes=("RLSA-", "RLBA-", "RLEA-", "RXSA-"),
        release_in_version=re.compile(r"[._+]el(\d+)"), scheme="rpm",
    ),
    "almalinux": Distro(
        name="almalinux", ecosystem="AlmaLinux", record_prefix="",
        standard=re.compile(r"AlmaLinux:(\d+)"), pro=None,
        advisory_prefixes=("ALSA-", "ALBA-", "ALEA-"),
        release_in_version=re.compile(r"[._+]el(\d+)"), scheme="rpm",
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
    urgency: str | None = None
    stream: str = ""

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.cve_id, self.release, self.channel, self.package, self.stream


@dataclass(frozen=True)
class PackageVersion:
    distro: str
    release: str
    package: str
    version: str
    upstream: str


def upstream_of(version: str) -> str:
    """Package version -> upstream part: "1:9.6p1-3ubuntu13.3" -> "9.6p1",
    "1:1.20.1-1.module+el8..." -> "1.20.1"."""
    v = version.split(":", 1)[1] if ":" in version else version
    return v.rsplit("-", 1)[0] if "-" in v else v


def module_stream(fixed: str | None) -> str:
    """RHEL AppStream module builds ("...module+el8.4.0+..."): the stream is
    the upstream major.minor ("1.14"). Fixes in one module stream say nothing
    about another stream of the same package in the same release."""
    if not fixed or ".module" not in fixed:
        return ""
    parts = upstream_of(fixed).split(".")
    return ".".join(parts[:2])


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


def _cve_ids(record: dict, per_cve: bool) -> list[str]:
    """CVE ids a record covers: one for per-CVE records, possibly several
    for per-advisory records (DSA/DLA)."""
    ids = []
    for a in (record.get("upstream") or []) + (record.get("aliases") or []) + (record.get("related") or []):
        if re.fullmatch(r"CVE-\d{4}-\d+", a) and a not in ids:
            ids.append(a)
    if not ids:
        m = re.search(r"CVE-\d{4}-\d+", record.get("id", ""))
        ids = [m.group(0)] if m else []
    return ids[:1] if per_cve else ids


def _older_than(d: "Distro", v: str, fixed: str) -> bool:
    try:
        return d.compare(v, fixed) < 0
    except ValueError:
        return False


@dataclass
class Transformed:
    rows: list[AdvisoryRow]
    versions: set[PackageVersion]
    withdrawn: bool = False


def transform(record: dict, d: Distro, packages: set[str], per_cve: bool = True) -> Transformed:
    """Turn one OSV record into advisory rows for the mapped packages.

    Affected-version lists are only trusted when they describe the release:
    for fixed entries, versions older than the fix are kept; for no-fix
    entries the list is used only if the distribution's lists are
    release-specific (Ubuntu yes, Debian no).
    """
    out = Transformed([], set())
    if record.get("withdrawn"):
        out.withdrawn = True
        return out
    cves = _cve_ids(record, per_cve)
    if not cves:
        return out
    for a in record.get("affected") or []:
        pkg = a.get("package") or {}  # some entries carry only git ranges
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
                    fixed = ev["fixed"]  # one fix point per release
        listed = [v for v in a.get("versions") or [] if isinstance(v, str)]
        if fixed:
            affected = [v for v in listed if _older_than(d, v, fixed)]
        else:
            affected = listed if d.unfixed_versions_release_specific else []
        urgency = (a.get("ecosystem_specific") or {}).get(d.urgency_key) if d.urgency_key else None
        for cve in cves:
            out.rows.append(AdvisoryRow(
                source=f"osv:{d.ecosystem}", advisory_id=record["id"], cve_id=cve, distro=d.name,
                release=release, channel=channel, codename=_codename(pkg.get("purl")), package=name,
                fixed_version=fixed,
                affected_upstreams=" ".join(sorted({upstream_of(v) for v in affected})),
                modified_at=record.get("modified"), urgency=urgency, stream=module_stream(fixed),
            ))
        if channel == "standard":
            known = list(affected)
            if fixed and (d.fixed_version_in_release or not per_cve or _version_release(d, fixed) == release):
                known.append(fixed)
            for v in known:
                out.versions.add(PackageVersion(d.name, release, name, v, upstream_of(v)))
    return out


def _version_release(d: Distro, version: str) -> str | None:
    if d.release_in_version and (m := d.release_in_version.search(version)):
        return m.group(1)
    return None


def iter_records(zip_path: Path, prefixes: str | tuple[str, ...]):
    """Yield the decoded records of an OSV ecosystem zip whose ids start
    with one of the given prefixes."""
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.rsplit("/", 1)[-1]
            if name.startswith(prefixes) and name.endswith(".json"):
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
