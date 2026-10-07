import base64
import copy
import gzip
import hashlib
import json
import zipfile
import socket
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "schema" / "schema.sql"
NVD_DATA = REPO / "testdata" / "nvd"
OSV_UBUNTU = REPO / "testdata" / "osv" / "ubuntu"
OSV_DEBIAN = REPO / "testdata" / "osv" / "debian"
OSV_DIR = REPO / "testdata" / "osv"
OSV_EXPORTS = {"Ubuntu": "ubuntu", "Debian": "debian", "Red Hat": "redhat", "Rocky Linux": "rocky", "AlmaLinux": "almalinux"}
KEV_FILE = "known_exploited_vulnerabilities.json"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests must never reach the Internet."""
    def refuse(*a, **k):
        raise AssertionError("network access attempted during tests")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def record(cve_id: str) -> dict:
    """A real NVD record from testdata/nvd/records (deep copy, safe to edit)."""
    return copy.deepcopy(json.loads((NVD_DATA / "records" / f"{cve_id}.json").read_text()))


def write_feed(directory: Path, name: str, items: list[dict], last_modified="2026-10-06T01:00:06-04:00"):
    """Write nvdcve-2.0-<name>.json.gz and a .meta whose sha256/size cover the
    uncompressed JSON, exactly as NVD publishes them."""
    body = json.dumps({
        "resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items),
        "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-06T01:00:04.9493803",
        "vulnerabilities": items,
    }, indent=2).encode()
    base = directory / f"nvdcve-2.0-{name}"
    with gzip.open(f"{base}.json.gz", "wb") as f:
        f.write(body)
    Path(f"{base}.meta").write_text(
        f"lastModifiedDate:{last_modified}\r\nsize:{len(body)}\r\nzipSize:0\r\n"
        f"gzSize:0\r\nsha256:{hashlib.sha256(body).hexdigest().upper()}\r\n")


OVERLAY_DESCRIPTION = "[TEST OVERLAY] updated description"


def overlay_records() -> list[dict]:
    """The modified-feed overlay used by the build tests, derived at runtime
    from the real records:
      - CVE-2021-44790 with a newer lastModified and new description (replace)
      - CVE-2021-41773 unchanged (no-op)
      - CVE-2024-34393 now Rejected (remove)
    """
    updated = record("CVE-2021-44790")
    updated["cve"]["lastModified"] = "2026-10-05T00:00:00.000"
    for d in updated["cve"]["descriptions"]:
        if d["lang"] == "en":
            d["value"] = OVERLAY_DESCRIPTION
    rejected = record("CVE-2024-34393")
    rejected["cve"]["vulnStatus"] = "Rejected"
    rejected["cve"]["lastModified"] = "2026-10-05T00:00:00.000"
    return [updated, record("CVE-2021-41773"), rejected]


def make_sources(directory: Path) -> Path:
    """Assemble a complete offline source directory from testdata/nvd."""
    directory.mkdir(parents=True, exist_ok=True)
    by_year: dict[str, list] = {}
    for p in sorted((NVD_DATA / "records").glob("CVE-*.json")):
        year = p.stem.split("-")[1]
        feed = "2002" if int(year) <= 2002 else year  # NVD puts 1999-2002 in the 2002 feed
        by_year.setdefault(feed, []).append(json.loads(p.read_text()))
    for year, items in by_year.items():
        write_feed(directory, year, items, last_modified="2026-10-05T03:00:00-04:00")
    write_feed(directory, "modified", overlay_records())
    (directory / KEV_FILE).write_bytes((NVD_DATA / KEV_FILE).read_bytes())
    for ecosystem, sub in OSV_EXPORTS.items():
        write_osv_export(directory, ecosystem, sorted((OSV_DIR / sub).glob("*.json")))
    return directory


def write_osv_export(directory: Path, ecosystem: str, records: list[Path]) -> None:
    """Assemble an OSV ecosystem export (all.zip) and its MD5 meta file the way
    the updater caches downloads from osv-vulnerabilities.storage.googleapis.com."""
    zip_path = directory / f"osv-{ecosystem}-all.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in records:
            z.writestr(p.name, p.read_text())
    md5 = base64.b64encode(hashlib.md5(zip_path.read_bytes()).digest()).decode()
    (directory / f"osv-{ecosystem}-all.meta.json").write_text(
        json.dumps({"md5": md5, "last_modified": "Tue, 06 Oct 2026 05:17:52 GMT"}))


@pytest.fixture
def sources(tmp_path) -> Path:
    return make_sources(tmp_path / "sources")
