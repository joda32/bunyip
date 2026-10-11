"""Download and verify source data.

Security boundary: this is the only module that touches the network. Only
HTTPS URLs on allow-listed hosts are fetched, downloads are size-capped, and
NVD feeds are verified against the sha256 in their .meta file (which NVD
computes over the *uncompressed* JSON) before being accepted into the cache.
"""

import base64
import gzip
import hashlib
import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILE = "known_exploited_vulnerabilities.json"
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"
EPSS_FILE = "epss_scores-current.csv.gz"
EPSS_URL = "https://epss.cyentia.com/" + EPSS_FILE
MSF_FILE = "modules_metadata_base.json"
MSF_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/" + MSF_FILE
EDB_FILE = "files_exploits.csv"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/" + EDB_FILE
ALLOWED_HOSTS = {"nvd.nist.gov", "www.cisa.gov", "osv-vulnerabilities.storage.googleapis.com",
                 "epss.cyentia.com", "raw.githubusercontent.com", "gitlab.com"}
FIRST_FEED_YEAR = 2002  # the 2002 feed also holds 1999-2001 CVEs
MAX_DOWNLOAD_BYTES = 1 << 30
TIMEOUT_SECONDS = 120
RETRIES = 4
USER_AGENT = f"bunyip-updater/{__version__}"


class FetchError(RuntimeError):
    """Raised when a download fails or does not verify."""


@dataclass
class Meta:
    last_modified: str  # RFC 3339 as published, e.g. 2026-10-06T01:00:06-04:00
    size: int           # uncompressed bytes
    sha256: str         # of the uncompressed JSON, lower-case hex

    def last_modified_utc(self) -> str:
        return datetime.fromisoformat(self.last_modified).astimezone(timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Feed:
    name: str      # e.g. "2021" or "modified"
    gz_path: Path
    meta: Meta


def feed_basename(name: str) -> str:
    return f"nvdcve-2.0-{name}"


def parse_meta(text: str) -> Meta:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep:
            fields[key] = value
    try:
        return Meta(fields["lastModifiedDate"], int(fields["size"]), fields["sha256"].lower())
    except (KeyError, ValueError) as e:
        raise FetchError(f"malformed .meta file: {e}") from None


def verify_feed(gz_path: Path, meta: Meta) -> None:
    """Check a feed's decompressed size and sha256 against its .meta."""
    h, size = hashlib.sha256(), 0
    with gzip.open(gz_path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
            size += len(chunk)
    if size != meta.size or h.hexdigest() != meta.sha256:
        raise FetchError(f"{gz_path.name}: checksum/size mismatch with .meta "
                         f"(got {size} bytes sha256 {h.hexdigest()}, want {meta.size} {meta.sha256})")


def _check_url(url: str) -> None:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise FetchError(f"refusing to fetch {url}: only HTTPS on {sorted(ALLOWED_HOSTS)}")


def download(url: str, dest: Path, log=print) -> None:
    """Download url to dest atomically, with retries and a size cap."""
    _check_url(url)
    part = dest.with_name(dest.name + ".part")
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                _check_url(resp.geturl())  # also covers redirects
                total = 0
                with open(part, "wb") as out:
                    while chunk := resp.read(1 << 20):
                        total += len(chunk)
                        if total > MAX_DOWNLOAD_BYTES:
                            raise FetchError(f"{url}: exceeds {MAX_DOWNLOAD_BYTES} bytes")
                        out.write(chunk)
            part.replace(dest)
            return
        except FetchError:
            part.unlink(missing_ok=True)
            raise
        except OSError as e:  # URLError, HTTPError, timeouts
            part.unlink(missing_ok=True)
            if attempt == RETRIES:
                raise FetchError(f"{url}: {e}") from e
            wait = 2 ** attempt
            log(f"  retry {attempt}/{RETRIES - 1} for {url} in {wait}s: {e}")
            time.sleep(wait)


def feed_names(now: datetime | None = None) -> list[str]:
    year = (now or datetime.now(timezone.utc)).year
    return [str(y) for y in range(FIRST_FEED_YEAR, year + 1)] + ["modified"]


def sync_nvd(cache: Path, names: list[str], log=print) -> list[Feed]:
    """Bring cached NVD feeds up to date. A feed is re-downloaded only when its
    published .meta sha256 differs from the cached copy."""
    cache.mkdir(parents=True, exist_ok=True)
    feeds = []
    for name in names:
        base = feed_basename(name)
        meta_path, gz_path = cache / f"{base}.meta", cache / f"{base}.json.gz"
        fresh_meta_path = cache / f"{base}.meta.new"
        download(NVD_FEED_BASE + f"{base}.meta", fresh_meta_path, log)
        fresh = parse_meta(fresh_meta_path.read_text())
        cached = parse_meta(meta_path.read_text()) if meta_path.exists() else None
        if cached and cached.sha256 == fresh.sha256 and gz_path.exists():
            fresh_meta_path.unlink()
            log(f"  {base}: unchanged")
        else:
            log(f"  {base}: downloading")
            download(NVD_FEED_BASE + f"{base}.json.gz", gz_path, log)
            try:
                verify_feed(gz_path, fresh)
            except FetchError:
                gz_path.unlink(missing_ok=True)
                fresh_meta_path.unlink(missing_ok=True)
                raise
            fresh_meta_path.replace(meta_path)
        feeds.append(Feed(name, gz_path, parse_meta(meta_path.read_text())))
    return feeds


def sync_kev(cache: Path, log=print) -> Path:
    """Download the KEV catalogue (CISA publishes no checksum for it; kev.load
    validates its structure)."""
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / KEV_FILE
    log(f"  {KEV_FILE}: downloading")
    download(KEV_URL, dest, log)
    return dest


def local_feeds(directory: Path) -> list[Feed]:
    """Use already-downloaded feeds (offline rebuild). Every feed is verified
    against its .meta, exactly as after a download."""
    feeds = []
    for meta_path in sorted(directory.glob("nvdcve-2.0-*.meta")):
        name = meta_path.name[len("nvdcve-2.0-"):-len(".meta")]
        gz_path = directory / f"{feed_basename(name)}.json.gz"
        if not gz_path.exists():
            raise FetchError(f"{meta_path.name} has no matching {gz_path.name}")
        meta = parse_meta(meta_path.read_text())
        verify_feed(gz_path, meta)
        feeds.append(Feed(name, gz_path, meta))
    return feeds


def local_kev(directory: Path) -> Path:
    """Use an already-downloaded KEV catalogue (offline rebuild)."""
    path = directory / KEV_FILE
    if not path.exists():
        raise FetchError(f"{path} not found")
    return path


def sync_epss(cache: Path, log=print) -> Path:
    """Download the current FIRST EPSS snapshot (gzipped CSV). FIRST publishes no
    sidecar checksum, so the gzip/CSV parse at load time is the integrity check;
    the "current" file changes daily, so it is always refreshed."""
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / EPSS_FILE
    log(f"  EPSS: downloading current snapshot")
    download(EPSS_URL, dest, log)
    return dest


def local_epss(directory: Path) -> Path | None:
    """Use an already-downloaded EPSS snapshot (offline rebuild); None if absent."""
    path = directory / EPSS_FILE
    return path if path.exists() else None


def sync_metasploit(cache: Path, log=print) -> Path:
    """Download Metasploit's module metadata (BSD-3-Clause). It changes daily, so
    it is always refreshed; the JSON parse at load time is the integrity check."""
    return _sync_file(cache, MSF_FILE, MSF_URL, "Metasploit module metadata", log)


def sync_exploitdb(cache: Path, log=print) -> Path:
    """Download the Exploit-DB index (GPL-2.0); the derived references are loaded
    at build time and not shipped."""
    return _sync_file(cache, EDB_FILE, EDB_URL, "Exploit-DB index", log)


def _sync_file(cache: Path, name: str, url: str, what: str, log=print) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / name
    log(f"  {what}: downloading")
    download(url, dest, log)
    return dest


def local_metasploit(directory: Path) -> Path | None:
    path = directory / MSF_FILE
    return path if path.exists() else None


def local_exploitdb(directory: Path) -> Path | None:
    path = directory / EDB_FILE
    return path if path.exists() else None


# --- OSV ecosystem exports ---------------------------------------------------

@dataclass
class OSVExport:
    ecosystem: str
    zip_path: Path
    md5: str            # base64, as published in the bucket's x-goog-hash header
    last_modified: str  # HTTP Last-Modified of the export


def _osv_paths(directory: Path, ecosystem: str) -> tuple[Path, Path]:
    return directory / f"osv-{ecosystem}-all.zip", directory / f"osv-{ecosystem}-all.meta.json"


def _md5_b64(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return base64.b64encode(h.digest()).decode()


def _head(url: str) -> dict[str, str]:
    _check_url(url)
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        _check_url(resp.geturl())
        md5 = ""
        for h in resp.headers.get_all("x-goog-hash") or []:
            if h.startswith("md5="):
                md5 = h[4:]
        return {"md5": md5, "last_modified": resp.headers.get("Last-Modified", "")}


def sync_osv(cache: Path, ecosystem: str, log=print) -> OSVExport:
    """Bring a cached OSV ecosystem export up to date. The export is only
    downloaded again when the bucket's published MD5 changes, and every
    download must match that MD5."""
    cache.mkdir(parents=True, exist_ok=True)
    url = f"{OSV_BASE}{urllib.parse.quote(ecosystem)}/all.zip"  # e.g. "Red Hat" -> "Red%20Hat"
    zip_path, meta_path = _osv_paths(cache, ecosystem)
    head = _head(url)
    if not head["md5"]:
        raise FetchError(f"{url}: no MD5 published; refusing unverifiable download")
    cached = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    if cached.get("md5") == head["md5"] and zip_path.exists():
        log(f"  OSV {ecosystem}: unchanged")
    else:
        log(f"  OSV {ecosystem}: downloading")
        download(url, zip_path, log)
        if _md5_b64(zip_path) != head["md5"]:
            zip_path.unlink(missing_ok=True)
            raise FetchError(f"{url}: MD5 mismatch with published x-goog-hash")
        meta_path.write_text(json.dumps(head))
    return OSVExport(ecosystem, zip_path, head["md5"], head["last_modified"])


def local_osv(directory: Path, ecosystem: str) -> OSVExport | None:
    """Use an already-downloaded export (offline rebuild), verified against
    its recorded MD5. Returns None if the directory has no such export."""
    zip_path, meta_path = _osv_paths(directory, ecosystem)
    if not zip_path.exists():
        return None
    if not meta_path.exists():
        raise FetchError(f"{zip_path.name} has no {meta_path.name} with its MD5")
    meta = json.loads(meta_path.read_text())
    if _md5_b64(zip_path) != meta.get("md5"):
        raise FetchError(f"{zip_path.name}: MD5 mismatch with {meta_path.name}")
    return OSVExport(ecosystem, zip_path, meta["md5"], meta.get("last_modified", ""))
