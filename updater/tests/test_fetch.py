import gzip
import shutil
from datetime import datetime, timezone

import pytest

from conftest import write_feed
from vulndb_update import fetch

REAL_META = ("lastModifiedDate:2026-10-06T01:00:06-04:00\r\nsize:51550134\r\nzipSize:4556862\r\n"
             "gzSize:4556718\r\nsha256:C4F6E366515C9F5D10458CACC26C6F756556298BC356C4BCBA76A1DB6A163E8F\r\n")


def test_parse_real_meta():
    m = fetch.parse_meta(REAL_META)
    assert m.size == 51550134
    assert m.sha256 == "c4f6e366515c9f5d10458cacc26c6f756556298bc356c4bcba76a1db6a163e8f"
    assert m.last_modified_utc() == "2026-10-06T05:00:06Z"


def test_parse_meta_malformed():
    with pytest.raises(fetch.FetchError):
        fetch.parse_meta("lastModifiedDate:x\nsize:notanumber\n")


def test_verify_feed(tmp_path):
    write_feed(tmp_path, "2021", [{"cve": {"id": "CVE-1"}}])
    meta = fetch.parse_meta((tmp_path / "nvdcve-2.0-2021.meta").read_text())
    gz = tmp_path / "nvdcve-2.0-2021.json.gz"
    fetch.verify_feed(gz, meta)
    with gzip.open(gz, "wb") as f:
        f.write(b'{"tampered": true}')
    with pytest.raises(fetch.FetchError, match="mismatch"):
        fetch.verify_feed(gz, meta)


def test_local_feeds_verifies_and_pairs(sources):
    feeds = fetch.local_feeds(sources)
    assert sorted(f.name for f in feeds) == ["2002", "2016", "2021", "2023", "2024", "modified"]
    (sources / "nvdcve-2.0-2016.json.gz").unlink()
    with pytest.raises(fetch.FetchError, match="no matching"):
        fetch.local_feeds(sources)


@pytest.mark.parametrize("url", [
    "http://nvd.nist.gov/feeds/x",           # not HTTPS
    "https://evil.example/feeds/x",          # not allow-listed
    "https://nvd.nist.gov.evil.example/x",   # suffix trick
    "file:///etc/passwd",
])
def test_url_allow_list(url, tmp_path):
    with pytest.raises(fetch.FetchError, match="refusing"):
        fetch.download(url, tmp_path / "x")


def test_feed_names():
    names = fetch.feed_names(datetime(2026, 10, 6, tzinfo=timezone.utc))
    assert names[0] == "2002" and names[-2] == "2026" and names[-1] == "modified"


class FakeServer:
    """Stands in for fetch.download, serving files from a directory."""

    def __init__(self, root):
        self.root, self.requests = root, []

    def __call__(self, url, dest, log=print):
        name = url.rsplit("/", 1)[1]
        self.requests.append(name)
        shutil.copy(self.root / name, dest)


def test_sync_nvd_caches_by_meta(tmp_path, monkeypatch):
    server_dir, cache = tmp_path / "server", tmp_path / "cache"
    server_dir.mkdir()
    write_feed(server_dir, "2021", [{"cve": {"id": "CVE-1"}}])
    server = FakeServer(server_dir)
    monkeypatch.setattr(fetch, "download", server)

    fetch.sync_nvd(cache, ["2021"], log=lambda *a: None)
    assert server.requests == ["nvdcve-2.0-2021.meta", "nvdcve-2.0-2021.json.gz"]

    server.requests.clear()
    feeds = fetch.sync_nvd(cache, ["2021"], log=lambda *a: None)
    assert server.requests == ["nvdcve-2.0-2021.meta"], "unchanged feed must not be re-downloaded"
    assert feeds[0].gz_path.exists()

    write_feed(server_dir, "2021", [{"cve": {"id": "CVE-2"}}])  # publisher updates the feed
    server.requests.clear()
    fetch.sync_nvd(cache, ["2021"], log=lambda *a: None)
    assert server.requests == ["nvdcve-2.0-2021.meta", "nvdcve-2.0-2021.json.gz"]


def test_sync_nvd_rejects_bad_checksum(tmp_path, monkeypatch):
    server_dir, cache = tmp_path / "server", tmp_path / "cache"
    server_dir.mkdir()
    write_feed(server_dir, "2021", [{"cve": {"id": "CVE-1"}}])
    with gzip.open(server_dir / "nvdcve-2.0-2021.json.gz", "wb") as f:
        f.write(b'{"vulnerabilities": []}')  # body no longer matches .meta
    monkeypatch.setattr(fetch, "download", FakeServer(server_dir))
    with pytest.raises(fetch.FetchError, match="mismatch"):
        fetch.sync_nvd(cache, ["2021"], log=lambda *a: None)
    assert not list(cache.glob("*.json.gz")) and not list(cache.glob("*.meta")), \
        "unverified files must not stay in the cache"
