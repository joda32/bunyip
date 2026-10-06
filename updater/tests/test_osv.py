import json
import shutil
import sqlite3

import pytest

from conftest import OSV_UBUNTU, REPO, SCHEMA, write_osv_export
from vulndb_update import build, fetch, osv

UBUNTU = osv.DISTROS["ubuntu"]
MAPPED = {"openssh", "apache2"}


def record(rid):
    return json.loads((OSV_UBUNTU / f"{rid}.json").read_text())


def rows_by(t, release, channel="standard"):
    return [r for r in t.rows if r.release == release and r.channel == channel]


def test_fixed_record():
    t = osv.transform(record("UBUNTU-CVE-2024-6387"), UBUNTU, MAPPED)
    jammy, noble = rows_by(t, "22.04")[0], rows_by(t, "24.04")[0]
    assert (jammy.cve_id, jammy.package, jammy.fixed_version, jammy.codename) == \
        ("CVE-2024-6387", "openssh", "1:8.9p1-3ubuntu0.10", "jammy")
    assert noble.fixed_version == "1:9.6p1-3ubuntu13.3" and noble.codename == "noble"
    assert "9.6p1" in noble.affected_upstreams.split()
    assert all(r.source == "osv:Ubuntu" and r.advisory_id == "UBUNTU-CVE-2024-6387" for r in t.rows)
    # Release inference data comes from standard-channel versions only.
    assert osv.PackageVersion("ubuntu", "24.04", "openssh", "1:9.6p1-3ubuntu13.3", "9.6p1") in t.versions


def test_unfixed_record():
    t = osv.transform(record("UBUNTU-CVE-2016-20012"), UBUNTU, MAPPED)
    jammy = rows_by(t, "22.04")[0]
    assert jammy.fixed_version is None and "8.9p1" in jammy.affected_upstreams.split()


def test_fixed_in_initial_release_package():
    # Fixed in 22.04 at 2.4.52-1ubuntu1: no 2.4.52 package in 22.04 is listed as affected.
    t = osv.transform(record("UBUNTU-CVE-2021-44790"), UBUNTU, MAPPED)
    jammy = rows_by(t, "22.04")[0]
    assert jammy.fixed_version == "2.4.52-1ubuntu1" and "2.4.52" not in jammy.affected_upstreams.split()


def test_pro_channel_and_skipped_streams():
    t = osv.transform(record("UBUNTU-CVE-2024-6387"), UBUNTU, MAPPED)
    channels = {(r.release, r.channel) for r in t.rows}
    assert all(c in ("standard", "pro") for _, c in channels)
    assert not any("FIPS" in r.release for r in t.rows)


def test_withdrawn_and_unmapped():
    assert osv.transform(record("UBUNTU-CVE-2023-51767"), UBUNTU, MAPPED).withdrawn
    assert osv.transform(record("UBUNTU-CVE-2002-2439"), UBUNTU, MAPPED).rows == []  # gcc: not mapped


@pytest.mark.parametrize("eco, want", [
    ("Ubuntu:24.04:LTS", ("24.04", "standard")),
    ("Ubuntu:25.10", ("25.10", "standard")),
    ("Ubuntu:Pro:18.04:LTS", ("18.04", "pro")),
    ("Ubuntu:Pro:FIPS-updates:22.04:LTS", None),
    ("Ubuntu:Pro:Realtime:24.04:LTS", None),
    ("Ubuntu:Nvidia-BlueField:22.04:LTS", None),
    ("Debian:12", None),
])
def test_parse_ecosystem(eco, want):
    assert osv.parse_ecosystem(UBUNTU, eco) == want


@pytest.mark.parametrize("v, up", [("1:9.6p1-3ubuntu13.3", "9.6p1"), ("2.4.52-1ubuntu4.1", "2.4.52"),
                                   ("1.0", "1.0"), ("2:1.2-3-4", "1.2-3")])
def test_upstream_of(v, up):
    assert osv.upstream_of(v) == up


def test_real_package_map():
    rows = osv.load_package_map(REPO / "data" / "distro_packages.json")
    assert ("a", "openbsd", "openssh", "ubuntu", "openssh") in {(r.part, r.vendor, r.product, r.distro, r.package) for r in rows}
    assert len({r.package for r in rows if r.product == "postgresql"}) >= 5


@pytest.mark.parametrize("doc, match", [
    ({"packages": []}, "missing source"),
    ({"source": "s", "packages": [{"cpe": "a:x", "ubuntu": ["p"]}]}, "part:vendor:product"),
    ({"source": "s", "packages": [{"cpe": "a:x:y", "gentoo": ["p"]}]}, "unknown distro"),
    ({"source": "s", "packages": [{"cpe": "a:x:y", "ubuntu": ["p", "p"]}]}, "duplicate"),
])
def test_package_map_errors(tmp_path, doc, match):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match=match):
        osv.load_package_map(p)


def test_build_with_ubuntu(sources, tmp_path):
    out = tmp_path / "v.sqlite"
    pm = osv.load_package_map(REPO / "data" / "distro_packages.json")
    export = fetch.local_osv(sources, "Ubuntu")
    stats = build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                        allow_small=True, log=lambda *a: None,
                        distros=[build.DistroInput(UBUNTU, export)], package_map=pm)
    conn = sqlite3.connect(out)
    q = lambda sql, *a: conn.execute(sql, a).fetchall()  # noqa: E731
    assert stats.distro_withdrawn == 1 and stats.distro_rows > 0
    assert q("SELECT fixed_version FROM distro_advisories WHERE cve_id = 'CVE-2024-6387' AND release = '24.04'"
             " AND channel = 'standard' AND package = 'openssh'") == [("1:9.6p1-3ubuntu13.3",)]
    assert q("SELECT COUNT(*) FROM distro_advisories WHERE package = 'gcc-4.7'") == [(0,)]
    assert q("SELECT DISTINCT release FROM distro_package_versions WHERE package = 'openssh' AND upstream = '8.9p1'") == [("22.04",)]
    assert q("SELECT COUNT(*) FROM distro_packages") == [(len(pm),)]
    meta = dict(q("SELECT key, value FROM database_metadata"))
    assert meta["distro_sources"] == "ubuntu" and meta["ubuntu_advisories_last_modified"].startswith("Tue, 06 Oct 2026")
    assert "ubuntu/nginx" in stats.unmapped_packages  # mapped, but absent from the small test export


def test_local_osv_verifies_md5(sources):
    assert fetch.local_osv(sources, "Ubuntu") is not None
    assert fetch.local_osv(sources, "Debian") is None
    zip_path = sources / "osv-Ubuntu-all.zip"
    zip_path.write_bytes(zip_path.read_bytes() + b"tampered")
    with pytest.raises(fetch.FetchError, match="MD5 mismatch"):
        fetch.local_osv(sources, "Ubuntu")


def test_sync_osv_caches_and_verifies(tmp_path, monkeypatch):
    server = tmp_path / "server"
    server.mkdir()
    write_osv_export(server, "Ubuntu", sorted(OSV_UBUNTU.glob("*.json")))
    published = json.loads((server / "osv-Ubuntu-all.meta.json").read_text())
    downloads = []

    def fake_download(url, dest, log=print):
        downloads.append(url)
        shutil.copy(server / "osv-Ubuntu-all.zip", dest)

    monkeypatch.setattr(fetch, "_head", lambda url: dict(published))
    monkeypatch.setattr(fetch, "download", fake_download)
    cache = tmp_path / "cache"
    fetch.sync_osv(cache, "Ubuntu", log=lambda *a: None)
    fetch.sync_osv(cache, "Ubuntu", log=lambda *a: None)
    assert downloads == ["https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"], \
        "unchanged export must not be downloaded again"

    published["md5"] = "AAAAAAAAAAAAAAAAAAAAAA=="  # publisher hash no longer matches the bytes
    with pytest.raises(fetch.FetchError, match="MD5 mismatch"):
        fetch.sync_osv(cache, "Ubuntu", log=lambda *a: None)
    assert not (cache / "osv-Ubuntu-all.zip").exists()

    published["md5"] = ""
    with pytest.raises(fetch.FetchError, match="no MD5"):
        fetch.sync_osv(cache, "Ubuntu", log=lambda *a: None)
