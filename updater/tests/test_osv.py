import json
import shutil
import sqlite3

import pytest

from conftest import OSV_DEBIAN, OSV_UBUNTU, REPO, SCHEMA, write_osv_export
from bunyip_update import build, fetch, osv

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
    assert q("SELECT COUNT(*) FROM distro_packages") == [(len([r for r in pm if r.distro == "ubuntu"]),)]
    meta = dict(q("SELECT key, value FROM database_metadata"))
    assert meta["distro_sources"] == "ubuntu" and meta["ubuntu_advisories_last_modified"].startswith("Tue, 06 Oct 2026")
    assert "ubuntu/nginx" in stats.unmapped_packages  # mapped, but absent from the small test export


def test_local_osv_verifies_md5(sources):
    assert fetch.local_osv(sources, "Ubuntu") is not None
    assert fetch.local_osv(sources, "Alpine") is None
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


# --- Debian -----------------------------------------------------------------

DEBIAN = osv.DISTROS["debian"]


def debian(rid):
    return json.loads((OSV_DEBIAN / f"{rid}.json").read_text())


def test_debian_per_cve_record():
    t = osv.transform(debian("DEBIAN-CVE-2024-6387"), DEBIAN, MAPPED)
    bookworm, trixie = rows_by(t, "12")[0], rows_by(t, "13")[0]
    assert (bookworm.fixed_version, bookworm.codename) == ("1:9.2p1-2+deb12u3", "bookworm")
    assert bookworm.affected_upstreams == "9.2p1"
    # Trixie's fix predates the release: no versions listed, and the fixed
    # version (an unstable upload) is not recorded as a trixie package.
    assert trixie.fixed_version == "1:9.7p1-7" and trixie.affected_upstreams == ""
    assert not any(v.release == "13" for v in t.versions)
    assert osv.PackageVersion("debian", "12", "openssh", "1:9.2p1-2+deb12u3", "9.2p1") in t.versions
    assert bookworm.urgency == "not yet assigned"


def test_debian_no_fix_versions_ignored():
    # The no-fix entry lists versions from the whole archive (10.0p1, backports, ...)
    # which bookworm never shipped; they must not become bookworm data.
    t = osv.transform(debian("DEBIAN-CVE-2007-2243"), DEBIAN, MAPPED)
    bookworm = rows_by(t, "12")[0]
    assert bookworm.fixed_version is None and bookworm.affected_upstreams == ""
    assert bookworm.urgency == "unimportant"
    assert t.versions == set()


def test_debian_advisory_record_lists_cves():
    t = osv.transform(debian("DLA-4057-1"), DEBIAN, MAPPED, per_cve=False)
    bullseye = rows_by(t, "11")[0]
    assert (bullseye.cve_id, bullseye.fixed_version, bullseye.advisory_id) == \
        ("CVE-2025-26465", "1:8.4p1-5+deb11u4", "DLA-4057-1")
    assert bullseye.affected_upstreams == "8.4p1"


@pytest.mark.parametrize("eco, want", [("Debian:12", ("12", "standard")), ("Debian:3.1", ("3.1", "standard")),
                                       ("Ubuntu:24.04:LTS", None)])
def test_debian_ecosystems(eco, want):
    assert osv.parse_ecosystem(DEBIAN, eco) == want


def test_build_with_debian(sources, tmp_path):
    out = tmp_path / "v.sqlite"
    pm = osv.load_package_map(REPO / "data" / "distro_packages.json")
    stats = build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                        allow_small=True, log=lambda *a: None, package_map=pm,
                        distros=[build.DistroInput(DEBIAN, fetch.local_osv(sources, "Debian"))])
    conn = sqlite3.connect(out)
    q = lambda sql, *a: conn.execute(sql, a).fetchall()  # noqa: E731
    # Bookworm comes from the per-CVE record, not DSA-5724-1 (same fix).
    assert q("SELECT advisory_id, fixed_version FROM distro_advisories WHERE cve_id = 'CVE-2024-6387'"
             " AND release = '12'") == [("DEBIAN-CVE-2024-6387", "1:9.2p1-2+deb12u3")]
    # Bullseye is only in DLA-4057-1.
    assert q("SELECT advisory_id, fixed_version FROM distro_advisories WHERE cve_id = 'CVE-2025-26465'"
             " AND release = '11'") == [("DLA-4057-1", "1:8.4p1-5+deb11u4")]
    assert q("SELECT urgency FROM distro_advisories WHERE cve_id = 'CVE-2007-2243' AND release = '12'") == [("unimportant",)]
    assert q("SELECT DISTINCT release FROM distro_package_versions WHERE package = 'openssh' AND upstream = '9.2p1'") == [("12",)]
    assert stats.distro_rows > 0


# --- Red Hat family -----------------------------------------------------------

REDHAT, ROCKY, ALMA = osv.DISTROS["redhat"], osv.DISTROS["rocky"], osv.DISTROS["almalinux"]
RH_MAPPED = {"openssh", "nginx"}


def rh(sub, rid):
    return json.loads((REPO / "testdata" / "osv" / sub / f"{rid.replace(':', '_')}.json").read_text())


def test_redhat_record():
    t = osv.transform(rh("redhat", "RHSA-2024:4312"), REDHAT, RH_MAPPED, per_cve=False)
    assert {(r.cve_id, r.release, r.package, r.fixed_version, r.stream) for r in t.rows} == \
        {("CVE-2024-6387", "9", "openssh", "0:8.7p1-38.el9_4.1", "")}
    assert osv.PackageVersion("redhat", "9", "openssh", "0:8.7p1-38.el9_4.1", "8.7p1") in t.versions


def test_redhat_extended_support_skipped():
    # RHSA-2024:4340 is for RHEL 9.2 EUS only.
    assert osv.transform(rh("redhat", "RHSA-2024:4340"), REDHAT, RH_MAPPED, per_cve=False).rows == []


def test_redhat_variants_collapse_to_major_release():
    t = osv.transform(rh("redhat", "RHSA-2023:4382"), REDHAT, RH_MAPPED, per_cve=False)
    assert {(r.release, r.fixed_version) for r in t.rows} == {("7", "0:7.4p1-23.el7_9")}
    assert len({r.key for r in t.rows}) == 1


@pytest.mark.parametrize("rid, stream", [("RHSA-2021:2290", "1.16"), ("RHSA-2021:2259", "1.18"), ("RHSA-2022:0323", "1.20")])
def test_redhat_module_streams(rid, stream):
    t = osv.transform(rh("redhat", rid), REDHAT, RH_MAPPED, per_cve=False)
    rel8 = [r for r in t.rows if r.release == "8" and r.package == "nginx"]
    assert {r.stream for r in rel8} == {stream}


def test_build_redhat_family(sources, tmp_path):
    out = tmp_path / "v.sqlite"
    pm = osv.load_package_map(REPO / "data" / "distro_packages.json")
    distros = [build.DistroInput(d, fetch.local_osv(sources, d.ecosystem)) for d in (REDHAT, ROCKY, ALMA)]
    build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                allow_small=True, log=lambda *a: None, package_map=pm, distros=distros)
    conn = sqlite3.connect(out)
    q = lambda sql, *a: conn.execute(sql, a).fetchall()  # noqa: E731
    # One CVE, three independent module-stream fixes in RHEL 8.
    assert sorted(q("SELECT stream, fixed_version FROM distro_advisories WHERE distro = 'redhat'"
                    " AND cve_id = 'CVE-2021-23017' AND release = '8'")) == [
        ("1.16", "1:1.16.1-2.module+el8.4.0+11155+68135136.1"),
        ("1.18", "1:1.18.0-3.module+el8.4.0+11152+f736ed63.1"),
        ("1.20", "1:1.20.1-1.module+el8.5.0+13723+ab304644")]
    # AlmaLinux re-lists CVE-2023-38408 in a 2026 advisory; the earliest fix is kept.
    assert q("SELECT advisory_id, fixed_version FROM distro_advisories WHERE distro = 'almalinux'"
             " AND cve_id = 'CVE-2023-38408' AND release = '8'") == [("ALSA-2023:4419", "8.0p1-19.el8_8")]
    assert q("SELECT DISTINCT release FROM distro_package_versions WHERE distro = 'redhat'"
             " AND package = 'openssh' AND upstream = '8.7p1'") == [("9",)]
    assert q("SELECT COUNT(*) FROM distro_advisories WHERE release LIKE '9.%' OR release LIKE '8.%'") == [(0,)]
