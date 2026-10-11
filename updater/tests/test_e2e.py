"""Golden end-to-end test: real NVD/KEV records -> Python build -> Go query engine."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import OVERLAY_DESCRIPTION, REPO
from bunyip_update import cli


def find_go():
    for candidate in (os.environ.get("GO"), shutil.which("go"), str(Path.home() / ".local/go/bin/go")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


@pytest.fixture(scope="module")
def bunyip_bin(tmp_path_factory):
    go = find_go()
    if not go:
        pytest.skip("Go toolchain not found (set GO=/path/to/go)")
    out = tmp_path_factory.mktemp("bin") / "bunyip"
    subprocess.run([go, "build", "-o", str(out), "./cmd/bunyip"], cwd=REPO, check=True,
                   env={**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"})
    return out


@pytest.fixture
def real_db(sources, tmp_path):
    out = tmp_path / "bunyip.sqlite"
    rc = cli.main(["build", "--offline-from", str(sources), "--out", str(out), "--allow-small", "--quiet"])
    assert rc == 0
    return out


def query(bin_, db, cpe):
    p = subprocess.run([str(bin_), "--db", str(db), "query", "--cpe", cpe, "--format", "json"],
                       capture_output=True, text=True, check=True)
    return {v["cve"]: v for v in json.loads(p.stdout)["result"]["vulnerabilities"]}


def test_apache_2_4_49(bunyip_bin, real_db):
    v = query(bunyip_bin, real_db, "cpe:/a:apache:http_server:2.4.49")
    assert set(v) == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44790", "CVE-2022-26377"}
    a = v["CVE-2021-41773"]
    assert a["version_status"] == "MATCH" and a["match_confidence"] == "EXACT"
    assert a["known_exploited"] is True and a["public_exploit"] is True
    assert a["exploit_sources"] == ["nvd-reference"]
    assert a["cvss"] == 9.8 and a["severity"] == "CRITICAL"
    # The overlay's newer description reached the query engine.
    assert v["CVE-2021-44790"]["description"] == OVERLAY_DESCRIPTION
    assert v["CVE-2021-44790"]["known_exploited"] is False


def test_apache_2_4_50_and_2_4_51(bunyip_bin, real_db):
    assert set(query(bunyip_bin, real_db, "cpe:/a:apache:http_server:2.4.50")) == {"CVE-2021-42013", "CVE-2021-44790", "CVE-2022-26377"}
    assert set(query(bunyip_bin, real_db, "cpe:/a:apache:http_server:2.4.51")) == {"CVE-2021-44790", "CVE-2022-26377"}
    assert set(query(bunyip_bin, real_db, "cpe:/a:apache:http_server:2.4.52")) == {"CVE-2022-26377"}
    assert query(bunyip_bin, real_db, "cpe:/a:apache:http_server:2.4.54") == {}


def test_openssh_version_update_split(bunyip_bin, real_db):
    # NVD: < 9.3, 9.3:-, 9.3:p1 (fixed in 9.3p2). The OpenSSH comparator joins
    # NVD's version+update so Nmap-style versions evaluate correctly.
    for detected, affected in [("8.9p1", True), ("9.3p1", True), ("9.3p2", False), ("9.4p1", False)]:
        v = query(bunyip_bin, real_db, f"cpe:/a:openbsd:openssh:{detected}")
        if affected:
            assert v["CVE-2023-38408"]["version_status"] == "MATCH", detected
        else:
            assert "CVE-2023-38408" not in v, detected


def test_and_configuration_is_conditional(bunyip_bin, real_db):
    v = query(bunyip_bin, real_db, "cpe:2.3:a:adobe:flash_player_desktop_runtime:21.0.0.197:*:*:*:*:*:*:*")
    f = v["CVE-2016-1019"]
    assert f["version_status"] == "MATCH" and f["applicability"] == "CONDITIONAL"
    assert f["known_exploited"] is True


def test_stats_reflect_rejections(bunyip_bin, real_db):
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "db", "stats"], capture_output=True, text=True, check=True)
    assert "cves                         11" in p.stdout


def test_go_verify_and_info(bunyip_bin, real_db):
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "db", "verify"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "Database OK" in p.stdout and "FAIL" not in p.stdout
    info = subprocess.run([str(bunyip_bin), "--db", str(real_db), "info"], capture_output=True, text=True, check=True)
    assert "NVD data as of:    2026-10-06T05:00:06Z" in info.stdout
    assert "SYNTHETIC" not in info.stdout


def test_nmap_sample_against_real_records(bunyip_bin, real_db):
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/sample.xml"),
                        "--format", "json"], capture_output=True, text=True, check=True)
    report = json.loads(p.stdout)["report"]
    svcs = {s["port"]: s for s in report["hosts"][0]["services"]}
    apache = {v["cve"]: v for v in svcs[80]["result"]["vulnerabilities"]}
    assert {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44790"} <= set(apache)
    assert apache["CVE-2021-41773"]["known_exploited"] is True
    ssh = svcs[22]
    assert ssh["distro"] == "Ubuntu package 3ubuntu0.10"
    # Ubuntu advisories were evaluated, so the generic backport caveat is replaced by verdicts.
    assert ssh["result"]["distro"]["status"] == "RESOLVED"
    assert not any("backported" in n for n in ssh.get("notes", []))
    v38408 = next(v for v in ssh["result"]["vulnerabilities"] if v["cve"] == "CVE-2023-38408")
    assert v38408["version_status"] == "MATCH" and v38408["distro"]["status"] == "FIXED"
    iis = report["hosts"][1]["services"][0]
    assert any("against Microsoft Windows" in n for n in iis.get("notes", []))
    assert report["summary"]["not_probed"] == 1 and report["summary"]["unidentified"] == 1


def test_ubuntu_advisories_against_real_records(bunyip_bin, real_db):
    """Real NVD + real Ubuntu OSV records: backport-aware verdicts per host."""
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/ubuntu-hosts.xml"),
                        "--format", "json"], capture_output=True, text=True, check=True)
    report = json.loads(p.stdout)["report"]
    patched, stale = report["hosts"]

    def verdicts(svc):
        return {v["cve"]: (v["distro"]["status"], v.get("distro_only", False)) for v in svc["result"]["vulnerabilities"]}

    assert patched["distro_release"] == "22.04"
    ssh = verdicts(patched["services"][0])
    assert ssh["CVE-2024-6387"] == ("FIXED", False)        # regreSSHion: Ubuntu fixed it in exactly 0.10
    assert ssh["CVE-2023-38408"] == ("FIXED", False)       # fixed in 0.3
    assert ssh["CVE-2025-61984"] == ("VULNERABLE", True)   # NVD has no rule; Ubuntu fixed it later, in 0.14
    assert "CVE-2016-20012" not in ssh                     # Ubuntu "no fix" alone never adds a finding
    assert not any(n.startswith("Distribution package detected") for n in patched["services"][0].get("notes", []))

    apache = patched["services"][1]
    assert apache["result"]["distro"]["status"] == "RESOLVED"
    assert verdicts(apache)["CVE-2022-26377"] == ("FIX_AVAILABLE", False)  # revision not visible for Apache

    old = verdicts(stale["services"][0])
    assert old["CVE-2024-6387"] == ("VULNERABLE", False)
    assert old["CVE-2023-38408"] == ("VULNERABLE", False)
    assert old["CVE-2025-61984"] == ("VULNERABLE", True)
    assert report["summary"]["distro_fixed"] == 2 and report["summary"]["distro_only"] == 2


def test_debian_advisories_against_real_records(bunyip_bin, real_db):
    """Real NVD + real Debian OSV records (DEBIAN-CVE-* and DLA-4057-1)."""
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/debian-hosts.xml"),
                        "--format", "json"], capture_output=True, text=True, check=True)
    report = json.loads(p.stdout)["report"]
    bookworm, bullseye = report["hosts"]

    def verdicts(svc):
        return {v["cve"]: (v["distro"]["status"], v.get("distro_only", False)) for v in svc["result"]["vulnerabilities"]}

    # "+deb12u3" pins Debian 12 even though that exact version is not in the data.
    assert bookworm["distro_release"] == "12"
    ssh = bookworm["services"][0]
    assert ssh["result"]["distro"]["installed_version"] == "1:9.2p1-2+deb12u3"
    v = verdicts(ssh)
    assert v["CVE-2024-6387"] == ("FIXED", False)       # fixed in exactly +deb12u3
    assert v["CVE-2023-38408"] == ("FIXED", False)      # fixed in +deb12u1
    assert v["CVE-2025-26465"] == ("VULNERABLE", True)  # Debian fixed it in +deb12u5
    assert v["CVE-2025-61984"] == ("VULNERABLE", True)  # +deb12u8; NVD has no rule
    assert "CVE-2007-2243" not in v                      # Debian: no fix, "unimportant" -> never added alone

    apache = bookworm["services"][1]
    assert apache["distro"] == "Debian"
    assert apache["result"]["distro"]["status"] == "RESOLVED"  # via the host's release (from OpenSSH)

    # Debian 11 (LTS): only the DLA advisory covers it.
    assert bullseye["distro_release"] == "11"
    old = verdicts(bullseye["services"][0])
    assert old["CVE-2025-26465"] == ("VULNERABLE", True)  # DLA-4057-1 fixed it in +deb11u4


def test_redhat_family_against_real_records(bunyip_bin, real_db):
    """Real NVD + real RHSA/RLSA/ALSA records; distributions inferred per host."""
    p = subprocess.run([str(bunyip_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/rhel-hosts.xml"),
                        "--format", "json"], capture_output=True, text=True, check=True)
    hosts = {h["address"]: h for h in json.loads(p.stdout)["report"]["hosts"]}

    def service(addr, port):
        return next(s for s in hosts[addr]["services"] if s["port"] == port)

    def verdicts(svc):
        return {v["cve"]: v["distro"]["status"] for v in svc["result"]["vulnerabilities"]}

    # RHEL 9: OpenSSH's banner names no distribution; Apache's does.
    assert hosts["192.0.2.50"]["distro"] == "Red Hat"
    ssh = service("192.0.2.50", 22)
    assert ssh["distro"].startswith("Red Hat (inferred")
    assert ssh["result"]["distro"]["releases"] == ["9"]  # 8.7p1 is RHEL 9's OpenSSH
    v = verdicts(ssh)
    assert v["CVE-2024-6387"] == "FIX_AVAILABLE"  # RHSA-2024:4312, 0:8.7p1-38.el9_4.1
    assert v["CVE-2023-38408"] == "FIX_AVAILABLE"  # RHSA-2023:4412, 0:8.7p1-30.el9_2
    fix = next(x for x in ssh["result"]["vulnerabilities"] if x["cve"] == "CVE-2024-6387")["distro"]
    assert fix["fixed_version"] == "0:8.7p1-38.el9_4.1" and fix["advisory"] == "RHSA-2024:4312"

    # RHEL 8: nginx 1.16.1 belongs to the 1.16 module stream.
    nginx = service("192.0.2.51", 443)
    d = next(x for x in nginx["result"]["vulnerabilities"] if x["cve"] == "CVE-2021-23017")["distro"]
    assert d["status"] == "FIX_AVAILABLE" and d["release"] == "8"
    assert d["fixed_version"] == "1:1.16.1-2.module+el8.4.0+11155+68135136.1" and "module stream 1.16" in d["reason"]

    # Rocky Linux 8 and AlmaLinux 9 use their own advisories.
    rocky = verdicts(service("192.0.2.52", 22))
    assert rocky["CVE-2023-38408"] == "FIX_AVAILABLE"  # RLSA-2023:4419
    alma_ssh = service("192.0.2.53", 22)
    assert alma_ssh["result"]["distro"]["releases"] == ["9"]
    alma = verdicts(alma_ssh)
    assert alma["CVE-2024-6387"] == "FIX_AVAILABLE" and alma["CVE-2023-38408"] == "FIX_AVAILABLE"
