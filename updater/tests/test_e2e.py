"""Golden end-to-end test: real NVD/KEV records -> Python build -> Go query engine."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import OVERLAY_DESCRIPTION, REPO
from vulndb_update import cli


def find_go():
    for candidate in (os.environ.get("GO"), shutil.which("go"), str(Path.home() / ".local/go/bin/go")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


@pytest.fixture(scope="module")
def vulndb_bin(tmp_path_factory):
    go = find_go()
    if not go:
        pytest.skip("Go toolchain not found (set GO=/path/to/go)")
    out = tmp_path_factory.mktemp("bin") / "vulndb"
    subprocess.run([go, "build", "-o", str(out), "./cmd/vulndb"], cwd=REPO, check=True,
                   env={**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"})
    return out


@pytest.fixture
def real_db(sources, tmp_path):
    out = tmp_path / "vulndb.sqlite"
    rc = cli.main(["build", "--offline-from", str(sources), "--out", str(out), "--allow-small", "--quiet"])
    assert rc == 0
    return out


def query(bin_, db, cpe):
    p = subprocess.run([str(bin_), "--db", str(db), "query", "--cpe", cpe, "--format", "json"],
                       capture_output=True, text=True, check=True)
    return {v["cve"]: v for v in json.loads(p.stdout)["result"]["vulnerabilities"]}


def test_apache_2_4_49(vulndb_bin, real_db):
    v = query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.49")
    assert set(v) == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44790", "CVE-2022-26377"}
    a = v["CVE-2021-41773"]
    assert a["version_status"] == "MATCH" and a["match_confidence"] == "EXACT"
    assert a["known_exploited"] is True and a["public_exploit"] is True
    assert a["exploit_sources"] == ["nvd-reference"]
    assert a["cvss"] == 9.8 and a["severity"] == "CRITICAL"
    # The overlay's newer description reached the query engine.
    assert v["CVE-2021-44790"]["description"] == OVERLAY_DESCRIPTION
    assert v["CVE-2021-44790"]["known_exploited"] is False


def test_apache_2_4_50_and_2_4_51(vulndb_bin, real_db):
    assert set(query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.50")) == {"CVE-2021-42013", "CVE-2021-44790", "CVE-2022-26377"}
    assert set(query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.51")) == {"CVE-2021-44790", "CVE-2022-26377"}
    assert set(query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.52")) == {"CVE-2022-26377"}
    assert query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.54") == {}


def test_openssh_version_update_split(vulndb_bin, real_db):
    # NVD: < 9.3, 9.3:-, 9.3:p1 (fixed in 9.3p2). The OpenSSH comparator joins
    # NVD's version+update so Nmap-style versions evaluate correctly.
    for detected, affected in [("8.9p1", True), ("9.3p1", True), ("9.3p2", False), ("9.4p1", False)]:
        v = query(vulndb_bin, real_db, f"cpe:/a:openbsd:openssh:{detected}")
        if affected:
            assert v["CVE-2023-38408"]["version_status"] == "MATCH", detected
        else:
            assert "CVE-2023-38408" not in v, detected


def test_and_configuration_is_conditional(vulndb_bin, real_db):
    v = query(vulndb_bin, real_db, "cpe:2.3:a:adobe:flash_player_desktop_runtime:21.0.0.197:*:*:*:*:*:*:*")
    f = v["CVE-2016-1019"]
    assert f["version_status"] == "MATCH" and f["applicability"] == "CONDITIONAL"
    assert f["known_exploited"] is True


def test_stats_reflect_rejections(vulndb_bin, real_db):
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "db", "stats"], capture_output=True, text=True, check=True)
    assert "cves                         10" in p.stdout


def test_go_verify_and_info(vulndb_bin, real_db):
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "db", "verify"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "Database OK" in p.stdout and "FAIL" not in p.stdout
    info = subprocess.run([str(vulndb_bin), "--db", str(real_db), "info"], capture_output=True, text=True, check=True)
    assert "NVD data as of:    2026-10-06T05:00:06Z" in info.stdout
    assert "SYNTHETIC" not in info.stdout


def test_nmap_sample_against_real_records(vulndb_bin, real_db):
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/sample.xml"),
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


def test_ubuntu_advisories_against_real_records(vulndb_bin, real_db):
    """Real NVD + real Ubuntu OSV records: backport-aware verdicts per host."""
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "nmap", str(REPO / "testdata/nmap/ubuntu-hosts.xml"),
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
