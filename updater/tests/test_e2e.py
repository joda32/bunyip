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
    assert set(v) == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44790"}
    a = v["CVE-2021-41773"]
    assert a["version_status"] == "MATCH" and a["match_confidence"] == "EXACT"
    assert a["known_exploited"] is True and a["public_exploit"] is True
    assert a["exploit_sources"] == ["nvd-reference"]
    assert a["cvss"] == 9.8 and a["severity"] == "CRITICAL"
    # The overlay's newer description reached the query engine.
    assert v["CVE-2021-44790"]["description"] == OVERLAY_DESCRIPTION
    assert v["CVE-2021-44790"]["known_exploited"] is False


def test_apache_2_4_50_and_2_4_51(vulndb_bin, real_db):
    assert set(query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.50")) == {"CVE-2021-42013", "CVE-2021-44790"}
    assert set(query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.51")) == {"CVE-2021-44790"}
    assert query(vulndb_bin, real_db, "cpe:/a:apache:http_server:2.4.52") == {}


def test_openssh_version_update_split(vulndb_bin, real_db):
    # Nmap-style 8.9p1 is clearly below 9.3: MATCH.
    v = query(vulndb_bin, real_db, "cpe:/a:openbsd:openssh:8.9p1")
    assert v["CVE-2023-38408"]["version_status"] == "MATCH"
    # 9.3p1 vs NVD's "9.3" + update "p1" cannot be decided by the generic
    # comparator: reported UNKNOWN, never as a false MATCH.
    v = query(vulndb_bin, real_db, "cpe:/a:openbsd:openssh:9.3p1")
    assert v["CVE-2023-38408"]["version_status"] == "UNKNOWN"
    assert query(vulndb_bin, real_db, "cpe:/a:openbsd:openssh:9.4p1") == {}


def test_and_configuration_is_conditional(vulndb_bin, real_db):
    v = query(vulndb_bin, real_db, "cpe:2.3:a:adobe:flash_player_desktop_runtime:21.0.0.197:*:*:*:*:*:*:*")
    f = v["CVE-2016-1019"]
    assert f["version_status"] == "MATCH" and f["applicability"] == "CONDITIONAL"
    assert f["known_exploited"] is True


def test_stats_reflect_rejections(vulndb_bin, real_db):
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "db", "stats"], capture_output=True, text=True, check=True)
    assert "cves                          5" in p.stdout


def test_go_verify_and_info(vulndb_bin, real_db):
    p = subprocess.run([str(vulndb_bin), "--db", str(real_db), "db", "verify"], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "Database OK" in p.stdout and "FAIL" not in p.stdout
    info = subprocess.run([str(vulndb_bin), "--db", str(real_db), "info"], capture_output=True, text=True, check=True)
    assert "NVD data as of:    2026-10-06T05:00:06Z" in info.stdout
    assert "SYNTHETIC" not in info.stdout
