import gzip
import sqlite3

import pytest

from conftest import SCHEMA
from bunyip_update import build, epss, fetch

SAMPLE = (
    "#model_version:v2025.03.14,score_date:2026-10-10T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-41773,0.94321,0.99012\n"
    "CVE-2024-6387,0.12345,0.80000\n"
    "not-a-cve,0.5,0.5\n"
    "CVE-2021-41773,0.1,0.1\n"  # duplicate, ignored
)


def test_parse(tmp_path):
    p = tmp_path / "epss.csv"
    p.write_text(SAMPLE)
    d = epss.load(p)
    assert d.model_version == "v2025.03.14"
    assert d.score_date == "2026-10-10T00:00:00+0000"  # colons in the time survive
    assert len(d.rows) == 2  # non-CVE and duplicate dropped
    assert (d.rows[0].cve_id, d.rows[0].score, d.rows[0].percentile) == ("CVE-2021-41773", 0.94321, 0.99012)


def test_load_gzip(tmp_path):
    p = tmp_path / "epss_scores-current.csv.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(SAMPLE)
    assert len(epss.load(p).rows) == 2


def test_empty_is_error(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("#model_version:v1,score_date:x\ncve,epss,percentile\n")
    with pytest.raises(epss.EPSSError):
        epss.load(p)


def test_local_epss(tmp_path):
    assert fetch.local_epss(tmp_path) is None
    (tmp_path / fetch.EPSS_FILE).write_bytes(b"x")
    assert fetch.local_epss(tmp_path) == tmp_path / fetch.EPSS_FILE


def test_sync_epss(tmp_path, monkeypatch):
    def fake_download(url, dest, log=print):
        assert url == fetch.EPSS_URL
        with gzip.open(dest, "wt", encoding="utf-8") as f:
            f.write(SAMPLE)
    monkeypatch.setattr(fetch, "download", fake_download)
    path = fetch.sync_epss(tmp_path, log=lambda *a, **k: None)
    assert epss.load(path).rows  # downloaded file parses


def test_build_loads_epss_and_metadata(sources, tmp_path):
    # CVE-2021-41773 is one of the testdata records.
    efile = tmp_path / "epss_scores-current.csv.gz"
    with gzip.open(efile, "wt", encoding="utf-8") as f:
        f.write(SAMPLE)
    out = tmp_path / "bunyip.sqlite"
    build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                allow_small=True, log=lambda *a, **k: None, epss=epss.load(efile))
    conn = sqlite3.connect(out)
    try:
        assert conn.execute("SELECT score, percentile FROM epss WHERE cve_id = 'CVE-2021-41773'").fetchone() \
            == (0.94321, 0.99012)
        meta = dict(conn.execute("SELECT key, value FROM database_metadata"))
        assert meta["epss_model_version"] == "v2025.03.14"
        assert meta["epss_score_date"] == "2026-10-10T00:00:00+0000"
        assert meta["epss_scores"] == "2"
    finally:
        conn.close()


def test_build_without_epss_writes_empty_metadata(sources, tmp_path):
    out = tmp_path / "bunyip.sqlite"
    build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                allow_small=True, log=lambda *a, **k: None, epss=None)
    conn = sqlite3.connect(out)
    try:
        assert conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 0
        meta = dict(conn.execute("SELECT key, value FROM database_metadata"))
        assert meta["epss_scores"] == "0" and meta["epss_model_version"] == ""
    finally:
        conn.close()
