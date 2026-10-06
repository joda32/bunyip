import sqlite3

import pytest

from conftest import OVERLAY_DESCRIPTION, SCHEMA, make_sources
from vulndb_update import build, fetch

QUIET = lambda *a, **k: None  # noqa: E731


def do_build(sources, out, allow_small=True):
    return build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                       allow_small=allow_small, log=QUIET)


@pytest.fixture
def db(sources, tmp_path):
    out = tmp_path / "vulndb.sqlite"
    stats = do_build(sources, out)
    conn = sqlite3.connect(out)
    yield conn, stats
    conn.close()


def scalar(conn, sql, *args):
    return conn.execute(sql, args).fetchone()[0]


def test_counts_and_overlay_stats(db):
    conn, stats = db
    # 7 records: 6 loaded, 1 rejected in its yearly feed. Overlay: 1 replaced,
    # 1 unchanged, 1 rejected (removing an already-loaded CVE).
    assert (stats.loaded, stats.replaced, stats.unchanged, stats.rejected) == (6, 1, 1, 2)
    assert scalar(conn, "SELECT COUNT(*) FROM cves") == 5
    assert scalar(conn, "SELECT COUNT(*) FROM kev") == 3


def test_overlay_replaces_record_and_rules(db):
    conn, _ = db
    desc, modified = conn.execute(
        "SELECT description, modified_at FROM cves WHERE cve_id = 'CVE-2021-44790'").fetchone()
    assert desc == OVERLAY_DESCRIPTION and modified == "2026-10-05T00:00:00.000"
    # Rules were deleted and re-inserted once, not duplicated.
    assert scalar(conn, "SELECT COUNT(*) FROM cve_matches WHERE cve_id = 'CVE-2021-44790'") == 35
    assert scalar(conn, "SELECT COUNT(*) FROM cve_configurations WHERE cve_id = 'CVE-2021-44790'") == 7


def test_rejections_removed(db):
    conn, _ = db
    for cve in ("CVE-1999-1598", "CVE-2024-34393"):
        assert scalar(conn, "SELECT COUNT(*) FROM cves WHERE cve_id = ?", cve) == 0
        assert scalar(conn, "SELECT COUNT(*) FROM cve_configurations WHERE cve_id = ?", cve) == 0


def test_rules_and_structure(db):
    conn, _ = db
    row = conn.execute("""
        SELECT m.criteria, m.criteria_part, m.criteria_vendor, m.criteria_product, m.vulnerable,
               m.version_end_excluding
        FROM cve_matches m WHERE m.cve_id = 'CVE-2021-44790' AND m.criteria_product = 'http_server'
    """).fetchone()
    assert row == ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "a", "apache", "http_server", 1, "2.4.52")
    # AND configurations with non-vulnerable platform nodes survive intact.
    n_and = scalar(conn, "SELECT COUNT(*) FROM cve_configurations WHERE cve_id = 'CVE-2016-1019' AND operator = 'AND'")
    assert n_and > 0
    assert scalar(conn, """SELECT COUNT(*) FROM cve_matches m JOIN cve_config_nodes n ON n.id = m.node_id
                           JOIN cve_configurations c ON c.id = n.configuration_id
                           WHERE c.cve_id = 'CVE-2016-1019' AND c.operator = 'AND' AND m.vulnerable = 0""") > 0


def test_exploit_evidence(db):
    conn, _ = db
    rows = conn.execute("SELECT source, reference_type, verified FROM exploit_evidence "
                        "WHERE cve_id = 'CVE-2021-41773'").fetchall()
    assert len(rows) == 6 and set(rows) == {("nvd-reference", "exploit-reference", 0)}


def test_metadata(db):
    conn, _ = db
    meta = dict(conn.execute("SELECT key, value FROM database_metadata"))
    assert meta["schema_version"] == "1"
    assert meta["dataset"] == "nvd+kev"
    assert meta["nvd_last_modified"] == "2026-10-06T05:00:06Z"  # newest .meta, in UTC
    assert meta["kev_catalog_version"] == "2026.10.04"
    assert meta["nvd_feeds"] == "2002,2016,2021,2023,2024,modified"
    assert meta["nvd_cves_total"] == "5"
    assert meta["nvd_cves_without_configurations"] == "0"
    assert meta["nvd_rules_skipped"] == "0"


def test_completeness_floors(sources, tmp_path):
    with pytest.raises(build.BuildError, match="CVEs loaded"):
        do_build(sources, tmp_path / "x.sqlite", allow_small=False)


def test_failed_build_keeps_existing_database(sources, tmp_path):
    out = tmp_path / "vulndb.sqlite"
    out.write_bytes(b"previous good database")
    with pytest.raises(build.BuildError):
        do_build(sources, out, allow_small=False)
    assert out.read_bytes() == b"previous good database"
    assert not list(tmp_path.glob(".*.building"))


def test_rebuild_replaces_existing(sources, tmp_path):
    out = tmp_path / "vulndb.sqlite"
    out.write_bytes(b"old")
    do_build(sources, out)
    assert scalar(sqlite3.connect(out), "SELECT COUNT(*) FROM cves") == 5


def test_feed_order(tmp_path):
    srcs = make_sources(tmp_path / "s")
    write_extra = srcs / "nvdcve-2.0-recent.meta"
    write_extra.write_text((srcs / "nvdcve-2.0-modified.meta").read_text())
    (srcs / "nvdcve-2.0-recent.json.gz").write_bytes((srcs / "nvdcve-2.0-modified.json.gz").read_bytes())
    names = [f.name for f in build.feed_order(fetch.local_feeds(srcs))]
    assert names == ["2002", "2016", "2021", "2023", "2024", "modified"]
