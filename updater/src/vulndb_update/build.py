"""Build a fresh Offline VulnDB SQLite database from verified source files.

The database is written to a temporary ".<name>.building" file next to the
target, self-checked, and only then renamed over the target, so a failed or
interrupted build never replaces a working database.
"""

import gzip
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, aliases, cpe, debversion, httpapps, httptech, kev, nvd, osv, productnames
from .fetch import Feed, OSVExport
from .jsonstream import ArrayStream

# Sanity floors for a complete build (NVD has >300k CVEs, KEV >1.7k entries
# as of 2026). Tests and partial builds pass allow_small=True.
MIN_CVES = 200_000
MIN_KEV = 1_000
MIN_DISTRO_ROWS = 1_000
DATASET = "nvd+kev"


# Indexes needed only while building (the overlay deletes a CVE's rows); the
# query engine never uses them, so they are dropped before shipping.
BUILD_INDEXES = """
CREATE INDEX build_cve_matches_cve     ON cve_matches (cve_id);
CREATE INDEX build_exploit_cve         ON exploit_evidence (cve_id);
"""
DROP_BUILD_INDEXES = """
DROP INDEX build_cve_matches_cve;
DROP INDEX build_exploit_cve;
"""


class BuildError(RuntimeError):
    """Raised when the database fails a self-check."""


@dataclass
class DistroInput:
    distro: osv.Distro
    export: OSVExport


@dataclass
class Stats:
    distro_rows: int = 0
    distro_withdrawn: int = 0
    unmapped_packages: list[str] = field(default_factory=list)
    aliases: int = 0
    aliases_without_rules: list[str] = field(default_factory=list)
    product_names_without_rules: list[str] = field(default_factory=list)
    http_tech_without_rules: list[str] = field(default_factory=list)
    loaded: int = 0
    replaced: int = 0
    unchanged: int = 0
    rejected: int = 0
    skipped_rules: list[str] = field(default_factory=list)


def feed_order(feeds: list[Feed]) -> list[Feed]:
    """Yearly feeds in year order, then the modified feed as an overlay.
    Other feeds (e.g. "recent") are ignored: "modified" is a superset."""
    yearly = sorted((f for f in feeds if f.name.isdigit()), key=lambda f: int(f.name))
    return yearly + [f for f in feeds if f.name == "modified"]


def build(out: Path, schema_sql: str, feeds: list[Feed], kev_path: Path,
          allow_small: bool = False, log=print, alias_rows: list | None = None,
          distros: list[DistroInput] | None = None, package_map: list | None = None,
          releases: list | None = None, windows_builds: list | None = None,
          product_names: list | None = None, http_apps: list | None = None,
          http_tech: list | None = None) -> Stats:
    out = Path(out)
    tmp = out.with_name(f".{out.name}.building")
    tmp.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp, isolation_level=None)
    try:
        stats = _build(conn, schema_sql, feeds, kev_path, allow_small, log, alias_rows or [],
                       distros or [], package_map or [], releases or [], windows_builds or [],
                       product_names or [], http_apps or [], http_tech or [])
        conn.close()
        os.replace(tmp, out)
        return stats
    except BaseException:
        conn.close()
        tmp.unlink(missing_ok=True)
        raise


def _build(conn, schema_sql, feeds, kev_path, allow_small, log, alias_rows, distros, package_map, releases,
           windows_builds, product_names, http_apps, http_tech) -> Stats:
    # The file is private until renamed, so durability during the load is
    # unnecessary; integrity is checked explicitly before the rename.
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -262144")
    conn.executescript(schema_sql)
    conn.executescript(BUILD_INDEXES)

    stats = Stats()
    ordered = feed_order(feeds)
    if not ordered:
        raise BuildError("no NVD feeds to load")
    for feed in ordered:
        _load_feed(conn, feed, stats, log)

    catalogue = kev.load(kev_path)
    conn.execute("BEGIN")
    conn.executemany(
        "INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, due_date,"
        " known_ransomware, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(r.cve_id, r.vendor_project, r.product, r.vulnerability_name, r.date_added, r.due_date,
          r.known_ransomware, r.notes) for r in catalogue.rows])
    conn.execute("COMMIT")
    log(f"  KEV {catalogue.catalog_version}: {len(catalogue.rows)} entries")

    _load_aliases(conn, alias_rows, stats, log)
    for di in distros:
        _load_distro(conn, di, package_map, stats, log)
    conn.execute("BEGIN")
    conn.executemany(
        "INSERT INTO distro_releases (distro, release, codename, eol, extended_until, extended, source)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r.distro, r.release, r.codename, r.eol, r.extended_until, r.extended, r.source) for r in releases])
    conn.executemany(
        "INSERT INTO windows_builds (build, kind, name, cpes, eol, support, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(w.build, w.kind, w.name, w.cpes, w.eol, w.support, w.source) for w in windows_builds])
    conn.executemany(
        "INSERT INTO product_names (pattern, match, kind, part, vendor, product, os, version, confidence, note, source)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(n.pattern, n.match, n.kind, n.part, n.vendor, n.product, n.os, n.version, n.confidence, n.note, n.source)
         for n in product_names])
    conn.executemany(
        "INSERT INTO http_apps (evidence, header, pattern, vendor, product, version_group, confidence, note, source)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(a.evidence, a.header, a.pattern, a.vendor, a.product, a.version_group, a.confidence, a.note, a.source)
         for a in http_apps])
    conn.executemany(
        "INSERT INTO http_tech (name, vendor, product, source) VALUES (?, ?, ?, ?)",
        [(t.name, t.vendor, t.product, t.source) for t in http_tech])
    if http_tech:
        stats.http_tech_without_rules = httptech.targets_without_rules(conn, http_tech)
    conn.execute("COMMIT")
    if product_names:
        stats.product_names_without_rules = productnames.targets_without_rules(conn, product_names)
        log(f"  product names: {len(product_names)} loaded, "
            f"{len(stats.product_names_without_rules)} targets without NVD rules")
    _write_metadata(conn, ordered, catalogue, stats, distros)
    _self_check(conn, allow_small, bool(distros))
    conn.executescript(DROP_BUILD_INDEXES)
    conn.execute("ANALYZE")
    conn.execute("PRAGMA temp_store = FILE")  # VACUUM's copy would otherwise be held in memory
    conn.execute("VACUUM")  # compact: overlay deletes and dropped indexes leave free pages
    return stats


def _load_feed(conn, feed: Feed, stats: Stats, log) -> None:
    start, count = time.monotonic(), 0
    with gzip.open(feed.gz_path, "rt", encoding="utf-8") as f:
        conn.execute("BEGIN")
        for item in ArrayStream(f, "vulnerabilities"):
            _apply(conn, nvd.transform(item), stats)
            count += 1
        conn.execute("COMMIT")
    log(f"  {feed.gz_path.name}: {count} records in {time.monotonic() - start:.1f}s")


def _load_aliases(conn, rows: list, stats: Stats, log) -> None:
    """Store curated aliases. A target with no NVD rules is kept (it may gain
    rules later) but reported, since it currently adds nothing."""
    conn.execute("BEGIN")
    conn.executemany(
        "INSERT INTO aliases (observed_vendor, observed_product, canonical_vendor, canonical_product,"
        " canonical_cpe_prefix, source, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r.observed_vendor, r.observed_product, r.canonical_vendor, r.canonical_product,
          r.canonical_cpe_prefix, r.source, r.confidence) for r in rows])
    conn.execute("COMMIT")
    stats.aliases = len(rows)
    for r in rows:
        if not conn.execute("SELECT 1 FROM cve_matches WHERE criteria_part = ? AND criteria_vendor = ?"
                            " AND criteria_product = ? LIMIT 1",
                            (r.part, r.canonical_vendor, r.canonical_product)).fetchone():
            stats.aliases_without_rules.append(r.canonical_cpe_prefix)
    if rows:
        log(f"  aliases: {len(rows)} loaded, {len(stats.aliases_without_rules)} targets without NVD rules")


def _load_distro(conn, di: DistroInput, package_map: list, stats: Stats, log) -> None:
    """Load one distribution's advisories for the mapped packages.

    Per-CVE records come first. Per-advisory records (Debian DSA/DLA, Red
    Hat RHSA, Rocky RLSA, AlmaLinux ALSA) then fill only CVE/release/package/
    stream combinations no per-CVE record covers. If several advisories list
    the same CVE for one release and stream, the earliest fixed version is
    kept: later advisories re-list CVEs (cumulative or regression updates),
    and taking their version would mark already-fixed hosts vulnerable.
    """
    start = time.monotonic()
    d = di.distro
    mapped = [r for r in package_map if r.distro == d.name]
    packages = {r.package for r in mapped}
    conn.execute("BEGIN")
    conn.executemany(
        "INSERT INTO distro_packages (cpe_part, cpe_vendor, cpe_product, distro, package, source)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [(r.part, r.vendor, r.product, r.distro, r.package, r.source) for r in mapped])
    rows: dict[tuple, osv.AdvisoryRow] = {}
    versions: set = set()
    withdrawn = 0
    if d.record_prefix:
        for record in osv.iter_records(di.export.zip_path, d.record_prefix):
            t = osv.transform(record, d, packages, per_cve=True)
            withdrawn += t.withdrawn
            versions |= t.versions
            for r in t.rows:
                rows[r.key] = r
    primary = set(rows)
    if d.advisory_prefixes:
        for record in osv.iter_records(di.export.zip_path, d.advisory_prefixes):
            t = osv.transform(record, d, packages, per_cve=False)
            withdrawn += t.withdrawn
            versions |= t.versions
            for r in t.rows:
                if r.key in primary:
                    continue
                old = rows.get(r.key)
                if old is None or _earlier_fix(d, r.fixed_version, old.fixed_version):
                    rows[r.key] = r
    conn.executemany(
        "INSERT INTO distro_advisories (source, advisory_id, cve_id, distro, release, channel, codename,"
        " package, fixed_version, affected_upstreams, urgency, stream, modified_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(r.source, r.advisory_id, r.cve_id, r.distro, r.release, r.channel, r.codename, r.package,
          r.fixed_version, r.affected_upstreams, r.urgency, r.stream, r.modified_at) for r in rows.values()])
    conn.executemany(
        "INSERT OR IGNORE INTO distro_package_versions (distro, release, package, version, upstream)"
        " VALUES (?, ?, ?, ?, ?)",
        [(v.distro, v.release, v.package, v.version, v.upstream) for v in versions])
    conn.execute("COMMIT")
    seen_packages = {r.package for r in rows.values()}
    stats.distro_rows += len(rows)
    stats.distro_withdrawn += withdrawn
    stats.unmapped_packages += sorted(f"{d.name}/{p}" for p in packages - seen_packages)
    log(f"  {d.name} advisories: {len(rows)} rows for {len(seen_packages)} packages "
        f"({len(rows) - len(primary)} from per-advisory records; {withdrawn} withdrawn records skipped) "
        f"in {time.monotonic() - start:.1f}s")


def _earlier_fix(d: osv.Distro, a: str | None, b: str | None) -> bool:
    """Whether fixed version a is an earlier fix point than b. A row with no
    fix never replaces a fixed one."""
    if a is None:
        return False
    if b is None:
        return True
    try:
        return d.compare(a, b) < 0
    except ValueError:
        return False


def _apply(conn, rec: nvd.Record, stats: Stats) -> None:
    """Insert a record, replacing an older copy (the modified-feed overlay) and
    removing CVEs that have since been rejected."""
    row = conn.execute("SELECT modified_at FROM cves WHERE cve_id = ?", (rec.cve_id,)).fetchone()
    if rec.rejected:
        if row:
            _delete(conn, rec.cve_id)
        stats.rejected += 1
        return
    if row:
        if (row[0] or "") >= (rec.modified_at or ""):
            stats.unchanged += 1
            return
        _delete(conn, rec.cve_id)
        stats.replaced += 1
    else:
        stats.loaded += 1
    stats.skipped_rules.extend(rec.skipped_rules)
    _insert(conn, rec)


def _delete(conn, cve_id: str) -> None:
    conn.execute("DELETE FROM cve_matches WHERE cve_id = ?", (cve_id,))
    conn.execute("DELETE FROM cve_config_nodes WHERE configuration_id IN"
                 " (SELECT id FROM cve_configurations WHERE cve_id = ?)", (cve_id,))
    conn.execute("DELETE FROM cve_configurations WHERE cve_id = ?", (cve_id,))
    conn.execute("DELETE FROM exploit_evidence WHERE cve_id = ? AND source = ?",
                 (cve_id, nvd.EXPLOIT_SOURCE))
    conn.execute("DELETE FROM cves WHERE cve_id = ?", (cve_id,))


def _insert(conn, r: nvd.Record) -> None:
    conn.execute(
        "INSERT INTO cves (cve_id, published_at, modified_at, description, cvss_v3_score, cvss_v3_vector,"
        " cvss_v4_score, cvss_v4_vector, severity, cwe) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (r.cve_id, r.published_at, r.modified_at, r.description, r.cvss_v3_score, r.cvss_v3_vector,
         r.cvss_v4_score, r.cvss_v4_vector, r.severity, r.cwe))
    for cfg in r.configurations:
        cfg_id = conn.execute("INSERT INTO cve_configurations (cve_id, operator) VALUES (?, ?)",
                              (r.cve_id, cfg.operator)).lastrowid
        and_config_siblings = int(cfg.operator == "AND" and len(cfg.nodes) > 1)
        for node in cfg.nodes:
            node_id = conn.execute(
                "INSERT INTO cve_config_nodes (configuration_id, operator, negate) VALUES (?, ?, ?)",
                (cfg_id, node.operator, int(node.negate))).lastrowid
            and_node_siblings = int(node.operator == "AND" and len(node.matches) > 1)
            conn.executemany(
                "INSERT INTO cve_matches (cve_id, node_id, criteria, criteria_part, criteria_vendor,"
                " criteria_product, vulnerable, version_start_including, version_start_excluding,"
                " version_end_including, version_end_excluding, node_operator, node_negate, config_operator,"
                " and_node_siblings, and_config_siblings, version_key)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(r.cve_id, node_id, m.criteria, m.part, m.vendor, m.product, int(m.vulnerable),
                  m.start_including, m.start_excluding, m.end_including, m.end_excluding,
                  node.operator, int(node.negate), cfg.operator, and_node_siblings, and_config_siblings,
                  m.version_key)
                 for m in node.matches])
    conn.executemany(
        "INSERT INTO exploit_evidence (cve_id, source, reference, reference_type, verified, metadata_json)"
        " VALUES (?, ?, ?, 'exploit-reference', 0, ?)",
        [(r.cve_id, nvd.EXPLOIT_SOURCE, e.reference, e.metadata_json) for e in r.exploits])


def _count(conn, sql: str) -> int:
    return conn.execute(sql).fetchone()[0]


def _write_metadata(conn, feeds: list[Feed], catalogue: kev.Catalogue, stats: Stats,
                    distros: list[DistroInput]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "dataset": DATASET,
        "database_version": now,
        "created_at": now,
        "updater_version": __version__,
        "nvd_last_modified": max(f.meta.last_modified_utc() for f in feeds),
        "nvd_feeds": ",".join(f.name for f in feeds),
        "kev_catalog_version": catalogue.catalog_version,
        "kev_date_released": catalogue.date_released,
        "nvd_cves_total": str(_count(conn, "SELECT COUNT(*) FROM cves")),
        "nvd_cves_without_configurations": str(_count(conn,
            "SELECT COUNT(*) FROM cves WHERE NOT EXISTS"
            " (SELECT 1 FROM cve_configurations c WHERE c.cve_id = cves.cve_id)")),
        "nvd_rules_skipped": str(len(stats.skipped_rules)),
        "aliases_loaded": str(stats.aliases),
        "distro_sources": ",".join(di.distro.name for di in distros),
        "distro_advisory_rows": str(stats.distro_rows),
    }
    for di in distros:
        meta[f"{di.distro.name}_advisories_last_modified"] = di.export.last_modified
    conn.execute("BEGIN")
    conn.executemany("INSERT OR REPLACE INTO database_metadata (key, value) VALUES (?, ?)",
                     list(meta.items()))
    conn.execute("COMMIT")


def _self_check(conn, allow_small: bool, expect_distro: bool = False) -> None:
    problems = []
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        problems.append(f"integrity_check: {integrity}")
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        problems.append(f"{len(fk)} foreign key violations, e.g. {fk[0]}")
    if not conn.execute("SELECT 1 FROM database_metadata WHERE key = 'schema_version'").fetchone():
        problems.append("schema_version metadata missing")

    # Mirror of the Go `db verify` check: lookup columns must agree with criteria.
    bad = 0
    for row_id, criteria, part, vendor, product, key, ranged in conn.execute(
            "SELECT id, criteria, criteria_part, criteria_vendor, criteria_product, version_key,"
            " COALESCE(version_start_including, version_start_excluding, version_end_including,"
            " version_end_excluding) IS NOT NULL FROM cve_matches"):
        try:
            attrs = cpe.parse_pattern(criteria)
            want_key = "" if ranged else cpe.version_key(cpe.unescape(attrs[3]))
            ok = (attrs[0], attrs[1], attrs[2]) == (part, vendor, product) and key == want_key
        except cpe.CPEError:
            ok = False
        if not ok:
            bad += 1
    if bad:
        problems.append(f"{bad} match rules whose lookup columns disagree with their criteria")

    if not allow_small:
        n_cves = _count(conn, "SELECT COUNT(*) FROM cves")
        n_kev = _count(conn, "SELECT COUNT(*) FROM kev")
        if n_cves < MIN_CVES:
            problems.append(f"only {n_cves} CVEs loaded (expected >= {MIN_CVES}); incomplete feeds?")
        if n_kev < MIN_KEV:
            problems.append(f"only {n_kev} KEV entries (expected >= {MIN_KEV})")
        n_distro = _count(conn, "SELECT COUNT(*) FROM distro_advisories")
        if expect_distro and n_distro < MIN_DISTRO_ROWS:
            problems.append(f"only {n_distro} distribution advisory rows (expected >= {MIN_DISTRO_ROWS})")
    if problems:
        raise BuildError("self-check failed: " + "; ".join(problems))
