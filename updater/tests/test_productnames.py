import json
import sqlite3

import pytest

from vulndb_update import productnames
from conftest import REPO, SCHEMA


def write(tmp_path, products=(), components=(), source="curated:test", rejected=()):
    p = tmp_path / "names.json"
    p.write_text(json.dumps({"source": source, "products": list(products), "os_components": list(components),
                             "rejected": list(rejected)}))
    return p


def prod(**kw):
    e = {"pattern": "ClamAV", "cpes": ["clamav:clamav"], "version": "nmap", "confidence": "HIGH"}
    e.update(kw)
    return e


def test_repo_map_is_valid():
    rows = productnames.load(REPO / "data" / "product_names.json")
    kinds = {r.kind for r in rows}
    assert kinds == {"product", "os_component"}
    rpc = [r for r in rows if r.pattern == "Microsoft Windows RPC"]
    assert rpc and rpc[0].kind == "os_component" and rpc[0].os == "windows"
    clam = sorted((r.vendor, r.product, r.version) for r in rows if r.pattern == "ClamAV")
    assert clam == [("clam_anti-virus", "clamav", "nmap"), ("clamav", "clamav", "nmap")]


def test_one_row_per_target(tmp_path):
    rows = productnames.load(write(tmp_path, [prod(cpes=["clamav:clamav", "clam_anti-virus:clamav"], note="n")]))
    assert [(r.part, r.vendor, r.product, r.match, r.note) for r in rows] == [
        ("a", "clamav", "clamav", "exact", "n"), ("a", "clam_anti-virus", "clamav", "exact", "n")]


@pytest.mark.parametrize("bad", [
    prod(version="maybe"),
    prod(confidence="LOW"),
    prod(cpes=[]),
    prod(cpes=["clamav"]),
    prod(pattern=""),
    prod(match="glob"),
    prod(pattern="ClamAV.*", match="regex"),                 # not anchored
    prod(pattern="^(?!Samba).*netbios$", match="regex"),     # lookahead: not RE2
    prod(pattern="^(a)\\1$", match="regex"),                 # back-reference: not RE2
    prod(pattern="^(unclosed$", match="regex"),
])
def test_rejects_invalid_products(tmp_path, bad):
    with pytest.raises(Exception):
        productnames.load(write(tmp_path, [bad]))


def test_os_components(tmp_path):
    [r] = productnames.load(write(tmp_path, components=[{"pattern": "Microsoft Windows RPC", "os": "windows"}]))
    assert (r.kind, r.os, r.vendor, r.version) == ("os_component", "windows", "", "none")
    with pytest.raises(ValueError, match="windows"):
        productnames.load(write(tmp_path, components=[{"pattern": "x", "os": "linux"}]))


def test_duplicates_rejected(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        productnames.load(write(tmp_path, [prod(), prod()]))


def test_targets_without_rules(tmp_path):
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA.read_text())
    conn.execute("INSERT INTO cves (cve_id, description) VALUES ('CVE-0000-1', 'x')")
    conn.execute("INSERT INTO cve_matches (cve_id, criteria, criteria_part, criteria_vendor, criteria_product, vulnerable)"
                 " VALUES ('CVE-0000-1', 'cpe:2.3:a:clamav:clamav:*:*:*:*:*:*:*:*', 'a', 'clamav', 'clamav', 1)")
    rows = productnames.load(write(tmp_path, [prod(cpes=["clamav:clamav", "nobody:nothing"])]))
    assert productnames.targets_without_rules(conn, rows) == ["nobody:nothing"]


PROBES = r"""
match clam m|^ClamAV ([\w.]+)/(\w+)/(.+)$| p/ClamAV/ v/$1 ($2)/
match smtp m|^220 hm ([\d.]+)| p/hMailServer smtpd/ v/$1/ o/Windows/ cpe:/o:microsoft:windows/a
match http m|^Server: nginx| p/nginx/ cpe:/a:igor_sysoev:nginx/
match http m|^Server: Web| p/Web/
match ftp m|^220 foo| p/Unknown Thing ftpd/
"""


def test_review(tmp_path):
    probes = tmp_path / "probes"
    probes.write_text(PROBES)
    db = tmp_path / "v.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA.read_text())
    for i, (v, p) in enumerate([("clamav", "clamav"), ("hmailserver", "hmailserver"), ("telegram", "web")]):
        conn.execute("INSERT INTO cves (cve_id, description) VALUES (?, 'x')", (f"CVE-0000-{i}",))
        conn.execute("INSERT INTO cve_matches (cve_id, criteria, criteria_part, criteria_vendor, criteria_product,"
                     " vulnerable) VALUES (?, ?, 'a', ?, ?, 1)", (f"CVE-0000-{i}", f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*", v, p))
    conn.commit()
    conn.close()
    # ClamAV is curated, "Web" rejected, nginx has a CPE, the ftpd has no NVD product.
    curated = write(tmp_path, [prod()], rejected=["Web"])
    cands = productnames.review(db, probes, curated)
    assert [(c.nmap_product, c.versions, c.targets) for c in cands] == [
        ("hMailServer smtpd", ["$1"], [("hmailserver", "hmailserver", 1)])]
