import json
import sqlite3

import pytest

from conftest import REPO, SCHEMA
from bunyip_update import aliases, build, fetch

REAL = REPO / "data" / "aliases.json"


def write(tmp_path, doc):
    p = tmp_path / "aliases.json"
    p.write_text(json.dumps(doc))
    return p


def test_real_aliases_file_is_valid():
    rows, rejected = aliases.load(REAL)
    assert len(rows) >= 74 and len(rejected) >= 39
    nginx = [r for r in rows if (r.observed_vendor, r.observed_product) == ("igor_sysoev", "nginx")]
    assert {r.canonical_cpe_prefix for r in nginx} == {"cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx"}
    assert all(r.confidence in aliases.CONFIDENCES and r.source for r in rows)


@pytest.mark.parametrize("doc, match", [
    ({"aliases": []}, "missing source"),
    ({"source": "s", "aliases": [{"observed": "a:x", "canonical": ["a:y:z"], "confidence": "HIGH"}]}, "part:vendor:product"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["a:y:z"], "confidence": "MAYBE"}]}, "confidence"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": [], "confidence": "HIGH"}]}, "no canonical"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["o:x:z"], "confidence": "HIGH"}]}, "change CPE part"),
    ({"source": "s", "aliases": [{"observed": "a:X:Y", "canonical": ["a:x:y"], "confidence": "HIGH"}]}, "to itself"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["a:*:z"], "confidence": "HIGH"}]}, "specific vendor"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["a:p q:z"], "confidence": "HIGH"}]}, "escaped"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["a:z:y"], "confidence": "HIGH"},
                                 {"observed": "a:x:y", "canonical": ["a:w:y"], "confidence": "HIGH"}]}, "duplicate"),
    ({"source": "s", "aliases": [{"observed": "a:x:y", "canonical": ["a:z:y"], "confidence": "HIGH"}],
      "rejected": [{"observed": "a:x:y"}]}, "both aliased and rejected"),
])
def test_invalid_files(tmp_path, doc, match):
    with pytest.raises(aliases.AliasError, match=match):
        aliases.load(write(tmp_path, doc))


def test_values_are_canonicalised(tmp_path):
    rows, _ = aliases.load(write(tmp_path, {"source": "s", "aliases": [
        {"observed": "a:Igor_Sysoev:NGINX", "canonical": ["a:F5:nginx"], "confidence": "HIGH"}]}))
    assert (rows[0].observed_vendor, rows[0].observed_product, rows[0].canonical_vendor) == ("igor_sysoev", "nginx", "f5")


def test_build_loads_aliases(sources, tmp_path):
    rows, _ = aliases.load(REAL)
    out = tmp_path / "v.sqlite"
    stats = build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                        allow_small=True, log=lambda *a: None, alias_rows=rows)
    conn = sqlite3.connect(out)
    assert conn.execute("SELECT COUNT(*) FROM aliases").fetchone()[0] == len(rows)
    assert conn.execute("SELECT value FROM database_metadata WHERE key = 'aliases_loaded'").fetchone()[0] == str(len(rows))
    # The small test dataset has no rules for most alias targets; they are reported, not fatal.
    assert stats.aliases == len(rows) and len(stats.aliases_without_rules) > 0


def test_review_proposes_and_skips_curated(sources, tmp_path):
    out = tmp_path / "v.sqlite"
    build.build(out, SCHEMA.read_text(), fetch.local_feeds(sources), fetch.local_kev(sources),
                allow_small=True, log=lambda *a: None)
    probes = tmp_path / "nmap-service-probes"
    probes.write_text(
        "match http m|^x| p/Apache httpd/ v/$1/ cpe:/a:apache:http_server:$1/\n"           # exact: no proposal
        "match http m|^y| p/Old Apache/ cpe:/a:apache_group:http_server/\n"                 # vendor mismatch
        "match ssh m|^z| p/OpenSSH/ cpe:/a:openbsd:openssh/ cpe:/o:linux:linux_kernel/\n"  # exact; OS ignored
        "match ftp m|^w| p/Flash/ cpe:/a:macromedia:flash_player/\n")                      # mismatch
    al = write(tmp_path, {"source": "s", "aliases": [], "rejected": [{"observed": "a:macromedia:flash_player"}]})
    cands = aliases.review(out, probes, al)
    assert [(c.kind, c.observed) for c in cands] == [("vendor-mismatch", "a:apache_group:http_server")]
    assert cands[0].targets[0].startswith("apache (")
