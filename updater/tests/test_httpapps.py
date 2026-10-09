import json
import pytest
from vulndb_update import httpapps
from conftest import REPO


def write(tmp_path, apps, source="curated:test"):
    p = tmp_path / "http.json"
    p.write_text(json.dumps({"source": source, "apps": apps}))
    return p


def app(**kw):
    a = {"evidence": "generator", "pattern": "^WordPress(?: ([0-9.]+))?",
         "vendor": "wordpress", "product": "wordpress", "version_group": 1, "confidence": "HIGH"}
    a.update(kw)
    return a


def test_repo_map_is_valid():
    rows = httpapps.load(REPO / "data" / "http_apps.json")
    assert any(r.vendor == "wordpress" and r.evidence == "generator" and r.version_group == 1 for r in rows)
    assert any(r.evidence == "header" and r.header == "x-jenkins" for r in rows)
    assert all(r.evidence in httpapps.EVIDENCE for r in rows)


def test_load_and_header_lowercased(tmp_path):
    [r] = httpapps.load(write(tmp_path, [app(evidence="header", header="X-Jenkins", pattern="^([0-9.]+)",
                                             vendor="jenkins", product="jenkins")]))
    assert r.header == "x-jenkins" and r.version_group == 1


@pytest.mark.parametrize("bad", [
    app(evidence="cookie"),                       # unknown evidence
    app(confidence="LOW"),                        # bad confidence
    app(pattern="("),                             # invalid regex
    app(version_group=5),                         # group out of range (pattern has 1)
    app(evidence="header"),                       # header evidence without a header name
    app(evidence="server", header="x-foo"),       # header name on non-header evidence
    app(pattern="^(?=WordPress)"),                # lookahead: not RE2-portable
    app(vendor=""),                               # missing vendor
])
def test_rejects_invalid(tmp_path, bad):
    with pytest.raises((ValueError, Exception)):
        httpapps.load(write(tmp_path, [bad]))


def test_duplicate_rejected(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        httpapps.load(write(tmp_path, [app(), app()]))
