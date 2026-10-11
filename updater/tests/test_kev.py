import json

import pytest

from conftest import KEV_FILE, NVD_DATA
from bunyip_update import kev


def test_load_real_trimmed_catalogue():
    c = kev.load(NVD_DATA / KEV_FILE)
    assert c.catalog_version == "2026.10.04"
    assert {r.cve_id for r in c.rows} == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2016-1019"}
    r = next(r for r in c.rows if r.cve_id == "CVE-2021-41773")
    assert (r.vendor_project, r.product, r.date_added) == ("Apache", "HTTP Server", "2021-11-03")
    assert r.known_ransomware in ("Known", "Unknown")


def test_unknown_fields_and_duplicates(tmp_path):
    p = tmp_path / "k.json"
    p.write_text(json.dumps({"catalogVersion": "1", "vulnerabilities": [
        {"cveID": "CVE-1", "brandNewField": {"x": 1}},
        {"cveID": "CVE-1"},
        {"noId": True},
    ]}))
    assert [r.cve_id for r in kev.load(p).rows] == ["CVE-1"]


@pytest.mark.parametrize("doc", [[], {"vulnerabilities": []}, {"catalogVersion": "1"}])
def test_rejects_wrong_shape(tmp_path, doc):
    p = tmp_path / "k.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(kev.KEVError):
        kev.load(p)
