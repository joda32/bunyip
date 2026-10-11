import json
import pytest
from bunyip_update import httptech
from conftest import REPO


def test_repo_map_valid():
    rows = httptech.load(REPO / "data" / "http_tech.json")
    assert len(rows) > 300
    by = {r.name.lower() for r in rows}
    assert "wordpress" in by and "gitlab" in by


def test_rejects_missing_fields(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"source": "x", "tech": [{"name": "A", "vendor": "v"}]}))
    with pytest.raises(ValueError):
        httptech.load(p)


def test_rejects_missing_source(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"tech": []}))
    with pytest.raises(ValueError, match="source"):
        httptech.load(p)
