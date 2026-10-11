import json

import pytest

from bunyip_update import windows
from conftest import REPO


def write(tmp_path, builds, source="curated:test"):
    p = tmp_path / "w.json"
    p.write_text(json.dumps({"source": source, "builds": builds}))
    return p


def row(**kw):
    r = {"build": 20348, "kind": "server", "name": "Windows Server 2022", "cpes": ["windows_server_2022:-:*"],
         "eol": "2031-10-14", "support": "extended support until 2031-10-14"}
    r.update(kw)
    return r


def test_repo_map_is_valid():
    rows = windows.load(REPO / "data" / "windows_builds.json")
    by_key = {(r.build, r.kind): r for r in rows}
    assert by_key[(14393, "server")].cpes == "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"
    # The client build is queried under both NVD spellings.
    assert by_key[(14393, "client")].cpes.split() == [
        "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"]
    assert all(r.source.startswith("curated:") for r in rows)


def test_load_full_names(tmp_path):
    [r] = windows.load(write(tmp_path, [row(cpes=["windows_server_2008:r2:sp1"])]))
    assert r.cpes == "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"
    assert (r.build, r.kind, r.eol, r.source) == (20348, "server", "2031-10-14", "curated:test")


@pytest.mark.parametrize("bad", [
    row(kind="desktop"),
    row(build="20348"),
    row(cpes=[]),
    row(cpes=["windows_server_2022:-"]),
    row(cpes=["windows_server_2022:*:*"]),
    row(cpes=["windows_server_*:-:*"]),
    row(eol="14 Oct 2031"),
    row(name=""),
])
def test_rejects_invalid_rows(tmp_path, bad):
    with pytest.raises((ValueError, KeyError)):
        windows.load(write(tmp_path, [bad]))


def test_rejects_duplicates_and_missing_source(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        windows.load(write(tmp_path, [row(), row()]))
    with pytest.raises(ValueError, match="source"):
        windows.load(write(tmp_path, [row()], source=""))
