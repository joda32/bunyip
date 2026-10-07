import json

import pytest

from conftest import REPO
from vulndb_update import rpmversion

VECTORS = json.loads((REPO / "testdata" / "contract" / "rpm_vectors.json").read_text())["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=[f"{v['a']}|{v['b']}" for v in VECTORS])
def test_contract_vectors(v):
    """Must agree with internal/version/rpm.go on every shared vector."""
    assert rpmversion.compare(v["a"], v["b"]) == v["want"]
    assert rpmversion.compare(v["b"], v["a"]) == -v["want"]


@pytest.mark.parametrize("bad", ["", "x:1.0", "1.0 1", ":1"])
def test_invalid(bad):
    with pytest.raises(rpmversion.RPMVersionError):
        rpmversion.parse(bad)
