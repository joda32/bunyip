import json

import pytest

from conftest import REPO
from vulndb_update import cpe

VECTORS = json.loads((REPO / "testdata" / "contract" / "cpe_vectors.json").read_text())["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=[v["criteria"] or "<empty>" for v in VECTORS])
def test_contract_vectors(v):
    """Must agree with internal/cpe (Go) on every shared vector."""
    if v.get("error"):
        with pytest.raises(cpe.CPEError):
            cpe.lookup_key(v["criteria"])
    else:
        assert cpe.lookup_key(v["criteria"]) == (v["part"], v["vendor"], v["product"])


def test_parse_pattern_all_attributes():
    vals = cpe.parse_pattern("cpe:2.3:a:openbsd:openssh:9.3:P1:*:*:*:*:*:*")
    assert vals == ["a", "openbsd", "openssh", "9.3", "p1", "*", "*", "*", "*", "*", "*"]


def test_error_names_attribute():
    with pytest.raises(cpe.CPEError, match="attribute product"):
        cpe.parse_pattern("cpe:2.3:a:apache:http server:*:*:*:*:*:*:*:*")
