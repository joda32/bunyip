import pytest

from vulndb_update import debversion

# Same vectors as internal/version/dpkg_test.go (dpkg's own suite + real versions).
VECTORS = [
    ("1.0", "1.0", 0), ("0:1.0", "1.0", 0), ("1.0-0", "1.0", 0), ("1.0", "1.0-1", -1),
    ("1:0.1", "2.0", 1), ("1.0~rc1", "1.0", -1), ("1.0~~", "1.0~", -1), ("1.0~", "1.0", -1),
    ("1.0", "1.0+b1", -1), ("1.0a", "1.0", 1), ("1.0a", "1.0+", -1), ("1.2.3-1~deb12u1", "1.2.3-1", -1),
    ("1.9", "1.10", -1), ("1.001", "1.1", 0), ("2.4.52-1ubuntu4.3", "2.4.52-1ubuntu4.12", -1),
    ("1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.18", -1), ("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.7", 1),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1), ("1:6.6p1-2ubuntu2.13+esm4", "1:6.6p1-2ubuntu2.13", 1),
    ("1.0-1ubuntu1", "1.0-1", 1), ("1.0-1build1", "1.0-1ubuntu1", -1),
    ("10:1.0", "9:2.0", 1),
]


@pytest.mark.parametrize("a, b, want", VECTORS)
def test_compare(a, b, want):
    assert debversion.compare(a, b) == want
    assert debversion.compare(b, a) == -want


@pytest.mark.parametrize("bad", ["", "x:1.0", "abc", "1.0-", "1.0_1", "1.0 1"])
def test_invalid(bad):
    with pytest.raises(debversion.DebVersionError):
        debversion.parse(bad)
