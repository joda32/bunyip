"""Debian package version ordering (dpkg algorithm, deb-version(7)).

A port of internal/version/dpkg.go; both are tested with the same vectors.
Used to keep only the affected versions that are actually older than a
release's fixed version (Debian's lists can span the whole archive).
"""


class DebVersionError(ValueError):
    pass


def parse(v: str) -> tuple[str, str, str]:
    """Split "[epoch:]upstream[-revision]" -> (epoch, upstream, revision)."""
    epoch, rest = "0", v
    if ":" in rest:
        epoch, rest = rest.split(":", 1)
        if not epoch.isdigit():
            raise DebVersionError(f"invalid epoch in {v!r}")
        epoch = epoch.lstrip("0") or "0"
    upstream, revision = (rest.rsplit("-", 1) + [""])[:2] if "-" in rest else (rest, "")
    if "-" in rest and revision == "":
        raise DebVersionError(f"empty revision in {v!r}")
    if not upstream or not upstream[0].isdigit():
        raise DebVersionError(f"upstream must start with a digit: {v!r}")
    for part in (upstream, revision):
        for c in part:
            if not (c.isascii() and (c.isalnum() or c in ".+~-:")):
                raise DebVersionError(f"invalid character {c!r} in {v!r}")
    return epoch, upstream, revision


def _order(c: str | None) -> int:
    if c is None or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = a[i] if i < len(a) else None
            cb = b[j] if j < len(b) else None
            if (ca is not None and ca.isdigit()):
                ca_w = 0
            else:
                ca_w = _order(ca)
            cb_w = 0 if (cb is not None and cb.isdigit()) else _order(cb)
            if ca_w != cb_w:
                return -1 if ca_w < cb_w else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare(a: str, b: str) -> int:
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return -1 if (len(ea), ea) < (len(eb), eb) else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
