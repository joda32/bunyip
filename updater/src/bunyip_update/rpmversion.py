"""RPM package version ordering ([epoch:]version-release, rpmvercmp).

A port of internal/version/rpm.go; both are tested against
testdata/contract/rpm_vectors.json.
"""


class RPMVersionError(ValueError):
    pass


def parse(v: str) -> tuple[str, str, str]:
    epoch, rest = "0", v
    if ":" in rest:
        epoch, rest = rest.split(":", 1)
        if not epoch.isdigit():
            raise RPMVersionError(f"invalid epoch in {v!r}")
        epoch = epoch.lstrip("0") or "0"
    version, release = (rest.rsplit("-", 1) if "-" in rest else (rest, ""))
    if not version:
        raise RPMVersionError(f"empty RPM version {v!r}")
    if any(c <= " " or c >= "\x7f" for c in v):
        raise RPMVersionError(f"invalid character in {v!r}")
    return epoch, version, release


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def _vercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ta, tb = i < len(a) and a[i] == "~", j < len(b) and b[j] == "~"
        if ta or tb:
            if not ta:
                return 1
            if not tb:
                return -1
            i += 1
            j += 1
            continue
        ca, cb = i < len(a) and a[i] == "^", j < len(b) and b[j] == "^"
        if ca or cb:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not ca:
                return 1
            if not cb:
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        si, sj = i, j
        numeric = a[i].isdigit()
        test = str.isdigit if numeric else (lambda c: c.isascii() and c.isalpha())
        while i < len(a) and test(a[i]):
            i += 1
        while j < len(b) and test(b[j]):
            j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:
            return 1 if numeric else -1
        if numeric:
            sa, sb = sa.lstrip("0") or "0", sb.lstrip("0") or "0"
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def compare(a: str, b: str) -> int:
    ea, va, ra = parse(a)
    eb, vb, rb = parse(b)
    if ea != eb:
        return -1 if (len(ea), ea) < (len(eb), eb) else 1
    return _vercmp(va, vb) or _vercmp(ra, rb)
