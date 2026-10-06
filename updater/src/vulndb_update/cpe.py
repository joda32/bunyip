"""CPE 2.3 match-criteria canonicalisation.

This is a deliberately small port of the Go package internal/cpe: it only
needs to turn an NVD criteria string into the canonical part/vendor/product
values stored in the cve_matches lookup columns. The Go engine looks rules up
by those columns, so the two implementations must agree exactly; both are
tested against testdata/contract/cpe_vectors.json.

Canonical form: lower case; every character other than [a-z0-9._-] is
backslash-escaped; unescaped '*' and '?' are wildcards; a decoded literal
hyphen that would read as NA ("-") stays escaped ("\\-").
"""

ANY = "*"
NA = "-"
_PREFIX = "cpe:2.3:"
_ATTRIBUTES = (
    "part", "vendor", "product", "version", "update", "edition",
    "language", "sw_edition", "target_sw", "target_hw", "other",
)


class CPEError(ValueError):
    """Raised for malformed CPE criteria."""


def parse_pattern(s: str) -> list[str]:
    """Parse a CPE 2.3 criteria string into its 11 canonical attribute values."""
    s = s.strip()
    if not s:
        raise CPEError("empty input")
    if not s.lower().startswith(_PREFIX):
        raise CPEError(f"{s!r} must start with {_PREFIX!r}")
    fields = _split_escaped(s[len(_PREFIX):])
    if len(fields) != len(_ATTRIBUTES):
        raise CPEError(f"need {len(_ATTRIBUTES)} attributes after {_PREFIX!r}, got {len(fields)}")
    values = []
    for name, field in zip(_ATTRIBUTES, fields):
        try:
            values.append(_canonical(field))
        except CPEError as e:
            raise CPEError(f"attribute {name}: {e}") from None
    if values[0] not in ("a", "o", "h"):
        raise CPEError(f"part must be a, o or h, got {values[0]!r}")
    return values


def lookup_key(criteria: str) -> tuple[str, str, str]:
    """Return the (part, vendor, product) lookup columns for a criteria string."""
    v = parse_pattern(criteria)
    return v[0], v[1], v[2]


def _split_escaped(s: str) -> list[str]:
    fields, cur, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 >= len(s):
                raise CPEError("trailing backslash")
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    fields.append("".join(cur))
    return fields


def _is_plain(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c in "_.-")


def _literal(c: str) -> str:
    return c.lower() if _is_plain(c) else "\\" + c


def _canonical(v: str) -> str:
    if v == "":
        raise CPEError("empty value (use * for ANY)")
    if v in (ANY, NA):
        return v
    if not v.isascii():
        # The Go implementation works on bytes and rejects any non-ASCII
        # byte, escaped or not; match that exactly.
        raise CPEError(f"non-ASCII character in value {v!r}")
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\":
            # _split_escaped guarantees a following character.
            out.append(_literal(v[i + 1]))
            i += 2
            continue
        if c in "*?":
            out.append(c)
        elif _is_plain(c):
            out.append(c.lower())
        else:
            raise CPEError(f"character {c!r} in value {v!r} must be escaped")
        i += 1
    result = "".join(out)
    return "\\-" if result == NA else result
