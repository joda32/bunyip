import io
import json

import pytest

from bunyip_update.jsonstream import ArrayStream, StreamError

TRICKY = [
    {"s": "contains ] and , and } and { and \"quotes\" and \\ backslash"},
    {"n": 123456789, "f": -1.5e3, "b": True, "z": None},
    {"nested": {"a": [1, [2, [3]]], "unicode": "café ☃"}},
    "plain string element",
    42,
    [],
    {},
]


def stream(text: str, chunk: int, key="vulnerabilities"):
    s = ArrayStream(io.StringIO(text), key, chunk_size=chunk)
    return s, list(s)


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 16, 1 << 20])
def test_elements_across_chunk_boundaries(chunk):
    doc = {"resultsPerPage": 1234567, "format": "NVD_CVE", "timestamp": "2026-10-06T01:00:04",
           "vulnerabilities": TRICKY, "after": "ignored"}
    for text in (json.dumps(doc), json.dumps(doc, indent=2)):
        s, items = stream(text, chunk)
        assert items == TRICKY
        # Numbers split across chunk boundaries must not be truncated.
        assert s.header == {"resultsPerPage": 1234567, "format": "NVD_CVE",
                            "timestamp": "2026-10-06T01:00:04"}


@pytest.mark.parametrize("chunk", [1, 5, 1 << 20])
def test_empty_array(chunk):
    assert stream('{"vulnerabilities" : [ ]}', chunk)[1] == []


def test_key_must_exist():
    with pytest.raises(StreamError, match="not found"):
        stream('{"other": [1, 2]}', 4)


@pytest.mark.parametrize("text", [
    '[1, 2]',                              # not an object
    '{"vulnerabilities": {"a": 1}}',       # not an array
    '{"vulnerabilities": [1 2]}',          # missing comma
    '{"vulnerabilities": [1, 2',           # truncated
    '{"a": 1 "vulnerabilities": []}',      # missing comma between keys
])
def test_malformed(text):
    with pytest.raises((StreamError, json.JSONDecodeError)):
        stream(text, 3)


def test_large_element_with_small_chunks():
    big = {"cpeMatch": [{"criteria": f"cpe:2.3:o:linux:linux_kernel:{i}:*:*:*:*:*:*:*"} for i in range(5000)]}
    _, items = stream(json.dumps({"vulnerabilities": [big, {"x": 1}]}), 64)
    assert items == [big, {"x": 1}]
