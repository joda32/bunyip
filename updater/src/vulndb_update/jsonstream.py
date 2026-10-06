"""Stream the elements of one large array inside a JSON object.

NVD yearly feeds are single JSON documents of hundreds of megabytes, with the
records in a top-level "vulnerabilities" array. The standard library has no
streaming parser, so this reads text in chunks and decodes one array element
at a time with json.JSONDecoder.raw_decode, keeping memory bounded to about
one record plus one chunk.

Scope: the target key must belong to the top-level object. Keys before it
are decoded normally (they are small scalars in NVD feeds) and exposed via
`header`; anything after the array is not read.
"""

import json
from typing import Any, Iterator, TextIO

_WS = " \t\n\r"


class StreamError(ValueError):
    """Raised when the document does not have the expected shape."""


class ArrayStream:
    """Iterate over obj[key] for a top-level JSON object read from `fp`."""

    def __init__(self, fp: TextIO, key: str, chunk_size: int = 1 << 20):
        self._fp = fp
        self._key = key
        self._chunk = chunk_size
        self._buf = ""
        self._pos = 0
        self._eof = False
        self._dec = json.JSONDecoder()
        self.header: dict[str, Any] = {}

    # -- buffer management -------------------------------------------------

    def _fill(self, want: int) -> bool:
        """Read at least `want` more characters unless EOF. Returns False at EOF."""
        if self._eof:
            return False
        if self._pos > self._chunk:
            self._buf = self._buf[self._pos:]
            self._pos = 0
        data = self._fp.read(max(want, self._chunk))
        if not data:
            self._eof = True
            return False
        self._buf += data
        return True

    def _peek(self) -> str:
        """Skip whitespace and return the next character ('' at EOF)."""
        while True:
            while self._pos < len(self._buf) and self._buf[self._pos] in _WS:
                self._pos += 1
            if self._pos < len(self._buf):
                return self._buf[self._pos]
            if not self._fill(self._chunk):
                return ""

    def _expect(self, ch: str) -> None:
        got = self._peek()
        if got != ch:
            raise StreamError(f"expected {ch!r} at offset {self._pos}, got {got!r}")
        self._pos += 1

    def _value(self) -> Any:
        """Decode the next JSON value, reading more input as needed."""
        self._peek()
        want = self._chunk
        while True:
            try:
                value, end = self._dec.raw_decode(self._buf, self._pos)
            except json.JSONDecodeError:
                if not self._fill(want):
                    raise
                want *= 2  # large element: grow reads to avoid quadratic retries
                continue
            # A value ending exactly at the buffer end may be truncated
            # (e.g. the number 12 of 123); read more and decode again.
            if end == len(self._buf) and self._fill(want):
                continue
            self._pos = end
            return value

    # -- document structure ------------------------------------------------

    def __iter__(self) -> Iterator[Any]:
        self._expect("{")
        while True:
            if self._peek() == "}":
                raise StreamError(f"key {self._key!r} not found")
            name = self._value()
            if not isinstance(name, str):
                raise StreamError("object key is not a string")
            self._expect(":")
            if name == self._key:
                yield from self._array()
                return
            self.header[name] = self._value()
            sep = self._peek()
            if sep == ",":
                self._pos += 1
            elif sep != "}":
                raise StreamError(f"expected ',' or '}}' at offset {self._pos}, got {sep!r}")

    def _array(self) -> Iterator[Any]:
        self._expect("[")
        if self._peek() == "]":
            self._pos += 1
            return
        while True:
            yield self._value()
            sep = self._peek()
            self._pos += 1
            if sep == "]":
                return
            if sep != ",":
                raise StreamError(f"expected ',' or ']' in array, got {sep!r}")
