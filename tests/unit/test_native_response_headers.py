# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure handwritten header grammar cases, not original receipts or scanner acceptance."""

import pytest

from fuzzy1337.native_response_headers import HeaderFieldAbsent, NativeResponseHeaderError

BASE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 0\r\n"


@pytest.mark.parametrize("extra,absent", [
    (b"", True), (b"X-Content-Type-Options: nosniff\r\n", False),
    (b"x-content-type-options: nosniff\r\n", False),
    (b"X-CONTENT-TYPE-OPTIONS: nosniff\r\n", False),
    (b"X-Content-Type-Options-Description: nosniff\r\n", True),
    (b"X-Description: X-Content-Type-Options: nosniff\r\n", True),
])
def test_OnlyTheCompleteActualFieldNameDeterminesAbsence(extra, absent):
    """Header-name interpretation ignores similarly named fields and header-like value text."""

    assert HeaderFieldAbsent(BASE + extra + b"\r\n") is absent, (
        "The predicate must compare complete case-insensitive field names only."
    )


@pytest.mark.parametrize("raw", [
    b"", b"\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.1 200 OK\nX: y\n\n",
    BASE + b"\r\nX-Content-Type-Options: nosniff", BASE + b"\r\nbody\r\n\r\n",
    b"HTTP/1.1 404 Missing\r\nX: value\r\n\r\n", BASE + b" folded\r\n\r\n",
    BASE + b"X : value\r\n\r\n", BASE + b"X: \xff\r\n\r\n",
    BASE + b"Content-Type: duplicate\r\n\r\n", BASE + b"content-type: duplicate\r\n\r\n",
    BASE + b"X: " + b"x" * 4096 + b"\r\n\r\n", b"x" * 16385 + b"\r\n\r\n",
    BASE + b"".join(f"X{index}: value\r\n".encode() for index in range(63)) + b"\r\n",
    bytearray(BASE + b"\r\n"), None,
], ids=lambda value: f"header-{len(value)}" if value is not None else "none")
def test_UnadmittedHeaderGrammarCannotProduceAnAbsenceResult(raw):
    """Partial framing, body suffixes, duplicate names and resource overflow remain unassessed."""

    with pytest.raises(NativeResponseHeaderError, match="header section is unadmitted"):
        HeaderFieldAbsent(raw)
