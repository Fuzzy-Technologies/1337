# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent source-coordinate oracles and consumed RFC 5424 grammar boundaries."""

from __future__ import annotations

import hashlib
import json

import pytest

from fuzzy1337 import syslog_records as records
from tests.syslog_helpers import FIRST, ORIGINAL, SECOND, THIRD


def Decode(payload: bytes, framing: str = "single") -> dict:
    """Invoke the actual parser with an independently computed original checksum."""

    return json.loads(records.ParseSavedSyslog(payload,
        expectedSha256=hashlib.sha256(payload).hexdigest(), framing=framing))


def test_IndependentByteOraclePreservesRepeatedValuesOffsetsAndUnknownFields():
    """The handwritten 166-byte original has independently specified spans and source clocks."""

    assert len(ORIGINAL) == 166, "The independent original byte oracle must remain fixed"
    document = Decode(ORIGINAL, "lines")
    items = document["records"]
    assert [(item["byte_offset"], item["byte_length"]) for item in items] == [
        (0, 99), (101, 16), (118, 48)
    ], "RFC source framing changed original message coordinates"
    assert [item["terminator"] for item in items] == ["CRLF", "LF", None], (
        "Saved line delimiters must remain observable without trimming message bytes"
    )
    first, second, third = items
    element = first["structured_data"][0]
    assert (element["byte_offset"], element["byte_length"]) == (51, 39), (
        "Structured data must retain its exact original global byte span"
    )
    parameters = element["parameters"]
    assert [(item["name"], item["value"]) for item in parameters] == [
        ("a", "one"), ("a", "two"), ("e", 'x]y"z\\')
    ], "Repeated RFC parameters and decoded escapes must keep source order"
    assert (parameters[2]["value_byte_offset"], parameters[2]["value_byte_length"]) == (79, 9), (
        "Escaped value coordinates must address original escaped bytes"
    )
    assert first["message"] == {
        "byte_offset": 91, "byte_length": 8, "content_byte_offset": 94,
        "content_byte_length": 5, "encoding": "utf-8-bom",
        "sha256": hashlib.sha256(b"\xef\xbb\xbfcaf\xc3\xa9").hexdigest(),
    }, "BOM and UTF-8 byte coordinates must be distinct from character counts"
    assert first["timestamp_utc"] == third["timestamp_utc"] == (
        "2026-11-25T04:45:30.123456Z"
    ), "Derived UTC must preserve original fractional precision"
    assert first["timestamp_offset"] == "+05:30" and first["offset_known"] is True, (
        "An explicitly declared offset must remain distinguishable from UTC and unknown"
    )
    assert all(second[key] is None for key in (
        "timestamp", "hostname", "app_name", "procid", "msgid", "structured_data", "message"
    )), "NIL fields must remain unknown without acquisition-clock or identity substitution"
    assert third["message"]["byte_offset"] == 166 and third["message"]["byte_length"] == 0, (
        "A present-empty message must remain distinct from an absent optional message"
    )
    assert [(item["facility_code"], item["severity_code"]) for item in items] == [
        (1, 5), (0, 0), (23, 7)
    ], "Facility and severity are preserved source codes, not product risk scores"
    assert "café" not in json.dumps(document, ensure_ascii=False), (
        "The normalized document must never contain arbitrary original MSG content"
    )


@pytest.mark.parametrize("timestamp,known,utc", [
    (b"-", None, None),
    (b"2026-11-25T00:00:00-00:00", False, None),
    (b"2026-11-25T00:00:00+00:00", True, "2026-11-25T00:00:00Z"),
    (b"2026-11-25T00:00:00.1Z", True, "2026-11-25T00:00:00.1Z"),
    (b"0000-02-29T00:00:00Z", True, None),
    (b"0001-01-01T00:00:00+23:59", True, None),
])
def test_DeclaredTimeNeverInfersUnknownOffsetOrRejectsUnrepresentableUtc(timestamp, known, utc):
    """RFC source spelling survives even when optional derived UTC cannot be represented."""

    item = Decode(b"<0>1 " + timestamp + b" opaque-host opaque-app not-a-pid ID -")["records"][0]
    assert item["offset_known"] is known and item["timestamp_utc"] == utc, (
        "Known offset, unknown offset and unrepresentable derived UTC were conflated"
    )
    assert item["hostname"] == "opaque-host" and item["procid"] == "not-a-pid", (
        "Source hostname and PROCID must remain opaque declarations"
    )


@pytest.mark.parametrize("payload", [
    b'<0>1 - - - - - [x a="one" a="two"]',
    b'<0>1 - - - - - [[ [="opening"]',
    b'<0>1 - - - - - [x a="unknown\\q"]',
    b'<0>1 - - - - - [x a="\x00\n\r"]',
    b"<0>1 - - - - - - \xff\x00\n\r",
    b"<0>1 - - - - - - \xef\xbb\xbf",
])
def test_ValidSourceGrammarPreservesValuesAndOpaqueMessageOctets(payload):
    """Do not reject repeated names, bracket names, unknown escapes or unmarked binary MSG."""

    assert len(Decode(payload)["records"]) == 1, "Valid consumed RFC bytes were rejected"


def test_UnknownEscapeAndControlParameterValuesRemainExact():
    """Unknown backslashes stay literal and UTF-8 parameter controls remain source data."""

    item = Decode(b'<0>1 - - - - - [x a="unknown\\q" a="\x00\n\r"]')["records"][0]
    assert [entry["value"] for entry in item["structured_data"][0]["parameters"]] == [
        "unknown\\q", "\x00\n\r"
    ], "The receiver must preserve unknown escapes and admitted UTF-8 control characters"


@pytest.mark.parametrize("payload", [
    b"", b"<00>1 - - - - - -", b"<192>1 - - - - - -", b"<0>2 - - - - - -",
    b"<0>1 2026-11-25t00:00:00Z - - - - -",
    b"<0>1 2026-11-25T00:00:00z - - - - -",
    b"<0>1 2026-11-25T00:00:60Z - - - - -",
    b"<0>1 2026-02-29T00:00:00Z - - - - -",
    b"<0>1 2026-11-25T00:00:00.1234567Z - - - - -",
    b"<0>1 2026-11-25T00:00:00+24:00 - - - - -",
    b"<0>1 - - - - - [x][x]", b'<0>1 - - - - - [x a="unescaped]"]',
    b'<0>1 - - - - - [x a="\xff"]', b"<0>1 - - - - - - \xef\xbb\xbf\xff",
    b"<0>1 - - - - - []", b"<0>1 - - - - - [x]unexpected",
    b"<0>1 - - - - - [private@not-decimal]",
])
def test_InvalidConsumedGrammarRefusesTheWholeDocument(payload):
    """A malformed original supplies no partial normalized output or source-bearing error."""

    with pytest.raises(records.SyslogDecodeError) as refusal:
        Decode(payload)

    assert refusal.value.code in {
        "source-limit", "priority-version", "timestamp", "structured-data",
        "parameter-utf8", "message-utf8",
    }, "Parser refusal must retain a fixed category rather than source text"


def test_LinesIsAnExplicitStorageRestrictionWithNoUnicodeSplittingOrTrimming():
    """Only byte LF/CRLF delimiters split records and significant trailing spaces survive."""

    raw = b"<0>1 - - - - - - \xe2\x80\xa8\r\n" + THIRD
    items = Decode(raw, "lines")["records"]
    assert len(items) == 2 and items[0]["message"]["byte_length"] == 3, (
        "Unicode line separators must remain message bytes, never framing delimiters"
    )
    assert items[1]["message"]["byte_length"] == 0, "A final significant SP was trimmed"

    with pytest.raises(records.SyslogDecodeError):
        Decode(FIRST + b"\n\n" + SECOND, "lines")

    assert Decode(b"<0>1 - - - - - - \n\x00")["records"][0]["message"]["byte_length"] == 2, (
        "Single-message mode must preserve control and LF payload octets"
    )


@pytest.mark.parametrize("field,maximum", [(2, 255), (3, 48), (4, 128), (5, 32)])
def test_HeaderLengthBoundariesAreExactAndDoNotNormalizeCase(field, maximum):
    """Each independent RFC header field preserves its exact admitted spelling."""

    parts = [b"<0>1", b"-", b"-", b"-", b"-", b"-", b"-"]
    parts[field] = b"A" * maximum
    assert len(Decode(b" ".join(parts))["records"]) == 1, "An exact header boundary was rejected"
    parts[field] += b"A"

    with pytest.raises(records.SyslogDecodeError):
        Decode(b" ".join(parts))


def test_ProfileCapsAndIndependentBytePinApplyBeforeAnyPartialResult():
    """Exercise byte, record, parameter, element and original-checksum ceilings separately."""

    raw = b"<0>1 - - - - - - " + b"x" * (records.MAX_SYSLOG_RECORD_BYTES - 17)
    assert len(raw) == records.MAX_SYSLOG_RECORD_BYTES, "Record ceiling oracle must be exact"
    assert len(Decode(raw)["records"]) == 1, "An exact record byte boundary was rejected"

    for refused in (
        raw + b"x",
        (SECOND + b"\n") * (records.MAX_SYSLOG_RECORDS + 1),
        b'<0>1 - - - - - [x a="' + b"x" * (records.MAX_SYSLOG_VALUE_BYTES + 1) + b'"]',
        b"<0>1 - - - - - " + b"".join(
            b"[x" + str(index).encode() + b"]" for index in range(33)),
        b"<0>1 - - - - - [x" + b' a=""' * 65 + b"]",
        b"x" * (records.MAX_SYSLOG_SOURCE_BYTES + 1),
    ):
        with pytest.raises(records.SyslogDecodeError):
            Decode(refused, "lines" if refused.startswith(SECOND + b"\n") else "single")

    assert len(Decode((SECOND + b"\n") * 256, "lines")["records"]) == 256, (
        "The exact saved-record count ceiling was rejected"
    )

    with pytest.raises(records.SyslogDecodeError, match="source-digest"):
        records.ParseSavedSyslog(SECOND, expectedSha256="0" * 64)

    with pytest.raises(ValueError):
        records.ParseSavedSyslog(SECOND, expectedSha256="A" * 64)

    with pytest.raises(ValueError):
        Decode(SECOND, "auto")


def test_ExactStructuredDataBoundariesAndExpandedDocumentBudget(monkeypatch):
    """Exact SD count/value limits remain admitted; canonical expansion has its own ceiling."""

    value = b'<0>1 - - - - - [x a="' + b"x" * 4096 + b'"]'
    assert len(Decode(value)["records"]) == 1, "Exact parameter raw-byte cap was rejected"
    elements = b"<0>1 - - - - - " + b"".join(
        b"[x" + str(index).encode() + b"]" for index in range(32))
    assert len(Decode(elements)["records"][0]["structured_data"]) == 32, (
        "Exact SD element count cap was rejected"
    )
    parameters = b"<0>1 - - - - - [x" + b' a=""' * 64 + b"]"
    assert len(Decode(parameters)["records"][0]["structured_data"][0]["parameters"]) == 64, (
        "Exact repeated parameter count cap was rejected"
    )
    monkeypatch.setattr(records, "MAX_SYSLOG_DOCUMENT_BYTES", 1)

    with pytest.raises(records.SyslogDecodeError, match="document-limit"):
        Decode(SECOND)


@pytest.mark.parametrize("payload", [
    b"<0>1 - - - - -", b"<0>1 -  - - - -", b"<0>1 - - - - - -extra",
    b'<0>1 - - - - - [x a="unterminated]', b'<0>1 - - - - - [x a=unquoted]',
    b'<0>1 - - - - - [x ="" ]', b"<0>1 - - - - - [" + b"x" * 33 + b"]",
    b'<0>1 - - - - - [x a b=""]', b"<0>1 - - - - - [x",
])
def test_IncompleteHeaderAndStructuredDataCannotYieldPartialRecords(payload):
    """Truncated names, values, delimiters and header tokens refuse completely."""

    with pytest.raises(records.SyslogDecodeError):
        Decode(payload)
