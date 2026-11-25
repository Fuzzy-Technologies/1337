# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed acquisition ABI/schema, independent fixture identities and parser/wire feasibility."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.adapters import ToolAdapter
from fuzzy1337.adapters.page_capture import (
    ERROR_EXITS,
    FIXTURE_ID,
    FIXTURE_SHA256,
    CanonicalRecord,
    KnownSyntheticHtmlBody,
    NativeLoopbackPageAdapter,
    PageCaptureRecordError,
    PageRenderer,
    ParseRecord,
)
from fuzzy1337.jobs import JobProvider
from fuzzy1337.page_capture import LocalPageCaptureProvider, PageCaptureLimits
from fuzzy1337.page_capture_worker import PageProtocolError, ParseHeaders
from tests.contract.page_capture_fixture import Body, Oracle, Wire

MINIMUM_HEADER_URL = "http://127.0.0.1:32123/docs/index"


def Schema() -> dict:
    """Load the checked-in worker record schema without importing provider/runtime plugins."""

    path = Path(__file__).resolve().parents[2] / "contracts" / "page-capture-record.schema.json"

    return json.loads(path.read_bytes())


def test_IndependentBodyWireAndHandOracleRemainExactlyPinned():
    """No producer-generated oracle can mask drift in the accepted 541-byte body or raw wire."""

    oracle = Oracle()

    for data, name in ((Body(), "body"), (Wire(), "wire")):
        assert (
            len(data) == oracle[name]["size_bytes"]
        ), (
            'Expected invariant: len(data) == oracle[name]["size_bytes"]'
        )
        assert (
            hashlib.sha256(data).hexdigest() == oracle[name]["sha256"]
        ), (
            'Expected invariant: hashlib.sha256(data).hexdigest() == '
            'oracle[name]["sha256"]'
        )

    header, body = Wire().split(b"\r\n\r\n", 1)
    assert (
        body == Body() and b"\r" not in body
    ), (
        'Expected invariant: body == Body() and b"\\r" not in body'
    )
    assert (
        len(header) + 4 == oracle["wire"]["header_size_bytes"]
    ), (
        'Expected invariant: len(header) + 4 == '
        'oracle["wire"]["header_size_bytes"]'
    )
    assert (
        header.count(b"\r\n") == oracle["wire"]["header_count"]
    ), (
        'Expected invariant: header.count(b"\\r\\n") == '
        'oracle["wire"]["header_count"]'
    )
    assert (
        KnownSyntheticHtmlBody(oracle["fixture_id"]).sha256 == FIXTURE_SHA256
    ), (
        'Expected invariant: KnownSyntheticHtmlBody(oracle["fixture_id"]).sha256 '
        '== FIXTURE_SHA256'
    )


def test_PublicShapesMatchOnlyTheAcceptedExperimentalConsumer():
    """One provider/adapter and finite records add no launch, registry or arbitrary-body API."""

    signature = inspect.signature(LocalPageCaptureProvider)
    assert (
        tuple(signature.parameters) == (
            "workspace_root", "source", "expected_body", "scope_id", "policy",
            "limits", "frontier_limits", "clock", "renderer",
        )
    ), (
        'Expected invariant: tuple(signature.parameters) == ( "workspace_root", '
        '"source", "expected_body", "scope_id", "policy", "limits", '
        '"frontier_limits", "clock", "renderer", )'
    )
    assert signature.parameters["renderer"].kind is inspect.Parameter.KEYWORD_ONLY, (
        "The browser selection changed existing positional constructor compatibility."
    )
    assert signature.parameters["renderer"].default is PageRenderer.NATIVE, (
        "The additive browser selection changed the existing native default."
    )
    assert (
        isinstance(NativeLoopbackPageAdapter(lambda _: b""), ToolAdapter)
    ), (
        'Expected invariant: isinstance(NativeLoopbackPageAdapter(lambda _: b""), '
        'ToolAdapter)'
    )
    assert (
        tuple(inspect.signature(LocalPageCaptureProvider.Run).parameters) == tuple(
            inspect.signature(JobProvider.Run).parameters
        )
    ), (
        'Expected invariant: '
        'tuple(inspect.signature(LocalPageCaptureProvider.Run).parameters) == '
        'tuple( inspect.signature(JobProvider.Run).parameters )'
    )
    assert (
        inspect.signature(KnownSyntheticHtmlBody).parameters["fixture_id"].default is (
            inspect.Parameter.empty
        )
    ), (
        'Expected invariant: '
        'inspect.signature(KnownSyntheticHtmlBody).parameters["fixture_id"].default '
        'is ( inspect.Parameter.empty )'
    )
    assert (
        PageCaptureLimits().max_body_bytes == 16384
    ), (
        'Expected invariant: PageCaptureLimits().max_body_bytes == 16384'
    )
    assert (
        inspect.iscoroutinefunction(LocalPageCaptureProvider.Run)
    ), (
        'Expected invariant: '
        'inspect.iscoroutinefunction(LocalPageCaptureProvider.Run)'
    )


def MinimumHeaderWire(charset: bool, count: int) -> bytes:
    """Build independent shortest fields, crossing from one-byte to two-byte names at count 54."""

    # One-byte names are case-insensitively distinct across the token alphabet.
    names = "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
    extras = [names[index].encode() if index < len(names) else f"X{index - len(names):x}".encode()
              for index in range(count - 2)]

    return (b"HTTP/1.1 200 \r\nContent-Length:541\r\nContent-Type:text/html" +
            (b";charset=utf-8" if charset else b"") + b"\r\n" +
            b"".join(name + b":\r\n" for name in extras) + b"\r\n")


def MinimumHeaderRecord(charset: bool, count: int) -> dict:
    """Use the actual pure header parser to populate one independently authored parent record."""

    raw = MinimumHeaderWire(charset, count)
    metadata = ParseHeaders(raw, 541, 541)

    return {"schema_version": 1, "fixture_id": FIXTURE_ID, "url": MINIMUM_HEADER_URL,
        "address": "127.0.0.1", "port": 32123, "scheme": "http", **metadata,
        "body_sha256": FIXTURE_SHA256, "body_base64": base64.b64encode(Body()).decode()}


@pytest.mark.parametrize("charset", [False, True], ids=["no-charset", "utf8"])
@pytest.mark.parametrize("count", [
    pytest.param(2, id="minimum"), pytest.param(3, id="first-extra"),
    pytest.param(52, id="before-name-width"), pytest.param(53, id="last-one-byte-name"),
    pytest.param(54, id="first-two-byte-name"), pytest.param(63, id="before-maximum"),
    pytest.param(64, id="maximum"),
])
def test_MinimumHeaderSizeClassesRetainExactWireAndParentFeasibility(charset, count):
    """Keep both charset classes, endpoints and token-width neighbors without interior repeats."""

    # Interior counts vary only the linear byte total; 53/54 is the sole name-width hinge.
    # Count 64 still includes every permitted one-byte token character used by the old matrix.
    raw = MinimumHeaderWire(charset, count)
    record = MinimumHeaderRecord(charset, count)
    jsonschema.validate(record, Schema())
    assert (
        ParseRecord(CanonicalRecord(record), MINIMUM_HEADER_URL,
                           KnownSyntheticHtmlBody(FIXTURE_ID), 541) == record
    ), (
        "The independent shortest wire must produce the exact admitted canonical parent record"
    )
    assert (
        record["header_count"] == count
    ), (
        "Measured field count must preserve this explicit feasibility boundary"
    )
    minimum = 61 + (14 if charset else 0) + 4 * (count - 2) + max(0, count - 53)
    assert len(raw) == minimum, "Independent field names do not meet exact minimum header length"

    with pytest.raises(PageCaptureRecordError, match="closed safe grammar"):
        ParseRecord(CanonicalRecord(dict(record, header_size_bytes=minimum - 1)),
                    MINIMUM_HEADER_URL, KnownSyntheticHtmlBody(FIXTURE_ID), 541)


@pytest.mark.parametrize("charset", [False, True], ids=["no-charset", "utf8"])
@pytest.mark.parametrize("count", [pytest.param(1, id="below-minimum"),
                                  pytest.param(65, id="above-maximum")])
def test_HeaderCountNeighborsRefuseInWorkerSchemaAndParent(charset, count):
    """One missing required field or the first excessive field cannot enter a successful record."""

    record = dict(MinimumHeaderRecord(charset, 2), header_count=count,
                  header_size_bytes=len(MinimumHeaderWire(charset, max(2, count))))

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, Schema())

    with pytest.raises(PageCaptureRecordError, match="closed safe grammar"):
        ParseRecord(CanonicalRecord(record), MINIMUM_HEADER_URL,
                    KnownSyntheticHtmlBody(FIXTURE_ID), 541)

    raw = MinimumHeaderWire(charset, count) if count == 65 else (
        b"HTTP/1.1 200 \r\nContent-Length:541\r\n\r\n")
    reason = "excessive field count" if count == 65 else "bounded header lines"

    with pytest.raises(PageProtocolError, match=reason):
        ParseHeaders(raw, 541, 541)


@pytest.mark.parametrize("error", ERROR_EXITS)
def test_FixedFailureRecordsSatisfyTheClosedOwnedSchema(error):
    """A closed failure has exactly two scalar fields and never body/response metadata."""

    jsonschema.validate({"schema_version": 1, "error": error}, Schema())


@pytest.mark.parametrize("record", [
    {"schema_version": True, "error": "input"},
    {"schema_version": 1, "error": "unknown"},
    {"schema_version": 1, "error": "protocol", "header": "synthetic-secret-marker"},
    {"schema_version": 1},
])
def test_SchemaAndParentRejectUnsupportedFailureCopies(record):
    """Boolean schema equality, unknown codes and extra raw fields are not valid records."""

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, Schema())

    with pytest.raises(PageCaptureRecordError):
        ParseRecord(CanonicalRecord(record), "http://127.0.0.1/",
                    KnownSyntheticHtmlBody(FIXTURE_ID), 16384)
