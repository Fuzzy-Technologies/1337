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
    ParseRecord,
)
from fuzzy1337.jobs import JobProvider
from fuzzy1337.page_capture import LocalPageCaptureProvider, PageCaptureLimits
from fuzzy1337.page_capture_worker import ParseHeaders
from tests.contract.page_capture_fixture import Body, Oracle, Wire


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
            "limits", "frontier_limits", "clock",
        )
    ), (
        'Expected invariant: tuple(signature.parameters) == ( "workspace_root", '
        '"source", "expected_body", "scope_id", "policy", "limits", '
        '"frontier_limits", "clock", )'
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


@pytest.mark.parametrize("charset", [False, True])
@pytest.mark.parametrize("count", range(2, 65))
def test_EveryExactMinimumHeaderSizeHasAValidIndependentWireAndParentRecord(charset, count):
    """Hand-derived minimum feasibility bounds admit all 126 distinct header-count profiles."""

    # One-byte names are case-insensitively distinct across the token alphabet.
    names = "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
    extras = [names[index].encode() if index < len(names) else f"X{index - len(names):x}".encode()
              for index in range(count - 2)]
    raw = (b"HTTP/1.1 200 \r\nContent-Length:541\r\nContent-Type:text/html" +
           (b";charset=utf-8" if charset else b"") + b"\r\n" +
           b"".join(name + b":\r\n" for name in extras) + b"\r\n")
    metadata = ParseHeaders(raw, 541, 541)
    url = "http://127.0.0.1:32123/docs/index"
    record = {"schema_version": 1, "fixture_id": FIXTURE_ID, "url": url,
        "address": "127.0.0.1", "port": 32123, "scheme": "http", **metadata,
        "body_sha256": FIXTURE_SHA256, "body_base64": base64.b64encode(Body()).decode()}
    jsonschema.validate(record, Schema())
    assert (
        ParseRecord(CanonicalRecord(record), url,
                           KnownSyntheticHtmlBody(FIXTURE_ID), 541) == record
    ), (
        'Expected invariant: ParseRecord(CanonicalRecord(record), url, '
        'KnownSyntheticHtmlBody(FIXTURE_ID), 541) == record'
    )
    assert (
        metadata["header_count"] == count
    ), (
        'Expected invariant: metadata["header_count"] == count'
    )
    minimum = 61 + (14 if charset else 0) + 4 * (count - 2) + max(0, count - 53)
    assert len(raw) == minimum, "Independent field names do not meet exact minimum header length"


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
