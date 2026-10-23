# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic native predicate, exact-input and original-report refusal boundaries."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.adapters.native_web import (
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_CHECK_ID,
    CanonicalRecord,
    MatchesGitHead,
    NativeWebAdapter,
    NativeWebEndpoint,
    NativeWebRecordError,
    ParseNativeWebRecord,
)

URL = "http://127.0.0.1:8080/.git/HEAD"
BODY = b"ref: refs/heads/owned\n"


def Record() -> dict[str, object]:
    """Construct a synthetic fixed worker record, never native transport acceptance."""

    return {"schema_version": 1, "check_id": NATIVE_WEB_CHECK_ID, "profile_version": "1",
            "url": URL, "address": "127.0.0.1", "port": 8080, "scheme": "http",
            "status": 200, "media_type": "text/plain", "body_bytes": len(BODY),
            "body_sha256": hashlib.sha256(BODY).hexdigest(), "matched": True}


def Report(raw: bytes | None = None, stderr: bytes = b""):
    """Bind exact synthetic streams to the actual adapter invocation and immutable references."""

    output = CanonicalRecord(Record()) if raw is None else raw
    streams = {"stdout": output, "stderr": stderr}
    adapter = NativeWebAdapter(lambda reference: streams[reference.role])
    invocation = adapter.PrepareInvocation(AdapterRequest(NATIVE_WEB_CAPABILITY,
        NativeWebEndpoint(URL)[0].Reference(), ImpactLevel.STANDARD,
        {"url": URL, "timeout_seconds": 3.0}))
    references = tuple(EvidenceReference(role, "blobs/" + role,
        hashlib.sha256(value).hexdigest(), "application/octet-stream", len(value))
        for role, value in streams.items())

    return adapter, AdapterReport(invocation,
        AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1), references)


@pytest.mark.parametrize("body", [
    b"ref: refs/heads/a", b"ref: refs/heads/a\n", b"ref: refs/heads/a\r\n",
    b"ref: refs/heads/a/b-c_d0\n", b"ref: refs/heads/" + b"a" * 64,
    b"ref: refs/heads/" + b"/".join([b"a" * 64] * 8) + b"\r\n",
])
def test_CompleteSupportedHeadGrammarMatches(body: bytes) -> None:
    """The native predicate supports only its complete finite symbolic-reference grammar."""

    assert MatchesGitHead(200, "text/plain", body), "Supported complete reference was rejected."
    assert MatchesGitHead(200, "application/octet-stream", body), "Octet-stream is supported."


@pytest.mark.parametrize("body", [
    b"", b"ref: refs/heads/a\ntrailing", b"prefix ref: refs/heads/a", b"ref: refs/heads/a\r",
    b"ref: refs/tags/a\n", b"ref: refs/heads/.a\n", b"ref: refs/heads/a.b\n",
    b"ref: refs/heads/" + b"a" * 65, b"ref: refs/heads/" + b"/".join([b"a"] * 9),
    b"ref: refs/heads/\xff", b"ref: refs/heads/a\n\n", b"a" * 4097,
])
def test_PartialDecoyAndUnsupportedHeadFormsNeverMatch(body: bytes) -> None:
    """Partial references, valid-but-unsupported forms and excessive bodies are not positives."""

    assert not MatchesGitHead(200, "text/plain", body), "Unsupported HEAD became a positive."


@pytest.mark.parametrize("status,media", [(403, "text/plain"), (302, "text/plain"),
                                        (500, "text/plain"), (200, "other"), (True, "text/plain")])
def test_StatusAndMediaArePartOfTheWholePredicate(status: int, media: str) -> None:
    """A matching body alone cannot establish the declared response exposure profile."""

    assert not MatchesGitHead(status, media, BODY), "Status/media guards were bypassed."


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:80/x", "http://127.0.0.1", "http://127.0.0.1/x?",
    "http://127.0.0.1/x?a=b", "http://example.test/x", "http://127.0.0.1/x#f",
    "http://u:p@127.0.0.1/x", "http://127.0.0.1/x\\y", "http://127.0.0.1/x\r\ny",
    "http://0.0.0.0/x", "http://127.0.0.1/%0a", "http://127.0.0.1/%2F",
])
def test_UnsupportedOrChangedDestinationSpellingRejects(url: str) -> None:
    """Destination preparation never silently rewrites operator-selected input."""

    with pytest.raises(ValueError):
        NativeWebEndpoint(url)


@pytest.mark.parametrize("raw", [b"", b"x" * 4097, b"[]\n", b"null\n", b"\xff",
    b'{"schema_version":1,"schema_version":1,"error":"input"}\n',
    b'{"error":"input","schema_version":1}', b'{"error":"input","schema_version":true}\n',
    b'{"error":"input","schema_version":NaN}\n'])
def test_OriginalRecordsRequireCanonicalUniqueFiniteJson(raw: bytes) -> None:
    """Ambiguous or malformed original metadata cannot enter normalized model state."""

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(raw, URL)


@pytest.mark.parametrize("field,value", [
    ("check_id", "other"), ("profile_version", 1), ("url", URL + "/"),
    ("address", "127.0.0.2"), ("port", True), ("scheme", "https"), ("status", 500),
    ("status", True), ("body_bytes", True), ("body_bytes", 4097), ("body_bytes", -1),
    ("media_type", []), ("media_type", "private-detail"), ("body_sha256", "A" * 64),
    ("body_sha256", 1), ("matched", 1), ("schema_version", False),
    ("body_bytes", 16), ("body_bytes", 538), ("status", 403), ("media_type", "other"),
])
def test_RecordDimensionsAndExactInvocationCannotDrift(field: str, value: object) -> None:
    """Typed dimensions and a positive's necessary status/media/size facts fail closed."""

    record = Record()
    record[field] = value

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(CanonicalRecord(record), URL)


def test_FixedFailuresAndEmptyUnmatchedResponsesHaveExactShapes() -> None:
    """Fixed errors remain errors, while zero-body metadata still binds the empty digest."""

    assert ParseNativeWebRecord(CanonicalRecord({"schema_version": 1, "error": "input"}),
                                URL)["error"] == "input", "Fixed safe error was lost."
    record = Record()
    record.update(matched=False, body_bytes=0, body_sha256=hashlib.sha256(b"").hexdigest())
    assert ParseNativeWebRecord(CanonicalRecord(record), URL) == record, "Empty metadata drifted."
    record["body_sha256"] = "0" * 64

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(CanonicalRecord(record), URL)

    for error in ("private-detail", 1):
        with pytest.raises(NativeWebRecordError):
            ParseNativeWebRecord(CanonicalRecord({"schema_version": 1, "error": error}), URL)


def test_AdapterPreparesOneStandardWorkerAndVerifiesBothOriginalStreams() -> None:
    """The first-party provider is packaged and requires the exact STANDARD request shape."""

    adapter, report = Report()
    result = adapter.NormalizeReport(report)
    assert len(result.findings) == 1, "Verified synthetic positive did not produce one envelope."
    assert result.observations[0].attributes["matched"] is True, "Predicate attribution was lost."
    assert adapter.CheckHealth().provider_version == "1", "Packaged provider version drifted."
    assert report.invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.native_web_worker"), (
        "Native worker execution must isolate Python from workspace package shadowing."
    )

    record = Record()
    record["matched"] = False
    adapter, report = Report(CanonicalRecord(record))
    assert adapter.NormalizeReport(report).findings == (), "A negative created a Finding."


@pytest.mark.parametrize("change", ["impact", "capability", "credentials", "parameters",
                                     "target"])
def test_AdapterPreparationCannotAddAuthorityOrHiddenInputs(change: str) -> None:
    """Unsupported capabilities, credential material and destination joins fail pre-execution."""

    adapter, report = Report()
    request = report.invocation.request
    values = {"impact": ImpactLevel.SAFE, "capability": "other", "credential_references": ("x",),
              "parameters": {"url": URL}, "target_reference": "target:other"}
    field = {"credentials": "credential_references", "target": "target_reference"}.get(
        change, change)

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(replace(request, **{field: values[field]}))


@pytest.mark.parametrize("change", ["invocation", "execution", "references", "size", "hash",
                                     "stderr", "error"])
def test_AdapterRejectsUnverifiedOrFailedOriginalReports(change: str) -> None:
    """Only successful exact original execution streams can become native observations."""

    adapter, report = Report()

    if change == "invocation":
        report = replace(report, invocation=replace(report.invocation, provider_version="other"))

    elif change == "execution":
        report = replace(report, execution=AdapterExecution(ExecutionState.FAILED, 1, 0.1))

    elif change == "references":
        report = replace(report, evidence=report.evidence[:1])

    elif change in {"size", "hash"}:
        reference = replace(report.evidence[0], **({"size_bytes": 4097} if change == "size"
                                                 else {"sha256": "0" * 64}))
        report = replace(report, evidence=(reference, report.evidence[1]))

    elif change == "stderr":
        adapter, report = Report(stderr=b"untrusted-text")

    else:
        adapter, report = Report(CanonicalRecord({"schema_version": 1, "error": "protocol"}))

    with pytest.raises(NativeWebRecordError):
        adapter.NormalizeReport(report)


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}")])
def test_OriginalReportReaderRequiresExactBytes(raw: object) -> None:
    """Text, mutable buffers and absent data cannot impersonate immutable original bytes."""

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(raw, URL)


@pytest.mark.parametrize("change", ["extra", "missing", "error-detail"])
def test_OriginalRecordCannotAddFieldsOrHideRequiredFacts(change: str) -> None:
    """The admitted fixed report grammar refuses extensions as well as incomplete records."""

    record = Record()

    if change == "extra":
        record["raw_body"] = "synthetic-private-response"

    elif change == "missing":
        del record["body_sha256"]

    else:
        record = {"schema_version": 1, "error": "input", "detail": "synthetic-private-detail"}

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(CanonicalRecord(record), URL)


@pytest.mark.parametrize("timeout", [False, 0, float("inf"), float("nan"), 10.01])
def test_AdapterRejectsUnboundedRequestDeadlinesBeforeInvocation(timeout: object) -> None:
    """Only a finite positive approved deadline may enter the worker's explicit argv."""

    adapter, report = Report()

    with pytest.raises(ValueError):
        request = replace(report.invocation.request, parameters={"url": URL,
                                                               "timeout_seconds": timeout})
        adapter.PrepareInvocation(request)


@pytest.mark.parametrize("change", ["role-order", "wrong-role", "short-read", "mutable-read"])
def test_OriginalStreamRolesAndReaderResultsRemainAuthoritative(change: str) -> None:
    """Two references alone are insufficient without role, length and immutable-byte integrity."""

    adapter, report = Report()

    if change == "role-order":
        report = replace(report, evidence=tuple(reversed(report.evidence)))

    elif change == "wrong-role":
        report = replace(report, evidence=(report.evidence[0],
                                           replace(report.evidence[1], role="diagnostic")))

    elif change == "short-read":
        adapter = NativeWebAdapter(lambda reference: b"")

    else:
        raw = CanonicalRecord(Record())
        adapter = NativeWebAdapter(lambda reference: bytearray(raw)
                                   if reference.role == "stdout" else b"")

    with pytest.raises(NativeWebRecordError):
        adapter.NormalizeReport(report)


def test_DescriptorRequiresOnlyItsDeclaredStandardCheck() -> None:
    """Packaged availability never lowers the capability's explicit STANDARD impact."""

    adapter, _ = Report()
    assert adapter.Descriptor.capabilities == (NATIVE_WEB_CAPABILITY,), (
        "The native descriptor silently added a hidden execution capability."
    )
    assert adapter.Descriptor.maximum_impact is ImpactLevel.STANDARD, (
        "The native web check unexpectedly lowered its explicit confirmation boundary."
    )
