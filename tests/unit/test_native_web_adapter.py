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
    NATIVE_FILE_CANARY_CAPABILITY,
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_FILE_CANARY_PROFILE,
    NATIVE_PROMETHEUS_CAPABILITY,
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_CHECK_ID,
    CanonicalRecord,
    MatchesFileCanary,
    MatchesGitHead,
    NativeFileCanaryTemplate,
    NativeWebAdapter,
    NativeWebCheckFor,
    NativeWebEndpoint,
    NativeWebParameters,
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


def test_DescriptorRequiresOnlyItsDeclaredStandardChecks() -> None:
    """Packaged availability never lowers the capability's explicit STANDARD impact."""

    adapter, _ = Report()
    assert adapter.Descriptor.capabilities == (
        NATIVE_WEB_CAPABILITY, NATIVE_FILE_CANARY_CAPABILITY, NATIVE_PROMETHEUS_CAPABILITY,
    ), (
        "The native descriptor silently added a hidden execution capability."
    )
    assert adapter.Descriptor.maximum_impact is ImpactLevel.STANDARD, (
        "The native web check unexpectedly lowered its explicit confirmation boundary."
    )


@pytest.mark.parametrize("value", [
    "http://127.0.0.1:8080/files/vulnerable?name=hello.txt",
    "http://127.0.0.2:8080/files/fixed?name=..%2Fprivate%2Fcanary.txt",
    "http://[::1]:8080/files/decoy?name=..%2Fprivate%2Fmissing.txt",
])
def test_CanaryEndpointAdmitsOnlyTheOwnedLoopbackPack(value: str) -> None:
    """The explicit closed file profile retains its exact path/query and refuses default Git use."""

    target, _, _, _ = NativeWebEndpoint(value, check_id=NATIVE_FILE_CANARY_CHECK_ID)
    assert target.value == value, "The closed native request rewrote its selected wire input."

    with pytest.raises(ValueError):
        NativeWebEndpoint(value)


@pytest.mark.parametrize("value", [
    "http://192.0.2.1/files/vulnerable?name=hello.txt",
    "http://10.0.0.1/files/vulnerable?name=hello.txt",
    "http://localhost/files/vulnerable?name=hello.txt",
    "http://127.0.0.1/other?name=hello.txt",
    "http://127.0.0.1/files/vulnerable?other=hello.txt",
    "http://127.0.0.1/files/vulnerable?name=hello.txt&name=hello.txt",
    "http://127.0.0.1/files/vulnerable?name=hello.txt&other=hello.txt",
    "http://127.0.0.1/files/vulnerable?name=..%2fprivate%2fcanary.txt",
    "http://127.0.0.1/files/vulnerable?name=..%252Fprivate%252Fcanary.txt",
    "http://127.0.0.1/files/vulnerable?name=../private/canary.txt",
    "http://127.0.0.1/files/vulnerable?name=hello+txt",
    "http://user:password@127.0.0.1/files/vulnerable?name=hello.txt",
])
def test_CanaryRefusesRemoteOrUnreviewedRequestsBeforeTransport(value: str) -> None:
    """Only the literal loopback pack and exact finite query spelling enter preparation."""

    with pytest.raises(ValueError):
        NativeWebEndpoint(value, check_id=NATIVE_FILE_CANARY_CHECK_ID)


@pytest.mark.parametrize("status,media,body,matched", [
    (200, "text/plain", b"owned-private-file-canary\n", True),
    (200, "application/octet-stream", b"owned-private-file-canary\n", True),
    (200, "other", b"owned-private-file-canary\n", False),
    (403, "text/plain", b"owned-private-file-canary\n", False),
    (200, "text/plain", b"prefix-owned-private-file-canary\n", False),
    (200, "text/plain", b"owned-private-file-canary\nsuffix", False),
    (200, "text/plain", b"owned-public-file\n", False),
])
def test_CanaryPredicateRequiresCompleteOwnedBytes(status, media, body, matched) -> None:
    """A fixed exact non-secret response determines the result independently of route labels."""

    assert MatchesFileCanary(status, media, body) is matched, "Closed canary predicate drifted."


def test_CanaryInvocationBindsItsAnonymousStructuralRequest() -> None:
    """The exact template, coordinate, profile and workspace enter the original intent."""

    url = "http://127.0.0.1:8080/files/vulnerable?name=hello.txt"
    parameters = NativeWebParameters(url, 1.0, check_id=NATIVE_FILE_CANARY_CHECK_ID,
                                     workspace_id="owned-canary")
    adapter = NativeWebAdapter(lambda _: b"")
    request = AdapterRequest(NATIVE_FILE_CANARY_CAPABILITY,
        NativeWebEndpoint(url, check_id=NATIVE_FILE_CANARY_CHECK_ID)[0].Reference(),
        ImpactLevel.STANDARD, parameters)
    invocation = adapter.PrepareInvocation(request)
    assert invocation.argv[-4:] == (url, "1.0", NATIVE_FILE_CANARY_CHECK_ID, "owned-canary"), (
        "The worker lost its exact selected local URL/check/workspace binding."
    )
    assert parameters["request_profile"] == NATIVE_FILE_CANARY_PROFILE, "Request profile changed."
    assert "owned-private-file-canary" not in CanonicalRecord(parameters).decode(), (
        "Concrete response bytes entered structural execution metadata."
    )

    for field in ("check_id", "request_profile", "injection_reference"):
        altered = dict(parameters)
        altered[field] = "unreviewed"

        with pytest.raises(ValueError):
            adapter.PrepareInvocation(replace(request, parameters=altered))


def CanaryRecord() -> tuple[str, dict[str, object]]:
    """Create fixed synthetic metadata for parser-boundary tests without any target contact."""

    url = "http://127.0.0.1:8080/files/vulnerable?name=..%2Fprivate%2Fcanary.txt"
    template = NativeFileCanaryTemplate("owned-canary", url)
    body = b"owned-private-file-canary\n"

    return url, {"schema_version": 1, "check_id": NATIVE_FILE_CANARY_CHECK_ID,
        "profile_version": "1", "url": url, "address": "127.0.0.1", "port": 8080,
        "scheme": "http", "status": 200, "media_type": "text/plain",
        "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(), "matched": True,
        "request_profile": NATIVE_FILE_CANARY_PROFILE, "request_reference": template.Reference(),
        "injection_reference": template.injection_points[0].Reference(template.Reference())}


def test_CanaryRecordRequiresTheOriginalCheckAndWorkspace() -> None:
    """The fixed original report is accepted only in its exact selected structural partition."""

    url, record = CanaryRecord()
    raw = CanonicalRecord(record)
    assert ParseNativeWebRecord(raw, url, check_id=NATIVE_FILE_CANARY_CHECK_ID,
                               workspace_id="owned-canary") == record, (
        "A canonical declared owned-canary report lost its exact original bindings."
    )

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(raw, url)

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(raw, url, check_id=NATIVE_FILE_CANARY_CHECK_ID, workspace_id="other")


@pytest.mark.parametrize("field,value", [
    ("request_profile", "other"), ("request_reference", "other"),
    ("injection_reference", "other"), ("check_id", NATIVE_WEB_CHECK_ID),
    ("body_bytes", 25), ("body_sha256", "0" * 64), ("matched", False),
])
def test_CanaryRecordRejectsForgedBindingsAndPredicateFacts(field, value) -> None:
    """Original-check references and complete canary digest/length facts cannot be substituted."""

    url, record = CanaryRecord()
    record[field] = value

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(CanonicalRecord(record), url, check_id=NATIVE_FILE_CANARY_CHECK_ID,
                             workspace_id="owned-canary")


def PrometheusReport(*, body_bytes=5000, matched=True):
    """Construct exact synthetic original metrics metadata without claiming an actual HTTP scan."""

    url = "http://127.0.0.1:8080/metrics"
    record = {**Record(), "check_id": NATIVE_PROMETHEUS_CHECK_ID, "url": url,
              "body_bytes": body_bytes, "matched": matched}
    raw = CanonicalRecord(record)
    streams = {"stdout": raw, "stderr": b""}
    adapter = NativeWebAdapter(lambda reference: streams[reference.role])
    request = AdapterRequest(NATIVE_PROMETHEUS_CAPABILITY,
        NativeWebEndpoint(url, check_id=NATIVE_PROMETHEUS_CHECK_ID)[0].Reference(),
        ImpactLevel.STANDARD, NativeWebParameters(url, 1.0, check_id=NATIVE_PROMETHEUS_CHECK_ID))
    invocation = adapter.PrepareInvocation(request)
    references = tuple(EvidenceReference(role, "blobs/" + role, hashlib.sha256(value).hexdigest(),
        "application/octet-stream", len(value)) for role, value in streams.items())

    return adapter, AdapterReport(invocation,
        AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1), references)


def test_PrometheusSelectionBindsExactNewCheckWithoutChangingGitDefault():
    """The additive capability cannot be selected implicitly through a Git invocation."""

    adapter, report = PrometheusReport()
    assert report.invocation.argv[-3:] == (
        "http://127.0.0.1:8080/metrics", "1.0", NATIVE_PROMETHEUS_CHECK_ID,
    ), "The metrics process lost its exact explicit check identity."
    assert set(report.invocation.request.parameters) == {"url", "timeout_seconds", "check_id"}, (
        "Metrics intent gained unrelated request/session parameters."
    )
    assert NativeWebParameters(URL, 1.0) == {"url": URL, "timeout_seconds": 1.0}, (
        "Existing Git invocation parameters changed."
    )
    assert NativeWebCheckFor(NATIVE_WEB_CHECK_ID).max_body_bytes == 4096, "Git cap widened."
    assert NativeWebCheckFor(NATIVE_FILE_CANARY_CHECK_ID).max_body_bytes == 4096, (
        "Canary cap widened."
    )
    assert NativeWebCheckFor(NATIVE_PROMETHEUS_CHECK_ID).max_body_bytes == 262144, (
        "Metrics body cap differs from its declared contract."
    )

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(replace(report.invocation.request,
                                          capability=NATIVE_WEB_CAPABILITY))

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(replace(report.invocation.request, parameters={
            "url": "http://127.0.0.1:8080/metrics", "timeout_seconds": 1.0,
        }))


@pytest.mark.parametrize("body_bytes", [4097, 262144])
def test_OriginalMetricsRecordsUseTheirOwnCapAndDescriptiveFinding(body_bytes):
    """Metadata attests the larger profile without reconstructing absent response bytes."""

    adapter, report = PrometheusReport(body_bytes=body_bytes)
    result = adapter.NormalizeReport(report)
    assert result.findings[0].kind == "prometheus-exposition", "Finding identity drifted."
    assert result.findings[0].attributes == {
        "check_id": NATIVE_PROMETHEUS_CHECK_ID, "severity": "low",
    }, "A metrics exposure claimed unsupported severity or exploitability."
    assert result.observations[0].attributes["body_bytes"] == body_bytes, "Body cap drifted."


@pytest.mark.parametrize("key,value", [("body_bytes", 262145), ("body_bytes", -1),
    ("status", 403), ("media_type", "application/octet-stream"), ("body_bytes", 0),
    ("check_id", NATIVE_WEB_CHECK_ID), ("profile_version", "2")])
def test_MetricsReplayRefusesForeignOrImpossiblePositiveFacts(key, value):
    """A positive record must bind its original check/version and possible response dimensions."""

    _, report = PrometheusReport()
    record = {**Record(), "check_id": NATIVE_PROMETHEUS_CHECK_ID,
              "url": "http://127.0.0.1:8080/metrics", "body_bytes": 5000, key: value}

    with pytest.raises(NativeWebRecordError):
        ParseNativeWebRecord(CanonicalRecord(record),
                             str(report.invocation.request.parameters["url"]),
                             check_id=NATIVE_PROMETHEUS_CHECK_ID)
