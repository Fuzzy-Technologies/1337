# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Network-free closed acquisition inputs, worker grammar and adapter normalization probes."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import socket
import sys
from collections.abc import Iterator
from dataclasses import replace
from types import MappingProxyType

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    ToolAdapter,
)
from fuzzy1337.adapters.page_capture import (
    ERROR_EXITS,
    FIXTURE_ID,
    FIXTURE_SHA256,
    MAX_RECORD_BYTES,
    PAGE_CAPTURE_CAPABILITY,
    PAGE_CAPTURE_PROVIDER_ID,
    CanonicalRecord,
    Destination,
    Execution,
    KnownBody,
    KnownSyntheticHtmlBody,
    NativeLoopbackPageAdapter,
    PageCaptureLimits,
    PageCaptureRecordError,
    ParseRecord,
)
from fuzzy1337.executors import LocalExecutionResult
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind, ExecutionTermination
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.jobs import (
    JobContext,
    JobEventKind,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
    ScanJob,
)
from fuzzy1337.model import LocalModelStore
from fuzzy1337.page_capture import (
    BoundedPageEvidenceStore,
    LocalPageCaptureProvider,
    ValidateResult,
)
from fuzzy1337.page_capture_worker import (
    Main,
    PageBodyPolicyError,
    PageProtocolError,
    PageResponsePolicyError,
    ParseHeaders,
    Probe,
    Remaining,
    WorkerInputs,
)
from fuzzy1337.policy import GovernedLocalExecutor
from fuzzy1337.scope import Target, TargetKind
from tests.contract.page_capture_fixture import NOW, Body, Fixture, Wire

URL = "http://127.0.0.1:32123/docs/index"


@pytest.fixture(scope="module")
def owned_page_runner() -> Iterator[asyncio.Runner]:
    """Initialize the owned Windows loop self-pipe before the unit network guard."""

    with asyncio.Runner() as runner:
        yield runner


@pytest.fixture
def page_runner(owned_page_runner: asyncio.Runner) -> Iterator[asyncio.Runner]:
    """Reuse the initialized loop and reap tasks at every isolated test boundary."""

    yield owned_page_runner

    async def Cleanup() -> None:
        """Cancel and reap any remaining test-owned tasks without opening another loop."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_page_runner.run(Cleanup())


def RunJob(job: ScanJob, runner: asyncio.Runner) -> JobSnapshot:
    """Use the actual job lifecycle on an already initialized, network-guarded loop."""

    async def StartAndWait() -> JobSnapshot:
        """Start and await the terminal owning job state without a provider bypass."""

        job.Start()

        return await job.Wait()

    return runner.run(StartAndWait())


def test_PageRunnerPreservesNetworkDenial(page_runner, monkeypatch):
    """Loop reuse leaves provider connections denied and never creates a lazy Windows loop."""

    def ReopenLoop():
        """Reject new event-loop construction inside the guarded unit-test phase."""

        raise AssertionError("Guarded page tests must reuse their initialized event loop")

    monkeypatch.setattr(asyncio.events, "new_event_loop", ReopenLoop)

    async def CheckConnections():
        """Exercise every unchanged unit connection guard from the running owned loop."""

        with socket.socket() as connection:
            for callback in (connection.connect, connection.connect_ex, socket.create_connection):
                with pytest.raises(RuntimeError, match="Unit tests must not access the network"):
                    callback(("127.0.0.1", 9))

    page_runner.run(CheckConnections())


def Request(**changes):
    """Create an exact legitimate anonymous acquisition request for isolated tests."""

    fields = {"url": URL, "timeout_seconds": 2.0,
              "fixture_id": FIXTURE_ID, "max_body_bytes": 16384, **changes}

    return AdapterRequest(PAGE_CAPTURE_CAPABILITY, Target(TargetKind.URL, URL).Reference(),
                          ImpactLevel.SAFE, fields)


def Record(**changes):
    """Use independent wire expectations for an isolated canonical successful worker record."""

    return {"schema_version": 1, "fixture_id": FIXTURE_ID, "url": URL, "address": "127.0.0.1",
        "port": 32123, "scheme": "http", "http_version": "HTTP/1.1", "status": 200,
        "content_type": "text/html", "declared_charset": "utf-8", "content_length": 541,
        "header_size_bytes": 252, "header_count": 7, "body_sha256": FIXTURE_SHA256,
        "body_base64": base64.b64encode(Body()).decode("ascii"), **changes}


def Adapter(raw: bytes = b"") -> NativeLoopbackPageAdapter:
    """Bind a deterministic in-memory evidence reader without files or networking."""

    return NativeLoopbackPageAdapter(lambda _: raw)


def Report(raw: bytes):
    """Construct the exact report from known stdout with a real owning SHA reference."""

    sha = hashlib.sha256(raw).hexdigest()

    return AdapterReport(Adapter().PrepareInvocation(Request()),
        AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1),
        (EvidenceReference("stdout", "blobs/sha256/" + sha, sha, "application/json", len(raw)),))


class Connection:
    """Deterministic socket double retaining only supplied bounded synthetic wire input."""

    def __init__(self, raw: bytes, *, peer: str = "127.0.0.1", failure: Exception | None = None):
        """Keep finite fake response and exact observed connection/request metadata."""

        self.raw = raw
        self.peer = peer
        self.failure = failure
        self.request = b""
        self.connected = None
        self.closed = False
        self.read_sizes = []

    def __enter__(self):
        """Return the fake socket without transport."""

        return self

    def __exit__(self, *_):
        """Record guaranteed connection cleanup after success or parser failure."""

        self.closed = True

    def SetTimeout(self, value):
        """Require a positive phase budget, without delaying the test."""

        assert (
            value > 0
        ), (
            'Expected invariant: value > 0'
        )

    def Connect(self, address):
        """Record the exact supplied literal tuple, optionally failing before send."""

        if self.failure is not None:
            raise self.failure

        self.connected = address

    def GetPeerName(self):
        """Return the synthetic literal connected peer for independent identity validation."""

        return self.peer, 32123

    def SendAll(self, data):
        """Record the exact bytes without a second request or implicit headers."""

        self.request += data

    def Receive(self, maximum):
        """Respect each exact requested bounded read size and return EOF when exhausted."""

        self.read_sizes.append(maximum)
        piece, self.raw = self.raw[:maximum], self.raw[maximum:]

        return piece

    # The socket protocol owns these external callback names.
    settimeout = SetTimeout
    connect = Connect
    getpeername = GetPeerName
    sendall = SendAll
    recv = Receive


def Socket(monkeypatch, raw: bytes = Wire(), **kwargs):
    """Replace socket construction with one deterministic fake rather than network access."""

    connection = Connection(raw, **kwargs)
    constructions = []

    def Build(family, kind):
        """Record family/kind and return exactly the controlled single connection."""

        constructions.append((family, kind))

        return connection

    monkeypatch.setattr(socket, "socket", Build)

    return connection, constructions


def test_ClosedBodySelectionAndImmutableDerivedFields():
    """The catalog cannot admit arbitrary identifiers/digests or boolean-derived copies."""

    selected = KnownSyntheticHtmlBody(FIXTURE_ID)
    assert (
        selected.size_bytes == 541 and selected.sha256 == hashlib.sha256(Body()).hexdigest()
    ), (
        'Expected invariant: selected.size_bytes == 541 and selected.sha256 == '
        'hashlib.sha256(Body()).hexdigest()'
    )
    assert (
        KnownBody(selected) is selected
    ), (
        'Expected invariant: KnownBody(selected) is selected'
    )

    for field, value in (("fixture_id", "unknown"), ("sha256", "0" * 64),
                         ("size_bytes", True), ("size_bytes", 541.0)):
        copied = copy.copy(selected)
        object.__setattr__(copied, field, value)

        with pytest.raises(ValueError):
            KnownBody(copied)


@pytest.mark.parametrize("value", [None, True, 541, "", "unknown", "x" * 100000],
                         ids=["none", "boolean", "integer", "empty", "unknown", "oversized-id"])
def test_UnknownFixtureIdentifiersNeverBecomeDeclarations(value):
    """Only the explicitly supplied known ID selects non-secret allowed bytes."""

    with pytest.raises(ValueError):
        KnownSyntheticHtmlBody(value)


@pytest.mark.parametrize("field,value", [
    ("max_body_bytes", True), ("max_body_bytes", 0), ("max_body_bytes", 65537),
    ("request_timeout_seconds", True), ("request_timeout_seconds", 0.049),
    ("request_timeout_seconds", 5.001), ("request_timeout_seconds", float("nan")),
    ("request_timeout_seconds", float("inf")),
    pytest.param("request_timeout_seconds", 10 ** 10000, id="oversized-integer"),
    ("timeout_seconds", 15.001), ("timeout_seconds", 1), ("timeout_seconds", float("nan")),
])
def test_LimitsRejectCoercionsNonfiniteAndInconsistentBudgets(field, value):
    """Bounds reject before float conversion even for an already allocated huge integer."""

    with pytest.raises(ValueError):
        PageCaptureLimits(**{field: value})


def test_LimitsIncludeExactAcceptedEndpoints():
    """Hard numeric endpoints and an exact body quota remain admitted."""

    assert (
        PageCaptureLimits(1, 0.05, 1.05).max_body_bytes == 1
    ), (
        'Expected invariant: PageCaptureLimits(1, 0.05, 1.05).max_body_bytes == 1'
    )
    assert (
        PageCaptureLimits(65536, 5, 15).request_timeout_seconds == 5
    ), (
        'Expected invariant: PageCaptureLimits(65536, 5, '
        '15).request_timeout_seconds == 5'
    )


@pytest.mark.parametrize("url", [
    None, True, "", "http://localhost/docs/index", "https://127.0.0.1/docs/index",
    "http://127.0.0.2/docs/index", "http://[::ffff:127.0.0.1]/docs/index",
    "http://[::1%25eth0]/docs/index", "http://127.0.0.1", "http://127.0.0.1:80/docs/index",
    "http://127.0.0.1/docs/index?x=1", "http://127.0.0.1/docs/index#fragment",
    "http://user:pass@127.0.0.1/docs/index", "http://127.0.0.1/{field}",
    "http://127.0.0.1/%61", "http://127.0.0.1/with space", "http://127.0.0.1/a\\b",
    "http://127.0.0.1/\x00", "http://127.0.0.1/\x7f", "http://127.0.0.1/非",
    "http://127.0.0.1/" + "a" * 1025, "x" * 2049,
])
def test_DestinationRejectsNoncanonicalNamesPathsAndAliases(url):
    """Literal-loopback qualification never infers authority from aliases or source content."""

    with pytest.raises(ValueError):
        Destination(url)


def test_AdapterIsSeparateSafePreparationWithoutNetwork():
    """The exact interpreter/module/argv is prepared without native HTTP privilege reuse."""

    adapter = Adapter()
    invocation = adapter.PrepareInvocation(Request())
    assert (
        isinstance(adapter, ToolAdapter)
    ), (
        'Expected invariant: isinstance(adapter, ToolAdapter)'
    )
    assert (
        adapter.CheckHealth().state is AdapterHealthState.AVAILABLE
    ), (
        'Expected invariant: adapter.CheckHealth().state is '
        'AdapterHealthState.AVAILABLE'
    )
    assert (
        adapter.Descriptor.adapter_id == PAGE_CAPTURE_PROVIDER_ID
    ), (
        'Expected invariant: adapter.Descriptor.adapter_id == '
        'PAGE_CAPTURE_PROVIDER_ID'
    )
    assert (
        adapter.Descriptor.maximum_impact is ImpactLevel.SAFE
    ), (
        'Expected invariant: adapter.Descriptor.maximum_impact is '
        'ImpactLevel.SAFE'
    )
    assert (
        invocation.argv == (sys.executable, "-m", "fuzzy1337.page_capture_worker", URL,
                                   "2.0", FIXTURE_ID, "16384")
    ), (
        'Expected invariant: invocation.argv == (sys.executable, "-m", '
        '"fuzzy1337.page_capture_worker", URL, "2.0", FIXTURE_ID, "16384")'
    )
    assert (
        invocation.timeout_seconds == 3
    ), (
        'Expected invariant: invocation.timeout_seconds == 3'
    )
    assert (
        Destination("http://[::1]/docs/index")[1:4] == ("::1", 80, "/docs/index")
    ), (
        'Expected invariant: Destination("http://[::1]/docs/index")[1:4] == '
        '("::1", 80, "/docs/index")'
    )
    assert (
        Destination("http://127.0.0.1/")[2] == 80
    ), (
        'Expected invariant: Destination("http://127.0.0.1/")[2] == 80'
    )


@pytest.mark.parametrize("field,value", [
    ("capability", "http.endpoint-discovery"), ("impact", "SAFE"),
    ("target_reference", "url:http://127.0.0.1/other"),
    ("credential_references", ("credential:synthetic",)),
    ("parameters", MappingProxyType({"url": URL})),
    ("parameters", MappingProxyType({**Request().parameters, "extra": "value"})),
    ("parameters", {**Request().parameters}),
])
def test_AdapterRefusesForgedNestedRequestFields(field, value):
    """Equal enum/string copies and mutable request wrappers cannot bypass typed preparation."""

    request = copy.copy(Request())
    object.__setattr__(request, field, value)

    with pytest.raises(ValueError):
        Adapter().PrepareInvocation(request)


@pytest.mark.parametrize("changes", [{"fixture_id": True}, {"max_body_bytes": 540},
                                      {"timeout_seconds": 0.01}, {"url": "http://localhost/"}])
def test_AdapterRefusesInvalidClosedParameters(changes):
    """No operation is prepared for body limits smaller than the known body or invalid values."""

    with pytest.raises(ValueError):
        Adapter().PrepareInvocation(Request(**changes))


def test_IndependentWireParsesAndEmitsExactOneConnectionRequest(monkeypatch):
    """Original wire yields only the hand-declared normalized metadata and known body."""

    connection, constructions = Socket(monkeypatch)
    record = Probe(URL, 2.0, FIXTURE_ID, 16384)
    assert (
        record == Record()
    ), (
        'Expected invariant: record == Record()'
    )
    assert (
        constructions == [(socket.AF_INET, socket.SOCK_STREAM)]
    ), (
        'Expected invariant: constructions == [(socket.AF_INET, '
        'socket.SOCK_STREAM)]'
    )
    assert (
        connection.connected == ("127.0.0.1", 32123) and connection.closed
    ), (
        'Expected invariant: connection.connected == ("127.0.0.1", 32123) and '
        'connection.closed'
    )
    assert (
        connection.request == (
            b"GET /docs/index HTTP/1.1\r\nHost: 127.0.0.1:32123\r\nConnection: close\r\n"
            b"Accept: text/html\r\nAccept-Encoding: identity\r\n\r\n"
        )
    ), (
        'Expected invariant: connection.request == ( b"GET /docs/index '
        'HTTP/1.1\\r\\nHost: 127.0.0.1:32123\\r\\nConnection: close\\r\\n" b"Accept: '
        'text/html\\r\\nAccept-Encoding: identity\\r\\n\\r\\n" )'
    )
    assert (
        max(connection.read_sizes) <= 4096 and connection.read_sizes[-1] == 1
    ), (
        'Expected invariant: max(connection.read_sizes) <= 4096 and '
        'connection.read_sizes[-1] == 1'
    )
    assert (
        ParseRecord(CanonicalRecord(record), URL, KnownSyntheticHtmlBody(FIXTURE_ID), 16384)
    ), (
        'Expected invariant: ParseRecord(CanonicalRecord(record), URL, '
        'KnownSyntheticHtmlBody(FIXTURE_ID), 16384)'
    )


@pytest.mark.parametrize("header,exception", [
    (b"HTTP/1.1 200\r\n", PageProtocolError),
    (b"HTTP/1.1 200 nonascii\xff\r\n", PageProtocolError),
    (b"HTTP/1.1 200 empty\n", PageProtocolError),
    (b"HTTP/1.1 100 Continue\r\n", PageResponsePolicyError),
    (b"HTTP/1.1 302 Found\r\n", PageResponsePolicyError),
    (b"HTTP/1.2 200 reason\r\n", PageProtocolError),
])
def test_StatusGrammarAndResponsePolicies(header, exception):
    """An exact required status separator and printable reason are transient parser requirements."""

    raw = header + b"Content-Length: 541\r\nContent-Type: text/html\r\n\r\n"

    with pytest.raises(exception):
        ParseHeaders(raw, 541, 16384)


@pytest.mark.parametrize("extra", [
    b"Content-Length: 541\r\n", b"CONTENT-TYPE: text/html\r\n", b" folded\r\n",
    b"Invalid Name: x\r\n", b"Invalid : x\r\n", b"X: \xff\r\n", b"X: \x01\r\n",
    b"\xe9: x\r\n", b"X: bare\nline\r\n", b": empty-name\r\n",
    b"X:" + b"x" * 4094 + b"\r\n",
])
def test_HeaderGrammarRefusesDuplicatesFoldingControlsAndLineOverflow(extra):
    """Case-insensitive uniqueness and exact ASCII token/value grammar fail closed."""

    raw = b"HTTP/1.1 200 \r\nContent-Length: 541\r\nContent-Type: text/html\r\n" + extra + b"\r\n"

    with pytest.raises(PageProtocolError):
        ParseHeaders(raw, 541, 16384)


@pytest.mark.parametrize("value", [b"0541", b"+541", b"541.0", b"-1", b"100000", b"", b"5 41"])
def test_ContentLengthRequiresCanonicalBoundedUnsignedDecimal(value):
    """Invalid/huge length tokens are never converted into an allocation budget."""

    raw = b"HTTP/1.0 200 \r\nContent-Length: " + value + b"\r\nContent-Type: text/html\r\n\r\n"

    with pytest.raises(PageProtocolError):
        ParseHeaders(raw, 541, 16384)


@pytest.mark.parametrize("value", [b"text/plain", b'text/html;charset="utf-8"',
    b"text/html;charset=ascii", b"text/html; extra=value", b"text/html;charset=utf-8;other=x"])
def test_ContentTypeAdmitsOnlyUtf8HtmlAndItsSingleOptionalCharset(value):
    """Declared media policy refuses unsupported parameters instead of reflecting them."""

    raw = b"HTTP/1.0 200 \r\nContent-Length: 541\r\nContent-Type: " + value + b"\r\n\r\n"

    with pytest.raises(PageResponsePolicyError):
        ParseHeaders(raw, 541, 16384)


@pytest.mark.parametrize("extra", [b"Content-Encoding: identity\r\n", b"Content-Encoding:\r\n",
                                 b"Transfer-Encoding:\r\n", b"Transfer-Encoding: chunked\r\n"])
def test_ContentAndTransferEncodingPresenceAlwaysRejects(extra):
    """Even identity or empty encoding fields remain outside version one."""

    raw = b"HTTP/1.1 200 \r\nContent-Length: 541\r\nContent-Type: text/html\r\n" + extra + b"\r\n"

    with pytest.raises(PageResponsePolicyError):
        ParseHeaders(raw, 541, 16384)


def test_HeaderExactCountLineByteLimitsAndMeasuredCanonicalMetadata():
    """Boundary-success probes retain measured counts while discarding all unknown values."""

    base = b"HTTP/1.0 200 \r\nContent-Length: 541\r\nContent-Type: TEXT/HTML ; CHARSET = UTF-8\r\n"
    extra = b"".join(f"X{index}:\r\n".encode() for index in range(62))
    accepted = base + extra + b"\r\n"
    parsed = ParseHeaders(accepted, 541, 541)
    assert (
        parsed["header_count"] == 64 and parsed["header_size_bytes"] == len(accepted)
    ), (
        'Expected invariant: parsed["header_count"] == 64 and '
        'parsed["header_size_bytes"] == len(accepted)'
    )

    with pytest.raises(PageProtocolError):
        ParseHeaders(base + extra + b"One-More:\r\n\r\n", 541, 541)

    shortest = b"HTTP/1.1 200 \r\nContent-Length:541\r\nContent-Type:text/html\r\n\r\n"
    parsed = ParseHeaders(shortest, 541, 541)
    assert (
        parsed["declared_charset"] is None and len(shortest) == 61
    ), (
        'Expected invariant: parsed["declared_charset"] is None and len(shortest) '
        '== 61'
    )

    with pytest.raises(PageProtocolError):
        ParseHeaders(b"x" * 16385, 541, 541)


@pytest.mark.parametrize("size,limit", [(540, 16384), (542, 16384), (541, 540)])
def test_DeclaredBodySizeMustExactlyFitTheReviewedCatalog(size, limit):
    """Body declaration mismatch never reaches output, even inside a larger selected quota."""

    raw = f"HTTP/1.1 200 \r\nContent-Length:{size}\r\nContent-Type:text/html\r\n\r\n".encode()

    with pytest.raises(PageBodyPolicyError):
        ParseHeaders(raw, 541, limit)


@pytest.mark.parametrize("variant", ["empty", "headers", "truncated", "extra", "changed", "peer"])
def test_WorkerRefusesIncompleteExcessMismatchedBodiesAndPeers(monkeypatch, variant):
    """Malformed response input remains transient; all paths release the fake socket."""

    raw = Wire()

    if variant == "empty":
        raw = b""

    elif variant == "headers":
        raw = b"X" * 16384

    elif variant == "truncated":
        raw = raw[:-1]

    elif variant == "extra":
        raw += b"!"

    elif variant == "changed":
        raw = raw[:-1] + b"!"

    connection, _ = Socket(monkeypatch, raw, peer="127.0.0.2" if variant == "peer" else "127.0.0.1")

    with pytest.raises((PageProtocolError, PageBodyPolicyError)):
        Probe(URL, 2, FIXTURE_ID, 16384)

    assert (
        connection.closed
    ), (
        'Expected invariant: connection.closed'
    )


def test_WorkerUsesSingleMonotonicBudgetForEverySocketPhase(monkeypatch):
    """Positive intermediate progress cannot renew the original whole-request deadline."""

    import fuzzy1337.page_capture_worker as worker

    readings = iter([0, 0.01, 0.02, 0.03, 2.1])
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(readings))
    connection, _ = Socket(monkeypatch)

    with pytest.raises(TimeoutError):
        Probe(URL, 2, FIXTURE_ID, 16384)

    assert (
        connection.closed
    ), (
        'Expected invariant: connection.closed'
    )
    monkeypatch.setattr(worker.time, "monotonic", lambda: 1)

    with pytest.raises(TimeoutError):
        Remaining(0)


@pytest.mark.parametrize("arguments", [(), (URL, "2.0", FIXTURE_ID),
    (URL, "2", FIXTURE_ID, "16384"), (URL, "2.00", FIXTURE_ID, "16384"),
    (URL, "nan", FIXTURE_ID, "16384"), (URL, "1" * 25, FIXTURE_ID, "16384"),
    (URL, "2.0", FIXTURE_ID, "016384"), (URL, "2.0", FIXTURE_ID, "100000"),
    (URL, "2.0", FIXTURE_ID, "540"), (URL, "2.0", FIXTURE_ID, True)])
def test_WorkerArgvTokensRejectBeforeNetworkOrConversion(arguments):
    """Only the exact bounded canonical prepared token grammar qualifies as worker input."""

    with pytest.raises(ValueError):
        WorkerInputs(arguments)


@pytest.mark.parametrize("error,exception", [
    ("input", ValueError("synthetic-secret-marker")),
    ("connection", OSError("synthetic-secret-marker")),
    ("timeout", TimeoutError("synthetic-secret-marker")),
    ("protocol", PageProtocolError("synthetic-secret-marker")),
    ("response-policy", PageResponsePolicyError("synthetic-secret-marker")),
    ("body-policy", PageBodyPolicyError("synthetic-secret-marker")),
])
def test_WorkerMainEmitsCanonicalFixedErrorAndNoSecretTraceback(monkeypatch, capsys,
                                                              error, exception):
    """Every expected failure yields exact safe fields/exit and zero stderr."""

    import fuzzy1337.page_capture_worker as worker

    def Fail(*args):
        """Inject an unknown marker in a transient failure without disclosing it."""

        raise exception

    monkeypatch.setattr(worker, "Probe", Fail)
    assert (
        Main((URL, "2.0", FIXTURE_ID, "16384")) == ERROR_EXITS[error]
    ), (
        'Expected invariant: Main((URL, "2.0", FIXTURE_ID, "16384")) == '
        'ERROR_EXITS[error]'
    )
    captured = capsys.readouterr()
    assert (
        captured.out.encode() == CanonicalRecord({"schema_version": 1, "error": error})
    ), (
        'Expected invariant: captured.out.encode() == '
        'CanonicalRecord({"schema_version": 1, "error": error})'
    )
    assert (
        captured.err == "" and "synthetic-secret-marker" not in captured.out
    ), (
        'Expected invariant: captured.err == "" and "synthetic-secret-marker" not '
        'in captured.out'
    )


def test_WorkerMainSuccessCanonicalRecordAndIpv6Family(monkeypatch, capsys):
    """A admitted body is output exactly once; IPv6 uses the supplied literal family."""

    connection, constructions = Socket(monkeypatch, peer="::1")
    url = "http://[::1]:32123/docs/index"
    assert (
        Main((url, "2.0", FIXTURE_ID, "16384")) == 0
    ), (
        'Expected invariant: Main((url, "2.0", FIXTURE_ID, "16384")) == 0'
    )
    captured = capsys.readouterr()
    record = ParseRecord(captured.out.encode(), url, KnownSyntheticHtmlBody(FIXTURE_ID), 16384)
    assert (
        record["address"] == "::1" and captured.err == ""
    ), (
        'Expected invariant: record["address"] == "::1" and captured.err == ""'
    )
    assert (
        constructions == [(socket.AF_INET6, socket.SOCK_STREAM)]
    ), (
        'Expected invariant: constructions == [(socket.AF_INET6, '
        'socket.SOCK_STREAM)]'
    )
    assert (
        b"Host: [::1]:32123\r\n" in connection.request
    ), (
        'Expected invariant: b"Host: [::1]:32123\\r\\n" in connection.request'
    )


@pytest.mark.parametrize("variant", ["missing", "extra", "bool", "version", "url", "address",
    "port", "scheme", "status", "http-version", "type", "charset", "size", "count",
    "impossible-header-size", "header-overflow", "digest", "base64", "noncanonical-base64",
    "body", "nonfinite", "nested", "duplicate", "whitespace", "ordering", "no-lf", "two-lf",
    "overflow", "bad-utf8", "array", "wrong-error"])
def test_ParentAdmissionRejectsInconsistentCanonicalAndCopiedRecords(variant):
    """No untrusted field, deep parse or equivalent noncanonical JSON enters evidence."""

    record = Record()
    changes = {
        "bool": {"content_length": True}, "version": {"schema_version": True},
        "url": {"url": "http://127.0.0.1:32123/other"}, "address": {"address": "localhost"},
        "port": {"port": True}, "scheme": {"scheme": "https"}, "status": {"status": 302},
        "http-version": {"http_version": "HTTP/2"}, "type": {"content_type": "text/plain"},
        "charset": {"declared_charset": "ascii"}, "size": {"content_length": 540},
        "count": {"header_count": 65}, "impossible-header-size": {"header_size_bytes": 1},
        "header-overflow": {"header_size_bytes": 16385}, "digest": {"body_sha256": "0" * 64},
        "base64": {"body_base64": "!" * 724}, "noncanonical-base64": {
            "body_base64": record["body_base64"][:-3] + "B=="},
        "body": {"body_base64": base64.b64encode(Body()[:-1] + b"!").decode()},
        "nested": {"status": {"nested": [True]}},
        "wrong-error": {"error": "synthetic-secret-marker"},
    }
    record.update(changes.get(variant, {}))

    if variant == "missing":
        del record["fixture_id"]

    if variant == "extra":
        record["raw_header"] = "synthetic-secret-marker"

    raw = CanonicalRecord(record)

    if variant == "nonfinite":
        raw = raw.replace(b'"status":200', b'"status":NaN')

    elif variant == "duplicate":
        raw = raw.replace(b'"status":200', b'"status":200,"status":200')

    elif variant == "whitespace":
        raw = json.dumps(record, sort_keys=True).encode() + b"\n"

    elif variant == "ordering":
        raw = json.dumps(record, separators=(",", ":")).encode() + b"\n"

    elif variant == "no-lf":
        raw = raw[:-1]

    elif variant == "two-lf":
        raw += b"\n"

    elif variant == "overflow":
        raw = b" " * (MAX_RECORD_BYTES + 1)

    elif variant == "bad-utf8":
        raw = b"\xff\n"

    elif variant == "array":
        raw = b"[]\n"

    with pytest.raises(PageCaptureRecordError) as caught:
        ParseRecord(raw, URL, KnownSyntheticHtmlBody(FIXTURE_ID), 16384)

    assert (
        "synthetic-secret-marker" not in str(caught.value) and caught.value.__suppress_context__
    ), (
        'Expected invariant: "synthetic-secret-marker" not in str(caught.value) '
        'and caught.value.__suppress_context__'
    )


@pytest.mark.parametrize("error", ERROR_EXITS)
def test_ParentAdmitsOnlyCanonicalKnownFixedFailureRecords(error):
    """A legitimate worker failure can be retained without becoming a page observation."""

    raw = CanonicalRecord({"schema_version": 1, "error": error})
    assert (
        ParseRecord(raw, URL, KnownSyntheticHtmlBody(FIXTURE_ID), 16384)["error"] == error
    ), (
        'Expected invariant: ParseRecord(raw, URL, '
        'KnownSyntheticHtmlBody(FIXTURE_ID), 16384)["error"] == error'
    )


def test_AdapterNormalizationPreservesSourceOnlyAndKnownMetadata():
    """SDK normalization produces one observed source with no object/relation/finding claims."""

    raw = CanonicalRecord(Record())
    result = Adapter(raw).NormalizeReport(Report(raw))
    assert (
        len(result.observations) == 1 and result.observations[0].kind == "http.synthetic-page"
    ), (
        'Expected invariant: len(result.observations) == 1 and '
        'result.observations[0].kind == "http.synthetic-page"'
    )
    assert (
        result.observations[0].subject_reference == Target(TargetKind.URL, URL).Reference()
    ), (
        'Expected invariant: result.observations[0].subject_reference == '
        'Target(TargetKind.URL, URL).Reference()'
    )
    assert (
        "body_base64" not in result.observations[0].attributes
    ), (
        'Expected invariant: "body_base64" not in '
        'result.observations[0].attributes'
    )
    assert (
        not result.findings and not result.object_enrichments and not result.relation_enrichments
    ), (
        'Expected invariant: not result.findings and not '
        'result.object_enrichments and not result.relation_enrichments'
    )


@pytest.mark.parametrize("variant", ["state", "invocation", "argv-list", "bool-timeout", "empty",
    "role", "count", "oversized", "reader-mismatch", "reader-type", "failed-record",
    "forged-execution", "duration-bool", "duration-nonfinite", "duration-huge", "state-string"])
def test_AdapterNormalizationRefusesSubstitutedNestedReportFields(variant):
    """Copied immutable wrappers are rechecked before any evidence bytes become observations."""

    raw = CanonicalRecord(Record())
    report = Report(raw)
    reader_raw = raw

    if variant == "state":
        report = replace(report, execution=AdapterExecution(ExecutionState.FAILED, 1, 0.1))

    elif variant == "invocation":
        report = replace(report, invocation=replace(report.invocation, argv=("unexpected",)))

    elif variant in ("argv-list", "bool-timeout"):
        invocation = copy.copy(report.invocation)
        object.__setattr__(invocation, "argv" if variant == "argv-list" else "timeout_seconds",
                           list(invocation.argv) if variant == "argv-list" else True)
        report = replace(report, invocation=invocation)

    elif variant == "empty":
        report = replace(report, evidence=())

    elif variant == "role":
        report = replace(report, evidence=(replace(report.evidence[0], role="stderr"),))

    elif variant == "count":
        report = replace(report, evidence=(report.evidence[0],
                         replace(report.evidence[0], role="other")))

    elif variant == "oversized":
        report = replace(report, evidence=(replace(report.evidence[0],
                         size_bytes=MAX_RECORD_BYTES + 1),))

    elif variant == "reader-mismatch":
        reader_raw = raw + b"!"

    elif variant == "reader-type":
        reader_raw = "unsupported"

    elif variant == "failed-record":
        reader_raw = CanonicalRecord({"schema_version": 1, "error": "protocol"})
        report = Report(reader_raw)

    else:
        execution = copy.copy(report.execution)
        values = {"forged-execution": ("exit_code", True),
            "duration-bool": ("duration_seconds", True),
            "duration-nonfinite": ("duration_seconds", float("inf")),
            "duration-huge": ("duration_seconds", 10 ** 10000),
            "state-string": ("state", "succeeded")}
        field, value = values[variant]
        object.__setattr__(execution, field, value)
        report = replace(report, execution=execution)

    with pytest.raises(PageCaptureRecordError):
        Adapter(reader_raw).NormalizeReport(report)


def test_ExecutionRefusesUnrelatedWrappers():
    """An object with similar attributes is not the actual owning execution record."""

    with pytest.raises(PageCaptureRecordError):
        Execution(object())


def Result(raw: bytes | None = None, *, error: str | None = None,
           termination: ExecutionTermination = ExecutionTermination.PROCESS_EXIT,
           stderr: bytes = b"") -> LocalExecutionResult:
    """Build finite real owner records for an isolated deterministic executor seam."""

    output = CanonicalRecord(Record()) if raw is None else raw
    state, exit_code = ExecutionState.SUCCEEDED, 0

    if error is not None:
        output = CanonicalRecord({"schema_version": 1, "error": error})
        state, exit_code = ExecutionState.FAILED, ERROR_EXITS[error]

    if termination in (ExecutionTermination.CANCELLATION, ExecutionTermination.OUTPUT_LIMIT):
        state, exit_code = ExecutionState.CANCELLED, None

    elif termination is ExecutionTermination.TIMEOUT:
        state, exit_code = ExecutionState.TIMED_OUT, None

    events = [ExecutionEvent(0, ExecutionEventKind.STARTED)]

    if output:
        events.append(ExecutionEvent(len(events), ExecutionEventKind.STDOUT, output))

    if stderr:
        events.append(ExecutionEvent(len(events), ExecutionEventKind.STDERR, stderr))

    events.append(ExecutionEvent(len(events), ExecutionEventKind.COMPLETED,
                                 termination=termination))

    return LocalExecutionResult(AdapterExecution(state, exit_code, 0.1), termination,
                                output, stderr, tuple(events))


@pytest.mark.parametrize("variant", ["wrong-type", "stdout-type", "stdout-overflow", "events-type",
    "event-sequence", "event-kind", "event-bytes", "event-overflow", "misordered-start",
    "misordered-completed", "wrong-stream", "wrong-state", "empty-events"])
def test_ExactExecutorResultRefusesEveryCopiedWrapperAndStreamMismatch(variant):
    """Terminal executor facts must be real bounded nested types before record parsing."""

    result = copy.copy(Result())

    if variant == "wrong-type":
        result = object()

    elif variant == "stdout-type":
        object.__setattr__(result, "stdout", bytearray(result.stdout))

    elif variant == "stdout-overflow":
        object.__setattr__(result, "stdout", b"x" * (MAX_RECORD_BYTES + 1))

    elif variant == "events-type":
        object.__setattr__(result, "events", list(result.events))

    elif variant in ("event-sequence", "event-kind", "event-bytes"):
        event = copy.copy(result.events[0])
        fields = {"event-sequence": ("sequence", True), "event-kind": ("kind", "started"),
                  "event-bytes": ("data", "synthetic-private-marker")}
        field, value = fields[variant]
        object.__setattr__(event, field, value)
        object.__setattr__(result, "events", (event, *result.events[1:]))

    elif variant == "event-overflow":
        event = copy.copy(result.events[1])
        object.__setattr__(event, "data", b"x" * (MAX_RECORD_BYTES + 1025))
        object.__setattr__(result, "events", (result.events[0], event, result.events[2]))

    elif variant == "misordered-start":
        object.__setattr__(result, "events", (
            ExecutionEvent(0, ExecutionEventKind.STDOUT, result.stdout),
            ExecutionEvent(1, ExecutionEventKind.STARTED), result.events[-1],
        ))

    elif variant == "misordered-completed":
        object.__setattr__(result, "events", (
            ExecutionEvent(0, ExecutionEventKind.COMPLETED,
                           termination=ExecutionTermination.PROCESS_EXIT),
            result.events[1], result.events[-1],
        ))

    elif variant == "wrong-stream":
        object.__setattr__(result, "stdout", result.stdout + b"!")

    elif variant == "wrong-state":
        object.__setattr__(result, "execution",
                           AdapterExecution(ExecutionState.CANCELLED, None, 0.1))

    elif variant == "empty-events":
        object.__setattr__(result, "events", ())

    with pytest.raises(PageCaptureRecordError):
        ValidateResult(result)


@pytest.mark.parametrize("variant", ["limits", "frontier", "policy", "clock", "body-quota",
                                     "source-method", "source-type", "scope"])
def test_ProviderRefusesCopiedInputsBeforeAnyTransport(tmp_path, variant):
    """Finite typed provider preparation does not infer authority or coerce owner copies."""

    from fuzzy1337.captured_web import CapturedWebLimits

    fixture = Fixture.Create(tmp_path / "workspace")
    source = copy.copy(fixture.source)
    parameters = {"limits": PageCaptureLimits(), "frontier_limits": CapturedWebLimits(),
                  "policy": fixture.policy, "clock": lambda: NOW}

    if variant == "limits":
        parameters["limits"] = {}

    elif variant == "frontier":
        parameters["frontier_limits"] = {}

    elif variant == "policy":
        parameters["policy"] = {}

    elif variant == "clock":
        parameters["clock"] = None

    elif variant == "body-quota":
        parameters["limits"] = PageCaptureLimits(max_body_bytes=540)

    elif variant == "source-method":
        endpoint = copy.copy(source.endpoint)
        object.__setattr__(endpoint, "method", ImpactLevel.SAFE)
        object.__setattr__(source, "endpoint", endpoint)

    elif variant == "source-type":
        source = None

    with pytest.raises(ValueError):
        LocalPageCaptureProvider(fixture.root, source, KnownSyntheticHtmlBody(FIXTURE_ID),
                                 "Invalid" if variant == "scope" else "local", **parameters)


@pytest.mark.parametrize("variant,code", [
    ("launch-error", JobFailureCode.PROVIDER), ("authority-io", JobFailureCode.STORAGE),
    ("result-wrapper", JobFailureCode.NORMALIZATION),
    ("output-limit", JobFailureCode.OUTPUT_LIMIT), ("timeout", JobFailureCode.TIMEOUT),
    ("stderr", JobFailureCode.NORMALIZATION), ("failure-exit", JobFailureCode.NORMALIZATION),
    ("success-exit", JobFailureCode.NORMALIZATION),
    ("wrong-body-record", JobFailureCode.NORMALIZATION),
    ("model-io", JobFailureCode.STORAGE), ("final-io", JobFailureCode.STORAGE),
    ("progress-delivery", JobFailureCode.OUTPUT_LIMIT),
])
def test_ProviderFailureClassificationAndExactTerminalAdmission(tmp_path, monkeypatch, page_runner,
                                                              variant, code):
    """An isolated executor seam proves output admission and post-Save failure behavior."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = fixture.Provider()
    result = Result()

    if variant == "output-limit":
        result = Result(termination=ExecutionTermination.OUTPUT_LIMIT)

    elif variant == "timeout":
        result = Result(termination=ExecutionTermination.TIMEOUT)

    elif variant == "stderr":
        result = Result(stderr=b"synthetic-private-marker")

    elif variant == "failure-exit":
        result = Result(error="input")
        result = replace(result, execution=AdapterExecution(ExecutionState.FAILED, 1, 0.1))

    elif variant == "success-exit":
        result = replace(result, execution=AdapterExecution(ExecutionState.FAILED, 1, 0.1))

    elif variant == "result-wrapper":
        result = object()

    async def Execute(self, request, **kwargs):
        """Return exact synthetic process facts or fixed launch failure without transport."""

        if variant == "launch-error":
            raise LocalExecutionError("synthetic-private-marker")

        if variant == "authority-io":
            raise OSError("synthetic-private-marker")

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)

    if variant == "wrong-body-record":
        original = JobContext.CaptureEvidence

        def WrongCapture(self, *args, **kwargs):
            """Return a copied manifest with an inconsistent immutable derived role."""

            artifact = original(self, *args, **kwargs)

            if artifact.evidence.reference.role == "response-body":
                record = copy.copy(artifact.evidence)
                object.__setattr__(record, "schema_version", True)

                return replace(artifact, evidence=record)

            return artifact

        monkeypatch.setattr(JobContext, "CaptureEvidence", WrongCapture)

    elif variant == "model-io":
        original = LocalModelStore.Open
        opened = [0]

        def FailSecondModelRead(self):
            """Refuse actual composition read after initial durable owner validation."""

            opened[0] += 1

            if opened[0] == 2:
                raise OSError("synthetic-private-marker")

            return original(self)

        monkeypatch.setattr(LocalModelStore, "Open", FailSecondModelRead)

    elif variant == "final-io":
        def FailFinal(*args, **kwargs):
            """Fail final authority I/O after artifacts and pure composition exist."""

            raise OSError("synthetic-private-marker")

        monkeypatch.setattr(provider, "FinalAuthority", FailFinal)

    elif variant == "progress-delivery":
        def FailProgress(self, *args, **kwargs):
            """Reject progress delivery after actual model Save and model delta publication."""

            raise RuntimeError("synthetic-private-marker")

        monkeypatch.setattr(JobContext, "Progress", FailProgress)

    job = fixture.Job(provider=provider)
    snapshot = RunJob(job, page_runner)
    assert snapshot.state is JobState.FAILED, snapshot.failure
    assert (
        snapshot.failure.code is code
    ), (
        'Expected invariant: snapshot.failure.code is code'
    )
    assert (
        "synthetic-private-marker" not in snapshot.failure.message
    ), (
        'Expected invariant: "synthetic-private-marker" not in '
        'snapshot.failure.message'
    )
    assert (
        all("synthetic-private-marker" not in str(event.data) for event in job.EventsSince())
    ), (
        'Expected invariant: all("synthetic-private-marker" not in '
        'str(event.data) for event in job.EventsSince())'
    )

    if variant == "progress-delivery":
        assert (
            "committed" in snapshot.failure.message
        ), (
            'Expected invariant: "committed" in snapshot.failure.message'
        )
        assert (
            LocalModelStore(fixture.root).Open().revision == 1
        ), (
            'Expected invariant: LocalModelStore(fixture.root).Open().revision == 1'
        )
        assert (
            any(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince())
        ), (
            'Expected invariant: any(event.kind is JobEventKind.MODEL_DELTA for event '
            'in job.EventsSince())'
        )


@pytest.mark.parametrize("variant", ["unknown-role", "wrong-media", "wrong-type", "oversized"])
def test_RoleBoundedEvidenceFacadeRejectsBeforeOwnerAllocation(tmp_path, monkeypatch, variant):
    """The role-aware interception applies to the actual parsed reference before eager raw reads."""

    reference = Report(CanonicalRecord(Record())).evidence[0]

    if variant == "unknown-role":
        reference = replace(reference, role="stderr")

    elif variant == "wrong-media":
        reference = replace(reference, media_type="text/html")

    elif variant == "wrong-type":
        reference = object()

    else:
        reference = replace(reference, size_bytes=MAX_RECORD_BYTES + 1)

    with pytest.raises(ValueError):
        BoundedPageEvidenceStore(tmp_path / "evidence").Read(reference)


def test_ProviderOwnershipAndMissingInitialModelDenyBeforeExecution(tmp_path, page_runner):
    """Consumer-owned persisted state must exist and exact job workspace attribution must match."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provider = fixture.Provider()
    spec = JobSpec("job:wrong", "wrong", "scope:local", "owner:test", PAGE_CAPTURE_PROVIDER_ID)
    assert (
        RunJob(ScanJob(spec, provider), page_runner).failure.code is JobFailureCode.AUTHORIZATION
    ), (
        'Expected invariant: RunJob(ScanJob(spec, provider), page_runner).failure.code is '
        'JobFailureCode.AUTHORIZATION'
    )
    (fixture.root / "state" / "model" / "model.json").unlink()
    assert (
        RunJob(fixture.Job(provider=provider), page_runner).failure.code is JobFailureCode.STORAGE
    ), (
        'Expected invariant: RunJob(fixture.Job(provider=provider), page_runner).failure.code is '
        'JobFailureCode.STORAGE'
    )


def test_ExactHeaderByteAndLineQuotasPrecedeBodyAllocation(monkeypatch):
    """A maximal complete header proves chunked body reads and rejects one-byte overflow."""

    shortest = b"HTTP/1.1 200 \r\nContent-Length:541\r\nContent-Type:text/html\r\n"
    extras = b"".join(name + b":" + b"x" * 4092 + b"\r\n" for name in (b"X", b"Y", b"Z"))
    final = b"W:" + b"x" * (16384 - len(shortest) - len(extras) - 6) + b"\r\n"
    headers = shortest + extras + final + b"\r\n"
    assert len(headers) == 16384, "Independent exact header-byte-bound fixture is not maximal"
    connection, _ = Socket(monkeypatch, headers + Body())
    record = Probe(URL, 2, FIXTURE_ID, 541)
    assert record["header_size_bytes"] == 16384, "Actual maximal header size was not measured"
    assert connection.read_sizes[-2:] == [541, 1], "Exact body and EOF were not read separately"
    ParseRecord(CanonicalRecord(record), URL, KnownSyntheticHtmlBody(FIXTURE_ID), 541)

    with pytest.raises(PageProtocolError):
        ParseHeaders(headers[:-2] + b"x\r\n", 541, 541)

    Socket(monkeypatch, headers + Body() + b"!")

    with pytest.raises(PageProtocolError):
        Probe(URL, 2, FIXTURE_ID, 541)


def test_UnexpectedBodyUtf8AndBomNeverReachWorkerOutput(monkeypatch, capsys):
    """Invalid UTF-8/BOM variants fail the closed body policy with no decoded exception content."""

    for prefix in (b"\xff", b"\xef\xbb\xbf"):
        body = prefix + Body()[len(prefix):]
        Socket(monkeypatch, Wire()[:-541] + body)
        assert Main((URL, "2.0", FIXTURE_ID, "541")) == 1, "Unreviewed invalid body was admitted"
        captured = capsys.readouterr()
        assert captured.out == '{"error":"body-policy","schema_version":1}\n', (
            "Invalid body bytes entered an output field"
        )
        assert captured.err == "", "Unexpected body produced a stderr traceback"


def test_WorkerMainBoundsArgumentCountBeforeAnyConsumerCopy(capsys):
    """An arbitrary sequence is not copied or iterated before exact four-token admission."""

    class UnboundedSequence:
        """Tripwire any copied iteration or prevalidation length work on an unsupported wrapper."""

        def __iter__(self):
            """Fail if the worker first copies untrusted argv instead of validating its shape."""

            raise AssertionError("Untrusted argv was copied before hard argument-count admission")

        def __len__(self):
            """Fail if validation calls methods on an unsupported copied sequence type."""

            raise AssertionError("Untrusted argv wrapper was inspected before exact type admission")

    assert Main(UnboundedSequence()) == 64, "Unsupported argv wrapper did not fail closed"
    captured = capsys.readouterr()
    assert captured.out == '{"error":"input","schema_version":1}\n', (
        "Invalid argv wrapper leaked a dynamic exception"
    )
    assert captured.err == "", "Untrusted argument wrapper reached a stderr traceback"
