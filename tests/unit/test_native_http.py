# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline native HTTP endpoint, safe-record, adapter and worker regression contracts."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from dataclasses import replace

import pytest

from fuzzy1337 import native_http_worker as worker
from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.adapters.native_http import (
    NATIVE_HTTP_CAPABILITY,
    NATIVE_HTTP_MAX_RECORD_BYTES,
    Endpoint,
    NativeHttpAdapter,
    NativeHttpRecordError,
    ParseRecord,
    RequestTimeout,
)

URL = "http://127.0.0.1:8080/health"


def Record(url: str = URL, **changes: object) -> bytes:
    """Produce a non-sensitive synthetic worker record for one explicitly pinned URL."""

    target, address, port, scheme = Endpoint(url)
    fields = {"schema_version": 1, "url": target.value, "address": address, "port": port,
              "scheme": scheme, "status": 200}
    fields.update(changes)
    return json.dumps(fields).encode()


def Request(**changes: object) -> AdapterRequest:
    """Build an approved-shape adapter request without issuing execution authority."""

    target = Endpoint(URL)[0]
    request = AdapterRequest(NATIVE_HTTP_CAPABILITY, target.Reference(), ImpactLevel.SAFE,
                             {"url": URL, "timeout_seconds": 0.1})
    return replace(request, **changes)


def Report(raw: bytes | None = None) -> tuple[NativeHttpAdapter, AdapterReport]:
    """Bind finite synthetic stdout to a recorded successful worker invocation."""

    payload = Record() if raw is None else raw
    reference = EvidenceReference("stdout", "blobs/fixture", hashlib.sha256(payload).hexdigest(),
                                  "application/json", len(payload))
    adapter = NativeHttpAdapter(lambda _: payload)
    report = AdapterReport(adapter.PrepareInvocation(Request()),
                           AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1), (reference,))
    return adapter, report


@pytest.mark.parametrize("url", [URL, "https://[::1]/", "http://127.0.0.1/"])
def test_EndpointIsCanonicalLiteral(url):
    """Canonical supported addresses need no resolver or inferred destination."""

    target, address, port, scheme = Endpoint(url)
    assert (
        target.value == url and address in {"127.0.0.1", "::1"}
    ), 'Endpoint Is Canonical Literal boundary invariant failed'
    assert (
        1 <= port <= 65535 and scheme in {"http", "https"}
    ), 'Endpoint Is Canonical Literal boundary invariant failed'


@pytest.mark.parametrize("value", [
    None, 1, "a" * 2049, "http://localhost/", "http://0.0.0.0/", "http://224.0.0.1/",
    "http://user:password@127.0.0.1/", "http://127.0.0.1/#fragment",
    "http://127.0.0.1/?token=secret", "ftp://127.0.0.1/", "http://[::%2]/",
])
def test_EndpointRejectsAmbiguousOrSensitiveInput(value):
    """No alias, query token or unsupported addressing can enter preparation."""

    with pytest.raises(ValueError):
        Endpoint(value)


@pytest.mark.parametrize("value", [True, None, "1", 0, 0.01, 11, float("nan"), float("inf")])
def test_TimeoutRequiresFiniteHardBounds(value):
    """Invalid deadlines cannot weaken the finite worker request budget."""

    with pytest.raises(ValueError):
        RequestTimeout(value)


@pytest.mark.parametrize("payload", [
    b"", b"\xff", b"[]", b"null", b"{}", b'{"schema_version":true}',
    b'{"schema_version":2}', b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":1,"error":NaN}', b'{"schema_version":1,"error":{}}',
    b'{"schema_version":1,"error":"server secret"}',
    b'{"schema_version":1,"error":"timeout","body":"secret"}',
    b"{" * 1500, b" " * (NATIVE_HTTP_MAX_RECORD_BYTES + 1),
])
def test_RecordGrammarRejectsUnsafeOrAmbiguousPayload(payload):
    """Only the narrow safe output grammar is eligible for persistence."""

    with pytest.raises(NativeHttpRecordError):
        ParseRecord(payload, URL)


@pytest.mark.parametrize("changes", [
    {"url": "http://127.0.0.2/"}, {"address": "127.0.0.2"}, {"port": 80}, {"port": True},
    {"scheme": "https"}, {"status": 199}, {"status": 600}, {"status": True},
    {"body": "secret"}, {"headers": {"Set-Cookie": "secret"}},
])
def test_RecordBindsEveryDestinationAndStatus(changes):
    """Valid JSON cannot substitute unchecked destinations or retained response data."""

    with pytest.raises(NativeHttpRecordError):
        ParseRecord(Record(**changes), URL)


def test_RecordPreservesRedirectAsOneObservation():
    """A redirect status carries no follow-up authority or Location contents."""

    assert (
        ParseRecord(Record(status=302), URL)["status"] == 302
    ), 'Record Preserves Redirect As One Observation boundary invariant failed'
    assert (
        ParseRecord(b'{"schema_version":1,"error":"timeout"}', URL)["error"] == "timeout"
    ), 'Record Preserves Redirect As One Observation boundary invariant failed'


@pytest.mark.parametrize("changes", [
    {"capability": "different"}, {"impact": ImpactLevel.STANDARD},
    {"credential_references": ("credential:test",)}, {"parameters": {}},
    {"target_reference": "target:other"},
])
def test_AdapterRejectsUnauthorizedShape(changes):
    """Finite preparation never accepts raw arguments or unrelated capabilities."""

    with pytest.raises(ValueError):
        NativeHttpAdapter(lambda _: b"").PrepareInvocation(Request(**changes))


def test_AdapterNormalizesActualFactsWithoutFindings():
    """One verified sensor result contributes four objects and three relations."""

    adapter, report = Report()
    result = adapter.NormalizeReport(report)
    assert (
        adapter.CheckHealth().state is AdapterHealthState.AVAILABLE
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert (
        adapter.Descriptor.maximum_impact is ImpactLevel.SAFE
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert (
        report.invocation.timeout_seconds == 2
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert (
        report.invocation.argv[-2:] == (URL, "0.1")
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert (
        not result.findings
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert tuple(item.object_kind for item in result.object_enrichments) == (
        "host", "port", "service", "endpoint",
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'
    assert (
        len(result.relation_enrichments) == 3
    ), 'Adapter Normalizes Actual Facts Without Findings boundary invariant failed'


@pytest.mark.parametrize("case", [
    "failed", "invocation", "empty", "roles", "size", "hash", "error",
])
def test_AdapterRejectsUnprovenSuccess(case):
    """No failed run, substituted invocation or invalid evidence becomes a service fact."""

    adapter, report = Report()

    if case == "failed":
        report = replace(report, execution=AdapterExecution(ExecutionState.FAILED, 1, 0.1))

    elif case == "invocation":
        report = replace(report, invocation=replace(report.invocation, argv=("other",)))

    elif case == "empty":
        report = replace(report, evidence=())

    elif case == "roles":
        report = replace(report, evidence=(replace(report.evidence[0], role="stderr"),))

    elif case == "size":
        report = replace(report, evidence=(replace(report.evidence[0], size_bytes=9999),))

    elif case == "hash":
        report = replace(report, evidence=(replace(report.evidence[0], sha256="0" * 64),))

    else:
        adapter, report = Report(b'{"schema_version":1,"error":"timeout"}')

    with pytest.raises(NativeHttpRecordError):
        adapter.NormalizeReport(report)


class FakeSocket:
    """Finite offline socket fixture; arbitrary secret response bytes stay transient."""

    def __init__(self, chunks: list[bytes], address: str = "127.0.0.1") -> None:
        """Bind finite received chunks and a synthetic peer."""

        self.chunks = chunks
        self.address = address
        self.sent = b""
        self.closed = False
        self.settimeout = self.SetTimeout
        self.connect = self.Connect
        self.getpeername = self.GetPeerName
        self.sendall = self.SendAll
        self.recv = self.Receive
        self.close = self.Close

    def SetTimeout(self, seconds: float) -> None:
        """Require the worker to keep every socket phase bounded."""

        assert seconds > 0, 'settimeout boundary invariant failed'

    def Connect(self, destination: tuple[str, int]) -> None:
        """Assert the worker uses a literal target tuple without resolving a name."""

        assert destination[0] in {"127.0.0.1", "::1"}, 'connect boundary invariant failed'

    def GetPeerName(self) -> tuple[str, int]:
        """Return the synthetic connected peer for destination-binding checks."""

        return self.address, 8080

    def SendAll(self, data: bytes) -> None:
        """Retain only the outbound synthetic request for credential-absence assertions."""

        self.sent = data

    def Receive(self, size: int) -> bytes:
        """Return finite fixture fragments respecting the worker's requested bound."""

        if not self.chunks:
            return b""

        chunk = self.chunks.pop(0)
        result, remainder = chunk[:size], chunk[size:]

        if remainder:
            self.chunks.insert(0, remainder)

        return result

    def Close(self) -> None:
        """Record owned-socket cleanup even after protocol or deadline failure."""

        self.closed = True


def test_WorkerUsesLiteralSocketAndDropsResponseSecrets(monkeypatch):
    """A real worker code path retains status only despite cookies, headers and body markers."""

    connection = FakeSocket([
        b"HTTP/1.1 302 Secret reason\r\nSet-Cookie: secret\r\n\r\nsecret body",
    ])
    monkeypatch.setattr(worker.socket, "socket", lambda *args: connection)
    result = worker.Probe(URL, 0.1)
    assert (
        result == json.loads(Record(status=302))
    ), 'Worker Uses Literal Socket And Drops Response Secrets boundary invariant failed'
    assert (
        "secret" not in json.dumps(result).lower()
    ), 'Worker Uses Literal Socket And Drops Response Secrets boundary invariant failed'
    assert (
        b"Authorization" not in connection.sent and b"Cookie" not in connection.sent
    ), 'Worker Uses Literal Socket And Drops Response Secrets boundary invariant failed'
    assert (
        connection.closed and connection.sent.startswith(b"GET /health HTTP/1.1\r\n")
    ), 'Worker Uses Literal Socket And Drops Response Secrets boundary invariant failed'


@pytest.mark.parametrize("chunks", [
    [], [b"not HTTP\r\n\r\n"], [b"HTTP/1.1 100 Continue\r\n\r\n"],
    [b"HTTP/1.1 200 OK\r\n" + b"x" * worker.MAX_HTTP_HEADER_BYTES],
])
def test_WorkerRejectsIncompleteUnsupportedOrOversizedHeaders(monkeypatch, chunks):
    """Malformed response text cannot become successful discovery or leak to output."""

    connection = FakeSocket(chunks)
    monkeypatch.setattr(worker.socket, "socket", lambda *args: connection)

    with pytest.raises(worker.HttpProtocolError):
        worker.Probe(URL, 1)

    assert (
        connection.closed
    ), 'Worker Rejects Incomplete Unsupported Or Oversized Headers boundary invariant failed'


def test_WorkerRejectsChangedConnectedPeer(monkeypatch):
    """Even a connected socket must identify the approved literal peer."""

    connection = FakeSocket([], "127.0.0.2")
    monkeypatch.setattr(worker.socket, "socket", lambda *args: connection)

    with pytest.raises(worker.HttpProtocolError, match="peer"):
        worker.Probe(URL, 1)

    assert connection.closed, 'Worker Rejects Changed Connected Peer boundary invariant failed'


def test_WorkerIpv6AndVerifiedTlsBoundary(monkeypatch):
    """IPv6 socket family and default verifying TLS context remain explicit."""

    connection = FakeSocket([b"HTTP/1.1 200 OK\r\n\r\n"], "::1")
    families = []
    monkeypatch.setattr(worker.socket, "socket",
                        lambda family, kind: (families.append(family), connection)[1])

    class Context:
        """Synthetic verifying-context boundary without any network or certificate bypass."""

        def WrapSocket(self, selected, *, server_hostname):
            """Assert literal IP verification identity, never a target-supplied override."""

            assert (
                selected is connection and server_hostname == "::1"
            ), 'wrap_socket boundary invariant failed'
            return selected

        wrap_socket = WrapSocket

    monkeypatch.setattr(worker.ssl, "create_default_context", lambda: Context())
    assert (
        worker.Probe("https://[::1]/", 1)["status"] == 200
    ), 'Worker Ipv6And Verified Tls Boundary boundary invariant failed'
    assert (
        families == [socket.AF_INET6] and connection.closed
    ), 'Worker Ipv6And Verified Tls Boundary boundary invariant failed'


def test_WorkerMonotonicDeadlineNeverRenewsOnProgress(monkeypatch):
    """Complete-probe deadline exhaustion is explicit, independent of socket progress."""

    monkeypatch.setattr(worker.time, "monotonic", lambda: 5)
    assert (
        worker.Remaining(6) == 1
    ), 'Worker Monotonic Deadline Never Renews On Progress boundary invariant failed'

    with pytest.raises(TimeoutError):
        worker.Remaining(5)


@pytest.mark.parametrize("error,code,name", [
    (TimeoutError("secret"), 124, "timeout"), (ssl.SSLError("secret"), 1, "tls"),
    (worker.HttpProtocolError("secret"), 1, "protocol"), (OSError("secret"), 1, "connection"),
    (ValueError("secret"), 64, "input"),
])
def test_WorkerExitPreservesFailureWithoutExceptionText(monkeypatch, capsys, error, code, name):
    """Failure records and exit codes are deterministic and contain no server-generated text."""

    def Fail(*arguments):
        """Raise only inside the offline worker fixture."""

        raise error

    monkeypatch.setattr(worker, "Probe", Fail)
    assert (
        worker.Main((URL, "1")) == code
    ), 'Worker Exit Preserves Failure Without Exception Text boundary invariant failed'
    captured = capsys.readouterr()
    assert (
        json.loads(captured.out) == {"schema_version": 1, "error": name}
    ), 'Worker Exit Preserves Failure Without Exception Text boundary invariant failed'
    assert (
        not captured.err and "secret" not in captured.out
    ), 'Worker Exit Preserves Failure Without Exception Text boundary invariant failed'


def test_WorkerMainSuccessAndInvalidArguments(monkeypatch, capsys):
    """Worker entry point writes a sole strict record and rejects ambiguous invocation shapes."""

    monkeypatch.setattr(worker, "Probe", lambda *args: json.loads(Record()))
    monkeypatch.setattr(worker.sys, "argv", ("worker", URL, "1"))
    assert worker.Main() == 0, 'Worker Main Success And Invalid Arguments boundary invariant failed'
    assert (
        json.loads(capsys.readouterr().out)["status"] == 200
    ), 'Worker Main Success And Invalid Arguments boundary invariant failed'
    assert (
        worker.Main(()) == 64
    ), 'Worker Main Success And Invalid Arguments boundary invariant failed'
    assert (
        json.loads(capsys.readouterr().out)["error"] == "input"
    ), 'Worker Main Success And Invalid Arguments boundary invariant failed'
