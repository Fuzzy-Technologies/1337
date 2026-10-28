# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Network-free strict native HTTP framing, transient-body and safe-error contracts."""

from __future__ import annotations

import hashlib
import io
import ssl
from dataclasses import replace

import pytest

from fuzzy1337 import native_web_worker as worker
from fuzzy1337.adapters.native_web import (
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_PROMETHEUS_CHECK_ID,
    CanonicalRecord,
    NativeFileCanaryTemplate,
)
from tests.unit.test_prometheus_exposition import DOCUMENT

BODY = b"ref: refs/heads/owned\n"
HEADER = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 22\r\n\r\n"


class FakeSocket:
    """Emulate an already-selected literal transport without any actual network connection."""

    def __init__(self, parts: list[bytes], peer: str = "127.0.0.1") -> None:
        """Retain finite scripted reads and independent request/cleanup observations."""

        self.parts = list(parts)
        self.peer = peer
        self.closed = False
        self.sent = b""
        self.timeouts: list[float] = []

    def SetTimeout(self, value: float) -> None:
        """Observe every remaining-deadline update without renewing a clock."""

        self.timeouts.append(value)

    def Connect(self, address: tuple[str, int]) -> None:
        """Record only the exact supplied literal address."""

        self.address = address

    def GetPeerName(self) -> tuple[str, int]:
        """Expose the selected literal peer for actual-destination verification."""

        return self.peer, 8080

    def SendAll(self, value: bytes) -> None:
        """Capture the one actual exact request without performing I/O."""

        self.sent += value

    def Receive(self, maximum: int) -> bytes:
        """Return at most the requested finite number of scripted response bytes."""

        if not self.parts:
            return b""

        value = self.parts.pop(0)

        if len(value) > maximum:
            self.parts.insert(0, value[maximum:])

        return value[:maximum]

    def Close(self) -> None:
        """Make deterministic transport cleanup observable on every outcome."""

        self.closed = True

    # Preserve the socket interface while implementations follow the callable contract.
    settimeout = SetTimeout
    connect = Connect
    getpeername = GetPeerName
    sendall = SendAll
    recv = Receive
    close = Close


def Header(body: bytes = BODY) -> bytes:
    """Create an independent complete bounded plain response framing fixture."""

    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n")


def MetricsWire(framing: str, body: bytes = DOCUMENT) -> bytes:
    """Build an independent plain response for each explicit metrics-only framing profile."""

    header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"

    if framing == "length":
        return header + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

    if framing == "chunked":
        return (header + b"Transfer-Encoding: chunked\r\n\r\n"
                + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")

    return header + b"\r\n" + body


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    (b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n"
     b"Content-Type: TEXT/PLAIN; charset=utf-8\r\n\r\n"),
    b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /private\r\n\r\n",
])
def test_CompleteFramedNegativeStatusesRemainBoundedObservations(raw: bytes) -> None:
    """Complete 2xx/3xx/4xx responses preserve status without following any Location."""

    status, media, size = worker.Headers(raw)
    assert 200 <= status <= 499 and size == 0, "Finite complete response metadata changed."
    assert media in {"text/plain", "other"}, "Unbounded raw media text was retained."


@pytest.mark.parametrize("raw", [
    b"", b"HTTP/1.1 200 OK\nContent-Length: 0\n\n", b"HTTP/1.1 200\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 00\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: \xff\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n folded\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + b"X: a\r\n" * 64 + b"\r\n",
    b"HTTP/1.1 200 " + b"a" * 4090 + b"\r\nContent-Length: 0\r\n\r\n",
    b"x" * 16385,
])
def test_AmbiguousOrUnboundedHeadersFailClosed(raw: bytes) -> None:
    """Malformed/incomplete/duplicate framing never becomes a negative detector result."""

    with pytest.raises(worker.NativeWebProtocolError):
        worker.Headers(raw)


@pytest.mark.parametrize("extra", [b"Content-Encoding: identity\r\n",
                                   b"Transfer-Encoding: chunked\r\n"])
def test_EncodedResponsesRemainUnassessed(extra: bytes) -> None:
    """Even identity encoding headers cannot silently widen the reviewed framing profile."""

    with pytest.raises(worker.NativeWebResponseError):
        worker.Headers(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + extra + b"\r\n")


def test_ServerFailureIsNotACleanResponse() -> None:
    """HTTP5xx remains a failed/unassessed run regardless of body/predicate shape."""

    with pytest.raises(worker.NativeWebResponseError):
        worker.Headers(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")


@pytest.mark.parametrize("parts", [[Header() + BODY], [Header(), BODY[:2], BODY[2:]],
                                  [Header()[:20], Header()[20:] + BODY]])
def test_ProbeCompletesOneExactRequestAndDiscardsRawBody(
    monkeypatch: pytest.MonkeyPatch, parts: list[bytes],
) -> None:
    """The transient complete body determines a fixed verdict but never enters worker output."""

    transport = FakeSocket(parts)
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    record = worker.Probe("http://127.0.0.1:8080/.git/HEAD", 1.0)
    assert record["matched"] is True, "Complete supported HEAD response was not matched."
    assert record["body_sha256"] == hashlib.sha256(BODY).hexdigest(), "Body attribution changed."
    assert BODY not in CanonicalRecord(record), "Raw Git ref leaked into worker output."
    assert transport.address == ("127.0.0.1", 8080), "Literal destination changed."
    assert transport.sent.startswith(b"GET /.git/HEAD HTTP/1.1\r\n"), "Exact path changed."
    assert transport.closed, "Successful transport was not closed."
    assert len(transport.timeouts) >= 4, "Complete deadline was not reused for every I/O phase."


@pytest.mark.parametrize("parts,peer", [
    ([], "127.0.0.1"), ([Header() + BODY[:-1]], "127.0.0.1"),
    ([Header() + BODY + b"extra"], "127.0.0.1"), ([Header() + BODY, b"x"], "127.0.0.1"),
    ([b"a" * 16384], "127.0.0.1"), ([Header() + BODY], "127.0.0.2"),
])
def test_IncompleteExcessiveAndWrongPeerResponsesAlwaysClose(
    monkeypatch: pytest.MonkeyPatch, parts: list[bytes], peer: str,
) -> None:
    """Truncation, excess bytes, unsupported header size and peer drift fail with cleanup."""

    transport = FakeSocket(parts, peer)
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)

    with pytest.raises(worker.NativeWebProtocolError):
        worker.Probe("http://127.0.0.1:8080/.git/HEAD", 1.0)

    assert transport.closed, "A failed native transport leaked its socket."


def test_HttpsUsesVerifiedDefaultTrustAndLiteralServerName(monkeypatch: pytest.MonkeyPatch) -> None:
    """TLS profile uses the platform default certificate verifier without a trust bypass."""

    transport = FakeSocket([Header() + BODY])

    class Context:
        """Observe fixed TLS setup without substituting a real network or trust decision."""

        def WrapSocket(self, connection, server_hostname):
            """Bind the exact literal peer and keep the fixed modern minimum TLS version."""

            assert server_hostname == "127.0.0.1", "TLS peer identity was silently changed."
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2, "TLS minimum was weakened."

            return connection

        wrap_socket = WrapSocket

    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker.ssl, "create_default_context", Context)
    assert worker.Probe("https://127.0.0.1:8080/.git/HEAD", 1.0)["matched"], (
        "Verified TLS response did not reach the unchanged predicate."
    )


@pytest.mark.parametrize("error,code,name", [
    (TimeoutError("private-detail"), 124, "timeout"),
    (ssl.SSLError("private-detail"), 1, "tls"),
    (worker.NativeWebResponseError("private-detail"), 1, "response-policy"),
    (worker.NativeWebProtocolError("private-detail"), 1, "protocol"),
    (OSError("private-detail"), 1, "connection"), (ValueError("private-detail"), 64, "input"),
])
def test_MainRetainsOnlyFixedSafeFailures(
    monkeypatch: pytest.MonkeyPatch, capsys, error: Exception, code: int, name: str,
) -> None:
    """Exceptions never echo input-derived text or become successful negative checks."""

    def Fail(*_arguments):
        """Inject a deterministic isolated transport/parser failure."""

        raise error

    monkeypatch.setattr(worker, "Probe", Fail)
    assert worker.Main(["http://127.0.0.1/", "1"]) == code, "Failure exit status changed."
    captured = capsys.readouterr()
    assert captured.out.encode() == CanonicalRecord({"schema_version": 1, "error": name}), (
        "Failure metadata retained a raw exception or lost its fixed reason."
    )
    assert not captured.err, "Native worker wrote private exception material to stderr."


def test_MainInputAndSuccessfulOutputRemainCanonical(monkeypatch: pytest.MonkeyPatch, capsys):
    """The module emits only its fixed canonical result or fixed invalid-input failure."""

    assert worker.Main([]) == 64, "Missing input did not fail."
    capsys.readouterr()
    record = {"schema_version": 1, "error": "input"}
    monkeypatch.setattr(worker, "Probe", lambda *_: record)
    assert worker.Main(["http://127.0.0.1/", "1"]) == 0, "Synthetic success exit changed."
    assert capsys.readouterr().out.encode() == CanonicalRecord(record), "Canonical output changed."


@pytest.mark.parametrize("outcome", ["success", "input", "timeout"])
def test_MainBypassesPlatformTextNewlineTranslation(monkeypatch, outcome):
    """Success and failure records retain exact canonical bytes on a Windows-like text stream."""

    output = io.BytesIO()
    stream = io.TextIOWrapper(output, encoding="utf-8", newline="\r\n")
    record = {"schema_version": 1, "matched": True}

    def Probe(*_arguments):
        """Return fixed metadata or reproduce the worker's request-timeout error path."""

        if outcome == "timeout":
            raise TimeoutError

        return record

    arguments = [] if outcome == "input" else ["http://127.0.0.1/", "1"]
    expected = record if outcome == "success" else {"schema_version": 1, "error": outcome}
    expected_code = {"success": 0, "input": 64, "timeout": 124}[outcome]
    monkeypatch.setattr(worker, "Probe", Probe)

    with monkeypatch.context() as output_patch:
        output_patch.setattr(worker.sys, "stdout", stream)
        code = worker.Main(arguments)
        stream.flush()
        actual = output.getvalue()

    assert code == expected_code, "Binary report output changed the truthful worker exit code."
    assert actual == CanonicalRecord(expected), (
        "Platform text translation changed canonical worker report bytes."
    )


def test_ProbeUsesLiteralIpv6WithoutDnsOrAuthorityRewriting(monkeypatch: pytest.MonkeyPatch):
    """The IPv6 path retains its literal peer, bracketed Host and one exact selected request."""

    transport = FakeSocket([Header() + BODY], peer="::1")
    families = []

    def Socket(family, socket_type):
        """Observe address-family selection without opening any real socket."""

        families.append((family, socket_type))

        return transport

    monkeypatch.setattr(worker.socket, "socket", Socket)
    record = worker.Probe("http://[::1]:8080/.git/HEAD", 1.0)
    assert families == [(worker.socket.AF_INET6, worker.socket.SOCK_STREAM)], (
        "A selected IPv6 literal used a different socket family."
    )
    assert transport.address == ("::1", 8080) and record["address"] == "::1", (
        "The selected and observed IPv6 peers must agree exactly."
    )
    assert b"Host: [::1]:8080\r\n" in transport.sent, "IPv6 Host authority lost its brackets."
    assert transport.closed, "The IPv6 native check leaked its transport."


def test_TlsFailureClosesOriginalSocketWithoutDisablingVerification(monkeypatch):
    """A certificate rejection releases the original connection and never retries in plaintext."""

    transport = FakeSocket([])

    class RejectingContext:
        """Model default certificate verification refusing its selected synthetic peer."""

        def WrapSocket(self, connection, server_hostname):
            """Refuse before any HTTP request can be transmitted."""

            assert connection is transport and server_hostname == "127.0.0.1", (
                "TLS verification received a different selected socket or peer."
            )

            raise ssl.SSLCertVerificationError("synthetic-certificate-rejection")

        wrap_socket = WrapSocket

    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker.ssl, "create_default_context", RejectingContext)

    with pytest.raises(ssl.SSLCertVerificationError):
        worker.Probe("https://127.0.0.1:8080/.git/HEAD", 1.0)

    assert transport.closed and not transport.sent, (
        "Rejected TLS must close the original socket without HTTP or plaintext fallback."
    )


def test_ProgressDoesNotRenewTheWholeRequestDeadline(monkeypatch):
    """Partial header progress cannot reset the original monotonic request budget."""

    transport = FakeSocket([b"HTTP/1.1 200", b" OK\r\n", Header()[17:] + BODY])
    readings = iter((0.0, 0.1, 0.2, 0.3, 1.1))
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(readings))

    with pytest.raises(TimeoutError):
        worker.Probe("http://127.0.0.1:8080/.git/HEAD", 1.0)

    assert transport.closed, "A timed-out progressing response leaked its socket."
    assert transport.timeouts == pytest.approx((0.9, 0.8, 0.7)), (
        "The transport renewed its total deadline instead of charging partial progress."
    )


def test_MainUsesProcessArgumentsWithoutLeakingResponseOrCookie(monkeypatch, capsys):
    """Actual Probe and Main retain only fixed metadata when a target sends private-shaped data."""

    body = b"owned-synthetic-private-response"
    headers = Header(body).replace(b"\r\n\r\n", b"\r\nSet-Cookie: owned-cookie-marker\r\n\r\n")
    transport = FakeSocket([headers + body])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker.sys, "argv", ["native-web", "http://127.0.0.1:8080/.git/HEAD", "1"])
    assert worker.Main() == 0, "The bounded complete nonmatch did not finish its native report."
    captured = capsys.readouterr()
    assert body.decode() not in captured.out and "owned-cookie-marker" not in captured.out, (
        "Native stdout leaked transient HTTP response or cookie material."
    )
    assert hashlib.sha256(body).hexdigest() in captured.out and '"matched":false' in captured.out, (
        "The original execution report lost its actual negative response attribution."
    )
    assert not captured.err and transport.closed, "Native completion leaked stderr or transport."


def test_OwnedCanaryProbeKeepsExactQueryAndStructuralReferences(monkeypatch):
    """The real bounded parser uses the selected owned query and emits no original body bytes."""

    url = "http://127.0.0.1:8080/files/vulnerable?name=..%2Fprivate%2Fcanary.txt"
    body = b"owned-private-file-canary\n"
    transport = FakeSocket([Header(body) + body])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    record = worker.Probe(url, 1.0, check_id=NATIVE_FILE_CANARY_CHECK_ID,
                          workspace_id="owned-canary")
    template = NativeFileCanaryTemplate("owned-canary", url)
    assert record["matched"] is True and record["request_reference"] == template.Reference(), (
        "The fixed owned response lost its declared predicate or request identity."
    )
    assert record["injection_reference"] == template.injection_points[0].Reference(
        template.Reference()), "The query coordinate lost its owning request binding."
    assert transport.sent.startswith(
        b"GET /files/vulnerable?name=..%2Fprivate%2Fcanary.txt HTTP/1.1\r\n"), (
        "The worker rewrote or omitted the explicitly selected fixed query."
    )
    assert body not in CanonicalRecord(record) and transport.closed, (
        "The worker retained raw response bytes or leaked its transport."
    )


@pytest.mark.parametrize("url,workspace_id", [
    ("http://192.0.2.1/files/vulnerable?name=hello.txt", "owned-canary"),
    ("http://127.0.0.1/other?name=hello.txt", "owned-canary"),
    ("http://127.0.0.1/files/vulnerable?name=hello.txt", None),
])
def test_OwnedCanaryWorkerRejectsUnreviewedInputBeforeSocket(monkeypatch, url, workspace_id):
    """The isolated worker independently enforces its closed local profile before any transport."""

    def RefuseSocket(*_arguments):
        """Expose any attempted transport for an input outside the fixed local profile."""

        raise AssertionError("unreviewed native input reached the socket boundary")

    monkeypatch.setattr(worker.socket, "socket", RefuseSocket)

    with pytest.raises(ValueError):
        worker.Probe(url, 1.0, check_id=NATIVE_FILE_CANARY_CHECK_ID, workspace_id=workspace_id)


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
@pytest.mark.parametrize("body", [DOCUMENT, DOCUMENT + b"# padding\n" * 600, b"not metrics\n"])
def test_MetricsOnlyFramingRetainsNoMetricValues(monkeypatch, framing, body):
    """All admitted metrics transports consume complete bodies and retain only safe metadata."""

    wire = MetricsWire(framing, body)
    transport = FakeSocket([wire[:11], wire[11:97], wire[97:]])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    record = worker.Probe("http://127.0.0.1:8080/metrics", 1.0,
                          check_id=NATIVE_PROMETHEUS_CHECK_ID)
    assert record["matched"] is body.startswith(DOCUMENT), "Complete metrics verdict changed."
    assert record["body_bytes"] == len(body), "Decoded-body length changed with framing."
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest(), "Body hash drifted."
    assert "active_jobs" not in CanonicalRecord(record).decode(), "Metric names leaked."
    assert b"Accept-Encoding: identity\r\n" in transport.sent, "Identity encoding was omitted."
    assert transport.closed and len(transport.sent.split(b"GET ")) == 2, "Request/cleanup drifted."


@pytest.mark.parametrize("wire", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 262145\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension=yes\r\nx\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: x\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxXX0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40001\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"0" * 33,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1\r\nx\r\n" * 4097
    + b"0\r\n\r\n",
    MetricsWire("eof", b"x" * 262145),
])
def test_MetricsFramingRefusesAmbiguityTruncationAndIndependentBounds(monkeypatch, wire):
    """Malformed, ambiguous, overlong and excessive-chunk responses remain unassessed failures."""

    transport = FakeSocket([wire])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)

    with pytest.raises(worker.NativeWebProtocolError):
        worker.Probe("http://127.0.0.1:8080/metrics", 1.0,
                     check_id=NATIVE_PROMETHEUS_CHECK_ID)

    assert transport.closed, "A rejected metrics wire leaked its socket."


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
def test_MetricsWireBudgetIsIndependentOfDecodedBody(monkeypatch, framing):
    """A small body cannot hide a separately exhausted total wire-byte budget."""

    transport = FakeSocket([MetricsWire(framing)[:80], MetricsWire(framing)[80:]])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker, "MAX_PROMETHEUS_WIRE_BYTES", 80)

    with pytest.raises(worker.NativeWebProtocolError):
        worker.Probe("http://127.0.0.1:8080/metrics", 1.0,
                     check_id=NATIVE_PROMETHEUS_CHECK_ID)

    assert transport.closed, "Wire-budget exhaustion leaked its socket."


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
@pytest.mark.parametrize("late_phase", ["header", "body", "eof", "predicate"])
def test_MetricsProgressNeverRenewsDeadlineIncludingFinalEof(monkeypatch, framing, late_phase):
    """Late returning reads and predicate parsing cannot finish after the original deadline."""

    wire = MetricsWire(framing)
    boundary = wire.index(b"\r\n\r\n") + 4
    transport = FakeSocket([wire[:boundary], wire[boundary:]])
    now = [0.0]
    original_receive = transport.recv

    def Receive(maximum):
        """Advance a deterministic shared clock on one selected actual I/O boundary."""

        before = len(transport.parts)
        part = original_receive(maximum)

        if (late_phase == "header" and before == 2 or
            late_phase == "body" and before == 1 or late_phase == "eof" and not part):
            now[0] = 1.1

        return part

    monkeypatch.setattr(transport, "recv", Receive)
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    monkeypatch.setattr(worker.time, "monotonic", lambda: now[0])

    if late_phase == "predicate":
        original_check = worker.NativeWebCheckFor(NATIVE_PROMETHEUS_CHECK_ID)

        def Predicate(*_args):
            """Model bounded interpretation returning after the same original deadline."""

            now[0] = 1.1

            return True

        monkeypatch.setattr(worker, "NativeWebCheckFor",
                            lambda _: replace(original_check, predicate=Predicate))

    with pytest.raises(TimeoutError):
        worker.Probe("http://127.0.0.1:8080/metrics", 1.0,
                     check_id=NATIVE_PROMETHEUS_CHECK_ID)

    assert transport.closed, "Total-deadline exhaustion leaked its metrics socket."


def test_MetricsMainSelectsExplicitCheckAndStillUsesCanonicalOutput(monkeypatch, capsys):
    """The new worker argv adds an exact check identity without changing old default invocations."""

    transport = FakeSocket([MetricsWire("chunked")])
    monkeypatch.setattr(worker.socket, "socket", lambda *_: transport)
    assert worker.Main(["http://127.0.0.1:8080/metrics", "1", NATIVE_PROMETHEUS_CHECK_ID]) == 0
    captured = capsys.readouterr()
    assert '"check_id":"native.prometheus-exposition"' in captured.out, "Check identity drifted."
    assert "active_jobs" not in captured.out and not captured.err, "Transient metrics leaked."
