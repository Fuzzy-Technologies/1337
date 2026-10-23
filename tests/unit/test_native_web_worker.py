# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Network-free strict native HTTP framing, transient-body and safe-error contracts."""

from __future__ import annotations

import hashlib
import io
import ssl

import pytest

from fuzzy1337 import native_web_worker as worker
from fuzzy1337.adapters.native_web import CanonicalRecord

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
