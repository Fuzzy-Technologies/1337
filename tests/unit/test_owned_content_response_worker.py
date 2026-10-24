# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite fake-socket acquisition proves framing, original deadlines and refusal privacy."""

from __future__ import annotations

import base64
import io
import socket
from types import SimpleNamespace

import pytest

from fuzzy1337 import owned_content_response_worker as worker
from fuzzy1337.adapters import SerializeContract
from tests.unit.test_owned_content_response import URL, Headers, Record


@pytest.fixture
def wire(monkeypatch):
    """Own a finite direct socket double without opening any actual socket or listener."""

    state = SimpleNamespace(chunks=[], sent=[], destinations=[], timeouts=[], maxima=[],
        family=None, peer=None, closed=False, failure=None, now=0.0, phase_seconds=0.0, sockets=0)

    class Connection:
        """Expose only the exact worker socket operations under one controlled clock."""

        def __enter__(self):
            """Return the already controlled connection."""

            return self

        def __exit__(self, *args):
            """Retain actual closure on every return and error path."""

            state.closed = True

        def SetTimeout(self, value):
            """Record the original remaining deadline supplied to a blocking operation."""

            state.timeouts.append(value)

        def Connect(self, destination):
            """Record one literal destination and optionally fail without a retry."""

            state.destinations.append(destination)
            state.now += state.phase_seconds

            if state.failure is not None:
                raise state.failure

        def GetPeerName(self):
            """Expose the actual selected peer or an explicit mismatch."""

            return state.destinations[0] if state.peer is None else state.peer

        def SendAll(self, raw):
            """Retain the exact buffer actually handed to the send operation."""

            state.sent.append(raw)
            state.now += state.phase_seconds

        def Receive(self, maximum):
            """Honor read bounds and consume a finite sequence of bytes or explicit errors."""

            state.maxima.append(maximum)
            state.now += state.phase_seconds

            if not state.chunks:
                return b""

            item = state.chunks[0]

            if isinstance(item, BaseException):
                raise item

            raw, state.chunks[0] = item[:maximum], item[maximum:]

            if not state.chunks[0]:
                state.chunks.pop(0)

            return raw

        settimeout = SetTimeout
        connect = Connect
        getpeername = GetPeerName
        sendall = SendAll
        recv = Receive

    def Socket(family, kind):
        """Count one socket of the exact literal IP family, without any system call."""

        assert kind == socket.SOCK_STREAM, "Only one direct TCP stream may be created."
        state.family = family
        state.sockets += 1

        return Connection()

    monkeypatch.setattr(worker, "socket", SimpleNamespace(AF_INET=socket.AF_INET,
        AF_INET6=socket.AF_INET6, SOCK_STREAM=socket.SOCK_STREAM, socket=Socket))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: state.now))

    return state


def RunMain(monkeypatch, arguments, explicit=False):
    """Retain only actual worker output in memory without process or network execution."""

    output, errors = io.BytesIO(), io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(argv=["worker", *arguments],
        stdout=SimpleNamespace(buffer=output), stderr=errors))
    code = worker.Main(arguments if explicit else None)

    return code, output.getvalue(), errors.getvalue()


@pytest.mark.parametrize("address", ["127.0.0.1", "[::1]"])
@pytest.mark.parametrize("body", [b"", b"new content", "\ufeffUTF-8 é".encode(), b"x" * 65536])
def test_ActualSentBufferAndCompleteOriginalsNeedTimelyEof(wire, monkeypatch, address, body):
    """Both literal families admit arbitrary content and explicitly probe EOF at the body cap."""

    url = f"http://{address}:19008/new-owned/path/"
    headers = Headers(body, extra=b"Server: changing\r\nX-Content-Type-Options:\r\n")
    record = Record(body, headers, url)
    wire.chunks = [headers[:7], headers[7:], body] if body else [headers[:7], headers[7:]]
    code, raw, errors = RunMain(monkeypatch, [url], explicit=True)
    assert code == 0 and raw == SerializeContract(record).encode() and not errors, (
        "Success must equal independently handwritten exact originals, without a newline."
    )
    assert wire.sent == [base64.b64decode(record["request"]["base64"])] and (
        wire.destinations == [("::1" if address == "[::1]" else address, 19008)]
        and wire.sockets == 1 and wire.closed
    ), "Only one exact literal request may be sent and the original socket must close."
    assert wire.maxima[-1] == 1 and all(size > 0 for size in wire.maxima), (
        "Even an empty or maximum body needs an actual bounded one-byte EOF probe."
    )
    assert wire.family == (socket.AF_INET6 if address == "[::1]" else socket.AF_INET), (
        "Literal socket family must match actual selected authority without DNS."
    )


@pytest.mark.parametrize("kind,error", [("truncated", "protocol"), ("trailing", "protocol"),
    ("initial-trailing", "protocol"), ("max-extra", "protocol"), ("no-header", "protocol"),
    ("header-cap", "response-policy"), ("status", "response-policy"),
    ("private", "response-policy"),
    ("cl-over", "body-policy"), ("cl-huge", "body-policy"), ("cl-duplicate", "protocol"),
    ("cl-noncanonical", "protocol"), ("line-cap", "response-policy"),
    ("field-cap", "response-policy"),
    ("utf8", "body-policy"), ("no-eof", "timeout")])
def test_RefusalContainsNoRejectedBytesOrHashes(wire, monkeypatch, kind, error):
    """Refused material never reaches hashing, byte descriptors, stdout or stderr."""

    body = b"new body"
    headers = Headers(body)
    wire.chunks = [headers, body]

    if kind == "truncated":
        wire.chunks = [headers, body[:-1]]

    elif kind == "trailing":
        wire.chunks.append(b"PRIVATE_MARKER")

    elif kind == "initial-trailing":
        wire.chunks = [headers + body + b"PRIVATE_MARKER"]

    elif kind == "max-extra":
        wire.chunks = [Headers(b"x" * 65536), b"x" * 65536, b"x"]

    elif kind == "no-header":
        wire.chunks = [b"HTTP/1.1 200 OK\r\nPRIVATE_MARKER"]

    elif kind == "header-cap":
        wire.chunks = [b"x" * 16384]

    elif kind == "status":
        wire.chunks = [headers.replace(b"200 OK", b"302 Found"), body]

    elif kind == "private":
        wire.chunks = [Headers(extra=b"Set-Cookie: PRIVATE_MARKER\r\n"), body]

    elif kind in {"cl-over", "cl-huge", "cl-noncanonical"}:
        length = {"cl-over": b"65537", "cl-huge": b"9" * 1000, "cl-noncanonical": b"08"}[kind]
        wire.chunks = [headers.replace(b"Length: 8", b"Length: " + length)]

    elif kind == "cl-duplicate":
        wire.chunks = [Headers(extra=b"content-length: 8\r\n")]

    elif kind == "line-cap":
        wire.chunks = [Headers(extra=b"X: " + b"x" * 4092 + b"\r\n")]

    elif kind == "field-cap":
        wire.chunks = [Headers(extra=b"".join(f"X-{n}: a\r\n".encode() for n in range(62)))]

    elif kind == "utf8":
        wire.chunks = [Headers(b"\xff"), b"\xff"]

    elif kind == "no-eof":
        wire.chunks.append(TimeoutError("PRIVATE_MARKER"))

    def NoHash(*args):
        """Expose any attempt to retain or hash bytes before complete source admission."""

        pytest.fail("Rejected bytes cannot reach retained byte descriptors or content hashes")

    monkeypatch.setattr(worker, "BytePart", NoHash)
    monkeypatch.setattr(worker, "hashlib", SimpleNamespace(sha256=NoHash))
    code, raw, errors = RunMain(monkeypatch, [URL])
    assert code == 2 and raw == SerializeContract({"schema_version": 1,
        "profile": "owned-content-response-capture.v1", "outcome": "refused", "error": error}
    ).encode() and not errors, "Only the exact four safe refusal fields may be emitted."
    assert b"PRIVATE_MARKER" not in raw and wire.closed, (
        "Rejected source material must remain transient and the actual socket must close."
    )


def test_ReadProgressCannotRenewTheOriginalFiveSecondDeadline(wire, monkeypatch):
    """A complete body whose original EOF arrives at expiry remains a timeout."""

    wire.chunks = [Headers(), b"new body"]
    wire.phase_seconds = 1.0
    code, raw, errors = RunMain(monkeypatch, [URL])
    assert code == 2 and b'"error":"timeout"' in raw and not errors and wire.closed, (
        "A late successful read must still refuse without publishing a source."
    )
    assert wire.timeouts == [5.0, 4.0, 3.0, 2.0, 1.0] and wire.now == 5.0, (
        "Connect/send/header/body/EOF must consume one common absolute deadline."
    )


@pytest.mark.parametrize("peer", [("127.0.0.2", 19008), ("127.0.0.1", 19009)])
def test_ActualPeerMismatchRefusesBeforeSending(wire, monkeypatch, peer):
    """The actual address and port are both checked before the sole request buffer."""

    wire.peer = peer
    code, raw, errors = RunMain(monkeypatch, [URL])
    assert code == 2 and b'"error":"protocol"' in raw and not errors and not wire.sent, (
        "Selected target text cannot substitute a different connected peer."
    )


def test_FirstConnectionErrorNeverRetriesOrEchoesDiagnostics(wire, monkeypatch):
    """The first connection error closes its sole socket and retains only a safe category."""

    wire.failure = OSError("PRIVATE_MARKER")
    code, raw, errors = RunMain(monkeypatch, [URL])
    assert code == 2 and b'"error":"connection"' in raw and not errors and wire.closed, (
        "Connection failures must remain safe closed refusals."
    )
    assert wire.sockets == 1 and not wire.sent and b"PRIVATE_MARKER" not in raw, (
        "No retry or diagnostic echo may follow a refused connection."
    )


@pytest.mark.parametrize("arguments", [[], [URL, URL], ["http://localhost:19008/x"]])
def test_UnsupportedInputsCreateNoSocket(wire, monkeypatch, arguments):
    """Wrong argument counts and unsupported URLs fail before any network operation."""

    code, raw, errors = RunMain(monkeypatch, arguments)
    assert code == 2 and b'"error":"input"' in raw and not errors and wire.sockets == 0, (
        "Invalid selection cannot create a socket or retain arbitrary input diagnostics."
    )
