# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic single-socket wire, shared-deadline and refusal non-retention checks."""

from __future__ import annotations

import base64
import io
import socket
from types import SimpleNamespace

import pytest

from fuzzy1337 import owned_response_capture_worker as worker
from fuzzy1337.adapters import SerializeContract
from tests.unit.test_owned_response_capture import ORACLE, Record


@pytest.fixture
def wire(monkeypatch):
    """Own one finite socket double; no unit test contacts any listener or resolves a name."""

    state = SimpleNamespace(chunks=[], sockets=[], sent=[], destinations=[], timeouts=[],
        family=None, peer=None, closed=False, failure=None, now=0.0, phase_seconds=0.0)

    class Connection:
        """Expose only controlled original socket observations and finite selected operations."""

        def __enter__(self):
            """Return this already owned test connection."""

            return self

        def __exit__(self, *args):
            """Record socket closure on every success or refusal path."""

            state.closed = True

        def SetTimeout(self, value):
            """Record the remaining shared deadline supplied before a socket operation."""

            state.timeouts.append(value)

        def Connect(self, destination):
            """Record the sole literal destination without actual DNS or network access."""

            state.destinations.append(destination)
            state.now += state.phase_seconds

            if state.failure is not None:
                raise state.failure

        def GetPeerName(self):
            """Return only the actual selected test peer unless a mismatch is requested."""

            return state.destinations[0] if state.peer is None else state.peer

        def SendAll(self, raw):
            """Retain exactly the actual buffer handed to the one successful send operation."""

            state.sent.append(raw)
            state.now += state.phase_seconds

        def Receive(self, maximum):
            """Honor requested read bounds with independently fragmented response chunks."""

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
        """Create exactly one owned socket double with the literal selected address family."""

        assert kind == socket.SOCK_STREAM, "The fixed worker must use only a direct stream socket."
        state.family = family
        result = Connection()
        state.sockets.append(result)

        return result

    monkeypatch.setattr(worker, "socket", SimpleNamespace(AF_INET=socket.AF_INET,
        AF_INET6=socket.AF_INET6, SOCK_STREAM=socket.SOCK_STREAM, socket=Socket))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: state.now))

    return state


def RunMain(monkeypatch, arguments):
    """Observe exact worker streams without a subprocess or any production policy substitute."""

    output = io.BytesIO()
    errors = io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(argv=["fixed-worker", *arguments],
        stdout=SimpleNamespace(buffer=output), stderr=errors))
    code = worker.Main()

    return code, output.getvalue(), errors.getvalue()


@pytest.mark.parametrize("case_id", ["missing", "fixed", "body-decoy"])
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_OneExactLiteralGetAdmitsOnlyCompleteReviewedOriginals(wire, monkeypatch, case_id, address):
    """Each known response is captured with exact original sent bytes and verified EOF."""

    record = Record(case_id, address)
    case = next(case for case in ORACLE["cases"] if case["case_id"] == case_id)
    raw = base64.b64decode(case["response"]["base64"])
    wire.chunks = [raw[:17], raw[17:101], raw[101:]]
    code, output, errors = RunMain(monkeypatch, [record["url"]])
    assert code == 0 and output == SerializeContract(record).encode() and errors == "", (
        "Success must emit only the independently expected canonical no-newline original record."
    )
    assert wire.sent == [base64.b64decode(record["request"]["base64"])], (
        "The retained request must be exactly the one actual buffer sent with no implicit headers."
    )
    assert wire.destinations == [(address, 19008)] and len(wire.sockets) == 1 and wire.closed, (
        "The worker must connect once to the exact literal family/address/port and close it."
    )
    assert wire.family == (socket.AF_INET6 if address == "::1" else socket.AF_INET), (
        "Literal family selection must never resolve or replace the approved destination."
    )


@pytest.mark.parametrize("kind", ["header", "body", "trailing", "truncated", "incomplete-header",
                                  "header-limit", "no-eof"])
def test_RejectedResponseNeverPublishesBytesOrContentHashes(wire, monkeypatch, kind):
    """First closed refusal preserves no rejected material and does not hash rejected parts."""

    record = Record()
    headers = base64.b64decode(record["response_headers"]["base64"])
    body = base64.b64decode(record["response_body"]["base64"])
    expected = "protocol"

    if kind == "header":
        wire.chunks = [headers.replace(b"Connection: close", b"PRIVATE: SECRET_MARKER") + body]
        expected = "response-policy"

    elif kind == "body":
        wire.chunks = [headers + b"X" * len(body)]
        expected = "body-policy"

    elif kind == "trailing":
        wire.chunks = [headers + body, b"PRIVATE_SECRET_MARKER"]

    elif kind == "truncated":
        wire.chunks = [headers + body[:-1]]

    elif kind == "incomplete-header":
        wire.chunks = [b"HTTP/1.1 200 OK\r\nPRIVATE_SECRET_MARKER"]

    elif kind == "header-limit":
        wire.chunks = [b"X" * (16384 + 1)]

    else:
        wire.chunks = [headers + body, TimeoutError("PRIVATE_SECRET_MARKER")]
        expected = "timeout"

    def NoHash(*args):
        """Fail if rejected bytes reach a content hash or emitted byte-part descriptor."""

        pytest.fail("Rejected original response bytes must not be hashed or published")

    monkeypatch.setattr(worker, "BytePart", NoHash)
    monkeypatch.setattr(worker, "hashlib", SimpleNamespace(sha256=NoHash))
    code, output, errors = RunMain(monkeypatch, [record["url"]])
    refusal = {"schema_version": 1, "profile": "owned-response-capture.v1", "outcome": "refused",
               "error": expected}
    assert code == 2 and output == SerializeContract(refusal).encode() and not errors, (
        "A refusal must contain only its safe four-field closed record and untouched stderr."
    )
    assert b"PRIVATE" not in output and wire.closed, "Rejected content must stay transient."


@pytest.mark.parametrize("peer", [("127.0.0.2", 19008), ("127.0.0.1", 19009)])
def test_ActualPeerAddressAndPortMustBothMatchBeforeSend(wire, monkeypatch, peer):
    """A connected socket is not enough when its actual peer differs from the selected literal."""

    wire.peer = peer
    code, output, errors = RunMain(monkeypatch, [Record()["url"]])
    assert code == 2 and b'"error":"protocol"' in output and not errors and not wire.sent, (
        "Peer mismatch must refuse before sending a request or retaining response fragments."
    )


def test_ProgressCannotRenewTheSingleFiveSecondBudget(wire, monkeypatch):
    """Connect, send, fragmented reads and final EOF consume the same fixed monotonic budget."""

    record = Record()
    wire.chunks = [base64.b64decode(record["response_headers"]["base64"]),
                   base64.b64decode(record["response_body"]["base64"])]
    wire.phase_seconds = 1.0
    code, output, errors = RunMain(monkeypatch, [record["url"]])
    assert code == 2 and b'"error":"timeout"' in output and not errors, (
        "Even an exact body cannot be admitted when actual EOF reaches the shared deadline."
    )
    assert wire.timeouts == [5.0, 4.0, 3.0, 2.0, 1.0] and wire.now == 5.0, (
        "Progress must monotonically consume the original request allowance without renewal."
    )


def test_ConnectionFailureHasNoRetryOrDiagnosticEcho(wire, monkeypatch):
    """The first direct connection error produces one safe refusal without a second socket."""

    wire.failure = OSError("PRIVATE_SECRET_MARKER")
    code, output, errors = RunMain(monkeypatch, [Record()["url"]])
    assert code == 2 and b'"error":"connection"' in output and not errors, (
        "Network exception text cannot become retained response diagnostics."
    )
    assert len(wire.sockets) == len(wire.destinations) == 1 and wire.closed and not wire.sent, (
        "Connection refusal must not retry, redirect or contact a second destination."
    )


@pytest.mark.parametrize("arguments", [[], ["http://localhost:19008/zap-passive/missing"],
    ["http://127.0.0.1:19008/zap-passive/missing", "--timeout=10"], [None]])
def test_InvalidFixedInputRefusesWithoutAnySocketOrEcho(wire, monkeypatch, arguments):
    """No alternate input grammar or caller flag can reach socket creation."""

    code, output, errors = RunMain(monkeypatch, arguments)
    assert code == 2 and b'"error":"input"' in output and not errors and not wire.sockets, (
        "Input refusal must remain canonical, non-retaining and before connection."
    )
