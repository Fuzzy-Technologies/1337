# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite fake socket/state counterexamples; no real listener, socket, thread or worker."""

from __future__ import annotations

import errno
import json
import socket
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_target as target
from tests.contract.owned_content_response_oracle import PRIMARY_PATH, RequestBytes


class FakeContentConnection:
    """Expose finite fake receive/send/close facts without an OS descriptor or transport."""

    def __init__(self, request: bytes,
        terminal: bytes | OSError | Callable[[], bytes] = b"") -> None:
        """Select two exact fake receive results and bounded short-write behavior."""

        self.receives = [request, terminal]
        self.sent = bytearray()
        self.shutdowns = []
        self.timeouts = []
        self.closed = False

    def SetTimeout(self, remaining: float) -> None:
        """Retain the original remaining bound without sleeping or renewing time."""

        self.timeouts.append(remaining)

    def Recv(self, maximum: int) -> bytes:
        """Return only the next explicit modeled original receive."""

        value = self.receives.pop(0)

        if callable(value):
            value = value()

        if isinstance(value, OSError):
            raise value

        if len(value) > maximum:
            self.receives.insert(0, value[maximum:])

        return value[:maximum]

    def Send(self, raw: bytes) -> int:
        """Return finite original short-send counts so complete-wire accounting is exercised."""

        count = min(17, len(raw))
        self.sent.extend(raw[:count])

        return count

    def Shutdown(self, direction: int) -> None:
        """Observe only the modeled local shutdown direction."""

        self.shutdowns.append(direction)

    def Close(self) -> None:
        """Record actual modeled close before source ownership can become idle."""

        self.closed = True

    settimeout = SetTimeout
    recv = Recv
    send = Send
    shutdown = Shutdown
    close = Close


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("case", ["missing", "held-eof"])
def test_ActualSourceHandlerUsesOneDeadlineAndSeparatesHeldPeerFromSentEof(address, case) -> None:
    """Exercise the source handler with fake descriptors; all clocks and bytes remain finite."""

    authority = "[::1]" if address == "::1" else address
    source = target.MutableContentSource("http://" + authority + ":15432", case)
    state = target.ContentResponseState(source, clock=lambda: 10.0)
    request = RequestBytes(source.Url())
    connection = FakeContentConnection(request)
    state.Accept(connection)
    state.RecordEndpoints(connection, (address, 33123), (address, 15432))
    handler = object.__new__(target.ContentResponseHandler)
    handler.server, handler.request = SimpleNamespace(state=state), connection
    handler.Handle()
    observation, = state.Observe()
    assert observation.deadline_at == 17.0 and observation.request_bytes == request, (
        "Original accept deadline and request bytes must survive every receive/send phase")
    assert bytes(connection.sent) == source.Response(PRIMARY_PATH).Wire() and (
        observation.sent_bytes == len(connection.sent)), "Keep exact original short-send totals"
    assert state.request_ready.is_set() and state.body_sent.is_set(), (
        "Local readiness must follow the actual modeled request and complete sends")

    if case == "held-eof":
        signal = state.EndpointFacts()[0]["peer_terminal"]
        assert signal["kind"] == "eof" and signal["before_local_close"] is True and (
            signal["within_hold"] is True), "Held EOF requires an original timely peer observation"
        assert connection.shutdowns == [] and observation.admission_state == "sent-peer-ended", (
            "Held source must not manufacture a local EOF before the original peer exits")

    else:
        signal = state.EndpointFacts()[0]["peer_terminal"]
        assert signal is not None and signal["kind"] == "eof" and (
            signal["before_local_close"] is True and signal["within_hold"] is True), (
                "Normal one-GET completion requires actual timely peer EOF after local half-close")
        assert connection.shutdowns == [socket.SHUT_WR] and (
            observation.admission_state == "completed"), "Ordinary source sends its own final EOF"

    state.CloseConnection(connection)
    assert connection.closed and state.WaitIdle(0) and state.Errors() == (), (
        "Physical close and original handler/dispatch idleness must precede reuse")
    assert all(remaining == 7 for remaining in connection.timeouts), (
        "Finite constant-clock sends cannot renew the original source deadline")


def NormalTailCase(terminal: bytes | OSError | Callable[[], bytes],
    *, clock: list[float] | None = None):
    """Run only the original normal handler using finite explicitly selected fake receive facts."""

    selected_clock = [10.0] if clock is None else clock
    source = target.MutableContentSource("http://127.0.0.1:15432", "missing")
    state = target.ContentResponseState(source, clock=lambda: selected_clock[0])
    request = RequestBytes(source.Url())
    connection = FakeContentConnection(request, terminal)
    state.Accept(connection)
    state.RecordEndpoints(connection, ("127.0.0.1", 33123), ("127.0.0.1", 15432))
    handler = object.__new__(target.ContentResponseHandler)
    handler.server, handler.request = SimpleNamespace(state=state), connection

    return state, connection, handler, request


@pytest.mark.parametrize("tail", [b"!", b"GET /alternate/plain HTTP/1.1\r\nHost: "
    b"127.0.0.1:15432\r\n\r\n", b"x" * 4096], ids=["late-byte", "late-second-get", "tail-overflow"])
def test_NormalRequestTailIsObservedAndNeverCreditedAsOneCompleteGet(tail) -> None:
    """A late tail after the first terminator must change original facts and refuse completion."""

    state, connection, handler, request = NormalTailCase(tail)
    handler.Handle()
    observation, = state.Observe()
    expected_prefix = (request + tail)[:2049]
    assert observation.request_bytes == expected_prefix and observation.received_bytes == (
        len(expected_prefix)), "Actual late request bytes must be retained within the original cap"
    assert observation.failure is not None and observation.completion_sequence is None and (
        state.Counters()["completed_responses"] == 0), "A late follow-up cannot pass strict one GET"
    signal = state.EndpointFacts()[0]["peer_terminal"]
    assert signal["kind"] == "unexpected-data" and signal["before_local_close"] is True, (
        "Actual trailing receive data is distinct from EOF or a local teardown artifact")
    assert connection.shutdowns == [socket.SHUT_WR], "Tail inspection follows original half-close"
    state.CloseConnection(connection)
    assert connection.closed and state.WaitIdle(0), "Refused tail still settles original owners"


@pytest.mark.parametrize("terminal,kind", [
    (TimeoutError("PRIVATE-TAIL-ERROR"), "timeout"),
    (OSError(123456, "PRIVATE-TAIL-ERROR"), "os-error"),
    (ConnectionResetError(errno.ECONNRESET, "PRIVATE-TAIL-ERROR"), "peer-reset"),
])
def test_NormalRequestTailErrorRetainsClassWithoutInventingCompleteEof(terminal, kind) -> None:
    """Timeout/unknown/reset records remain honest and cannot prove a complete normal stream."""

    state, connection, handler, request = NormalTailCase(terminal)
    handler.Handle()
    observation, = state.Observe()
    assert observation.failure is not None and observation.completion_sequence is None, (
        "Normal completion needs actual complete EOF, never timeout, unknown or reset inference")
    signal = state.EndpointFacts()[0]["peer_terminal"]
    assert signal["kind"] == kind and "PRIVATE-TAIL-ERROR" not in json.dumps(signal), (
        "Keep bounded original error class/code without raw exception text")
    assert observation.request_bytes == request and observation.deadline_at == 17.0, (
        "A failed tail receive neither invents bytes nor renews the original deadline")
    state.CloseConnection(connection)
    assert connection.closed and state.WaitIdle(0), "Failed tail reads still settle original owners"


@pytest.mark.parametrize("mode", ["late-eof", "late-data", "local-close-eof"])
def test_NormalRequestTailLateOrLocalReadNeverCompletesOriginalDeadline(mode) -> None:
    """A receive returning late or after local admission close retains its actual failed facts."""

    clock = [10.0]
    holder = []

    def Terminal():
        """Select only one finite read interleaving, without a wall timer or thread."""

        if mode == "local-close-eof":
            holder[0].CloseAdmission()

        else:
            clock[0] = 17.0

        return b"x" if mode == "late-data" else b""

    state, connection, handler, request = NormalTailCase(Terminal, clock=clock)
    holder.append(state)
    handler.Handle()
    observation, = state.Observe()
    assert observation.failure is not None and observation.completion_sequence is None, (
        "Late/local returns must not manufacture timely normal request completion")
    signal = state.EndpointFacts()[0]["peer_terminal"]
    expected_kind = {"late-eof": "eof", "late-data": "unexpected-data",
        "local-close-eof": "local-teardown"}[mode]
    assert signal["kind"] == expected_kind and signal["within_hold"] is (mode == (
        "local-close-eof")), "Retain actual EOF/data/local and original deadline facts separately"
    assert observation.request_bytes == request + (b"x" if mode == "late-data" else b""), (
        "Even a late rejected receive remains original target-side byte evidence")
    state.CloseConnection(connection)
    assert connection.closed and state.WaitIdle(0), "Late/local reads still settle original owners"


@pytest.mark.parametrize("owner", ["connection", "handler", "dispatch"])
def test_MutableSameUrlRejectsEveryFalseIdleOriginalOwner(owner) -> None:
    """Changing headers/body must never race a leftover accepted socket, handler or slot owner."""

    source = target.MutableContentSource("http://127.0.0.1:15432")
    state = target.ContentResponseState(source, clock=lambda: 10.0)
    connection = FakeContentConnection(b"")

    if owner == "connection":
        state.connections[connection] = SimpleNamespace()

    elif owner == "handler":
        state.running_handlers.add(connection)

    else:
        state.dispatch_owners.add(connection)

    with pytest.raises(RuntimeError, match="original owners idle"):
        source.SetCase("fixed")

    state.connections.clear()
    state.running_handlers.clear()
    state.dispatch_owners.clear()
    original_url = source.Url()
    original_wire = source.Response(PRIMARY_PATH).Wire()
    source.SetCase("fixed")
    assert source.Url() == original_url and source.Response(PRIMARY_PATH).Wire() != original_wire, (
        "A local mutation changes actual bytes while preserving the exact selected URL")


@pytest.mark.parametrize("local_close,now", [(True, 10.0), (False, 17.0)])
def test_LateOrLocallyInducedPeerEofNeverProvesTimelyRemoteTermination(local_close, now) -> None:
    """Teardown-induced EOF and the exclusive original source deadline remain failed proof."""

    clock = [10.0]
    state = target.ContentResponseState(target.MutableContentSource("http://127.0.0.1:15432",
        "held-eof"), clock=lambda: clock[0])
    connection = FakeContentConnection(b"")
    state.Accept(connection)
    state.RecordEndpoints(connection, ("127.0.0.1", 33123), ("127.0.0.1", 15432))
    clock[0] = now

    if local_close:
        state.CloseAdmission()

    assert state.RecordHeldTerminal(connection, data=b"") is False, (
        "Only timely original peer termination before local close can satisfy the held fixture")
    signal = state.EndpointFacts()[0]["peer_terminal"]
    assert signal["kind"] == ("local-teardown" if local_close else "eof") and (
        signal["within_hold"] is (not now == 17.0)), "Keep actual signal and timing facts separate"


def test_PreCloseIdleWaitRetainsOriginalDeadlineAndDispatchOwnership(monkeypatch) -> None:
    """Physical socket closure cannot make a still-owned dispatch slot disappear from the wait."""

    state = target.ContentResponseState(target.MutableContentSource("http://127.0.0.1:15432"),
        clock=lambda: 15.0)
    connection = FakeContentConnection(b"")
    state.dispatch_owners.add(connection)
    state.original_deadlines[connection] = 17.0
    waits = []

    def WaitIdle(remaining):
        """Record only one modeled original-deadline Event wait without sleeping."""

        waits.append(remaining)

        return False

    monkeypatch.setattr(state, "WaitIdle", WaitIdle)
    assert state.WaitOriginalIdle() is False and waits == [2.0], (
        "Idle wait must retain the last original dispatch owner and only its remaining time")
    assert state.original_deadlines[connection] == 17.0 and connection in state.dispatch_owners, (
        "Waiting cannot renew an original deadline or manufacture dispatch-slot release")


@pytest.mark.parametrize("failure", ["constructor", "body", "cleanup", "wait"])
def test_TargetFinallyRetainsOriginalOwnerStateAndCleanupFailure(monkeypatch, failure) -> None:
    """Finite source-owner doubles retain failures before any assertion can hide final facts."""

    records = []
    source = target.MutableContentSource("http://127.0.0.1:15432")
    state = target.ContentResponseState(source, clock=lambda: 10.0)
    descriptor = SimpleNamespace(closed=False)
    descriptor.fileno = lambda: -1 if descriptor.closed else 7

    if failure == "wait":
        def RefuseWait():
            """Fail the pre-close observation while leaving physical cleanup mandatory."""

            raise RuntimeError("fixed idle wait failure")

        state.WaitOriginalIdle = RefuseWait

    class SourceServer:
        """Return a modeled owner only; never construct a server, socket or actual thread."""

        def __init__(self, _address, _case):
            """Fail before ownership returns or expose the independently constructed pure state."""

            if failure == "constructor":
                raise RuntimeError("fixed constructor failure")

            self.state, self.socket = state, descriptor

        def Settle(self, thread):
            """Physically settle the model before an optional original cleanup refusal."""

            descriptor.closed = True
            thread.alive = False

            if failure == "cleanup":
                raise RuntimeError("fixed cleanup failure")

    class SourceThread:
        """Model lifecycle flags without starting the supplied callback or a real thread."""

        def __init__(self, **_kwargs):
            """Allocate only one finite modeled thread state."""

            self.alive = False

        def Start(self):
            """Expose readiness without executing any listener code."""

            self.alive = True

        def IsAlive(self):
            """Return the modeled owner's actual settled flag."""

            return self.alive

        start = Start
        is_alive = IsAlive

    monkeypatch.setattr(target, "ContentResponseServer", SourceServer)
    monkeypatch.setattr(target, "Thread", SourceThread)
    monkeypatch.setattr(target, "Event", lambda: SimpleNamespace(wait=lambda _bound: True))
    evidence = SimpleNamespace(Json=lambda name, value: records.append((name, value)))

    with pytest.raises(RuntimeError, match="fixed"):
        with target.OwnedContentResponseTarget(evidence):
            if failure == "body":
                raise RuntimeError("fixed body failure")

    name, final = records[0]
    assert name == "content-source-final.json", "Always retain post-cleanup original owner facts"
    assert final["target_yielded"] is (failure != "constructor"), (
        "A failed original constructor cannot be credited as a yielded target")

    if failure == "constructor":
        assert final["owner_state"] == "unobserved", "Unavailable originals remain unobserved"

    else:
        assert final["owner_state"] == "settled" and final["counters"]["contacts"] == 0, (
            "Actual modeled physical state and original accepted count remain visible")
        refused_cleanup = failure in ("cleanup", "wait")
        assert final["cleanup_returned"] is (not refused_cleanup) and (
            final["cleanup_failure"] == ("RuntimeError" if refused_cleanup else None)), (
                "Settled physical owners never erase an actual cleanup failure")
