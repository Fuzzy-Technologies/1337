# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite original receive-signal doubles; no real socket, thread, worker or capture runs."""

from __future__ import annotations

import errno
import json
import threading
from types import SimpleNamespace

import pytest

from tests.integration import test_owned_response_product as held

REQUEST = b"GET /held HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"


class FakeHeldConnection:
    """Return one exact request then an explicitly selected original terminal receive."""

    def __init__(self, terminal):
        """Retain fixed receive outcomes without creating an OS descriptor."""

        self.blocks = [REQUEST, terminal]
        self.timeouts = []
        self.closed = False

    def __enter__(self):
        """Enter only this modeled original accepted connection."""

        return self

    def __exit__(self, *_):
        """Record local context closure after the actual modeled receive observation."""

        self.closed = True

    def SetTimeout(self, value):
        """Keep the original three-second socket timeout visible to assertions."""

        self.timeouts.append(value)

    def Recv(self, limit):
        """Return or raise one fixed original outcome under the requested byte ceiling."""

        value = self.blocks.pop(0)

        if isinstance(value, OSError):
            raise value

        assert len(value) <= limit, "The fake must respect the original receive byte ceiling"

        return value

    settimeout = SetTimeout
    recv = Recv


class FakeHeldAcceptor:
    """Accept the one original fake connection, then stop the source-selected serve loop."""

    def __init__(self, connection):
        """Own one existing fake connection without binding or listening."""

        self.connection = connection

    def Accept(self):
        """Return exactly once, without a live port or any readiness probe."""

        if self.connection is None:
            raise OSError("fixed fake accept completion")

        connection, self.connection = self.connection, None

        return connection, ("127.0.0.1", 12345)

    accept = Accept


class FakeHeldEvent:
    """Model one bounded original Event wait without sleeping or starting a thread."""

    def __init__(self, on_wait=None):
        """Retain finite fake wait durations and one explicit interleaving callback."""

        self.ready = False
        self.waits = []
        self.on_wait = on_wait

    def Wait(self, timeout):
        """Run only the selected fake receive interleaving and return actual modeled state."""

        self.waits.append(timeout)

        if self.on_wait is not None:
            self.on_wait()

        return self.ready

    def Set(self):
        """Release the original modeled terminal observation once recorded."""

        self.ready = True

    def IsSet(self):
        """Return whether the original terminal observation was actually recorded."""

        return self.ready

    wait = Wait
    set = Set
    is_set = IsSet


def PureHeldListener(tmp_path):
    """Create only original observation state, bypassing socket/thread construction."""

    listener = object.__new__(held.HeldResponseListener)
    listener.InitializePeerObservation()
    listener.readiness = tmp_path / "selected-ready"
    listener.stopping = threading.Event()
    listener.accepted = 0
    listener.requests = []

    return listener


def ResetError(kind):
    """Construct a labeled original reset double with a known platform error number."""

    error = ConnectionResetError(errno.ECONNRESET, "private reset message", "/private/source")

    if kind == "windows-errno-reset":
        error.errno = 10054

    elif kind == "windows-winerror-reset":
        error.errno = None
        error.winerror = 10054

    return error


@pytest.mark.parametrize("kind", ("eof", "posix-reset", "windows-errno-reset",
    "windows-winerror-reset", "timeout", "unknown", "bad-reset-number", "local-abort",
    "unexpected-data"))
def test_OriginalHeldReceiveSeparatesEofResetAndRefusedSignals(tmp_path, kind):
    """Actual Serve records the original signal before its local connection context closes."""

    terminals = {"eof": b"", "timeout": TimeoutError("private timeout"),
        "unknown": OSError(123456, "private unknown", "/private/source"),
        "bad-reset-number": ConnectionResetError(123456, "private unknown reset"),
        "local-abort": ConnectionAbortedError(10053, "private local abort"),
        "unexpected-data": b"x"}
    terminal = ResetError(kind) if kind.endswith("reset") else terminals[kind]
    listener = PureHeldListener(tmp_path)
    connection = FakeHeldConnection(terminal)
    listener.listener = FakeHeldAcceptor(connection)
    listener.Serve()
    signal = listener.PeerSignal()
    expected = "peer-reset" if kind.endswith("reset") else "os-error" if kind in (
        "unknown", "bad-reset-number", "local-abort") else kind
    assert signal["kind"] == expected and signal["phase"] == "peer-receive", (
        "Original terminal class must not be collapsed into a timeout or fabricated EOF")
    assert listener.PeerTerminated() is (kind == "eof" or kind.endswith("reset")), (
        "Only original EOF and known receive resets qualify as remote termination")
    assert listener.peer_closed is (kind == "eof"), "Reset is never an observed EOF"
    assert listener.hold_expired is (kind == "timeout"), "Unknown/reset is not a timeout"
    assert listener.requests == [REQUEST] and listener.accepted == 1 and connection.closed, (
        "The original full request and original local settlement remain independently visible")
    assert connection.timeouts == [3] and listener.readiness.read_bytes() == (
        b"actual-selected-get"
    ), (
        "The original timeout and complete-request readiness marker must remain unchanged")


@pytest.mark.parametrize("phase", ("request", "readiness"))
def test_PreReadyResetIsNotPeerTermination(tmp_path, phase):
    """Even a known reset number at another phase cannot prove post-request peer closure."""

    listener = PureHeldListener(tmp_path)
    listener.RecordPeerSignal(phase, error=ResetError("posix-reset"))
    assert listener.PeerSignal()["kind"] == "before-peer-receive", (
        "Only the original post-readiness receive phase may attest remote termination")
    assert not listener.PeerTerminated() and not listener.peer_closed, (
        "Pre-readiness failure must remain failed rather than cleanup proof")


@pytest.mark.parametrize("terminal", (b"", ConnectionResetError(errno.ECONNRESET, "private")))
def test_LocalTeardownCannotManufactureRemoteProof(tmp_path, terminal):
    """A receive return after local teardown begins remains explicitly local/unknown."""

    listener = PureHeldListener(tmp_path)
    listener.local_close_started = True
    listener.RecordPeerSignal("peer-receive",
        data=terminal if isinstance(terminal, bytes) else None,
        error=terminal if isinstance(terminal, OSError) else None)
    assert listener.PeerSignal()["kind"] == "local-teardown" and not listener.PeerTerminated(), (
        "Local teardown must not satisfy the remote-termination acceptance guard")
    assert not listener.peer_closed, "A post-local-close empty receive is not accepted EOF proof"


def test_OriginalSignalAndBoundedPrivacySurviveLaterObservations(tmp_path):
    """First timeout/unknown evidence cannot be overwritten or expose private diagnostics."""

    listener = PureHeldListener(tmp_path)

    class PrivateReceiveError(OSError):
        """Represent an unapproved class name and unknown numbers without exposing them."""

    marker = "/private/PID99999/source-bytes-sha256:" + "a" * 64
    error = PrivateReceiveError(123456, marker, marker)
    error.winerror = 123456
    listener.RecordPeerSignal("peer-receive", error=error)
    first = listener.PeerSignal()
    listener.RecordPeerSignal("peer-receive", data=b"")
    encoded = json.dumps(listener.PeerSignal())
    assert listener.PeerSignal() == first and not listener.PeerTerminated(), (
        "Later receive facts cannot replace the original unknown terminal signal")
    assert first["error_type"] == "other" and first["errno"] is first["winerror"] is None, (
        "Only whitelisted class names and known original error numbers may be retained")
    assert len(encoded) < 256 and marker not in encoded and "PrivateReceiveError" not in encoded, (
        "Diagnostic metadata must contain no original message/path/PID/bytes/hash/class marker")


def test_EventWaitUsesOriginalDeadlineAndPrecedesLocalClose(tmp_path, monkeypatch):
    """A bounded terminal Event observes peer EOF before the exact local close action."""

    listener = PureHeldListener(tmp_path)
    listener.peer_deadline = 13.0
    clock = [11.0]
    event = FakeHeldEvent(lambda: listener.RecordPeerSignal("peer-receive", data=b""))
    listener.peer_observed = event
    monkeypatch.setattr(held, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    local = []

    def Close(_self):
        """Record the existing local cleanup action without running socket/thread methods."""

        assert listener.local_close_started, "Local teardown must be marked before its action"
        local.append(listener.PeerSignal())

    monkeypatch.setattr(held.OwnedResponseListener, "Close", Close)
    listener.Close()
    assert event.waits == [2.0] and listener.peer_deadline == 13.0 and local, (
        "One original remaining-time Event wait must precede local close without renewal")
    assert local[0]["before_local_close"] is True and listener.PeerTerminated(), (
        "Only the actual modeled pre-close EOF is credited")
    clock[0] = 14.0
    listener.WaitPeerTerminal()
    assert event.waits[-1] == 0, "Expired waits must never gain a replacement deadline"


def test_PostLocalCloseReceiveRemainsUnsuccessful(tmp_path, monkeypatch):
    """A local cleanup action that causes recv EOF cannot retroactively establish remote proof."""

    listener = PureHeldListener(tmp_path)
    listener.peer_deadline = 13.0
    listener.peer_observed = FakeHeldEvent()
    monkeypatch.setattr(held, "time", SimpleNamespace(monotonic=lambda: 14.0))

    def Close(_self):
        """Model only a receive completion induced after local cleanup starts."""

        listener.RecordPeerSignal("peer-receive", data=b"")

    monkeypatch.setattr(held.OwnedResponseListener, "Close", Close)
    listener.Close()
    assert listener.PeerSignal()["kind"] == "local-teardown" and not listener.PeerTerminated(), (
        "Post-local-close EOF must remain a failed remote-closure observation")


def test_LateOriginalEofRemainsEofWithoutPassingTheHold(tmp_path, monkeypatch):
    """Actual EOF observed after the original deadline is retained but earns no timely proof."""

    listener = PureHeldListener(tmp_path)
    listener.peer_deadline = 13.0
    monkeypatch.setattr(held, "time", SimpleNamespace(monotonic=lambda: 14.0))
    listener.RecordPeerSignal("peer-receive", data=b"")
    signal = listener.PeerSignal()
    assert listener.peer_closed and signal["kind"] == "eof" and not listener.hold_expired, (
        "A late observed EOF is neither a fabricated reset nor an original timeout exception")
    assert signal["within_hold"] is False and not listener.PeerTerminated(), (
        "Remote termination outside the original hold cannot satisfy cancellation acceptance")
