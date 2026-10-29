# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable deterministic supervisor refusal/control tests; real ownership requires Linux CI."""

from __future__ import annotations

import ctypes
import hashlib
import io
import os
import sys
from types import SimpleNamespace

import pytest

from fuzzy1337.executors import descendant_supervisor as supervisor
from fuzzy1337.executors import owned_process as owned


@pytest.mark.parametrize("mutation", [
    {"schema_version": True}, {"argv": []}, {"argv": ["worker", 1]}, {"argv": ["a\0b"]},
    {"environment": {"A=B": "value"}}, {"environment": {"": "value"}},
    {"environment": {"A": 1}}, {"environment": {"A": "v\0"}}, {"parent_pid": True},
    {"parent_pid": 1}, {"extra": "private"},
])
def test_SealedControlShapeCannotChangeApprovedInvocation(monkeypatch, mutation):
    """Sealed control must retain exact typed argv, environment and parent fields."""

    value = {"schema_version": 1, "argv": ["approved-worker"], "environment": {"A": "value"},
             "parent_pid": 321, **mutation}
    raw = owned.CanonicalControl(value)
    selected = SimpleNamespace(**vars(os))
    selected.read = lambda descriptor, bound: raw
    monkeypatch.setattr(supervisor, "os", selected)
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(fcntl=lambda *args: 15))

    with pytest.raises(supervisor.OwnershipFailure, match="setup"):
        supervisor.ReadConfiguration(7, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("mode", ["valid", "digest", "unsealed", "duplicate"])
def test_ConfigurationRequiresOriginalDigestKernelSealAndUniqueCanonicalFields(monkeypatch, mode):
    """A fake seal controls this parsing test only; actual Linux memfd sealing has its own check."""

    raw = owned.CanonicalControl({"schema_version": 1, "argv": ["worker", "literal space"],
        "environment": {"A": "unchanged"}, "parent_pid": 321})

    if mode == "duplicate":
        raw = b'{"schema_version":1,"schema_version":1}\n'

    selected = SimpleNamespace(**vars(os))
    selected.read = lambda descriptor, bound: raw
    monkeypatch.setattr(supervisor, "os", selected)
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(
        fcntl=lambda *args: 0 if mode == "unsealed" else 15))
    digest = "f" * 64 if mode == "digest" else hashlib.sha256(raw).hexdigest()

    if mode == "valid":
        assert supervisor.ReadConfiguration(7, digest) == (("worker", "literal space"),
            {"A": "unchanged"}, 321), "Canonical control changed the original invocation."

    else:
        with pytest.raises((supervisor.OwnershipFailure, ValueError)):
            supervisor.ReadConfiguration(7, digest)


@pytest.mark.parametrize("mode", ["valid", "set", "get", "value", "parent", "stopped", "child"])
def test_ConfigureMustVerifyPrivateSubreaperParentAndEmptyOwnedChildState(monkeypatch, mode):
    """No global subreaper state is touched: every prctl and signal operation is a local double."""

    calls = []
    owner = supervisor.DescendantOwner()
    owner.stopping = mode == "stopped"

    class Prctl:
        """Return fixed kernel facts and record only the finite approved primitive operations."""

        def __call__(self, operation, value, *unused):
            """Model configured ownership without changing any real test-host process state."""

            calls.append(operation)

            if mode == "set" and operation == 36 or mode == "get" and operation == 37:
                return -1

            if operation in (37, 2):
                ctypes.c_int.from_address(value).value = (
                    0 if mode == "value" else 1 if operation == 37 else 15
                )

            return 0

    selected_signals = SimpleNamespace(SIGTERM=15, SIGINT=2, SIGHUP=1, SIGCHLD=17,
        SIG_DFL=0, SIG_UNBLOCK=1, signal=lambda *args: None, pthread_sigmask=lambda *args: None)
    selected_os = SimpleNamespace(getppid=lambda: 999 if mode == "parent" else 321)
    monkeypatch.setattr(supervisor, "signal", selected_signals)
    monkeypatch.setattr(supervisor, "os", selected_os)
    monkeypatch.setattr(supervisor, "ctypes", SimpleNamespace(CDLL=lambda *args, **kwargs:
        SimpleNamespace(prctl=Prctl()), c_int=ctypes.c_int, c_ulong=ctypes.c_ulong,
        addressof=ctypes.addressof))
    monkeypatch.setattr(owner, "Children", lambda: (101,) if mode == "child" else ())

    if mode == "valid":
        owner.Configure(321)
        assert calls == [36, 1, 37, 2], "Required Linux ownership facts were not read back."
        owner.Stop(15, None)
        assert owner.stopping, "A stop signal did not request cleanup."

    else:
        with pytest.raises(supervisor.OwnershipFailure):
            owner.Configure(321)


@pytest.mark.parametrize("raw,category", [
    (b"101 202 ", None), (b"", None), (b"101 101", "ownership"),
    (b"321", "ownership"), (b"-1", "ownership"), (b"x", "ownership"),
    (b"1 " * 129, "ownership"), (b"1" * 1537, "limit"),
])
def test_OwnedChildSelectionIsFreshBoundedAndNeverUsesAnotherProcessesKernelFile(
    monkeypatch, raw, category,
):
    """Only strict unreaped identities from the supervisor's own kernel file may be signaled."""

    accesses = []

    class SelectedPath:
        """Expose only the fixed own-process kernel file to the child-list parser."""

        def __init__(self, path):
            """Record the exact kernel path selected by the code under test."""

            accesses.append(path)

        def Open(self, mode):
            """Return fixed original kernel bytes without opening any process table."""

            assert mode == "rb", "Kernel child selection was not read-only."

            return io.BytesIO(raw)

        open = Open

    monkeypatch.setattr(supervisor, "Path", SelectedPath)
    monkeypatch.setattr(supervisor, "os", SimpleNamespace(getpid=lambda: 321))
    owner = supervisor.DescendantOwner()

    if category is None:
        assert owner.Children() == tuple(int(part) for part in raw.split()), "Owned list changed."

    else:
        with pytest.raises(supervisor.OwnershipFailure, match=category):
            owner.Children()

    assert accesses == ["/proc/321/task/321/children"], "An unrelated process was inspected."


@pytest.mark.parametrize("mode", ["exit", "live", "limit"])
def test_SoleReaperRetainsSignedOriginalExitAndBoundsOwnedProcessCount(monkeypatch, mode):
    """Interrupted waits retry, adopted statuses stay distinct, and the process count is bounded."""

    owner = supervisor.DescendantOwner()
    owner.worker_pid = 101
    owner.reaped = 128 if mode == "limit" else 0
    sequence = iter([InterruptedError(), (101, 17 << 8), (202, 9),
                     (0, 0) if mode == "live" else ChildProcessError()])

    def Wait(process_id, options):
        """Return only controlled kernel-owned wait observations, never actual test children."""

        assert process_id == -1 and options == 1, "Reaper selected an unexpected wait boundary."
        value = next(sequence)

        if isinstance(value, BaseException):
            raise value

        return value

    monkeypatch.setattr(supervisor, "os", SimpleNamespace(waitpid=Wait, WNOHANG=1,
        waitstatus_to_exitcode=lambda status: status >> 8 if status & 127 == 0
        else -(status & 127)))

    if mode == "limit":
        with pytest.raises(supervisor.OwnershipFailure, match="limit"):
            owner.Reap()

    else:
        assert owner.Reap() is (mode == "exit"), "Reaper invented an empty-child proof."
        assert owner.worker_returncode == 17 and owner.reaped == 2, "Original status was lost."


def test_CleanupDeadlineNeverBecomesConfirmedEmptyOwnership(monkeypatch):
    """An exhausted finite cleanup budget fails even when a later check might become empty."""

    owner = supervisor.DescendantOwner()
    ticks = iter((0.0, 3.0))
    monkeypatch.setattr(supervisor, "time", SimpleNamespace(monotonic=lambda: next(ticks)))

    with pytest.raises(supervisor.OwnershipFailure, match="timeout"):
        owner.Cleanup()


@pytest.mark.parametrize("mode", ["ack", "eof", "invalid", "stopped", "deadline"])
def test_StartGateRequiresExplicitParentAcknowledgementBeforePopen(monkeypatch, mode):
    """Readiness, EOF and a stop flag cannot substitute an explicit parent start acknowledgement."""

    owner = supervisor.DescendantOwner()
    owner.stopping = mode == "stopped"
    ticks = iter((0.0, 4.0) if mode == "deadline" else (0.0, 0.0))
    monkeypatch.setattr(supervisor, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(supervisor, "select", SimpleNamespace(
        select=lambda *args: ((7,), (), ())))
    monkeypatch.setattr(supervisor, "os", SimpleNamespace(
        read=lambda *args: b"1" if mode == "ack" else b"" if mode == "eof" else b"11"))

    if mode == "ack":
        supervisor.WaitForHandoff(7, owner)

    else:
        with pytest.raises(supervisor.OwnershipFailure, match="parent-lost"):
            supervisor.WaitForHandoff(7, owner)


@pytest.mark.parametrize("mode,status", [
    ("normal", 0), ("normal", 17), ("normal", -9), ("spawn", None), ("setup", None),
    ("gate", None), ("missing-root", None), ("cleanup", 0), ("ready-write", None),
    ("receipt-write", 0),
])
def test_SupervisorControlOutcomeCannotInventWorkerCompletion(monkeypatch, mode, status):
    """Portable lifecycle doubles check report truth; they do not establish actual Linux cleanup."""

    configuration_fd, configuration_write = os.pipe()
    receipt_read, receipt_fd = os.pipe()
    gate_fd, gate_write = os.pipe()
    ready_read, ready_fd = os.pipe()
    os.close(configuration_write)
    os.write(gate_write, b"0" if mode == "gate" else b"1")
    os.close(gate_write)
    digest = "a" * 64
    selected_os = SimpleNamespace(**vars(os))
    original_write = os.write
    facts = {"spawned": False}

    class Owner:
        """Represent fixed owned-kernel observations without changing any real process state."""

        def __init__(self):
            """Start with no original worker or observed wait status."""

            self.worker_pid = self.worker_returncode = None
            self.reaped = 0
            self.stopping = False

        def Configure(self, parent):
            """Inject a finite setup refusal without changing real Linux ownership state."""

            assert parent == 321, "Parent binding changed."

            if mode == "setup":
                raise supervisor.OwnershipFailure("setup")

        def Reap(self):
            """Report a controlled original-worker exit or missing-root ownership failure."""

            if mode == "missing-root":
                return True

            self.worker_returncode = status
            self.reaped = 1

            return True

        def Cleanup(self):
            """Confirm only synthetic statuses, or explicitly fail the bounded cleanup proof."""

            if mode == "cleanup":
                raise supervisor.OwnershipFailure("timeout")

            if self.worker_pid is not None and self.worker_returncode is None:
                self.worker_returncode = -9
                self.reaped = 1

    def Spawn(argv, **options):
        """Observe exact original payload and absence of inherited private control descriptors."""

        assert argv == ("approved-worker",) and options == {
            "env": {"A": "original"}, "close_fds": True, "start_new_session": True,
        }, "Supervisor altered invocation/environment or leaked control descriptors."
        assert os.read(ready_read, 2) == b"1", "Worker started before readiness was published."

        with pytest.raises(OSError):
            os.fstat(ready_fd)

        facts["spawned"] = True

        if mode == "spawn":
            raise OSError(2, "PRIVATE_WORKER_PATH")

        return SimpleNamespace(pid=101, returncode=None)

    def Write(descriptor, raw):
        """Inject only fixed control-write failures, leaving all other private bytes untouched."""

        if mode == "ready-write" and descriptor == ready_fd:
            return 0

        if mode == "receipt-write" and descriptor == receipt_fd:
            raise OSError(5, "PRIVATE_PIPE_MARKER")

        return original_write(descriptor, raw)

    selected_os.write = Write
    monkeypatch.setattr(supervisor, "os", selected_os)
    monkeypatch.setattr(supervisor, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(supervisor, "DescendantOwner", Owner)
    monkeypatch.setattr(supervisor, "ReadConfiguration", lambda *args:
        (("approved-worker",), {"A": "original"}, 321))
    monkeypatch.setattr(supervisor, "subprocess", SimpleNamespace(Popen=Spawn))
    monkeypatch.setattr(supervisor, "select", SimpleNamespace(
        select=lambda *args: ((gate_fd,), (), ())))

    try:
        result = supervisor.Main((str(configuration_fd), str(receipt_fd), digest,
                                  str(gate_fd), str(ready_fd)))
        raw = os.read(receipt_read, 513)
        assert result == (owned.WrapperExit(status) if mode == "normal" else 125), (
            "Failed supervisor control was reported as completed original work."
        )

        if mode == "receipt-write":
            assert raw == b"", "A failed receipt write fabricated a confirmation."

        else:
            record = owned.DecodeControl(raw, 512)
            assert record["configuration_sha256"] == digest, "Receipt lost configuration custody."
            assert record["worker_returncode"] == (status if mode in ("normal", "cleanup")
                else -9 if mode == "missing-root" else None), "Original status was invented."
            assert record["cleanup"] == ("failed" if mode == "cleanup" else "confirmed"), (
                "Cleanup failure lost its explicit unknown state."
            )

        assert facts["spawned"] is (mode not in ("setup", "gate", "ready-write")), (
            "Refused setup/handoff still reached the approved worker."
        )

    finally:
        os.close(receipt_read)
        os.close(ready_read)


@pytest.mark.parametrize("arguments", [(), ("1",), ("7", "8", "bad", "9", "10"),
    ("7", "8", "a" * 64, "9", "0"), (7, "8", "a" * 64, "9", "10")])
def test_InvalidPrivateEntrypointCannotReachSetupOrAnApprovedPayload(arguments):
    """Malformed private descriptors or binding digests fail without touching user authority."""

    assert supervisor.Main(arguments) == 125, "Malformed helper invocation was accepted."
