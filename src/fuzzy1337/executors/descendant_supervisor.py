# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal Linux single-threaded subreaper for one approved worker and adopted descendants."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import select
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from fuzzy1337.executors.owned_process import (
    LINUX_F_GET_SEALS,
    LINUX_REQUIRED_SEALS,
    MAX_CONFIGURATION_BYTES,
    MAX_OWNED_PROCESSES,
    MAX_RECEIPT_BYTES,
    OWNED_CLEANUP_SECONDS,
    CanonicalControl,
    DecodeControl,
    WrapperExit,
)

_SHA256 = re.compile(r"[a-f0-9]{64}")
_DECIMAL = re.compile(r"[1-9][0-9]{0,9}")


class OwnershipFailure(RuntimeError):
    """A bounded fixed-category ownership operation could not be established."""


class DescendantOwner:
    """Track one original child without another thread, callback or competing waitpid owner."""

    def __init__(self) -> None:
        """Initialize only invocation-local flags and actual waitpid facts."""

        self.stopping = False
        self.worker_pid: int | None = None
        self.worker_returncode: int | None = None
        self.reaped = 0

    def Stop(self, signum: int, frame: object) -> None:
        """Request cleanup without reaping or changing PID ownership in a signal handler.

        Args:
            signum: Kernel-delivered signal; only the fixed owner stop flag is changed.
            frame: Python signal frame, deliberately unused.
        """

        self.stopping = True

    def Configure(self, expected_parent: int) -> None:
        """Establish private Linux subreaper/parent-death ownership before worker launch.

        Args:
            expected_parent: Workbench PID recorded in the original private configuration.
        """

        for selected in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(selected, self.Stop)

        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK,
                              {signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD})
        library = ctypes.CDLL(None, use_errno=True)
        prctl = library.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int

        if prctl(36, 1, 0, 0, 0) != 0 or prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
            raise OwnershipFailure("setup")

        subreaper, death_signal = ctypes.c_int(), ctypes.c_int()

        if prctl(37, ctypes.addressof(subreaper), 0, 0, 0) != 0 or (
            prctl(2, ctypes.addressof(death_signal), 0, 0, 0) != 0
            or subreaper.value != 1 or death_signal.value != signal.SIGTERM
        ):
            raise OwnershipFailure("setup")

        if os.getppid() != expected_parent or self.stopping:
            raise OwnershipFailure("parent-lost")

        if self.Children():
            raise OwnershipFailure("ownership")

    def Reap(self) -> bool:
        """Reap only owned children and retain the original worker's exact signed return code.

        Returns:
            True only when waitpid independently reports no remaining children.
        """

        while True:
            try:
                process_id, status = os.waitpid(-1, os.WNOHANG)

            except ChildProcessError:
                return True

            except InterruptedError:
                continue

            if process_id == 0:
                return False

            self.reaped += 1

            if self.reaped > MAX_OWNED_PROCESSES:
                raise OwnershipFailure("limit")

            if process_id == self.worker_pid:
                self.worker_returncode = os.waitstatus_to_exitcode(status)

    def Children(self) -> tuple[int, ...]:
        """Read only this single-threaded supervisor's fresh kernel direct-child list.

        Returns:
            Still-unreaped direct/adopted child identifiers, never a global process listing.
        """

        own_pid = os.getpid()
        selected = Path(f"/proc/{own_pid}/task/{own_pid}/children")

        with selected.open("rb") as stream:
            raw = stream.read(MAX_OWNED_PROCESSES * 12 + 1)

        if len(raw) > MAX_OWNED_PROCESSES * 12:
            raise OwnershipFailure("limit")

        tokens = raw.decode("ascii").split()

        if len(tokens) > MAX_OWNED_PROCESSES or any(_DECIMAL.fullmatch(token) is None
                                                  for token in tokens):
            raise OwnershipFailure("ownership")

        children = tuple(int(token) for token in tokens)

        if len(set(children)) != len(children) or own_pid in children:
            raise OwnershipFailure("ownership")

        return children

    def Cleanup(self) -> None:
        """Kill and reap bounded fresh owned-child waves, including adopted detached descendants.

        No reap occurs between a fresh child-list read and its kill wave. Exited children
        remain unreaped and retain their PIDs, preventing PID reuse from selecting strangers.
        """

        deadline = time.monotonic() + OWNED_CLEANUP_SECONDS

        while time.monotonic() < deadline:
            empty = self.Reap()
            children = self.Children()

            if empty and not children:
                return

            for process_id in children:
                os.kill(process_id, signal.SIGKILL)

            time.sleep(0.005)

        raise OwnershipFailure("timeout")


def ReadConfiguration(descriptor: int, digest: str) -> tuple[tuple[str, ...], dict[str, str], int]:
    """Verify the sealed bounded original configuration without disclosing its contents.

    Args:
        descriptor: Private anonymous configuration file received from the executor.
        digest: Exact expected configuration-byte SHA-256 supplied by the executor.

    Returns:
        Original approved argv, unchanged worker environment and expected parent PID.
    """

    import fcntl

    seals = fcntl.fcntl(descriptor, LINUX_F_GET_SEALS)
    required = LINUX_REQUIRED_SEALS

    if seals & required != required:
        raise OwnershipFailure("setup")

    raw = os.read(descriptor, MAX_CONFIGURATION_BYTES + 1)

    if hashlib.sha256(raw).hexdigest() != digest:
        raise OwnershipFailure("setup")

    value = DecodeControl(raw, MAX_CONFIGURATION_BYTES)
    argv, environment, parent = value.get("argv"), value.get("environment"), value.get("parent_pid")

    if set(value) != {"schema_version", "argv", "environment", "parent_pid"} or (
        type(value["schema_version"]) is not int or value["schema_version"] != 1
        or type(argv) is not list or not argv
        or any(type(item) is not str or "\x00" in item for item in argv)
        or type(environment) is not dict
        or any(type(key) is not str or not key or "=" in key or "\x00" in key
               or type(item) is not str or "\x00" in item for key, item in environment.items())
        or type(parent) is not int or parent <= 1
    ):
        raise OwnershipFailure("setup")

    return tuple(argv), cast(dict[str, str], environment), parent


def WaitForHandoff(descriptor: int, owner: DescendantOwner) -> None:
    """Do not start a worker until its parent has acquired the actual supervisor handle.

    Args:
        descriptor: Private start gate; parent cancellation before handoff closes it without data.
        owner: Single-threaded supervisor whose termination flag also refuses this handoff.
    """

    deadline = time.monotonic() + 3.0

    while not owner.stopping and time.monotonic() < deadline:
        ready, _, _ = select.select((descriptor,), (), (), 0.01)

        if ready:
            if os.read(descriptor, 2) != b"1":
                raise OwnershipFailure("parent-lost")

            return

    raise OwnershipFailure("parent-lost")


def Main(arguments: Sequence[str] | None = None) -> int:
    """Supervise one exact approved worker, emitting only its private bounded cleanup receipt.

    Args:
        arguments: Private configuration/receipt/start/ready descriptors and configuration SHA-256.

    Returns:
        Worker-compatible ordinary exit status after cleanup, or 125 for unconfirmed ownership.
        The private receipt retains the original signed worker status independently.
    """

    selected = tuple(sys.argv[1:] if arguments is None else arguments)

    if sys.platform != "linux" or len(selected) != 5 or (
        any(type(value) is not str for value in selected)
        or _DECIMAL.fullmatch(selected[0]) is None or _DECIMAL.fullmatch(selected[1]) is None
        or _DECIMAL.fullmatch(selected[3]) is None
        or _DECIMAL.fullmatch(selected[4]) is None
        or _SHA256.fullmatch(selected[2]) is None
    ):
        return 125

    configuration_fd, receipt_fd = int(selected[0]), int(selected[1])
    gate_fd = int(selected[3])
    ready_fd = int(selected[4])
    digest = selected[2]
    owner = DescendantOwner()
    worker: subprocess.Popen[bytes] | None = None
    failure: str | None = None
    cleanup = "failed"

    try:
        if len({configuration_fd, receipt_fd, gate_fd, ready_fd}) != 4 or (
            min(configuration_fd, receipt_fd, gate_fd, ready_fd) < 3
        ):
            raise OwnershipFailure("setup")

        os.set_inheritable(receipt_fd, False)
        argv, environment, parent = ReadConfiguration(configuration_fd, digest)
        os.close(configuration_fd)
        configuration_fd = -1
        owner.Configure(parent)

        if os.write(ready_fd, b"1") != 1:
            raise OwnershipFailure("setup")

        os.close(ready_fd)
        ready_fd = -1
        WaitForHandoff(gate_fd, owner)
        os.close(gate_fd)
        gate_fd = -1

        try:
            worker = subprocess.Popen(argv, env=environment, close_fds=True, start_new_session=True)

        except (OSError, ValueError):
            raise OwnershipFailure("spawn") from None

        owner.worker_pid = worker.pid

        while owner.worker_returncode is None and not owner.stopping:
            if owner.Reap() and owner.worker_returncode is None:
                raise OwnershipFailure("ownership")

            if owner.worker_returncode is None:
                time.sleep(0.005)

    except OwnershipFailure as error:
        failure = str(error)

    except (OSError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        failure = "ownership"

    finally:
        try:
            owner.Cleanup()
            cleanup = "confirmed"

        except OwnershipFailure as error:
            failure = str(error)

        except (OSError, ValueError, TypeError, UnicodeError):
            failure = "ownership"

        if worker is not None:
            # This process is the sole reaper; prevent Popen's finalizer from polling again.
            worker.returncode = owner.worker_returncode

            if worker.returncode is None:
                worker.returncode = 125

        record = CanonicalControl({"schema_version": 1, "configuration_sha256": digest,
            "cleanup": cleanup, "worker_returncode": owner.worker_returncode,
            "reaped_processes": min(owner.reaped, MAX_OWNED_PROCESSES), "failure": failure})

        try:
            if len(record) > MAX_RECEIPT_BYTES or os.write(receipt_fd, record) != len(record):
                failure = "ownership"

        except OSError:
            failure = "ownership"

        finally:
            for descriptor in set((configuration_fd, receipt_fd, gate_fd, ready_fd)):
                if descriptor >= 0:
                    os.close(descriptor)

    if cleanup != "confirmed" or failure is not None or owner.worker_returncode is None:
        return 125

    return WrapperExit(owner.worker_returncode)


if __name__ == "__main__":
    raise SystemExit(Main())
