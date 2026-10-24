# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed experimental test owner; never imported or enrolled by production code."""

from __future__ import annotations

import array
import asyncio
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import platform
import select
import signal
import socket
import stat
import struct
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.executors import CapabilityDescriptor, ExecutionResources, LocalExecutionRequest
from fuzzy1337.executors.contracts import ExecutionEventKind, LocalExecutionResult
from fuzzy1337.policy import (
    CapabilityPermission,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyContext,
    PolicyEngine,
)
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

HERE = Path(__file__).resolve().parent
SO_PEERPIDFD = 77
SO_PEERCRED = 17
HOST_CAP_FIELDS = ("CapEff", "CapPrm", "CapAmb")
PEER_CAP_FIELDS = ("CapEff", "CapPrm", "CapAmb", "CapInh", "CapBnd")
ALIASES = {"home": "/work/home", "tmp": "/work/tmp", "var/tmp": "/work/tmp",
    "session": "/work/session", "report": "/work/report", "dev/shm": "/work/shm"}


def LoadContract():
    """Load only the fixed adjacent pure contract, without a runtime entrypoint.

    Returns:
        The test-only contract module.
    """

    spec = importlib.util.spec_from_file_location("inert_test_contract", HERE / "contract.py")
    assert spec is not None and spec.loader is not None, (
        "Closed inert source material loading invariant failed"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module


CONTRACT = LoadContract()


def Canonical(value: object) -> bytes:
    """Encode the bounded outer test request deterministically.

    Args:
        value: Owner-built closed record.

    Returns:
        Sorted compact JSON bytes.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def Identity(info: os.stat_result) -> tuple[int, ...]:
    """Return the full physical identity used for original material and report reads.

    Args:
        info: One original nofollow stat result.

    Returns:
        Device, inode, mode, owner, links, size and nanosecond timestamps.
    """

    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def Exclusive(path: Path, raw: bytes) -> None:
    """Create one bounded private original without replacing anything.

    Args:
        path: Fresh operation-local destination.
        raw: Original owner-built bytes.

    Raises:
        ValueError: The fixed outer request ceiling is exceeded.
    """

    if len(raw) > 4096:
        raise ValueError("inert original exceeds its fixed request cap")

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError("inert original write was incomplete")

        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def BoundedRead(path: Path, maximum: int) -> bytes:
    """Read only a selected known-peer kernel file under a fixed byte cap.

    Args:
        path: Exact known peer kernel path.
        maximum: Fixed role-specific cap.

    Returns:
        Complete bytes through EOF.

    Raises:
        ValueError: The bounded read is incomplete or too large.
    """

    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)

    if len(raw) > maximum:
        raise ValueError("known-peer inspection exceeded its fixed cap")

    return raw


def Fields(raw: bytes) -> dict[str, str]:
    """Parse only colon-delimited kernel status lines.

    Args:
        raw: Bounded original kernel status.

    Returns:
        Kernel field names and values.
    """

    return dict(line.split(":", 1) for line in raw.decode("ascii").splitlines() if ":" in line)


def Preflight() -> None:
    """Refuse unsupported host identity before creating any payload request.

    Raises:
        ValueError: This is not the exact unprivileged Linux x86_64 profile.
    """

    if sys.platform != "linux" or platform.machine() != "x86_64" or os.getuid() == 0 or (
        os.geteuid() != os.getuid() or os.getegid() != os.getgid()
    ):
        raise ValueError("inert acceptance requires unprivileged Linux x86_64")

    fields = Fields(BoundedRead(Path("/proc/self/status"), 16384))

    if any(int(fields[name].strip(), 16) for name in HOST_CAP_FIELDS):
        raise ValueError("inert acceptance refuses host capabilities")


def Material(path: Path, *, executable: bool) -> dict[str, object]:
    """Admit one fixed trusted original without granting arbitrary workload selection.

    Args:
        path: A source-selected fixture/helper/recipe material.
        executable: Whether this role must have an executable owner bit.

    Returns:
        Original path, physical identity and SHA-256 record.

    Raises:
        ValueError: Type, mode, owner, link or capability facts are unsafe.
    """

    before = path.lstat()

    if path.resolve() != path or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or (
        before.st_uid not in (0, os.getuid()) or before.st_mode & 0o7022
        or bool(before.st_mode & stat.S_IXUSR) != executable
        or before.st_size > 16 * 1024 * 1024
        or "security.capability" in os.listxattr(path)
    ):
        raise ValueError("inert selected material admission refused")

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)

    try:
        raw = os.read(descriptor, 16 * 1024 * 1024 + 1)

        if Identity(before) != Identity(os.fstat(descriptor)) or (
            Identity(before) != Identity(path.lstat()) or len(raw) != before.st_size
        ):
            raise ValueError("inert selected material changed")

    finally:
        os.close(descriptor)

    return {"path": str(path), "identity": Identity(before),
        "sha256": hashlib.sha256(raw).hexdigest()}


def VerifyBuild(material_root: Path, materials: dict) -> dict:
    """Bind actual build provenance and static fixture metadata before payload release.

    Args:
        material_root: Fixed CI private build directory.
        materials: Already admitted helper/fixture original identities.

    Returns:
        Bounded observed build record.

    Raises:
        ValueError: Source/build provenance or static ELF facts differ.
    """

    manifest = material_root / "provenance.json"
    Material(manifest, executable=False)
    provenance = json.loads(BoundedRead(manifest, 16384))

    if provenance["source_archive_sha256"] != CONTRACT.BWRAP_SHA256 or (
        provenance["source_archive_bytes"] != CONTRACT.BWRAP_SIZE
        or provenance["source_commit"] != "719a4fd474d44b26906bcf2b1b0fb6eddd8d56d0"
        or provenance["fixture_source_sha256"] != hashlib.sha256(
            (HERE / "inert.c").read_bytes()).hexdigest()
        or provenance["fixture_flags"] != ["-static", "-std=c11", "-O2", "-D_GNU_SOURCE"]
        or provenance["fixture_sha256"] != materials["fixture"]["sha256"]
        or provenance["bwrap_sha256"] != materials["bwrap"]["sha256"]
        or provenance["host_uid"] != os.getuid()
    ):
        raise ValueError("inert helper/source build provenance differs")

    spec = importlib.util.spec_from_file_location("inert_build_validation", HERE / "build.py")

    if spec is None or spec.loader is None:
        raise ValueError("fixed inert ELF admission is unavailable")

    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    build.ValidateElf((material_root / "inert").read_bytes())

    return provenance


def Alive(descriptor: int) -> None:
    """Require the original kernel pidfd to remain live, without numeric PID reopening.

    Args:
        descriptor: The original SO_PEERPIDFD descriptor.

    Raises:
        ValueError: The kernel reports exit or invalid descriptor state.
    """

    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)

    if poller.poll(0):
        raise ValueError("original inert peer is no longer live")


def RequirePeerExit(descriptor: int) -> None:
    """Require readable exit on the exact original pidfd without accepting readiness errors.

    Args:
        descriptor: Original direct kernel peer pidfd, still owned by this attempt.

    Raises:
        ValueError: Exit is absent, foreign, malformed or accompanied by invalid/error flags.
        OSError: The original descriptor cannot be inspected.
    """

    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("original inert peer descriptor is invalid")

    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    events = poller.poll(0)

    if type(events) is not list or len(events) != 1 or type(events[0]) is not tuple or (
        len(events[0]) != 2
    ):
        raise ValueError("original inert peer has no exact readable exit indication")

    observed_descriptor, flags = events[0]
    allowed = select.POLLIN | select.POLLHUP

    if type(observed_descriptor) is not int or observed_descriptor != descriptor or (
        type(flags) is not int or not flags & select.POLLIN
        or flags & (select.POLLERR | select.POLLNVAL) or flags & ~allowed
    ):
        raise ValueError("original inert peer exit indication is invalid")


def ReceiveReady(channel: socket.socket, envelope) -> tuple[int, int, int, tuple[int, ...]]:
    """Receive one original kernel peer and exactly one readonly quota directory FD.

    Args:
        channel: Accepted final sandbox pathname stream.
        envelope: Original fixed request.

    Returns:
        Original directory FD, direct peer pidfd, kernel peer locator and quota declaration.

    Raises:
        ValueError: Ancillary, wire, peer or descriptor facts are not exact.
    """

    received = []
    pidfd = None

    try:
        raw, ancillary, flags, _ = channel.recvmsg(CONTRACT.READY.size, socket.CMSG_SPACE(16 * 4),
            socket.MSG_CMSG_CLOEXEC | socket.MSG_WAITALL)
        valid_control = True

        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(data) % 4:
                valid_control = False
                continue

            values = array.array("i")
            values.frombytes(data)
            received.extend(values)

        if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or not valid_control or (
            len(ancillary) != 1 or len(received) != 1
        ):
            raise ValueError("inert READY ancillary descriptors refused")

        previous_timeout = channel.gettimeout()
        channel.setblocking(False)

        try:
            try:
                trailing = channel.recv(1, socket.MSG_PEEK)

            except BlockingIOError:
                trailing = b""

        finally:
            channel.settimeout(previous_timeout)

        if trailing:
            raise ValueError("inert READY has trailing data")

        declaration = CONTRACT.ParseReady(raw, envelope)
        directory = received[0]
        flags = fcntl.fcntl(directory, fcntl.F_GETFL)
        info = os.fstat(directory)

        if flags & os.O_ACCMODE != os.O_RDONLY or flags & os.O_PATH or (
            not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or (info.st_dev, info.st_ino) != declaration[:2]
            or not fcntl.fcntl(directory, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        ):
            raise ValueError("inert READY directory descriptor refused")

        kernel_raw = channel.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)

        if len(kernel_raw) != 4:
            raise ValueError("unsupported direct peer pidfd ABI")

        pidfd = struct.unpack("=i", kernel_raw)[0]

        if pidfd < 0 or not fcntl.fcntl(pidfd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise ValueError("invalid direct kernel peer pidfd")

        Alive(pidfd)
        peer_pid, peer_uid, peer_gid = struct.unpack("=iii",
            channel.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12))

        if peer_pid <= 0 or (peer_uid, peer_gid) != (os.getuid(), os.getgid()):
            raise ValueError("inert peer host owner differs")

        return directory, pidfd, peer_pid, declaration

    except BaseException:
        for descriptor in received:
            os.close(descriptor)

        if pidfd is not None and pidfd >= 0:
            os.close(pidfd)

        raise


def VerifyPeer(
    peer_pid: int, pidfd: int, directory: int, declaration: tuple[int, ...],
    request_bytes: bytes, materials: dict,
) -> dict:
    """Compare known-peer kernel observations and the original received quota FD.

    Args:
        peer_pid: Kernel credential PID used only as a known `/proc` locator.
        pidfd: Original direct peer pidfd guarding all locator inspection.
        directory: Original transferred quota directory.
        declaration: Untrusted READY quota fields, already bound to the request.
        request_bytes: Exact original closed binary request.
        materials: Parent-admitted original material identities.

    Returns:
        Bounded independently observed namespace and mount facts.

    Raises:
        ValueError: Any required confinement or original-file observation differs.
    """

    Alive(pidfd)
    peer = Path("/proc") / str(peer_pid)
    status = Fields(BoundedRead(peer / "status", 16384))

    if any(int(status[name].strip(), 16) for name in PEER_CAP_FIELDS) or (
        status["NoNewPrivs"].strip() != "1" or status["Threads"].strip() != "1"
    ):
        raise ValueError("inert peer privilege or single-thread facts differ")

    for name, owner_id in (("uid_map", os.getuid()), ("gid_map", os.getgid())):
        mapping = BoundedRead(peer / name, 1024).split()

        if mapping != [b"0", str(owner_id).encode(), b"1"]:
            raise ValueError("inert peer identity mapping differs")

    namespaces = {}

    for name in ("user", "mnt", "net", "pid", "ipc", "uts"):
        selected = os.readlink(peer / "ns" / name)

        if selected == os.readlink(Path("/proc/self/ns") / name):
            raise ValueError("inert peer shares a forbidden host namespace")

        namespaces[name] = selected

    mountinfo = BoundedRead(peer / "mountinfo", 65536).decode("ascii")
    mounts = {}

    for line in mountinfo.splitlines():
        left, right = line.split(" - ", 1)
        fields, super_fields = left.split(), right.split()
        mounts[fields[4]] = (set(fields[5].split(",")), super_fields)

    if set(mounts) != {"/", "/work", "/inert", "/request.bin", "/control.sock"}:
        raise ValueError("inert peer has an unexpected mounted filesystem")

    if "ro" not in mounts["/"][0] or any("ro" not in mounts[name][0]
        for name in ("/inert", "/request.bin", "/control.sock")):
        raise ValueError("inert root or fixed inputs are writable")

    work_flags, super_fields = mounts["/work"]

    if not {"rw", "nodev", "nosuid", "noexec"} <= work_flags or super_fields[0] != "tmpfs":
        raise ValueError("inert quota mount flags differ")

    quota = os.fstatvfs(directory)

    if (quota.f_frsize, quota.f_blocks, quota.f_files) != declaration[2:] or (
        quota.f_frsize * quota.f_blocks != CONTRACT.QUOTA_BYTES
        or quota.f_files != CONTRACT.QUOTA_INODES
    ):
        raise ValueError("inert received filesystem quota differs")

    descriptors = set()

    with os.scandir(peer / "fd") as entries:
        for entry in entries:
            descriptors.add(entry.name)

            if len(descriptors) > 5:
                raise ValueError("inert peer retains extra inherited descriptors")

    if not {"0", "1", "2", "4"} <= descriptors <= {"0", "1", "2", "3", "4"}:
        raise ValueError("inert peer descriptor roles differ")

    if not os.readlink(peer / "fd/4").startswith("socket:["):
        raise ValueError("inert final control descriptor differs")

    root = peer / "root"
    work = os.stat(root / "work")
    original = os.fstat(directory)

    if (work.st_dev, work.st_ino) != (original.st_dev, original.st_ino):
        raise ValueError("inert received directory is not the actual quota mount")

    for role, leaf in (("fixture", "inert"), ("request", "request.bin")):
        if Identity(os.stat(root / leaf)) != tuple(materials[role]["identity"]):
            raise ValueError("inert peer mounted different original material")

    if BoundedRead(root / "request.bin", 64) != request_bytes:
        raise ValueError("inert peer request bytes differ")

    for alias, expected in ALIASES.items():
        if os.readlink(root / alias) != expected or os.stat(root / alias).st_dev != work.st_dev:
            raise ValueError("inert writable alias differs from the original quota")

    for path in ("work/home", "work/tmp", "work/session", "work/report", "work/shm", "work/run"):
        child_info = os.lstat(root / path)

        if not stat.S_ISDIR(child_info.st_mode) or stat.S_IMODE(child_info.st_mode) != 0o700 or (
            child_info.st_uid != os.getuid() or child_info.st_dev != work.st_dev
        ):
            raise ValueError("inert work child differs from quota mount")

    report_directory = os.open("report", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | os.O_CLOEXEC, dir_fd=directory)

    try:
        try:
            os.stat("result.bin", dir_fd=report_directory, follow_symlinks=False)

        except FileNotFoundError:
            pass

        else:
            raise ValueError("late inert report exists before ACK")

    finally:
        os.close(report_directory)

    Alive(pidfd)

    return {"namespaces": namespaces, "quota": declaration, "mount_count": len(mounts)}


def ReadOriginal(directory: int, name: str, expected: tuple[int, ...] | None) -> bytes:
    """Read the exact original only after the caller has confirmed owned cleanup.

    Args:
        directory: Original retained quota directory FD.
        name: Closed setup or late-report role.
        expected: Original writer identity for late report; no substitute is accepted.

    Returns:
        Exact bounded original bytes.

    Raises:
        ValueError: Type, identity, length, mode or content differs.
    """

    if name not in {"setup", "report"}:
        raise ValueError("unknown inert custody role")

    parent = directory
    child = None

    try:
        if name == "report":
            child = os.open("report", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory)
            parent = child

        leaf = "result.bin" if name == "report" else "setup.bin"
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        identity = Identity(before)

        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or (
            before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size > 4096
            or expected is not None and identity != expected
        ):
            raise ValueError("inert original report identity refused")

        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)

        try:
            if Identity(os.fstat(descriptor)) != identity:
                raise ValueError("inert original changed at open")

            raw = os.read(descriptor, 4097)

            if len(raw) != before.st_size or Identity(os.fstat(descriptor)) != identity or (
                Identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity
            ):
                raise ValueError("inert original changed during read")

        finally:
            os.close(descriptor)

        if raw != (CONTRACT.REPORT_BYTES if name == "report" else CONTRACT.SETUP_BYTES):
            raise ValueError("inert original bytes differ")

        return raw

    finally:
        if child is not None:
            os.close(child)


def ReadyRemaining(deadline: float) -> float:
    """Deduct elapsed work from one original final READY deadline without renewal.

    Args:
        deadline: Original STARTED-derived monotonic deadline.

    Returns:
        Strictly positive remaining seconds.

    Raises:
        ValueError: Original deadline expired or the clock is invalid.
    """

    remaining = deadline - time.monotonic()

    if not math.isfinite(remaining) or remaining <= 0:
        raise ValueError("original inert final READY deadline expired")

    return remaining


async def WaitPeerExit(pidfd: int, deadline: float) -> None:
    """Observe only the original direct peer exit within the original invocation budget.

    Args:
        pidfd: Original direct kernel peer descriptor.
        deadline: Original invocation deadline, never renewed for a signal.
    """

    loop = asyncio.get_running_loop()
    exited = loop.create_future()

    def Observe() -> None:
        """Resolve one original direct-handle readiness observation."""

        if not exited.done():
            exited.set_result(None)

    loop.add_reader(pidfd, Observe)

    try:
        await asyncio.wait_for(exited, ReadyRemaining(deadline))

    finally:
        loop.remove_reader(pidfd)


def Acknowledge(
    channel: socket.socket, envelope, pidfd: int, cancellation: asyncio.Event,
    validate_current: Callable[[], None], owner_started: float, ready_deadline: float,
) -> None:
    """Release the one original request after synchronous fresh authority and liveness checks.

    Args:
        channel: Original accepted final-sandbox channel.
        envelope: Original bound closed request.
        pidfd: Original direct kernel peer handle.
        cancellation: Original execution cancellation bridge.
        validate_current: Same original synchronous policy validation.
        owner_started: Original owner monotonic origin.
        ready_deadline: Original final READY deadline, without renewal.

    Raises:
        ValueError: Authority, cancellation, liveness or the original deadline refuses release.
    """

    validate_current()

    if cancellation.is_set() or time.monotonic() - owner_started > 10:
        raise ValueError("inert authority or original deadline no longer admits ACK")

    Alive(pidfd)
    ReadyRemaining(ready_deadline)
    channel.sendall(envelope.Ack())


class CleanupPending(RuntimeError):
    """The original bounded cleanup did not settle; its exact task/handles remain owned."""


async def Settle(
    task: asyncio.Task, cancellation: asyncio.Event, *, deadline: float | None = None,
    on_caller_cancel: Callable[[], None] | None = None,
):
    """Settle one original task through caller cancellation within its absolute cleanup budget.

    Args:
        task: Single original executor task, never replaced or directly cancelled.
        cancellation: Its original cooperative cancellation bridge.
        deadline: Original absolute cleanup ceiling; never renewed on cancellation.
        on_caller_cancel: Preserve the first observed caller cancellation classification.

    Returns:
        Actual original terminal executor result.

    Raises:
        CleanupPending: The original task is still pending at its original cleanup ceiling.
        ValueError: The original task became terminally cancelled without a cleanup result.
    """

    while True:
        if task.done():
            if task.cancelled():
                raise ValueError("inert execution cleanup result is unknown")

            return task.result()

        try:
            if deadline is None:
                return await asyncio.shield(task)

            remaining = deadline - time.monotonic()

            if not math.isfinite(remaining) or remaining <= 0:
                cancellation.set()

                raise CleanupPending("original inert cleanup deadline expired")

            done, _ = await asyncio.wait((task,), timeout=remaining)

            if not done:
                cancellation.set()

                raise CleanupPending("original inert cleanup deadline expired")

        except asyncio.CancelledError:
            cancellation.set()

            if on_caller_cancel is not None:
                on_caller_cancel()

            if task.done() and task.cancelled():
                raise ValueError("inert execution cleanup result is unknown") from None


@dataclass(slots=True)
class Outcome:
    """Bounded test evidence with actual termination and separately stated custody."""

    execution: LocalExecutionResult | None
    observations: dict
    report: bytes | None
    setup: bytes | None
    complete: bool
    failure: str | None
    _retained_directory: int | None = field(init=False, default=None, repr=False)
    _retained_pidfd: int | None = field(init=False, default=None, repr=False)
    _retained_task: asyncio.Task | None = field(init=False, default=None, repr=False)
    _retained_runner: asyncio.Runner | None = field(init=False, default=None, repr=False)
    cleanup_confirmed: bool = field(init=False, default=False)
    observed_stdout_prefix: bytes = field(init=False, default=b"", repr=False)

    def ConfirmSettledRecovery(self) -> None:
        """Confirm only an already-settled original task; never wait, relaunch or renew a lease.

        Raises:
            ValueError: Original cleanup or direct peer exit is still unconfirmed.
        """

        task = self._retained_task

        if task is None or not task.done() or task.cancelled() or task.exception() is not None:
            raise ValueError("original inert recovery task has not confirmed cleanup")

        result = task.result()

        if not isinstance(result, LocalExecutionResult):
            raise ValueError("original inert recovery has no actual executor result")

        if self._retained_pidfd is not None:
            RequirePeerExit(self._retained_pidfd)

        self.execution = result
        self.cleanup_confirmed = True


    def CloseRecovery(self) -> None:
        """Close only this outcome's original retained mount after explicit test recovery."""

        if self._retained_task is not None and (not self._retained_task.done()
            or not self.cleanup_confirmed
        ):
            raise ValueError("original inert recovery ownership cannot be silently dropped")

        for name in ("_retained_directory", "_retained_pidfd"):
            descriptor = getattr(self, name)

            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

        self._retained_task = None

        if self._retained_runner is not None:
            self._retained_runner.close()
            self._retained_runner = None


def SaveTestEvidence(operation: Path, outcome: Outcome) -> None:
    """Persist bounded admitted originals once, with actual control last and no receipt claim.

    Args:
        operation: Original private operation directory.
        outcome: Actual post-cleanup result and original bounded reads.

    Raises:
        OSError: Publication is uncertain; callers preserve existing staging and original FD.
        ValueError: Admitted staging exceeds the fixed one-MiB bound.
    """

    stage = operation / "admitted-evidence"
    stage.mkdir(mode=0o700)
    if outcome.execution is None:
        records = {"observed-stdout-prefix.bin": outcome.observed_stdout_prefix}
        terminal = {"termination": None, "state": "unknown", "exit_code": None}

    else:
        records = {"stdout.bin": outcome.execution.stdout, "stderr.bin": outcome.execution.stderr}
        terminal = {"termination": outcome.execution.termination.value,
            "state": outcome.execution.execution.state.value,
            "exit_code": outcome.execution.execution.exit_code}

    if outcome.setup is not None:
        records["setup.bin"] = outcome.setup

    if outcome.report is not None:
        records["report.bin"] = outcome.report

    control = {**terminal, "cleanup_confirmed": outcome.cleanup_confirmed,
        "custody_complete": outcome.complete,
        "failure": outcome.failure, "observations": outcome.observations,
        "originals": {role: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for role, raw in records.items()}}
    records["actual.json"] = Canonical(control)

    if sum(map(len, records.values())) > 1048576:
        raise ValueError("inert admitted test staging exceeds its fixed bound")

    for role, raw in records.items():
        descriptor = os.open(stage / role, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

        try:
            if os.write(descriptor, raw) != len(raw):
                raise OSError("inert test original write incomplete")

            os.fsync(descriptor)

        finally:
            os.close(descriptor)

    descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


async def FinishOwned(
    task: asyncio.Task, cancellation: asyncio.Event, operation: Path,
    directory: int | None, pidfd: int | None, observations: dict,
    failure: str | None, started: float, observed_stdout: bytearray, sink,
) -> Outcome:
    """Funnel one owned execution through actual cleanup and bounded original custody.

    Args:
        task: The same original governed execution task.
        cancellation: Its original cancellation bridge.
        operation: Original admitted private operation.
        directory: Original received quota directory, ownership transferred by Run.
        pidfd: Original direct peer pidfd, ownership transferred by Run.
        observations: Original bounded kernel/control observations.
        failure: First failure already observed by the executing owner.
        started: Original owner monotonic origin; no deadline renewal.
        observed_stdout: Original bounded event prefix, not a synthesized terminal stream.
        sink: Same held host sink, used only for its bounded final counter.

    Returns:
        Actual or explicitly unknown execution and original recovery ownership.
    """

    result = None
    report = setup = None
    cleanup_confirmed = False
    custody_valid = True
    retain_originals = False

    def CallerCancelled() -> None:
        """Preserve the first caller cancellation while settling the same original task."""

        nonlocal failure
        failure = failure or "caller-cancelled"

    try:
        try:
            result = await Settle(task, cancellation, deadline=started + 20,
                on_caller_cancel=CallerCancelled)

        except Exception as error:
            failure = failure or "owned-cleanup-unknown-" + type(error).__name__
            retain_originals = True

        else:
            cleanup_confirmed = True

            if time.monotonic() > started + 20:
                failure = failure or "execution-cleanup-measured-late"

            if pidfd is not None:
                try:
                    RequirePeerExit(pidfd)

                    observations["original_peer_exited_after_cleanup"] = True

                except (OSError, ValueError):
                    cleanup_confirmed = False
                    failure = failure or "owned-cleanup-unknown-peer"
                    retain_originals = True

        if cleanup_confirmed and directory is not None:
            try:
                if time.monotonic() >= started + 28:
                    raise ValueError("original inert custody deadline expired")

                setup = ReadOriginal(directory, "setup", None)

                if time.monotonic() >= started + 28:
                    raise ValueError("original inert custody deadline expired")

                late_lines = [line for line in result.stdout.splitlines()
                    if line.startswith(b"LATE ")]

                if len(late_lines) == 1:
                    expected = tuple(int(value) for value in late_lines[0].split()[1:])

                    if len(expected) != 8 or expected[3] != 0:
                        raise ValueError("invalid original inert writer identity")

                    expected = expected[:3] + (os.getuid(),) + expected[4:]
                    report = ReadOriginal(directory, "report", expected)

                    if time.monotonic() >= started + 28:
                        raise ValueError("original inert custody deadline expired")

                else:
                    failure = failure or "missing-late-report"

            except (OSError, ValueError) as error:
                failure = failure or "custody-incomplete-" + type(error).__name__
                custody_valid = False
                retain_originals = True

        try:
            contacted, _ = sink.accept()

        except BlockingIOError:
            observations["host_sink_contacts"] = 0

        else:
            contacted.close()
            observations["host_sink_contacts"] = 1
            failure = failure or "host-network-contact"

        observations["host_sink_observation_final"] = cleanup_confirmed
        outcome = Outcome(result, observations, report, setup,
            report is not None and custody_valid and cleanup_confirmed, failure)
        outcome.cleanup_confirmed = cleanup_confirmed
        outcome.observed_stdout_prefix = bytes(observed_stdout)

        if time.monotonic() < started + 28:
            try:
                SaveTestEvidence(operation, outcome)

            except (OSError, ValueError) as error:
                outcome.failure = outcome.failure or "test-publication-" + type(error).__name__
                outcome.complete = False
                retain_originals = True

        else:
            outcome.failure = outcome.failure or "custody-publication-measured-late"
            outcome.complete = False
            retain_originals = True

        if time.monotonic() >= started + 28:
            outcome.failure = outcome.failure or "custody-publication-measured-late"
            outcome.complete = False
            retain_originals = True

        if time.monotonic() >= started + 30:
            outcome.failure = outcome.failure or "owner-measured-deadline"
            outcome.complete = False
            retain_originals = True

        if retain_originals:
            outcome._retained_directory, directory = directory, None
            outcome._retained_pidfd, pidfd = pidfd, None
            outcome._retained_task = task

        return outcome

    finally:
        for descriptor in (directory, pidfd):
            if descriptor is not None:
                os.close(descriptor)


async def Run(operation: Path, material_root: Path, mode: str, case: str) -> Outcome:
    """Run only one closed inert case through the existing policy and descendant owner.

    Args:
        operation: Fresh pytest-owned private operation directory.
        material_root: Fixed CI build directory containing only bwrap and inert fixture.
        mode: One closed inert mode.
        case: Closed acceptance scenario, never an execution parameter language.

    Returns:
        Actual result, bounded observations and post-cleanup original custody.

    Raises:
        ValueError: Preflight or the closed case binding is invalid.
    """

    cases = {"normal": "normal", "bytes": "byte-limit", "inodes": "inode-limit",
        "timeout": "wait", "cancel": "wait", "kill": "wait", "deny": "normal",
        "missing": "before-report"}

    if cases.get(case) != mode:
        raise ValueError("invalid closed inert acceptance case")

    started = time.monotonic()
    Preflight()
    operation.mkdir(mode=0o700)
    sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection = None
    operation_fd = None
    directory = pidfd = None
    observations = {}
    failure = None
    task = None
    cancellation = asyncio.Event()
    late = asyncio.Event()
    before_report = asyncio.Event()
    launched = asyncio.Event()
    work_complete = asyncio.Event()
    stream = bytearray()
    denied = False
    ready_deadline = None
    execution_handed_off = False

    try:
        sink.bind(("127.0.0.1", 0))
        sink.listen(1)
        sink.setblocking(False)
        held.bind(("127.0.0.1", 0))
        envelope = CONTRACT.Envelope(mode, sink.getsockname()[1], held.getsockname()[1],
            os.urandom(16), hashlib.sha256(str(operation).encode()).digest())
        request_path = operation / "request.bin"
        Exclusive(request_path, envelope.Encode())
        operation_fd = os.open(operation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC)
        listener.bind(f"/proc/self/fd/{operation_fd}/control.sock")
        os.chmod(operation / "control.sock", 0o600)
        listener.listen(1)
        listener.setblocking(False)
        materials = {"fixture": Material(material_root / "inert", executable=True),
            "bwrap": Material(material_root / "bin/bwrap", executable=True),
            "contract": Material(HERE / "contract.py", executable=False),
            "bootstrap": Material(HERE / "bootstrap.py", executable=False),
            "request": Material(request_path, executable=False)}
        provenance = VerifyBuild(material_root, materials)
        outer = {"operation": str(operation), "request_sha256": hashlib.sha256(
            envelope.Encode()).hexdigest(), "materials": materials}
        outer_path = operation / "bootstrap.json"
        Exclusive(outer_path, Canonical(outer))
        target = Target(TargetKind.IP, "127.0.0.1")
        scope = ScopeSnapshot("inert", "inert", ScopeAuthorization(
            AuthorizationState.GRANTED, "operator:inert-test", "approval:closed-inert"),
            targets=(target,), allow=(target,))
        policy = ImpactPolicy("closed-inert", permissions=(CapabilityPermission(
            "test.zap-inert", "native.zap-inert-test", ImpactLevel.SAFE),))
        context = PolicyContext(scope, policy, target, (target,))
        capability = CapabilityDescriptor(
            "test.zap-inert", "native.zap-inert-test", ImpactLevel.SAFE)
        invocation = AdapterInvocation("native.zap-inert-test", AdapterRequest(
            "test.zap-inert", target.Reference(), ImpactLevel.SAFE),
            (sys.executable, "-I", "-B", str(HERE / "bootstrap.py"), str(outer_path)), 11, "1")
        engine = PolicyEngine()
        grant = engine.Authorize(invocation, capability, context, at=datetime.now(timezone.utc))
        request = LocalExecutionRequest(invocation, capability, grant.authorization,
            workspace=operation.name, environment={},
            resources=ExecutionResources(16384, 16384, 0.5))
        executor = GovernedLocalExecutor(operation.parent)

        def CurrentContext():
            """Read the same current test authority; denial never becomes an ACK."""

            if denied:
                raise ValueError("original inert authority revoked")

            return context

        def OnEvent(event):
            """Observe original bounded stdout markers without reading a report before cleanup."""

            nonlocal ready_deadline

            if event.kind is ExecutionEventKind.STARTED:
                if ready_deadline is not None:
                    raise ValueError("original inert READY origin cannot be renewed")

                ready_deadline = time.monotonic() + 5
                launched.set()

            if event.kind is ExecutionEventKind.STDOUT:
                stream.extend(event.data)

                if len(stream) > 16384:
                    raise ValueError("inert stdout exceeded its owner cap")

                if b"LATE " in stream and (mode != "wait" or b"OWNED_CHILD " in stream):
                    late.set()

                if b"ACK_WITHOUT_REPORT\n" in stream:
                    before_report.set()

                if b"WORK_COMPLETE\n" in stream:
                    observations["work_complete_observed"] = True
                    work_complete.set()

        if time.monotonic() - started > 2:
            raise ValueError("inert preflight exceeded its measured budget")

        task = asyncio.create_task(executor.Execute(request, grant=grant,
            context_provider=CurrentContext, on_event=OnEvent, cancellation=cancellation,
            own_descendants=True))
        accept = asyncio.create_task(asyncio.get_running_loop().sock_accept(listener))
        start_wait = asyncio.create_task(launched.wait())

        try:
            started_done, _ = await asyncio.wait((task, start_wait), timeout=3,
                return_when=asyncio.FIRST_COMPLETED)

            if start_wait not in started_done:
                raise ValueError("inert original outer READY was not observed")

            if ready_deadline is None:
                raise ValueError("original final READY origin is absent")

            done, _ = await asyncio.wait((task, accept), timeout=ReadyRemaining(ready_deadline),
                return_when=asyncio.FIRST_COMPLETED)

            if accept not in done:
                raise ValueError("inert final READY was not obtained before exit/deadline")

            connection, _ = accept.result()
            connection.setblocking(True)
            connection.settimeout(min(1, ReadyRemaining(ready_deadline)))
            directory, pidfd, peer_pid, declaration = ReceiveReady(connection, envelope)
            observations = VerifyPeer(peer_pid, pidfd, directory, declaration,
                envelope.Encode(), materials)
            observations.update(build=provenance, final_ready_verified=True, ack_sent=False,
                intentional_authority_revocation=False, current_authority_refused=False,
                cooperative_cancel_requested=False, direct_peer_sigkill_requested=False,
                direct_peer_exit_observed=False, work_complete_observed=False,
                normal_release_requested=False)

            for role, original in materials.items():
                if Material(Path(original["path"]), executable=role in {"fixture", "bwrap"}) != (
                    original
                ):
                    raise ValueError("original inert material changed before ACK")

            if case == "deny":
                denied = True
                observations["intentional_authority_revocation"] = True

            def FreshAuthority() -> None:
                """Revalidate original policy synchronously immediately before the bound ACK."""

                try:
                    engine.Validate(grant, request.invocation, request.capability,
                        CurrentContext(), at=datetime.now(timezone.utc))

                except ValueError:
                    if denied:
                        observations["current_authority_refused"] = True

                    raise

            Acknowledge(connection, envelope, pidfd, cancellation, FreshAuthority,
                started, ready_deadline)
            observations["ack_sent"] = True
            connection.close()
            connection = None

            if case not in {"deny", "missing"}:
                readiness = work_complete if case in {"normal", "bytes", "inodes"} else late

                await asyncio.wait_for(readiness.wait(),
                    ReadyRemaining(ready_deadline - 5 + 11))
                Alive(pidfd)
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe.settimeout(0.5)

                try:
                    if probe.connect_ex(held.getsockname()) != 111:
                        raise ValueError("private live listener is exposed on host")

                finally:
                    probe.close()

                Alive(pidfd)
                observations["live_private_listener_host_refused"] = True

                if case in {"normal", "bytes", "inodes"}:
                    Alive(pidfd)
                    ReadyRemaining(ready_deadline - 5 + 11)
                    signal.pidfd_send_signal(pidfd, signal.SIGUSR1)
                    observations["normal_release_requested"] = True

            if case in {"cancel", "kill"}:
                if case == "kill":
                    Alive(pidfd)
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    observations["direct_peer_sigkill_requested"] = True

                    await WaitPeerExit(pidfd, ready_deadline - 5 + 11)
                    observations["direct_peer_exit_observed"] = True

                if not task.done():
                    observations["cooperative_cancel_requested"] = True
                    cancellation.set()

            elif case == "missing":
                await asyncio.wait_for(before_report.wait(), 5)
                observations["cooperative_cancel_requested"] = True
                cancellation.set()

        except asyncio.CancelledError:
            failure = failure or "caller-cancelled"
            cancellation.set()

        except (OSError, ValueError, TimeoutError) as error:
            failure = failure or type(error).__name__
            cancellation.set()

        finally:
            for pending in (accept, start_wait):
                if not pending.done():
                    pending.cancel()

                try:
                    await pending

                except asyncio.CancelledError:
                    current_task = asyncio.current_task()

                    if current_task is not None and current_task.cancelling():
                        failure = failure or "caller-cancelled"
                        cancellation.set()

        execution_handed_off = True
        custody_directory, directory = directory, None
        custody_pidfd, pidfd = pidfd, None

        return await FinishOwned(task, cancellation, operation, custody_directory, custody_pidfd,
            observations, failure, started, stream, sink)

    finally:
        cancellation.set()

        try:
            if task is not None and not task.done() and not execution_handed_off:
                await Settle(task, cancellation, deadline=started + 20)

        finally:
            for handle in (connection, listener, sink, held):
                if handle is not None:
                    handle.close()

            for descriptor in (directory, pidfd, operation_fd):
                if descriptor is not None:
                    os.close(descriptor)
