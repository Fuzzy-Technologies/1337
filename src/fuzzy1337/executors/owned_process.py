# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Private bounded Linux supervisor configuration and verified cleanup receipts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fuzzy1337.executors.local import LocalExecutionError

MAX_CONFIGURATION_BYTES = 65536
MAX_RECEIPT_BYTES = 512
MAX_OWNED_PROCESSES = 128
OWNED_CLEANUP_SECONDS = 2.0
OWNED_PARENT_GRACE_SECONDS = 3.0
# Linux UAPI values are stable even when a Python build omits conditional fcntl names.
LINUX_F_ADD_SEALS = 1033
LINUX_F_GET_SEALS = 1034
LINUX_REQUIRED_SEALS = 0x0F
_RECEIPT_FIELDS = frozenset({"schema_version", "configuration_sha256", "cleanup",
                            "worker_returncode", "reaped_processes", "failure"})
_FAILURES = frozenset({"setup", "spawn", "parent-lost", "ownership", "limit", "timeout"})


def RequireLinuxOwnership() -> None:
    """Refuse unsupported platforms or procfs without reading another job's child list.

    Raises:
        LocalExecutionError: Required Linux primitives or this process's child interface are absent.
    """

    if sys.platform != "linux" or not hasattr(os, "memfd_create"):
        raise LocalExecutionError("Owned descendant execution requires supported Linux primitives")

    own_pid = os.getpid()

    try:
        descriptor = os.open(f"/proc/{own_pid}/task/{own_pid}/children", os.O_RDONLY | os.O_CLOEXEC)
        os.close(descriptor)

    except OSError:
        raise LocalExecutionError("Linux owned-child interface is unavailable") from None


def CanonicalControl(value: object) -> bytes:
    """Serialize only private control data; no source or environment enters public streams.

    Args:
        value: Finite internally constructed control fields.

    Returns:
        Canonical ASCII JSON with one LF terminator.
    """

    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii") + b"\n"


def UniqueControl(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse duplicate private fields before last-key-wins decoding loses their identity.

    Args:
        pairs: Original decoder field sequence, before a mapping discards duplicates.

    Returns:
        Unique original control fields without interpretation.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate private control field")

        result[key] = value

    return result


def DecodeControl(raw: bytes, maximum: int) -> dict[str, object]:
    """Require bounded exact canonical JSON without exposing raw control diagnostics.

    Args:
        raw: Private immutable bytes received through the sealed file or receipt pipe.
        maximum: Fixed profile-specific byte ceiling.

    Returns:
        Original canonical object; shape and field types are checked by its consumer.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise ValueError("private control size differs")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=UniqueControl)

    if type(value) is not dict or raw != CanonicalControl(value):
        raise ValueError("private control encoding differs")

    return value


def WrapperExit(returncode: int) -> int:
    """Represent a signed original worker status in the supervisor's ordinary exit range.

    Args:
        returncode: Actual original worker's ordinary or negative signal status.

    Returns:
        The corresponding portable nonnegative supervisor exit status.
    """

    return returncode if returncode >= 0 else 128 - returncode


@dataclass(slots=True)
class OwnedExecution:
    """Own the actual supervisor plus its private single-consumer cleanup receipt."""

    process: asyncio.subprocess.Process
    receipt_fd: int
    configuration_sha256: str
    ready_fd: int = -1
    worker_returncode: int | None = None
    verified: bool = False
    receipt: dict[str, object] | None = None

    async def Wait(self) -> int:
        """Observe supervisor exit and verify cleanup before publishing original worker status.

        Returns:
            The actual signed-integer worker return code after confirmed descendant cleanup.

        Raises:
            LocalExecutionError: Supervisor, receipt, worker launch or cleanup is unverified.
        """

        await self.process.wait()

        return self.Verify()

    async def AwaitReady(self) -> None:
        """Require one exact private readiness byte before the final synchronous launch check."""

        if self.ready_fd < 0:
            raise LocalExecutionError("Owned supervisor readiness has no private descriptor")

        loop = asyncio.get_running_loop()
        ready: asyncio.Future[None] = loop.create_future()
        descriptor = self.ready_fd
        os.set_blocking(descriptor, False)

        def Receive() -> None:
            """Consume only the separate fixed readiness byte, leaving the receipt untouched."""

            try:
                value = os.read(descriptor, 2)

                if value != b"1":
                    raise ValueError("invalid readiness handoff")

            except (OSError, ValueError):
                if not ready.done():
                    ready.set_exception(LocalExecutionError("Owned supervisor readiness failed"))

            else:
                if not ready.done():
                    ready.set_result(None)

        loop.add_reader(descriptor, Receive)

        try:
            await asyncio.wait_for(ready, OWNED_PARENT_GRACE_SECONDS)

        except TimeoutError:
            raise LocalExecutionError("Owned supervisor readiness deadline exceeded") from None

        finally:
            loop.remove_reader(descriptor)
            os.close(descriptor)
            self.ready_fd = -1

    def Verify(self) -> int:
        """Read the bounded receipt only after the sole descriptor owner exited.

        Returns:
            Cached or newly verified original signed-integer worker return code.
        """

        if self.verified:
            assert self.worker_returncode is not None, "Verified original status must be present."

            return self.worker_returncode

        try:
            record = self.ReadReceipt()
            status = record.get("worker_returncode")

            if record["cleanup"] != "confirmed" or record["failure"] is not None or (
                type(status) is not int or record["reaped_processes"] == 0
                or self.process.returncode != WrapperExit(status)
            ):
                raise LocalExecutionError("Owned cleanup unconfirmed: "
                    f"cleanup={record['cleanup']}, failure={record['failure']}, "
                    f"worker={status}, supervisor={self.process.returncode}, "
                    f"reaped={record['reaped_processes']}")

            self.worker_returncode = status
            self.verified = True

            return status

        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise LocalExecutionError("Owned descendant launch or cleanup could not be confirmed") \
                from None

        finally:
            self.Close()

    def ReadReceipt(self) -> dict[str, object]:
        """Validate the sole private receipt after supervisor exit without accepting success.

        Returns:
            Cached strict control fields; the caller separately checks launch/cleanup outcome.
        """

        if self.receipt is not None:
            return self.receipt

        try:
            if self.process.returncode is None or self.receipt_fd < 0:
                raise ValueError("owned supervisor has no exit proof")

            record = DecodeControl(os.read(self.receipt_fd, MAX_RECEIPT_BYTES + 1),
                                   MAX_RECEIPT_BYTES)
            status, reaped, failure = (record.get("worker_returncode"),
                                      record.get("reaped_processes"), record.get("failure"))

            if set(record) != _RECEIPT_FIELDS or (
                type(record["schema_version"]) is not int or record["schema_version"] != 1
                or record["configuration_sha256"] != self.configuration_sha256
                or record["cleanup"] not in ("confirmed", "failed")
                or status is not None and (type(status) is not int or not -64 <= status <= 255)
                or type(reaped) is not int or not 0 <= reaped <= MAX_OWNED_PROCESSES
                or failure is not None and (type(failure) is not str or failure not in _FAILURES)
            ):
                raise ValueError("owned supervisor receipt fields differ")

            self.receipt = record

            return record

        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise LocalExecutionError("Owned supervisor receipt could not be verified") from None

        finally:
            self.Close()

    def VerifyUnstarted(self) -> None:
        """Confirm an interrupted handoff left no approved worker and reaped its supervisor."""

        record = self.ReadReceipt()

        if self.process.returncode != 125 or record["cleanup"] != "confirmed" or (
            record["worker_returncode"] is not None or record["reaped_processes"] != 0
            or record["failure"] not in _FAILURES
        ):
            raise LocalExecutionError("Interrupted owned worker handoff has unconfirmed cleanup")

    def Close(self) -> None:
        """Release the private parent descriptor exactly once, including failed verification."""

        if self.receipt_fd >= 0:
            descriptor, self.receipt_fd = self.receipt_fd, -1
            os.close(descriptor)

        if self.ready_fd >= 0:
            descriptor, self.ready_fd = self.ready_fd, -1
            os.close(descriptor)


async def StartOwnedExecution(argv: tuple[str, ...], workspace: Path,
                              environment: dict[str, str], helper_environment: dict[str, str],
                              *, before_worker_start: Callable[[], None] | None = None,
                              ) -> OwnedExecution:
    """Launch the isolated installed supervisor using sealed configuration and private receipt.

    Args:
        argv: Exact original already-approved invocation, never a new command authority.
        workspace: Existing executor-resolved owning directory.
        environment: Original existing worker environment including explicit validated overrides.
        helper_environment: Separately sanitized inherited environment without worker overrides.
        before_worker_start: Fresh synchronous policy check after helper readiness, immediately
            before the sole worker-start acknowledgement with no intervening await.

    Returns:
        Actual supervisor process and its sole parent-owned receipt reader.

    Raises:
        LocalExecutionError: Linux primitives, configuration bounds or helper launch fail.
    """

    RequireLinuxOwnership()

    import fcntl

    configuration_fd = read_fd = write_fd = gate_read_fd = gate_write_fd = -1
    ready_read_fd = ready_write_fd = -1
    process: asyncio.subprocess.Process | None = None
    owned: OwnedExecution | None = None
    launch_task: asyncio.Task[asyncio.subprocess.Process] | None = None
    phase = "configuration"
    handoff_attempted = False

    try:
        raw = CanonicalControl({"schema_version": 1, "parent_pid": os.getpid(),
                                "argv": argv, "environment": environment})

        if len(raw) > MAX_CONFIGURATION_BYTES:
            raise ValueError("owned execution configuration exceeds its bound")

        phase = "sealed-file"
        configuration_fd = os.memfd_create("1337-owned-execution", os.MFD_CLOEXEC |
                                          os.MFD_ALLOW_SEALING)

        if os.write(configuration_fd, raw) != len(raw):
            raise OSError("private configuration write was incomplete")

        os.lseek(configuration_fd, 0, os.SEEK_SET)
        fcntl.fcntl(configuration_fd, LINUX_F_ADD_SEALS, LINUX_REQUIRED_SEALS)

        if fcntl.fcntl(configuration_fd, LINUX_F_GET_SEALS) & LINUX_REQUIRED_SEALS != (
            LINUX_REQUIRED_SEALS
        ):
            raise OSError("private configuration seals were not established")
        phase = "control-pipes"
        read_fd, write_fd = os.pipe()
        gate_read_fd, gate_write_fd = os.pipe()
        ready_read_fd, ready_write_fd = os.pipe()
        digest = hashlib.sha256(raw).hexdigest()
        phase = "supervisor-launch"
        launch_task = asyncio.create_task(asyncio.create_subprocess_exec(sys.executable, "-I", "-m",
            "fuzzy1337.executors.descendant_supervisor", str(configuration_fd), str(write_fd),
            digest, str(gate_read_fd), str(ready_write_fd), cwd=workspace, env=helper_environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
            pass_fds=(configuration_fd, write_fd, gate_read_fd, ready_write_fd)))
        process = await asyncio.shield(launch_task)
        owned = OwnedExecution(process, read_fd, digest, ready_fd=ready_read_fd)
        read_fd = ready_read_fd = -1

        for descriptor in (configuration_fd, write_fd, gate_read_fd, ready_write_fd):
            os.close(descriptor)

        configuration_fd = write_fd = gate_read_fd = ready_write_fd = -1
        phase = "helper-readiness"

        await owned.AwaitReady()

        phase = "authority"

        if before_worker_start is not None:
            result = before_worker_start()

            if result is not None:
                raise LocalExecutionError("Owned final launch check must return None")

        phase = "start-handoff"
        handoff_attempted = True

        if os.write(gate_write_fd, b"1") != 1:
            raise OSError("owned worker start handoff failed")

        return owned

    except BaseException as error:
        # Closing the gate before awaiting startup prevents any interrupted payload launch.
        if gate_write_fd >= 0:
            os.close(gate_write_fd)
            gate_write_fd = -1

        if launch_task is not None:
            async def AbortHandoff() -> None:
                """Finish owned startup, then verify an unstarted worker and exited supervisor."""

                nonlocal process, owned, read_fd, ready_read_fd
                nonlocal configuration_fd, write_fd, gate_read_fd, ready_write_fd

                if process is None:
                    try:
                        process = await asyncio.wait_for(asyncio.shield(launch_task),
                                                         OWNED_PARENT_GRACE_SECONDS)

                    except (OSError, ValueError):
                        return

                # Keep inherited descriptor identities reserved until subprocess startup finishes.
                for descriptor in (configuration_fd, write_fd, gate_read_fd, ready_write_fd):
                    if descriptor >= 0:
                        os.close(descriptor)

                configuration_fd = write_fd = gate_read_fd = ready_write_fd = -1

                if handoff_attempted and process.returncode is None:
                    try:
                        process.terminate()

                    except ProcessLookupError:
                        pass

                try:
                    await asyncio.wait_for(process.wait(), OWNED_PARENT_GRACE_SECONDS)

                except TimeoutError:
                    if process.returncode is None:
                        try:
                            process.kill()

                        except ProcessLookupError:
                            pass

                        await asyncio.wait_for(process.wait(), OWNED_PARENT_GRACE_SECONDS)

                    raise LocalExecutionError("Interrupted owned supervisor required forced stop")

                if owned is None:
                    owned = OwnedExecution(process, read_fd, digest, ready_fd=ready_read_fd)
                    read_fd = ready_read_fd = -1

                record = owned.ReadReceipt()

                if record["worker_returncode"] is None:
                    owned.VerifyUnstarted()

                else:
                    owned.Verify()

                owned.Close()

            cleanup_task = asyncio.create_task(AbortHandoff())

            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)

                except asyncio.CancelledError:
                    continue

            try:
                cleanup_task.result()

            except BaseException:
                if not launch_task.done():
                    launch_task.cancel()

                if owned is not None:
                    owned.Close()

                raise LocalExecutionError("Interrupted owned supervisor cleanup is unconfirmed") \
                    from None

        if phase == "authority" or isinstance(error,
            (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise

        error_number = getattr(error, "errno", None)
        diagnostic = str(error_number) if type(error_number) is int else "unavailable"
        raise LocalExecutionError(f"Owned execution failed at {phase} (errno {diagnostic})") \
            from None

    finally:
        if launch_task is not None and not launch_task.done():
            reserved = (configuration_fd, write_fd, gate_read_fd, ready_write_fd)
            configuration_fd = write_fd = gate_read_fd = ready_write_fd = -1

            def ReleaseAfterStartup(task: asyncio.Task[asyncio.subprocess.Process]) -> None:
                """Release reserved descriptor identities only after startup cannot inherit them.

                Args:
                    task: Sole original subprocess-creation owner, including startup failure.
                """

                for descriptor in reserved:
                    if descriptor >= 0:
                        os.close(descriptor)

                if not task.cancelled():
                    task.exception()

            launch_task.add_done_callback(ReleaseAfterStartup)

        for descriptor in (configuration_fd, read_fd, write_fd, gate_read_fd, gate_write_fd,
                           ready_read_fd, ready_write_fd):
            if descriptor >= 0:
                os.close(descriptor)
