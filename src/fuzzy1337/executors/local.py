# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable local subprocess execution with explicit ownership and bounds."""

from __future__ import annotations

import asyncio
import errno
import inspect
import os
import signal
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from fuzzy1337.executors.owned_process import OwnedExecution

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.executors.contracts import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionRequest,
    LocalExecutionResult,
)

_INHERITED_ENVIRONMENT = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
)
_READ_SIZE = 64 * 1024

EventCallback = Callable[[ExecutionEvent], object]


def KillProcessGroup(process_id: int, termination_signal: int) -> None:
    """Call the POSIX-only process-group primitive behind a platform guard.

    The caller must apply a POSIX platform guard and ensure process-group ownership.

    Args:
        process_id: Owned POSIX process group leader identifier
        termination_signal: Signal to deliver to the group.

    Raises:
        ProcessLookupError: The process group no longer exists.
        OSError: The operating system rejects the owned-group signal.
    """

    killpg = cast(Callable[[int, int], None], getattr(os, "killpg"))
    killpg(process_id, termination_signal)


class LocalExecutionError(RuntimeError):
    """Fail-closed workspace, launch or owned-process cleanup error from the local executor."""


class LocalExecutor:
    """Execute one approved adapter invocation inside a bounded workspace root."""

    def __init__(self, workspace_root: Path) -> None:
        """Bind the executor to an existing workspace root.

        Args:
            workspace_root: Existing directory defining the workspace boundary.

        Raises:
            OSError: The root cannot be resolved.
            ValueError: The resolved root is not a directory.
        """

        root = workspace_root.resolve(strict=True)

        if not root.is_dir():
            raise ValueError("workspace_root must be an existing directory")

        self._workspace_root = root

    async def Execute(
        self,
        request: LocalExecutionRequest,
        *,
        on_event: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
        pre_launch: Callable[[LocalExecutionRequest], None] | None = None,
        own_descendants: bool = False,
    ) -> LocalExecutionResult:
        """Run an immutable argv and return bounded output plus structured events.

        Starts an owned process using explicit argv and a limited inherited environment.
        Observer errors and task cancellation propagate after owned cleanup,
        including the initial STARTED handoff. An operating-system denial or
        bounded cleanup failure instead raises LocalExecutionError.
        Awaitable observers must remain responsive; the process-wait timeout does
        not bound observer execution. Timeout, cancellation and output overflow
        during the process-wait phase terminate the owned process.
        This boundary is not an OS sandbox or a replacement for upstream scope approval.

        Args:
            request: Validated invocation, authorization binding, workspace and limits
            on_event: Optional synchronous or awaitable sequenced-event observer
            cancellation: Optional cooperative signal also checked before launch.
            pre_launch: Optional synchronous upstream policy check immediately before launch;
                must return None. Exceptions propagate without starting a process.
            own_descendants: Explicit Linux-only stronger descendant ownership. The default
                request serialization and direct process path remain unchanged.

        Returns:
            Terminal state, retained bounded streams and ordered lifecycle events.

        Raises:
            LocalExecutionError: Workspace validation, launch or bounded owned cleanup fails.
            asyncio.CancelledError: The caller cancels execution; cleanup completes first.
        """

        if type(own_descendants) is not bool or (
            own_descendants and sys.platform != "linux"
        ):
            raise LocalExecutionError(
                "Owned descendant execution requires an explicit Linux opt-in")

        if own_descendants:
            from fuzzy1337.executors.owned_process import RequireLinuxOwnership

            RequireLinuxOwnership()

        workspace = self.ResolveWorkspace(request.workspace)
        owned: OwnedExecution | None = None
        grace_seconds = request.resources.terminate_grace_seconds
        events: list[ExecutionEvent] = []

        async def Emit(
            kind: ExecutionEventKind,
            *,
            data: bytes = b"",
            termination: ExecutionTermination | None = None,
        ) -> None:
            """Record an event and notify the optional observer.

            Args:
                kind: Stream or lifecycle classification for the next sequence number.
                data: Retained output bytes; lifecycle events keep this empty.
                termination: Terminal reason supplied only for completion.

            Observer exceptions propagate to the execution owner.
            """

            event = ExecutionEvent(len(events), kind, data, termination)
            events.append(event)

            if on_event is not None:
                response = on_event(event)

                if inspect.isawaitable(response):
                    await cast(Awaitable[object], response)

        started = time.perf_counter()

        if cancellation is not None and cancellation.is_set():
            termination = ExecutionTermination.CANCELLATION

            await Emit(ExecutionEventKind.COMPLETED, termination=termination)

            return LocalExecutionResult(
                execution=AdapterExecution(
                    state=ExecutionState.CANCELLED,
                    exit_code=None,
                    duration_seconds=time.perf_counter() - started,
                ),
                termination=termination,
                stdout=b"",
                stderr=b"",
                events=tuple(events),
            )

        inherited_environment = {
            name: os.environ[name] for name in _INHERITED_ENVIRONMENT if name in os.environ
        }
        environment = {**inherited_environment, **request.environment}

        if pre_launch is not None:
            response = cast(Callable[[LocalExecutionRequest], object], pre_launch)(request)

            if response is not None:
                if inspect.iscoroutine(response):
                    response.close()

                raise LocalExecutionError("pre_launch must be synchronous and return None")

        if own_descendants:
            from fuzzy1337.executors.owned_process import (
                OWNED_PARENT_GRACE_SECONDS,
                StartOwnedExecution,
            )

            grace_seconds = max(grace_seconds, OWNED_PARENT_GRACE_SECONDS)

            def BeforeWorkerStart() -> None:
                """Recheck current authority after helper readiness and before the worker gate."""

                if pre_launch is not None:
                    response = cast(Callable[[LocalExecutionRequest], object], pre_launch)(request)

                    if response is not None:
                        if inspect.iscoroutine(response):
                            response.close()

                        raise LocalExecutionError("pre_launch must return None")

            owned = await StartOwnedExecution(request.invocation.argv, workspace, environment,
                inherited_environment, before_worker_start=BeforeWorkerStart)
            process = owned.process

        else:
            process = await self.StartProcess(request, workspace, environment)

        stdout = bytearray()
        stderr = bytearray()

        output_limit = asyncio.Event()
        emit_lock = asyncio.Lock()

        async def Pump(
            reader: asyncio.StreamReader,
            destination: bytearray,
            limit: int,
            kind: ExecutionEventKind,
        ) -> None:
            """Drain one process stream while enforcing its byte limit.

            Args:
                reader: Captured stdout or stderr pipe owned by this invocation.
                destination: Buffer receiving retained bytes up to the configured limit.
                limit: Maximum retained bytes for this stream.
                kind: Stream event classification emitted for retained chunks.

            Discards excess bytes while draining the pipe and signals output overflow.
            """

            limited = False

            while chunk := await reader.read(_READ_SIZE):
                if limited:
                    continue

                remaining = limit - len(destination)
                retained = chunk[:remaining]

                if retained:
                    destination.extend(retained)

                    async with emit_lock:
                        await Emit(kind, data=retained)

                if len(chunk) > remaining:
                    limited = True
                    output_limit.set()

        assert process.stdout is not None, "Subprocess stdout pipe must be available."
        assert process.stderr is not None, "Subprocess stderr pipe must be available."

        stdout_task = asyncio.create_task(
            Pump(
                process.stdout,
                stdout,
                request.resources.max_stdout_bytes,
                ExecutionEventKind.STDOUT,
            )
        )
        stderr_task = asyncio.create_task(
            Pump(
                process.stderr,
                stderr,
                request.resources.max_stderr_bytes,
                ExecutionEventKind.STDERR,
            )
        )

        process_task = asyncio.create_task(process.wait() if owned is None else owned.Wait())
        output_limit_task = asyncio.create_task(output_limit.wait())
        cancellation_task = (
            asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        )

        waiters = {process_task, output_limit_task, stdout_task, stderr_task}

        if cancellation_task is not None:
            waiters.add(cancellation_task)

        termination = ExecutionTermination.PROCESS_EXIT
        state = ExecutionState.FAILED
        owned_tasks = (stdout_task, stderr_task, process_task, output_limit_task, cancellation_task)

        async def Join(*awaitables: Awaitable[object]) -> None:
            """Bound owned exit/pipe joins by the configured termination grace.

            Args:
                awaitables: Owned process-wait or stream-drain tasks to finish.

            Raises:
                LocalExecutionError: A join times out or the operating system rejects cleanup.
            """

            try:
                await asyncio.wait_for(
                    asyncio.gather(*awaitables),
                    timeout=grace_seconds,
                )

            except (TimeoutError, OSError) as error:
                raise LocalExecutionError("Owned execution cleanup could not complete") from error

        try:
            async with emit_lock:
                await Emit(ExecutionEventKind.STARTED)

            deadline = time.monotonic() + request.invocation.timeout_seconds

            while True:
                done, _ = await asyncio.wait(
                    waiters,
                    timeout=max(0.0, deadline - time.monotonic()),
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for stream_task in (stdout_task, stderr_task):
                    if stream_task in done:
                        stream_task.result()
                        waiters.discard(stream_task)

                if not done or done.intersection(
                    {process_task, output_limit_task, cancellation_task}
                ):
                    break

            if not done:
                termination = ExecutionTermination.TIMEOUT
                state = ExecutionState.TIMED_OUT

                await self.Terminate(process, grace_seconds)

            elif output_limit_task in done and output_limit.is_set():
                termination = ExecutionTermination.OUTPUT_LIMIT
                state = ExecutionState.CANCELLED

                await self.Terminate(process, grace_seconds)

            elif (
                cancellation_task is not None
                and cancellation_task in done
                and cancellation is not None
                and cancellation.is_set()
                and not process_task.done()
            ):
                termination = ExecutionTermination.CANCELLATION
                state = ExecutionState.CANCELLED

                await self.Terminate(process, grace_seconds)

            else:
                natural_return_code = await process_task
                state = (
                    ExecutionState.SUCCEEDED if natural_return_code == 0 else ExecutionState.FAILED
                )

            await Join(process_task)

            await asyncio.gather(stdout_task, stderr_task)

        except BaseException:
            async def Abort() -> None:
                """Stop observers, drain bounded chunks and reap the owned child."""

                for task in owned_tasks:
                    if task is not None and not task.done():
                        task.cancel()

                await asyncio.gather(
                    *(task for task in owned_tasks if task is not None), return_exceptions=True,
                )

                async def Drain(reader: asyncio.StreamReader) -> None:
                    """Discard pipe bytes without invoking observers or retaining output.

                    Args:
                        reader: Owned stdout or stderr pipe after its observer task stops.
                    """

                    while await reader.read(_READ_SIZE):
                        pass

                drains = [
                    asyncio.create_task(Drain(reader))
                    for reader in (process.stdout, process.stderr) if reader is not None
                ]

                try:
                    await self.Terminate(process, grace_seconds)

                    if owned is not None:
                        owned.Verify()

                    await Join(*drains)

                finally:
                    for task in drains:
                        if not task.done():
                            task.cancel()

                    await asyncio.gather(*drains, return_exceptions=True)

            cleanup_task = asyncio.create_task(Abort())

            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)

                except asyncio.CancelledError:
                    continue

            cleanup_task.result()

            raise

        finally:
            for task in owned_tasks:
                if task is not None and not task.done():
                    task.cancel()

            await asyncio.gather(
                *(task for task in owned_tasks if task is not None),
                return_exceptions=True,
            )

            if owned is not None:
                owned.Close()

        final_return_code = process.returncode if owned is None else owned.worker_returncode

        if state in {ExecutionState.TIMED_OUT, ExecutionState.CANCELLED} and final_return_code == 0:
            final_return_code = None

        await Emit(ExecutionEventKind.COMPLETED, termination=termination)

        return LocalExecutionResult(
            execution=AdapterExecution(
                state=state,
                exit_code=final_return_code,
                duration_seconds=time.perf_counter() - started,
            ),
            termination=termination,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            events=tuple(events),
        )

    def ResolveWorkspace(self, relative_workspace: str) -> Path:
        """Resolve a workspace path without permitting root escape.

        Resolves symlinks before checking containment; does not create directories.

        Args:
            relative_workspace: Workspace path relative to the configured executor root.

        Returns:
            Resolved existing directory contained within the executor root.

        Raises:
            LocalExecutionError: The workspace is unavailable, not a directory or escapes the
                root.
        """

        candidate = self._workspace_root.joinpath(*relative_workspace.split("/"))

        try:
            resolved = candidate.resolve(strict=True)

        except OSError as error:
            raise LocalExecutionError(
                f"Execution workspace is unavailable: {relative_workspace}"
            ) from error

        if not resolved.is_dir():
            raise LocalExecutionError(
                f"Execution workspace is not a directory: {relative_workspace}"
            )

        if not resolved.is_relative_to(self._workspace_root):
            raise LocalExecutionError("Execution workspace escapes the configured workspace root")

        return resolved

    async def StartProcess(
        self,
        request: LocalExecutionRequest,
        workspace: Path,
        environment: dict[str, str],
    ) -> asyncio.subprocess.Process:
        """Start an owned subprocess with isolated output streams.

        Uses a new POSIX session or Windows process group. Callers own subsequent termination
        and stream draining; this helper does not perform scope authorization.

        Args:
            request: Validated request supplying explicit argv
            workspace: Directory previously resolved within the executor root
            environment: Complete child environment prepared by the caller.

        Returns:
            Owned child process with captured stdout and stderr pipes.

        Raises:
            LocalExecutionError: The operating system rejects process launch.
        """

        arguments = request.invocation.argv

        try:
            if os.name == "posix":
                return await asyncio.create_subprocess_exec(
                    *arguments,
                    cwd=workspace,
                    env=environment,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )

            return await asyncio.create_subprocess_exec(
                *arguments,
                cwd=workspace,
                env=environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )

        except OSError as error:
            detail = error.strerror or str(error)

            raise LocalExecutionError(f"Could not start approved invocation: {detail}") from error

    async def Terminate(
        self,
        process: asyncio.subprocess.Process,
        grace_seconds: float,
    ) -> None:
        """Terminate the owned process group and escalate after the grace period.

        Known exited children are never signaled again. Each exit wait is bounded.
        POSIX EPERM recovery requires observed child exit and a non-mutating check
        proving group disappearance. Vanished groups still require observed child
        exit. Windows uses the owned subprocess terminate/kill operations.

        Args:
            process: Child process owned by this executor
            grace_seconds: Maximum exit-observation wait in each termination phase.

        Raises:
            LocalExecutionError: Signaling or bounded reaping cannot confirm owned cleanup.
        """

        if process.returncode is not None:
            return

        async def ObserveExit() -> bool:
            """Independently observe owned-child exit without an unbounded waiter.

            Returns:
                True only when the owned wait finishes and publishes a return code.

            Raises:
                LocalExecutionError: The operating system rejects owned-child reaping.
            """

            try:
                await asyncio.wait_for(process.wait(), timeout=grace_seconds)

            except TimeoutError:
                return False

            except OSError as error:
                raise LocalExecutionError("Could not observe owned process exit") from error

            return process.returncode is not None

        async def Signal(*, forced: bool) -> bool:
            """Signal only a still-owned child or prove a narrowly recovered exit race.

            Args:
                forced: Escalate to KILL instead of the initial TERM request.

            Returns:
                True when owned-child exit is already known or independently confirmed.

            Raises:
                LocalExecutionError: Signaling denial or group disappearance is unresolved.
            """

            if process.returncode is not None:
                return True

            try:
                if os.name == "posix":
                    selected = cast(int, getattr(signal, "SIGKILL")) if forced else signal.SIGTERM
                    KillProcessGroup(process.pid, selected)

                elif forced:
                    process.kill()

                else:
                    process.terminate()

            except ProcessLookupError as error:
                if os.name == "posix" and error.errno != errno.ESRCH:
                    raise LocalExecutionError(
                        "Could not confirm process group disappearance"
                    ) from error

                if await ObserveExit():
                    return True

                raise LocalExecutionError(
                    "Vanished process group has unconfirmed child exit"
                ) from error

            except OSError as error:
                if os.name != "posix" or error.errno != errno.EPERM:
                    raise LocalExecutionError("Could not signal owned local execution") from error

                if not await ObserveExit():
                    raise LocalExecutionError("Denied signal has unconfirmed child exit") from error

                try:
                    KillProcessGroup(process.pid, 0)

                except ProcessLookupError as proof_error:
                    if proof_error.errno == errno.ESRCH:
                        return True

                    raise LocalExecutionError(
                        "Could not confirm process group disappearance"
                    ) from proof_error

                except OSError as proof_error:
                    raise LocalExecutionError(
                        "Could not confirm process group disappearance"
                    ) from proof_error

                raise LocalExecutionError(
                    "Denied process group remains after child exit"
                ) from error

            return False

        if await Signal(forced=False) or await ObserveExit():
            return

        if await Signal(forced=True) or await ObserveExit():
            return

        raise LocalExecutionError("Owned process did not exit after forced termination")
