"""Portable local subprocess execution with explicit ownership and bounds."""

from __future__ import annotations

import asyncio
import inspect
import os
import signal
import subprocess
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

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


class LocalExecutionError(RuntimeError):
    """Fail-closed validation or process-launch error from the local executor."""


class LocalExecutor:
    """Execute one approved adapter invocation inside a bounded workspace root."""

    def __init__(self, workspace_root: Path) -> None:
        root = workspace_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace_root must be an existing directory")
        self._workspace_root = root

    async def execute(
        self,
        request: LocalExecutionRequest,
        *,
        on_event: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> LocalExecutionResult:
        """Run an immutable argv and return bounded output plus structured events."""
        workspace = self._resolve_workspace(request.workspace)
        events: list[ExecutionEvent] = []

        async def emit(
            kind: ExecutionEventKind,
            *,
            data: bytes = b"",
            termination: ExecutionTermination | None = None,
        ) -> None:
            event = ExecutionEvent(len(events), kind, data, termination)
            events.append(event)
            if on_event is not None:
                response = on_event(event)
                if inspect.isawaitable(response):
                    await cast(Awaitable[object], response)

        started = time.perf_counter()
        if cancellation is not None and cancellation.is_set():
            termination = ExecutionTermination.CANCELLATION
            await emit(ExecutionEventKind.COMPLETED, termination=termination)
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

        environment = {
            name: os.environ[name]
            for name in _INHERITED_ENVIRONMENT
            if name in os.environ
        }
        environment.update(request.environment)
        process = await self._start_process(request, workspace, environment)
        await emit(ExecutionEventKind.STARTED)

        stdout = bytearray()
        stderr = bytearray()
        output_limit = asyncio.Event()
        emit_lock = asyncio.Lock()

        async def pump(
            reader: asyncio.StreamReader,
            destination: bytearray,
            limit: int,
            kind: ExecutionEventKind,
        ) -> None:
            limited = False
            while chunk := await reader.read(_READ_SIZE):
                if limited:
                    continue
                remaining = limit - len(destination)
                retained = chunk[:remaining]
                if retained:
                    destination.extend(retained)
                    async with emit_lock:
                        await emit(kind, data=retained)
                if len(chunk) > remaining:
                    limited = True
                    output_limit.set()

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(
            pump(
                process.stdout,
                stdout,
                request.resources.max_stdout_bytes,
                ExecutionEventKind.STDOUT,
            )
        )
        stderr_task = asyncio.create_task(
            pump(
                process.stderr,
                stderr,
                request.resources.max_stderr_bytes,
                ExecutionEventKind.STDERR,
            )
        )
        process_task = asyncio.create_task(process.wait())
        output_limit_task = asyncio.create_task(output_limit.wait())
        cancellation_task = (
            asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        )
        waiters = {process_task, output_limit_task}
        if cancellation_task is not None:
            waiters.add(cancellation_task)

        termination = ExecutionTermination.PROCESS_EXIT
        state = ExecutionState.FAILED
        try:
            done, _ = await asyncio.wait(
                waiters,
                timeout=request.invocation.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                termination = ExecutionTermination.TIMEOUT
                state = ExecutionState.TIMED_OUT
                await self._terminate(process, request.resources.terminate_grace_seconds)
            elif output_limit_task in done and output_limit.is_set():
                termination = ExecutionTermination.OUTPUT_LIMIT
                state = ExecutionState.CANCELLED
                await self._terminate(process, request.resources.terminate_grace_seconds)
            elif (
                cancellation_task is not None
                and cancellation_task in done
                and cancellation is not None
                and cancellation.is_set()
                and not process_task.done()
            ):
                termination = ExecutionTermination.CANCELLATION
                state = ExecutionState.CANCELLED
                await self._terminate(process, request.resources.terminate_grace_seconds)
            else:
                natural_return_code = await process_task
                state = (
                    ExecutionState.SUCCEEDED
                    if natural_return_code == 0
                    else ExecutionState.FAILED
                )

            await process_task
            await asyncio.gather(stdout_task, stderr_task)
        except BaseException:
            await self._terminate(process, request.resources.terminate_grace_seconds)
            raise
        finally:
            for task in (output_limit_task, cancellation_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (output_limit_task, cancellation_task) if task is not None),
                return_exceptions=True,
            )

        final_return_code = process.returncode
        if state in {ExecutionState.TIMED_OUT, ExecutionState.CANCELLED} and final_return_code == 0:
            final_return_code = None
        await emit(ExecutionEventKind.COMPLETED, termination=termination)
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

    def _resolve_workspace(self, relative_workspace: str) -> Path:
        candidate = self._workspace_root.joinpath(*relative_workspace.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise LocalExecutionError(f"Execution workspace is unavailable: {relative_workspace}") from error
        if not resolved.is_dir():
            raise LocalExecutionError(f"Execution workspace is not a directory: {relative_workspace}")
        if not resolved.is_relative_to(self._workspace_root):
            raise LocalExecutionError("Execution workspace escapes the configured workspace root")
        return resolved

    async def _start_process(
        self,
        request: LocalExecutionRequest,
        workspace: Path,
        environment: dict[str, str],
    ) -> asyncio.subprocess.Process:
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

    async def _terminate(
        self,
        process: asyncio.subprocess.Process,
        grace_seconds: float,
    ) -> None:
        if process.returncode is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(process.wait(), timeout=grace_seconds)
            return
        except TimeoutError:
            pass

        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            return
        await process.wait()
