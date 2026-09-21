"""Переносимый запуск дочерних процессов с явным владением и лимитами."""

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

INHERITEDENVIRONMENT = (
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
READSIZE = 64 * 1024

EventCallback = Callable[[ExecutionEvent], object]


def KillProcessGroup(processId: int, terminationSignal: int) -> None:
    """Вызывает POSIX-операцию группы процессов под защитой платформы."""

    killpg = cast(Callable[[int, int], None], getattr(os, "killpg"))
    killpg(processId, terminationSignal)


class LocalExecutionError(RuntimeError):
    """Описывает закрытую ошибку проверки или запуска процесса."""

    pass


class LocalExecutor:
    """Выполняет одобренный вызов внутри ограниченной рабочей области."""

    def __init__(self, workspaceRoot: Path) -> None:
        """Фиксирует существующий корень рабочих областей."""

        root = workspaceRoot.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace_root must be an existing directory")
        self.workspaceRoot = root

    async def Execute(
        self,
        request: LocalExecutionRequest,
        *,
        onEvent: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> LocalExecutionResult:
        """Запускает неизменяемый argv и возвращает вывод с событиями."""

        workspace = self.ResolveWorkspace(request.workspace)
        events: list[ExecutionEvent] = []

        async def Emit(
            kind: ExecutionEventKind,
            *,
            data: bytes = b"",
            termination: ExecutionTermination | None = None,
        ) -> None:
            """Добавляет событие и уведомляет необязательного наблюдателя."""

            event = ExecutionEvent(len(events), kind, data, termination)
            events.append(event)
            if onEvent is not None:
                response = onEvent(event)
                if inspect.isawaitable(response):
                    await cast(Awaitable[object], response)

        started = time.perf_counter()
        if cancellation is not None and cancellation.is_set():
            termination = ExecutionTermination.CANCELLATION
            await Emit(ExecutionEventKind.COMPLETED, termination=termination)
            return LocalExecutionResult(
                execution=AdapterExecution(
                    state=ExecutionState.CANCELLED,
                    exitCode=None,
                    durationSeconds=time.perf_counter() - started,
                ),
                termination=termination,
                stdout=b"",
                stderr=b"",
                events=tuple(events),
            )

        environment = {
            name: os.environ[name]
            for name in INHERITEDENVIRONMENT
            if name in os.environ
        }
        environment.update(request.environment)
        process = await self.StartProcess(request, workspace, environment)
        await Emit(ExecutionEventKind.STARTED)

        stdout = bytearray()
        stderr = bytearray()
        outputLimit = asyncio.Event()
        emitLock = asyncio.Lock()

        async def Pump(
            reader: asyncio.StreamReader,
            destination: bytearray,
            limit: int,
            kind: ExecutionEventKind,
        ) -> None:
            """Читает поток, сохраняя только разрешённый объём данных."""

            limited = False
            while chunk := await reader.read(READSIZE):
                if limited:
                    continue
                remaining = limit - len(destination)
                retained = chunk[:remaining]
                if retained:
                    destination.extend(retained)
                    async with emitLock:
                        await Emit(kind, data=retained)
                if len(chunk) > remaining:
                    limited = True
                    outputLimit.set()

        assert process.stdout is not None, "subprocess stdout pipe must be available"
        assert process.stderr is not None, "subprocess stderr pipe must be available"
        stdoutTask = asyncio.create_task(
            Pump(
                process.stdout,
                stdout,
                request.resources.maxStdoutBytes,
                ExecutionEventKind.STDOUT,
            )
        )
        stderrTask = asyncio.create_task(
            Pump(
                process.stderr,
                stderr,
                request.resources.maxStderrBytes,
                ExecutionEventKind.STDERR,
            )
        )
        processTask = asyncio.create_task(process.wait())
        outputLimitTask = asyncio.create_task(outputLimit.wait())
        cancellationTask = (
            asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        )
        waiters = {processTask, outputLimitTask}
        if cancellationTask is not None:
            waiters.add(cancellationTask)

        termination = ExecutionTermination.PROCESSEXIT
        state = ExecutionState.FAILED
        try:
            done, _ = await asyncio.wait(
                waiters,
                timeout=request.invocation.timeoutSeconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                termination = ExecutionTermination.TIMEOUT
                state = ExecutionState.TIMEDOUT
                await self.Terminate(process, request.resources.terminateGraceSeconds)

            elif outputLimitTask in done and outputLimit.is_set():
                termination = ExecutionTermination.OUTPUTLIMIT
                state = ExecutionState.CANCELLED
                await self.Terminate(process, request.resources.terminateGraceSeconds)

            elif (
                cancellationTask is not None
                and cancellationTask in done
                and cancellation is not None
                and cancellation.is_set()
                and not processTask.done()
            ):
                termination = ExecutionTermination.CANCELLATION
                state = ExecutionState.CANCELLED
                await self.Terminate(process, request.resources.terminateGraceSeconds)

            else:
                naturalReturnCode = await processTask
                state = (
                    ExecutionState.SUCCEEDED
                    if naturalReturnCode == 0
                    else ExecutionState.FAILED
                )

            await processTask
            await asyncio.gather(stdoutTask, stderrTask)

        except BaseException:
            await self.Terminate(process, request.resources.terminateGraceSeconds)
            raise

        finally:
            for task in (outputLimitTask, cancellationTask):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (outputLimitTask, cancellationTask) if task is not None),
                return_exceptions=True,
            )

        finalReturnCode = process.returncode
        if state in {ExecutionState.TIMEDOUT, ExecutionState.CANCELLED} and finalReturnCode == 0:
            finalReturnCode = None
        await Emit(ExecutionEventKind.COMPLETED, termination=termination)
        return LocalExecutionResult(
            execution=AdapterExecution(
                state=state,
                exitCode=finalReturnCode,
                durationSeconds=time.perf_counter() - started,
            ),
            termination=termination,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            events=tuple(events),
        )

    def ResolveWorkspace(self, relativeWorkspace: str) -> Path:
        """Разрешает рабочую область строго внутри настроенного корня."""

        candidate = self.workspaceRoot.joinpath(*relativeWorkspace.split("/"))
        try:
            resolved = candidate.resolve(strict=True)

        except OSError as error:
            raise LocalExecutionError(
                f"Execution workspace is unavailable: {relativeWorkspace}"
            ) from error
        if not resolved.is_dir():
            raise LocalExecutionError(
                f"Execution workspace is not a directory: {relativeWorkspace}"
            )
        if not resolved.is_relative_to(self.workspaceRoot):
            raise LocalExecutionError("Execution workspace escapes the configured workspace root")
        return resolved

    async def StartProcess(
        self,
        request: LocalExecutionRequest,
        workspace: Path,
        environment: dict[str, str],
    ) -> asyncio.subprocess.Process:
        """Запускает одобренный argv без оболочки в отдельной группе."""

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
        graceSeconds: float,
    ) -> None:
        """Мягко завершает принадлежащий процесс и затем убивает его."""

        if process.returncode is not None:
            return
        try:
            if os.name == "posix":
                KillProcessGroup(process.pid, signal.SIGTERM)

            else:
                process.terminate()

        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(process.wait(), timeout=graceSeconds)
            return

        except TimeoutError:
            pass

        try:
            if os.name == "posix":
                KillProcessGroup(
                    process.pid,
                    cast(int, getattr(signal, "SIGKILL")),
                )

            else:
                process.kill()

        except ProcessLookupError:
            return
        await process.wait()
