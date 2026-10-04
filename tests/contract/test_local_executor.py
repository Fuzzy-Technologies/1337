# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local executor process-lifecycle tests using only owned child processes."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from unittest.mock import Mock

import pytest

from fuzzy1337.adapters import (
    AdapterInvocation,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionError,
    LocalExecutionRequest,
    LocalExecutor,
)


def Request(
    tmp_path,
    script: str,
    *,
    timeout_seconds: int = 5,
    workspace: str = ".",
    environment: dict[str, str] | None = None,
    resources: ExecutionResources | None = None,
) -> LocalExecutionRequest:
    """Provide deterministic test support for request."""

    invocation = AdapterInvocation(
        adapter_id="native.python-fixture",
        request=AdapterRequest(
            capability="test.local-process",
            target_reference="target:localhost-fixture",
            impact=ImpactLevel.PASSIVE,
        ),
        argv=(sys.executable, "-c", script),
        timeout_seconds=timeout_seconds,
        provider_version=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    capability = CapabilityDescriptor(
        identifier="test.local-process",
        adapter_id="native.python-fixture",
        maximum_impact=ImpactLevel.PASSIVE,
    )
    authorization = ExecutionAuthorization(
        authorization_id="authorization:local-test",
        scope_reference="scope:localhost-fixture",
        policy_reference="policy:test-only",
        invocation_sha256=InvocationDigest(invocation),
    )

    return LocalExecutionRequest(
        invocation=invocation,
        capability=capability,
        authorization=authorization,
        workspace=workspace,
        environment=environment or {},
        resources=resources or ExecutionResources(),
    )


def test_LocalExecutorStreamsAndPreservesCompleteProcessOutput(tmp_path):
    """Verify local executor streams and preserves complete process output."""

    workspace = tmp_path / "runs" / "job-1"
    workspace.mkdir(parents=True)
    script = (
        "import json,os,pathlib,sys; "
        "print(json.dumps({'cwd': pathlib.Path.cwd().name, 'mode': os.environ['EXECUTOR_MODE']})); "
        "print('warning', file=sys.stderr)"
    )
    request = Request(
        tmp_path,
        script,
        workspace="runs/job-1",
        environment={"EXECUTOR_MODE": "fixture"},
    )
    observed = []

    result = asyncio.run(LocalExecutor(tmp_path).Execute(request, on_event=observed.append))

    assert result.execution.state is ExecutionState.SUCCEEDED, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.execution.exit_code == 0, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert json.loads(result.stdout) == {"cwd": "job-1", "mode": "fixture"}, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.stderr == f"warning{os.linesep}".encode(), (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.termination is ExecutionTermination.PROCESS_EXIT, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert observed == list(result.events), (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert tuple(event.sequence for event in result.events) == tuple(range(len(result.events))), (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.events[0].kind is ExecutionEventKind.STARTED, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert {event.kind for event in result.events[1:-1]} == {
        ExecutionEventKind.STDOUT,
        ExecutionEventKind.STDERR,
    }, "local executor streams and preserves complete process output invariant failed."


def test_NonzeroExitIsNeverReportedAsSuccess(tmp_path):
    """Verify nonzero exit is never reported as success."""

    result = asyncio.run(LocalExecutor(tmp_path).Execute(Request(tmp_path, "raise SystemExit(7)")))

    assert result.execution.state is ExecutionState.FAILED, (
        "nonzero exit is never reported as success invariant failed."
    )
    assert result.execution.exit_code == 7, (
        "nonzero exit is never reported as success invariant failed."
    )
    assert result.termination is ExecutionTermination.PROCESS_EXIT, (
        "nonzero exit is never reported as success invariant failed."
    )


def test_TimeoutTerminatesTheOwnedProcess(tmp_path):
    """Verify timeout terminates the owned process."""

    result = asyncio.run(
        LocalExecutor(tmp_path).Execute(
            Request(tmp_path, "import time; time.sleep(30)", timeout_seconds=1)
        )
    )

    assert result.execution.state is ExecutionState.TIMED_OUT, (
        "timeout terminates the owned process invariant failed."
    )
    assert result.execution.exit_code != 0, "timeout terminates the owned process invariant failed."
    assert result.termination is ExecutionTermination.TIMEOUT, (
        "timeout terminates the owned process invariant failed."
    )


def test_CancellationTerminatesTheOwnedProcess(tmp_path):
    """Verify cancellation terminates the owned process."""

    async def Run():
        """Provide deterministic test support for run."""

        cancellation = asyncio.Event()
        task = asyncio.create_task(
            LocalExecutor(tmp_path).Execute(
                Request(tmp_path, "import time; time.sleep(30)"),
                cancellation=cancellation,
            )
        )

        await asyncio.sleep(0.05)

        cancellation.set()

        return await task

    result = asyncio.run(Run())

    assert result.execution.state is ExecutionState.CANCELLED, (
        "cancellation terminates the owned process invariant failed."
    )
    assert result.execution.exit_code != 0, (
        "cancellation terminates the owned process invariant failed."
    )
    assert result.termination is ExecutionTermination.CANCELLATION, (
        "cancellation terminates the owned process invariant failed."
    )


def test_PreCancelledRequestNeverLaunchesAProcess(tmp_path, monkeypatch):
    """Verify pre cancelled request never launches a process."""

    async def Run():
        """Provide deterministic test support for run."""

        cancellation = asyncio.Event()
        cancellation.set()

        return await LocalExecutor(tmp_path).Execute(
            Request(tmp_path, "raise AssertionError('must not start')"),
            cancellation=cancellation,
        )

    process = Mock(side_effect=AssertionError("process must not start"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", process)
    result = asyncio.run(Run())

    assert result.execution.state is ExecutionState.CANCELLED, (
        "pre cancelled request never launches a process invariant failed."
    )
    assert result.execution.exit_code is None, (
        "pre cancelled request never launches a process invariant failed."
    )
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, (
        "pre cancelled request never launches a process invariant failed."
    )
    process.assert_not_called()


def test_OutputLimitCancelsProcessWithoutHidingPartialEvidence(tmp_path):
    """Verify output limit cancels process without hiding partial evidence."""

    resources = ExecutionResources(max_stdout_bytes=32, max_stderr_bytes=32)
    result = asyncio.run(
        LocalExecutor(tmp_path).Execute(
            Request(
                tmp_path,
                "import sys,time; print('x' * 10000); sys.stdout.flush(); time.sleep(30)",
                resources=resources,
            )
        )
    )

    assert result.execution.state is ExecutionState.CANCELLED, (
        "output limit cancels process without hiding partial evidence invariant failed."
    )
    assert result.termination is ExecutionTermination.OUTPUT_LIMIT, (
        "output limit cancels process without hiding partial evidence invariant failed."
    )
    assert len(result.stdout) == 32, (
        "output limit cancels process without hiding partial evidence invariant failed."
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation is not portable on Windows")
def test_WorkspaceSymlinkEscapeFailsClosed(tmp_path):
    """Verify workspace symlink escape fails closed."""

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    escaping = Request(tmp_path, "print('unsafe')", workspace="escape")

    with pytest.raises(LocalExecutionError, match="workspace root"):
        asyncio.run(LocalExecutor(tmp_path).Execute(escaping))


def test_MissingWorkspaceAndLaunchFailureFailClosed(tmp_path):
    """Verify missing workspace and launch failure fail closed."""

    missing = Request(tmp_path, "print('missing')", workspace="missing")

    with pytest.raises(LocalExecutionError, match="workspace"):
        asyncio.run(LocalExecutor(tmp_path).Execute(missing))

    invocation = missing.invocation
    unavailable_invocation = AdapterInvocation(
        adapter_id=invocation.adapter_id,
        request=invocation.request,
        argv=(str(tmp_path / "not-an-executable"),),
        timeout_seconds=invocation.timeout_seconds,
    )
    unavailable = LocalExecutionRequest(
        invocation=unavailable_invocation,
        capability=missing.capability,
        authorization=ExecutionAuthorization(
            authorization_id="authorization:missing-tool",
            scope_reference="scope:localhost-fixture",
            policy_reference="policy:test-only",
            invocation_sha256=InvocationDigest(unavailable_invocation),
        ),
    )

    with pytest.raises(LocalExecutionError, match="Could not start"):
        asyncio.run(LocalExecutor(tmp_path).Execute(unavailable))


def CaptureExecutor(tmp_path, monkeypatch):
    """Capture only test-owned child handles for leak assertions and fallback cleanup."""

    executor = LocalExecutor(tmp_path)
    processes = []
    start_process = executor.StartProcess

    async def Start(request, workspace, environment):
        """Record the owned child without changing real process creation."""

        process = await start_process(request, workspace, environment)
        processes.append(process)

        return process

    monkeypatch.setattr(executor, "StartProcess", Start)

    return executor, processes


async def CleanupFixture(executor, processes):
    """Reap fixture children even when the implementation under test leaks ownership."""

    for process in processes:
        drains = [
            asyncio.create_task(reader.read())
            for reader in (process.stdout, process.stderr) if reader is not None
        ]

        await executor.Terminate(process, 0.1)

        await asyncio.gather(*drains)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_StartedObserverFailureReapsOwnedProcess(tmp_path, monkeypatch, asynchronous):
    """Propagate either observer form only after the launched child is reaped."""

    async def Run():
        """Exercise a real owned child and clean it even on a failing regression."""

        executor, processes = CaptureExecutor(tmp_path, monkeypatch)
        failure = RuntimeError("started observer failed")

        def Observe(event):
            """Fail synchronously at the first lifecycle handoff."""

            assert event.kind is ExecutionEventKind.STARTED, "Expected the initial handoff."

            raise failure

        async def ObserveAsync(event):
            """Fail after an actual asynchronous observer suspension."""

            await asyncio.sleep(0)

            Observe(event)

        try:
            with pytest.raises(RuntimeError) as raised:
                await executor.Execute(
                    Request(tmp_path, "import time; time.sleep(30)"),
                    on_event=ObserveAsync if asynchronous else Observe,
                )

            assert raised.value is failure, "Cleanup must preserve the original observer error."
            assert processes[0].returncode is not None, "STARTED failure leaked a live child."
            assert asyncio.all_tasks() == {asyncio.current_task()}, (
                "Observer failure left executor-owned background tasks pending."
            )

        finally:
            await CleanupFixture(executor, processes)

    asyncio.run(Run())


@pytest.mark.parametrize("kind", [ExecutionEventKind.STARTED, ExecutionEventKind.STDOUT])
def test_CancellationDuringObserverReapsProcessAndTasks(tmp_path, monkeypatch, kind):
    """Cancel an awaitable observer and prove complete child/task ownership cleanup."""

    async def Run():
        """Cancel only after the selected observer enters its suspension point."""

        executor, processes = CaptureExecutor(tmp_path, monkeypatch)
        entered = asyncio.Event()
        baseline = asyncio.all_tasks()

        async def Observe(event):
            """Signal the deterministic cancellation handoff and then remain suspended."""

            if event.kind is kind:
                entered.set()

                await asyncio.Event().wait()

        task = asyncio.create_task(executor.Execute(
            Request(tmp_path, "import sys,time; print('ready', flush=True); time.sleep(30)"),
            on_event=Observe,
        ))

        try:
            await asyncio.wait_for(entered.wait(), 3)

            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)

            assert processes[0].returncode is not None, "Observer cancellation leaked a live child."
            assert asyncio.all_tasks() == baseline, "Cancellation left executor tasks pending."

        finally:
            if not task.done():
                task.cancel()

                await asyncio.gather(task, return_exceptions=True)

            await CleanupFixture(executor, processes)

    asyncio.run(Run())


@pytest.mark.parametrize("kind,descriptor", [
    (ExecutionEventKind.STDOUT, 1), (ExecutionEventKind.STDERR, 2),
])
def test_OutputObserverFailureReapsProcessWithoutWaitingForTimeout(
    tmp_path, monkeypatch, kind, descriptor,
):
    """Fail a pipe-filling producer promptly without leaking its sibling reader."""

    async def Run():
        """Use a live owned producer and preserve the exact observer exception."""

        executor, processes = CaptureExecutor(tmp_path, monkeypatch)
        failure = RuntimeError("output observer failed")
        baseline = asyncio.all_tasks()

        def Observe(event):
            """Reject the first retained output chunk."""

            if event.kind is kind:
                raise failure

        try:
            with pytest.raises(RuntimeError) as raised:
                await asyncio.wait_for(executor.Execute(
                    Request(tmp_path, (
                        f"import os,time; os.write({descriptor}, b'x'*1048576); time.sleep(30)"
                    )),
                    on_event=Observe,
                ), 3)

            assert raised.value is failure, "The output observer failure was replaced or hidden."
            assert processes[0].returncode is not None, "Output failure leaked a live child."
            assert asyncio.all_tasks() == baseline, "Output failure left executor tasks pending."

        finally:
            await CleanupFixture(executor, processes)

    asyncio.run(Run())


def test_RepeatedCancellationCannotInterruptOwnedCleanup(tmp_path, monkeypatch):
    """Keep reaping ownership when cancellation is requested again during cleanup."""

    async def Run():
        """Hold the cleanup boundary open to make the second cancellation deterministic."""

        executor, processes = CaptureExecutor(tmp_path, monkeypatch)
        observed = asyncio.Event()
        cleanup_entered = asyncio.Event()
        finish_cleanup = asyncio.Event()
        baseline = asyncio.all_tasks()
        terminate = executor.Terminate

        async def Observe(event):
            """Remain suspended in the initial lifecycle handoff."""

            observed.set()

            await asyncio.Event().wait()

        async def Terminate(process, grace_seconds):
            """Pause test-owned reaping until the second cancellation is delivered."""

            cleanup_entered.set()

            await finish_cleanup.wait()

            await terminate(process, grace_seconds)

        monkeypatch.setattr(executor, "Terminate", Terminate)
        task = asyncio.create_task(executor.Execute(
            Request(tmp_path, "import time; time.sleep(30)"), on_event=Observe,
        ))

        try:
            await asyncio.wait_for(observed.wait(), 3)

            task.cancel()

            await asyncio.wait_for(cleanup_entered.wait(), 3)

            task.cancel()

            await asyncio.sleep(0)

            assert not task.done(), "Repeated cancellation abandoned in-progress reaping."
            finish_cleanup.set()

            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)

            assert processes[0].returncode is not None, "Repeated cancellation leaked a live child."
            assert asyncio.all_tasks() == baseline, "Repeated cancellation left background tasks."

        finally:
            finish_cleanup.set()

            if not task.done():
                task.cancel()

                await asyncio.gather(task, return_exceptions=True)

            await CleanupFixture(executor, processes)

    asyncio.run(Run())


def test_AsyncObserverCallbacksRemainOrderedAndNonOverlapping(tmp_path):
    """Serialize awaitable lifecycle/output callbacks while preserving complete output."""

    async def Run():
        """Observe both streams with an explicit scheduler suspension per callback."""

        active = False
        observed = []

        async def Observe(event):
            """Reject overlapping callback execution and retain the delivered order."""

            nonlocal active
            assert not active, "Awaitable lifecycle and stream observers must not overlap."
            active = True

            await asyncio.sleep(0)

            observed.append(event)
            active = False

        result = await LocalExecutor(tmp_path).Execute(Request(
            tmp_path, "import sys; print('out'); print('err', file=sys.stderr)",
        ), on_event=Observe)

        assert result.execution.state is ExecutionState.SUCCEEDED, "Ordinary execution regressed."
        assert observed == list(result.events), "Awaitable callbacks changed lifecycle ordering."
        assert result.stdout == f"out{os.linesep}".encode(), "stdout evidence was lost."
        assert result.stderr == f"err{os.linesep}".encode(), "stderr evidence was lost."

    asyncio.run(Run())
