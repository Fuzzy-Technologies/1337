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
