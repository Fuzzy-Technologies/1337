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
    timeoutSeconds: int = 5,
    workspace: str = ".",
    environment: dict[str, str] | None = None,
    resources: ExecutionResources | None = None,
) -> LocalExecutionRequest:
    """Build an authorized local execution request for one Python script."""

    invocation = AdapterInvocation(
        adapterId="native.python-fixture",
        request=AdapterRequest(
            capability="test.local-process",
            targetReference="target:localhost-fixture",
            impact=ImpactLevel.PASSIVE,
        ),
        argv=(sys.executable, "-c", script),
        timeoutSeconds=timeoutSeconds,
        providerVersion=f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    capability = CapabilityDescriptor(
        identifier="test.local-process",
        adapterId="native.python-fixture",
        maximumImpact=ImpactLevel.PASSIVE,
    )
    authorization = ExecutionAuthorization(
        authorizationId="authorization:local-test",
        scopeReference="scope:localhost-fixture",
        policyReference="policy:test-only",
        invocationSha256=InvocationDigest(invocation),
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
    """Stream events while preserving complete bounded process output."""

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

    result = asyncio.run(
        LocalExecutor(tmp_path).Execute(request, onEvent=observed.append)
    )

    assert result.execution.state is ExecutionState.SUCCEEDED, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.execution.exitCode == 0, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert json.loads(result.stdout) == {"cwd": "job-1", "mode": "fixture"}, (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.stderr == f"warning{os.linesep}".encode(), (
        "local executor streams and preserves complete process output invariant failed."
    )
    assert result.termination is ExecutionTermination.PROCESSEXIT, (
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
    """Never report a nonzero child exit as successful execution."""

    result = asyncio.run(
        LocalExecutor(tmp_path).Execute(Request(tmp_path, "raise SystemExit(7)"))
    )

    assert result.execution.state is ExecutionState.FAILED, (
        "nonzero exit is never reported as success invariant failed."
    )
    assert result.execution.exitCode == 7, (
        "nonzero exit is never reported as success invariant failed."
    )
    assert result.termination is ExecutionTermination.PROCESSEXIT, (
        "nonzero exit is never reported as success invariant failed."
    )


def test_TimeoutTerminatesTheOwnedProcess(tmp_path):
    """Terminate an owned child when its request timeout expires."""

    result = asyncio.run(
        LocalExecutor(tmp_path).Execute(
            Request(tmp_path, "import time; time.sleep(30)", timeoutSeconds=1)
        )
    )

    assert result.execution.state is ExecutionState.TIMEDOUT, (
        "timeout terminates the owned process invariant failed."
    )
    assert result.execution.exitCode != 0, "timeout terminates the owned process invariant failed."
    assert result.termination is ExecutionTermination.TIMEOUT, (
        "timeout terminates the owned process invariant failed."
    )


def test_CancellationTerminatesTheOwnedProcess(tmp_path):
    """Terminate an owned child after explicit cancellation."""

    async def Run():
        """Execute and cancel one owned child process."""

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
    assert result.execution.exitCode != 0, (
        "cancellation terminates the owned process invariant failed."
    )
    assert result.termination is ExecutionTermination.CANCELLATION, (
        "cancellation terminates the owned process invariant failed."
    )


def test_PreCancelledRequestNeverLaunchesAProcess(tmp_path, monkeypatch):
    """Return cancellation without launching a pre-cancelled request."""

    async def Run():
        """Execute a request whose cancellation is already set."""

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
    assert result.execution.exitCode is None, (
        "pre cancelled request never launches a process invariant failed."
    )
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, (
        "pre cancelled request never launches a process invariant failed."
    )
    process.assert_not_called()


def test_OutputLimitCancelsProcessWithoutHidingPartialEvidence(tmp_path):
    """Cancel excessive output while retaining its bounded prefix."""

    resources = ExecutionResources(maxStdoutBytes=32, maxStderrBytes=32)
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
    assert result.termination is ExecutionTermination.OUTPUTLIMIT, (
        "output limit cancels process without hiding partial evidence invariant failed."
    )
    assert len(result.stdout) == 32, (
        "output limit cancels process without hiding partial evidence invariant failed."
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation is not portable on Windows")
def test_WorkspaceSymlinkEscapeFailsClosed(tmp_path):
    """Reject a workspace symlink that escapes the configured root."""

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    escaping = Request(tmp_path, "print('unsafe')", workspace="escape")

    with pytest.raises(LocalExecutionError, match="workspace root"):
        asyncio.run(LocalExecutor(tmp_path).Execute(escaping))


def test_MissingWorkspaceAndLaunchFailureFailClosed(tmp_path):
    """Fail closed for missing workspaces and unavailable executables."""

    missing = Request(tmp_path, "print('missing')", workspace="missing")
    with pytest.raises(LocalExecutionError, match="workspace"):
        asyncio.run(LocalExecutor(tmp_path).Execute(missing))

    invocation = missing.invocation
    unavailableInvocation = AdapterInvocation(
        adapterId=invocation.adapterId,
        request=invocation.request,
        argv=(str(tmp_path / "not-an-executable"),),
        timeoutSeconds=invocation.timeoutSeconds,
    )
    unavailable = LocalExecutionRequest(
        invocation=unavailableInvocation,
        capability=missing.capability,
        authorization=ExecutionAuthorization(
            authorizationId="authorization:missing-tool",
            scopeReference="scope:localhost-fixture",
            policyReference="policy:test-only",
            invocationSha256=InvocationDigest(unavailableInvocation),
        ),
    )
    with pytest.raises(LocalExecutionError, match="Could not start"):
        asyncio.run(LocalExecutor(tmp_path).Execute(unavailable))
