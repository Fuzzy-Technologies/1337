"""Local executor process-lifecycle tests using only owned child processes."""

from __future__ import annotations

import asyncio
import json
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
    LocalExecutionError,
    LocalExecutionRequest,
    LocalExecutor,
    invocation_digest,
)


def _request(
    tmp_path,
    script: str,
    *,
    timeout_seconds: int = 5,
    workspace: str = ".",
    environment: dict[str, str] | None = None,
    resources: ExecutionResources | None = None,
) -> LocalExecutionRequest:
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
        invocation_sha256=invocation_digest(invocation),
    )
    return LocalExecutionRequest(
        invocation=invocation,
        capability=capability,
        authorization=authorization,
        workspace=workspace,
        environment=environment or {},
        resources=resources or ExecutionResources(),
    )


def test_local_executor_streams_and_preserves_complete_process_output(tmp_path):
    workspace = tmp_path / "runs" / "job-1"
    workspace.mkdir(parents=True)
    script = (
        "import json,os,pathlib,sys; "
        "print(json.dumps({'cwd': pathlib.Path.cwd().name, 'mode': os.environ['EXECUTOR_MODE']})); "
        "print('warning', file=sys.stderr)"
    )
    request = _request(
        tmp_path,
        script,
        workspace="runs/job-1",
        environment={"EXECUTOR_MODE": "fixture"},
    )
    observed = []

    result = asyncio.run(
        LocalExecutor(tmp_path).execute(request, on_event=observed.append)
    )

    assert result.execution.state is ExecutionState.SUCCEEDED
    assert result.execution.exit_code == 0
    assert json.loads(result.stdout) == {"cwd": "job-1", "mode": "fixture"}
    assert result.stderr == b"warning\n"
    assert result.termination is ExecutionTermination.PROCESS_EXIT
    assert observed == list(result.events)
    assert tuple(event.sequence for event in result.events) == tuple(range(len(result.events)))
    assert result.events[0].kind is ExecutionEventKind.STARTED
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED
    assert {event.kind for event in result.events[1:-1]} == {
        ExecutionEventKind.STDOUT,
        ExecutionEventKind.STDERR,
    }


def test_nonzero_exit_is_never_reported_as_success(tmp_path):
    result = asyncio.run(
        LocalExecutor(tmp_path).execute(_request(tmp_path, "raise SystemExit(7)"))
    )

    assert result.execution.state is ExecutionState.FAILED
    assert result.execution.exit_code == 7
    assert result.termination is ExecutionTermination.PROCESS_EXIT


def test_timeout_terminates_the_owned_process(tmp_path):
    result = asyncio.run(
        LocalExecutor(tmp_path).execute(
            _request(tmp_path, "import time; time.sleep(30)", timeout_seconds=1)
        )
    )

    assert result.execution.state is ExecutionState.TIMED_OUT
    assert result.execution.exit_code != 0
    assert result.termination is ExecutionTermination.TIMEOUT


def test_cancellation_terminates_the_owned_process(tmp_path):
    async def run():
        cancellation = asyncio.Event()
        task = asyncio.create_task(
            LocalExecutor(tmp_path).execute(
                _request(tmp_path, "import time; time.sleep(30)"),
                cancellation=cancellation,
            )
        )
        await asyncio.sleep(0.05)
        cancellation.set()
        return await task

    result = asyncio.run(run())

    assert result.execution.state is ExecutionState.CANCELLED
    assert result.execution.exit_code != 0
    assert result.termination is ExecutionTermination.CANCELLATION


def test_pre_cancelled_request_never_launches_a_process(tmp_path, monkeypatch):
    async def run():
        cancellation = asyncio.Event()
        cancellation.set()
        return await LocalExecutor(tmp_path).execute(
            _request(tmp_path, "raise AssertionError('must not start')"),
            cancellation=cancellation,
        )

    process = Mock(side_effect=AssertionError("process must not start"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", process)
    result = asyncio.run(run())

    assert result.execution.state is ExecutionState.CANCELLED
    assert result.execution.exit_code is None
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED
    process.assert_not_called()


def test_output_limit_cancels_process_without_hiding_partial_evidence(tmp_path):
    resources = ExecutionResources(max_stdout_bytes=32, max_stderr_bytes=32)
    result = asyncio.run(
        LocalExecutor(tmp_path).execute(
            _request(
                tmp_path,
                "import sys,time; print('x' * 10000); sys.stdout.flush(); time.sleep(30)",
                resources=resources,
            )
        )
    )

    assert result.execution.state is ExecutionState.CANCELLED
    assert result.termination is ExecutionTermination.OUTPUT_LIMIT
    assert len(result.stdout) == 32


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation is not portable on Windows")
def test_workspace_symlink_escape_fails_closed(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    escaping = _request(tmp_path, "print('unsafe')", workspace="escape")

    with pytest.raises(LocalExecutionError, match="workspace root"):
        asyncio.run(LocalExecutor(tmp_path).execute(escaping))


def test_missing_workspace_and_launch_failure_fail_closed(tmp_path):
    missing = _request(tmp_path, "print('missing')", workspace="missing")
    with pytest.raises(LocalExecutionError, match="workspace"):
        asyncio.run(LocalExecutor(tmp_path).execute(missing))

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
            invocation_sha256=invocation_digest(unavailable_invocation),
        ),
    )
    with pytest.raises(LocalExecutionError, match="Could not start"):
        asyncio.run(LocalExecutor(tmp_path).execute(unavailable))
