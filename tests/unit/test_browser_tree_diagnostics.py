# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic browser failure-custody tests without processes, Playwright or Chromium."""

from __future__ import annotations

import asyncio
import json

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionError,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from tests.contract.browser_tree_diagnostics import (
    AwaitBrowserReadiness,
    FixtureFiles,
    WriteBrowserTreeDiagnostics,
)
from tests.integration import test_browser_page_execution as browser_acceptance


@pytest.fixture(scope="module")
def diagnostic_runner():
    """Create portable loop resources before unit network guards, without any provider launch."""

    with asyncio.Runner() as runner:
        runner.get_loop()

        yield runner


@pytest.fixture
def diagnostic_request():
    """Construct inert unit metadata; this argv is never passed to an executor."""

    invocation = AdapterInvocation("test.browser", AdapterRequest("test.browser",
        "target:unit-browser", ImpactLevel.PASSIVE), ("unit-never-executed",), 8)

    return LocalExecutionRequest(invocation,
        CapabilityDescriptor("test.browser", "test.browser", ImpactLevel.PASSIVE),
        ExecutionAuthorization("authorization:unit", "scope:unit", "policy:unit",
            InvocationDigest(invocation)), resources=ExecutionResources(4096, 4096))


@pytest.mark.parametrize("raises", [False, True])
def test_ReadinessWaitReturnsOriginalEarlyCompletionWithoutCancellingIt(diagnostic_runner, raises):
    """An early result or exception must win over the unraised readiness signal immediately."""

    async def Check():
        """Use only scheduled deterministic task completion, without a real-time provider."""

        original = LocalExecutionError("owned worker failed before readiness") if (
            raises) else object()

        async def Complete():
            """Deliver the exact known unit outcome."""

            if raises:
                raise original

            return original

        task = asyncio.create_task(Complete())
        outcome = await AwaitBrowserReadiness(task, asyncio.Event(), timeout_seconds=7)
        assert outcome == "execution-complete" and task.done() and not task.cancelled(), (
            "Early execution must end readiness waiting without cancelling original custody"
        )

        if raises:
            with pytest.raises(LocalExecutionError) as caught:
                await task

            assert caught.value is original, "The readiness race must retain the original exception"

        else:
            assert await task is original, "Readiness must retain the original result object"

    diagnostic_runner.run(Check())


@pytest.mark.parametrize("ready", [False, True])
def test_ReadinessRaceLeavesPendingExecutionOwnedAtReadyOrDeadline(diagnostic_runner, ready):
    """Never cancel a still-owned task at readiness or the exact zero-time boundary."""

    async def Check():
        """Keep an inert task behind an explicit finite owner release event."""

        release = asyncio.Event()
        readiness = asyncio.Event()

        if ready:
            readiness.set()

        task = asyncio.create_task(release.wait())

        try:
            outcome = await AwaitBrowserReadiness(task, readiness, timeout_seconds=0)
            assert outcome == ("ready" if ready else "readiness-deadline") and not task.done(), (
                "Readiness/deadline observation must leave execution for its owner to settle"
            )

        finally:
            release.set()

            await task

    diagnostic_runner.run(Check())


def test_TerminalFailureCustodyRetainsExactBinaryStreamsEventsAndFixtureFiles(
    tmp_path, diagnostic_request,
):
    """Persist complete original failure facts before acceptance assertions can hide them."""

    stdout = b"partial-ready\xff"
    stderr = b"actual launch error\x00\xfe\n"
    events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
        ExecutionEvent(1, ExecutionEventKind.STDOUT, stdout),
        ExecutionEvent(2, ExecutionEventKind.STDERR, stderr),
        ExecutionEvent(3, ExecutionEventKind.COMPLETED,
            termination=ExecutionTermination.PROCESS_EXIT))
    result = LocalExecutionResult(AdapterExecution(ExecutionState.FAILED, 1, 0.25),
        ExecutionTermination.PROCESS_EXIT, stdout, stderr, events)
    identities = b'[{"pid":123,"started_ticks":456}]'
    (tmp_path / "identities.pending").write_bytes(identities)
    destination = tmp_path / "evidence" / "browser-owner-unit.json"
    summary = WriteBrowserTreeDiagnostics(destination, tmp_path, diagnostic_request, result=result,
        error=None, observed_events=events, ready_bytes=stdout, wait_outcome="execution-complete")
    payload = json.loads(destination.read_bytes())
    expected_events = [{"sequence": 0, "kind": "started", "data_hex": "", "termination": None},
        {"sequence": 1, "kind": "stdout", "data_hex": stdout.hex(), "termination": None},
        {"sequence": 2, "kind": "stderr", "data_hex": stderr.hex(), "termination": None},
        {"sequence": 3, "kind": "completed", "data_hex": "", "termination": "process_exit"}]
    assert payload["terminal_result"] == {"execution": {"state": "failed", "exit_code": 1,
        "duration_seconds": 0.25}, "termination": "process_exit", "stdout_hex": stdout.hex(),
        "stderr_hex": stderr.hex(), "events": expected_events}, (
        "Diagnostic custody must preserve every original terminal, byte and event field exactly"
    )
    assert payload["observed_events"] == expected_events and (
        payload["ready_bytes_hex"] == stdout.hex() and payload["execution_exception"] is None
    ), "Observed events must retain their own custody and agree with the original terminal result"
    assert payload["fixture_files"]["ready.json"] == {"state": "absent"} and (
        payload["fixture_files"]["identities.pending"] == {"state": "present",
            "size_bytes": len(identities), "data_hex": identities.hex(), "truncated": False}
    ), "Pre-readiness absence and partial identity publication must remain explicit original facts"
    assert repr(stderr) in summary and "'exit_code': 1" in summary, (
        "Pytest/JUnit must expose original stderr and terminal status without another fetch"
    )


def test_RaisedFailureRetainsObservedStderrWithoutInventingATerminalResult(
    tmp_path, diagnostic_request,
):
    """Retain actual delivered bytes and the original raised execution failure classification."""

    error = LocalExecutionError("owned cleanup refused")
    events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
        ExecutionEvent(1, ExecutionEventKind.STDERR, b"original worker traceback\n"))
    destination = tmp_path / "browser-owner-unit.json"
    summary = WriteBrowserTreeDiagnostics(destination, tmp_path, diagnostic_request, result=None,
        error=error, observed_events=events, ready_bytes=b"", wait_outcome="execution-complete")
    payload = json.loads(destination.read_bytes())
    assert payload["terminal_result"] is None and payload["execution_exception"] == {
        "type": "LocalExecutionError", "module": "fuzzy1337.executors.local",
        "message": "owned cleanup refused"}, (
        "Unknown terminal custody must retain the raised exception and invent no completed result"
    )
    assert payload["observed_events"][1]["data_hex"] == b"original worker traceback\n".hex() and (
        "original worker traceback" in summary
    ), "Raised failures must retain exact delivered stderr in evidence and the failure text"


def test_FixtureDiagnosticsReadOnlyFixedNamesAndMarkFiniteTruncation(tmp_path):
    """Bound readiness-file custody while leaving unrelated owned files unread."""

    (tmp_path / "ready.pending").write_bytes(b"x" * 16385)
    (tmp_path / "unrelated").write_bytes(b"must remain unrelated")
    files = FixtureFiles(tmp_path)
    assert set(files) == {"ready.json", "ready.pending", "identities.json", "identities.pending"}, (
        "Diagnostics must inspect only this fixture's four exact output names"
    )
    assert files["ready.pending"] == {"state": "present", "size_bytes": 16385,
        "data_hex": (b"x" * 16384).hex(), "truncated": True}, (
        "Oversized diagnostic files must retain the explicit bounded prefix and truncation fact"
    )


def test_TimeoutAcceptanceWaitsForOriginalExecutionWithoutAReadinessCancel(
    tmp_path, monkeypatch, diagnostic_runner,
):
    """Exercise a simulated early failure, never a successful or genuine browser acceptance."""

    observed = []

    async def ForbiddenReadiness(*_args, **_kwargs):
        """Reject scheduling any seven-second readiness barrier for the timeout case."""

        raise AssertionError("Timeout acceptance must await only its original execution deadline")

    async def EarlyFailure(executor, request, **options):
        """Return an explicitly simulated failed worker, with no process or browser identities."""

        del executor
        assert request.invocation.timeout_seconds == 8, (
            "Original worker timeout must stay eight seconds"
        )
        assert not options["cancellation"].is_set(), "Timeout waiting must not request cancellation"
        observed.append(options["cancellation"])
        stderr = b"simulated early launch failure\n"
        events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDERR, stderr),
            ExecutionEvent(2, ExecutionEventKind.COMPLETED,
                termination=ExecutionTermination.PROCESS_EXIT))

        for event in events:
            options["on_event"](event)

        return LocalExecutionResult(AdapterExecution(ExecutionState.FAILED, 1, 0.25),
            ExecutionTermination.PROCESS_EXIT, b"", stderr, events)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(browser_acceptance, "AwaitBrowserReadiness", ForbiddenReadiness)
    monkeypatch.setattr(browser_acceptance.LocalExecutor, "Execute", EarlyFailure)
    monkeypatch.setattr(browser_acceptance.asyncio, "run", diagnostic_runner.run)

    with pytest.raises(AssertionError, match="Actual browser readiness was not established"):
        browser_acceptance.test_ActualNodeAndChromiumAreReapedBeforeStoppedExecutionReturns(
            tmp_path, "timeout")

    payload = json.loads((tmp_path / "functional-evidence/browser-owner-timeout.json").read_bytes())
    assert len(observed) == 1 and not observed[0].is_set(), (
        "The timeout branch must settle its original result without a new readiness cancellation"
    )
    assert payload["wait_outcome"] == "execution-complete" and (
        payload["terminal_result"]["stderr_hex"] == b"simulated early launch failure\n".hex()
        and payload["terminal_result"]["execution"]["exit_code"] == 1
    ), "Early timeout-case failures must retain original custody before acceptance refusal"
