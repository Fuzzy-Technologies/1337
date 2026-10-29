# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent actual detached-process ownership checks against a closed local fixture."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import signal
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
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
    LocalExecutor,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux descendant ownership")
FIXTURE = Path(__file__).resolve().parents[1] / "contract/fixtures/owned_descendant_tree.py"
ROLES = ("root", "branch", "leaf")


def Identity(process_id: int) -> int | None:
    """Read only a recorded owned PID's kernel identity, including unreaped zombies."""

    try:
        metadata = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")

    except FileNotFoundError:
        return None

    return int(metadata.rsplit(")", 1)[1].split()[19])


def Recorded(root: Path) -> dict[int, int]:
    """Read the three explicit fixture records without enumerating host processes."""

    recorded = {}

    for role in ROLES:
        path = root / (role + ".json")

        if path.is_file():
            record = json.loads(path.read_text(encoding="utf-8"))
            assert record["role"] == role, "Fixture role identity changed"
            recorded[record["pid"]] = record["started_ticks"]

    return recorded


def AssertGone(root: Path) -> None:
    """Require all detached fixture identities to be gone before fallback teardown can run."""

    recorded = Recorded(root)
    assert len(recorded) == 3, "The actual root, detached branch and detached leaf must run"
    remaining = [pid for pid, started in recorded.items() if Identity(pid) == started]
    assert not remaining, f"Executor returned before owned descendants were reaped: {remaining}"


def ReapRecorded(root: Path) -> None:
    """Clean only recorded matching fixture identities through stable Linux PID handles."""

    (root / "release").write_text("owned teardown release", encoding="ascii")
    deadline = time.monotonic() + 2

    while True:
        remaining = Recorded(root)

        for process_id, started in remaining.items():
            try:
                descriptor = os.pidfd_open(process_id)

            except ProcessLookupError:
                continue

            try:
                if Identity(process_id) == started:
                    try:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)

                    except ProcessLookupError:
                        pass

            finally:
                os.close(descriptor)

            try:
                os.waitpid(process_id, os.WNOHANG)

            except ChildProcessError:
                pass

        if not any(Identity(pid) == started for pid, started in remaining.items()):
            return

        if time.monotonic() >= deadline:
            pytest.fail("Recorded owned fixture descendants survived bounded teardown")

        time.sleep(0.01)


@pytest.fixture
def owned_tree(tmp_path: Path) -> Iterator[Path]:
    """Reap only this case's recorded descendants if the implementation regresses."""

    own_children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")

    try:
        with own_children.open("rb"):
            pass

    except OSError:
        if os.environ.get("FUZZY1337_RUN_DESCENDANT_ACCEPTANCE") == "1":
            pytest.fail("Required actual Linux descendant ownership interface is unavailable")

        pytest.skip("Actual Linux direct-child interface is unavailable; not acceptance")

    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert library.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0, "Cannot read test subreaper"
    assert library.prctl(36, 1, 0, 0, 0) == 0, "Cannot own failed fixture descendants"

    try:
        yield tmp_path

    finally:
        try:
            ReapRecorded(tmp_path)

        finally:
            assert library.prctl(36, previous.value, 0, 0, 0) == 0, "Cannot restore test subreaper"


def Request(root: Path, mode: str, exit_code: int = 0) -> LocalExecutionRequest:
    """Bind the actual isolated fixture argv to explicit local capability and authorization."""

    invocation = AdapterInvocation(
        adapter_id="native.owned-descendant-fixture",
        request=AdapterRequest(capability="test.owned-descendants",
            target_reference="target:owned-process-fixture", impact=ImpactLevel.PASSIVE),
        argv=(sys.executable, "-I", str(FIXTURE), str(root), "--mode", mode,
              "--exit-code", str(exit_code)),
        timeout_seconds=2 if mode == "hold" else 5,
        provider_version="owned-descendant-tree.v1",
    )

    return LocalExecutionRequest(
        invocation=invocation,
        capability=CapabilityDescriptor(identifier="test.owned-descendants",
            adapter_id=invocation.adapter_id, maximum_impact=ImpactLevel.PASSIVE),
        authorization=ExecutionAuthorization(authorization_id="authorization:owned-tree",
            scope_reference="scope:owned-tree", policy_reference="policy:owned-tree",
            invocation_sha256=InvocationDigest(invocation)),
        workspace=".", resources=ExecutionResources(max_stdout_bytes=128,
            max_stderr_bytes=128),
    )


async def Ready(root: Path) -> None:
    """Wait for all three owned processes through their explicit leaf barrier."""

    deadline = time.monotonic() + 3

    while not (root / "ready").is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("Owned detached leaf never acknowledged readiness")

        await asyncio.sleep(0.01)


def test_ActualUnavailableKernelInterfaceRefusesBeforeTheClosedFixtureRuns(tmp_path):
    """An actually unsupported host cannot start the approved fixture or emit a launch event."""

    own_children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")

    try:
        with own_children.open("rb"):
            pass

    except OSError:
        pass

    else:
        pytest.skip("This negative oracle requires an actually unavailable kernel child interface")

    observed = []

    with pytest.raises(LocalExecutionError, match="Linux owned-child interface is unavailable"):
        asyncio.run(LocalExecutor(tmp_path).Execute(
            Request(tmp_path, "normal"), own_descendants=True, on_event=observed.append))

    assert Recorded(tmp_path) == {} and not (tmp_path / "ready").exists(), (
        "Unsupported kernel ownership must refuse before any approved fixture process starts"
    )
    assert observed == [], "Unsupported ownership cannot emit a started or successful event"


@pytest.mark.parametrize("exit_code", [0, 17])
def test_NaturalExitReapsDetachedBranchAndLeafBeforeReturning(owned_tree, exit_code):
    """A successful or failed root cannot leave its independently detached descendants alive."""

    result = asyncio.run(LocalExecutor(owned_tree).Execute(
        Request(owned_tree, "normal", exit_code), own_descendants=True))
    AssertGone(owned_tree)
    expected = ExecutionState.SUCCEEDED if exit_code == 0 else ExecutionState.FAILED
    assert result.execution.state is expected and result.execution.exit_code == exit_code, (
        "The original worker status must survive supervisor execution unchanged"
    )
    assert result.termination is ExecutionTermination.PROCESS_EXIT, "Natural exit reason changed"
    assert result.stdout == b"owned-root-stdout\n" and result.stderr == b"owned-root-stderr\n", (
        "The supervisor must preserve both original worker streams byte for byte"
    )
    assert result.events[0].kind is ExecutionEventKind.STARTED, "Started lifecycle event is missing"
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, "Completion event is missing"


@pytest.mark.parametrize("stop", ["cancellation", "timeout", "output"])
def test_StoppedExecutionReapsActualDetachedTreeBeforeTerminalResult(owned_tree, stop):
    """Cooperative cancellation, elapsed budget and overflow all require completed ownership."""

    async def Run():
        """Cancel only after the actual detached leaf has acknowledged readiness."""

        cancellation = asyncio.Event()
        root_output = asyncio.Event()

        def Observe(event: ExecutionEvent) -> None:
            """Acknowledge root output only after the detached leaf readiness barrier."""

            if event.kind is ExecutionEventKind.STDOUT:
                root_output.set()

        task = asyncio.create_task(LocalExecutor(owned_tree).Execute(
            Request(owned_tree, "output" if stop == "output" else "hold"),
            own_descendants=True, cancellation=cancellation, on_event=Observe))

        try:
            if stop == "cancellation":
                await Ready(owned_tree)

                await asyncio.wait_for(root_output.wait(), 3)
                cancellation.set()

            return await task

        finally:
            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

    result = asyncio.run(Run())
    AssertGone(owned_tree)
    expected = {
        "cancellation": ExecutionTermination.CANCELLATION,
        "timeout": ExecutionTermination.TIMEOUT,
        "output": ExecutionTermination.OUTPUT_LIMIT,
    }
    assert result.termination is expected[stop], "The actual stop reason must survive cleanup"
    state = ExecutionState.TIMED_OUT if stop == "timeout" else ExecutionState.CANCELLED
    assert result.execution.state is state, "Stopped execution cannot become successful"
    assert result.execution.exit_code == -signal.SIGKILL, "Return the worker's signed signal status"
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, "Verified stop event is missing"
    assert result.stdout.startswith(b"owned-root-stdout\n"), "Actual partial stdout was lost"

    if stop == "output":
        assert len(result.stdout) == 128, "Overflow must preserve exactly its declared byte budget"


@pytest.mark.parametrize("abort", ["observer", "caller"])
def test_ObserverAndCallerAbortPropagateOnlyAfterDetachedTreeCleanup(owned_tree, abort):
    """Failure propagation cannot bypass owned cleanup or emit a false completed event."""

    async def Run():
        """Abort at an actual root output event, after the fixture's complete readiness barrier."""

        observed = []
        root_output = asyncio.Event()

        async def Observe(event: ExecutionEvent) -> None:
            """Refuse the observer or suspend until the caller cancels this exact invocation."""

            observed.append(event)

            if event.kind is ExecutionEventKind.STDOUT:
                root_output.set()

                if abort == "observer":
                    raise RuntimeError("owned observer failure")

                await asyncio.Event().wait()

        task = asyncio.create_task(LocalExecutor(owned_tree).Execute(
            Request(owned_tree, "hold"), own_descendants=True, on_event=Observe))

        try:
            if abort == "caller":
                await asyncio.wait_for(root_output.wait(), 3)
                task.cancel()

            error_type = RuntimeError if abort == "observer" else asyncio.CancelledError
            message = "^owned observer failure$" if abort == "observer" else None

            with pytest.raises(error_type, match=message):
                await task

            assert not any(event.kind is ExecutionEventKind.COMPLETED for event in observed), (
                "An observer or caller abort cannot emit a false completed lifecycle event"
            )

        finally:
            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(Run())
    AssertGone(owned_tree)
