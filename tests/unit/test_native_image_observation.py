# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed observer-unit protocol simulations, never genuine helper or engine acceptance."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_image_observation as observation
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.native_image_material_worker import (
    CanonicalControl,
    ObserveControl,
    ParseControl,
    ReadControl,
    SelectionFromControl,
)
from fuzzy1337.native_image_observation import (
    NativeImageMaterialObserver,
    NativeImageObservationBudget,
    NativeImageObservationError,
)
from tests.contract.native_image_task_barriers import OwnedTaskAtReadiness
from tests.unit.test_native_image_material_worker import material_control as material_control


@pytest.fixture(scope="module")
def observation_runner():
    """Initialize owned event-loop resources before the Windows unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()

        yield runner


@pytest.fixture
def simulated_observer(material_control, monkeypatch):
    """Drive only finite protocol doubles with actual tiny pytest-owned file reads."""

    path, digest, identity, _ = material_control
    selection = SelectionFromControl(ReadControl(path, digest, identity))
    owner = NativeImageMaterialObserver(selection, "workspace:unit", "actor:unit")
    state = SimpleNamespace(calls=[], change=None, before_launch=None,
                            mode="success", started=asyncio.Event())
    monkeypatch.setattr(observation, "RequireLinuxOwnership", lambda: None)

    async def Execute(executor, request, **options):
        """Simulate already-owned terminal facts without claiming Linux process acceptance."""

        state.calls.append((request, options))
        assert options["own_descendants"] is True, "The observer must request descendant ownership."

        if state.before_launch is not None:
            state.before_launch()

        options["pre_launch"](request)
        arguments = request.invocation.argv
        control = ReadControl(observation.Path(arguments[-3]), arguments[-2],
                              tuple(map(int, arguments[-1].split(","))))
        raw = ObserveControl(control, arguments[-2], tuple(map(int, arguments[-1].split(","))))
        value = ParseControl(raw)

        if state.change is not None:
            state.change(value)

        raw = CanonicalControl(value)
        kind = ExecutionTermination.PROCESS_EXIT
        terminal = ExecutionState.SUCCEEDED
        code = 0

        if state.mode == "pending":
            state.started.set()

            await options["cancellation"].wait()

            terminal, kind, code = ExecutionState.CANCELLED, ExecutionTermination.CANCELLATION, None

        elif state.mode == "timeout":
            terminal, kind, code = ExecutionState.TIMED_OUT, ExecutionTermination.TIMEOUT, None

        if state.mode == "events":
            for index in range(1025):
                options["on_event"](ExecutionEvent(index, ExecutionEventKind.STDOUT, b"x"))

        events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDOUT, raw),
            ExecutionEvent(2, ExecutionEventKind.COMPLETED, termination=kind))

        for event in events:
            options["on_event"](event)

        return LocalExecutionResult(AdapterExecution(terminal, code, 0.001), kind, raw, b"", events)

    monkeypatch.setattr(observation.LocalExecutor, "Execute", Execute)

    return owner, state


def test_SimulatedWorkerProofAndCheapCurrentChecksUseNoSelectedContent(
    simulated_observer, observation_runner, monkeypatch
):
    """The proof is detached and its cheap hook never calls the original synchronous hasher."""

    owner, state = simulated_observer
    budget = NativeImageObservationBudget()
    proof = observation_runner.run(owner.Observe(budget, operation_reference="pair:unit"))
    assert len(proof.facts) == 4 and len(proof.Digest()) == 64, "Proof retains exact finite facts."
    assert proof.Digest() == proof.Digest(), "Repeated proof correlation must be deterministic."
    metadata = proof.Metadata()
    metadata["Version"] = 99
    assert proof.Metadata()["Version"] == 2, "Detached metadata mutation must not change proof."
    monkeypatch.setattr(observation.NativeTrivySelection, "Material",
                        lambda selection: pytest.fail("Cheap current checks must not hash files"))
    owner.CheckCurrent(proof, operation_reference="pair:unit")
    assert len(tuple(owner.selection.workspace_root.glob("native-material-*/request.json"))) == 1, (
        "The completed observer removes its directory and leaves only the separate fixture control."
    )
    assert state.calls[0][0].invocation.argv[1:4] == (
        "-I", "-m", "fuzzy1337.native_image_material_worker"
    ), "Only the installed isolated fixed material worker is selected."
    assert budget.ObservationCount == 1 and not budget.Failed, "Successful work is charged once."


@pytest.mark.parametrize("change", [
    lambda value: value.update({"schema_version": True}),
    lambda value: value.update({"workspace_identity": [True, False]}),
    lambda value: value.update({"nonce": "b" * 32}),
    lambda value: value.update({"extra": "FORBIDDEN"}),
    lambda value: value.update({"facts": []}),
    lambda value: value["facts"][0].update({"role": "other"}),
    lambda value: value["facts"][0].update({"sha256": "X" * 64}),
    lambda value: value["facts"][0].update({"size_bytes": True}),
    lambda value: value.update({"metadata": {"Version": 2, "UpdatedAt": "invalid"}}),
])
def test_SimulatedPrivateWireCannotIssueProofForChangedFacts(
    simulated_observer, observation_runner, change
):
    """Only an exactly associated complete private wire can reach opaque proof issuance."""

    owner, state = simulated_observer
    state.change = change
    budget = NativeImageObservationBudget()

    with pytest.raises(NativeImageObservationError):
        observation_runner.run(owner.Observe(budget, operation_reference="pair:unit"))

    assert budget.Failed and not owner._proofs, "Unverified wire can never issue a usable proof."


@pytest.mark.parametrize("mode", ["timeout", "events"])
def test_FailedWorkerOrEventOverflowNeverIssuesUsableProof(
    simulated_observer, observation_runner, mode
):
    """Finite original event overhead is enforced during acquisition, not after list growth."""

    owner, state = simulated_observer
    state.mode = mode
    budget = NativeImageObservationBudget()

    with pytest.raises(NativeImageObservationError):
        observation_runner.run(owner.Observe(budget, operation_reference="pair:unit"))

    assert budget.Failed and not owner._proofs, "Worker failure cannot supply a successful proof."


def test_OuterCancellationAwaitsOwnedSimulatedTerminalBeforeRemovingControl(
    simulated_observer, observation_runner
):
    """Direct cancellation signals the owned execution and awaits its actual cooperative result."""

    owner, state = simulated_observer
    state.mode = "pending"
    budget = NativeImageObservationBudget()

    async def Cancel():
        """Cancel only after the fixed simulated worker handshake reaches its owned wait."""

        async with OwnedTaskAtReadiness(owner.Observe(budget, operation_reference="pair:unit"),
                                       state.started) as task:
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

    observation_runner.run(Cancel())
    assert budget.Failed and not owner._proofs, "Cancellation cannot issue a usable proof."
    assert len(tuple(owner.selection.workspace_root.glob("native-material-*/request.json"))) == 1, (
        "Verified terminal cancellation permits cleanup of only the observer's private request."
    )


def test_ReadinessRethrowsOriginalEarlyExceptionAndSettlesItsWaiter(observation_runner):
    """An operation that fails before its signal cannot leave the readiness controller waiting."""

    original = NativeImageObservationError("controlled original early observation failure")

    async def Fail():
        """Raise the original controlled exception before publishing any readiness signal."""

        raise original

    async def Run():
        """Verify exact original exception identity and no remaining owned background tasks."""

        before = asyncio.all_tasks()
        with pytest.raises(NativeImageObservationError) as caught:
            async with OwnedTaskAtReadiness(Fail(), asyncio.Event()):
                pytest.fail("An early failed operation cannot reach readiness")
        assert caught.value is original, (
            "The barrier must rethrow the original operation exception."
        )
        assert asyncio.all_tasks() == before, "Early failure must settle the event waiter as well."

    observation_runner.run(Run())


def test_PostReadinessAssertionStillCancelsAndSettlesOwnedTasks(observation_runner):
    """A failure before the caller requests cancellation cannot abandon the ready operation."""

    async def Run():
        """Assert post-readiness failure settles both owned tasks before propagation."""

        ready = asyncio.Event()
        settled = asyncio.Event()
        original = AssertionError("controlled readiness-body assertion")
        before = asyncio.all_tasks()

        async def Pending():
            """Publish actual controlled readiness, then remain owned until final cleanup."""

            try:
                ready.set()

                await asyncio.Event().wait()

            finally:
                settled.set()

        with pytest.raises(AssertionError) as caught:
            async with OwnedTaskAtReadiness(Pending(), ready):
                raise original
        assert caught.value is original and settled.is_set(), (
            "The caller's original failure must propagate only after owned operation cleanup."
        )
        assert asyncio.all_tasks() == before, (
            "A failed readiness assertion must leave no owned tasks."
        )

    observation_runner.run(Run())


def test_MissingReadinessDeadlineCancelsAndSettlesTheOwnedOperation(observation_runner):
    """A deterministic zero deadline rejects neither-ready-nor-terminal and awaits task cleanup."""

    async def Run():
        """Use event controls only, without clocks, subprocesses or an unowned background task."""

        settled = asyncio.Event()
        before = asyncio.all_tasks()

        async def Pending():
            """Remain pending until the readiness owner cancels and awaits this operation."""

            try:
                await asyncio.Event().wait()

            finally:
                settled.set()

        with pytest.raises(TimeoutError, match="neither became ready nor terminated"):
            async with OwnedTaskAtReadiness(Pending(), asyncio.Event(), timeout_seconds=0):
                pytest.fail("Neither completed task can supply readiness")
        assert settled.is_set(), "Deadline refusal must wait for the owned operation's cleanup."
        assert asyncio.all_tasks() == before, "Deadline refusal must settle both owned tasks."

    observation_runner.run(Run())


@pytest.mark.parametrize("mutation", ["consent", "workspace", "file", "pair", "copy"])
def test_CurrentProofRejectsChangedContextOrRebuiltObject(
    simulated_observer, observation_runner, mutation
):
    """Current physical metadata and full read-consent identity are part of issued proof use."""

    owner, _ = simulated_observer
    proof = observation_runner.run(owner.Observe(NativeImageObservationBudget(),
                                                 operation_reference="pair:unit"))
    pair = "pair:unit"

    if mutation == "consent":
        owner.selection = replace(owner.selection,
            read_consent=replace(owner.selection.read_consent, record_ref="read:changed"))

    elif mutation == "workspace":
        owner.workspace_id = "workspace:changed"

    elif mutation == "file":
        (owner.selection.workspace_root / owner.selection.archive).write_bytes(b"CHANGED")

    elif mutation == "pair":
        pair = "pair:changed"

    else:
        proof = replace(proof)

    with pytest.raises(NativeImageObservationError):
        owner.CheckCurrent(proof, operation_reference=pair)


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), "12",
    pytest.param(10**10000, id="oversized-int")])
def test_ObservationLedgerRejectsNonfiniteOrCoercibleDeadline(deadline):
    """No deadline is inferred from a boolean, string or nonfinite scalar."""

    with pytest.raises(NativeImageObservationError):
        NativeImageObservationBudget(overall_deadline=deadline)


def test_FreshWorkerHandoffRechecksTheWholeCurrentReadConsent(
    simulated_observer, observation_runner
):
    """A same-actor replacement consent record cannot pass the final actual launch hook."""

    owner, state = simulated_observer

    def ReplaceConsent():
        """Change this unit observer binding immediately before simulated final handoff."""

        owner.selection = replace(owner.selection,
            read_consent=replace(owner.selection.read_consent, record_ref="read:replaced"))

    state.before_launch = ReplaceConsent
    budget = NativeImageObservationBudget()

    with pytest.raises(NativeImageObservationError):
        observation_runner.run(owner.Observe(budget, operation_reference="pair:unit"))

    assert budget.Failed and not owner._proofs, "Changed final consent cannot issue a proof."


def test_ObservationLedgerOwnsExactWindowsAndChargesInterleavedFinalization(monkeypatch):
    """Both captures share nine seconds across multiple independent journal/publication slices."""

    clock = [100.0]
    monkeypatch.setattr(observation, "monotonic", lambda: clock[0])
    budget = NativeImageObservationBudget()
    first = budget.BeginObservation()

    with pytest.raises(NativeImageObservationError):
        budget.BeginFinalization()

    with pytest.raises(NativeImageObservationError):
        budget.FinishObservation(replace(first), successful=True)

    clock[0] += 1
    budget.FinishObservation(first, successful=True)

    with pytest.raises(NativeImageObservationError):
        budget.FinishObservation(first, successful=True)

    for _ in range(3):
        final = budget.BeginFinalization()
        clock[0] += 2
        budget.FinishFinalization(final)

    assert budget.FinalizationSeconds == 6 and budget.SpentSeconds == 7, (
        "All finalization slices debit the same cumulative reserve and total."
    )
    final = budget.BeginFinalization()
    assert final.deadline - final.started_at == 3, "Only three of the shared nine seconds remain."
    clock[0] += 3
    budget.FinishFinalization(final)

    with pytest.raises(NativeImageObservationError):
        budget.BeginFinalization()


def test_PlanningAndExpiredWindowsCannotRenewOrSupplyWorkingTime(monkeypatch):
    """Planning owns only one slot, and a phase overrun permanently refuses another read."""

    clock = [10.0]
    monkeypatch.setattr(observation, "monotonic", lambda: clock[0])
    plan = NativeImageObservationBudget(planning=True)
    window = plan.BeginObservation()
    clock[0] = window.working_deadline

    with pytest.raises(NativeImageObservationError):
        window.WorkerSeconds()

    clock[0] = window.deadline + 1

    with pytest.raises(NativeImageObservationError):
        plan.FinishObservation(window, successful=True)

    assert plan.Failed and plan.SpentSeconds == 13, (
        "Actual elapsed overrun is not hidden or renewed."
    )

    with pytest.raises(NativeImageObservationError):
        plan.BeginObservation()

    with pytest.raises(NativeImageObservationError):
        plan.BeginFinalization()
