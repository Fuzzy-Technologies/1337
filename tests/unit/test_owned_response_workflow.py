# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Controlled original-response SDK ownership, source persistence and offline replay regressions."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import owned_response_workflow as product
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.jobs import JobState
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.policy import GovernedLocalExecutor, ImpactPolicy
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.browser_tree_diagnostics import AwaitBrowserReadiness
from tests.unit.test_owned_response_parent import AT, URL, Result, Setup
from tests.unit.test_owned_response_parent import runner as runner


@pytest.fixture
def owned(tmp_path, monkeypatch):
    """Use real canonical owners with the parent's finite original-execution wire double."""

    root = tmp_path / "workspace"
    workspace = LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned response"),
                                                "workspace")
    store = LocalModelStore(root)
    initial = store.Create()
    asset = SecurityObject(ObjectIdentity("workspace", ObjectKind.ASSET, "asset:unrelated"),
        {"operator_note": "preserve this unrelated canonical interpretation"},
        (ModelProvenance("operator.seed", "run:seed", AT.isoformat(), "scope:seed",
                         "target:seed"),))
    model, _ = initial.Apply(objects=(asset,))
    store.Save(model, expected_revision=initial.revision)
    provider, job, authority = Setup(root, monkeypatch)
    LocalScopeStore(root).Create(authority[0].context.scope)

    return SimpleNamespace(root=root, workspace=workspace, model=model, authority=authority,
                           provider=provider, original_job=job, asset=asset)


def Capture(owned, runner, **kwargs):
    """Run the actual SDK with explicit approval and the fixture's deterministic decision clock."""

    return runner.run(product.RunOwnedResponseCapture(owned.root, "lab", URL, "operator:execution",
        lambda: owned.authority[0].context.policy, approve_safe_response_capture=True,
        clock=lambda: AT, **kwargs))


def test_DescriptivePlanCreatesNoGrantPrivateOperationOrPersistentState(owned):
    """SAFE descriptive planning preserves exact immutable bases without contacting a target."""

    before = LocalWorkspaceStore(owned.root).Open()
    plan = product.PlanOwnedResponseCapture(owned.root, "lab", URL, "operator:execution",
        lambda: owned.authority[0].context.policy, clock=lambda: AT)
    assert not plan.ToDict()["execution_authorized"] and (
        plan.model_revision == owned.model.revision
    ), (
        "Planning must expose only descriptive intent and actual existing revision bases."
    )
    assert not tuple(owned.root.glob("owned-response-*")), "Planning creates no private operation."
    assert LocalWorkspaceStore(owned.root).Open() == before, "Planning must not persist authority."


def test_RepeatedRealOwnerCompositionKeepsEveryOriginalSourceAndUnrelatedState(owned, runner):
    """One canonical endpoint retains two immutable receipt/job facts without inventing Findings."""

    first = Capture(owned, runner)
    second = Capture(owned, runner)
    assert first.ExitCode() == second.ExitCode() == 0, (first.ToDict(), second.ToDict())
    assert first.snapshot.spec.job_id != second.snapshot.spec.job_id and (
        first.original_receipt_id != second.original_receipt_id
    ), "Each real attempt must preserve a distinct original job and receipt association."
    state = LocalModelStore(owned.root).Open()
    facts = tuple(item for item in state.observations if item.kind == product.SOURCE_KIND)
    assert len(facts) == 2 and len(state.Objects(ObjectKind.ENDPOINT)) == 1, (
        "Repeated captures must preserve both source observations and one stable Endpoint."
    )
    assert next(item for item in state.objects if item.identity == owned.asset.identity) == (
        owned.asset
    ), "Source-only projection must preserve every unrelated original attribute and provenance."
    assert not state.Objects(ObjectKind.FINDING), "Acquisition cannot manufacture security results."
    assert second.model_revision == owned.model.revision + 2 and second.workspace_revision == 2, (
        "Each acknowledged capture must use one real model CAS and one workspace CAS."
    )
    assert second.model_persistence_status == second.workspace_persistence_status == (
        "acknowledged"
    ), (
        "Completion must require both exact durable acknowledgements."
    )
    original_ids = {item.evidence_id for item in (*first.records, *second.records)}
    assert len(second.records) == 7 and set(LocalWorkspaceStore(owned.root).Open(
    ).evidence_record_references) == original_ids, (
        "Each original ID must survive; identical fixed-clock provenance may reuse canonical IDs."
    )
    assert first.stage_retained and len(tuple(owned.root.glob("owned-response-*"))) == 2, (
        "SDK persistence must not pretend the parent recovery stage was removed."
    )
    assert any(event.kind.value == "model_delta" for event in second.events), (
        "A real source transition may publish ModelChanged only inside the same active job."
    )


def test_RelocatedReplayUsesKnownOriginalJobAndIdsWithoutCurrentAuthorityOrRuntime(
    owned, runner, monkeypatch,
):
    """Historical integrity verification needs neither old target, policy, scope nor program."""

    summary = Capture(owned, runner)
    assert summary.ExitCode() == 0, summary.ToDict()
    relocated = owned.root.parent / "relocated"
    shutil.move(owned.root, relocated)
    before = LocalWorkspaceStore(relocated).Open()
    model = LocalModelStore(relocated).Open()

    def Refuse(*args, **kwargs):
        """Forbid current authority, runtime preparation and all canonical writes during replay."""

        pytest.fail("Offline original replay must not acquire authority, execute or persist")

    monkeypatch.setattr(LocalScopeStore, "Open", Refuse)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    monkeypatch.setattr(product, "PrepareOwnedResponseInvocation", Refuse)
    replay = product.ReplayOwnedResponse(relocated, summary.original_receipt_id)
    assert replay.original_job_id == summary.snapshot.spec.job_id and replay.source_facts == (
        summary.source_facts
    ), "Original replay must recover the actual durable source/job association without guessing."
    assert replay.ToDict()["original_role_ids"] == summary.ToDict()["original_role_ids"], (
        "Relocation must preserve all seven original acquisition manifest IDs."
    )
    assert LocalWorkspaceStore(relocated).Open() == before and (
        LocalModelStore(relocated).Open() == model
    ), "Historical verification must not Save or change canonical revisions."


@pytest.mark.parametrize("change", ["missing-fact", "job-id", "role-id", "unenrolled-receipt"])
def test_HistoricalReplayCannotAdoptUnknownOrChangedOriginalSourceAssociation(
    owned, runner, change,
):
    """Stored original bytes alone cannot invent a successful source/job persistence association."""

    summary = Capture(owned, runner)
    assert summary.ExitCode() == 0, summary.ToDict()
    store = LocalModelStore(owned.root)
    model = store.Open()
    fact = next(item for item in model.observations if item.kind == product.SOURCE_KIND)

    if change == "unenrolled-receipt":
        workspace_store = LocalWorkspaceStore(owned.root)
        state = workspace_store.Open()
        workspace_store.Save(replace(state, evidence_record_references=tuple(
            value for value in state.evidence_record_references
            if value != summary.original_receipt_id)))

    else:
        facts = ()

        if change != "missing-fact":
            attrs = dict(fact.attributes)
            attrs["original_job_id" if change == "job-id" else "original_role_ids"] = (
                "job:invented" if change == "job-id" else {})
            facts = (replace(fact, attributes=attrs),)

        store.Save(replace(model, revision=model.revision + 1, observations=facts),
                   expected_revision=model.revision)

    with pytest.raises(ValueError, match="owned response original"):
        product.ReplayOwnedResponse(owned.root, summary.original_receipt_id)


def test_MissingApprovalAndRefreshedActorDenialOccurBeforeAcquisition(owned, runner):
    """Independent attestation or a capability permission cannot replace executing attribution."""

    with pytest.raises(product.OwnedResponseAuthorityDeniedError):
        runner.run(product.RunOwnedResponseCapture(owned.root, "lab", URL, "operator:execution",
            lambda: owned.authority[0].context.policy, clock=lambda: AT))
    with pytest.raises(product.OwnedResponseAuthorityDeniedError):
        product.PlanOwnedResponseCapture(owned.root, "lab", URL, "operator:execution",
            lambda: owned.authority[0].context.policy, clock=lambda: AT,
            current_owner_provider=lambda: "operator:changed")
    with pytest.raises(product.OwnedResponseAuthorityDeniedError):
        Capture(owned, runner, current_owner_provider=lambda: "operator:changed")
    assert not tuple(owned.root.glob("owned-response-*")), "Actor refusal precedes work creation."


def test_CurrentAcquisitionPermissionRemainsDistinctFromWorkflowApproval(owned, runner):
    """Explicit workflow approval cannot grant a missing current acquisition capability."""

    owned.authority[0] = replace(owned.authority[0], context=replace(
        owned.authority[0].context, policy=ImpactPolicy("denied")))
    summary = Capture(owned, runner)
    assert summary.snapshot.state is JobState.FAILED and summary.ExitCode() == 3, summary.ToDict()
    assert not summary.records and summary.model_revision == owned.model.revision, (
        "Denied acquisition cannot fabricate original capture or source-model persistence."
    )


def test_CallerCancellationAwaitsOwnedParentAndReportsOnlyControlCustody(
    owned, runner, monkeypatch,
):
    """Cancellation settles the original task without upgrading control-only receipt custody."""

    ready = asyncio.Event()
    cleaned = asyncio.Event()

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Wait on the original cancellation bridge before returning terminal control."""

        context_provider()
        ready.set()

        await cancellation.wait()

        events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.COMPLETED,
                           termination=ExecutionTermination.CANCELLATION))

        for event in events:
            on_event(event)

        cleaned.set()

        return LocalExecutionResult(AdapterExecution(ExecutionState.CANCELLED, None, 0.01),
            ExecutionTermination.CANCELLATION, b"", b"", events)

    async def Cancel():
        """Race readiness with actual completion and settle the owned operation on every exit."""

        task = asyncio.create_task(product.RunOwnedResponseCapture(owned.root, "lab", URL,
            "operator:execution", lambda: owned.authority[0].context.policy,
            approve_safe_response_capture=True, clock=lambda: AT))

        try:
            outcome = await AwaitBrowserReadiness(task, ready, timeout_seconds=2)
            assert outcome == "ready", "The actual controlled operation must reach owned readiness."
            task.cancel()

            return await task

        finally:
            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    summary = runner.run(Cancel())
    assert cleaned.is_set() and summary.snapshot.state is JobState.CANCELLED, summary.ToDict()
    assert summary.ExitCode() == 130 and summary.custody_status == "incomplete", (
        "A cancelled actual operation cannot become a successful original response capture."
    )
    assert summary.model_revision == owned.model.revision and summary.workspace_revision == 0, (
        "Cancelled cleanup must not bypass the fresh guard to Save source facts or references."
    )


@pytest.mark.parametrize("presentation_failure", [False, True])
def test_RepeatedCallerCancellationCannotOutrunCleanupOrReplaceFirstPresentationError(
    owned, runner, monkeypatch, presentation_failure,
):
    """Repeated external cancellation cannot detach the one original coordinator cleanup task."""

    ready, stopping, release, cleaned = (asyncio.Event() for _ in range(4))
    jobs = []
    original_job = product.ScanJob
    original_error = RuntimeError("controlled original presentation failure")
    cancellation_calls = []

    class CapturedJob(original_job):
        """Retain only this test's actual original coordinator for guaranteed failure teardown."""

        def __init__(self, *args, **kwargs):
            """Record the real original job without changing its ownership or state machine."""

            super().__init__(*args, **kwargs)
            jobs.append(self)

        async def CancelAndWait(self, requested_by, **kwargs):
            """Count original cancellation entry without issuing extra provider cancellation."""

            cancellation_calls.append(requested_by)

            return await super().CancelAndWait(requested_by, **kwargs)

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Hold cleanup after cancellation until the test releases the owned operation."""

        context_provider()
        ready.set()
        on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))

        await cancellation.wait()

        stopping.set()

        await release.wait()

        cleaned.set()
        completed = ExecutionEvent(1, ExecutionEventKind.COMPLETED,
                                   termination=ExecutionTermination.CANCELLATION)
        on_event(completed)

        return LocalExecutionResult(AdapterExecution(ExecutionState.CANCELLED, None, 0.01),
            ExecutionTermination.CANCELLATION, b"", b"",
            (ExecutionEvent(0, ExecutionEventKind.STARTED), completed))

    def Observe(event):
        """Fail the presentation sink only after this test's actual owned execution is active."""

        if presentation_failure and ready.is_set():
            raise original_error

    async def Run():
        """Require public SDK ownership to outlive held cleanup, with bounded failure teardown."""

        task = asyncio.create_task(product.RunOwnedResponseCapture(owned.root, "lab", URL,
            "operator:execution", lambda: owned.authority[0].context.policy,
            approve_safe_response_capture=True, clock=lambda: AT, on_event=Observe))

        try:
            assert await AwaitBrowserReadiness(task, ready, timeout_seconds=2) == "ready", (
                "The actual original operation must become ready before cancellation."
            )

            if not presentation_failure:
                task.cancel()

            await asyncio.wait_for(stopping.wait(), timeout=2)

            for _ in range(2):
                task.cancel()

                await asyncio.sleep(0)

            assert not task.done() and not cleaned.is_set(), (
                "The public SDK must not finish while its actual original cleanup remains held."
            )
            release.set()

            if presentation_failure:
                with pytest.raises(RuntimeError) as caught:
                    await task

                assert caught.value is original_error, (
                    "Later caller cancellation cannot replace the first presentation exception."
                )

            else:
                summary = await task
                assert summary.snapshot.state is JobState.CANCELLED and summary.ExitCode() == 130, (
                    "Only original confirmed cancellation may produce the terminal SDK summary."
                )

            assert cleaned.is_set() and cancellation_calls == ["operator:execution"], (
                "Cleanup must finish before return and the coordinator must be cancelled only once."
            )

        finally:
            release.set()

            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

            if jobs:
                await asyncio.wait_for(jobs[0].Wait(), timeout=2)

    monkeypatch.setattr(product, "ScanJob", CapturedJob)
    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    runner.run(Run())


@pytest.mark.parametrize("cancelled", [False, True])
def test_TerminalCleanupFailureNeverLoopsOrFabricatesConfirmation(runner, cancelled):
    """An already failed or cancelled cleanup child differs from repeated external cancellation."""

    original = RuntimeError("controlled original cleanup error")

    async def Failed():
        """Terminate the actual owned child with one explicit original failure state."""

        if cancelled:
            raise asyncio.CancelledError

        raise original

    async def Run():
        """Inspect child completion without launching a job, process or background owner."""

        task = asyncio.create_task(Failed())

        with pytest.raises(RuntimeError) as caught:
            await product.SettleOwnedResponseCleanup(task)

        assert task.done(), "A terminal child must be observed once rather than busy-looped."

        if cancelled:
            assert task.cancelled() and "without confirmation" in str(caught.value), (
                "A terminal cancelled cleanup task cannot claim confirmed original cleanup."
            )

        else:
            assert caught.value is original, "Original cleanup failure identity must survive."

    runner.run(Run())


def test_ConcurrentOperatorModelChangeIsNeverSilentlyRebased(owned, runner, monkeypatch):
    """The source CAS uses its exact initial basis and preserves a concurrent operator note."""

    original = product.SourceFact

    def Fact(*args, **kwargs):
        """Commit only a real independent operator model change after source verification."""

        fact = original(*args, **kwargs)
        store = LocalModelStore(owned.root)
        state = store.Open()
        changed, _ = state.Apply(objects=(replace(owned.asset,
            attributes={"operator_note": "concurrent operator value"}),))
        store.Save(changed, expected_revision=state.revision)

        return fact

    monkeypatch.setattr(product, "SourceFact", Fact)
    summary = Capture(owned, runner)
    assert summary.ExitCode() == 4 and summary.model_persistence_status == "not-attempted", (
        "A changed original model basis must refuse instead of rebasing source or triage state."
    )
    state = LocalModelStore(owned.root).Open()
    assert state.objects[0].attributes["operator_note"] == "concurrent operator value", (
        "The SDK must preserve the actual independently committed operator state."
    )
    assert summary.workspace_revision == 0 and len(summary.records) == 7, (
        "A failed composition retains actual original attachments without an unauthorized CAS."
    )


def test_PresentationFailureAfterBothSavesNeverRollsBackSourceState(owned, runner):
    """A failed external event consumer cannot erase already acknowledged source persistence."""

    def Fail(event):
        """Raise only after the actual source ModelChanged event follows both durable saves."""

        if event.kind.value == "model_delta":
            raise RuntimeError("controlled external presentation failure")

    with pytest.raises(RuntimeError, match="controlled external presentation failure"):
        Capture(owned, runner, on_event=Fail)

    model = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    assert model.revision == owned.model.revision + 1 and workspace.revision == 1, (
        "A presentation exception must preserve actual acknowledged model and workspace revisions."
    )
    assert len(workspace.evidence_record_references) == 7, "Original IDs cannot be rolled back."


@pytest.mark.parametrize("kind", ["closed-refusal", "unsafe-record"])
def test_OriginalRefusalAndControlOnlyReceiptNeverBecomeSuccessfulSourceCustody(
    owned, runner, monkeypatch, kind,
):
    """Safe worker refusal and rejected output preserve distinct truthful custody branches."""

    async def Execute(self, request, *, context_provider, on_event, cancellation, **kwargs):
        """Emit only controlled original process facts through the parent's real owner path."""

        context_provider()
        result = Result(error="protocol") if kind == "closed-refusal" else Result(
            raw=b"PRIVATE_REJECTED_RESPONSE_MARKER")

        for event in result.events:
            on_event(event)

        return result

    monkeypatch.setattr(GovernedLocalExecutor, "Execute", Execute)
    summary = Capture(owned, runner)
    assert summary.ExitCode() == 4 and summary.snapshot.state is JobState.FAILED, summary.ToDict()
    expected = (("refused", "complete", 3) if kind == "closed-refusal" else
                ("unknown", "incomplete", 1))
    actual = summary.acquisition_outcome, summary.custody_status, len(summary.records)
    assert actual == expected, (
        "A control-only receipt cannot be presented as complete original response custody."
    )
    assert summary.model_revision == owned.model.revision and summary.workspace_revision == 0, (
        "Refused or unsafe output cannot produce a successful source fact or unguarded Save."
    )
    assert "PRIVATE_REJECTED" not in str(summary.ToDict()), "Rejected bytes cannot reach summaries."


@pytest.mark.parametrize("boundary", ["model-before", "model-after", "workspace-before",
                                     "workspace-after"])
def test_SaveFailureReportsActualCommitAndNeverRetriesOriginalCas(
    owned, runner, monkeypatch, boundary,
):
    """A raised Save may already have committed; summaries preserve actual reopened revisions."""

    model_save = LocalModelStore.Save
    workspace_save = LocalWorkspaceStore.Save
    calls = {"model": 0, "workspace": 0}

    def ModelSave(store, state, *, expected_revision):
        """Fail only this test's actual source-model write before or after canonical commit."""

        calls["model"] += 1

        if boundary == "model-before":
            raise OSError("controlled original model failure before commit")

        result = model_save(store, state, expected_revision=expected_revision)

        if boundary == "model-after":
            raise OSError("controlled lost model acknowledgement")

        return result

    def WorkspaceSave(store, state):
        """Fail the one actual workspace write without retrying stale original references."""

        calls["workspace"] += 1

        if boundary == "workspace-before":
            raise OSError("controlled original workspace failure before commit")

        result = workspace_save(store, state)

        if boundary == "workspace-after":
            raise OSError("controlled lost workspace acknowledgement")

        return result

    monkeypatch.setattr(LocalModelStore, "Save", ModelSave)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", WorkspaceSave)
    summary = Capture(owned, runner)
    assert summary.ExitCode() == 4 and summary.snapshot.state is JobState.FAILED, summary.ToDict()
    assert calls == {"model": 1, "workspace": 1}, "Neither Save may silently retry or rebase."
    expected_model = owned.model.revision + (boundary != "model-before")
    expected_workspace = 0 if boundary == "workspace-before" else 1
    assert summary.model_revision == expected_model and (
        summary.workspace_revision == expected_workspace
    ), (
        "The SDK must report the actual independently reopened committed revisions."
    )
    statuses = (summary.model_persistence_status, summary.workspace_persistence_status)
    expected_status = "observed-committed" if boundary.endswith("after") else "observed-unchanged"
    assert expected_status in statuses, (
        "Lost acknowledgement must remain distinct from acknowledged completion and rollback."
    )
    assert len(summary.records) == 7 and summary.stage_retained and not any(
        event.kind.value == "model_delta" for event in summary.events
    ), "Every original remains available while a failed pair publishes no successful model event."


@pytest.mark.parametrize("boundary", ["before-model", "after-model"])
def test_FreshActorRevocationAtSaveBoundaryPreventsEveryLaterUnauthorizedWrite(
    owned, runner, monkeypatch, boundary,
):
    """A real current-owner change cannot be ignored by forward or failure-path Save guards."""

    actor = ["operator:execution"]
    original_fact = product.SourceFact
    original_save = LocalModelStore.Save

    def Fact(*args, **kwargs):
        """Change only trusted current attribution after original capture replay finishes."""

        fact = original_fact(*args, **kwargs)

        if boundary == "before-model":
            actor[0] = "operator:changed"

        return fact

    def Save(store, state, *, expected_revision):
        """Change attribution immediately after a real model acknowledgement."""

        result = original_save(store, state, expected_revision=expected_revision)
        actor[0] = "operator:changed"

        return result

    monkeypatch.setattr(product, "SourceFact", Fact)
    monkeypatch.setattr(LocalModelStore, "Save", Save)
    summary = Capture(owned, runner, current_owner_provider=lambda: actor[0])
    assert summary.ExitCode() == 3 and summary.snapshot.state is JobState.FAILED, summary.ToDict()
    assert summary.model_revision == owned.model.revision + (boundary == "after-model"), (
        "A post-commit denial must preserve the actual already committed source fact."
    )
    assert summary.workspace_revision == 0 and (
        summary.workspace_persistence_status == "not-attempted"
    ), (
        "The failure finalizer must never Save after the original guard denies authority."
    )
    assert len(summary.records) == 7 and summary.stage_retained, (
        "Revocation must report actual original attachment IDs and keep admitted recovery staging."
    )
