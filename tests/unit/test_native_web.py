# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable actual policy/evidence/model orchestration with an isolated synthetic transport."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from fuzzy1337 import native_web
from fuzzy1337.adapters import AdapterExecution, ExecutionState, ImpactLevel
from fuzzy1337.adapters.native_web import CanonicalRecord
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.jobs import JobEventKind, JobFailureCode
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import (
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    NativeWebAuthorityDeniedError,
    NativeWebScanLimits,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation, PolicyEngine
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore


@pytest.fixture(scope="module")
def owned_loop():
    """Initialize runtime self-pipes before the unchanged unit network-denial guard."""

    with asyncio.Runner() as runner:
        yield runner


@pytest.fixture
def runner(owned_loop):
    """Reuse the isolated loop and reap every test-owned task after each scenario."""

    yield owned_loop

    async def Cleanup():
        """Cancel and await residual test tasks without changing network isolation."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_loop.run(Cleanup())


def Policy():
    """Declare only the explicit native STANDARD capability, never execution permission."""

    return ImpactPolicy("owned-native-web", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    """Replace only subprocess transport; canonical policy/job/evidence/model owners remain real."""

    root = tmp_path / "workspace"
    CreateWorkspace(root, "owned-native-web", "Synthetic portable native workflow")
    target = Target(TargetKind.URL, "http://127.0.0.1:8080/.git/HEAD")
    now = datetime.now(UTC)
    address = Target(TargetKind.IP, "127.0.0.1")
    LocalScopeStore(root).Create(ScopeSnapshot("local", "owned-native-web", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-native-web",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target, address), allow=(target, address)))
    probe = {"mode": "match", "executed": False, "mutate": None}

    class SyntheticExecutor:
        """Model a controlled returned process result, never native scanner acceptance."""

        def __init__(self, root, *, clock):
            """Retain only the real current authority clock without starting a process."""

            self.clock = clock

        async def Execute(self, request, *, grant, context_provider, on_event, cancellation):
            """Repeat genuine final policy validation before returning synthetic bytes."""

            if probe["mutate"] is not None:
                probe["mutate"]()

            PolicyEngine().Validate(grant, request.invocation, request.capability,
                                    context_provider(), at=self.clock())
            probe["executed"] = True
            on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
            mode = probe["mode"]

            await asyncio.sleep(0)

            if mode == "wait":
                await cancellation.wait()

                state, code, termination = (ExecutionState.CANCELLED, None,
                                             ExecutionTermination.CANCELLATION)

            elif mode == "process-timeout":
                state, code, termination = (ExecutionState.TIMED_OUT, None,
                                             ExecutionTermination.TIMEOUT)

            elif mode in {"fail", "request-timeout", "false-timeout"}:
                state, code, termination = (ExecutionState.FAILED,
                    124 if mode == "request-timeout" else 7, ExecutionTermination.PROCESS_EXIT)

            elif mode == "output-limit":
                state, code, termination = (ExecutionState.FAILED, 7,
                                             ExecutionTermination.OUTPUT_LIMIT)

            else:
                state, code, termination = (ExecutionState.SUCCEEDED, 0,
                                             ExecutionTermination.PROCESS_EXIT)

            body = b"ref: refs/heads/owned\n"
            stdout = CanonicalRecord({"schema_version": 1, "check_id": NATIVE_WEB_CHECK_ID,
                "profile_version": "1", "url": target.value, "address": "127.0.0.1",
                "port": 8080, "scheme": "http", "status": 200, "media_type": "text/plain",
                "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                "matched": mode != "negative"})

            if mode in {"request-timeout", "false-timeout"}:
                stdout = CanonicalRecord({"schema_version": 1, "error": "timeout"})

            elif mode == "invalid":
                stdout = b"not-canonical"

            return LocalExecutionResult(AdapterExecution(state, code, 0.01), termination,
                stdout, b"", (ExecutionEvent(0, ExecutionEventKind.STARTED),
                    ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination)))

    monkeypatch.setattr(native_web, "GovernedLocalExecutor", SyntheticExecutor)
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", Policy)
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:owned-native-exact")
    assert plan.ToDict()["policy_plan"]["intent_sha256"] == approval.intent_sha256, (
        "Displayed exact intent must match the independently supplied confirmation."
    )

    return root, target, approval, probe


@pytest.mark.parametrize("request_timeout,total", [(False, 10), (0, 10), (11, 20),
    (float("inf"), 20), (float("nan"), 20), (3, True), (3, 3), (3, 61)])
def test_RequestAndWholeJobBudgetsAreFiniteAndCompatible(request_timeout, total):
    """Bool aliases, nonfinite values and insufficient startup budgets cannot widen the job."""

    with pytest.raises(ValueError):
        NativeWebScanLimits(request_timeout, total)


@pytest.mark.parametrize("mode,expected,failure", [
    ("match", 0, None), ("negative", 0, None), ("invalid", 4, JobFailureCode.NORMALIZATION),
    ("fail", 4, JobFailureCode.PROVIDER), ("process-timeout", 4, JobFailureCode.TIMEOUT),
    ("request-timeout", 4, JobFailureCode.TIMEOUT), ("false-timeout", 4, JobFailureCode.PROVIDER),
    ("output-limit", 4, JobFailureCode.OUTPUT_LIMIT),
])
def test_PortableWorkflowRetainsActualOutcomesAndOriginalStreams(
    workflow, runner, mode, expected, failure,
):
    """Actual owner composition distinguishes false/failed/time-limited interpretations."""

    root, target, approval, probe = workflow
    probe["mode"] = mode
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval))
    assert summary.ExitCode() == expected, "Terminal native check outcome was misrepresented."
    assert len(summary.snapshot.artifacts) == 2, "Original returned streams were discarded."
    assert len(Findings(LocalModelStore(root).Open())) == (1 if mode == "match" else 0), (
        "Failed or negative metadata must not create a canonical Finding."
    )
    assert summary.ToDict()["state"] == summary.snapshot.state.value, "Summary state drifted."
    assert summary.snapshot.failure is None if failure is None else (
        summary.snapshot.failure.code is failure
    ), "Failure classification changed."


@pytest.mark.parametrize("approval", [None, PolicyConfirmation("0" * 64, "approval:wrong")])
def test_MissingOrStaleConfirmationDeniesBeforeExecution(workflow, runner, approval):
    """A previous plan and capability permission never replace explicit exact confirmation."""

    root, target, _, probe = workflow
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval))
    assert summary.ExitCode() == 3, "Missing or stale confirmation did not deny STANDARD."
    assert not probe["executed"], "Denied native operation reached the transport boundary."


@pytest.mark.parametrize("stage", ["authorize", "launch", "save"])
@pytest.mark.parametrize("mutation", ["owner", "policy"])
def test_CurrentAuthorityIsCheckedAgainBeforeLaunchAndSave(
    workflow, runner, monkeypatch, stage, mutation,
):
    """Owner/permission drift cannot reuse an earlier valid scope or exact-plan grant."""

    root, target, approval, probe = workflow
    policy = [Policy()]
    calls = [0]

    def Mutate():
        """Change the actual current owning policy or persisted scope consent actor."""

        if mutation == "policy":
            policy[0] = replace(policy[0], permissions=())

        else:
            store = LocalScopeStore(root)
            current = store.Open("local")
            store.Save(replace(current, authorization=replace(current.authorization,
                                                             authority_reference="operator:new")))

    def CurrentPolicy():
        """Model real typed current policy at the planning and authorization seams."""

        calls[0] += 1

        if stage == "authorize" and calls[0] == 2:
            Mutate()

        return policy[0]

    if stage == "launch":
        probe["mutate"] = Mutate

    elif stage == "save":
        original = native_web.ApplyVerifiedFindings

        def Apply(*args, **kwargs):
            """Change current authority after actual evidence and pure Finding projection."""

            updated = original(*args, **kwargs)
            Mutate()

            return updated

        monkeypatch.setattr(native_web, "ApplyVerifiedFindings", Apply)

    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", CurrentPolicy,
                                         confirmation=approval))
    assert summary.ExitCode() in {3, 4}, "Changed authority was accepted as successful."
    assert summary.model_revision == 0, "Changed authority wrote canonical Findings."


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("error_type", [OSError, PermissionError])
def test_DurableOwnerFailuresPreserveFailureAndActualStreams(
    workflow, runner, monkeypatch, owner, error_type,
):
    """Storage/CAS failures remain failures after actually acquired original evidence."""

    root, target, approval, _ = workflow

    def FailSave(*args, **kwargs):
        """Inject an isolated source-independent owning persistence failure."""

        raise error_type("synthetic-storage-failure")

    monkeypatch.setattr(LocalModelStore if owner == "model" else LocalWorkspaceStore,
                        "Save", FailSave)
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval))
    assert summary.ExitCode() == 4, "A failed owner acknowledgement claimed completion."
    assert len(summary.snapshot.artifacts) == 2, "Acquired original evidence was discarded."


def test_PublishedModelSurvivesLostAcknowledgement(workflow, runner, monkeypatch):
    """An acknowledged-unknown Save remains failure while actual published state is reopened."""

    root, target, approval, _ = workflow
    original = LocalModelStore.Save

    def SaveAndFail(self, *args, **kwargs):
        """Publish through the actual owner before failing its synthetic acknowledgement."""

        original(self, *args, **kwargs)

        raise OSError("synthetic-acknowledgement-failure")

    monkeypatch.setattr(LocalModelStore, "Save", SaveAndFail)
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval))
    assert summary.ExitCode() == 4 and summary.model_revision == 1, (
        "Unknown acknowledgement must retain failed outcome and actual saved revision."
    )
    assert len(Findings(LocalModelStore(root).Open())) == 1, "Published Finding was rolled back."
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 2, (
        "Original acquisitions were lost during failed acknowledgement."
    )


def test_FinalGrantExpiryCannotWriteCanonicalFindings(workflow, runner, monkeypatch):
    """A grant expiring during verified normalization must be rechecked before CAS Save."""

    root, target, approval, _ = workflow
    now = [datetime.now(UTC)]
    original = native_web.ApplyVerifiedFindings

    def Apply(*args, **kwargs):
        """Advance time only after the actual incoming original evidence was verified."""

        projected = original(*args, **kwargs)
        now[0] += timedelta(minutes=20)

        return projected

    monkeypatch.setattr(native_web, "ApplyVerifiedFindings", Apply)
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval, clock=lambda: now[0]))
    assert summary.ExitCode() == 3 and summary.model_revision == 0, (
        "Expired final authority created canonical Findings."
    )
    assert len(summary.snapshot.artifacts) == 2, "Actual returned streams must remain acquired."


def test_ConsumerCancellationAndPresentationFailureDrainOwnedWork(workflow, runner):
    """Presentation errors/cancellation await owning job cleanup without detached work."""

    root, target, approval, probe = workflow
    probe["mode"] = "wait"

    async def Scenario():
        """Cancel only after the synthetic transport actually published a heartbeat."""

        entered = asyncio.Event()

        def Observe(event):
            """Observe actual transport liveness before requesting cancellation."""

            if event.kind is JobEventKind.HEARTBEAT:
                entered.set()

        task = asyncio.create_task(RunNativeWebScan(root, "local", target, "operator:owned",
            Policy, confirmation=approval, on_event=Observe))

        await entered.wait()

        task.cancel()

        return await task

    assert runner.run(Scenario()).ExitCode() == 130, "Cancellation was reported as complete."

    def Fail(event):
        """Fail presentation after ownership has been established."""

        raise RuntimeError("synthetic-presentation-failure")

    with pytest.raises(RuntimeError, match="presentation"):
        runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                    confirmation=approval, on_event=Fail))


def test_InvalidInputsAndInitialOwnerPolicyFailuresStayExplicit(workflow):
    """Preflight reads never create execution authority from malformed state or policy."""

    root, target, _, probe = workflow

    for invalid in (Target(TargetKind.IP, "127.0.0.1"), "untyped"):
        with pytest.raises(ValueError):
            PlanNativeWebScan(root, "local", invalid, "operator:owned", Policy)

    with pytest.raises(NativeWebAuthorityDeniedError):
        PlanNativeWebScan(root, "local", target, "operator:wrong", Policy)

    with pytest.raises(ValueError, match="typed current"):
        PlanNativeWebScan(root, "local", target, "operator:owned", lambda: None)

    assert not probe["executed"], "Invalid planning input reached a process boundary."


def test_RepeatedDetectionPreservesCanonicalIdentityAndOperatorTriage(workflow, runner):
    """A fresh native acquisition adds provenance without resetting the operator's disposition."""

    root, target, approval, _ = workflow
    first = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                       confirmation=approval))
    assert first.ExitCode() == 0, "Initial native acquisition must complete before triage."
    store = LocalModelStore(root)
    state = store.Open()
    finding = Findings(state)[0]
    reference = finding.ToObject(state.workspace_id).Reference()
    decision = replace(finding.provenance[0], source_id="operator.triage",
                       run_reference="decision:owned", execution=None, provider_version=None)
    triaged, _ = TransitionFinding(state, reference, FindingStatus.DISMISSED, decision,
                                   "Reviewed owned fixture exposure")
    store.Save(triaged, expected_revision=state.revision)
    second = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                        confirmation=approval))
    retained = Findings(store.Open())
    assert second.ExitCode() == 0 and len(retained) == 1, (
        "Repeated native acquisition must preserve one canonical finding identity."
    )
    assert retained[0].Fingerprint() == finding.Fingerprint(), "Detector identity changed."
    assert retained[0].status is FindingStatus.DISMISSED and (
        retained[0].status_reason == "Reviewed owned fixture exposure"
    ), "A repeated detector update silently overwrote the operator's disposition."
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 4, (
        "Both actual acquisitions must retain their independently attributed original streams."
    )


def test_PolicyRevisionOnlyDriftAfterEvidenceCannotReuseTheLaunchGrant(
    workflow, runner, monkeypatch,
):
    """A changed policy revision invalidates the original grant even with identical permissions."""

    root, target, approval, _ = workflow
    policy = [Policy()]
    original = native_web.ApplyVerifiedFindings

    def Apply(*args, **kwargs):
        """Change only current policy revision after real incoming evidence verification."""

        projected = original(*args, **kwargs)
        policy[0] = replace(policy[0], revision=policy[0].revision + 1)

        return projected

    monkeypatch.setattr(native_web, "ApplyVerifiedFindings", Apply)
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned",
                                         lambda: policy[0], confirmation=approval))
    assert summary.ExitCode() == 3 and summary.model_revision == 0, (
        "Changed policy revision reused an expired policy snapshot for canonical Save."
    )
    assert len(summary.snapshot.artifacts) == 2, "Actual original executions were discarded."


@pytest.mark.parametrize("stage", ["authorize", "launch", "save"])
@pytest.mark.parametrize("error_type", [OSError, PermissionError])
def test_CurrentPolicyReaderFilesystemFailuresRemainStorageFailures(
    workflow, runner, stage, error_type,
):
    """OS permission/read errors remain distinct from an explicit operator or policy denial."""

    root, target, approval, _ = workflow
    calls = [0]
    failed_call = {"authorize": 2, "launch": 3, "save": 4}[stage]

    def ReadPolicy():
        """Return actual typed policy or fail at the selected fresh authority-read seam."""

        calls[0] += 1

        if calls[0] == failed_call:
            raise error_type("synthetic-current-policy-read-failure")

        return Policy()

    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", ReadPolicy,
                                         confirmation=approval))
    assert summary.ExitCode() == 4 and summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "Filesystem access failure was mislabeled as explicit authorization denial."
    )
    assert summary.model_revision == 0, "Failed authority reads permitted canonical Save."
