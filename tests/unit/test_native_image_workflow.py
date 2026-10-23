# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic native product configuration, original evidence and durable-truth boundaries."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_image_workflow as product
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.jobs import JobArtifact, JobSnapshot, JobSpec, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_image_capture import NativeFileFact, NativeTrivySelection
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.unit.test_native_image_policy import AT
from tests.unit.test_native_image_policy import authority as authority
from tests.unit.test_native_image_policy import collector as collector
from tests.unit.test_native_image_policy import material_control as material_control
from tests.unit.test_native_image_policy import observation_runner as observation_runner
from tests.unit.test_native_image_policy import simulated_observer as simulated_observer


@pytest.fixture(scope="module")
def native_image_runner():
    """Initialize portable loop resources before the unchanged per-test network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def owned(tmp_path):
    """Create only explicitly owned tiny material and existing canonical state."""

    root = tmp_path / "workspace"
    workspace = LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned native unit"),
                                                 "owned-native")
    model = LocalModelStore(root).Create()
    (root / "owned.tar").write_bytes(b"inert owned unit material; no image decoder")
    executable = root / "selected-binary"
    executable.write_bytes(b"not an executable; deterministic unit never launches it")
    selection = NativeTrivySelection(root, executable, "owned.tar", "cache",
                                    ArtifactReadConsent("owner:unit", "read:explicit"))
    now = datetime.now(UTC)
    manifest = ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT,
        (ArtifactFile("image.tar", (root / "owned.tar").stat().st_size,
                      hashlib.sha256((root / "owned.tar").read_bytes()).hexdigest()),))
    scope = LocalScopeStore(root).Create(ScopeSnapshot("native-scope", workspace.workspace_id,
        authorization=ScopeAuthorization(AuthorizationState.GRANTED, "attester:independent",
            "consent:unit", (now - timedelta(seconds=10)).isoformat(),
            (now + timedelta(hours=1)).isoformat()), targets=(manifest.Target(),),
        allow=(manifest.Target(),)))
    spec = JobSpec("job:unit", workspace.workspace_id, scope.Reference(),
                   "owner:unit", "native.trivy")
    canonical = LocalEvidenceStore(root / "evidence")
    context = SimpleNamespace(Spec=spec)
    context.CaptureEvidence = lambda data, role, media, provenance: JobArtifact(
        spec.job_id, spec.workspace_id, canonical.Put(data, role, media, provenance))
    provenance = EvidenceProvenance(workspace.workspace_id, scope.Reference(), "native.trivy",
                                    "1", None, now.isoformat(), now.isoformat())
    return SimpleNamespace(root=root, workspace=workspace, model=model, selection=selection,
                           scope=scope, context=context, canonical=canonical, provenance=provenance)


@pytest.mark.parametrize("timeout", [0, 3601, True, None, 1.5, "30"])
def test_InvalidNativeLimitsRefuseBeforeMaterialRead(owned, timeout):
    """Invalid limits do not become a reader or execution permission."""

    with pytest.raises(ValueError, match="exact selections"):
        product.ValidateSelection(owned.root, "owner:unit", owned.selection, timeout)


@pytest.mark.parametrize("timeout", [1, 3600])
def test_ExistingNativeAdapterLimitEndpointsRemainAccepted(owned, timeout):
    """The new native workflow preserves the existing native deadline interval."""

    product.ValidateSelection(owned.root, "owner:unit", owned.selection, timeout)


def test_ExecutingOwnerIsReadActorAndScopeAttesterIsIndependent(owned):
    """Scope provenance is fully retained without requiring the attester to execute the scan."""

    product.ValidateSelection(owned.root, "owner:unit", owned.selection, 30)
    context = product.CurrentContext(owned.root, "native-scope", "owner:unit",
                                     lambda: ImpactPolicy("operator"))
    assert context.scope.authorization.authority_reference == "attester:independent", (
        "The consent attester must not be silently replaced by the executing actor."
    )
    with pytest.raises(ValueError, match="exact selections"):
        product.ValidateSelection(owned.root, "other:actor", owned.selection, 30)
    with pytest.raises(ValueError, match="typed policy"):
        product.CurrentContext(owned.root, "native-scope", "owner:unit", lambda: None)


@pytest.mark.parametrize("scope,policy", [("native-scope", None), (None, lambda: None)])
def test_AmbiguousPreviewAuthorityRefusesBeforeObservation(owned, native_image_runner,
                                                         monkeypatch, scope, policy):
    """One missing authority argument cannot silently select material preview."""

    calls = []
    monkeypatch.setattr(product, "NativeImageMaterialObserver", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="scope and policy together"):
        native_image_runner.run(product.PlanNativeImageScan(owned.root, "owner:unit",
            owned.selection, scope_id=scope, policy_provider=policy))
    assert not calls, "Ambiguous planning must refuse before even constructing the reader."


def test_MaterialPreviewReturnsCanonicalTargetWithoutAuthorityOrTrivy(
    owned, native_image_runner, monkeypatch,
):
    """A separate one-observation preview supplies only descriptive manifest registration facts."""

    archive = owned.root / "owned.tar"
    fact = NativeFileFact("archive", str(archive), archive.stat().st_size,
                         hashlib.sha256(archive.read_bytes()).hexdigest(), None)
    observed = []

    class Observer:
        """Supply deterministic nonexecuting material only for the descriptive preview unit."""

        def __init__(self, *args):
            """Record constructor ownership without accessing selected contents."""

            observed.append(args)

        async def Observe(self, budget, **kwargs):
            """Return one deterministic descriptive fact without an engine or authority call."""

            assert budget.ObservationCount == 0, "Planning must use a new separate reader budget."
            observed.append(kwargs)
            return SimpleNamespace(facts=(fact,))

    monkeypatch.setattr(product, "NativeImageMaterialObserver", Observer)
    plan = native_image_runner.run(product.PlanNativeImageScan(owned.root, "owner:unit",
                                                               owned.selection))
    assert plan.input_manifest.Target() == owned.scope.targets[0], (
        "Preview must use the existing canonical IMAGE INPUT manifest target contract."
    )
    assert plan.phase == "material-preview" and plan.version_invocation is None, (
        "Preview must never pretend to contain an executed VERSION or a native grant."
    )
    assert plan.ToDict()["execution_authorized"] is False and len(observed) == 2, (
        "Exactly one descriptive material observation must not manufacture current authority."
    )


@pytest.mark.parametrize("role", tuple(product.NATIVE_ROLES))
def test_BridgePublishesEachClosedRoleWithOriginalCanonicalIdentity(owned, role):
    """Exact original bytes and provenance pass through the canonical job/store once."""

    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    media = product.NATIVE_ROLES[role][1]
    record = bridge.Put(b"owned original", role, media, owned.provenance)
    assert record == owned.canonical.Get(record.evidence_id), (
        "Job attachment must retain the exact unchanged content-addressed original manifest."
    )
    assert tuple(bridge.records.values()) == (record,), (
        "Only independently confirmed originals belong."
    )
    assert not bridge.publication_uncertain, (
        "Acknowledged original publication must remain confirmed."
    )


@pytest.mark.parametrize("phase", ["before", "after"])
def test_PublicationExceptionRetainsOnlyIndependentlyConfirmedAcquisition(owned, phase):
    """Lost acknowledgement remains a failure even when exact canonical readback finds its bytes."""

    def Publish(data, role, media, provenance):
        """Model real storage refusal on either side of the original canonical Put."""

        if phase == "after":
            owned.canonical.Put(data, role, media, provenance)
        raise OSError("owned-publication-failure")

    owned.context.CaptureEvidence = Publish
    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    with pytest.raises(OSError, match="owned-publication-failure"):
        bridge.Put(b"original", "stdout", "application/json", owned.provenance)
    assert bridge.publication_uncertain and bool(bridge.records) is (phase == "after"), (
        "Only exact independently recovered acquisitions survive, without turning failure into ack."
    )


@pytest.mark.parametrize("mutation", ["role", "media", "size", "scope", "source"])
def test_BridgeRejectsChangedRoleAndProvenanceBeforePut(owned, mutation):
    """A closed acquisition bridge cannot capture another source, scope or arbitrary role."""

    role, media, data, provenance = "stdout", "application/json", b"owned", owned.provenance
    if mutation == "role":
        role = "arbitrary-role"
    elif mutation == "media":
        media = "text/plain"
    elif mutation == "size":
        data = b"x" * (4 * 1024 * 1024 + 1)
    elif mutation == "scope":
        provenance = replace(provenance, scope_reference="scope:other")
    else:
        provenance = replace(provenance, source_id="synthetic.trivy")
    calls = []
    owned.context.CaptureEvidence = lambda *args: calls.append(args)
    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    with pytest.raises(ValueError, match="provenance differs"):
        bridge.Put(data, role, media, provenance)
    assert not calls and not bridge.records, "Rejected source facts must never reach generic Put."


def test_InheritedGetChecksActualManifestRoleBeforeEagerRead(owned, monkeypatch):
    """A same-store unexpected manifest must be refused before allocating its blob."""

    record = owned.canonical.Put(b"owned", "unrelated", "text/plain", owned.provenance)
    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    reads = []
    monkeypatch.setattr(LocalEvidenceStore, "Read", lambda *args: reads.append(args))
    with pytest.raises(ValueError, match="closed role bounds"):
        bridge.Get(record.evidence_id)
    assert not reads, "Closed role preflight must run before the evidence owner's eager raw read."


def test_FailedReferenceCleanupSavesAcquisitionsOnceUsingOriginalWorkspaceCas(owned):
    """Confirmed originals survive failure without retrying an original workspace save."""

    snapshot = JobSnapshot(owned.context.Spec, JobState.RUNNING, 0, None, None, (), False)
    workflow = product.NativeImageWorkflow(owned.root, "native-scope", "owner:unit",
        owned.selection, lambda: ImpactPolicy("operator"), 30, owned.workspace, owned.model,
        lambda: snapshot, lambda: datetime.now(UTC))
    workflow.bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    record = workflow.bridge.Put(b"original", "stdout", "application/json", owned.provenance)
    workflow.PersistReferences(owned.context)
    first = LocalWorkspaceStore(owned.root).Open()
    workflow.PersistReferences(owned.context)
    assert LocalWorkspaceStore(owned.root).Open() == first, (
        "Success/finally cleanup must share one workspace save attempt, without stale retry."
    )
    assert record.evidence_id in first.evidence_record_references, (
        "Confirmed failed acquisition must remain reopenable through its exact original ID."
    )


def test_PairedSdkUsesCanonicalAuthorityCustodyAndModelWithControlledWire(authority):
    """Controlled wire exercises canonical owners without claiming genuine engine acceptance."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    preview = selected.run(product.PlanNativeImageScan(authority.root, "actor:unit",
                                                      selected.selection, clock=lambda: AT))
    assert preview.phase == "material-preview" and not selected.state.calls, (
        "Preview must start no selected provider and supply no native execution claim."
    )
    plan = selected.run(product.PlanNativeImageScan(authority.root, "actor:unit",
        selected.selection, scope_id="native-unit",
        policy_provider=lambda: authority.context.policy, clock=lambda: AT))
    assert plan.phase == "scoped-version-plan" and (
        plan.version_invocation.provider_version is None
    ), (
        "Scoped planning must retain the unknown-version original VERSION invocation."
    )
    assert not selected.state.calls, "Neither planning phase may launch the selected engine."
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    assert summary.snapshot.state is JobState.COMPLETED, summary.ToDict()
    assert len(summary.captures) == 2 and len(summary.retained_records) == 6, (
        "The paired product job must retain each original VERSION and SCAN role exactly once."
    )
    assert summary.captures[1].version_prerequisite_sha256 == summary.captures[0].Digest(), (
        "The product must bind the actual original VERSION, not a reconstructed prerequisite."
    )
    assert summary.model_revision == 1 and summary.first_model_update_seconds is not None, (
        "The original model CAS and workspace acknowledgement must precede the model event."
    )
    assert summary.ToDict()["workflow"] == "native-image" and summary.ExitCode() == 0, (
        "Native results must retain their own workflow identity rather than synthetic summary wire."
    )


@pytest.mark.parametrize("failure", ["failed", "unknown", "post-observation"])
def test_FailedOriginalVersionRetainsAvailableCustodyAndNeverStartsScan(authority, failure):
    """Version failure and unknown cleanup cannot produce a successful canonical empty scan."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    if failure == "post-observation":
        selected.state.after = lambda: setattr(selected.wire, "mode", "timeout")
    else:
        selected.state.mode = failure
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    assert summary.snapshot.state is JobState.FAILED and summary.ExitCode() == 4, (
        "An actual refused original operation must remain a failed unassessed product result."
    )
    assert len(selected.state.calls) == 1 and summary.model_revision == 0, (
        "No failed or unverified VERSION may start SCAN or change canonical inventory."
    )
    expected = 0 if failure == "unknown" else 3
    assert len(summary.retained_records) == expected, (
        "Only complete independently confirmed original acquisitions may be retained as records."
    )
    workspace = LocalWorkspaceStore(authority.root).Open()
    assert {record.evidence_id for record in summary.retained_records} <= set(
        workspace.evidence_record_references), (
        "Every confirmed failed acquisition must be referenced."
    )
    assert not any(event.kind.value == "model_delta" for event in summary.events), (
        "A failed native operation cannot publish a successful model transition."
    )


def test_MissingExplicitNativeApprovalRefusesBeforeReaderOrGrant(authority):
    """Independent file-read consent must never supply native workflow approval."""

    before = len(authority.collector.wire.calls)
    with pytest.raises(product.ArtifactDeniedError):
        authority.collector.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
            authority.collector.selection, lambda: authority.context.policy, clock=lambda: AT))
    assert len(authority.collector.wire.calls) == before and not authority.collector.state.calls, (
        "Missing native approval must refuse before another material reader or selected operation."
    )


def test_CurrentPolicyDenialDoesNotBecomePreviewOrSuccessfulEmptyInventory(authority):
    """A current native permission remains separate from explicit workflow and read approval."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    with pytest.raises(product.ArtifactDeniedError):
        selected.run(product.PlanNativeImageScan(authority.root, "actor:unit", selected.selection,
            scope_id="native-unit", policy_provider=lambda: ImpactPolicy("denied"),
            clock=lambda: AT))
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: ImpactPolicy("denied"), approve_safe_image=True,
        clock=lambda: AT))
    assert summary.ExitCode() == 3 and summary.model_revision == 0, (
        "Current native denial must remain authorization failure with unchanged canonical state."
    )
    assert not selected.state.calls, "Current policy denial must start no selected Trivy operation."


@pytest.mark.parametrize("boundary", ["model-before", "model-after", "workspace-after"])
def test_DurableSaveFailuresKeepActualRevisionAndDoNotRetryOriginalCas(
    authority, monkeypatch, boundary,
):
    """Lost acknowledgements preserve original acquisitions and actual committed model truth."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    original_model_save = LocalModelStore.Save
    original_workspace_save = LocalWorkspaceStore.Save
    calls = []

    def ModelSave(store, state, *, expected_revision):
        """Fail on either side of the one actual model CAS, without rebasing or rollback."""

        calls.append("model")
        if boundary == "model-before":
            raise OSError("owned-model-save-before")
        saved = original_model_save(store, state, expected_revision=expected_revision)
        if boundary == "model-after":
            raise OSError("owned-model-save-after")
        return saved

    def WorkspaceSave(store, state):
        """Fail only after one complete workspace commit and preserve its real revision."""

        calls.append("workspace")
        saved = original_workspace_save(store, state)
        if boundary == "workspace-after":
            raise OSError("owned-workspace-save-after")
        return saved

    monkeypatch.setattr(LocalModelStore, "Save", ModelSave)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", WorkspaceSave)
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    expected = 0 if boundary == "model-before" else 1
    assert summary.snapshot.state is JobState.FAILED and summary.model_revision == expected, (
        "Storage refusal must expose the actual committed revision, not a fabricated rollback."
    )
    assert calls.count("model") == calls.count("workspace") == 1, (
        "Model and workspace writes must each be attempted once without blind retry."
    )
    assert len(summary.retained_records) == 6 and not summary.first_model_update_seconds, (
        "Failed durable acknowledgement must retain all originals without a successful model event."
    )



def test_CallerCancellationWaitsForOwnedWireAndRetainsOriginalAcquisitions(authority):
    """Caller cancellation is a measured terminal job only after cooperative owned completion."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    selected.state.mode = "pending"

    async def Cancel():
        """Cancel only the explicit owned SDK task after its selected wire reaches readiness."""

        task = asyncio.create_task(product.ScanNativeImage(
            authority.root, "native-unit", "actor:unit", selected.selection,
            lambda: authority.context.policy, approve_safe_image=True,
            clock=lambda: AT))
        await selected.state.started.wait()
        task.cancel()
        return await task

    summary = selected.run(Cancel())
    assert selected.state.cleanup and summary.snapshot.state is JobState.CANCELLED, (
        "The native SDK must wait for its owned operation cleanup before returning cancellation."
    )
    assert summary.ExitCode() == 130 and summary.model_revision == 0, (
        "Cancellation must not be presented as an empty completed inventory."
    )
    assert len(summary.retained_records) == 3 and len(selected.state.calls) == 1, (
        "Cancelled VERSION originals remain available while SCAN never starts."
    )


def test_OriginalPairSupportsSeparateAcknowledgedReportExport(authority):
    """The native SDK reuses existing report owners over the acknowledged durable model."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    output = authority.root.parent / "native-report.json"
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT, report_format="json", report_output=output))
    assert summary.snapshot.state is JobState.COMPLETED and summary.report.status == "completed", (
        "Only the completed durable native pair may supply the separately exported report."
    )
    assert output.is_file() and summary.ExitCode() == 0, (
        "The explicit new report must be published."
    )


def test_ReportFailureDoesNotRewriteCompletedNativeExecution(authority, monkeypatch):
    """A separate report failure retains actual completed scan and confirmed publication truth."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    monkeypatch.setattr(product, "ExportImageReport", lambda *args:
        product.ImageReportOutcome("failed", "json", output_published=True, failure="publication"))
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT, report_format="json", report_output=authority.root.parent / "owned.json"))
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 4, (
        "Separate export failure must not rewrite original completed scan execution facts."
    )
    assert summary.report.output_published and len(summary.captures) == 2, (
        "Confirmed report publication and both actual original captures must remain factual."
    )


def test_RevokedAuthorityAfterVersionRetainsOriginalsAndRefusesScan(authority):
    """A fresh changed scope after acquisition cannot authorize a follow-on selected operation."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()

    def Revoke():
        """Revoke only the current registered test-owned scope after original VERSION runs."""

        store = LocalScopeStore(authority.root)
        current = store.Open("native-unit")
        store.Save(replace(current, authorization=replace(current.authorization,
            state=AuthorizationState.REVOKED)))

    selected.state.after = Revoke
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    assert summary.ExitCode() == 3 and len(selected.state.calls) == 1, (
        "Fresh post-run revocation must remain authorization refusal and stop before SCAN."
    )
    assert len(summary.retained_records) == 3 and summary.model_revision == 0, (
        "Revocation cannot erase acquired exact originals or create successful inventory."
    )


def test_BridgeWrongJobAttachmentRemainsFailureWithVerifiedAcquisition(owned):
    """A same-workspace wrong-job acknowledgement is rejected without hiding an exact original."""

    owned.context.CaptureEvidence = lambda data, role, media, provenance: JobArtifact(
        "job:substituted", owned.context.Spec.workspace_id,
        owned.canonical.Put(data, role, media, provenance))
    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    with pytest.raises(product.EvidenceError, match="attachment differs"):
        bridge.Put(b"original", "stdout", "application/json", owned.provenance)
    assert bridge.publication_uncertain and len(bridge.records) == 1, (
        "Wrong job acknowledgement must fail while independently confirmed original survives."
    )


@pytest.mark.parametrize("media,size", [("text/plain", 1), ("application/json", 4 * 1024**2 + 1)])
def test_BridgeReadRejectsOversizeOrWrongMediaBeforeGenericAllocation(
    owned, monkeypatch, media, size,
):
    """Bounded recovery uses actual role/media ceilings before the generic reader."""

    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    calls = []
    monkeypatch.setattr(LocalEvidenceStore, "Read", lambda *args: calls.append(args))
    reference = EvidenceReference("stdout", "blobs/sha256/" + "a" * 64, "a" * 64, media, size)
    with pytest.raises(ValueError, match="closed role bounds"):
        bridge.Read(reference)
    assert not calls, "Closed media/size refusal must precede eager generic reads."


@pytest.mark.parametrize("boundary", ["model", "workspace"])
def test_FreshAuthorityImmediatelyBeforeEachSuccessfulSaveKeepsFailureAcquisitions(
    authority, monkeypatch, boundary,
):
    """Final revocation refuses success while reference cleanup retains actual committed truth."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()
    normalize = product.ApplyVerifiedNativeTrivyImages
    save_model = LocalModelStore.Save
    save_workspace = LocalWorkspaceStore.Save
    writes = []

    def Revoke():
        """Change the exact current attested scope after the selected successful pair."""

        store = LocalScopeStore(authority.root)
        scope = store.Open("native-unit")
        store.Save(replace(scope, authorization=replace(scope.authorization,
            state=AuthorizationState.REVOKED)))

    def Normalize(*args):
        """Revoke after exact original admission but before the first successful model write."""

        proposal = normalize(*args)
        if boundary == "model":
            Revoke()
        return proposal

    def SaveModel(store, state, *, expected_revision):
        """Revoke only after the already acknowledged model if workspace is the chosen boundary."""

        writes.append("model")
        saved = save_model(store, state, expected_revision=expected_revision)
        if boundary == "workspace":
            Revoke()
        return saved

    def SaveWorkspace(store, state):
        """Count only an actual original-revision write, including acquisition-only finalization."""

        writes.append("workspace")
        return save_workspace(store, state)

    monkeypatch.setattr(product, "ApplyVerifiedNativeTrivyImages", Normalize)
    monkeypatch.setattr(LocalModelStore, "Save", SaveModel)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", SaveWorkspace)
    summary = selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
        selected.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    assert summary.ExitCode() == 3 and summary.snapshot.state is JobState.FAILED, (
        "Fresh revocation at either successful write barrier must refuse native completion."
    )
    assert summary.model_revision == int(boundary == "workspace"), (
        "A model already committed before revocation must not be hidden or rolled back."
    )
    assert writes.count("model") == int(boundary == "workspace"), (
        "No successful model CAS may occur after the current original grant is refused."
    )
    assert writes.count("workspace") == 1 and summary.first_model_update_seconds is None, (
        "One acquisition-only cleanup write must not publish a successful model delta."
    )
    workspace = LocalWorkspaceStore(authority.root).Open()
    assert {item.evidence_id for item in summary.retained_records} <= set(
        workspace.evidence_record_references), "Revocation cannot erase exact acquired originals."


def test_EventSinkFailureAfterDurableSavesDoesNotEraseCommittedState(authority):
    """A presentation exception propagates after owned cleanup and preserves durable originals."""

    selected = authority.collector
    LocalModelStore(authority.root).Create()

    def Present(event):
        """Fail only when the already acknowledged model transition reaches the original sink."""

        if event.kind is product.JobEventKind.MODEL_DELTA:
            raise RuntimeError("owned-event-sink-failure")

    with pytest.raises(RuntimeError, match="owned-event-sink-failure"):
        selected.run(product.ScanNativeImage(authority.root, "native-unit", "actor:unit",
            selected.selection, lambda: authority.context.policy, approve_safe_image=True,
            clock=lambda: AT, on_event=Present))
    assert LocalModelStore(authority.root).Open().revision == 1, (
        "Presentation failure cannot invent a rollback of the acknowledged original model."
    )
    assert len(LocalWorkspaceStore(authority.root).Open().evidence_record_references) == 6, (
        "Both acknowledged original captures must remain referenced after presentation failure."
    )


def test_BridgeRefusesReplacingAnOriginalRoleBeforeAnotherPublication(owned):
    """A complete native pair has one immutable record per original role, without replacement."""

    bridge = product.NativeJobEvidenceStore(owned.context, owned.canonical.root)
    first = bridge.Put(b"first-original", "stdout", "application/json", owned.provenance)
    calls = []
    owned.context.CaptureEvidence = lambda *args: calls.append(args)
    with pytest.raises(ValueError, match="replace an original"):
        bridge.Put(b"replacement", "stdout", "application/json", owned.provenance)
    assert not calls and tuple(bridge.records.values()) == (first,), (
        "A replacement role must not be published or substituted for the original acquisition."
    )
