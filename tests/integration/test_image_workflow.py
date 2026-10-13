# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual governed synthetic image workflows, native isolation, durable history and exports."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from shutil import copytree, rmtree

import pytest

from fuzzy1337 import image_workflow
from fuzzy1337.adapters import ExecutionState
from fuzzy1337.artifact_policy import ArtifactPolicyEngine, GovernedArtifactExecutor
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import LocalExecutor
from fuzzy1337.findings import (
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    Remediation,
    TransitionFinding,
)
from fuzzy1337.image_workflow import ExportImageReport, RunSyntheticImageScan
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.synthetic_images import (
    ApplyVerifiedSyntheticTrivyImages,
    VerifySyntheticTrivyImageReplay,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConflictError
from tests.image_helpers import ORACLE, CollectOwnedImagePair, CreateOwnedImage


def NativeBaseline(owned):
    """Seed reviewed colliding native assets and a dismissed Finding as owned test data."""

    now = datetime.now(UTC).isoformat()
    scope = owned.context.scope.Reference()
    source = EvidenceProvenance("owned-images", scope, "synthetic.baseline", "1", None, now, now)
    record = LocalEvidenceStore(owned.root / "evidence").Put(
        b"Owned native namespace test seeds; not genuine discovery",
        "baseline", "text/plain", source
    )
    provenance = ModelProvenance(source.source_id, "run:baseline", now, scope,
        owned.context.scope.targets[0].Reference(), evidence_references=(record.reference,))
    oracle = ORACLE["native_namespace_baseline"]
    objects = [SecurityObject(ObjectIdentity("owned-images", ObjectKind.ASSET, seed["natural_key"]),
        seed["attributes"], (provenance,)) for seed in oracle["asset_seeds"]]
    finding = oracle["triaged_finding"]
    subject = next(item.Reference() for item in objects
        if item.identity.key == finding["subject_object_key"])
    native = Finding(subject, finding["check_id"], finding["location_key"], "Owned native baseline",
        (provenance,), severity=FindingSeverity(finding["severity"]),
        confidence=finding["confidence"], status=FindingStatus.DISMISSED,
        status_reason="Owned baseline operator disposition",
        remediation=Remediation(finding["remediation_summary"]))
    objects.append(native.ToObject("owned-images"))
    seed = ModelState("owned-images", 1, tuple(objects))
    LocalModelStore(owned.root).Save(seed, expected_revision=0)
    workspace_store = LocalWorkspaceStore(owned.root)
    workspace_store.Save(replace(workspace_store.Open(), scope_references=(scope,),
        object_references=tuple(item.Reference() for item in objects),
        evidence_references=(record.reference,), evidence_record_references=(record.evidence_id,)))

    return seed


@pytest.mark.parametrize("report_format", ["json", "sarif"])
def test_ActualTwoOperationWorkflowPreservesNativeGraphAndProjectsExactSavedReport(
    tmp_path, report_format
):
    """Real canonical receipts precede durable model/workspace saves and the published delta."""

    owned = CreateOwnedImage(tmp_path)
    seed = NativeBaseline(owned)
    original_bytes = {item.Reference(): CanonicalModelJson(item) for item in seed.objects}
    events = []
    output = tmp_path / ("image-report." + report_format)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, on_event=events.append,
        report_format=report_format, report_output=output))
    saved = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0, (
        "Closed synthetic integration must complete only after both durable saves"
    )
    assert summary.model_revision == saved.revision == seed.revision + 1, (
        "Summary must describe the actually saved atomic model transition"
    )
    assert len(summary.operations) == 2 and summary.operations[0]["operation"] == "version", (
        "Independent observed VERSION must precede SCAN"
    )
    assert set(original_bytes) <= {item.Reference() for item in saved.objects}, (
        "All original native assets and the triaged Finding must remain present"
    )
    assert all(CanonicalModelJson(item) == original_bytes[item.Reference()]
        for item in saved.objects if item.Reference() in original_bytes), (
        "Every entire colliding native asset and operator-triaged Finding must remain byte-exact"
    )
    synthetic = [item for item in saved.Objects(ObjectKind.ASSET)
        if item.identity.key.startswith(ORACLE["synthetic_asset_prefix"])]
    assert {item.identity.key for item in synthetic} == set(
        ORACLE["domain_facts"]["synthetic_asset_keys"].values()
    ), "Actual image/domain identities must match the unchanged independent oracle"
    synthetic_refs = {item.Reference() for item in synthetic}
    assert all({item.source_reference, item.target_reference} <= synthetic_refs
        for item in saved.relations), "No digest/PURL hint may create a synthetic-to-native edge"
    findings = [item for item in Findings(saved) if item.check_id.startswith("synthetic.")]
    assert len(findings) == 1 and findings[0].check_id == "synthetic.supply-chain.vulnerability", (
        "Synthetic detector fingerprints must retain their separate check namespace"
    )
    assert all(len(item.provenance[0].evidence_references) == 6 for item in synthetic), (
        "Every interpretation must retain all six original operation evidence roles"
    )
    assert summary.first_model_update_seconds is not None, "Measure the actual committed delta time"
    delta_events = [item for item in events if item.kind is JobEventKind.MODEL_DELTA]
    assert len(delta_events) == 1 and delta_events[0].data.revision == saved.revision, (
        "Publish only the actual saved atomic model delta"
    )
    assert summary.snapshot.spec.job_id in workspace.job_references, (
        "Persist the owning job reference"
    )
    assert {item.Reference() for item in saved.objects} <= set(workspace.object_references), (
        "Workspace must retain both native and newly saved object references"
    )
    assert len(workspace.evidence_record_references) == 13, (
        "Preserve the prior baseline acquisition"
    )
    assert len(summary.snapshot.artifacts) == 12, (
        "Selected-byte receipts remain separate from the six execution interpretation records"
    )
    report = VerifyReportEvidence(ReportSnapshot(saved), owned.root)
    assert summary.report is not None, "Requested export must return its own outcome"
    assert summary.report.snapshot_sha256 == report.SnapshotDigest(), (
        "Export must project this exact saved snapshot"
    )
    exported = json.loads(output.read_bytes())

    if report_format == "json":
        assert exported["model"] == saved.ToDict(), (
            "Only embedded model uses the canonical model wire"
        )
        assert exported["scan_completeness"] == "not-assessed", (
            "Inventory cannot imply a clean scan"
        )

    else:
        run = exported["runs"][0]
        assert len(run["results"]) == 1, "SARIF should show the active synthetic Finding only"
        assert all("physicalLocation" not in item
            for item in run["results"][0].get("locations", [])), (
            "Retain canonical logical subjects without inventing original physical locations"
        )

    rendered = json.dumps(summary.ToDict(), sort_keys=True)
    assert "synthetic.trivy" in rendered and "not-assessed" in rendered, (
        "Summary must retain synthetic source and explicit unassessed completeness"
    )


@pytest.mark.parametrize("scenario,code", [
    ("no_findings", None), ("provider_error", JobFailureCode.PROVIDER),
    ("malformed", JobFailureCode.NORMALIZATION),
    ("version_mismatch", JobFailureCode.NORMALIZATION),
    ("package_mismatch", JobFailureCode.NORMALIZATION),
    ("output_limit", JobFailureCode.OUTPUT_LIMIT), ("hold", JobFailureCode.TIMEOUT),
])
def test_ActualIndependentScenarioOracleRetainsRawFailureTruth(tmp_path, scenario, code):
    """The unchanged reviewed worker executes through actual SDK operations and bounded failures."""

    owned = CreateOwnedImage(tmp_path, scenario)
    original = LocalModelStore(owned.root).Open()
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, timeout_seconds=1))
    saved = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    assert len(summary.operations) == 2, "Failure cannot erase the actual VERSION and SCAN outcomes"
    assert len(summary.snapshot.artifacts) == len(workspace.evidence_record_references) == 12, (
        "Retain raw and selected-byte acquisitions after owned process cleanup"
    )
    store = LocalEvidenceStore(owned.root / "evidence")
    roles = {"provider-version", "provider-version-stderr", "stdout", "stderr",
        "artifact-version-receipt", "artifact-scan-receipt"}
    records = tuple(item.evidence for item in summary.snapshot.artifacts
        if item.evidence.reference.role in roles)
    replay = VerifySyntheticTrivyImageReplay(records, owned.root)
    refusal = None if replay.scan_acceptance.refusal is None else (
        replay.scan_acceptance.refusal.value)
    assert replay.provenance.execution == summary.operations[-1]["execution"] and (
        refusal == summary.operations[-1]["acceptance_refusal"]
    ), "Historical replay must retain actual failed or refused SCAN facts without model authority"
    assert all(store.Get(record.evidence_id) == record for record in replay.records), (
        "Historical facts must retain the same original immutable owning acquisitions"
    )

    if code is None:
        assert summary.snapshot.state is JobState.COMPLETED and not Findings(saved), (
            "no_findings is successful inventory with zero vulnerability proposals"
        )
        assert summary.ToDict()["scan_completeness"] == "not-assessed", (
            "Zero Findings cannot claim complete or clean detection"
        )

    else:
        assert summary.snapshot.state is JobState.FAILED, "Rejected image job must fail"
        assert summary.snapshot.failure.code is code, (
            "Actual process and interpretation failure classification must remain truthful"
        )
        assert saved == original and summary.first_model_update_seconds is None, (
            "Rejected runs cannot mutate the prior model or publish a successful delta"
        )
        assert not any(item.kind is JobEventKind.MODEL_DELTA for item in summary.events), (
            "No model delta may be fabricated after refusal"
        )
        assert summary.ExitCode() != 0, "Rejected scanner output cannot produce successful exit"


def test_TypedLiveImportAndHistoricalRelocationPreserveTriageWithoutAuthority(
    tmp_path, monkeypatch
):
    """Historical verification reads original facts after the old physical stages disappear."""

    owned = CreateOwnedImage(tmp_path)
    original = NativeBaseline(owned)
    proof, scan, records = asyncio.run(CollectOwnedImagePair(owned))
    proposal, delta = ApplyVerifiedSyntheticTrivyImages(original, proof, scan.outcome,
        scan.prepared, scan.stage, records, owned.root, context_provider=lambda: owned.context)
    saved = LocalModelStore(owned.root).Save(proposal, expected_revision=original.revision)
    finding = next(item for item in Findings(saved) if item.check_id.startswith("synthetic."))
    triaged, _ = TransitionFinding(saved, finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED,
        replace(finding.provenance[0], source_id="operator.test", run_reference="run:owned-triage",
            provider_version=None, execution=None,
            observed_at=datetime.now(UTC).isoformat()), "Owned synthetic operator dismissal")
    LocalModelStore(owned.root).Save(triaged, expected_revision=saved.revision)
    later_proof, later_scan, later_records = asyncio.run(CollectOwnedImagePair(owned))
    redetected, _ = ApplyVerifiedSyntheticTrivyImages(triaged, later_proof, later_scan.outcome,
        later_scan.prepared, later_scan.stage, later_records, owned.root,
        context_provider=lambda: owned.context)
    LocalModelStore(owned.root).Save(redetected, expected_revision=triaged.revision)
    latest = next(item for item in Findings(redetected) if item.check_id.startswith("synthetic."))
    assert latest.status is FindingStatus.DISMISSED and latest.status_reason == (
        "Owned synthetic operator dismissal"
    ), "A later genuine governed synthetic collection cannot reopen operator disposition"
    explicitly_open, _ = TransitionFinding(redetected, latest.ToObject("owned-images").Reference(),
        FindingStatus.OPEN, replace(latest.provenance[0], source_id="operator.test",
            run_reference="run:explicit-reopen", provider_version=None, execution=None,
            observed_at=datetime.now(UTC).isoformat()), "Explicit owned test reopen")
    assert next(item for item in Findings(explicitly_open) if item.check_id.startswith(
        "synthetic."
    )).status is FindingStatus.OPEN, "Only explicit operator transition may reopen disposition"
    triaged = redetected
    original_bytes = CanonicalModelJson(triaged.ToDict())
    provenance = VerifySyntheticTrivyImageReplay(records, owned.root).provenance
    assert provenance == finding.provenance[0], "Replay must return the exact original attribution"
    assert delta.revision == saved.revision, "Live import proposes the actual atomic transition"
    for stage_root in (proof.stage.root, scan.stage.root):
        stage_root.chmod(0o700)

        for path in stage_root.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)

        rmtree(stage_root)
        assert not stage_root.exists(), "Original test-owned stage must be physically removed"

    relocated = tmp_path / "relocated image workspace"
    copytree(owned.root, relocated)

    def Forbidden(*arguments, **options):
        """Fail immediately if read-only historical verification crosses any live boundary."""

        raise AssertionError("Historical verification attempted live authority or persistence")

    monkeypatch.setattr(ArtifactPolicyEngine, "Authorize", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Save", Forbidden)
    assert VerifySyntheticTrivyImageReplay(records, relocated).provenance == provenance, (
        "Relocation must preserve original receipt paths/digests without reading current stages"
    )
    assert CanonicalModelJson(LocalModelStore(relocated).Open().ToDict()) == original_bytes, (
        "Historical verification cannot reopen triage or add model history"
    )


def test_ExplicitCapabilityOptInAndCurrentOwnerAreRequiredBeforeAnyProcess(tmp_path):
    """Read consent alone cannot grant image execution, and another owner never inherits a grant."""

    owned = CreateOwnedImage(tmp_path)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection))
    assert summary.ExitCode() == 3 and not summary.operations, (
        "Missing opt-in must deny before launch"
    )
    assert LocalModelStore(owned.root).Open().revision == 0, "Denial cannot fabricate model state"
    other = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:other",
        owned.selection, approve_safe_image=True))
    assert other.ExitCode() == 3 and not other.operations, (
        "Current owner must match recorded authority"
    )


def test_RevokedVersionAcceptancePreventsAnyScanGrantAndRetainsRawVersion(tmp_path, monkeypatch):
    """Induce actual scope revocation after VERSION cleanup at the canonical acceptance boundary."""

    owned = CreateOwnedImage(tmp_path)
    original = GovernedArtifactExecutor.ValidateAcceptanceFresh

    def Revoke(self, outcome, prepared, stage, context_provider):
        """Change the actual persisted scope before the canonical fresh acceptance check."""

        store = LocalScopeStore(owned.root)
        current = store.Open("image-scope")
        store.Save(replace(current, authorization=replace(current.authorization,
            state=AuthorizationState.REVOKED)))

        return original(self, outcome, prepared, stage, context_provider)

    monkeypatch.setattr(GovernedArtifactExecutor, "ValidateAcceptanceFresh", Revoke)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True))
    assert summary.ExitCode() == 3 and len(summary.operations) == 1, (
        "Revocation after actual VERSION must prevent SCAN issuance rather than erase raw truth"
    )
    assert summary.operations[0]["operation"] == "version", "The only actual run remains VERSION"
    assert LocalModelStore(owned.root).Open().revision == 0, (
        "Refused version cannot enter the model"
    )


@pytest.mark.parametrize("storage_error", [PermissionError, OSError])
@pytest.mark.parametrize("failure_at", [
    "initial", "launch", "post-run", "final-import", "final-save",
])
def test_ActualScopeReaderStorageFailuresRetainOriginalProcessAndSavedStateTruth(
    tmp_path, monkeypatch, storage_error, failure_at
):
    """Fail one actual scope read without replacing canonical processes, grants or acceptance."""

    owned = CreateOwnedImage(tmp_path)
    initial = LocalModelStore(owned.root).Open()
    original_open = LocalScopeStore.Open
    original_execute = LocalExecutor.Execute
    original_pair = GovernedArtifactExecutor.ValidatePairAcceptanceFresh
    private_detail = "Owned private scope path must not reach diagnostics"
    scope_error = storage_error(13 if storage_error is PermissionError else 5, private_detail)
    assert type(scope_error) is storage_error, "Both parameter rows must exercise distinct OS types"
    armed = False
    fired = False
    scope_reads = 0
    pair_calls = 0

    def Open(self, scope_id):
        """Fail one selected physical read while permitting preflight and durable references."""

        nonlocal armed, fired, scope_reads
        scope_reads += 1

        if failure_at == "initial" and scope_reads == 2:
            armed = True

        if armed and not fired:
            armed = False
            fired = True

            raise scope_error

        return original_open(self, scope_id)

    async def Execute(self, request, *, on_event=None, cancellation=None, pre_launch=None):
        """Arm storage failure around the actual canonical launch or completed raw result."""

        nonlocal armed

        def BeforeLaunch(actual):
            """Fail the real SDK context lookup immediately before process launch."""

            nonlocal armed
            assert pre_launch is not None, "Governed image launches must retain the SDK callback"

            if failure_at == "launch" and not fired:
                armed = True

            return pre_launch(actual)

        result = await original_execute(self, request, on_event=on_event,
            cancellation=cancellation, pre_launch=BeforeLaunch)

        if failure_at == "post-run" and not fired:
            armed = True

        return result

    def ValidatePair(self, version, scan, context_provider):
        """Fail the final context refresh only after both canonical physical validations."""

        nonlocal pair_calls
        pair_calls += 1
        current_reads = 0
        selected_pair = 1 if failure_at == "final-import" else 2

        def CurrentContext():
            """Read actual scope and fail the after-hashing refresh for the selected pair."""

            nonlocal armed, current_reads
            current_reads += 1

            if failure_at in {"final-import", "final-save"} and (
                pair_calls == selected_pair and current_reads == 3
            ):
                armed = True

            return context_provider()

        return original_pair(self, version, scan, CurrentContext)

    monkeypatch.setattr(LocalScopeStore, "Open", Open)
    monkeypatch.setattr(LocalExecutor, "Execute", Execute)
    monkeypatch.setattr(GovernedArtifactExecutor, "ValidatePairAcceptanceFresh", ValidatePair)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True))
    workspace = LocalWorkspaceStore(owned.root).Open()
    expected_operations = 2 if failure_at.startswith("final-") else int(failure_at == "post-run")
    expected_acquisitions = 12 if failure_at.startswith("final-") else {
        "initial": 0, "launch": 3, "post-run": 6,
    }[failure_at]
    assert fired, "Every parameter must exercise its actual one-shot scope-reader failure"
    assert summary.snapshot.state is JobState.FAILED and (
        summary.snapshot.failure.code is JobFailureCode.STORAGE and summary.ExitCode() == 4
    ), "Physical scope storage failures must remain separate from policy and owner denial"
    assert summary.model_revision == 0 and LocalModelStore(owned.root).Open() == initial, (
        "A failed current-context read cannot commit a proposed model transition"
    )
    assert summary.first_model_update_seconds is None and not any(
        item.kind is JobEventKind.MODEL_DELTA for item in summary.events
    ), "Neither acceptance barrier may publish an uncommitted model delta"
    assert len(summary.operations) == expected_operations, (
        "A storage refusal cannot fabricate a launch or erase an already completed operation"
    )
    assert len(summary.snapshot.artifacts) == len(workspace.evidence_record_references) == (
        expected_acquisitions
    ), "A later storage refusal must retain every actual selected-byte and process acquisition"
    assert summary.snapshot.spec.job_id in workspace.job_references, (
        "Recovered storage must persist the owning job reference even after a failed current read"
    )
    store = LocalEvidenceStore(owned.root / "evidence")
    assert all(store.Get(item.evidence.evidence_id) == item.evidence
        for item in summary.snapshot.artifacts), (
        "Retained workspace acquisitions must resolve to the original immutable owner records"
    )
    assert all(item["execution"].state is ExecutionState.SUCCEEDED and (
        item["execution"].exit_code == 0 and item["termination"] == "process_exit"
    ) for item in summary.operations), "Scope storage errors cannot rewrite successful raw exits"
    assert all(item["acceptance_refusal"] == (
        "storage" if failure_at == "post-run" else None
    ) for item in summary.operations), (
        "Preserve the original SDK receipt refusal without changing earlier successful receipts"
    )
    assert private_detail not in json.dumps(summary.ToDict(), sort_keys=True), (
        "Machine diagnostics must not reflect the failing physical scope path or OS exception"
    )


@pytest.mark.parametrize("failure", [
    "conflict", "permission", "after-save", "after-save-permission",
])
def test_ModelSaveFailuresRetainRawTruthAndActualCommittedRevision(tmp_path, monkeypatch,
                                                                  failure):
    """Inject failure around real model CAS publication without fabricating successful jobs."""

    owned = CreateOwnedImage(tmp_path)
    original = LocalModelStore.Save
    acknowledged = failure.startswith("after-save")

    def Fail(self, proposal, *, expected_revision):
        """Exercise a rejected CAS or a lost acknowledgement of an actual canonical save."""

        assert expected_revision == 0, "Workflow must retain the original model revision"

        if acknowledged:
            original(self, proposal, expected_revision=expected_revision)

            if failure.endswith("permission"):
                raise PermissionError(13, "Owned injected post-save storage permission failure")

            raise OSError("Owned injected post-save acknowledgement failure")

        if failure == "permission":
            raise PermissionError(13, "Owned injected model storage permission failure")

        raise WorkspaceConflictError("Owned injected model CAS conflict")

    monkeypatch.setattr(LocalModelStore, "Save", Fail)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, report_format="json",
        report_output=tmp_path / "not-exported.json"))
    assert summary.snapshot.failure.code is JobFailureCode.STORAGE and summary.ExitCode() == 4, (
        "Actual storage failure must remain separate from both completed process outcomes"
    )
    assert summary.model_revision == int(acknowledged), (
        "Reopen and report the actual saved revision"
    )
    assert len(summary.operations) == 2 and len(summary.snapshot.artifacts) == 12, (
        "Storage failure cannot erase completed process facts or original raw evidence"
    )
    assert not any(item.kind is JobEventKind.MODEL_DELTA for item in summary.events), (
        "A failed durable workflow cannot publish a successful model delta"
    )
    assert summary.report.status == "not-run" and not (tmp_path / "not-exported.json").exists(), (
        "Requested export must have an explicit separate not-run outcome"
    )


def test_WorkspaceSaveFailureRetainsAlreadySavedModelAndRawJobArtifacts(tmp_path, monkeypatch):
    """A post-model workspace failure remains failed storage with the saved model visibly intact."""

    owned = CreateOwnedImage(tmp_path)

    def Fail(*arguments, **options):
        """Induce canonical workspace publication failure after actual model persistence."""

        raise OSError("Owned injected workspace publication failure")

    monkeypatch.setattr(LocalWorkspaceStore, "Save", Fail)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True))
    assert summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "Workspace failure stays explicit"
    )
    assert summary.model_revision == 1 and LocalModelStore(owned.root).Open().revision == 1, (
        "Already committed model facts must remain visible when workspace publication fails"
    )
    assert len(summary.snapshot.artifacts) == 12, "Raw acquisitions survive workspace write failure"
    assert summary.first_model_update_seconds is None, (
        "Successful delta cannot precede workspace save"
    )


@pytest.mark.parametrize("published", [False, True])
def test_ReportFailureKeepsCompletedScanAndConfirmedPublicationTruth(
    tmp_path, monkeypatch, published
):
    """Fail requested output around real complete publication without changing scan facts."""

    owned = CreateOwnedImage(tmp_path)
    original = image_workflow.PublishReport
    output = tmp_path / "report.json"

    def Fail(destination, payload):
        """Induce an explicit existing-exporter failure around its actual atomic publication."""

        if published:
            original(destination, payload)

        raise ReportFailure("publication", published=published)

    monkeypatch.setattr(image_workflow, "PublishReport", Fail)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, report_format="json", report_output=output))
    assert summary.snapshot.state is JobState.COMPLETED and summary.model_revision == 1, (
        "Independent export failure cannot rewrite actual completed scanner/model/job facts"
    )
    assert summary.ExitCode() == 4 and summary.report.status == "failed", (
        "Requested export failure must still return a nonzero overall command outcome"
    )
    assert summary.report.output_published is published and output.exists() is published, (
        "Do not erase a complete output already atomically published before acknowledgement failure"
    )


def test_ReportRefusesChangedSnapshotAndExistingDestinationWithoutClobbering(tmp_path):
    """Export only the selected saved snapshot into a new explicit output file."""

    owned = CreateOwnedImage(tmp_path)
    initial = LocalModelStore(owned.root).Open()
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"Owned existing document")
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, report_format="json", report_output=existing))
    assert summary.snapshot.state is JobState.COMPLETED, (
        "Existing output cannot change scan outcome"
    )
    assert summary.report.failure == "configuration", (
        "An existing output is an export refusal, not a scan failure"
    )
    assert existing.read_bytes() == b"Owned existing document", (
        "Export cannot clobber an existing file"
    )
    changed = ExportImageReport(owned.root, initial, "json", tmp_path / "changed.json")
    assert changed.failure == "input-changed" and not changed.output_published, (
        "A newer model must not replace the exact selected report projection"
    )


def test_SupportedCallerCancellationWaitsForOwnedProcessCleanupAndRetainsActualResults(tmp_path):
    """Cancel the owned hold scenario after SCAN staging and wait through cooperative cleanup."""

    owned = CreateOwnedImage(tmp_path, "hold")

    async def Run():
        """Request cancellation through the real job workflow once the second phase has started."""

        count = 0

        def Observe(event):
            """Signal supported cancellation after the actual SCAN selected-byte acquisition."""

            nonlocal count

            if event.kind is JobEventKind.ARTIFACT and (
                event.data.evidence.reference.role == "artifact-input-manifest"
            ):
                count += 1

                if count == 2:
                    task.cancel()

        task = asyncio.create_task(RunSyntheticImageScan(
            owned.root, "image-scope", "owner:image-test",
            owned.selection, approve_safe_image=True, timeout_seconds=5, on_event=Observe))

        return await task

    summary = asyncio.run(Run())
    assert summary.snapshot.state is JobState.CANCELLED and summary.ExitCode() == 130, (
        "Cancellation must be terminal only after owned executor cleanup"
    )
    assert summary.model_revision == 0 and summary.first_model_update_seconds is None, (
        "Cancelled raw output cannot produce a successful model interpretation"
    )
    assert len(summary.operations) == 2 and len(summary.snapshot.artifacts) == 12, (
        "Cooperative cancellation retains actual version/scan results and their original receipts"
    )
