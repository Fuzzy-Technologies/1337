# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual configuration execution, durable canonical model, replay and report boundaries."""

from __future__ import annotations

import asyncio
import copy
import json
import shutil
import stat
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from configuration_helpers import CASES, ORACLE, LiveConfiguration

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_policy import ArtifactDeniedError, GovernedArtifactExecutor
from fuzzy1337.configuration_evidence import (
    ApplyVerifiedSyntheticConfiguration,
    VerifySyntheticConfigurationReplay,
)
from fuzzy1337.configuration_workflow import RunSyntheticConfigurationScan
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ObjectKind
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConflictError


@pytest.mark.parametrize("case_id", list(CASES), ids=list(CASES))
@pytest.mark.parametrize("report_format", ["json", "sarif"])
def test_ActualAllFiveCasesPersistExactCoordinatesAndReusableReports(
    tmp_path, case_id, report_format
):
    """Actual SDK/job/save/report composition matches the independent design oracle."""

    root, selection, _ = LiveConfiguration(tmp_path, case_id)
    events = []
    output = tmp_path / ("report." + report_format)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True, on_event=events.append,
        report_format=report_format, report_output=output))
    saved = LocalModelStore(root).Open()
    workspace = LocalWorkspaceStore(root).Open()
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0, (
        "Actual accepted configuration must complete only after durable canonical state saves"
    )
    assert summary.model_revision == saved.revision == 1, "Summary must show the saved revision"
    assert len(summary.captures) == 1 and len(summary.snapshot.artifacts) == 4, (
        "Configuration is one SCAN with four original stream/source/receipt acquisitions"
    )
    assets = saved.Objects(ObjectKind.ASSET)
    assert len(assets) == 1 and assets[0].identity.key.startswith("synthetic:configuration:"), (
        "Configuration subjects must use their own content-addressed synthetic namespace"
    )
    expected = CASES[case_id]["expected_findings"]
    findings = Findings(saved)
    assert len(findings) == len(expected), "Detection counts must match the independent oracle"

    for finding, oracle in zip(findings, expected, strict=True):
        position = json.loads(finding.location_key)
        assert position == {key: oracle[key] for key in (
            "start_line", "end_line", "document_index", "resource_selector")}, (
                "Original line/document/resource coordinates must survive canonical Finding"
            )
        assert finding.check_id == oracle["check_id"] and finding.severity.value == "high", (
            "Known synthetic check and normalized impact must match the independent oracle"
        )
        assert finding.subject_reference == assets[0].Reference(), (
            "No source hint may create a native/image/workload correlation"
        )

    assert not saved.relations and len(workspace.evidence_record_references) == 4, (
        "Retain exact acquisitions without fabricated runtime edges"
    )
    assert {item.Reference() for item in saved.objects} == set(workspace.object_references), (
        "The workspace must reference all actually committed canonical objects"
    )
    assert summary.snapshot.spec.job_id in workspace.job_references, "Persist the actual owning job"
    assert len([item for item in events if item.kind is JobEventKind.MODEL_DELTA]) == 1, (
        "Successful delta must describe the actually committed canonical revision"
    )
    report = VerifyReportEvidence(ReportSnapshot(saved), root)
    assert summary.report.status == "completed" and (
        summary.report.snapshot_sha256 == report.SnapshotDigest()
    ), "Export must project the exact saved verified snapshot"
    rendered = output.read_bytes()
    assert ORACLE["raw_only_marker"].encode() not in rendered and (
        b"owned.invalid" not in rendered
    ), (
        "Selected private source must remain raw-only evidence rather than normalized reports"
    )
    exported = json.loads(rendered)

    if report_format == "json":
        assert exported["model"] == saved.ToDict(), "JSON must retain canonical saved model wire"

    else:
        results = exported["runs"][0]["results"]
        assert len(results) == len(expected), "SARIF must preserve exactly the active detections"

    assert summary.ToDict()["scan_completeness"] == "not-assessed", (
        "A no-finding case is not native acceptance or a clean-scan claim"
    )


def Captured(tmp_path):
    """Execute one actual accepted job and retain its original four records for hostile probes."""

    root, selection, context = LiveConfiguration(tmp_path)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.COMPLETED, "Hostile probe needs an accepted run"
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    capture = summary.captures[0]
    from fuzzy1337.adapters import ImpactLevel
    from fuzzy1337.artifact_policy import ProfileCapability
    from fuzzy1337.policy import CapabilityPermission, ImpactPolicy

    capability = ProfileCapability(selection.profile)
    policy = ImpactPolicy("synthetic-configuration-safe-v1", permissions=(CapabilityPermission(
        capability.identifier, capability.adapter_id, ImpactLevel.SAFE),))

    return root, capture, records, replace(context, policy=policy)


def RemoveOwnedTree(root):
    """Remove this test's owned snapshots after allowing Windows deletion of read-only files."""

    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    shutil.rmtree(root)


def test_RelocationReplayPreservesOriginalFactsWithoutStageOrAuthority(tmp_path, monkeypatch):
    """Read-only replay survives removed original stages and expired consent without launching."""

    root, capture, records, _ = Captured(tmp_path)
    original = VerifySyntheticConfigurationReplay(records, root)
    relocated = tmp_path / "relocated"
    shutil.copytree(root, relocated)
    RemoveOwnedTree(capture.stage.root)
    RemoveOwnedTree(root)

    def Forbidden(*_args, **_kwargs):
        """Trip any current execution authority lookup during historical verification."""

        raise AssertionError("Historical replay cannot launch or validate current physical stages")

    monkeypatch.setattr(GovernedArtifactExecutor, "ValidateAcceptanceFresh", Forbidden)
    replay = VerifySyntheticConfigurationReplay(records, relocated)
    assert replay == original, "Relocated facts must retain bytes, identity and provenance"
    assert LocalModelStore(relocated).Open().revision == 1, "Replay cannot mutate model state"


@pytest.mark.parametrize("role", ["configuration-stdout", "configuration-stderr",
                                  "configuration-receipt", "configuration-source"])
@pytest.mark.parametrize("change", ["source", "scope", "invocation", "execution", "time"])
def test_ForeignReacquiredOriginalBytesCannotBorrowReceipt(tmp_path, role, change):
    """Actual immutable acquisitions with original bytes and forged attribution fail closed."""

    root, _, records, _ = Captured(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    record = next(item for item in records if item.reference.role == role)
    changes = {"source": {"source_id": "synthetic.foreign"},
        "scope": {"scope_reference": "scope:foreign"},
        "invocation": {"invocation_sha256": "0" * 64},
        "execution": {"execution": None},
        "time": {"finished_at": datetime.now(UTC).isoformat()}}
    substituted = store.Put(store.Read(record.reference), role, record.reference.media_type,
                            replace(record.provenance, **changes[change]))
    altered = tuple(substituted if item is record else item for item in records)

    with pytest.raises(ValueError):
        VerifySyntheticConfigurationReplay(altered, root)


@pytest.mark.parametrize("change", ["raw-source", "schema", "family", "profile", "request",
    "stage", "chronology", "version", "extra", "raw-stdout"])
def test_RehashedDetachedEnvelopeCannotChangeOriginalFacts(tmp_path, change):
    """Owning-store rehashing cannot repair an inconsistent original source/factory/receipt."""

    root, _, records, _ = Captured(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    role = "configuration-source" if change == "raw-source" else (
        "configuration-stdout" if change == "raw-stdout" else "configuration-receipt")
    record = next(item for item in records if item.reference.role == role)
    raw = store.Read(record.reference)

    if change in {"raw-source", "raw-stdout"}:
        payload = raw + b"changed"

    else:
        envelope = copy.deepcopy(json.loads(raw))

        if change == "schema":
            envelope["schema_version"] = True

        elif change in {"family", "profile", "version"}:
            field = {"family": "producer_family", "profile": "profile",
                     "version": "provider_version"}[change]
            envelope["artifact_metadata"]["grant"]["plan"][field] = "foreign"

        elif change == "request":
            envelope["prepared_payload"]["resources"]["max_stdout_bytes"] += 1

        elif change == "stage":
            envelope["stage_payload"]["lease"] = "0" * 32

        elif change == "chronology":
            envelope["collection_started_at"] = envelope["collection_finished_at"]

        else:
            envelope["extra"] = "unreviewed"

        payload = SerializeContract(envelope).encode()

    substituted = store.Put(payload, role, record.reference.media_type, record.provenance)
    altered = tuple(substituted if item is record else item for item in records)

    with pytest.raises(ValueError):
        VerifySyntheticConfigurationReplay(altered, root)


def test_ReDetectionPreservesTriageAndExactReplayIsNoOp(tmp_path):
    """Fresh runs preserve triage; reapplication of exact originals deduplicates."""

    root, capture, records, context = Captured(tmp_path)
    saved = LocalModelStore(root).Open()
    proposal, delta = ApplyVerifiedSyntheticConfiguration(saved, capture, records, root,
                                                          context_provider=lambda: context)
    assert proposal == saved and delta.created == delta.updated == (), (
        "Reapplying the exact original accepted capture must be a canonical no-op"
    )
    finding = Findings(saved)[0]
    triaged, _ = TransitionFinding(saved, finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED, replace(finding.provenance[0], source_id="operator.test",
            run_reference="run:triage", observed_at=datetime.now(UTC).isoformat(), execution=None),
        "Owned operator dismissal")
    LocalModelStore(root).Save(triaged, expected_revision=saved.revision)
    redetected, _ = ApplyVerifiedSyntheticConfiguration(triaged, capture, records, root,
                                                        context_provider=lambda: context)
    latest = Findings(redetected)[0]
    assert latest.status is FindingStatus.DISMISSED and latest.status_reason == (
        "Owned operator dismissal"), "Detection may not erase operator-triaged Finding disposition"


@pytest.mark.parametrize("change", ["revoked", "excluded", "owner", "material"])
def test_CurrentAuthorityOrMaterialRefusalPreventsAcceptedHistoricalApplication(tmp_path, change):
    """Historical valid evidence cannot replace current original-run SDK acceptance."""

    root, capture, records, context = Captured(tmp_path)
    original = LocalModelStore(root).Open()

    if change == "material":
        path = capture.stage.root / "input" / "Dockerfile"
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"changed")

    elif change == "owner":
        context = replace(context, owner_ref="owner:foreign")

    else:
        scope = replace(context.scope, exclusions=context.scope.targets) if (
            change == "excluded"
        ) else (
            replace(context.scope, authorization=replace(context.scope.authorization,
                state=AuthorizationState.REVOKED)))
        context = replace(context, scope=LocalScopeStore(root).Save(scope))

    with pytest.raises(ArtifactDeniedError):
        ApplyVerifiedSyntheticConfiguration(original, capture, records, root,
                                              context_provider=lambda: context)

    assert LocalModelStore(root).Open() == original, "Refusal cannot mutate saved canonical model"


@pytest.mark.parametrize("change", ["asset", "finding"])
def test_ForeignSourceIdentityCollisionDeniesWithoutChangingAnyOriginalObject(tmp_path, change):
    """A copied synthetic identity carrying foreign-family facts cannot be overwritten."""

    root, capture, records, context = Captured(tmp_path)
    original = LocalModelStore(root).Open()
    selected = next(item for item in original.objects if item.identity.kind.value == change)
    foreign = replace(selected, provenance=tuple(replace(item, source_id="native.trivy")
                                                for item in selected.provenance))
    state = replace(original, objects=tuple(foreign if item is selected else item
                                          for item in original.objects))
    before = CanonicalModelJson(state)

    with pytest.raises(ValueError):
        ApplyVerifiedSyntheticConfiguration(state, capture, records, root,
                                              context_provider=lambda: context)

    assert CanonicalModelJson(state) == before, "Rejected collisions must preserve original state"


@pytest.mark.parametrize("change", ["no-approval", "owner", "source", "policy", "scope"])
def test_PreLaunchRefusalHasNoRawProcessOrModelUpdate(tmp_path, change):
    """Actual workflow refuses current authority/selected-source failures before launching."""

    root, selection, _ = LiveConfiguration(tmp_path)
    owner = "owner:foreign" if change == "owner" else "owner:test"

    if change == "source":
        selection.source.write_bytes(b"unreviewed")

    elif change == "policy":
        selection.material.write_bytes(b"{}")

    elif change == "scope":
        store = LocalScopeStore(root)
        scope = store.Open("config-scope")
        store.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", owner, selection,
        approve_safe_configuration=change != "no-approval"))
    assert summary.snapshot.state is JobState.FAILED and summary.ExitCode() == 3, (
        "Refused pre-launch authority must not become a scanner success"
    )
    assert not summary.captures and not summary.snapshot.artifacts, (
        "No invocation or raw process result may be invented before a refused launch"
    )
    assert LocalModelStore(root).Open().revision == 0 and (
        summary.first_model_update_seconds is None
    ), (
        "Refused pre-launch selected inputs cannot publish a model update"
    )


def test_PostRunRevocationRetainsRawAndPreventsModelDelta(tmp_path, monkeypatch):
    """Post-run revocation keeps truthful raw evidence and refuses normalization."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **kwargs):
        """Run the real worker, then revoke current consent before normalization."""

        outcome = await original(self, *args, **kwargs)
        store = LocalScopeStore(root)
        scope = store.Open("config-scope")
        store.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

        return outcome

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.failure.code is JobFailureCode.AUTHORIZATION, (
        "Fresh current acceptance must deny the originally successful run after revocation"
    )
    assert len(summary.snapshot.artifacts) == 4 and LocalModelStore(root).Open().revision == 0, (
        "Original streams/source/receipt survive denial without a canonical model write"
    )
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    assert VerifySyntheticConfigurationReplay(records, root).acceptance.refusal is None, (
        "Historical original success must remain distinct from the later current refusal"
    )
    assert not any(event.kind is JobEventKind.MODEL_DELTA for event in summary.events), (
        "No successful model delta may follow revoked authorization"
    )


def test_ActualCancellationAfterExecutionPreservesRawWithoutModelPublication(tmp_path, monkeypatch):
    """Owning cancellation preserves actual process facts and suppresses model writes."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **kwargs):
        """Request owned cooperative cancellation just after the real SDK execution returns."""

        outcome = await original(self, *args, **kwargs)
        kwargs["cancellation"].set()

        return outcome

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.CANCELLED and summary.ExitCode() == 130, (
        "The actual owning cancellation cannot be reported as successful scan/model completion"
    )
    assert len(summary.snapshot.artifacts) == 4 and LocalModelStore(root).Open().revision == 0, (
        "Cancellation cleanup must retain acquired raw facts without changing the model"
    )


def test_StorageConflictRetainsRawAndNoSuccessfulDelta(tmp_path, monkeypatch):
    """Model CAS failure keeps actual capture references while refusing successful publication."""

    root, selection, _ = LiveConfiguration(tmp_path)

    def Save(*_args, **_kwargs):
        """Inject the existing optimistic model-store conflict at its actual consumer boundary."""

        raise WorkspaceConflictError("Owned conflict")

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "CAS conflict must remain a storage failure"
    )
    assert len(summary.snapshot.artifacts) == 4 and summary.first_model_update_seconds is None, (
        "Model CAS failure must preserve raw facts and never publish a successful delta"
    )


def test_RealCaptureOverflowRetainsBoundedOriginalResultAndNoModel(tmp_path, monkeypatch):
    """Actual unchanged worker fails truthfully under a tightened canonical capture budget."""

    import fuzzy1337.configuration_workflow as workflow
    from fuzzy1337.artifact_policy import PrepareArtifact
    from fuzzy1337.executors import ExecutionResources, ExecutionTermination

    root, selection, _ = LiveConfiguration(tmp_path)

    def Prepare(stage, workspace_root, **options):
        """Tighten allowed canonical resources before the actual matching approval is created."""

        return PrepareArtifact(stage, workspace_root, resources=ExecutionResources(
            max_stdout_bytes=3, max_stderr_bytes=16 * 1024), **options)

    monkeypatch.setattr(workflow, "PrepareArtifact", Prepare)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.failure.code is JobFailureCode.OUTPUT_LIMIT, (
        "The actual real-process capture overflow must remain an output-limit failure"
    )
    actual = summary.captures[0].outcome.raw_result
    assert actual.termination is ExecutionTermination.OUTPUT_LIMIT, (
        "Original executor termination must survive the workflow's failure presentation"
    )
    assert len(summary.captures[0].outcome.raw_result.stdout) == 3, (
        "Retain exactly the original bounded prefix rather than fabricating complete JSON"
    )
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    assert VerifySyntheticConfigurationReplay(records, root).acceptance.refusal is not None, (
        "Historical original refusal and three captured bytes must remain replayable"
    )
    assert LocalModelStore(root).Open().revision == 0 and len(records) == 4, (
        "A truncated actual process must retain evidence without proposing configuration findings"
    )


def test_ActualScopeMutationAfterGrantDeniesLaunchWithoutFabricatingRaw(tmp_path, monkeypatch):
    """The production SDK rejects a once-valid approval when actual persisted consent changes."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **kwargs):
        """Revoke owning consent after grant creation and use production launch checks."""

        store = LocalScopeStore(root)
        scope = store.Open("config-scope")
        store.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

        return await original(self, *args, **kwargs)

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.failure.code is JobFailureCode.AUTHORIZATION and not summary.captures, (
        "Stale once-valid grant cannot launch or manufacture a raw execution"
    )
    assert LocalModelStore(root).Open().revision == 0, "Stale approval cannot change state"
