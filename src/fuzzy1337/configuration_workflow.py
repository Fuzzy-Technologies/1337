# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed SCAN-only synthetic configuration jobs with durable model, evidence and report truth."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import (
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactSelection,
    ArtifactStage,
    ReadArtifactFile,
)
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    PrepareArtifact,
    ProfileCapability,
)
from fuzzy1337.configuration_evidence import (
    CONFIGURATION_SOURCE,
    CONFIGURATION_VERSION,
    ApplyVerifiedSyntheticConfiguration,
    ConfigurationOperationCapture,
)
from fuzzy1337.evidence import EvidenceError, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import ExecutionTermination
from fuzzy1337.jobs import (
    JobContext,
    JobError,
    JobEvent,
    JobEventKind,
    JobFailure,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
    ScanJob,
)
from fuzzy1337.model import LocalModelStore, ModelDelta, ModelState, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.report_commands import (
    CheckReportSnapshot,
    OpenReportInput,
    PublishReport,
    ReportFailure,
    ReportOutputPath,
)
from fuzzy1337.report_formats import SerializeJson, SerializeSarif
from fuzzy1337.reporting import MAX_REPORT_BYTES, ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

__all__ = [
    "ConfigurationScanSelection", "ConfigurationScanSummary", "ConfigurationReportOutcome",
    "ExportConfigurationReport", "RunSyntheticConfigurationScan",
]


@dataclass(frozen=True, slots=True)
class ConfigurationScanSelection:
    """Explicit source, runtime, reviewed worker, policy and selected-read consent."""

    profile: ArtifactProfile
    logical_path: str
    source: Path
    executable: Path
    producer: Path
    material: Path
    read_consent: ArtifactReadConsent

    def __post_init__(self) -> None:
        """Require closed synthetic profiles and absolute paths without reads or discovery."""

        if type(self.profile) is not ArtifactProfile or self.profile not in {
            ArtifactProfile.SYNTHETIC_DOCKERFILE, ArtifactProfile.SYNTHETIC_KUBERNETES
        } or type(self.read_consent) is not ArtifactReadConsent or any(
            not isinstance(path, Path) or not path.is_absolute()
            for path in (self.source, self.executable, self.producer, self.material)
        ):
            raise ValueError("configuration selection requires explicit closed synthetic inputs")

        ArtifactSelection(self.logical_path, self.source)

    def Stage(self, root: Path) -> ArtifactStage:
        """Snapshot explicit source, runtime, worker and material through the artifact owner.

        Args:
            root: New owned per-operation stage within the explicitly selected workspace.

        Returns:
            Role-separated immutable selected-byte manifests with original read consent.

        Raises:
            ValueError: Selected paths, bytes, profile shape or physical identities are invalid.
            OSError: Explicit selected material cannot be safely read or staged.
        """

        return ArtifactStage.Create(root, self.profile, self.read_consent,
            (ArtifactSelection(self.logical_path, self.source),),
            ArtifactSelection("executable", self.executable), CONFIGURATION_VERSION,
            material=(ArtifactSelection("policy.json", self.material),),
            producer=ArtifactSelection("producer.py", self.producer))


@dataclass(frozen=True, slots=True)
class ConfigurationReportOutcome:
    """Separate requested publication from original completed scanner and durable model facts."""

    status: str
    format: str
    model_revision: int | None = None
    snapshot_sha256: str | None = None
    report_sha256: str | None = None
    size_bytes: int | None = None
    output_published: bool = False
    failure: str | None = None


def ExportConfigurationReport(root: Path, model: ModelState, report_format: str,
                              output: Path) -> ConfigurationReportOutcome:
    """Publish the exact saved snapshot through canonical report verification/output owners.

    Args:
        root: Existing owning workspace after scan model/reference persistence.
        model: Exact committed canonical model snapshot.
        report_format: Explicit json or sarif format.
        output: New destination outside the owning source workspace.

    Returns:
        Separate actual publication outcome, including confirmed post-link failures.
    """

    outcome = ConfigurationReportOutcome("failed", report_format)
    phase = "configuration"

    try:
        if report_format not in {"json", "sarif"}:
            raise ReportFailure("configuration", 2)

        destination = ReportOutputPath(output, root)
        phase = "integrity"
        original = OpenReportInput(root)

        if original.report.state != model:
            raise ReportFailure("input-changed")

        outcome = replace(outcome, model_revision=model.revision,
            snapshot_sha256=original.report.SnapshotDigest())
        phase = "rendering"
        payload = SerializeJson(original.report) if report_format == "json" else (
            SerializeSarif(original.report))

        if len(payload) > MAX_REPORT_BYTES:
            raise ReportFailure("limit")

        outcome = replace(outcome, report_sha256=hashlib.sha256(payload).hexdigest(),
                          size_bytes=len(payload))
        phase = "integrity"
        CheckReportSnapshot(root, original)
        phase = "publication"
        PublishReport(destination, payload)

        return replace(outcome, status="completed", output_published=True)

    except ReportFailure as error:
        return replace(outcome, failure=error.kind, output_published=error.published)

    except (EvidenceError, OSError, ValueError, TypeError, RecursionError):
        return replace(outcome, failure=phase)

    except KeyboardInterrupt:
        return replace(outcome, failure="interrupted")


@dataclass(frozen=True, slots=True)
class ConfigurationScanSummary:
    """Terminal canonical job, actually saved model and separate requested report outcome."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    first_model_update_seconds: float | None
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]
    captures: tuple[ConfigurationOperationCapture, ...]
    report: ConfigurationReportOutcome | None = None

    def ToDict(self) -> dict[str, object]:
        """Render canonical machine facts without physical paths or private source bytes.

        Returns:
            Version-one configuration summary using unchanged job and report projections.
        """

        operations = [{"operation": "scan", "run_reference": item.outcome.run_id,
            "execution": item.outcome.raw_result.execution,
            "termination": item.outcome.raw_result.termination.value,
            "acceptance_refusal": None if item.outcome.acceptance.refusal is None else
                item.outcome.acceptance.refusal.value,
            "started_at": item.started_at, "finished_at": item.finished_at}
            for item in self.captures]

        return {"schema_version": 1, "workflow": "synthetic-configuration",
            "source_id": CONFIGURATION_SOURCE, "state": self.snapshot.state.value,
            "scan_completeness": "not-assessed", "started_at": self.started_at,
            "finished_at": self.finished_at, "duration_seconds": self.duration_seconds,
            "first_model_update_seconds": self.first_model_update_seconds,
            "model_revision": self.model_revision, "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
            "operations": json.loads(SerializeContract(operations)),
            "report": None if self.report is None else json.loads(SerializeContract(self.report))}

    def ExitCode(self) -> int:
        """Keep cancellation, authorization, scanner and export failure truth distinct.

        Returns:
            Zero for completion, 3 for authority refusal, 4 for failure, 130 for cancellation.
        """

        if self.snapshot.state is JobState.CANCELLED:
            return 130

        if self.snapshot.state is JobState.COMPLETED:
            if self.report is not None and self.report.status != "completed":
                return 130 if self.report.failure == "interrupted" else 4

            return 0

        if self.snapshot.failure is not None and (
            self.snapshot.failure.code is JobFailureCode.AUTHORIZATION
        ):
            return 3

        return 4


@dataclass(slots=True)
class SyntheticConfigurationWorkflow:
    """Owned provider that saves canonical state before publishing successful model changes."""

    workspace_root: Path
    scope_id: str
    owner_reference: str
    selection: ConfigurationScanSelection
    policy: ImpactPolicy
    timeout_seconds: int
    initial_workspace: WorkspaceState
    initial_model: ModelState
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]
    captures: list[ConfigurationOperationCapture] = field(default_factory=list)
    saved_model: ModelState | None = None

    def CurrentContext(self) -> ArtifactPolicyContext:
        """Reopen actual same-store scope and enforce the explicitly executing recorded owner."""

        try:
            scope = LocalScopeStore(self.workspace_root).Open(self.scope_id)

        except OSError:
            raise ArtifactDeniedError(ArtifactDenialReason.STORAGE) from None

        if scope.authorization.authority_reference != self.owner_reference:
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        return ArtifactPolicyContext(scope, self.policy, self.owner_reference)

    def CaptureOperation(self, context: JobContext, capture: ConfigurationOperationCapture,
                         source: bytes) -> tuple[EvidenceRecord, ...]:
        """Retain original streams, detached SDK facts and selected source before interpretation."""

        result = capture.outcome.raw_result
        provenance = capture.Provenance()
        values = (("configuration-stdout", result.stdout, "application/json"),
            ("configuration-stderr", result.stderr, "text/plain"),
            ("configuration-receipt", SerializeContract(capture.Envelope()).encode(),
                "application/json"), ("configuration-source", source, "text/plain"))

        return tuple(context.CaptureEvidence(data, role, media, provenance).evidence
                     for role, data, media in values)

    async def Run(self, context: JobContext) -> None:
        """Run actual governed SDK execution and persist one atomic accepted model proposal."""

        delta: ModelDelta | None = None
        phase = JobFailureCode.STORAGE
        executor = GovernedArtifactExecutor(self.workspace_root, clock=self.clock)

        try:
            VerifyWorkspaceEvidence(self.initial_workspace,
                LocalEvidenceStore(self.workspace_root / "evidence"))
            VerifyReportEvidence(ReportSnapshot(self.initial_model), self.workspace_root)
            context.CheckCancellation()
            phase = JobFailureCode.AUTHORIZATION
            self.CurrentContext()
            stage_root = self.workspace_root / ("configuration-stage-" + uuid4().hex)
            stage = self.selection.Stage(stage_root)
            prepared = PrepareArtifact(stage, self.workspace_root,
                                       timeout_seconds=self.timeout_seconds)
            selected = stage.input.manifest.files[0]
            grant = ArtifactPolicyEngine().Authorize(prepared, stage, self.CurrentContext(),
                                                      at=self.clock())
            started = self.clock().isoformat()
            buffer = io.BytesIO()
            observed = ReadArtifactFile(stage.root / "input" / selected.name, selected.name,
                                        buffer, max_bytes=4096)

            if observed != selected:
                raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)

            source = buffer.getvalue()

            outcome = await executor.Execute(prepared, stage, grant, self.CurrentContext,
                                             cancellation=context.Cancellation)
            capture = ConfigurationOperationCapture(outcome, prepared, stage, started,
                                                     self.clock().isoformat())
            self.captures.append(capture)
            phase = JobFailureCode.STORAGE
            records = self.CaptureOperation(context, capture, source)
            context.CheckCancellation()
            self.RequireProcessSuccess(capture)
            phase = JobFailureCode.AUTHORIZATION
            executor.ValidateAcceptanceFresh(outcome, prepared, stage, self.CurrentContext)
            phase = JobFailureCode.STORAGE
            original = LocalModelStore(self.workspace_root).Open()

            if original != self.initial_model:
                raise WorkspaceConflictError("Configuration model changed during execution")

            phase = JobFailureCode.NORMALIZATION
            proposal, delta = ApplyVerifiedSyntheticConfiguration(original, capture, records,
                self.workspace_root, context_provider=self.CurrentContext)
            context.CheckCancellation()
            phase = JobFailureCode.AUTHORIZATION
            executor.ValidateAcceptanceFresh(outcome, prepared, stage, self.CurrentContext)
            phase = JobFailureCode.STORAGE
            self.saved_model = LocalModelStore(self.workspace_root).Save(proposal,
                expected_revision=original.revision)

        except ArtifactDeniedError as error:
            code = JobFailureCode.STORAGE if error.reason is ArtifactDenialReason.STORAGE else (
                JobFailureCode.AUTHORIZATION)

            raise JobError(JobFailure(code,
                "Synthetic configuration authority or selected material was refused")) from None

        except OSError:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Synthetic configuration storage could not be read or written")) from None

        except (EvidenceError, ValueError, TypeError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(phase,
                "Synthetic configuration workflow could not complete")) from None

        finally:
            self.PersistReferences()

        if delta is not None and delta.revision != delta.previous_revision:
            context.Progress(1, 1)
            context.ModelChanged(delta)

    def RequireProcessSuccess(self, capture: ConfigurationOperationCapture) -> None:
        """Preserve actual process failure classifications after retaining raw facts."""

        raw = capture.outcome.raw_result
        code = JobFailureCode.PROVIDER

        if raw.termination is ExecutionTermination.TIMEOUT:
            code = JobFailureCode.TIMEOUT

        elif raw.termination is ExecutionTermination.OUTPUT_LIMIT:
            code = JobFailureCode.OUTPUT_LIMIT

        if raw.execution.state is not ExecutionState.SUCCEEDED or (
            raw.termination is not ExecutionTermination.PROCESS_EXIT or raw.execution.exit_code != 0
        ):
            raise JobError(JobFailure(code, "Configuration owned process did not succeed"))

    def PersistReferences(self) -> None:
        """Verify retained evidence and CAS-save workspace references before successful events."""

        try:
            store = LocalWorkspaceStore(self.workspace_root)
            workspace = store.Open()
            model = LocalModelStore(self.workspace_root).Open()

            if workspace != self.initial_workspace or (
                self.saved_model is not None and model != self.saved_model
            ):
                raise WorkspaceConflictError("Configuration workspace changed during execution")

            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            VerifyWorkspaceEvidence(workspace, evidence)
            VerifyReportEvidence(ReportSnapshot(model), self.workspace_root)
            references = {(item.locator, item.role): item for item in workspace.evidence_references}
            records = set(workspace.evidence_record_references)
            snapshot = self.snapshot()
            scopes = {*workspace.scope_references, snapshot.spec.scope_reference}

            for reference in scopes:
                if not reference.startswith("scope:"):
                    raise ValueError("Configuration workspace scope reference is invalid")

                LocalScopeStore(self.workspace_root).Open(reference[6:])

            objects = {item.Reference() for item in model.objects}

            if not set(workspace.object_references) <= objects:
                raise ValueError("Configuration workspace contains missing object references")

            for artifact in snapshot.artifacts:
                record = artifact.evidence

                if evidence.Get(record.evidence_id) != record:
                    raise ValueError("Configuration acquisition differs from its manifest")

                evidence.Read(record.reference)
                references.setdefault((record.reference.locator, record.reference.role),
                                      record.reference)
                records.add(record.evidence_id)

            store.Save(replace(workspace, scope_references=tuple(sorted(scopes)),
                object_references=tuple(sorted(objects)),
                job_references=tuple(sorted({*workspace.job_references, snapshot.spec.job_id})),
                evidence_references=tuple(references[key] for key in sorted(references)),
                evidence_record_references=tuple(sorted(records))))

        except (EvidenceError, OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not preserve configuration workspace references")) from None


async def RunSyntheticConfigurationScan(workspace_root: Path, scope_id: str, owner_reference: str,
    selection: ConfigurationScanSelection, *, approve_safe_configuration: bool = False,
    timeout_seconds: int = 30, on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow, report_format: str | None = None,
    report_output: Path | None = None,
) -> ConfigurationScanSummary:
    """Run the closed synthetic configuration SDK/job workflow and return actual durable outcomes.

    Args:
        workspace_root: Existing initialized workspace and canonical model.
        scope_id: Existing approved ARTIFACT registration/allow/consent record.
        owner_reference: Explicit executing owner matching current recorded authority.
        selection: Explicit one-source/runtime/worker/material/read-consent selection.
        approve_safe_configuration: Explicit SAFE capability opt-in; false denies launch.
        timeout_seconds: Actual integer SCAN deadline from one through sixty seconds.
        on_event: Optional fast synchronous canonical event presentation sink.
        clock: Trusted aware decision clock; defaults to current UTC.
        report_format: Explicit json or sarif export, paired with report_output.
        report_output: Explicit new destination outside the owning workspace.

    Returns:
        Truthful terminal summary with unassessed scan completeness and separate export truth.

    Raises:
        ValueError: Selection, bounds, workspace or scope configuration is invalid.
        OSError: Initial workspace, model or scope storage cannot be read.
    """

    if type(selection) is not ConfigurationScanSelection or (
        type(approve_safe_configuration) is not bool
        or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
        or (report_format is None) != (report_output is None)
    ):
        raise ValueError("configuration workflow parameters are invalid")

    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    model_store = LocalModelStore(store.root)
    model = model_store.Open()
    scope = LocalScopeStore(store.root).Open(scope_id)
    capability = ProfileCapability(selection.profile)
    policy = ImpactPolicy("synthetic-configuration-safe-v1", permissions=(CapabilityPermission(
        capability.identifier, capability.adapter_id, ImpactLevel.SAFE),
    ) if approve_safe_configuration else ())
    spec = JobSpec("job:configuration-" + uuid4().hex, workspace.workspace_id, scope.Reference(),
        owner_reference, CONFIGURATION_SOURCE, timeout_seconds=timeout_seconds + 15)

    def Snapshot() -> JobSnapshot:
        """Bind provider persistence to its original owning job."""

        return job.Snapshot()

    workflow = SyntheticConfigurationWorkflow(store.root, scope_id, owner_reference, selection,
        policy, timeout_seconds, workspace, model, Snapshot, clock)
    job = ScanJob(spec, workflow, evidence_store=LocalEvidenceStore(store.root / "evidence"))
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    first_update: float | None = None
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Measure actually published committed delta time and retain canonical event identity."""

        nonlocal cursor, first_update
        cursor = event.sequence

        if event.kind is JobEventKind.MODEL_DELTA and first_update is None:
            first_update = time.monotonic() - started

        if on_event is not None:
            on_event(event)

    try:
        async for event in job.Events():
            Observe(event)

    except asyncio.CancelledError:
        await job.CancelAndWait(owner_reference)

        for event in job.EventsSince(cursor):
            Observe(event)

    except Exception:
        await job.CancelAndWait(owner_reference)

        raise

    snapshot = await job.Wait()
    actual = model_store.Open()
    report = None

    if report_format is not None and report_output is not None and (
        snapshot.state is JobState.COMPLETED and workflow.saved_model is not None
    ):
        report = ExportConfigurationReport(store.root, workflow.saved_model, report_format,
                                           report_output)

    elif report_format is not None:
        report = ConfigurationReportOutcome("not-run", report_format,
                                            model_revision=actual.revision,
                                    failure="scan-not-completed")

    return ConfigurationScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, first_update, actual.revision,
        tuple((kind.value, len(actual.Objects(kind))) for kind in ObjectKind),
        job.EventsSince(), tuple(workflow.captures), report)
