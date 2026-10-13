# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed synthetic image VERSION/SCAN jobs with durable model/workspace and report outcomes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import (
    ArtifactOperation,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactSelection,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ArtifactVersionProof,
    GovernedArtifactExecutor,
    PrepareArtifact,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import ExecutionTermination
from fuzzy1337.image_evidence import (
    SYNTHETIC_IMAGE_SOURCE,
    SYNTHETIC_IMAGE_VERSION,
    ImageOperationCapture,
)
from fuzzy1337.images import ApplyVerifiedSyntheticTrivyImages
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


@dataclass(frozen=True, slots=True)
class ImageScanSelection:
    """Explicit non-secret archive, trusted runtime, reviewed worker and fixture material."""

    archive: Path
    executable: Path
    producer: Path
    material: Path
    read_consent: ArtifactReadConsent

    def __post_init__(self) -> None:
        """Require explicit absolute selections without discovery or filesystem reads."""

        if not isinstance(self.read_consent, ArtifactReadConsent) or any(
            not isinstance(path, Path) or not path.is_absolute()
            for path in (self.archive, self.executable, self.producer, self.material)
        ):
            raise ValueError("image workflow requires explicit consent and absolute selected paths")

    def Stage(self, root: Path) -> ArtifactStage:
        """Take one fresh separate owned immutable snapshot through the canonical artifact producer.

        Args:
            root: New owned per-operation stage directly within the selected workspace.

        Returns:
            Fresh input/scanner/material partitions and a new original physical single-run lease.
        """

        return ArtifactStage.Create(root, ArtifactProfile.SYNTHETIC_IMAGE, self.read_consent,
            (ArtifactSelection("image.tar", self.archive),),
            ArtifactSelection("executable", self.executable), SYNTHETIC_IMAGE_VERSION,
            material=(ArtifactSelection("policy.json", self.material),),
            producer=ArtifactSelection("producer.py", self.producer))


@dataclass(frozen=True, slots=True)
class ImageReportOutcome:
    """Separate requested report publication from the original completed scanner/job facts."""

    status: str
    format: str
    model_revision: int | None = None
    snapshot_sha256: str | None = None
    report_sha256: str | None = None
    size_bytes: int | None = None
    output_published: bool = False
    failure: str | None = None


def ExportImageReport(root: Path, model: ModelState, report_format: str,
                      output: Path) -> ImageReportOutcome:
    """Use existing report owners to publish the exact saved snapshot with atomic output truth.

    Args:
        root: Existing owning source workspace after model/workspace persistence.
        model: Exact snapshot actually committed by this completed image workflow.
        report_format: Explicit json or sarif format.
        output: Explicit new destination outside the source workspace.

    Returns:
        Independent export outcome including confirmed publication after post-link failures.
    """

    outcome = ImageReportOutcome("failed", report_format)
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
            SerializeSarif(original.report)
        )

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
class ImageScanSummary:
    """Measured terminal job and saved-model truth, with original operation and report outcomes."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    first_model_update_seconds: float | None
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]
    operations: tuple[dict[str, object], ...]
    report: ImageReportOutcome | None = None

    def ToDict(self) -> dict[str, object]:
        """Render detached machine facts without original physical paths or raw stream values.

        Returns:
            Versioned synthetic workflow summary reusing canonical jobs and report projections.
        """

        return {
            "schema_version": 1, "workflow": "synthetic-image",
            "source_id": SYNTHETIC_IMAGE_SOURCE, "state": self.snapshot.state.value,
            "scan_completeness": "not-assessed", "started_at": self.started_at,
            "finished_at": self.finished_at, "duration_seconds": self.duration_seconds,
            "first_model_update_seconds": self.first_model_update_seconds,
            "model_revision": self.model_revision, "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
            "operations": json.loads(SerializeContract(self.operations)),
            "report": None if self.report is None else json.loads(SerializeContract(self.report)),
        }

    def ExitCode(self) -> int:
        """Keep completed scan facts intact when separate report publication fails.

        Returns:
            Zero for complete scan/export, three for denial, four for failure, 130 for cancellation.
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
class SyntheticImageWorkflow:
    """One owned job whose successful delta follows both canonical durable saves."""

    workspace_root: Path
    scope_id: str
    owner_reference: str
    selection: ImageScanSelection
    policy: ImpactPolicy
    timeout_seconds: int
    initial_workspace: WorkspaceState
    initial_model: ModelState
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]
    captures: list[ImageOperationCapture] = field(default_factory=list)
    saved_model: ModelState | None = None

    def CurrentContext(self) -> ArtifactPolicyContext:
        """Reopen current same-store scope and check the exact executing owner on every SDK call.

        Returns:
            Fresh typed factual scope/operator-policy/owner context; this is not a grant.
        """

        scope = LocalScopeStore(self.workspace_root).Open(self.scope_id)

        if scope.authorization.authority_reference != self.owner_reference:
            raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

        return ArtifactPolicyContext(scope, self.policy, self.owner_reference)

    def CaptureSelections(self, context: JobContext, stage: ArtifactStage,
                          operation: ArtifactOperation, started_at: str, finished_at: str) -> None:
        """Retain selected-byte/read-consent receipts separately from six execution evidence roles.

        Args:
            context: Owning job evidence boundary.
            stage: Actual newly observed immutable selected-byte snapshots.
            operation: Exact independently staged version or scan phase.
            started_at: Actual clock reading before selected-file snapshotting.
            finished_at: Actual clock reading after its owned snapshot operation.
        """

        provenance = EvidenceProvenance(context.Spec.workspace_id, context.Spec.scope_reference,
            SYNTHETIC_IMAGE_SOURCE, "1", None, started_at, finished_at)

        for snapshot in (stage.input, stage.scanner, stage.material):
            payload = {"schema_version": 1, "operation": operation.value,
                "manifest": snapshot.manifest.ToDict(), "read_consent": snapshot.consent,
                "physical_identities": snapshot.identities,
                "directory_identity": snapshot.directory_identity}
            context.CaptureEvidence(SerializeContract(payload).encode("utf-8"),
                "artifact-" + snapshot.manifest.role.value + "-manifest", "application/json",
                provenance)

    def CaptureOperation(self, context: JobContext,
                         capture: ImageOperationCapture) -> tuple[EvidenceRecord, ...]:
        """Preserve both raw streams and original detached capture envelope before interpretation.

        Args:
            context: Owning job's real evidence publication boundary.
            capture: Actual original process result and observed cleanup/acceptance window.

        Returns:
            Three immutable operation records, including a verified empty stderr stream.
        """

        version = capture.prepared.operation.value == "version"
        roles = ("provider-version", "provider-version-stderr", "artifact-version-receipt") if (
            version
        ) else ("stdout", "stderr", "artifact-scan-receipt")
        source = capture.Provenance()
        raw = capture.outcome.raw_result
        values = ((raw.stdout, "application/json"), (raw.stderr, "text/plain"),
            (SerializeContract(capture.Envelope()).encode("utf-8"), "application/json"))

        return tuple(context.CaptureEvidence(data, role, media, source).evidence
                     for role, (data, media) in zip(roles, values, strict=True))

    async def Run(self, context: JobContext) -> None:
        """Execute accepted VERSION then grant-bound SCAN and persist before successful publication.

        Args:
            context: Existing owned job cancellation, evidence and delta event boundary.

        Raises:
            JobError: Truthful authority, process, normalization or durable-storage failure.
        """

        delta: ModelDelta | None = None
        phase = JobFailureCode.STORAGE
        executor = GovernedArtifactExecutor(self.workspace_root, clock=self.clock)

        try:
            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            VerifyWorkspaceEvidence(self.initial_workspace, evidence)
            VerifyReportEvidence(ReportSnapshot(self.initial_model), self.workspace_root)
            context.CheckCancellation()
            phase = JobFailureCode.AUTHORIZATION
            self.CurrentContext()
            records: list[EvidenceRecord] = []
            proof: ArtifactVersionProof | None = None

            for operation in (ArtifactOperation.VERSION, ArtifactOperation.SCAN):
                context.CheckCancellation()
                phase = JobFailureCode.STORAGE
                stage_started = self.clock().isoformat()
                stage = self.selection.Stage(self.workspace_root / ("image-stage-" + uuid4().hex))
                self.CaptureSelections(context, stage, operation, stage_started,
                    self.clock().isoformat())
                phase = JobFailureCode.AUTHORIZATION
                prepared = PrepareArtifact(stage, self.workspace_root, operation=operation,
                    timeout_seconds=3 if operation is ArtifactOperation.VERSION else (
                        self.timeout_seconds), version_proof=proof)
                grant = ArtifactPolicyEngine().Authorize(prepared, stage,
                    self.CurrentContext(), at=self.clock())
                collected_started = self.clock().isoformat()
                outcome = await executor.Execute(prepared, stage, grant, self.CurrentContext,
                    cancellation=context.Cancellation)
                capture = ImageOperationCapture(outcome, prepared, stage, collected_started,
                    self.clock().isoformat())
                self.captures.append(capture)
                records.extend(self.CaptureOperation(context, capture))
                context.CheckCancellation()
                self.RequireProcessSuccess(capture)
                executor.ValidateAcceptanceFresh(outcome, prepared, stage, self.CurrentContext)

                if operation is ArtifactOperation.VERSION:
                    phase = JobFailureCode.NORMALIZATION
                    proof = ArtifactVersionProof(outcome, prepared, stage)
                    phase = JobFailureCode.AUTHORIZATION

                context.Progress(len(self.captures), 2)

            assert proof is not None, "Accepted VERSION must precede the fixed SCAN loop"
            scan = self.captures[-1]
            phase = JobFailureCode.STORAGE
            original = LocalModelStore(self.workspace_root).Open()

            if original != self.initial_model:
                raise WorkspaceConflictError("Image model changed from its original revision")

            phase = JobFailureCode.NORMALIZATION
            proposal, delta = ApplyVerifiedSyntheticTrivyImages(original, proof, scan.outcome,
                scan.prepared, scan.stage, tuple(records), self.workspace_root,
                context_provider=self.CurrentContext)
            context.CheckCancellation()
            phase = JobFailureCode.AUTHORIZATION
            executor.ValidatePairAcceptanceFresh(
                (proof.outcome, proof.prepared, proof.stage),
                (scan.outcome, scan.prepared, scan.stage), self.CurrentContext,
            )
            phase = JobFailureCode.STORAGE
            self.saved_model = LocalModelStore(self.workspace_root).Save(proposal,
                expected_revision=original.revision)

        except ArtifactDeniedError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Synthetic image authority or selected material was refused")) from None

        except (EvidenceError, OSError, ValueError, TypeError,
                WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(phase,
                "Synthetic image workflow could not complete")) from None

        finally:
            self.PersistReferences()

        if delta is not None and delta.revision != delta.previous_revision:
            context.ModelChanged(delta)

    def RequireProcessSuccess(self, capture: ImageOperationCapture) -> None:
        """Keep actual process exit/timeout/output-limit failures separate from authority refusal.

        Args:
            capture: Original result already retained through the job's evidence store.

        Raises:
            JobError: Actual process execution did not succeed; raw facts remain unchanged.
        """

        termination = capture.outcome.raw_result.termination
        code = JobFailureCode.PROVIDER

        if termination is ExecutionTermination.TIMEOUT:
            code = JobFailureCode.TIMEOUT

        elif termination is ExecutionTermination.OUTPUT_LIMIT:
            code = JobFailureCode.OUTPUT_LIMIT

        if capture.outcome.raw_result.execution.state is not ExecutionState.SUCCEEDED or (
            termination is not ExecutionTermination.PROCESS_EXIT
            or capture.outcome.raw_result.execution.exit_code != 0
        ):
            raise JobError(JobFailure(code, "Synthetic image owned process did not succeed"))

    def PersistReferences(self) -> None:
        """Verify all retained old/new facts and CAS-save the original workspace before success.

        Raises:
            JobError: References cannot be verified or original workspace/model revision changed.
        """

        try:
            store = LocalWorkspaceStore(self.workspace_root)
            workspace = store.Open()
            model = LocalModelStore(self.workspace_root).Open()

            if workspace != self.initial_workspace or (
                self.saved_model is not None and model != self.saved_model
            ):
                raise WorkspaceConflictError("Image workspace changed from its original revision")

            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            VerifyWorkspaceEvidence(workspace, evidence)
            VerifyReportEvidence(ReportSnapshot(model), self.workspace_root)
            references = {(item.locator, item.role): item for item in workspace.evidence_references}
            record_ids = set(workspace.evidence_record_references)
            snapshot = self.snapshot()
            scopes = {*workspace.scope_references, snapshot.spec.scope_reference}

            for reference in scopes:
                if not reference.startswith("scope:"):
                    raise ValueError("Image workspace scope reference is invalid")

                LocalScopeStore(self.workspace_root).Open(reference[6:])

            object_refs = {item.Reference() for item in model.objects}

            if not set(workspace.object_references) <= object_refs:
                raise ValueError("Image workspace contains missing model object references")

            for artifact in snapshot.artifacts:
                record = artifact.evidence

                if evidence.Get(record.evidence_id) != record:
                    raise ValueError("Image acquisition differs from its immutable manifest")

                evidence.Read(record.reference)
                references.setdefault((record.reference.locator, record.reference.role),
                    record.reference)
                record_ids.add(record.evidence_id)

            store.Save(replace(workspace, scope_references=tuple(sorted(scopes)),
                object_references=tuple(sorted(object_refs)),
                job_references=tuple(sorted({*workspace.job_references, snapshot.spec.job_id})),
                evidence_references=tuple(references[key] for key in sorted(references)),
                evidence_record_references=tuple(sorted(record_ids))))

        except (EvidenceError, OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not preserve synthetic image workspace references")) from None


async def RunSyntheticImageScan(
    workspace_root: Path, scope_id: str, owner_reference: str, selection: ImageScanSelection,
    *, approve_safe_image: bool = False, timeout_seconds: int = 30,
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
    report_format: str | None = None, report_output: Path | None = None,
) -> ImageScanSummary:
    """Run one closed synthetic image job and return actual saved state and separate export truth.

    Args:
        workspace_root: Existing initialized owning workspace and canonical model.
        scope_id: Existing approved ARTIFACT registration/allow/consent record.
        owner_reference: Explicit executing owner matching current recorded authority.
        selection: Explicit input/scanner/material/read-consent selection, without discovery.
        approve_safe_image: Explicit image capability opt-in; false denies process authorization.
        timeout_seconds: Actual integer SCAN deadline from one through sixty seconds.
        on_event: Fast optional synchronous job presentation sink.
        clock: Trusted aware decision clock for deterministic owned tests.
        report_format: Explicit json or sarif export request, or absent for no export.
        report_output: Explicit new output path paired with report_format.

    Returns:
        Truthful terminal summary; native scanner/database/detection acceptance remains unassessed.
    """

    if not isinstance(selection, ImageScanSelection) or type(approve_safe_image) is not bool or (
        type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
        or (report_format is None) != (report_output is None)
    ):
        raise ValueError("image workflow configuration is invalid")

    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    model_store = LocalModelStore(workspace_store.root)
    model = model_store.Open()
    scope = LocalScopeStore(workspace_store.root).Open(scope_id)
    policy = ImpactPolicy("synthetic-image-safe-v1", permissions=(CapabilityPermission(
        "image.archive-vulnerabilities", SYNTHETIC_IMAGE_SOURCE, ImpactLevel.SAFE),
    ) if approve_safe_image else ())
    spec = JobSpec("job:image-" + uuid4().hex, workspace.workspace_id, scope.Reference(),
        owner_reference, SYNTHETIC_IMAGE_SOURCE, timeout_seconds=timeout_seconds + 15)

    def Snapshot() -> JobSnapshot:
        """Attach the provider to its original owning job before execution starts."""

        return job.Snapshot()

    workflow = SyntheticImageWorkflow(workspace_store.root, scope_id, owner_reference,
        selection, policy, timeout_seconds, workspace, model, Snapshot, clock)
    job = ScanJob(spec, workflow,
        evidence_store=LocalEvidenceStore(workspace_store.root / "evidence"))
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    first_update: float | None = None
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Measure the committed delta time and pass the unchanged canonical event to the sink."""

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
    export = None

    if report_format is not None and report_output is not None and (
        snapshot.state is JobState.COMPLETED and workflow.saved_model is not None
    ):
        export = ExportImageReport(workspace_store.root, workflow.saved_model,
            report_format, report_output)

    elif report_format is not None:
        export = ImageReportOutcome("not-run", report_format, model_revision=actual.revision,
            failure="scan-not-completed")

    operations: tuple[dict[str, object], ...] = tuple({"operation": item.prepared.operation.value,
        "run_reference": item.outcome.run_id,
        "execution": item.outcome.raw_result.execution,
        "termination": item.outcome.raw_result.termination.value,
        "acceptance_refusal": None if item.outcome.acceptance.refusal is None else (
            item.outcome.acceptance.refusal.value),
        "started_at": item.started_at, "finished_at": item.finished_at}
        for item in workflow.captures)

    return ImageScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, first_update, actual.revision,
        tuple((kind.value, len(actual.Objects(kind))) for kind in ObjectKind),
        job.EventsSince(), operations, export)
