# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit native Dockerfile/Kubernetes planning and governed durable configuration scan jobs."""

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

from fuzzy1337.adapters import EvidenceReference, ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactManifest, ReadArtifactFile
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.configuration_workflow import (
    ConfigurationReportOutcome,
    ExportConfigurationReport,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
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
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_configuration_capture import (
    CaptureNativeConfigurationOperation,
    NativeConfigurationCaptureError,
    NativeConfigurationOperationCapture,
)
from fuzzy1337.native_configuration_evidence import (
    ApplyVerifiedNativeConfiguration,
    NativeConfigurationEvidenceStore,
)
from fuzzy1337.native_configuration_material import NativeConfigurationMaterialObserver, Settle
from fuzzy1337.native_configuration_policy import (
    NativeConfigurationOperationPlan,
    PrepareNativeConfigurationOperation,
)
from fuzzy1337.native_configuration_report import NATIVE_CONFIGURATION_ROLES
from fuzzy1337.native_image_bounded_capture import Finalization
from fuzzy1337.native_image_observation import NativeImageObservationBudget
from fuzzy1337.policy import ImpactPolicy, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import LocalScopeStore, Target
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

__all__ = ["NativeConfigurationScanPlan", "NativeConfigurationScanSummary",
           "PlanNativeConfigurationScan", "ScanNativeConfiguration"]


def ValidateSelection(workspace_root: Path, owner_reference: str,
                      selection: NativeConfigurationSelection, timeout_seconds: int) -> None:
    """Require explicit exact typed owner/read consent and bounded native scan declarations.

    Args:
        workspace_root: Existing explicit absolute workspace path.
        owner_reference: Explicit executing owner.
        selection: Exact native selection without filesystem discovery.
        timeout_seconds: Integer SCAN allowance from one through sixty seconds.
    """

    if type(selection) is not NativeConfigurationSelection or (
        not isinstance(workspace_root, Path) or not workspace_root.is_absolute()
        or selection.read_consent.actor_ref != owner_reference
        or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
    ):
        raise ValueError("Native configuration requires explicit owner selections and limits")


def CurrentContext(root: Path, scope_id: str, owner_reference: str,
                   policy_provider: Callable[[], ImpactPolicy]) -> ArtifactPolicyContext:
    """Reopen same-store recorded scope and independently supplied current operator policy.

    Args:
        root: Canonical owning workspace.
        scope_id: Explicit existing registered artifact scope.
        owner_reference: Explicit executing owner matching selected read consent.
        policy_provider: Synchronous factual typed operator policy source.

    Returns:
        Current factual authority context without issuing a grant.
    """

    policy = policy_provider()

    if type(policy) is not ImpactPolicy:
        raise ValueError("Native configuration requires a fresh typed operator policy")

    return ArtifactPolicyContext(LocalScopeStore(root).Open(scope_id), policy, owner_reference)


@dataclass(frozen=True, slots=True)
class NativeConfigurationScanPlan:
    """Read-authorized target preview or descriptive VERSION authority plan; neither can execute."""

    input_manifest: ArtifactManifest
    phase: str
    scan_timeout_seconds: int
    authority_plan: NativeConfigurationOperationPlan | None = None

    @property
    def Target(self) -> Target:
        """Return the exact canonical selected artifact target for independent registration.

        Returns:
            Manifest-derived ARTIFACT identity.
        """

        return self.input_manifest.Target()

    def ToDict(self) -> dict[str, object]:
        """Render descriptive target facts without private paths, raw source or execution grants.

        Returns:
            Schema-one preview with original VERSION still required.
        """

        return {"schema_version": 1, "workflow": "native-configuration", "phase": self.phase,
            "execution_authorized": False, "input_manifest": self.input_manifest.ToDict(),
            "target": json.loads(SerializeContract(self.Target)),
            "authority_plan": None if self.authority_plan is None else json.loads(
                SerializeContract(self.authority_plan)),
            "scan_recipe": {"timeout_seconds": self.scan_timeout_seconds,
                            "requires_original_version": True}}


async def PlanNativeConfigurationScan(
    workspace_root: Path, owner_reference: str, selection: NativeConfigurationSelection, *,
    scope_id: str | None = None, policy_provider: Callable[[], ImpactPolicy] | None = None,
    timeout_seconds: int = 30,
) -> NativeConfigurationScanPlan:
    """Observe selected material to preview its target or plan current VERSION without executing it.

    Args:
        workspace_root: Existing initialized canonical workspace.
        owner_reference: Explicit executing owner with independent selected-read consent.
        selection: One selected native source and pinned executable.
        scope_id: Optional existing recorded scope, paired with policy_provider.
        policy_provider: Optional fresh typed policy source, paired with scope_id.
        timeout_seconds: Future SCAN deadline from one through sixty seconds.

    Returns:
        Manifest target preview or descriptive current VERSION authority plan.
    """

    ValidateSelection(workspace_root, owner_reference, selection, timeout_seconds)

    if (scope_id is None) != (policy_provider is None):
        raise ValueError("Native configuration planning requires paired scope and policy")

    workspace = LocalWorkspaceStore(workspace_root).Open()
    observer = NativeConfigurationMaterialObserver(selection, workspace_root,
                                                   workspace.workspace_id, owner_reference)
    pair = "native-configuration-pair:" + uuid4().hex

    try:
        proof = await observer.Create(NativeImageObservationBudget(planning=True),
                                      operation_reference=pair)
        plan = None

        if scope_id is not None and policy_provider is not None:
            prepared = PrepareNativeConfigurationOperation("version", selection,
                observer=observer, material_proof=proof, operation_reference=pair)
            plan = ArtifactPolicyEngine().PlanNativeConfigurationOperation(prepared,
                CurrentContext(workspace_root, scope_id, owner_reference, policy_provider),
                observer=observer, material_proof=proof, at=UtcNow())

        return NativeConfigurationScanPlan(proof.stage.input.manifest,
            "material-preview" if plan is None else "version-authority-plan", timeout_seconds, plan)

    finally:
        observer.Close()


class NativeConfigurationJobEvidenceStore(NativeConfigurationEvidenceStore):
    """Bridge fixed collector acquisitions into canonical job ownership and acknowledgements."""

    def __init__(self, context: JobContext, root: Path) -> None:
        """Bind the original running job and retain only independently confirmed acquisitions."""

        super().__init__(root)
        self.context = context
        self.records: dict[str, EvidenceRecord] = {}
        self.publication_uncertain = False

    def Confirm(self, expected: EvidenceRecord, data: bytes) -> None:
        """Confirm original immutable manifest and bounded blob before exposing an acquisition.

        Args:
            expected: Exact anticipated canonical content-addressed record.
            data: Original already-bounded acquisition bytes.
        """

        if self.Get(expected.evidence_id) != expected or self.Read(expected.reference) != data:
            raise EvidenceError("Native configuration original evidence acknowledgement differs")

        previous = self.records.get(expected.reference.role)

        if previous is not None and previous != expected:
            raise ValueError("Native configuration cannot replace an original acquisition role")

        self.records[expected.reference.role] = expected

    def Put(self, data: bytes, role: str, media_type: str,
            provenance: EvidenceProvenance) -> EvidenceRecord:
        """Publish exact collector bytes once and preserve confirmed facts after a lost event ack.

        Args:
            data: Original bounded stream, receipt or source bytes.
            role: One of seven native configuration acquisition roles.
            media_type: Exact role media type.
            provenance: Exact original job, scope, invocation and execution attribution.

        Returns:
            Unchanged confirmed canonical record after actual job attachment.
        """

        maximum, media = NATIVE_CONFIGURATION_ROLES.get(role, (0, ""))

        if role not in NATIVE_CONFIGURATION_ROLES or type(data) is not bytes or (
            media_type != media or len(data) > maximum
            or provenance.workspace_id != self.context.Spec.workspace_id
            or provenance.scope_reference != self.context.Spec.scope_reference
            or provenance.source_id != "native.trivy" or provenance.source_version != "1"
        ):
            raise ValueError("Native configuration original job evidence role/provenance differs")

        digest = hashlib.sha256(data).hexdigest()
        expected = EvidenceRecord(EvidenceReference(role, "blobs/sha256/" + digest,
                                                    digest, media_type, len(data)), provenance)

        try:
            artifact = self.context.CaptureEvidence(data, role, media_type, provenance)

            if artifact.job_id != self.context.Spec.job_id or artifact.evidence != expected:
                raise EvidenceError("Native configuration original job attachment differs")

            self.Confirm(expected, data)

        except BaseException:
            self.publication_uncertain = True

            try:
                self.Confirm(expected, data)

            except (EvidenceError, OSError, ValueError):
                pass

            raise

        return expected


@dataclass(frozen=True, slots=True)
class NativeConfigurationScanSummary:
    """Actual terminal native job, saved-model facts and independently requested report outcome."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    first_model_update_seconds: float | None
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]
    captures: tuple[NativeConfigurationOperationCapture, ...]
    retained_records: tuple[EvidenceRecord, ...]
    custody_uncertain: bool = False
    report: ConfigurationReportOutcome | None = None

    def ToDict(self) -> dict[str, object]:
        """Render canonical original facts without private paths, source bytes or mutable handles.

        Returns:
            Distinct native-configuration schema-one job summary.
        """

        operations = [{"operation": item.operation, "capture_sha256": item.Digest(),
            "execution": item.outcome.execution, "termination": item.outcome.termination,
            "acceptance_refusal": item.refusal, "started_at": item.started_at,
            "finished_at": item.finished_at} for item in self.captures]

        return {"schema_version": 1, "workflow": "native-configuration",
            "source_id": "native.trivy",
            "state": self.snapshot.state.value, "scan_completeness": "not-assessed",
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "first_model_update_seconds": self.first_model_update_seconds,
            "model_revision": self.model_revision, "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
            "operations": json.loads(SerializeContract(operations)),
            "retained_evidence_ids": [record.evidence_id for record in self.retained_records],
            "custody_uncertain": self.custody_uncertain,
            "report": None if self.report is None else json.loads(SerializeContract(self.report))}

    def ExitCode(self) -> int:
        """Keep cancellation, authorization, provider failure and export outcomes distinct.

        Returns:
            Zero for completion, three for authority, four for failure, 130 for cancellation.
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
class NativeConfigurationWorkflow:
    """One original VERSION/SCAN provider with original custody and one-attempt durable save."""

    workspace_root: Path
    scope_id: str
    owner_reference: str
    selection: NativeConfigurationSelection
    policy_provider: Callable[[], ImpactPolicy]
    timeout_seconds: int
    initial_workspace: WorkspaceState
    initial_model: ModelState
    clock: Callable[[], datetime]
    captures: list[NativeConfigurationOperationCapture] = field(default_factory=list)
    bridge: NativeConfigurationJobEvidenceStore | None = None
    saved_model: ModelState | None = None
    custody_uncertain: bool = False
    workspace_attempted: bool = False

    def Context(self) -> ArtifactPolicyContext:
        """Reopen exact current same-store scope and independently provided typed policy.

        Returns:
            Factual current authority context without granting execution.
        """

        return CurrentContext(self.workspace_root, self.scope_id, self.owner_reference,
                              self.policy_provider)

    def Records(self) -> tuple[EvidenceRecord, ...]:
        """Return only independently confirmed original acquisitions, including failure evidence.

        Returns:
            Zero through seven exact canonical original records.
        """

        return () if self.bridge is None else tuple(self.bridge.records.values())

    def PersistReferences(self, context: JobContext) -> None:
        """Attempt one original-workspace CAS preserving every confirmed original acquisition.

        Args:
            context: Actual owning running job, including cancellation cleanup.
        """

        if self.workspace_attempted:
            return

        store = LocalWorkspaceStore(self.workspace_root)
        workspace = store.Open()
        model = LocalModelStore(self.workspace_root).Open()

        if workspace != self.initial_workspace or self.saved_model is not None and (
            model != self.saved_model
        ):
            raise WorkspaceConflictError("Native configuration original save state changed")

        evidence = NativeConfigurationEvidenceStore(self.workspace_root / "evidence")
        VerifyWorkspaceEvidence(workspace, LocalEvidenceStore(evidence.root))
        VerifyReportEvidence(ReportSnapshot(model), self.workspace_root)
        references = {(item.locator, item.role): item for item in workspace.evidence_references}
        records = set(workspace.evidence_record_references)

        for record in self.Records():
            if evidence.Get(record.evidence_id) != record:
                raise EvidenceError("Native configuration retained manifest differs")

            evidence.Read(record.reference)
            references[(record.reference.locator, record.reference.role)] = record.reference
            records.add(record.evidence_id)

        objects = {item.Reference() for item in model.objects}

        if not set(workspace.object_references) <= objects:
            raise ValueError("Native configuration prior object reference is missing")

        self.workspace_attempted = True
        proposal = replace(workspace,
            scope_references=tuple(sorted({*workspace.scope_references,
                                           context.Spec.scope_reference})),
            object_references=tuple(sorted(objects)),
            job_references=tuple(sorted({*workspace.job_references, context.Spec.job_id})),
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted(records)))
        acknowledged = store.Save(proposal)
        committed = replace(proposal, revision=proposal.revision + 1)

        if type(acknowledged) is not WorkspaceState or acknowledged != committed or (
            store.Open() != committed
        ):
            raise WorkspaceConflictError("Native configuration workspace acknowledgement differs")

    def RequireSuccess(self, capture: NativeConfigurationOperationCapture) -> None:
        """Preserve timeout/output/provider classifications after retaining original raw facts.

        Args:
            capture: Original terminal process capture with confirmed raw acquisitions.
        """

        raw = capture.outcome

        if raw.execution.state is not ExecutionState.SUCCEEDED or (
            raw.termination is not ExecutionTermination.PROCESS_EXIT or raw.execution.exit_code != 0
        ):
            code = {ExecutionTermination.TIMEOUT: JobFailureCode.TIMEOUT,
                ExecutionTermination.OUTPUT_LIMIT: JobFailureCode.OUTPUT_LIMIT}.get(
                    raw.termination, JobFailureCode.PROVIDER)

            raise JobError(JobFailure(code, "Native configuration owned process did not succeed"))

        if capture.refusal is not None:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native configuration original material or authority was refused"))

    async def Run(self, context: JobContext) -> None:
        """Execute and persist one exact governed pair before publishing a canonical model delta.

        Args:
            context: Actual canonical job cancellation, evidence and event boundary.
        """

        self.bridge = NativeConfigurationJobEvidenceStore(context, self.workspace_root / "evidence")
        observer = NativeConfigurationMaterialObserver(self.selection, self.workspace_root,
            self.initial_workspace.workspace_id, self.owner_reference)
        engine = ArtifactPolicyEngine()
        budget = NativeImageObservationBudget()
        pair = "native-configuration-pair:" + uuid4().hex
        delta: ModelDelta | None = None
        phase = JobFailureCode.STORAGE

        try:
            VerifyWorkspaceEvidence(self.initial_workspace,
                                   LocalEvidenceStore(self.workspace_root / "evidence"))
            VerifyReportEvidence(ReportSnapshot(self.initial_model), self.workspace_root)
            context.CheckCancellation()
            phase = JobFailureCode.AUTHORIZATION
            self.Context()

            proof = await observer.Create(budget, operation_reference=pair,
                                          cancellation=context.Cancellation)

            with Finalization(budget):
                version_prepared = PrepareNativeConfigurationOperation("version", self.selection,
                    observer=observer, material_proof=proof, operation_reference=pair)
                version_grant = engine.AuthorizeNativeConfigurationOperation(version_prepared,
                    self.Context(), observer=observer, material_proof=proof, at=self.clock(),
                    approve_safe_configuration=True)
                version_claim = engine.ClaimNativeConfigurationExecution(version_grant,
                    version_prepared, self.Context(), observer=observer, material_proof=proof,
                    at=self.clock())

            version_capture, latest = await CaptureNativeConfigurationOperation(engine,
                version_prepared, version_grant, version_claim, self.bridge, self.Context,
                observer=observer, material_proof=proof, budget=budget,
                cancellation=context.Cancellation, clock=self.clock)
            self.captures.append(version_capture)
            self.RequireSuccess(version_capture)

            if latest is None:
                raise ValueError("Native configuration original VERSION has no verified material")

            proof = latest

            with Finalization(budget):
                prerequisite = engine.AcceptNativeConfigurationVersion(version_claim,
                    version_capture, self.Context(), observer=observer, material_proof=proof,
                    at=self.clock())
                prepared = PrepareNativeConfigurationOperation("scan", self.selection,
                    observer=observer, material_proof=proof, operation_reference=pair,
                    timeout_seconds=self.timeout_seconds, version_prerequisite=prerequisite)
                grant = engine.AuthorizeNativeConfigurationOperation(prepared, self.Context(),
                    observer=observer, material_proof=proof, at=self.clock(),
                    approve_safe_configuration=True)
                claim = engine.ClaimNativeConfigurationExecution(grant, prepared, self.Context(),
                    observer=observer, material_proof=proof, at=self.clock())

            capture, latest = await CaptureNativeConfigurationOperation(engine, prepared,
                grant, claim, self.bridge, self.Context, observer=observer, material_proof=proof,
                budget=budget, cancellation=context.Cancellation, clock=self.clock)
            self.captures.append(capture)
            self.RequireSuccess(capture)

            if latest is None:
                raise ValueError("Native configuration original SCAN has no verified material")

            proof = latest

            with Finalization(budget):
                buffer = io.BytesIO()
                source_path = proof.stage.input.directory / self.selection.logical_path
                selected = ReadArtifactFile(source_path,
                    self.selection.logical_path, buffer, max_bytes=4096)

                if (selected,) != proof.stage.input.manifest.files:
                    raise ValueError("Native configuration original retained source differs")

                self.bridge.Put(buffer.getvalue(), "native-configuration-source", "text/plain",
                                capture.Provenance())
                phase = JobFailureCode.NORMALIZATION
                original = LocalModelStore(self.workspace_root).Open()

                if original != self.initial_model:
                    raise WorkspaceConflictError("Native configuration original model changed")

                proposal, delta = ApplyVerifiedNativeConfiguration(
                    original, capture, self.Records(),
                    self.workspace_root, engine=engine, version_prerequisite=prerequisite,
                    scan_claim=claim, observer=observer, material_proof=proof,
                    context_provider=self.Context)
                context.CheckCancellation()
                phase = JobFailureCode.AUTHORIZATION
                engine.ValidateNativeConfigurationPairFresh(prerequisite, claim, capture,
                    self.Context(), observer=observer, material_proof=proof, at=self.clock())
                observer.Close()
                phase = JobFailureCode.STORAGE
                acknowledged = LocalModelStore(self.workspace_root).Save(proposal,
                    expected_revision=original.revision)

                if type(acknowledged) is not ModelState or acknowledged != proposal:
                    raise WorkspaceConflictError("Native configuration model ACK differs")

                self.saved_model = acknowledged
                self.PersistReferences(context)

        except ArtifactDeniedError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native configuration current authority was refused")) from None

        except NativeConfigurationCaptureError:
            self.custody_uncertain = True

            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                "Native configuration original custody is unconfirmed")) from None

        except OSError:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Native configuration storage could not be read or written")) from None

        except (EvidenceError, ValueError, TypeError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(phase,
                "Native configuration workflow could not complete")) from None

        finally:
            try:
                with Finalization(budget):
                    if self.captures and "native-configuration-source" not in self.bridge.records:
                        stage = self.captures[-1].prepared
                        input_path = proof.stage.input.directory
                        buffer = io.BytesIO()
                        observed = ReadArtifactFile(input_path / self.selection.logical_path,
                            self.selection.logical_path, buffer, max_bytes=4096)

                        if (observed,) == stage.input_manifest.files:
                            self.bridge.Put(buffer.getvalue(), "native-configuration-source",
                                            "text/plain", self.captures[-1].Provenance())

            except (EvidenceError, OSError, ValueError):
                self.custody_uncertain = True

            try:
                with Finalization(budget):
                    if not self.custody_uncertain:
                        observer.Close()

            except (OSError, ValueError):
                self.custody_uncertain = True

            try:
                with Finalization(budget):
                    self.PersistReferences(context)

            except (EvidenceError, OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError):
                raise JobError(JobFailure(JobFailureCode.STORAGE,
                    "Could not preserve native configuration original references")) from None

        if self.custody_uncertain or self.bridge.publication_uncertain:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Native configuration cleanup or publication is unconfirmed"))

        if delta is not None and delta.revision != delta.previous_revision:
            context.Progress(1, 1)
            context.ModelChanged(delta)


async def ScanNativeConfiguration(
    workspace_root: Path, scope_id: str, owner_reference: str,
    selection: NativeConfigurationSelection, policy_provider: Callable[[], ImpactPolicy], *,
    approve_safe_configuration: bool = False, timeout_seconds: int = 30,
    on_event: Callable[[JobEvent], None] | None = None, clock: Callable[[], datetime] = UtcNow,
    report_format: str | None = None, report_output: Path | None = None,
) -> NativeConfigurationScanSummary:
    """Run one explicit governed native configuration job with durable source/Finding/report truth.

    Args:
        workspace_root: Existing initialized canonical workspace.
        scope_id: Existing independently registered and authorized exact artifact target scope.
        owner_reference: Explicit executing owner matching selected-read consent.
        selection: One selected native source and pinned executable.
        policy_provider: Fresh synchronous typed operator policy source.
        approve_safe_configuration: Exact True workflow opt-in, independent of permission.
        timeout_seconds: Integer SCAN deadline from one through sixty seconds.
        on_event: Optional fast synchronous canonical event sink.
        clock: Trusted aware authority clock.
        report_format: Optional json/sarif export paired with report_output.
        report_output: New output destination outside the workspace, paired with report_format.

    Returns:
        Actual canonical terminal job, confirmed original acquisitions and separate export outcome.
    """

    ValidateSelection(workspace_root, owner_reference, selection, timeout_seconds)

    if type(approve_safe_configuration) is not bool or not callable(policy_provider) or (
        (report_format is None) != (report_output is None)
    ):
        raise ValueError("Native configuration approval or report options are invalid")

    if not approve_safe_configuration:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    workspace = LocalWorkspaceStore(workspace_root).Open()
    model = LocalModelStore(workspace_root).Open()
    scope = LocalScopeStore(workspace_root).Open(scope_id)
    spec = JobSpec("job:native-configuration-" + uuid4().hex, workspace.workspace_id,
        scope.Reference(), owner_reference, "native.trivy", timeout_seconds=timeout_seconds + 61)
    workflow = NativeConfigurationWorkflow(workspace_root, scope_id, owner_reference, selection,
        policy_provider, timeout_seconds, workspace, model, clock)
    job = ScanJob(spec, workflow, evidence_store=LocalEvidenceStore(workspace_root / "evidence"))
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    first_update = None
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Measure acknowledged durable model publication and present unchanged canonical events."""

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
        task = asyncio.create_task(job.CancelAndWait(owner_reference))

        await Settle(task, asyncio.Event())

        for event in job.EventsSince(cursor):
            Observe(event)

    except BaseException:
        task = asyncio.create_task(job.CancelAndWait(owner_reference))

        await Settle(task, asyncio.Event())

        raise

    snapshot = await job.Wait()
    actual = LocalModelStore(workspace_root).Open()
    report = None

    if report_format is not None and report_output is not None:
        report = ExportConfigurationReport(workspace_root, workflow.saved_model, report_format,
            report_output) if snapshot.state is JobState.COMPLETED and workflow.saved_model is not (
                None
            ) else ConfigurationReportOutcome("not-run", report_format,
                model_revision=actual.revision, failure="scan-not-completed")

    return NativeConfigurationScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, first_update, actual.revision,
        tuple((kind.value, len(actual.Objects(kind))) for kind in ObjectKind), job.EventsSince(),
        tuple(workflow.captures), workflow.Records(), workflow.custody_uncertain or (
            workflow.bridge is not None and workflow.bridge.publication_uncertain), report)
