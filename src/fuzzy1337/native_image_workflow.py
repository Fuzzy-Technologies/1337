# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit bounded native image planning and paired governed product jobs."""

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

from fuzzy1337.adapters import (
    AdapterInvocation,
    EvidenceReference,
    ExecutionState,
    SerializeContract,
)
from fuzzy1337.adapters.trivy import TRIVY_MAX_TIMEOUT_SECONDS
from fuzzy1337.artifact_inputs import ArtifactFile, ArtifactManifest, ArtifactProfile, ArtifactRole
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import ExecutionTermination, LocalExecutionRequest
from fuzzy1337.image_workflow import ExportImageReport, ImageReportOutcome
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
from fuzzy1337.native_image_admission import ApplyVerifiedNativeTrivyImages
from fuzzy1337.native_image_bounded_capture import (
    CaptureBoundedNativeTrivyOperation,
    Finalization,
    NativeImageBoundedCaptureError,
)
from fuzzy1337.native_image_capture import (
    NativeTrivyOperation,
    NativeTrivyOperationCapture,
    NativeTrivySelection,
)
from fuzzy1337.native_image_observation import (
    NativeImageMaterialObserver,
    NativeImageMaterialProof,
    NativeImageObservationBudget,
    NativeImageObservationError,
)
from fuzzy1337.native_image_policy import (
    NativeImageExecutionClaim,
    NativeImageOperationGrant,
    NativeImageOperationPlan,
    NativeImageVersionPrerequisite,
    PreparedNativeImageOperation,
    PrepareNativeImageOperation,
)
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

NATIVE_IMAGE_SOURCE = "native.trivy"
NATIVE_ROLES = {
    "provider-version": (16 * 1024, "application/json"),
    "provider-version-stderr": (16 * 1024, "text/plain"),
    "native-version-receipt": (256 * 1024, "application/json"),
    "stdout": (4 * 1024 * 1024, "application/json"),
    "stderr": (1024 * 1024, "text/plain"),
    "native-scan-receipt": (16 * 1024 * 1024, "application/json"),
}


def ValidateSelection(workspace_root: Path, owner_reference: str,
                      selection: NativeTrivySelection, timeout_seconds: int) -> None:
    """Reject incompatible declarations without selected content reads.

    Args:
        workspace_root: Existing selected physical workspace.
        owner_reference: Explicit executing actor, independent from the scope attester.
        selection: Exact typed explicit native selection and independent read consent.
        timeout_seconds: Existing native adapter scan deadline.

    Raises:
        ValueError: Ownership, workspace or finite timeout declarations differ.
    """

    if type(selection) is not NativeTrivySelection or (
        selection.workspace_root != workspace_root
        or selection.read_consent.actor_ref != owner_reference
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= TRIVY_MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("native image workflow requires exact selections and finite limits")


def CurrentContext(root: Path, scope_id: str, owner_reference: str,
                   policy_provider: Callable[[], ImpactPolicy]) -> ArtifactPolicyContext:
    """Reopen exact scope and typed policy without manufacturing actor authority.

    Args:
        root: Existing owning physical workspace.
        scope_id: Explicit already recorded scope identifier.
        owner_reference: Executing actor matching selected read consent.
        policy_provider: Fresh synchronous typed operator policy source.

    Returns:
        Current complete scope/policy/actor context, without an execution grant.
    """

    policy = policy_provider()
    if type(policy) is not ImpactPolicy:
        raise ValueError("native image requires a fresh typed policy")
    return ArtifactPolicyContext(LocalScopeStore(root).Open(scope_id), policy, owner_reference)


@dataclass(frozen=True, slots=True)
class NativeImageScanPlan:
    """Descriptive material preview or scoped VERSION plan; neither permits execution."""

    input_manifest: ArtifactManifest
    phase: str
    scan_timeout_seconds: int
    authority_plan: NativeImageOperationPlan | None = None
    version_invocation: AdapterInvocation | None = None

    @property
    def Target(self) -> Target:
        """Return the existing explicit ARTIFACT identity without registering it.

        Returns:
            Exact canonical input-manifest target.
        """

        return self.input_manifest.Target()

    def ToDict(self) -> dict[str, object]:
        """Render bounded planning metadata without observation paths, raw content or grants.

        Returns:
            Explicit preview/plan phase, input target and deferred original-SCAN requirement.
        """

        return {"schema_version": 1, "workflow": "native-image", "phase": self.phase,
            "execution_authorized": False, "input_manifest": self.input_manifest.ToDict(),
            "target": json.loads(SerializeContract(self.Target)),
            "version_invocation": None if self.version_invocation is None else (
                json.loads(SerializeContract(self.version_invocation))),
            "scan_recipe": {"timeout_seconds": self.scan_timeout_seconds,
                            "requires_original_version": True}}


async def PlanNativeImageScan(
    workspace_root: Path, owner_reference: str, selection: NativeTrivySelection,
    *, scope_id: str | None = None, policy_provider: Callable[[], ImpactPolicy] | None = None,
    timeout_seconds: int = 30, clock: Callable[[], datetime] = UtcNow,
) -> NativeImageScanPlan:
    """Observe material once, then optionally plan strictly registered VERSION without Trivy.

    Args:
        workspace_root: Existing owning workspace.
        owner_reference: Explicit selected read-consent actor.
        selection: Exact workspace-relative archive/cache and absolute trusted executable.
        scope_id: Absent only for explicit material preview.
        policy_provider: Absent with scope_id, or fresh typed policy for a scoped plan.
        timeout_seconds: Deferred native scan deadline from one through 3600 seconds.
        clock: Trusted aware authority clock.

    Returns:
        Material preview when both authority arguments are absent; otherwise a strict scoped
        VERSION plan. Denied scoped planning never falls back to a material preview.

    Raises:
        ValueError: Selection or paired authority arguments are invalid.
        ArtifactDeniedError: Scoped planning is refused by current artifact authority.
        NativeImageObservationError: The bounded read/cleanup could not supply original proof.
    """

    ValidateSelection(workspace_root, owner_reference, selection, timeout_seconds)
    if (scope_id is None) != (policy_provider is None):
        raise ValueError("native image scoped planning requires scope and policy together")
    workspace = LocalWorkspaceStore(workspace_root).Open()
    LocalModelStore(workspace_root).Open()
    pair = "operation:native-image-plan-" + uuid4().hex
    observer = NativeImageMaterialObserver(selection, workspace.workspace_id, owner_reference)
    proof = await observer.Observe(NativeImageObservationBudget(planning=True),
                                   operation_reference=pair)
    archive = proof.facts[0]
    if archive.size_bytes is None or archive.sha256 is None:
        raise NativeImageObservationError("native image archive material is unverified")
    manifest = ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT,
                                (ArtifactFile("image.tar", archive.size_bytes, archive.sha256),))
    if scope_id is None or policy_provider is None:
        return NativeImageScanPlan(manifest, "material-preview", timeout_seconds)
    prepared = PrepareNativeImageOperation(NativeTrivyOperation.VERSION, selection,
        LocalEvidenceStore(workspace_root / "evidence"), observer=observer,
        material_proof=proof, operation_reference=pair, timeout_seconds=timeout_seconds)
    plan = ArtifactPolicyEngine().PlanNativeImageOperation(prepared,
        CurrentContext(workspace_root, scope_id, owner_reference, policy_provider),
        observer=observer, material_proof=proof, at=clock())
    return NativeImageScanPlan(manifest, "scoped-version-plan", timeout_seconds,
                               plan, prepared.invocation)


class NativeJobEvidenceStore(LocalEvidenceStore):
    """Fixed collector bridge; the job itself retains its separate plain canonical store.

    Args:
        context: Owning running native job context.
        root: Exact canonical evidence root.
    """

    def __init__(self, context: JobContext, root: Path) -> None:
        """Bind original acquisitions without granting execution or changing evidence identities."""

        super().__init__(root)
        self.context = context
        self.records: dict[str, EvidenceRecord] = {}
        self.publication_uncertain = False

    def Read(self, reference: EvidenceReference) -> bytes:
        """Preflight closed original role budgets before the evidence owner's eager read.

        Args:
            reference: Original native reference from a manifest or bounded recovery attempt.

        Returns:
            Exact canonical bytes after role/media/size and integrity checks.
        """

        maximum, media = NATIVE_ROLES.get(reference.role, (0, ""))
        if reference.role not in NATIVE_ROLES or reference.media_type != media or (
            reference.size_bytes is None
        ) or (
            reference.size_bytes > maximum
        ):
            raise ValueError("native job evidence is outside its original closed role bounds")
        return super().Read(reference)

    def Confirm(self, expected: EvidenceRecord, data: bytes) -> None:
        """Retain only a bounded independently verified exact original manifest and blob.

        Args:
            expected: Expected content-addressed original, including full original provenance.
            data: Exact original already bounded bytes supplied to Put.
        """

        if self.Get(expected.evidence_id) != expected or self.Read(expected.reference) != data:
            raise EvidenceError("native job original evidence acknowledgement differs")
        previous = self.records.get(expected.reference.role)
        if previous is not None and previous != expected:
            raise ValueError("native job cannot replace an original operation role")
        self.records[expected.reference.role] = expected

    def Put(self, data: bytes, role: str, media_type: str,
            provenance: EvidenceProvenance) -> EvidenceRecord:
        """Publish exact originals once and preserve verified acquisition truth after lost ack.

        Args:
            data: Closed bounded exact original collector bytes.
            role: One of the unchanged six native roles.
            media_type: Fixed original role media.
            provenance: Exact collector provenance matching this job.

        Returns:
            Unchanged original record after confirmed job attachment and readback.

        Raises:
            ValueError: Role, bytes or provenance differs from this native job.
            BaseException: Publication/event failure is rethrown even if readback finds evidence.
        """

        maximum, media = NATIVE_ROLES.get(role, (0, ""))
        if role not in NATIVE_ROLES or not isinstance(data, bytes) or (
            media_type != media or len(data) > maximum
        ) or (
            provenance.workspace_id != self.context.Spec.workspace_id
            or provenance.scope_reference != self.context.Spec.scope_reference
            or provenance.source_id != NATIVE_IMAGE_SOURCE or provenance.source_version != "1"
        ):
            raise ValueError("native job evidence role or original provenance differs")
        digest = hashlib.sha256(data).hexdigest()
        expected = EvidenceRecord(EvidenceReference(role, "blobs/sha256/" + digest,
                                                    digest, media_type, len(data)), provenance)
        previous = self.records.get(role)
        if previous is not None and previous != expected:
            raise ValueError("native job cannot replace an original operation role")
        try:
            artifact = self.context.CaptureEvidence(data, role, media_type, provenance)
            if artifact.job_id != self.context.Spec.job_id or (
                artifact.workspace_id != self.context.Spec.workspace_id
                or artifact.evidence != expected
            ):
                raise EvidenceError("native job evidence attachment differs")
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
class NativeImageScanSummary:
    """Actual native job, saved-model, original acquisition and separate export truth."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    first_model_update_seconds: float | None
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]
    captures: tuple[NativeTrivyOperationCapture, ...]
    retained_records: tuple[EvidenceRecord, ...]
    custody_uncertain: bool = False
    report: ImageReportOutcome | None = None

    def ToDict(self) -> dict[str, object]:
        """Render native facts without raw bytes, selected paths or private recovery locations.

        Returns:
            Distinct schema-one native workflow with unchanged canonical jobs and original IDs.
        """

        operations = tuple({"operation": item.operation.value,
            "authorization_id": item.request.authorization.authorization_id,
            "capture_sha256": item.Digest(), "execution": item.outcome.execution,
            "termination": item.outcome.termination.value, "acceptance_refusal": item.refusal,
            "started_at": item.started_at, "finished_at": item.finished_at}
            for item in self.captures)
        return {"schema_version": 1, "workflow": "native-image", "source_id": NATIVE_IMAGE_SOURCE,
            "state": self.snapshot.state.value, "scan_completeness": "not-assessed",
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "first_model_update_seconds": self.first_model_update_seconds,
            "model_revision": self.model_revision, "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
            "operations": json.loads(SerializeContract(operations)),
            "retained_evidence_ids": tuple(record.evidence_id for record in self.retained_records),
            "custody_uncertain": self.custody_uncertain,
            "report": None if self.report is None else json.loads(SerializeContract(self.report))}

    def ExitCode(self) -> int:
        """Preserve existing terminal and separate report exit meanings.

        Returns:
            Zero on completion, three for authority, four for failure or 130 for cancellation.
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
class NativeImageWorkflow:
    """One paired native job retaining original custody and one-attempt durable save truth."""

    workspace_root: Path
    scope_id: str
    owner_reference: str
    selection: NativeTrivySelection
    policy_provider: Callable[[], ImpactPolicy]
    timeout_seconds: int
    initial_workspace: WorkspaceState
    initial_model: ModelState
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]
    captures: list[NativeTrivyOperationCapture] = field(default_factory=list, init=False)
    engine: ArtifactPolicyEngine = field(default_factory=ArtifactPolicyEngine, init=False)
    bridge: NativeJobEvidenceStore | None = field(default=None, init=False)
    saved_model: ModelState | None = field(default=None, init=False)
    workspace_attempted: bool = field(default=False, init=False)
    custody_uncertain: bool = field(default=False, init=False)

    def Context(self) -> ArtifactPolicyContext:
        """Reopen the current complete typed authority context.

        Returns:
            Current scope, independently attested consent and explicit executing actor/policy.
        """

        return CurrentContext(self.workspace_root, self.scope_id, self.owner_reference,
                              self.policy_provider)

    def Records(self) -> tuple[EvidenceRecord, ...]:
        """Return only independently confirmed original acquisitions.

        Returns:
            At most six original role records, without private journal paths or raw content.
        """

        return () if self.bridge is None else tuple(self.bridge.records.values())

    def PersistReferences(self, context: JobContext, *, validate_success: Callable[[], None] | None
                          = None) -> None:
        """Attempt one original-workspace CAS for actual acquisitions and current model facts.

        Args:
            context: Original native job whose bounded acquisitions may survive failure.
            validate_success: Fresh pair/cancellation check immediately before a successful save;
                absent only for acquisition-only cleanup after failure.

        Raises:
            JobError: Original workspace state, evidence or durable acknowledgement is unconfirmed.
        """

        if self.workspace_attempted:
            return
        try:
            store = LocalWorkspaceStore(self.workspace_root)
            workspace = store.Open()
            model = LocalModelStore(self.workspace_root).Open()
            if workspace != self.initial_workspace or (
                self.saved_model is not None and model != self.saved_model
            ):
                raise WorkspaceConflictError("native image original save state changed")
            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            VerifyWorkspaceEvidence(workspace, evidence)
            VerifyReportEvidence(ReportSnapshot(model), self.workspace_root)
            records = {record.evidence_id: record for record in self.Records()}
            records.update((artifact.evidence.evidence_id, artifact.evidence)
                           for artifact in self.snapshot().artifacts)
            references = {(item.locator, item.role): item for item in workspace.evidence_references}
            identities = set(workspace.evidence_record_references)
            if self.bridge is not None:
                for record in records.values():
                    if self.bridge.Get(record.evidence_id) != record:
                        raise EvidenceError("native image original retained manifest differs")
                    references[(record.reference.locator, record.reference.role)] = record.reference
                    identities.add(record.evidence_id)
            object_refs = {item.Reference() for item in model.objects}
            if not set(workspace.object_references) <= object_refs:
                raise ValueError("native image prior object reference is missing")
            if validate_success is not None:
                validate_success()
            self.workspace_attempted = True
            store.Save(replace(workspace,
                scope_references=tuple(sorted({*workspace.scope_references,
                                               context.Spec.scope_reference})),
                object_references=tuple(sorted(object_refs)),
                evidence_references=tuple(references[key] for key in sorted(references)),
                evidence_record_references=tuple(sorted(identities)),
                job_references=tuple(sorted({*workspace.job_references, context.Spec.job_id}))))
        except ArtifactDeniedError:
            raise
        except (EvidenceError, OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Could not preserve native image workspace references")) from None

    def RequireProcessSuccess(self, capture: NativeTrivyOperationCapture) -> None:
        """Keep original process failure categories distinct from successful execution.

        Args:
            capture: Original already retained native process outcome.

        Raises:
            JobError: The original process did not successfully exit with status zero.
        """

        raw = capture.outcome
        if raw.execution.state is ExecutionState.SUCCEEDED and (
            raw.termination is ExecutionTermination.PROCESS_EXIT and raw.execution.exit_code == 0
        ):
            return
        code = {ExecutionTermination.TIMEOUT: JobFailureCode.TIMEOUT,
                ExecutionTermination.OUTPUT_LIMIT: JobFailureCode.OUTPUT_LIMIT}.get(
                    raw.termination, JobFailureCode.PROVIDER)
        raise JobError(JobFailure(code, "Native image owned process did not succeed"))

    def LaunchValidator(self, claim: NativeImageExecutionClaim,
                        observer: NativeImageMaterialObserver,
                        proof: NativeImageMaterialProof) -> Callable[[LocalExecutionRequest], None]:
        """Create one private once-binding callback per fresh claimed attempt.

        Args:
            claim: Original newly consumed current operation claim.
            observer: Exact original whole-pair material issuer.
            proof: Exact original proof selected for this particular operation claim.

        Returns:
            Fresh synchronous callback whose first call always binds, with no restored success.
        """

        first = True

        def Validate(actual: LocalExecutionRequest) -> None:
            """Refresh original authority and bind once before the first actual startup.

            Args:
                actual: Exact request created by the trusted bounded collector.
            """

            nonlocal first
            if first:
                self.engine.BindNativeImageRequest(claim, actual, self.Context(),
                    observer=observer, material_proof=proof, at=self.clock())
                first = False
            else:
                self.engine.ValidateNativeImageClaim(claim, actual, self.Context(),
                    observer=observer, material_proof=proof, at=self.clock())

        return Validate

    async def Run(self, context: JobContext) -> None:
        """Execute the original governed pair and publish a delta only after durable saves.

        Args:
            context: Original running job, cancellation and evidence publication owner.

        Raises:
            JobError: Current authority, custody, execution or durable completion is refused.
        """

        phase = JobFailureCode.STORAGE
        delta: ModelDelta | None = None
        budget = NativeImageObservationBudget(overall_deadline=time.monotonic()
                                               + self.timeout_seconds + 60)
        observer = NativeImageMaterialObserver(self.selection, context.Spec.workspace_id,
                                                self.owner_reference)
        pair = "operation:native-image-" + uuid4().hex
        prerequisite: NativeImageVersionPrerequisite | None = None
        scan_grant: NativeImageOperationGrant | None = None
        scan_claim: NativeImageExecutionClaim | None = None
        scan_prepared: PreparedNativeImageOperation | None = None
        latest: NativeImageMaterialProof | None = None
        try:
            VerifyWorkspaceEvidence(self.initial_workspace,
                                    LocalEvidenceStore(self.workspace_root / "evidence"))
            VerifyReportEvidence(ReportSnapshot(self.initial_model), self.workspace_root)
            self.bridge = NativeJobEvidenceStore(context, self.workspace_root / "evidence")
            phase = JobFailureCode.AUTHORIZATION
            self.Context()
            context.CheckCancellation()
            phase = JobFailureCode.PROVIDER
            latest = await observer.Observe(budget, operation_reference=pair,
                                            cancellation=context.Cancellation)
            for operation in (NativeTrivyOperation.VERSION, NativeTrivyOperation.SCAN):
                with Finalization(budget):
                    phase = JobFailureCode.AUTHORIZATION
                    prepared = PrepareNativeImageOperation(operation, self.selection, self.bridge,
                        observer=observer, material_proof=latest, operation_reference=pair,
                        timeout_seconds=self.timeout_seconds, version_prerequisite=prerequisite)
                    grant = self.engine.AuthorizeNativeImageOperation(prepared, self.Context(),
                        observer=observer, material_proof=latest, approve_safe_image=True,
                        at=self.clock())
                    claim = self.engine.ClaimNativeImageExecution(grant, prepared, self.Context(),
                        observer=observer, material_proof=latest, at=self.clock())
                    context.CheckCancellation()
                original_proof = latest
                validate = self.LaunchValidator(claim, observer, original_proof)
                phase = JobFailureCode.PROVIDER
                result = await CaptureBoundedNativeTrivyOperation(operation, self.selection,
                    prepared.invocation, grant.authorization, self.bridge,
                    context.Spec.workspace_id, self.owner_reference,
                    observer=observer, budget=budget,
                    material_proof=original_proof, operation_reference=pair,
                    version_prerequisite=None if prerequisite is None else prerequisite.capture,
                    cancellation=context.Cancellation, validate_authority=validate)
                capture = result.capture
                self.captures.append(capture)
                context.CheckCancellation()
                self.RequireProcessSuccess(capture)
                if capture.refusal == "authority-unverified":
                    raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)
                context.CheckCancellation()
                latest = result.material_proof
                if latest is None:
                    raise NativeImageObservationError("native image post material is unverified")
                with Finalization(budget):
                    phase = JobFailureCode.AUTHORIZATION
                    if operation is NativeTrivyOperation.VERSION:
                        prerequisite = self.engine.AcceptNativeImageVersion(claim, capture,
                            self.Context(), observer=observer, material_proof=latest,
                            at=self.clock())
                    else:
                        self.engine.ValidateNativeImageCapture(claim, capture, self.Context(),
                            observer=observer, material_proof=latest, at=self.clock())
                        scan_prepared, scan_grant, scan_claim = prepared, grant, claim
                context.Progress(len(self.captures), 2)
            assert prerequisite is not None and scan_grant is not None and scan_claim is not None, (
                "An accepted original pair must exist before native final projection."
            )
            assert scan_prepared is not None and latest is not None, (
                "The original SCAN and latest issued material proof must remain attached."
            )

            def ValidatePair() -> None:
                """Require both current original grants and cleanup-safe persistent bindings."""

                context.CheckCancellation()
                self.engine.ValidateNativeImagePairFresh(prerequisite, scan_prepared, scan_grant,
                    scan_claim, self.captures[-1], self.Context(), observer=observer,
                    material_proof=latest, at=self.clock())

            with Finalization(budget):
                phase = JobFailureCode.STORAGE
                original = LocalModelStore(self.workspace_root).Open()
                if original != self.initial_model:
                    raise WorkspaceConflictError("native image original model snapshot changed")
                phase = JobFailureCode.NORMALIZATION
                proposal, delta = ApplyVerifiedNativeTrivyImages(original,
                    self.captures[0], self.captures[1], self.workspace_root)
                phase = JobFailureCode.AUTHORIZATION
                ValidatePair()
                phase = JobFailureCode.STORAGE
                self.saved_model = LocalModelStore(self.workspace_root).Save(proposal,
                    expected_revision=original.revision)
                self.PersistReferences(context, validate_success=ValidatePair)
        except ArtifactDeniedError as error:
            code = JobFailureCode.STORAGE if error.reason is ArtifactDenialReason.STORAGE else (
                JobFailureCode.AUTHORIZATION)
            raise JobError(JobFailure(code, "Native image current authority was refused")) from None
        except NativeImageBoundedCaptureError:
            self.custody_uncertain = True
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Native image original custody is unconfirmed")) from None
        except (EvidenceError, OSError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Native image local storage is unconfirmed")) from None
        except (ValueError, TypeError):
            raise JobError(JobFailure(phase, "Native image workflow could not complete")) from None
        finally:
            self.PersistReferences(context)
        if delta is not None and delta.revision != delta.previous_revision:
            context.ModelChanged(delta)


async def ScanNativeImage(
    workspace_root: Path, scope_id: str, owner_reference: str, selection: NativeTrivySelection,
    policy_provider: Callable[[], ImpactPolicy], *, approve_safe_image: bool = False,
    timeout_seconds: int = 30, on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow, report_format: str | None = None,
    report_output: Path | None = None,
) -> NativeImageScanSummary:
    """Run one explicit native paired job and expose actual original and saved-state truth.

    Args:
        workspace_root: Existing canonical owning physical workspace.
        scope_id: Already registered exact artifact scope with independently recorded consent.
        owner_reference: Executing actor matching observer and explicit selected read consent.
        selection: Exact existing native archive/cache/executable selection without discovery.
        policy_provider: Fresh synchronous typed native capability policy source.
        approve_safe_image: Explicit workflow approval, never a policy permission.
        timeout_seconds: Native adapter SCAN deadline from one through 3600 seconds.
        on_event: Optional fast synchronous unchanged canonical event sink.
        clock: Trusted aware authority clock.
        report_format: Optional existing json/sarif export request.
        report_output: Explicit new destination paired with report_format.

    Returns:
        Measured native terminal job, original acquisitions, actual model and separate export truth.

    Raises:
        ValueError: Explicit declarations or report options are incompatible.
        OSError: Initial canonical workspace/model/scope cannot be opened.
    """

    ValidateSelection(workspace_root, owner_reference, selection, timeout_seconds)
    if not callable(policy_provider) or type(approve_safe_image) is not bool or (
        (report_format is None) != (report_output is None)
    ):
        raise ValueError("native image approval or report options are invalid")
    if not approve_safe_image:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)
    workspace = LocalWorkspaceStore(workspace_root).Open()
    model = LocalModelStore(workspace_root).Open()
    scope = LocalScopeStore(workspace_root).Open(scope_id)
    spec = JobSpec("job:native-image-" + uuid4().hex, workspace.workspace_id, scope.Reference(),
        owner_reference, NATIVE_IMAGE_SOURCE, timeout_seconds=timeout_seconds + 61)

    def Snapshot() -> JobSnapshot:
        """Return only the original owning job's factual snapshot."""

        return job.Snapshot()

    workflow = NativeImageWorkflow(workspace_root, scope_id, owner_reference, selection,
        policy_provider, timeout_seconds, workspace, model, Snapshot, clock)
    job = ScanJob(spec, workflow, evidence_store=LocalEvidenceStore(workspace_root / "evidence"))
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    first_update: float | None = None
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Measure acknowledged durable projection and present the unchanged canonical event.

        Args:
            event: Original ordered job event.
        """

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
    except BaseException:
        await job.CancelAndWait(owner_reference)
        raise
    snapshot = await job.Wait()
    actual = LocalModelStore(workspace_root).Open()
    export = None
    if report_format is not None and report_output is not None:
        export = (ExportImageReport(workspace_root, workflow.saved_model,
                                    report_format, report_output)
            if snapshot.state is JobState.COMPLETED and workflow.saved_model is not None else
            ImageReportOutcome("not-run", report_format, model_revision=actual.revision,
                               failure="scan-not-completed"))
    return NativeImageScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, first_update, actual.revision,
        tuple((kind.value, len(actual.Objects(kind))) for kind in ObjectKind), job.EventsSince(),
        tuple(workflow.captures), workflow.Records(), workflow.custody_uncertain or (
            workflow.bridge is not None and workflow.bridge.publication_uncertain), export)
