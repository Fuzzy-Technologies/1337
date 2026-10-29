# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit local-reference export jobs; generated archive scans require separate authority."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from uuid import uuid4

from fuzzy1337.adapters import ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity, ReadArtifactFile
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.jobs import (
    JobContext,
    JobError,
    JobEvent,
    JobFailure,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
    ScanJob,
)
from fuzzy1337.local_image_archive import LocalImageArchivePin
from fuzzy1337.local_image_material import LocalImageMaterialObserver
from fuzzy1337.local_image_policy import (
    LocalImageExecutionClaim,
    LocalImageResolution,
    PrepareLocalImageOperation,
    ValidateCompletedLocalExport,
)
from fuzzy1337.local_image_reference import (
    LOCAL_IMAGE_SOURCE,
    LocalImageOperation,
    LocalImageSelection,
)
from fuzzy1337.model import LocalModelStore, ModelState
from fuzzy1337.native_image_policy import PrivateDirectory
from fuzzy1337.native_image_workflow import SettleNativeImageCleanup
from fuzzy1337.policy import ImpactPolicy, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceState


@dataclass(frozen=True, slots=True)
class LocalImageExportPlan:
    """Pure selected source descriptor; neither a scope registration nor an execution grant."""

    selection: LocalImageSelection

    def ToDict(self) -> dict[str, object]:
        """Render the exact source target and explicit two-phase authority requirement.

        Returns:
            Detached selected descriptor without reading files or contacting Docker.
        """

        return {"schema_version": 1, "workflow": "local-image-export",
            "execution_authorized": False, "descriptor": self.selection.Manifest(),
            "target": json.loads(SerializeContract(self.selection.Target())),
            "capability": "image.local-reference-export", "required_privileges":
                ["local-docker-read"], "archive_scan_requires_separate_scope": True}


def PlanLocalImageExport(selection: LocalImageSelection) -> LocalImageExportPlan:
    """Describe one explicit local source without filesystem reads or daemon access.

    Args:
        selection: Exact typed source and selected read-consent declaration.

    Returns:
        Pure selected source plan without creating scope, claims or scratch.
    """

    if type(selection) is not LocalImageSelection:
        raise ValueError("local image export planning requires an exact selection")
    return LocalImageExportPlan(selection)


@dataclass(frozen=True, slots=True)
class LocalImageExportSummary:
    """Actual job outcome; archive pins are exposed only after confirmed workspace persistence."""

    snapshot: JobSnapshot
    archive_relative_path: str | None
    archive_pin: LocalImageArchivePin | None
    workspace_acknowledged: bool

    def ExitCode(self) -> int:
        """Return zero only for an acknowledged completed export.

        Returns:
            Zero for completion, three for authority, four for failure, or 130 for cancellation.
        """

        if self.snapshot.state is JobState.COMPLETED and self.workspace_acknowledged:
            return 0
        if self.snapshot.state is JobState.CANCELLED:
            return 130
        if self.snapshot.failure is not None and (
            self.snapshot.failure.code is JobFailureCode.AUTHORIZATION
        ):
            return 3
        return 4

    def ToDict(self) -> dict[str, object]:
        """Render factual export results without presenting an export as a scan.

        Returns:
            Terminal job, original records and accepted archive/config identities if confirmed.
        """

        pin = self.archive_pin
        return {"schema_version": 1, "workflow": "local-image-export",
            "job_id": self.snapshot.spec.job_id, "state": self.snapshot.state.value,
            "job": json.loads(SerializeContract(self.snapshot)),
            "failure": None if self.snapshot.failure is None else (
                self.snapshot.failure.code.value),
            "workspace_acknowledged": self.workspace_acknowledged,
            "archive_relative_path": self.archive_relative_path,
            "image_config_id": None if pin is None else pin.image_config_id,
            "archive_sha256": None if pin is None else pin.archive_sha256,
            "archive_size_bytes": None if pin is None else pin.size_bytes,
            "archive_manifest": None if pin is None else pin.Manifest().ToDict(),
            "archive_target": None if pin is None else json.loads(
                SerializeContract(pin.Manifest().Target())),
            "archive_scan_requires_separate_scope": True,
            "evidence_record_references": [item.evidence.evidence_id
                                            for item in self.snapshot.artifacts]}


@dataclass(slots=True)
class LocalImageExportWorkflow:
    """One original inspect/export/recheck job preserving current authority and raw evidence."""

    selection: LocalImageSelection
    scope_id: str
    owner_reference: str
    policy_provider: Callable[[], ImpactPolicy]
    initial_workspace: WorkspaceState
    initial_model: ModelState
    clock: Callable[[], datetime]
    engine: ArtifactPolicyEngine = field(default_factory=ArtifactPolicyEngine, init=False)
    records: list[EvidenceRecord] = field(default_factory=list, init=False)
    acknowledged: bool = field(default=False, init=False)
    persistence_attempted: bool = field(default=False, init=False)
    archive_path: str | None = field(default=None, init=False)
    pin: LocalImageArchivePin | None = field(default=None, init=False)

    def Context(self) -> ArtifactPolicyContext:
        """Reopen current source scope and explicit fresh policy without implicit permissions.

        Returns:
            Same-store current authority and selected executing actor.
        """

        policy = self.policy_provider()
        if type(policy) is not ImpactPolicy:
            raise ValueError("local image export requires a fresh typed policy")
        return ArtifactPolicyContext(LocalScopeStore(self.selection.workspace_root).Open(
            self.scope_id), policy, self.owner_reference)

    def Persist(self, context: JobContext, validate: Callable[[], None] | None = None) -> None:
        """Attempt one CAS preserving original workspace, model and actual retained acquisitions.

        Args:
            context: Original owning job context.
            validate: Fresh final acceptance gate, absent only during failed-job evidence cleanup.
        """

        if self.persistence_attempted:
            return
        root = self.selection.workspace_root
        store = LocalWorkspaceStore(root)
        current = store.Open()
        if current != self.initial_workspace or LocalModelStore(root).Open() != self.initial_model:
            raise ValueError("local image export original workspace or model changed")
        evidence = LocalEvidenceStore(root / "evidence")
        VerifyWorkspaceEvidence(current, evidence)
        VerifyReportEvidence(ReportSnapshot(self.initial_model), root)
        references = {(item.locator, item.role): item for item in current.evidence_references}
        identities = set(current.evidence_record_references)
        for record in self.records:
            if evidence.Get(record.evidence_id) != record:
                raise ValueError("local image export retained manifest changed")
            references[(record.reference.locator, record.reference.role)] = record.reference
            identities.add(record.evidence_id)
        if validate is not None:
            validate()
        self.persistence_attempted = True
        saved = store.Save(replace(current,
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted(identities)),
            scope_references=tuple(sorted({*current.scope_references,
                                           context.Spec.scope_reference})),
            job_references=tuple(sorted({*current.job_references, context.Spec.job_id}))))
        if store.Open() != saved:
            raise ValueError("local image export workspace acknowledgement changed")
        self.acknowledged = True

    async def Run(self, context: JobContext) -> None:
        """Execute three bounded commands and publish one separately scoped immutable archive.

        Args:
            context: Shared job owner of cancellation, events and original evidence.

        Raises:
            JobError: Current authority, provider, acceptance or persistence refuses completion.
        """

        root = self.selection.workspace_root
        phase = JobFailureCode.AUTHORIZATION
        try:
            context.CheckCancellation()
            observer = LocalImageMaterialObserver(self.selection, self.owner_reference,
                "operation:local-export-" + uuid4().hex)
            proof = observer.Observe()
            run = root / ("local-image-export-" + uuid4().hex)
            run.mkdir(mode=0o700)
            scratch = run / "scratch"
            scratch.mkdir(mode=0o700)
            for name in ("home", "docker-config"):
                (scratch / name).mkdir(mode=0o700)
            config = scratch / "docker-config/config.json"
            with config.open("xb") as stream:
                stream.write(b"{}\n")
            config.chmod(0o600)
            run_identity = PrivateDirectory(run)
            claims: list[LocalImageExecutionClaim] = []
            resolution: LocalImageResolution | None = None
            pin: LocalImageArchivePin | None = None
            archive_raw: bytes | None = None
            for completed, operation in enumerate(LocalImageOperation, 1):
                context.CheckCancellation()
                phase = JobFailureCode.AUTHORIZATION
                prepared = PrepareLocalImageOperation(self.engine, observer, proof, operation,
                    scratch, resolution=resolution)
                grant = self.engine.AuthorizeLocalImageOperation(prepared, self.Context(),
                    at=self.clock(), approve_local_image=True)
                claim, request = self.engine.ClaimLocalImageExecution(grant, prepared,
                    self.Context(), at=self.clock())
                claims.append(claim)
                self.engine.BindLocalImageExecution(claim, request, self.Context(), at=self.clock())

                def PreLaunch(actual: LocalExecutionRequest) -> None:
                    """Bind the exact executor entry to current original source authority.

                    Args:
                        actual: Full actual request passed by the executor before startup.
                    """

                    context.CheckCancellation()
                    self.engine.ValidateLocalImageClaim(claim, actual, self.Context(),
                                                         at=self.clock())

                phase = JobFailureCode.PROVIDER
                started = datetime.now(UTC).isoformat()
                result = await LocalExecutor(root).Execute(request, pre_launch=PreLaunch,
                    cancellation=context.Cancellation, own_descendants=True)
                finished = datetime.now(UTC).isoformat()
                provenance = EvidenceProvenance(context.Spec.workspace_id,
                    context.Spec.scope_reference, LOCAL_IMAGE_SOURCE, "1", None, started, finished,
                    InvocationDigest(request.invocation), result.execution)
                receipt = {"schema_version": 1, "operation": operation.value,
                    "operation_reference": proof.operation_reference, "request": request,
                    "execution": result.execution, "termination": result.termination,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "stdout_size": len(result.stdout), "stderr_size": len(result.stderr),
                    "event_count": len(result.events), "plan": grant.plan,
                    "selected_material": prepared.Payload()}
                for role, raw, media in (
                    ("stdout", result.stdout, "application/octet-stream"),
                    ("stderr", result.stderr, "application/octet-stream"),
                    ("receipt", SerializeContract(receipt).encode(), "application/json"),
                ):
                    artifact = context.CaptureEvidence(raw, "local-image-" + operation.value +
                        "-" + role, media, provenance)
                    self.records.append(artifact.evidence)
                phase = JobFailureCode.NORMALIZATION
                if result.execution.state is not ExecutionState.SUCCEEDED:
                    phase = JobFailureCode.PROVIDER
                if result.termination is ExecutionTermination.TIMEOUT:
                    phase = JobFailureCode.TIMEOUT
                elif result.termination is ExecutionTermination.OUTPUT_LIMIT:
                    phase = JobFailureCode.OUTPUT_LIMIT
                accepted = self.engine.AcceptLocalImageExecution(claim, request, result,
                    self.Context(), at=self.clock())
                if operation is LocalImageOperation.INSPECT:
                    if type(accepted) is not LocalImageResolution:
                        raise ValueError("local image inspect association is missing")
                    resolution = accepted
                elif operation is LocalImageOperation.EXPORT:
                    if type(accepted) is not LocalImageArchivePin:
                        raise ValueError("local image archive pin is missing")
                    pin, archive_raw = accepted, result.stdout
                context.Progress(completed, 3)
            if resolution is None or pin is None or archive_raw is None:
                raise ValueError("local image export original phase association is missing")

            def Validate() -> None:
                """Require original completed custody and current authority before publication."""

                context.CheckCancellation()
                if resolution is None or pin is None or PrivateDirectory(run) != run_identity:
                    raise ValueError("local image export publication association changed")
                ValidateCompletedLocalExport(self.engine, tuple(claims), resolution, pin,
                    self.Context(), at=self.clock())

            phase = JobFailureCode.AUTHORIZATION
            Validate()
            phase = JobFailureCode.STORAGE
            archive = run / "image.tar"
            descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(archive_raw)
                stream.flush()
                os.fsync(stream.fileno())
            identity = PhysicalIdentity(ArtifactPathInfo(archive))
            actual = ReadArtifactFile(archive, "image.tar", max_bytes=pin.size_bytes)
            if actual.sha256 != pin.archive_sha256 or actual.size_bytes != pin.size_bytes:
                raise ValueError("local image export published archive differs from original bytes")

            def ValidatePublication() -> None:
                """Recheck original archive identity and all current source authority before CAS."""

                Validate()
                if PhysicalIdentity(ArtifactPathInfo(archive)) != identity:
                    raise ValueError("local image export archive physical identity changed")

            self.Persist(context, ValidatePublication)
            self.archive_path = archive.relative_to(root).as_posix()
            self.pin = pin
        except asyncio.CancelledError:
            raise
        except ArtifactDeniedError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Local image export current authority was refused")) from None
        except Exception:
            raise JobError(JobFailure(phase, "Local image export did not complete")) from None
        finally:
            if not self.persistence_attempted:
                try:
                    self.Persist(context)
                except Exception:
                    raise JobError(JobFailure(JobFailureCode.STORAGE,
                        "Local image export evidence references were not acknowledged")) from None


async def ExportLocalImage(selection: LocalImageSelection, scope_id: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, approve_local_image: bool = False,
    on_event: Callable[[JobEvent], None] | None = None, clock: Callable[[], datetime] = UtcNow,
) -> LocalImageExportSummary:
    """Run an explicitly approved local export without authorizing the generated archive scan.

    Args:
        selection: Exact trusted executable, local reference, Unix endpoint and owning workspace.
        scope_id: Already registered exact source descriptor scope.
        owner_reference: Actor matching the explicit selected read consent.
        policy_provider: Fresh typed source permission supplier.
        approve_local_image: Exact explicit SAFE workflow approval, independent of policy.
        on_event: Optional fast unchanged canonical event consumer.
        clock: Trusted aware authority clock.

    Returns:
        Actual terminal job and accepted archive only after confirmed workspace persistence.
    """

    PlanLocalImageExport(selection)
    if approve_local_image is not True or not callable(policy_provider) or (
        owner_reference != selection.read_consent.actor_ref
    ):
        raise ValueError("local image export requires explicit approval and matching read actor")
    root = selection.workspace_root
    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    evidence = LocalEvidenceStore(root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    VerifyReportEvidence(ReportSnapshot(model), root)
    scope = LocalScopeStore(root).Open(scope_id)
    spec = JobSpec("job:local-image-export-" + uuid4().hex, workspace.workspace_id,
        scope.Reference(), owner_reference, LOCAL_IMAGE_SOURCE, timeout_seconds=65)
    workflow = LocalImageExportWorkflow(selection, scope_id, owner_reference, policy_provider,
                                        workspace, model, clock)
    job = ScanJob(spec, workflow, evidence_store=evidence)
    cursor = -1
    job.Start()
    try:
        async for event in job.Events():
            cursor = event.sequence
            if on_event is not None:
                on_event(event)
    except BaseException:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))
        await SettleNativeImageCleanup(cleanup)
        if on_event is not None:
            for event in job.EventsSince(cursor):
                on_event(event)
        raise
    snapshot = job.Snapshot()
    accepted = snapshot.state is JobState.COMPLETED and workflow.acknowledged
    return LocalImageExportSummary(snapshot, workflow.archive_path if accepted else None,
        workflow.pin if accepted else None, workflow.acknowledged)
