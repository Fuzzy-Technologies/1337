# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit local-reference export jobs; generated archive scans require separate authority."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import EvidenceReference, ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity, ReadArtifactFile
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
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
from fuzzy1337.local_image_archive import (
    InspectConfigId,
    JsonDocument,
    LocalImageArchivePin,
    VerifyDockerSave,
)
from fuzzy1337.local_image_material import LocalImageMaterialObserver
from fuzzy1337.local_image_policy import (
    LocalImageExecutionClaim,
    LocalImageResolution,
    PrepareLocalImageOperation,
    ValidateCompletedLocalExport,
)
from fuzzy1337.local_image_reference import (
    LOCAL_IMAGE_ARCHIVE_BYTES,
    LOCAL_IMAGE_INSPECT_BYTES,
    LOCAL_IMAGE_PROFILE,
    LOCAL_IMAGE_SOURCE,
    LOCAL_IMAGE_STDERR_BYTES,
    LocalImageOperation,
    LocalImageSelection,
)
from fuzzy1337.model import LocalModelStore, ModelState
from fuzzy1337.native_image_policy import PrivateDirectory
from fuzzy1337.native_image_workflow import SettleNativeImageCleanup
from fuzzy1337.policy import Digest, ImpactPolicy, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields, WorkspaceState

_COMPLETION_ROLE = "local-image-export-completion"
_COMPLETION_BYTES = 4 * 1024
_OPERATION_RECEIPT_BYTES = 256 * 1024
_JOB_PREFIX = "job:local-image-export-"
_OPERATION_PREFIX = "operation:local-export-"
_RUN_PREFIX = "local-image-export-"
_STREAM_ROLES = ("stdout", "stderr", "receipt")
_JSON_MEDIA = "application/json"
_STREAM_MEDIA = "application/octet-stream"
_EVIDENCE_LIMITS = {
    **{f"local-image-{operation.value}-{role}": (maximum, media)
       for operation in LocalImageOperation
       for role, maximum, media in (
           ("stdout", LOCAL_IMAGE_ARCHIVE_BYTES if operation is LocalImageOperation.EXPORT
            else LOCAL_IMAGE_INSPECT_BYTES, _STREAM_MEDIA),
           ("stderr", LOCAL_IMAGE_STDERR_BYTES, _STREAM_MEDIA),
           ("receipt", _OPERATION_RECEIPT_BYTES, _JSON_MEDIA),
       )},
    _COMPLETION_ROLE: (_COMPLETION_BYTES, _JSON_MEDIA),
}


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
    """Actual job outcome; archive pins require confirmed workspace persistence.

    The optional SDK receipt ID identifies separate offline completion evidence.
    It is absent unless retention is requested and publication is confirmed. The legacy job
    snapshot and JSON receipt contain the original acquisition records.
    """

    snapshot: JobSnapshot
    archive_relative_path: str | None
    archive_pin: LocalImageArchivePin | None
    workspace_acknowledged: bool
    completion_record_reference: str | None = None

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
        proposal = replace(current,
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted(identities)),
            scope_references=tuple(sorted({*current.scope_references,
                                           context.Spec.scope_reference})),
            job_references=tuple(sorted({*current.job_references, context.Spec.job_id})))
        expected = replace(proposal, revision=current.revision + 1)
        saved = store.Save(proposal)
        if type(saved) is not WorkspaceState or saved != expected:
            raise ValueError("local image export workspace acknowledgement changed")
        actual = store.Open()
        if type(actual) is not WorkspaceState or actual != expected:
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
            attempt = ExportAttempt(context.Spec.job_id)
            observer = LocalImageMaterialObserver(self.selection, self.owner_reference,
                _OPERATION_PREFIX + attempt)
            proof = observer.Observe()
            run = root / (_RUN_PREFIX + attempt)
            run.mkdir(mode=0o700)
            scratch = run / "scratch"
            scratch.mkdir(mode=0o700)
            for name in ("home", "docker-config"):
                (scratch / name).mkdir(mode=0o700)
            config = scratch / "docker-config/config.json"
            with config.open("xb") as stream:
                stream.write(b"{}\n")
            config.chmod(0o600)
            runIdentity = PrivateDirectory(run)
            claims: list[LocalImageExecutionClaim] = []
            resolution: LocalImageResolution | None = None
            pin: LocalImageArchivePin | None = None
            archiveRaw: bytes | None = None
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
                    pin, archiveRaw = accepted, result.stdout
                context.Progress(completed, 3)
            if resolution is None or pin is None or archiveRaw is None:
                raise ValueError("local image export original phase association is missing")

            def Validate() -> None:
                """Require original completed custody and current authority before publication."""

                context.CheckCancellation()
                if resolution is None or pin is None or PrivateDirectory(run) != runIdentity:
                    raise ValueError("local image export publication association changed")
                ValidateCompletedLocalExport(self.engine, tuple(claims), resolution, pin,
                    self.Context(), at=self.clock())

            phase = JobFailureCode.AUTHORIZATION
            Validate()
            phase = JobFailureCode.STORAGE
            archive = run / "image.tar"
            descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(archiveRaw)
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


@dataclass(frozen=True, slots=True)
class LocalImageExportReplay:
    """Internal replay of the acknowledged export and its complete original archive stdout."""

    workspace_id: str
    workspace_revision: int
    job_reference: str
    scope_reference: str
    target_reference: str
    pin: LocalImageArchivePin
    operation_records: tuple[EvidenceRecord, ...]
    archive_stdout: bytes


class LocalExportEvidenceStore(LocalEvidenceStore):
    """Bound each selected raw acquisition before the immutable owner's eager read."""

    def __init__(self, root: Path, role: str) -> None:
        """Select one expected role and bound before opening the caller-supplied evidence ID."""

        super().__init__(root)
        self._role = role

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read a selected export record within its exact role, media and size budget.

        Args:
            reference: Exact stored reference for the role selected by this reader.

        Returns:
            Original bytes verified by the evidence owner.
        """

        maximum, media = _EVIDENCE_LIMITS[self._role]

        if reference.role != self._role or (
            reference.size_bytes > maximum or reference.media_type != media
        ):
            raise ValueError("local image export evidence differs from its role or byte budget")

        return super().Read(reference)


def ExportAttempt(jobReference: str) -> str:
    """Derive the single original run identity shared by the job, receipts and scratch.

    Args:
        jobReference: Original job identifier issued by the export workflow.

    Returns:
        Canonical lowercase hexadecimal attempt identifier.
    """

    if type(jobReference) is not str or not jobReference.startswith(_JOB_PREFIX):
        raise ValueError("local image export requires its original job reference")

    attempt = jobReference.removeprefix(_JOB_PREFIX)

    if re.fullmatch(r"[0-9a-f]{32}", attempt) is None:
        raise ValueError("local image export requires a canonical attempt identity")

    return attempt


def ReadCompletedOperation(evidenceRoot: Path, workspace: WorkspaceState,
    proof: dict[str, object], operation: LocalImageOperation, ids: tuple[str, ...],
) -> tuple[tuple[EvidenceRecord, ...], dict[str, object], bytes]:
    """Verify ownership, role order, invocation and stream bindings of one original command.

    Args:
        evidenceRoot: Local evidence directory in the current workspace.
        workspace: Current saved workspace with the selected original references.
        proof: Validated terminal export receipt.
        operation: Original inspect, save or recheck operation.
        ids: Three evidence IDs in stdout, stderr and receipt order.

    Returns:
        Verified ordered records, selected material and the original stdout bytes.
    """

    stores = tuple(LocalExportEvidenceStore(evidenceRoot, f"local-image-{operation.value}-{role}")
                   for role in _STREAM_ROLES)
    records = tuple(store.Get(identity) for store, identity in zip(stores, ids, strict=True))
    stdout, stderr, receipt = records
    source = receipt.provenance

    if any(item.reference not in workspace.evidence_references or item.provenance != source
           for item in records) or (
        source.workspace_id != workspace.workspace_id
        or source.scope_reference != proof["scope_reference"]
        or source.source_id != LOCAL_IMAGE_SOURCE or source.source_version != "1"
        or source.tool_version is not None or source.execution is None
        or source.execution.state is not ExecutionState.SUCCEEDED
    ):
        raise ValueError("local image export original records differ from their selected operation")

    receiptRaw = stores[2].Read(receipt.reference)
    original = WorkspaceFields(JsonDocument(receiptRaw, _OPERATION_RECEIPT_BYTES),
        {"schema_version", "operation", "operation_reference", "request", "execution",
         "termination", "stdout_sha256", "stderr_sha256", "stdout_size", "stderr_size",
         "event_count", "plan", "selected_material"}, "local image export original receipt")
    request = WorkspaceFields(original["request"],
        {"invocation", "capability", "authorization", "workspace", "environment", "resources"},
        "local image export original request")
    invocation = WorkspaceFields(request["invocation"],
        {"adapter_id", "request", "argv", "timeout_seconds", "provider_version"},
        "local image export original invocation")
    requested = WorkspaceFields(invocation["request"],
        {"capability", "target_reference", "impact", "parameters", "credential_references"},
        "local image export original adapter request")
    material = WorkspaceFields(original["selected_material"],
        {"family", "operation_id", "operation", "operation_reference", "workspace_root",
         "workspace_id", "owner_reference", "read_consent", "descriptor", "material", "invocation",
         "scratch", "scratch_identities", "config_identity", "environment", "resources",
         "resolution"}, "local image export selected material")
    plan = WorkspaceFields(original["plan"],
        {"prepared_sha256", "scope_sha256", "policy_sha256", "scope_reference", "policy_reference",
         "workspace_id", "owner_reference", "target_reference", "invocation_sha256"},
        "local image export original plan")
    descriptor = WorkspaceFields(material["descriptor"],
        {"schema_version", "profile", "reference", "docker_executable", "endpoint"},
        "local image export original descriptor")
    target = Target(TargetKind.ARTIFACT, "manifest-sha256:" + Digest(descriptor))
    resolution = material["resolution"]
    exportId = resolution.get("image_config_id") if type(resolution) is dict else None
    parameters = {"operation": operation.value, "reference": descriptor["reference"],
                  "image_id": exportId if operation is LocalImageOperation.EXPORT else None}

    if type(original["schema_version"]) is not int or original["schema_version"] != 1 or (
        original["operation"] != operation.value or material["operation"] != operation.value
        or original["operation_reference"] != proof["operation_reference"]
        or material["operation_reference"] != proof["operation_reference"]
        or material["workspace_id"] != workspace.workspace_id
        or plan["workspace_id"] != workspace.workspace_id
        or plan["scope_reference"] != source.scope_reference
        or plan["prepared_sha256"] != Digest(material)
        or plan["invocation_sha256"] != source.invocation_sha256
        or material["invocation"] != invocation or Digest(invocation) != source.invocation_sha256
        or invocation["adapter_id"] != LOCAL_IMAGE_SOURCE
        or descriptor["profile"] != LOCAL_IMAGE_PROFILE or requested["parameters"] != parameters
        or requested["target_reference"] != proof["target_reference"]
        or plan["target_reference"] != proof["target_reference"]
        or target.Reference() != proof["target_reference"]
        or request["workspace"] != proof["scratch"]
        or original["termination"] != ExecutionTermination.PROCESS_EXIT.value
        or SerializeContract(original["execution"]) != SerializeContract(source.execution)
        or original["stdout_sha256"] != stdout.reference.sha256
        or original["stderr_sha256"] != stderr.reference.sha256
        or type(original["stdout_size"]) is not int or type(original["stderr_size"]) is not int
        or original["stdout_size"] != stdout.reference.size_bytes
        or original["stderr_size"] != stderr.reference.size_bytes
    ):
        raise ValueError("local image export receipt differs from original acquisition facts")

    return records, material, stores[0].Read(stdout.reference)


def VerifyLocalImageExportCompletion(workspaceRoot: Path,
                                     completionRecordReference: str) -> LocalImageExportReplay:
    """Reopen an explicitly selected successful export without old paths, Docker or writes.

    Args:
        workspaceRoot: Existing or relocated workspace owning all selected records.
        completionRecordReference: Independently retained terminal evidence manifest ID.

    Returns:
        Verified ordered original records and complete archive bytes bound to the config ID.

    Raises:
        ValueError: The selected proof, workspace or captures conflict with original acceptance.
        EvidenceError: Required proof or retained original bytes are absent or corrupt.
        OSError: Owning workspace state cannot be opened.
    """

    owner = LocalWorkspaceStore(workspaceRoot)
    workspace = owner.Open()
    evidenceRoot = owner.root / "evidence"
    store = LocalExportEvidenceStore(evidenceRoot, _COMPLETION_ROLE)
    receipt = store.Get(completionRecordReference)
    raw = store.Read(receipt.reference)
    proof = WorkspaceFields(JsonDocument(raw, _COMPLETION_BYTES),
        {"schema_version", "workspace_id", "workspace_revision", "scope_reference",
         "job_reference", "operation_reference", "target_reference", "scratch", "pin",
         "operation_record_references"}, "local image export completion")
    revision, job = proof["workspace_revision"], proof["job_reference"]
    scope, operationRef = proof["scope_reference"], proof["operation_reference"]
    targetRef, ids = proof["target_reference"], proof["operation_record_references"]
    provenance = receipt.provenance

    if type(job) is not str:
        raise ValueError("local image export completion requires its original job reference")

    attempt = ExportAttempt(job)

    if (
        raw != SerializeContract(proof).encode("utf-8") or type(proof["schema_version"]) is not int
        or proof["schema_version"] != 1 or proof["workspace_id"] != workspace.workspace_id
        or type(revision) is not int or not 1 <= revision <= workspace.revision
        or job not in workspace.job_references
        or type(scope) is not str or scope not in workspace.scope_references
        or operationRef != _OPERATION_PREFIX + attempt
        or proof["scratch"] != _RUN_PREFIX + attempt + "/scratch"
        or type(targetRef) is not str or re.fullmatch(r"target:[0-9a-f]{64}", targetRef) is None
        or provenance.workspace_id != workspace.workspace_id or provenance.scope_reference != scope
        or provenance.source_id != LOCAL_IMAGE_SOURCE or provenance.source_version != "1"
        or provenance.tool_version is not None or provenance.invocation_sha256 is not None
        or provenance.execution is not None or provenance.started_at != provenance.finished_at
        or type(ids) is not list or len(ids) != 9
        or any(type(identity) is not str or identity not in workspace.evidence_record_references
               for identity in ids)
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("local image export completion differs from the selected workspace")

    originals = tuple(
        ReadCompletedOperation(evidenceRoot, workspace, proof, operation,
                                tuple(ids[index:index + 3]))
        for index, operation in zip(range(0, 9, 3), LocalImageOperation, strict=True)
    )
    (inspections, inspect, inspectRaw), (exports, export, archive), (
        rechecks, recheck, recheckRaw
    ) = originals
    configId = InspectConfigId(inspectRaw)
    expectedResolution = LocalImageResolution(configId, inspections[0].reference.sha256,
                                               _OPERATION_PREFIX + attempt)
    pin = VerifyDockerSave(archive, configId)

    if inspect["resolution"] is not None or any(
        SerializeContract(material["resolution"]) != SerializeContract(expectedResolution)
        or any(material[key] != inspect[key] for key in (
            "descriptor", "workspace_root", "owner_reference", "read_consent", "material",
            "scratch",
        ))
        for material in (export, recheck)
    ) or (
        InspectConfigId(recheckRaw) != configId
        or SerializeContract(proof["pin"]) != SerializeContract(pin)
        or inspections[0].provenance.finished_at > exports[0].provenance.started_at
        or exports[0].provenance.finished_at > rechecks[0].provenance.started_at
        or rechecks[0].provenance.finished_at > provenance.started_at or owner.Open() != workspace
    ):
        raise ValueError("local image export completion differs from its original sequence")

    return LocalImageExportReplay(workspace.workspace_id, revision, job, scope, targetRef, pin,
                                  (*inspections, *exports, *rechecks), archive)


def RetainCompletion(workflow: LocalImageExportWorkflow, snapshot: JobSnapshot) -> str | None:
    """Publish a separate receipt only after terminal success and exact workspace readback.

    Args:
        workflow: Owning export workflow with its acknowledged workspace and originals.
        snapshot: Terminal snapshot of the same export job.

    Returns:
        Verified completion evidence ID when publication is acknowledged, otherwise None.
    """

    if snapshot.state is not JobState.COMPLETED or not workflow.acknowledged:
        return None

    if workflow.pin is None:
        return None

    attempt = ExportAttempt(snapshot.spec.job_id)
    statement = {"schema_version": 1, "workspace_id": snapshot.spec.workspace_id,
        "workspace_revision": workflow.initial_workspace.revision + 1,
        "scope_reference": snapshot.spec.scope_reference, "job_reference": snapshot.spec.job_id,
        "operation_reference": _OPERATION_PREFIX + attempt,
        "target_reference": workflow.selection.Target().Reference(),
        "scratch": _RUN_PREFIX + attempt + "/scratch", "pin": workflow.pin,
        "operation_record_references": [record.evidence_id for record in workflow.records]}
    raw = SerializeContract(statement).encode("utf-8")
    timestamp = datetime.now(UTC).isoformat()
    provenance = EvidenceProvenance(snapshot.spec.workspace_id, snapshot.spec.scope_reference,
        LOCAL_IMAGE_SOURCE, "1", None, timestamp, timestamp)
    evidenceRoot = workflow.selection.workspace_root / "evidence"
    store = LocalExportEvidenceStore(evidenceRoot, _COMPLETION_ROLE)

    if len(raw) > _COMPLETION_BYTES:
        return None

    try:
        result = store.Put(raw, _COMPLETION_ROLE, _JSON_MEDIA, provenance)

        if type(result) is EvidenceRecord and result.provenance == provenance and (
            result.reference.role == _COMPLETION_ROLE and store.Get(result.evidence_id) == result
            and store.Read(result.reference) == raw
        ):
            return result.evidence_id

    except (EvidenceError, OSError, ValueError):
        pass

    return None


async def ExportLocalImage(selection: LocalImageSelection, scope_id: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, approve_local_image: bool = False,
    on_event: Callable[[JobEvent], None] | None = None, clock: Callable[[], datetime] = UtcNow,
    retainCompletion: bool = False,
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
        retainCompletion: Opt in to separate evidence for offline completion replay.

    Returns:
        Actual terminal job, accepted archive after confirmed workspace persistence, and
        optional separately retained completion evidence for offline replay.
    """

    PlanLocalImageExport(selection)

    if type(retainCompletion) is not bool:
        raise ValueError("local image export requires an explicit boolean completion option")

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
    spec = JobSpec(_JOB_PREFIX + uuid4().hex, workspace.workspace_id,
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
        workflow.pin if accepted else None, workflow.acknowledged,
        RetainCompletion(workflow, snapshot) if retainCompletion else None)
