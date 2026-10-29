# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit original-response acquisition, source-only persistence and offline known replay."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import AdapterInvocation, ImpactLevel, SerializeContract
from fuzzy1337.adapters.owned_response_capture import (
    ERROR_CODES,
)
from fuzzy1337.evidence import EvidenceError, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import CapabilityDescriptor
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
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.owned_response_capture import (
    OwnedResponseAuthority,
    OwnedResponseCaptureProvider,
    PrepareOwnedResponseInvocation,
    PrepareResponseInvocation,
)
from fuzzy1337.owned_response_custody import (
    _CATALOG_FAMILY,
    _CONTENT_FAMILY,
    OwnedResponseEvidenceStore,
    ParseResponseRecord,
    ReplayOwnedResponseCapture,
    RequireResponseFamily,
    ResponseDestination,
    ResponseFamily,
)
from fuzzy1337.policy import ImpactPolicy, PolicyContext, PolicyEngine, PolicyPlan, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceText,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

SOURCE_KIND = "owned-response-source"


class OwnedResponseAuthorityDeniedError(PermissionError):
    """Explicit workflow approval or current trusted actor attribution differs from selection."""


def CurrentAuthority(root: Path, scope_id: str, url: str, owner: str,
                     policy_provider: Callable[[], ImpactPolicy], approved: bool,
                     current_owner_provider: Callable[[], str] | None = None,
                     *, _family: ResponseFamily = _CATALOG_FAMILY,
                     retain_response: bool = False,
                     ) -> OwnedResponseAuthority:
    """Read complete current source authority without replacing independent consent attestation.

    Args:
        root: Existing owning workspace root.
        scope_id: Explicit existing source scope identifier.
        url: Exact original selected literal URL.
        owner: Explicit executing actor, independent from the consent attester.
        policy_provider: Fresh synchronous reader of the actual selected policy.
        approved: Exact independent workflow approval, never a derived permission.
        current_owner_provider: Optional trusted fresh actor attribution, not authentication.
        _family: Immutable catalog or content binding selecting the source URL grammar.
        retain_response: Explicit retention selection passed into current authority; defaults false.

    Returns:
        Current complete original URL and literal destination authority.
    """

    address = ResponseDestination(url, _family)[0]
    RequireWorkspaceText(owner, "owner_reference")
    current_owner = owner if current_owner_provider is None else current_owner_provider()

    if type(current_owner) is not str or current_owner != owner:
        raise OwnedResponseAuthorityDeniedError("owned response current actor attribution changed")

    policy = policy_provider()

    if type(policy) is not ImpactPolicy:
        raise ValueError("owned response requires a typed current policy")

    target = Target(TargetKind.URL, url)
    context = PolicyContext(LocalScopeStore(root).Open(scope_id), policy, target,
                            (target, Target(TargetKind.IP, address)))

    return OwnedResponseAuthority(context, owner, approved, retain_response)


@dataclass(frozen=True, slots=True)
class OwnedResponseCapturePlan:
    """Descriptive exact acquisition intent and current bases, never an execution grant."""

    invocation: AdapterInvocation
    policy_plan: PolicyPlan
    model_revision: int
    workspace_revision: int
    _family: ResponseFamily = _CATALOG_FAMILY

    def ToDict(self) -> dict[str, object]:
        """Return exact nonexecuting intent without private work or response bytes.

        Returns:
            Schema-one descriptive SAFE acquisition plan.
        """

        return {"schema_version": 1, "workflow": ("owned-response-capture"
                          if self._family is _CATALOG_FAMILY else
                          "owned-content-response-capture"), "state": "planned",
            "execution_authorized": False, "source_id": self._family.provider_id,
            "capability": self._family.capability_id, "profile": self._family.profile,
            "model_revision": self.model_revision, "workspace_revision": self.workspace_revision,
            "invocation": json.loads(SerializeContract(self.invocation)),
            "policy_plan": json.loads(SerializeContract(self.policy_plan)),
            **({"retention_required": True} if self._family is _CONTENT_FAMILY else {})}


def PlanResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
    _family: ResponseFamily = _CATALOG_FAMILY,
) -> OwnedResponseCapturePlan:
    """Plan one current consented source operation without grant, work directory or contact.

    Args:
        workspace_root: Explicit existing workspace containing initialized canonical state.
        scope_id: Already registered complete source URL/literal consent scope.
        url: Exact original canonical catalog URL.
        owner_reference: Explicit executing actor, without attester substitution.
        policy_provider: Fresh typed acquisition policy reader.
        clock: Aware current policy decision clock.
        current_owner_provider: Optional fresh trusted actor attribution; default is selected actor.
        _family: Immutable catalog or content binding; defaults to the catalog plan.

    Returns:
        Exact installed invocation, descriptive policy plan and observed revision bases.
    """

    invocation = (PrepareOwnedResponseInvocation(url) if _family is _CATALOG_FAMILY else
                  PrepareResponseInvocation(url, _family=_family))
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    model = LocalModelStore(store.root).Open()
    VerifyWorkspaceEvidence(workspace, LocalEvidenceStore(store.root / "evidence"))
    authority = CurrentAuthority(store.root, scope_id, url, owner_reference, policy_provider, False,
                                 current_owner_provider, _family=_family)

    if authority.context.scope.workspace_id != workspace.workspace_id or (
        model.workspace_id != workspace.workspace_id
    ):
        raise PermissionError("owned response source belongs to another workspace")

    plan = PolicyEngine().Plan(invocation, CapabilityDescriptor(_family.capability_id,
        _family.provider_id, ImpactLevel.SAFE), authority.context, at=clock())

    return OwnedResponseCapturePlan(invocation, plan, model.revision, workspace.revision, _family)


def SourceFact(workspace_id: str, record: dict[str, object], records: tuple[EvidenceRecord, ...],
               receipt_id: str, job_id: str, *,
               _family: ResponseFamily = _CATALOG_FAMILY) -> Observation:
    """Bind a source-only immutable observation to actual original receipt, job and role IDs.

    Args:
        workspace_id: Owning canonical model workspace.
        record: Fully replay-verified captured worker record.
        records: Actual independently verified original complete role records.
        receipt_id: Actual original receipt manifest identifier.
        job_id: Actual owning ScanJob identifier, never guessed from receipt fields.
        _family: Immutable catalog or content binding selecting source identity and metadata.

    Returns:
        Content-addressed source fact with original execution provenance and no assessment.
    """

    roles = {item.reference.role: item.evidence_id for item in records}
    receipt = next(item for item in records if item.evidence_id == receipt_id)
    url = str(record["url"])
    subject = ObjectIdentity(workspace_id, ObjectKind.ENDPOINT, url)
    original = receipt.provenance
    provenance = ModelProvenance(RequireResponseFamily(_family).provider_id, job_id,
        original.finished_at,
        original.scope_reference, Target(TargetKind.URL, url).Reference(), "1",
        tuple(item.reference for item in sorted(records, key=lambda item: item.reference.role)),
        original.execution)
    request = record["request"]
    response = record["response"]
    headers = record["response_headers"]
    body = record["response_body"]

    if not isinstance(request, dict) or not isinstance(response, dict) or (
        not isinstance(headers, dict) or not isinstance(body, dict)
    ):
        raise ValueError("owned response original parts are unverified")

    attributes = {
        "profile": _family.profile, "original_job_id": job_id,
        "original_receipt_id": receipt_id, "original_role_ids": roles,
        "request_sha256": request["sha256"], "response_sha256": response["sha256"],
        "header_size_bytes": headers["size_bytes"], "body_size_bytes": body["size_bytes"],
    }

    if _family is _CATALOG_FAMILY:
        attributes.update(catalog_sha256=record["catalog_sha256"], case_id=record["case_id"])

    else:
        attributes.update(schema_version=1, media_type=record["media_type"])

    return Observation(_family.source_kind, subject.Reference(), attributes, provenance)


class OwnedResponseWorkflow:
    """Keep parent acquisition and original-basis persistence inside the same active job."""

    def __init__(self, root: Path, workspace: WorkspaceState, model: ModelState,
                 provider: OwnedResponseCaptureProvider,
                 snapshot: Callable[[], JobSnapshot]) -> None:
        """Freeze one attempt without adding an authority, evidence or recovery owner.

        Args:
            root: Existing physical workspace.
            workspace: Exact original workspace CAS basis.
            model: Exact original model CAS basis, including unrelated triage.
            provider: Original single-use first-party acquisition provider.
            snapshot: Actual original coordinator snapshot callback.
        """

        self.root, self.workspace, self.model = root, workspace, model
        self.provider, self.snapshot = provider, snapshot
        self.model_proposed: ModelState | None = None
        self.workspace_proposed: WorkspaceState | None = None
        self.model_attempted = self.workspace_attempted = False
        self.model_acknowledged = self.workspace_acknowledged = False
        self.source_fact: Observation | None = None

    def Records(self) -> tuple[EvidenceRecord, ...]:
        """Authenticate actual attached original records without adopting stored candidates.

        Returns:
            Exact independently read-back original job attachments.
        """

        snapshot = self.snapshot()
        records = []

        for artifact in snapshot.artifacts:
            record = artifact.evidence

            if artifact.job_id != snapshot.spec.job_id or (
                artifact.workspace_id != self.workspace.workspace_id
                or record.provenance.workspace_id != self.workspace.workspace_id
                or record.provenance.scope_reference != snapshot.spec.scope_reference
                or record.provenance.source_id != self.provider._family.provider_id
                or self.provider.store.Get(record.evidence_id) != record
            ):
                raise ValueError("owned response original attachment differs")

            self.provider.store.Read(record.reference)
            records.append(record)

        return tuple(records)

    def PersistReferences(self, context: JobContext) -> None:
        """Attempt one guarded original workspace CAS, including failure-path retention.

        Args:
            context: Same still-running owning job; terminal attachment is never attempted.
        """

        if self.workspace_attempted or self.provider.capture is None:
            return

        capture = self.provider.capture
        records = self.Records()

        if not records:
            return

        store = LocalWorkspaceStore(self.root)
        current = store.Open()
        model = LocalModelStore(self.root).Open()

        if current != self.workspace or model not in (self.model, self.model_proposed):
            raise WorkspaceConflictError("owned response original persistence bases changed")

        references = {(item.locator, item.role): item for item in current.evidence_references}

        for record in records:
            key = (record.reference.locator, record.reference.role)

            if key in references and references[key] != record.reference:
                raise ValueError("owned response original reference conflicts")

            references[key] = record.reference

        proposal = replace(current,
            scope_references=tuple(sorted({*current.scope_references,
                                           context.Spec.scope_reference})),
            job_references=tuple(sorted({*current.job_references, context.Spec.job_id})),
            object_references=tuple(sorted({*current.object_references,
                                           *(item.Reference() for item in model.objects)})),
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted({*current.evidence_record_references,
                                                     *(item.evidence_id for item in records)})))
        self.workspace_proposed = replace(proposal, revision=current.revision + 1)
        self.provider.ValidatePersistence(context, capture)
        self.workspace_attempted = True
        saved = store.Save(proposal)

        if saved != self.workspace_proposed:
            raise ValueError("owned response workspace acknowledgement differs")

        self.workspace_acknowledged = True
        self.provider.ValidatePersistence(context, capture)

    async def Run(self, context: JobContext) -> None:
        """Acquire, project only verified source facts and acknowledge both canonical saves.

        Args:
            context: Same original active ScanJob context used by the parent acquisition.

        Raises:
            JobError: Original authority, custody, shared deadline or persistence failed.
            asyncio.CancelledError: The original parent finishes owned cancellation cleanup.
        """

        try:
            await self.provider.Run(context)

            capture = self.provider.capture

            if capture is None or capture.receipt_id is None or capture.refusal is not None:
                raise ValueError("owned response successful original custody is unavailable")

            records = self.Records()
            replay = ReplayOwnedResponseCapture(self.provider.store, capture.receipt_id)

            if {*replay.original_ids, replay.receipt_id} != {item.evidence_id for item in records}:
                raise ValueError("owned response original role association differs")

            record = ParseResponseRecord(replay.record_json, self.provider.url,
                                         self.provider._family)
            self.source_fact = SourceFact(self.model.workspace_id, record, records,
                                           capture.receipt_id, context.Spec.job_id,
                                           _family=self.provider._family)
            identity = ObjectIdentity(self.model.workspace_id, ObjectKind.ENDPOINT,
                                      self.provider.url)
            existing = next((item for item in self.model.objects if item.identity == identity),
                            None)

            if existing is not None and existing.attributes.get("url", self.provider.url) != (
                self.provider.url
            ):
                raise ValueError("owned response endpoint URL conflicts with existing state")

            updated, delta = self.model.Apply(objects=(SecurityObject(identity,
                {"url": self.provider.url}, (self.source_fact.provenance,)),),
                observations=(self.source_fact,))
            store = LocalModelStore(self.root)

            if store.Open() != self.model:
                raise WorkspaceConflictError("owned response original model basis changed")

            self.model_proposed = updated
            self.provider.ValidatePersistence(context, capture)
            self.model_attempted = True
            saved = store.Save(updated, expected_revision=self.model.revision)

            if saved != updated:
                raise ValueError("owned response model acknowledgement differs")

            self.model_acknowledged = True
            self.provider.ValidatePersistence(context, capture)
            self.PersistReferences(context)
            context.CheckCancellation()

            if delta.created or delta.updated:
                context.ModelChanged(delta)

        except (EvidenceError, OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError):
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Owned response persistence is unverified; originals retained")) from None

        finally:
            if not self.workspace_attempted:
                try:
                    self.PersistReferences(context)

                except (JobError, EvidenceError, OSError, ValueError,
                        WorkspaceBusyError, WorkspaceConflictError):
                    pass


def PersistenceStatus(actual: object, prior: object, proposed: object,
                      attempted: bool, acknowledged: bool) -> str:
    """Distinguish returned acknowledgements from independently observed commits and uncertainty.

    Args:
        actual: Actual reopened canonical state, absent when reopening failed.
        prior: Exact original state before this attempt's own Save.
        proposed: Exact original proposal, never a rebase.
        attempted: Whether the owning Save boundary was entered.
        acknowledged: Whether its exact successful return was validated.

    Returns:
        Fixed truthful persistence classification, without rollback or blind retry.
    """

    if acknowledged:
        return "acknowledged"

    if not attempted:
        return "not-attempted"

    if actual is not None and actual == proposed:
        return "observed-committed"

    return "observed-unchanged" if actual is not None and actual == prior else "unconfirmed"


@dataclass(frozen=True, slots=True)
class OwnedResponseCaptureSummary:
    """Actual job, original attachments and observed commits; acquisition is no assessment."""

    snapshot: JobSnapshot
    records: tuple[EvidenceRecord, ...]
    original_receipt_id: str | None
    model_revision: int | None
    workspace_revision: int | None
    model_persistence_status: str
    workspace_persistence_status: str
    source_facts: dict[str, object] | None
    acquisition_outcome: str
    custody_status: str
    stage_retained: bool
    events: tuple[JobEvent, ...]
    duration_seconds: float
    _family: ResponseFamily = _CATALOG_FAMILY

    def ToDict(self) -> dict[str, object]:
        """Return only safe original IDs/source facts and truthful durable execution state.

        Returns:
            Schema-one acquisition summary without raw wire, staging path or assessment fields.
        """

        return {"schema_version": 1, "workflow": ("owned-response-capture"
                          if self._family is _CATALOG_FAMILY else
                          "owned-content-response-capture"),
            "source_id": self._family.provider_id, "state": self.snapshot.state.value,
            "original_job_id": self.snapshot.spec.job_id,
            "original_receipt_id": self.original_receipt_id,
            "original_role_ids": {item.reference.role: item.evidence_id for item in self.records},
            "model_revision": self.model_revision, "workspace_revision": self.workspace_revision,
            "model_persistence_status": self.model_persistence_status,
            "workspace_persistence_status": self.workspace_persistence_status,
            "source_facts": self.source_facts, "acquisition_outcome": self.acquisition_outcome,
            "custody_status": self.custody_status, "stage_retained": self.stage_retained,
            "duration_seconds": self.duration_seconds,
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events))}

    def ExitCode(self) -> int:
        """Preserve execution, authority and cancellation outcomes independently of source bytes.

        Returns:
            Zero for completion, three for denial, four for failure or 130 for cancellation.
        """

        if self.snapshot.state is JobState.COMPLETED:
            return 0

        if self.snapshot.state is JobState.CANCELLED:
            return 130

        if self.snapshot.failure is not None and (
            self.snapshot.failure.code is JobFailureCode.AUTHORIZATION
        ):
            return 3

        return 4


async def SettleOwnedResponseCleanup(task: asyncio.Task[JobSnapshot]) -> JobSnapshot:
    """Settle the one owned cleanup task despite repeated external caller cancellations.

    Args:
        task: Original single coordinator cancellation/wait task, never a replacement attempt.

    Returns:
        Actual terminal snapshot only after the original cleanup task has completed.

    Raises:
        RuntimeError: The cleanup task itself terminated cancelled without confirmation.
        BaseException: The original cleanup task's failure, without a fabricated terminal snapshot.
    """

    while not task.done():
        try:
            await asyncio.shield(task)

        except asyncio.CancelledError:
            continue

    if task.cancelled():
        raise RuntimeError("Owned response cleanup terminated without confirmation")

    return task.result()


async def RunResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, approve_safe_response_capture: bool = False,
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
    _family: ResponseFamily = _CATALOG_FAMILY,
    _retain_response: bool = False,
) -> OwnedResponseCaptureSummary:
    """Compose one original capture and guarded source persistence inside the same active job.

    Args:
        workspace_root: Explicit existing owning workspace with initialized shared model.
        scope_id: Existing source consent scope; no target is registered automatically.
        url: Exact canonical catalog URL, never normalized into another spelling.
        owner_reference: Explicit executing actor, distinct from independent attestation metadata.
        policy_provider: Fresh synchronous current acquisition policy reader.
        approve_safe_response_capture: Exact independent SAFE workflow approval.
        on_event: Optional synchronous presentation sink for original safe job events.
        clock: Aware current policy/evidence clock, without renewing monotonic budgets.
        current_owner_provider: Trusted fresh attribution, not an identity authentication mechanism.
        _family: Immutable catalog or content binding selecting acquisition and custody.
        _retain_response: Explicit response-retention opt-in; defaults false and is required
            for content.

    Returns:
        Actual original terminal snapshot and reopened persistence facts; stage remains retained.

    Raises:
        PermissionError: Explicit workflow approval is absent.
        ValueError: Inputs or initial canonical state are invalid before a job starts.
    """

    ResponseDestination(url, _family)

    if type(approve_safe_response_capture) is not bool:
        raise ValueError("owned response approval requires an exact boolean")

    if type(_retain_response) is not bool:
        raise ValueError("owned response retention requires an exact boolean")

    if not approve_safe_response_capture or (_family is _CONTENT_FAMILY and not _retain_response):
        raise OwnedResponseAuthorityDeniedError("owned response requires explicit SAFE approval")

    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    model_store = LocalModelStore(store.root)
    model = model_store.Open()
    evidence = LocalEvidenceStore(store.root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    authority = CurrentAuthority(store.root, scope_id, url, owner_reference, policy_provider, True,
                                 current_owner_provider, _family=_family,
                                 retain_response=_retain_response)

    if model.workspace_id != workspace.workspace_id:
        raise ValueError("owned response canonical model belongs to another workspace")

    provider = OwnedResponseCaptureProvider(store.root, url,
        lambda: CurrentAuthority(store.root, scope_id, url, owner_reference, policy_provider, True,
                                 current_owner_provider, _family=_family,
                                 retain_response=_retain_response),
        approve_workflow=True, retain_response=_retain_response, _family=_family, clock=clock)

    def Snapshot() -> JobSnapshot:
        """Return only the actual original owning coordinator snapshot."""

        return job.Snapshot()

    workflow = OwnedResponseWorkflow(store.root, workspace, model, provider, Snapshot)
    spec = JobSpec("job:owned-response-" + uuid4().hex, workspace.workspace_id,
        authority.context.scope.Reference(), owner_reference, _family.provider_id, 30)
    job = ScanJob(spec, workflow, evidence_store=evidence, max_events=32)
    started = time.monotonic()
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Forward actual safe ordered events without executor fragments or invented lifecycle."""

        nonlocal cursor
        cursor = event.sequence

        if on_event is not None:
            on_event(event)

    try:
        async for event in job.Events():
            Observe(event)

    except asyncio.CancelledError:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))

        await SettleOwnedResponseCleanup(cleanup)

        for event in job.EventsSince(cursor):
            Observe(event)

    except BaseException:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))

        await SettleOwnedResponseCleanup(cleanup)

        raise

    snapshot = await job.Wait()

    try:
        actual_model = model_store.Open()

    except (OSError, ValueError):
        actual_model = None

    try:
        actual_workspace = store.Open()

    except (OSError, ValueError):
        actual_workspace = None

    records = tuple(artifact.evidence for artifact in snapshot.artifacts)

    try:
        verified = workflow.Records() == records

    except (EvidenceError, OSError, ValueError):
        verified = False

    capture = provider.capture
    roles = {item.reference.role for item in records}
    expected_roles = {"stdout", "stderr", "owned-response-receipt"}

    if capture is not None and capture.refusal is None:
        expected_roles |= {"owned-response-request", "owned-response-headers",
                           "owned-response-body", "owned-response-wire"}

    complete = capture is not None and capture.receipt_id is not None and verified and (
        roles == expected_roles and (capture.refusal is None or capture.refusal in ERROR_CODES)
    )
    facts = (None if workflow.source_fact is None else
             json.loads(SerializeContract(workflow.source_fact.attributes)))
    outcome = "unknown"

    if complete and capture is not None:
        outcome = "captured" if capture.refusal is None else "refused"

    return OwnedResponseCaptureSummary(snapshot, records,
        None if capture is None else capture.receipt_id,
        None if actual_model is None else actual_model.revision,
        None if actual_workspace is None else actual_workspace.revision,
        PersistenceStatus(actual_model, model, workflow.model_proposed, workflow.model_attempted,
                          workflow.model_acknowledged),
        PersistenceStatus(actual_workspace, workspace, workflow.workspace_proposed,
                          workflow.workspace_attempted, workflow.workspace_acknowledged), facts,
        outcome,
        "complete" if complete else "incomplete", provider.prepared is not None,
        job.EventsSince(), time.monotonic() - started, _family)


@dataclass(frozen=True, slots=True)
class OwnedResponseReplaySummary:
    """Known immutable original source association, verified offline without renewed authority."""

    original_job_id: str
    original_receipt_id: str
    records: tuple[EvidenceRecord, ...]
    source_facts: dict[str, object]
    model_revision: int
    workspace_revision: int
    _family: ResponseFamily = _CATALOG_FAMILY

    def ToDict(self) -> dict[str, object]:
        """Return verified source facts and original IDs without a fabricated replay job.

        Returns:
            Safe schema-one historical verification result without runtime or persistence.
        """

        return {"schema_version": 1, "workflow": ("owned-response-replay"
                          if self._family is _CATALOG_FAMILY else
                          "owned-content-response-replay"), "state": "verified",
            "source_id": self._family.provider_id, "original_job_id": self.original_job_id,
            "original_receipt_id": self.original_receipt_id,
            "original_role_ids": {item.reference.role: item.evidence_id for item in self.records},
            "source_facts": self.source_facts, "model_revision": self.model_revision,
            "workspace_revision": self.workspace_revision}


def ReplayResponse(
    workspace_root: Path, original_receipt_id: str, *,
    _family: ResponseFamily = _CATALOG_FAMILY,
) -> OwnedResponseReplaySummary:
    """Verify known successful original source association without current scope or target access.

    Args:
        workspace_root: Explicit relocated existing canonical workspace boundary.
        original_receipt_id: Actual original receipt manifest ID already retained by this workspace.
        _family: Immutable catalog or content binding required for original custody and
            source facts.

    Returns:
        Independently verified original job/role IDs and immutable source facts.

    Raises:
        ValueError: Original custody or durable source/job association is absent or inconsistent.
    """

    RequireResponseFamily(_family)
    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    model = LocalModelStore(workspace_store.root).Open()

    if original_receipt_id not in workspace.evidence_record_references:
        raise ValueError("owned response original receipt association is unknown")

    store = OwnedResponseEvidenceStore(workspace_store.root / "evidence", _family=_family)
    replay = ReplayOwnedResponseCapture(store, original_receipt_id)

    original_ids = (*replay.original_ids, replay.receipt_id)

    if any(identity not in workspace.evidence_record_references for identity in original_ids):
        raise ValueError("owned response original role association is unknown")

    records = tuple(store.Get(identity) for identity in original_ids)
    receipt = next(item for item in records if item.evidence_id == original_receipt_id)
    facts = tuple(item for item in model.observations if item.kind == _family.source_kind and
                  item.attributes.get("original_receipt_id") == original_receipt_id)

    if len(facts) != 1 or receipt.provenance.workspace_id != workspace.workspace_id:
        raise ValueError("owned response original source/job association is unknown")

    fact = facts[0]
    job_id = fact.provenance.run_reference

    if job_id not in workspace.job_references:
        raise ValueError("owned response original job association is unknown")

    request = json.loads(replay.record_json)
    record = ParseResponseRecord(replay.record_json, request.get("url"), _family)

    if record["outcome"] != "captured":
        raise ValueError("owned response historical acquisition was refused")

    expected = SourceFact(workspace.workspace_id, record, records, original_receipt_id, job_id,
                          _family=_family)
    endpoint = next((item for item in model.objects if item.Reference() == fact.subject_reference),
                    None)

    if fact != expected or endpoint is None or fact.provenance not in endpoint.provenance:
        raise ValueError("owned response original source fact differs")

    return OwnedResponseReplaySummary(job_id, original_receipt_id, records,
        json.loads(SerializeContract(fact.attributes)), model.revision, workspace.revision, _family)



def PlanOwnedContentResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> OwnedResponseCapturePlan:
    """Describe explicit content retention and SAFE intent without grant, work or contact.

    Args:
        workspace_root: Existing canonical workspace root.
        scope_id: Existing selected complete URL and literal-IP consent scope.
        url: Exact anonymous literal-loopback content URL.
        owner_reference: Explicit executing actor, independent from the attester.
        policy_provider: Fresh typed acquisition policy reader.
        clock: Aware current policy decision clock.
        current_owner_provider: Optional fresh trusted actor attribution.

    Returns:
        Nonexecuting content-family plan with retention_required true.
    """

    return PlanResponseCapture(workspace_root, scope_id, url, owner_reference,
        policy_provider, clock=clock, current_owner_provider=current_owner_provider,
        _family=_CONTENT_FAMILY)


async def RunOwnedContentResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *,
    approve_safe_content_response_capture: bool = False, retain_response: bool = False,
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> OwnedResponseCaptureSummary:
    """Acquire one selected content response with separate explicit SAFE and retention consent.

    Args:
        workspace_root: Existing owning canonical workspace.
        scope_id: Existing complete source consent scope.
        url: Exact anonymous literal-loopback content URL.
        owner_reference: Explicit executing actor, independent from attestation.
        policy_provider: Fresh typed current acquisition policy reader.
        approve_safe_content_response_capture: Exact independent SAFE workflow opt-in.
        retain_response: Exact separate response-byte retention opt-in.
        on_event: Optional synchronous presentation sink for safe original job events.
        clock: Aware current policy/evidence clock, without renewing budgets.
        current_owner_provider: Optional fresh trusted actor attribution.

    Returns:
        Actual original terminal job, custody and separate persistence outcomes.
    """

    return await RunResponseCapture(workspace_root, scope_id, url, owner_reference,
        policy_provider, approve_safe_response_capture=approve_safe_content_response_capture,
        on_event=on_event, clock=clock, current_owner_provider=current_owner_provider,
        _family=_CONTENT_FAMILY, _retain_response=retain_response)


def ReplayOwnedContentResponse(workspace_root: Path,
                               original_receipt_id: str) -> OwnedResponseReplaySummary:
    """Verify retained content-family originals offline without a job, Put, Save or contact.

    Args:
        workspace_root: Existing or relocated canonical workspace boundary.
        original_receipt_id: Actual original acknowledged receipt retained by this workspace.

    Returns:
        Independently verified original job, seven role IDs and immutable source fact.
    """

    return ReplayResponse(workspace_root, original_receipt_id, _family=_CONTENT_FAMILY)


def PlanOwnedResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> OwnedResponseCapturePlan:
    """Plan one current consented source operation without grant, work directory or contact.

    Args:
        workspace_root: Explicit existing workspace containing initialized canonical state.
        scope_id: Already registered complete source URL/literal consent scope.
        url: Exact original canonical catalog URL.
        owner_reference: Explicit executing actor, without attester substitution.
        policy_provider: Fresh typed acquisition policy reader.
        clock: Aware current policy decision clock.
        current_owner_provider: Optional fresh trusted actor attribution; default is selected actor.

    Returns:
        Exact installed invocation, descriptive policy plan and observed revision bases.
    """

    return PlanResponseCapture(workspace_root, scope_id, url, owner_reference,
        policy_provider, clock=clock, current_owner_provider=current_owner_provider)


async def RunOwnedResponseCapture(
    workspace_root: Path, scope_id: str, url: str, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], *, approve_safe_response_capture: bool = False,
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> OwnedResponseCaptureSummary:
    """Compose one original capture and guarded source persistence inside the same active job.

    Args:
        workspace_root: Explicit existing owning workspace with initialized shared model.
        scope_id: Existing source consent scope; no target is registered automatically.
        url: Exact canonical catalog URL, never normalized into another spelling.
        owner_reference: Explicit executing actor, distinct from independent attestation metadata.
        policy_provider: Fresh synchronous current acquisition policy reader.
        approve_safe_response_capture: Exact independent SAFE workflow approval.
        on_event: Optional synchronous presentation sink for original safe job events.
        clock: Aware current policy/evidence clock, without renewing monotonic budgets.
        current_owner_provider: Trusted fresh attribution, not an identity authentication mechanism.

    Returns:
        Actual original terminal snapshot and reopened persistence facts; stage remains retained.

    Raises:
        PermissionError: Explicit workflow approval is absent.
        ValueError: Inputs or initial canonical state are invalid before a job starts.
    """

    return await RunResponseCapture(workspace_root, scope_id, url, owner_reference,
        policy_provider, approve_safe_response_capture=approve_safe_response_capture,
        on_event=on_event, clock=clock, current_owner_provider=current_owner_provider)


def ReplayOwnedResponse(
    workspace_root: Path, original_receipt_id: str,
) -> OwnedResponseReplaySummary:
    """Verify known successful original source association without current scope or target access.

    Args:
        workspace_root: Explicit relocated existing canonical workspace boundary.
        original_receipt_id: Actual original receipt manifest ID already retained by this workspace.

    Returns:
        Independently verified original job/role IDs and immutable source facts.

    Raises:
        ValueError: Original custody or durable source/job association is absent or inconsistent.
    """

    return ReplayResponse(workspace_root, original_receipt_id)
