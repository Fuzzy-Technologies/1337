# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit native crawl SDK planning, original job ownership and one workspace CAS."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.adapters.native_crawl import (
    NATIVE_CRAWL_CAPABILITY,
    NATIVE_CRAWL_PROFILE,
    NATIVE_CRAWL_PROVIDER_ID,
    BuildCrawlInput,
)
from fuzzy1337.evidence import EvidenceError, EvidenceRecord, LocalEvidenceStore
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
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_crawl import (
    NativeCrawlAuthorityDeniedError,
    NativeCrawlLimits,
    NativeCrawlProvider,
    SettleCrawlTask,
)
from fuzzy1337.policy import ImpactPolicy, PolicyEngine, PolicyPlan, UtcNow
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceState


@dataclass(frozen=True, slots=True)
class NativeCrawlPlan:
    """Descriptive immutable admitted intents; only the seed initially becomes reachable work."""

    invocations: tuple[AdapterInvocation, ...]
    policy_plans: tuple[PolicyPlan, ...]
    limits: NativeCrawlLimits
    model_revision: int
    workspace_revision: int

    def ToDict(self) -> dict[str, object]:
        """Expose exact nonexecuting selected intent without granting or predicting a frontier.

        Returns:
            Schema-one plan with no worker contact, raw response bytes or assessment claim.
        """

        return {"schema_version": 1, "workflow": "native-crawl", "state": "planned",
            "execution_authorized": False, "source_id": NATIVE_CRAWL_PROVIDER_ID,
            "capability": NATIVE_CRAWL_CAPABILITY, "profile": NATIVE_CRAWL_PROFILE,
            "model_revision": self.model_revision, "workspace_revision": self.workspace_revision,
            "limits": json.loads(SerializeContract(self.limits)),
            "invocations": json.loads(SerializeContract(self.invocations)),
            "policy_plans": json.loads(SerializeContract(self.policy_plans))}


def PlanNativeCrawl(
    workspace_root: Path, scope_id: str, seed_url: str, selected_urls: tuple[str, ...],
    owner_reference: str, policy_provider: Callable[[], ImpactPolicy], *,
    limits: NativeCrawlLimits = NativeCrawlLimits(), clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> NativeCrawlPlan:
    """Plan the exact admitted set without grant, target contact or canonical writes.

    Args:
        workspace_root: Existing initialized workspace/model/evidence partition.
        scope_id: Existing complete selected URL and literal IP consent scope.
        seed_url: Original exact canonical anonymous HTTP seed.
        selected_urls: Entire sorted distinct finite same-origin URL set including the seed.
        owner_reference: Original selected actor attribution, independent of consent attester.
        policy_provider: Fresh synchronous typed acquisition policy reader.
        limits: Accepted finite operation/request/allocation bounds.
        clock: Aware current authority clock.
        current_owner_provider: Optional trusted fresh attribution, without authentication claim.

    Returns:
        Exact descriptive per-source intents and observed canonical revision bases.
    """

    provider = NativeCrawlProvider(workspace_root, scope_id, seed_url, selected_urls,
        owner_reference, policy_provider, approve_safe_crawl=False, limits=limits, clock=clock,
        current_owner_provider=current_owner_provider)
    workspace = LocalWorkspaceStore(provider.root).Open()
    model = LocalModelStore(provider.root).Open()
    VerifyWorkspaceEvidence(workspace, LocalEvidenceStore(provider.root / "evidence"))

    if model.workspace_id != workspace.workspace_id:
        raise ValueError("native crawl model belongs to another workspace")

    invocations, plans = [], []

    for url in selected_urls:
        document = BuildCrawlInput(workspace.workspace_id, seed_url, url, selected_urls,
            max_body_bytes=limits.max_body_bytes, request_timeout_ms=limits.request_timeout_ms)
        invocation = provider.adapter.PrepareInvocation(AdapterRequest(NATIVE_CRAWL_CAPABILITY,
            Target(TargetKind.URL, url).Reference(), ImpactLevel.SAFE, document))
        authority = provider.Current(url)
        plans.append(PolicyEngine().Plan(invocation, provider.capability, authority.context,
                                         at=clock()))
        invocations.append(invocation)

    return NativeCrawlPlan(tuple(invocations), tuple(plans), limits, model.revision,
                            workspace.revision)


class NativeCrawlWorkflow:
    """Keep guarded original workspace retention inside the same live outer ScanJob."""

    def __init__(self, provider: NativeCrawlProvider, workspace: WorkspaceState) -> None:
        """Freeze one original workspace basis and share one attempt across success/finally.

        Args:
            provider: Original single-use first-party acquisition/scheduling owner.
            workspace: Exact original CAS basis, never refreshed or silently rebased.
        """

        self.provider, self.workspace = provider, workspace
        self.proposed: WorkspaceState | None = None
        self.attempted = self.acknowledged = False

    def Persist(self, context: JobContext) -> None:
        """Make at most one guarded workspace Save, preserving actual original evidence IDs.

        Args:
            context: Same active outer owner used for acquisition and canonical model commits.
        """

        if self.attempted:
            return

        records = self.provider.Records()

        if not records:
            return

        store = LocalWorkspaceStore(self.provider.root)

        if store.Open() != self.workspace:
            raise ValueError("native crawl original workspace CAS basis changed")

        model = LocalModelStore(self.provider.root).Open()

        if model != self.provider.persistence_model:
            raise ValueError("native crawl actual model differs from its original owning Save")

        references = {(item.locator, item.role): item
                      for item in self.workspace.evidence_references}

        for record in records:
            key = record.reference.locator, record.reference.role

            if key in references and references[key] != record.reference:
                raise ValueError("native crawl original evidence reference conflicts")

            references[key] = record.reference

        proposal = replace(self.workspace,
            scope_references=tuple(sorted({*self.workspace.scope_references,
                                           context.Spec.scope_reference})),
            job_references=tuple(sorted({*self.workspace.job_references, context.Spec.job_id})),
            object_references=tuple(sorted({*self.workspace.object_references,
                                           *(item.Reference() for item in model.objects)})),
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted({*self.workspace.evidence_record_references,
                                                     *(item.evidence_id for item in records)})))
        self.proposed = replace(proposal, revision=self.workspace.revision + 1)
        self.provider.ValidatePersistence(context)
        context.CheckCancellation()
        self.attempted = True
        actual = store.Save(proposal)

        if actual != self.proposed:
            raise ValueError("native crawl workspace acknowledgement differs")

        self.acknowledged = True
        self.provider.ValidatePersistence(context)

    async def Run(self, context: JobContext) -> None:
        """Retain original model/evidence state on failure without unauthorized Save or repair.

        Args:
            context: Actual running job context, shared directly with the original provider.

        Raises:
            JobError: Original execution, authority or exact persistence failed.
            asyncio.CancelledError: Cancellation after the original provider cleanup settled.
        """

        try:
            await self.provider.Run(context)
            self.Persist(context)

        except PermissionError:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Native crawl current persistence authority denied")) from None

        except (EvidenceError, OSError, ValueError, RuntimeError) as error:
            if isinstance(error, JobError):
                raise

            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Native crawl workspace persistence is unverified")) from None

        finally:
            if not self.attempted:
                try:
                    self.Persist(context)

                except (asyncio.CancelledError, EvidenceError, OSError, ValueError, RuntimeError):
                    pass


@dataclass(frozen=True, slots=True)
class NativeCrawlSummary:
    """Actual original job and incremental persistence facts, never a security assessment."""

    snapshot: JobSnapshot
    records: tuple[EvidenceRecord, ...]
    completed_urls: tuple[str, ...]
    model_revision: int | None
    workspace_revision: int | None
    model_saves: tuple[dict[str, object], ...]
    workspace_persistence_status: str
    acknowledged_record_ids: tuple[str, ...]
    custody_status: str
    events: tuple[JobEvent, ...]
    duration_seconds: float

    def ToDict(self) -> dict[str, object]:
        """Return safe selected URLs, actual original IDs and explicit partial/unknown outcomes.

        Returns:
            Schema-one summary without raw markup, excluded hrefs or Findings claims.
        """

        return {"schema_version": 1, "workflow": "native-crawl",
            "source_id": NATIVE_CRAWL_PROVIDER_ID, "profile": NATIVE_CRAWL_PROFILE,
            "state": self.snapshot.state.value, "original_job_id": self.snapshot.spec.job_id,
            "completed_urls": list(self.completed_urls),
            "original_record_ids": [item.evidence_id for item in self.records],
            "acknowledged_record_ids": list(self.acknowledged_record_ids),
            "model_revision": self.model_revision, "workspace_revision": self.workspace_revision,
            "model_saves": list(self.model_saves),
            "workspace_persistence_status": self.workspace_persistence_status,
            "custody_status": self.custody_status, "duration_seconds": self.duration_seconds,
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events))}

    def ExitCode(self) -> int:
        """Map actual terminal state without converting refused work into a negative finding.

        Returns:
            Zero on completion, three for denial, four for failure or 130 for cancellation.
        """

        if self.snapshot.state is JobState.COMPLETED:
            return 0

        if self.snapshot.state is JobState.CANCELLED:
            return 130

        return 3 if self.snapshot.failure is not None and (
            self.snapshot.failure.code is JobFailureCode.AUTHORIZATION) else 4


async def RunNativeCrawl(
    workspace_root: Path, scope_id: str, seed_url: str, selected_urls: tuple[str, ...],
    owner_reference: str, policy_provider: Callable[[], ImpactPolicy], *,
    approve_safe_crawl: bool = False, on_event: Callable[[JobEvent], None] | None = None,
    limits: NativeCrawlLimits = NativeCrawlLimits(), clock: Callable[[], datetime] = UtcNow,
    current_owner_provider: Callable[[], str] | None = None,
) -> NativeCrawlSummary:
    """Run content-driven acquisition with explicit SAFE approval and one original owner.

    Args:
        workspace_root: Existing initialized caller-owned workspace.
        scope_id: Existing current complete URL/IP consent scope.
        seed_url: Exact canonical seed URL, sole initial scheduled source.
        selected_urls: Complete sorted same-origin selection, never automatic enrollment.
        owner_reference: Original selected actor attribution, independent from attester.
        policy_provider: Synchronous current typed acquisition policy reader.
        approve_safe_crawl: Exact independent SAFE workflow opt-in.
        on_event: Optional synchronous presentation of original safe events.
        limits: Accepted finite request/scheduling/allocation/inclusive time bounds.
        clock: Fresh aware authority and evidence clock.
        current_owner_provider: Optional trusted fresh attribution; default is selected actor.

    Returns:
        Actual terminal job, original records and reopened exact persistence state.
    """

    if type(approve_safe_crawl) is not bool or not approve_safe_crawl:
        raise NativeCrawlAuthorityDeniedError("native crawl requires explicit SAFE approval")

    plan = PlanNativeCrawl(workspace_root, scope_id, seed_url, selected_urls, owner_reference,
        policy_provider, limits=limits, clock=clock, current_owner_provider=current_owner_provider)
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    model_store = LocalModelStore(store.root)

    if workspace.revision != plan.workspace_revision or model_store.Open().revision != (
        plan.model_revision
    ):
        raise ValueError("native crawl canonical bases changed after planning")

    provider = NativeCrawlProvider(store.root, scope_id, seed_url, selected_urls, owner_reference,
        policy_provider, approve_safe_crawl=True, limits=limits, clock=clock,
        current_owner_provider=current_owner_provider)
    workflow = NativeCrawlWorkflow(provider, workspace)
    spec = JobSpec("job:native-crawl-" + uuid4().hex, workspace.workspace_id,
        "scope:" + scope_id, owner_reference, NATIVE_CRAWL_PROVIDER_ID, limits.timeout_seconds + 1)
    job = ScanJob(spec, workflow, evidence_store=provider.store, max_events=4096)
    started = time.monotonic()
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Forward actual safe job events without raw worker fragments or inferred progress.

        Args:
            event: One original ordered retained job event.
        """

        nonlocal cursor
        cursor = event.sequence

        if on_event is not None:
            on_event(event)

    try:
        async for event in job.Events():
            Observe(event)

    except asyncio.CancelledError:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))

        await SettleCrawlTask(cleanup)

        for event in job.EventsSince(cursor):
            Observe(event)

    except BaseException:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))

        await SettleCrawlTask(cleanup)

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

    status = "not-attempted"

    if workflow.attempted:
        status = "acknowledged" if workflow.acknowledged else (
            "observed-committed" if actual_workspace == workflow.proposed else
            "observed-unchanged" if actual_workspace == workspace else "unconfirmed")

    try:
        records = provider.Records()
        acknowledged = tuple(key for key, value in sorted(provider._publications.items())
                             if value[2])
        controls = tuple(json.loads(provider.store.Read(item.reference)) for item in records
                         if item.reference.role == "native-crawl-control")
        custody = "complete" if controls and len(records) == len(acknowledged) and all(
            item["original_stdout_id"] is not None and item["original_stderr_id"] is not None
            for item in controls) else "incomplete"

    except (EvidenceError, OSError, ValueError):
        records, acknowledged, custody = (), (), "unconfirmed"

    return NativeCrawlSummary(snapshot, records, provider.completed_urls,
        None if actual_model is None else actual_model.revision,
        None if actual_workspace is None else actual_workspace.revision,
        tuple(provider.model_saves), status, acknowledged, custody, job.EventsSince(),
        time.monotonic() - started)
