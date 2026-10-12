# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded SAFE Quick Scan orchestration over governed native discovery and owned jobs."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.discovery import (
    NATIVE_HTTP_CAPABILITY,
    NATIVE_HTTP_PROVIDER_ID,
    DiscoveryLimits,
    NativeDiscoveryProvider,
)
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
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
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, UtcNow
from fuzzy1337.scope import LocalScopeStore, Target
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError

QUICK_SCAN_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class QuickScanSummary:
    """Detached terminal evidence, measured timings and the exact ordered job event prefix."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    first_model_update_seconds: float | None
    first_update_budget_seconds: float
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]

    def ToDict(self) -> dict[str, object]:
        """Return schema-versioned machine output without raw payloads or secret resolution.

        Returns:
            Detached JSON fields reusing the exact owned job serialization contract.
        """

        return {
            "schema_version": QUICK_SCAN_SCHEMA_VERSION,
            "workflow": "quick",
            "state": self.snapshot.state.value,
            "capabilities": [NATIVE_HTTP_CAPABILITY],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "first_model_update_seconds": self.first_model_update_seconds,
            "first_update_budget_seconds": self.first_update_budget_seconds,
            "model_revision": self.model_revision,
            "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
        }

    def ExitCode(self) -> int:
        """Separate authorization, execution and cancellation from successful discovery.

        Returns:
            Zero for completed, three for denied, four for other failure, 130 for cancelled.
        """

        if self.snapshot.state is JobState.CANCELLED:
            return 130

        if self.snapshot.state is JobState.COMPLETED:
            return 0

        if self.snapshot.failure is not None and (
            self.snapshot.failure.code is JobFailureCode.AUTHORIZATION
        ):
            return 3

        return 4


@dataclass(frozen=True, slots=True)
class QuickScanWorkflow:
    """Persist discovered state references before the owning job declares its terminal state."""

    native: NativeDiscoveryProvider
    workspace_root: Path
    scope_id: str
    owner_reference: str
    snapshot: Callable[[], JobSnapshot]

    async def Run(self, context: JobContext) -> None:
        """Run the native provider and preserve partial acquired state on every exit.

        Args:
            context: Existing job-owned cancellation and evidence boundary.

        Raises:
            JobError: Ownership is denied or durable workspace references cannot be saved.
        """

        try:
            scope = LocalScopeStore(self.workspace_root).Open(self.scope_id)

            if scope.authorization.authority_reference != self.owner_reference:
                raise JobError(JobFailure(
                    JobFailureCode.AUTHORIZATION,
                    "Operator does not match recorded scope authority",
                ))

            await self.native.Run(context)

        finally:
            self.PersistReferences()

    def PersistReferences(self) -> None:
        """Verify retained acquisitions and save shared-model references after provider cleanup.

        Raises:
            JobError: Evidence verification, model reopening or workspace CAS fails.
        """

        try:
            snapshot = self.snapshot()
            store = LocalWorkspaceStore(self.workspace_root)
            workspace = store.Open()
            model = LocalModelStore(self.workspace_root).Open()
            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            references = {
                (item.locator, item.role): item for item in workspace.evidence_references
            }
            record_ids = set(workspace.evidence_record_references)

            for artifact in snapshot.artifacts:
                record = artifact.evidence

                if evidence.Get(record.evidence_id) != record:
                    raise ValueError("retained acquisition differs from its evidence record")

                evidence.Read(record.reference)
                references.setdefault((record.reference.locator, record.reference.role),
                                      record.reference)
                record_ids.add(record.evidence_id)

            store.Save(replace(
                workspace,
                scope_references=tuple(sorted({*workspace.scope_references,
                                               snapshot.spec.scope_reference})),
                object_references=tuple(sorted({*workspace.object_references,
                                                *(item.Reference() for item in model.objects)})),
                job_references=(*workspace.job_references, snapshot.spec.job_id),
                evidence_references=tuple(references[key] for key in sorted(references)),
                evidence_record_references=tuple(sorted(record_ids)),
            ))

        except (
            OSError, ValueError, EvidenceError, WorkspaceBusyError, WorkspaceConflictError,
        ) as error:
            raise JobError(JobFailure(
                JobFailureCode.STORAGE, "Could not preserve Quick Scan workspace references",
            )) from error


async def RunQuickScan(
    workspace_root: Path,
    scope_id: str,
    targets: tuple[Target, ...],
    owner_reference: str,
    *,
    approve_safe_http: bool = False,
    limits: DiscoveryLimits = DiscoveryLimits(),
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
) -> QuickScanSummary:
    """Start bounded discovery immediately and return truthful durable terminal evidence.

    Args:
        workspace_root: Existing workspace with an initialized authoritative model.
        scope_id: Existing explicit registration, allow/exclusion and consent snapshot.
        targets: Finite operator-selected literal-IP HTTP(S) URL targets.
        owner_reference: Operator reference matching recorded scope authority.
        approve_safe_http: Explicit capability opt-in; false produces policy denial.
        limits: Native provider's validated request, rate, endpoint and total bounds.
        on_event: Optional fast synchronous presentation consumer for ordered job events.
        clock: Explicit aware policy clock; injection permits deterministic validity tests.

    Returns:
        Terminal summary including measured first persisted-model-update time and event prefix.

    Raises:
        ValueError: Inputs, paths or authoritative state are invalid before a job starts.
        OSError: The initial authoritative workspace, scope or model cannot be opened.
        Exception: A presentation consumer fails, after the owned job has cleaned up.
    """

    if type(approve_safe_http) is not bool:
        raise ValueError("approve_safe_http must be an explicit boolean")

    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    model_store = LocalModelStore(workspace_store.root)
    model_store.Open()
    scope = LocalScopeStore(workspace_store.root).Open(scope_id)
    policy = ImpactPolicy(
        "quick-safe-http",
        permissions=(CapabilityPermission(
            NATIVE_HTTP_CAPABILITY, NATIVE_HTTP_PROVIDER_ID, ImpactLevel.SAFE,
        ),) if approve_safe_http else (),
    )
    native = NativeDiscoveryProvider(
        workspace_store.root, targets, scope_id, policy, limits=limits, clock=clock,
    )
    spec = JobSpec(
        "job:quick-" + uuid4().hex, workspace.workspace_id, scope.Reference(), owner_reference,
        NATIVE_HTTP_PROVIDER_ID, timeout_seconds=limits.timeout_seconds,
    )

    def Snapshot() -> JobSnapshot:
        """Bind the workflow to its owning handle before any provider task starts."""

        return job.Snapshot()

    workflow = QuickScanWorkflow(native, workspace_store.root, scope_id, owner_reference, Snapshot)
    job = ScanJob(
        spec, workflow, evidence_store=LocalEvidenceStore(workspace_store.root / "evidence"),
    )
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    first_update: float | None = None
    observed_cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Measure first persisted change and pass the unchanged event to the presentation sink."""

        nonlocal observed_cursor, first_update
        observed_cursor = event.sequence

        if event.kind is JobEventKind.MODEL_DELTA and first_update is None:
            first_update = time.monotonic() - started

        if on_event is not None:
            on_event(event)

    try:
        async for event in job.Events():
            Observe(event)

    except asyncio.CancelledError:
        await job.CancelAndWait(owner_reference)

        for event in job.EventsSince(observed_cursor):
            Observe(event)

    except Exception:
        await job.CancelAndWait(owner_reference)

        raise

    snapshot = await job.Wait()
    model = model_store.Open()

    return QuickScanSummary(
        snapshot, started_at, datetime.now(UTC).isoformat(), time.monotonic() - started,
        first_update, limits.FirstUpdateBudgetSeconds, model.revision,
        tuple((kind.value, len(model.Objects(kind))) for kind in ObjectKind), job.EventsSince(),
    )
