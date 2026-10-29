# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit first-party web response checks through existing governed Workbench owners."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import (
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.adapters.native_http import RequestTimeout
from fuzzy1337.adapters.native_web import (
    MAX_NATIVE_WEB_RECORD_BYTES,
    NATIVE_FILE_CANARY_CAPABILITY,
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_FILE_CANARY_PROFILE,
    NATIVE_PROMETHEUS_CAPABILITY,
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    NATIVE_WEB_VERSION,
    CanonicalRecord,
    NativeWebAdapter,
    NativeWebCheckFor,
    NativeWebEndpoint,
    NativeWebParameters,
)
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.executors.contracts import ExecutionTermination
from fuzzy1337.executors.local import EventCallback
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingSeverity
from fuzzy1337.jobs import (
    JobContext,
    JobError,
    JobEvent,
    JobFailure,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
    LocalExecutionJob,
    ScanJob,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.policy import (
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyConfirmation,
    PolicyContext,
    PolicyDeniedError,
    PolicyEngine,
    PolicyGrant,
    PolicyPlan,
    UtcNow,
)
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.requests import ProjectRequests, RequestsFromObject, RequestTemplate
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceText,
    WorkspaceBusyError,
    WorkspaceConflictError,
)

__all__ = [
    "NATIVE_WEB_PROVIDER_ID", "NATIVE_WEB_CAPABILITY", "NATIVE_WEB_CHECK_ID",
    "NATIVE_FILE_CANARY_CHECK_ID", "NATIVE_FILE_CANARY_CAPABILITY", "NATIVE_FILE_CANARY_PROFILE",
    "NATIVE_PROMETHEUS_CHECK_ID", "NATIVE_PROMETHEUS_CAPABILITY",
    "NativeWebAuthorityDeniedError", "NativeWebScanLimits", "NativeWebScanPlan",
    "NativeWebScanSummary", "PlanNativeWebScan", "RunNativeWebScan",
]


class NativeWebAuthorityDeniedError(PermissionError):
    """The selected operator differs from the current explicitly recorded consent actor."""


@dataclass(frozen=True, slots=True)
class NativeWebScanLimits:
    """Bound one complete request and its startup-inclusive owning job deadline."""

    request_timeout_seconds: float = 3.0
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        """Reject nonfinite/bool bounds and preserve enough room for worker startup/cleanup."""

        timeout = RequestTimeout(self.request_timeout_seconds)

        if type(self.timeout_seconds) is not int or not (
            math.ceil(timeout + 1) <= self.timeout_seconds <= 60
        ):
            raise ValueError("native web whole-job timeout must fit request/startup and at most 60")


@dataclass(frozen=True, slots=True)
class NativeWebScanPlan:
    """Exact native invocation and STANDARD confirmation intent; planning contacts no target."""

    invocation: AdapterInvocation
    policy_plan: PolicyPlan

    def ToDict(self) -> dict[str, object]:
        """Expose the complete immutable planned operation without granting execution.

        Returns:
            Detached schema-one exact invocation, policy intent and required confirmation fields.
        """

        return {
            "schema_version": 1, "workflow": "native-web", "state": "planned",
            "check_id": self.invocation.request.parameters.get("check_id", NATIVE_WEB_CHECK_ID),
            "impact": ImpactLevel.STANDARD.value,
            "confirmation_required": True, "intent_sha256": self.policy_plan.intent_sha256,
            "invocation": json.loads(SerializeContract(self.invocation)),
            "policy_plan": json.loads(SerializeContract(self.policy_plan)),
        }


def CurrentContext(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy],
    *, check_id: str = NATIVE_WEB_CHECK_ID,
) -> PolicyContext:
    """Reread explicit owner, current consent, URL/IP membership and typed operator policy.

    Args:
        workspace_root: Existing caller-owned persisted workspace partition.
        scope_id: Explicit current owning scope identifier.
        target: Exact canonical URL admitted by the explicit native request profile.
        owner_reference: Operator required to match the current recorded consent authority.
        policy_provider: Trusted synchronous reader of the current typed impact policy.
        check_id: Selected packaged check; its stricter destination profile remains enforced.

    Returns:
        Fresh current owner context joining the exact URL and its actual literal IP.
    """

    scope = LocalScopeStore(workspace_root).Open(scope_id)

    if scope.authorization.authority_reference != owner_reference:
        raise NativeWebAuthorityDeniedError("native web operator differs from current consent")

    policy = policy_provider()

    if type(policy) is not ImpactPolicy:
        raise ValueError("native web requires a typed current impact policy")

    _, address, _, _ = NativeWebEndpoint(target.value, check_id=check_id)

    return PolicyContext(scope, policy, target, (target, Target(TargetKind.IP, address)))


def PlanNativeWebScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy],
    *, check_id: str = NATIVE_WEB_CHECK_ID,
    limits: NativeWebScanLimits = NativeWebScanLimits(),
    clock: Callable[[], datetime] = UtcNow,
) -> NativeWebScanPlan:
    """Verify owned local state and plan one exact first-party STANDARD response check.

    Args:
        workspace_root: Existing initialized workspace, model, evidence and explicit scope.
        scope_id: Existing caller-selected current consented scope.
        target: One exact canonical URL admitted by the selected native request profile.
        owner_reference: Operator matching the recorded scope authority at every boundary.
        policy_provider: Trusted synchronous reader of current typed operator policy.
        check_id: Explicit registered predicate, defaulting to the original query-free Git check.
        limits: Finite complete-request and whole-operation deadlines.
        clock: Aware authority clock; planning performs no HTTP or subprocess execution.

    Returns:
        Exact invocation and intent digest requiring separate STANDARD confirmation.

    Raises:
        ValueError: Typed inputs, original evidence or stored state violate their contracts.
        PermissionError: Current operator, consent, scope or capability permission is denied.
        OSError: Authoritative local state cannot be read.
    """

    if type(target) is not Target or target.kind is not TargetKind.URL or (
        type(limits) is not NativeWebScanLimits
    ):
        raise ValueError("native web requires one exact URL target and typed limits")

    check = NativeWebCheckFor(check_id)
    NativeWebEndpoint(target.value, check_id=check_id)
    RequireWorkspaceText(owner_reference, "owner_reference")
    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    evidence = LocalEvidenceStore(workspace_store.root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    LocalModelStore(workspace_store.root).Open()
    authority = CurrentContext(workspace_store.root, scope_id, target, owner_reference,
                               policy_provider, check_id=check_id)
    adapter = NativeWebAdapter(evidence.Read)
    invocation = adapter.PrepareInvocation(AdapterRequest(
        check.capability, target.Reference(), ImpactLevel.STANDARD,
        NativeWebParameters(target.value, limits.request_timeout_seconds, check_id=check_id,
                            workspace_id=workspace.workspace_id),
    ))
    capability = next(item for item in CapabilityDescriptors(adapter.Descriptor)
                      if item.identifier == invocation.request.capability)
    policy_plan = PolicyEngine().Plan(invocation, capability, authority, at=clock())

    return NativeWebScanPlan(invocation, policy_plan)


@dataclass(frozen=True, slots=True)
class NativeWebScanSummary:
    """Truthful terminal job state and durable model counts, without arbitrary HTTP bytes."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]
    check_id: str = NATIVE_WEB_CHECK_ID

    def ToDict(self) -> dict[str, object]:
        """Serialize the existing job/evidence state and finite assessed capability only.

        Returns:
            Detached schema-one terminal fields with actual job/events and model counts.
        """

        return {
            "schema_version": 1, "workflow": "native-web", "check_id": self.check_id,
            "state": self.snapshot.state.value,
            "capabilities": [NativeWebCheckFor(self.check_id).capability],
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds, "model_revision": self.model_revision,
            "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
        }

    def ExitCode(self) -> int:
        """Keep completed/denied/failed/cancelled product exit codes 0/3/4/130.

        Returns:
            Zero for completion, three for authority denial, four for failure, 130 for cancellation.
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
class NativeWebWorkflow:
    """Compose unchanged policy, process, job, evidence and canonical Finding owners."""

    workspace_root: Path
    scope_id: str
    target: Target
    owner_reference: str
    policy_provider: Callable[[], ImpactPolicy]
    adapter: NativeWebAdapter
    invocation: AdapterInvocation
    confirmation: PolicyConfirmation | None
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]

    def Context(self) -> PolicyContext:
        """Reread current operator authority and verify the exact original selected invocation.

        Returns:
            Fresh owning policy/scope context for the same original prepared operation.
        """

        if self.adapter.PrepareInvocation(self.invocation.request) != self.invocation:
            raise ValueError("native web selected invocation changed")

        check_id = str(self.invocation.request.parameters.get("check_id", NATIVE_WEB_CHECK_ID))

        if check_id == NATIVE_FILE_CANARY_CHECK_ID:
            template = RequestTemplate.FromDict(JsonValue(
                self.invocation.request.parameters["request_template"]))

            if template.endpoint.workspace_id != (
                LocalWorkspaceStore(self.workspace_root).Open().workspace_id
            ):
                raise ValueError("owned canary request differs from its current workspace")

        return CurrentContext(self.workspace_root, self.scope_id, self.target,
                              self.owner_reference, self.policy_provider, check_id=check_id)

    async def Run(self, context: JobContext) -> None:
        """Run one exact confirmed worker and retain actual acquisitions on every terminal path.

        Args:
            context: Existing owning job's cancellation, event and original-evidence boundary.
        """

        try:
            try:
                capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
                                  if item.identifier == self.invocation.request.capability)
                grant = PolicyEngine().Authorize(self.invocation, capability, self.Context(),
                    at=self.clock(), confirmation=self.confirmation)

            except (NativeWebAuthorityDeniedError, PolicyDeniedError) as error:
                raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                          "Native web exact-plan execution was denied")) from error

            except (OSError, ValueError) as error:
                raise JobError(JobFailure(JobFailureCode.STORAGE,
                                          "Could not read current native web authority")) from error

            executor = GovernedLocalExecutor(self.workspace_root, clock=self.clock)
            completed_result: LocalExecutionResult | None = None

            async def Ingest(context: JobContext, report: AdapterReport) -> None:
                """Preserve the actual launch grant for the final current-authority CAS gate."""

                await self.Ingest(context, report, grant=grant)

            async def Execute(
                request: LocalExecutionRequest, *, on_event: EventCallback | None = None,
                cancellation: asyncio.Event | None = None,
            ) -> LocalExecutionResult:
                """Use the governed process owner and fresh scope immediately before launch."""

                nonlocal completed_result

                try:
                    completed_result = await executor.Execute(request, grant=grant,
                        context_provider=self.Context, on_event=on_event,
                        cancellation=cancellation)

                    return completed_result

                except (NativeWebAuthorityDeniedError, PolicyDeniedError):
                    raise

                except (OSError, ValueError) as error:
                    raise JobError(JobFailure(JobFailureCode.STORAGE,
                                              "Could not read final native web authority")) \
                        from error

            try:
                await LocalExecutionJob(LocalExecutionRequest(
                    self.invocation, capability, grant.authorization,
                    resources=ExecutionResources(MAX_NATIVE_WEB_RECORD_BYTES, 1024, 0.1),
                ), Execute, Ingest).Run(context)

            except JobError as error:
                # The process owner has already retained both actual original streams.
                if error.failure.code is JobFailureCode.PROVIDER and (
                    completed_result is not None
                    and completed_result.termination is ExecutionTermination.PROCESS_EXIT
                    and completed_result.execution.exit_code == 124
                    and completed_result.stdout == CanonicalRecord({
                        "schema_version": 1, "error": "timeout",
                    }) and completed_result.stderr == b""
                ):
                    raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                                              "Native web complete request deadline exceeded")) \
                        from error

                raise

        finally:
            self.PersistReferences()

    async def Ingest(
        self, context: JobContext, report: AdapterReport, *, grant: PolicyGrant,
    ) -> None:
        """Verify original worker metadata and save one canonical model transition.

        The metadata attests the original native process interpretation. The response
        body is deliberately absent, so reopening does not independently re-evaluate
        the HTTP predicate or authenticate the remote publisher.

        Args:
            context: Existing owning job receiving only actual canonical commits and metadata.
            report: Original successful execution and verified original stdout/stderr references.
            grant: The exact original launch grant, validated afresh immediately before Save.
        """

        normalized = self.adapter.NormalizeReport(report)
        provenance = ModelProvenance(NATIVE_WEB_PROVIDER_ID, context.Spec.job_id,
            self.clock().isoformat(), context.Spec.scope_reference, self.target.Reference(),
            NATIVE_WEB_VERSION, report.evidence, report.execution)
        store = LocalModelStore(self.workspace_root)
        state = store.Open()
        check_id = str(self.invocation.request.parameters.get("check_id", NATIVE_WEB_CHECK_ID))

        if check_id == NATIVE_FILE_CANARY_CHECK_ID:
            template = RequestTemplate.FromDict(JsonValue(
                self.invocation.request.parameters["request_template"]))

            if template.endpoint.workspace_id != state.workspace_id:
                raise ValueError("owned canary template differs from its model workspace")

            subject = template.endpoint.Identity()
            current = next((item for item in state.objects if item.identity == subject), None)
            previous = RequestsFromObject(current) if current is not None else ()
            templates = {item.Reference(): item for item in (*previous, template)}
            patch = ProjectRequests(tuple(templates[key] for key in sorted(templates)),
                                    provenance=(provenance,))
            projected, _ = state.Apply(objects=(patch,))

        else:
            subject = ObjectIdentity(state.workspace_id, ObjectKind.ENDPOINT, self.target.value)
            projected, _ = state.Apply(objects=(SecurityObject(subject, {"url": self.target.value},
                                                                (provenance,)),))
        projected, _ = projected.ApplyAdapterResult(
            normalized, {self.target.Reference(): subject}, provenance,
        )
        findings = tuple(Finding(
            subject.Reference(), check_id, self.target.value, item.summary,
            (provenance,), severity=FindingSeverity.LOW,
        ) for item in normalized.findings)
        projected, _ = ApplyVerifiedFindings(projected, findings, self.workspace_root)
        projected, _ = projected.Apply(observations=tuple(Observation(
            item.kind, subject.Reference(), dict(item.attributes), provenance,
        ) for item in normalized.observations))
        updated, delta = state.Apply(objects=projected.objects, relations=projected.relations,
                                      observations=projected.observations)

        try:
            context.CheckCancellation()
            PolicyEngine().Validate(grant, self.invocation,
                next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
                     if item.identifier == self.invocation.request.capability),
                self.Context(), at=self.clock())

        except (NativeWebAuthorityDeniedError, PolicyDeniedError) as error:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                      "Native web authority changed before model persistence")) \
                from error

        except (OSError, ValueError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not verify native web final authority")) from error

        try:
            store.Save(updated, expected_revision=state.revision)

        except (OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not persist native web model findings")) from error

        context.ModelChanged(delta)

        for observation in normalized.observations:
            context.Observe(observation)

        context.Progress(1, 1)

    def PersistReferences(self) -> None:
        """Verify old and acquired evidence and preserve actual model/job references before exit."""

        try:
            snapshot = self.snapshot()
            store = LocalWorkspaceStore(self.workspace_root)
            workspace = store.Open()
            model = LocalModelStore(self.workspace_root).Open()
            evidence = LocalEvidenceStore(self.workspace_root / "evidence")
            VerifyWorkspaceEvidence(workspace, evidence)
            references = {(item.locator, item.role): item for item in workspace.evidence_references}
            record_ids = set(workspace.evidence_record_references)

            for artifact in snapshot.artifacts:
                record = artifact.evidence

                if evidence.Get(record.evidence_id) != record:
                    raise ValueError("native web retained acquisition differs from its record")

                evidence.Read(record.reference)
                references.setdefault((record.reference.locator, record.reference.role),
                                      record.reference)
                record_ids.add(record.evidence_id)

            store.Save(replace(workspace,
                scope_references=tuple(sorted({*workspace.scope_references,
                                               snapshot.spec.scope_reference})),
                object_references=tuple(sorted({*workspace.object_references,
                                                *(item.Reference() for item in model.objects)})),
                job_references=(*workspace.job_references, snapshot.spec.job_id),
                evidence_references=tuple(references[key] for key in sorted(references)),
                evidence_record_references=tuple(sorted(record_ids)),
            ))

        except (OSError, ValueError, EvidenceError, WorkspaceBusyError,
                WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not preserve native web workspace references")) \
                from error


async def RunNativeWebScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy],
    *, confirmation: PolicyConfirmation | None = None,
    check_id: str = NATIVE_WEB_CHECK_ID,
    limits: NativeWebScanLimits = NativeWebScanLimits(),
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
) -> NativeWebScanSummary:
    """Rebuild a current exact plan and execute one explicitly confirmed native check.

    Args:
        workspace_root: Existing owned workspace/model/evidence and explicit current scope.
        scope_id: Selected current persisted scope.
        target: One exact canonical URL admitted by the explicit selected native profile.
        owner_reference: Operator matching recorded consent at every authority boundary.
        policy_provider: Trusted fresh typed policy reader, never an implicit capability grant.
        confirmation: Separate STANDARD confirmation binding the exact previously shown intent.
        check_id: Registered native predicate; default Git invocation/report behavior is unchanged.
        limits: Finite request and whole-job time budgets.
        on_event: Fast synchronous presentation sink; errors cancel and await owned cleanup.
        clock: Aware authority clock used again at launch and immediately before model Save.

    Returns:
        Truthful owned terminal result after worker cleanup and workspace reference persistence.

    Raises:
        ValueError: Initial request, evidence or stored state violates its owning contract.
        PermissionError: Initial planning fails current operator/scope/capability authority.
        OSError: Initial authoritative local state cannot be read.
        Exception: Presentation fails after cancellation and actual owned worker cleanup.
    """

    plan = PlanNativeWebScan(workspace_root, scope_id, target, owner_reference,
                            policy_provider, check_id=check_id, limits=limits, clock=clock)
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    evidence = LocalEvidenceStore(store.root / "evidence")
    adapter = NativeWebAdapter(evidence.Read)
    spec = JobSpec("job:native-web-" + uuid4().hex, workspace.workspace_id,
                   plan.policy_plan.scope_reference, owner_reference, NATIVE_WEB_PROVIDER_ID,
                   timeout_seconds=limits.timeout_seconds)

    def Snapshot() -> JobSnapshot:
        """Bind the workflow to its original job before any process can launch."""

        return job.Snapshot()

    provider = NativeWebWorkflow(store.root, scope_id, target, owner_reference, policy_provider,
                                adapter, plan.invocation, confirmation, Snapshot, clock)
    job = ScanJob(spec, provider, evidence_store=evidence)
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Forward only owned job metadata and retain the exact presentation cursor."""

        nonlocal cursor
        cursor = event.sequence

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
    model = LocalModelStore(store.root).Open()

    return NativeWebScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, model.revision,
        tuple((kind.value, len(model.Objects(kind))) for kind in ObjectKind), job.EventsSince(),
        check_id=check_id)
