# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite optional TCP-connect scans through existing governed Workbench owners."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import (
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.nmap import NMAP_MAX_TIMEOUT_SECONDS, NMAP_XML_MAX_BYTES, NmapAdapter
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.executors.local import EventCallback
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
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectIdentity, ObjectKind
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
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceText,
    WorkspaceBusyError,
    WorkspaceConflictError,
)

PORT_SCAN_PROVIDER_ID = "native.nmap"
PORT_SCAN_CAPABILITY = "network.tcp-connect"

__all__ = [
    "PORT_SCAN_PROVIDER_ID", "PORT_SCAN_CAPABILITY", "PortScanAuthorityDeniedError",
    "PortScanUnavailableError", "PortScanLimits", "PortScanPlan", "PortScanSummary",
    "PlanPortScan", "RunPortScan",
]


class PortScanAuthorityDeniedError(PermissionError):
    """The selected operator differs from the current recorded scope consent actor."""


class PortScanUnavailableError(RuntimeError):
    """The explicitly selected optional Nmap executable is unavailable or unhealthy."""


@dataclass(frozen=True, slots=True)
class PortScanLimits:
    """Bound host/executor time; the owning job adds five seconds for cleanup and custody."""

    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        """Reject booleans and timeouts outside the existing adapter contract."""

        if type(self.timeout_seconds) is not int or not (
            1 <= self.timeout_seconds <= NMAP_MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("port scan timeout must be an integer from 1 through 3600")


@dataclass(frozen=True, slots=True)
class PortScanPlan:
    """Read-only exact invocation and STANDARD confirmation intent for one finite scan."""

    invocation: AdapterInvocation
    policy_plan: PolicyPlan

    def ToDict(self) -> dict[str, object]:
        """Expose exact provider inputs and current intent without granting execution.

        Returns:
            Detached schema-one invocation, policy plan, and required confirmation fields.
        """

        return {
            "schema_version": 1, "workflow": "ports", "state": "planned",
            "impact": ImpactLevel.STANDARD.value, "confirmation_required": True,
            "intent_sha256": self.policy_plan.intent_sha256,
            "invocation": json.loads(SerializeContract(self.invocation)),
            "policy_plan": json.loads(SerializeContract(self.policy_plan)),
        }


def PortRequest(target: Target, ports: tuple[int, ...], limits: PortScanLimits) -> AdapterRequest:
    """Bind actual address and opaque subject to the same explicitly selected literal IP.

    Args:
        target: Canonical IP target; URL, domain, network, and artifact targets are refused.
        ports: Immutable explicit port selection, validated by the existing Nmap adapter.
        limits: Typed existing finite timeout; no permission is derived from these limits.

    Returns:
        The sole supported STANDARD TCP-connect request without credentials or arbitrary flags.
    """

    if type(target) is not Target or target.kind is not TargetKind.IP or (
        type(ports) is not tuple or type(limits) is not PortScanLimits
    ):
        raise ValueError("port scan requires an IP target, explicit port tuple, and typed limits")

    return AdapterRequest(PORT_SCAN_CAPABILITY, target.Reference(), ImpactLevel.STANDARD,
        {"address": target.value, "ports": ports, "timeout_seconds": limits.timeout_seconds})


def CurrentContext(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy],
) -> PolicyContext:
    """Read current recorded actor, consent, IP scope, and explicit typed capability policy.

    Args:
        workspace_root: Existing owning workspace partition.
        scope_id: Explicit existing scope; this reader never registers a target.
        target: The same canonical IP used as the actual invocation address.
        owner_reference: Operator required to match the current recorded authority.
        policy_provider: Trusted fresh policy reader; omissions grant no permission.

    Returns:
        Current policy context with exactly the selected IP as its actual destination.
    """

    scope = LocalScopeStore(workspace_root).Open(scope_id)

    if scope.authorization.authority_reference != owner_reference:
        raise PortScanAuthorityDeniedError("port scan operator differs from current scope consent")

    policy = policy_provider()

    if type(policy) is not ImpactPolicy:
        raise ValueError("port scan requires a typed current impact policy")

    return PolicyContext(scope, policy, target, (target,))


def PlanPortScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    ports: tuple[int, ...], executable: str, policy_provider: Callable[[], ImpactPolicy],
    *, limits: PortScanLimits = PortScanLimits(), clock: Callable[[], datetime] = UtcNow,
) -> PortScanPlan:
    """Plan one finite optional TCP-connect operation without contacting a target.

    Args:
        workspace_root: Existing initialized workspace, model, and verified retained evidence.
        scope_id: Explicit existing IP scope with independently granted consent.
        target: One selected literal IP; no DNS resolution or target expansion occurs.
        owner_reference: Operator matching current recorded scope authority.
        ports: Explicit unique TCP ports, one through 1024 entries, each from 1 through 65535.
        executable: Explicit trusted absolute local Nmap executable, never installed implicitly.
        policy_provider: Fresh synchronous typed policy reader; no authority defaults are added.
        limits: Existing Nmap/executor timeout; the owning job adds five cleanup/custody seconds.
        clock: Aware authority clock; only the bounded local version probe may execute here.

    Returns:
        Exact invocation and policy intent requiring a separate STANDARD confirmation.

    Raises:
        ValueError: Selection, retained evidence, or stored state violates its contract.
        PermissionError: Current owner, consent, scope, capability, or impact is denied.
        PortScanUnavailableError: The selected optional executable is unavailable or unhealthy.
        OSError: Initial authoritative local state cannot be read.
    """

    request = PortRequest(target, ports, limits)
    RequireWorkspaceText(owner_reference, "owner_reference")

    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise ValueError("port scan requires an explicit absolute trusted Nmap executable")

    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    evidence = LocalEvidenceStore(workspace_store.root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    LocalModelStore(workspace_store.root).Open()
    authority = CurrentContext(workspace_store.root, scope_id, target, owner_reference,
                               policy_provider)
    adapter = NmapAdapter(evidence.Read, executable)
    invocation = adapter.PrepareInvocation(request)
    capability = next(item for item in CapabilityDescriptors(adapter.Descriptor)
                      if item.identifier == PORT_SCAN_CAPABILITY)
    PolicyEngine().Plan(invocation, capability, authority, at=clock())
    health = adapter.CheckHealth()

    if health.state is not AdapterHealthState.AVAILABLE or health.provider_version is None:
        raise PortScanUnavailableError("Selected optional Nmap is unavailable or unhealthy")

    adapter = NmapAdapter(evidence.Read, executable, health.provider_version)
    invocation = adapter.PrepareInvocation(request)
    policy_plan = PolicyEngine().Plan(invocation, capability,
        CurrentContext(workspace_store.root, scope_id, target, owner_reference, policy_provider),
        at=clock())

    return PortScanPlan(invocation, policy_plan)


@dataclass(frozen=True, slots=True)
class PortScanSummary:
    """Truthful owned-job terminal state and durable canonical discovery counts."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]

    def ToDict(self) -> dict[str, object]:
        """Serialize actual job/evidence state without claiming all selected ports were assessed.

        Returns:
            Detached schema-one terminal fields, model counts, and ordered job events.
        """

        return {
            "schema_version": 1, "workflow": "ports", "state": self.snapshot.state.value,
            "capabilities": [PORT_SCAN_CAPABILITY],
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
class PortScanWorkflow:
    """Compose existing policy, process, job, evidence, and canonical discovery owners."""

    workspace_root: Path
    scope_id: str
    target: Target
    owner_reference: str
    ports: tuple[int, ...]
    limits: PortScanLimits
    policy_provider: Callable[[], ImpactPolicy]
    adapter: NmapAdapter
    invocation: AdapterInvocation
    confirmation: PolicyConfirmation | None
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]

    def Context(self) -> PolicyContext:
        """Rebind actual address to the selected target and reread current operator authority.

        Returns:
            Current owning scope/policy context for the exact originally selected operation.
        """

        expected = self.adapter.PrepareInvocation(PortRequest(self.target, self.ports, self.limits))

        if expected != self.invocation:
            raise ValueError("port scan selected invocation changed")

        return CurrentContext(self.workspace_root, self.scope_id, self.target,
                              self.owner_reference, self.policy_provider)

    async def Run(self, context: JobContext) -> None:
        """Authorize the exact confirmed invocation and preserve acquisitions before completion.

        Args:
            context: Existing owner of job events, cancellation, and original raw evidence.
        """

        try:
            capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
                              if item.identifier == PORT_SCAN_CAPABILITY)

            try:
                grant = PolicyEngine().Authorize(self.invocation, capability, self.Context(),
                    at=self.clock(), confirmation=self.confirmation)

            except (PortScanAuthorityDeniedError, PolicyDeniedError) as error:
                raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                          "Port scan exact-plan execution was denied")) from error

            except (OSError, ValueError) as error:
                raise JobError(JobFailure(JobFailureCode.STORAGE,
                                          "Could not verify port scan authority")) from error

            executor = GovernedLocalExecutor(self.workspace_root, clock=self.clock)

            async def Ingest(owner: JobContext, report: AdapterReport) -> None:
                """Keep the original launch grant for the final canonical persistence check."""

                await self.Ingest(owner, report, grant=grant)

            async def Execute(
                request: LocalExecutionRequest, *, on_event: EventCallback | None = None,
                cancellation: asyncio.Event | None = None,
            ) -> LocalExecutionResult:
                """Supply fresh current authority at the existing process owner's launch hook."""

                try:
                    return await executor.Execute(request, grant=grant,
                        context_provider=self.Context, on_event=on_event, cancellation=cancellation)

                except (PortScanAuthorityDeniedError, PolicyDeniedError):
                    raise

                except (OSError, ValueError) as error:
                    raise JobError(JobFailure(JobFailureCode.STORAGE,
                        "Could not verify final port scan authority")) from error

            await LocalExecutionJob(LocalExecutionRequest(
                self.invocation, capability, grant.authorization,
                resources=ExecutionResources(NMAP_XML_MAX_BYTES, 64 * 1024, 0.2),
            ), Execute, Ingest).Run(context)

        finally:
            self.PersistReferences()

    async def Ingest(
        self, context: JobContext, report: AdapterReport, *, grant: PolicyGrant,
    ) -> None:
        """Map reported facts to existing Host/Port/Service identities and save under current grant.

        Args:
            context: Owning job, receiving only actually saved model deltas and observations.
            report: Original successful executor facts and verified stdout/stderr references.
            grant: The exact launch grant, revalidated immediately before model CAS Save.
        """

        normalized = self.adapter.NormalizeReport(report)
        state = LocalModelStore(self.workspace_root).Open()
        subject = self.target.Reference()
        bindings = {subject: ObjectIdentity(state.workspace_id, ObjectKind.HOST, self.target.value)}

        for port in self.ports:
            provider_port = f"{subject}:tcp:{port}"
            natural_port = f"host:{self.target.value}/tcp/{port}"
            bindings[provider_port] = ObjectIdentity(
                state.workspace_id, ObjectKind.PORT, natural_port,
            )
            bindings[provider_port + ":service"] = ObjectIdentity(
                state.workspace_id, ObjectKind.SERVICE, natural_port,
            )

        # A run without a reported host has no canonical observation subject; its run
        # metadata remains in the original report and job events without inventing a Host.
        projected = normalized if normalized.object_enrichments else replace(
            normalized, observations=(),
        )
        updated, delta = state.ApplyAdapterResult(projected, bindings, ModelProvenance(
            self.adapter.Descriptor.adapter_id, context.Spec.job_id, self.clock().isoformat(),
            context.Spec.scope_reference, subject, report.invocation.provider_version,
            report.evidence, report.execution,
        ))

        try:
            context.CheckCancellation()
            capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
                              if item.identifier == PORT_SCAN_CAPABILITY)
            PolicyEngine().Validate(grant, self.invocation, capability,
                                    self.Context(), at=self.clock())

        except (PortScanAuthorityDeniedError, PolicyDeniedError) as error:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                      "Port scan authority changed before model persistence")) \
                from error

        except (OSError, ValueError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not verify port scan save authority")) from error

        try:
            LocalModelStore(self.workspace_root).Save(updated, expected_revision=state.revision)

        except (OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not persist port scan observations")) from error

        context.ModelChanged(delta)

        for observation in normalized.observations:
            context.Observe(observation)

        context.Progress(1, 1)

    def PersistReferences(self) -> None:
        """Verify retained originals and preserve acquisition/model/job workspace references."""

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
                    raise ValueError("Port scan acquisition differs from its original record")

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
                                      "Could not preserve port scan workspace")) from error


async def RunPortScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    ports: tuple[int, ...], executable: str, policy_provider: Callable[[], ImpactPolicy],
    *, confirmation: PolicyConfirmation | None = None, limits: PortScanLimits = PortScanLimits(),
    on_event: Callable[[JobEvent], None] | None = None, clock: Callable[[], datetime] = UtcNow,
) -> PortScanSummary:
    """Rebuild the current exact plan and run one explicitly confirmed finite TCP-connect scan.

    Args:
        workspace_root: Existing initialized caller-owned workspace partition.
        scope_id: Explicit current recorded IP scope; execution never broadens membership.
        target: The selected literal IP, also used as the sole actual policy destination.
        owner_reference: Operator matching current recorded consent at every authority boundary.
        ports: Explicit immutable unique TCP port selection under the existing adapter bounds.
        executable: Explicit trusted absolute optional Nmap executable, never installed implicitly.
        policy_provider: Trusted fresh typed policy reader with explicit capability permission.
        confirmation: Separate STANDARD approval binding the exact previously presented intent.
        limits: Finite host/executor deadline, plus five owning-job cleanup/custody seconds.
        on_event: Fast synchronous presentation sink; errors cancel and await owned cleanup.
        clock: Aware authority clock checked at planning, launch, and immediately before Save.

    Returns:
        Truthful terminal job result after owned cleanup and workspace reference persistence.

    Raises:
        ValueError: Initial selection, evidence, or stored state violates its contract.
        PermissionError: Initial current scope, owner, or capability authority is denied.
        PortScanUnavailableError: The optional selected provider is unavailable or unhealthy.
        OSError: Initial authoritative local state cannot be read.
        Exception: Presentation fails after actual owned cancellation and cleanup.
    """

    plan = PlanPortScan(workspace_root, scope_id, target, owner_reference, ports, executable,
                        policy_provider, limits=limits, clock=clock)
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    evidence = LocalEvidenceStore(store.root / "evidence")
    adapter = NmapAdapter(evidence.Read, executable, plan.invocation.provider_version)
    spec = JobSpec("job:ports-" + uuid4().hex, workspace.workspace_id,
        plan.policy_plan.scope_reference, owner_reference, PORT_SCAN_PROVIDER_ID,
        timeout_seconds=limits.timeout_seconds + 5)

    def Snapshot() -> JobSnapshot:
        """Bind the workflow to its original job before any target process can launch."""

        return job.Snapshot()

    provider = PortScanWorkflow(store.root, scope_id, target, owner_reference, ports, limits,
        policy_provider, adapter, plan.invocation, confirmation, Snapshot, clock)
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

    return PortScanSummary(snapshot, started_at, datetime.now(UTC).isoformat(),
        time.monotonic() - started, model.revision,
        tuple((kind.value, len(model.Objects(kind))) for kind in ObjectKind), job.EventsSince())
