# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit STANDARD Nuclei planning and governed durable Workbench execution."""

from __future__ import annotations

import asyncio
import json
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from uuid import uuid4

from fuzzy1337.adapters import (
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.nuclei import (
    NUCLEI_JSONL_MAX_BYTES,
    CanonicalUrl,
    NucleiAdapter,
    NucleiProfile,
    NucleiTemplate,
    RejectJsonConstant,
    RequireInteger,
    UniqueJsonObject,
)
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    LocalExecutionRequest,
    LocalExecutionResult,
)
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
    CapabilityPermission,
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
    WorkspaceFields,
)

NUCLEI_SCAN_SCHEMA_VERSION = 1
NUCLEI_CONFIGURATION_MAX_BYTES = 256 * 1024

__all__ = [
    "NUCLEI_SCAN_SCHEMA_VERSION", "NUCLEI_CONFIGURATION_MAX_BYTES", "NucleiScanLimits",
    "NucleiScanPlan", "NucleiScanSummary", "NucleiUnavailableError", "NucleiAuthorityDeniedError",
    "ReadNucleiProfile",
    "ReadNucleiPolicy", "PlanNucleiScan", "RunNucleiScan",
]


class NucleiUnavailableError(RuntimeError):
    """The explicitly selected optional provider failed its bounded local version probe."""


class NucleiAuthorityDeniedError(PermissionError):
    """The workflow's selected operator differs from the current recorded consent actor.

    This typed workflow denial remains distinct from filesystem PermissionError.
    Core scope, impact and exact-plan decisions retain PolicyDeniedError.
    """


def ReadConfiguration(path: Path) -> object:
    """Read bounded strict local JSON without following observed filesystem links.

    Args:
        path: Operator-selected profile or policy metadata file; not a target resource.

    Returns:
        Detached unique-key, finite JSON data.

    Raises:
        ValueError: The file, size, nesting or JSON violates the finite configuration contract.
        OSError: The supplied local artifact is unreadable.
    """

    path = Path(path).absolute()

    for component in (*reversed(path.parents), path):
        metadata = component.lstat()

        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", False):
            raise ValueError("Nuclei configuration cannot traverse filesystem links")

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("Nuclei configuration must be a singly linked regular file")

    with path.open("rb") as stream:
        raw = stream.read(NUCLEI_CONFIGURATION_MAX_BYTES + 1)

    if len(raw) > NUCLEI_CONFIGURATION_MAX_BYTES:
        raise ValueError("Nuclei configuration exceeds the byte budget")

    try:
        value: object = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueJsonObject,
                                   parse_constant=RejectJsonConstant)

    except (ValueError, RecursionError) as error:
        raise ValueError("Nuclei configuration is invalid strict JSON") from error

    pending = [(value, 0)]
    count = 0

    while pending:
        item, depth = pending.pop()
        count += 1

        if depth > 16 or count > 4096:
            raise ValueError("Nuclei configuration exceeds the structural budget")

        if isinstance(item, dict):
            pending.extend((nested, depth + 1) for nested in item.values())

        elif isinstance(item, list):
            pending.extend((nested, depth + 1) for nested in item)

        elif isinstance(item, float):
            # Both configuration schemas require integers; exponent overflow is also rejected.
            raise ValueError("Nuclei configuration does not accept floating-point values")

    return value


def ReadNucleiProfile(path: Path) -> NucleiProfile:
    """Decode exactly existing NucleiProfile metadata without creating a template review.

    Args:
        path: Bounded strict JSON containing profile_id, templates and configuration_path.

    Returns:
        Typed finite adapter profile with operator-supplied review provenance.

    Raises:
        ValueError: Unknown fields, material metadata or collection types are invalid.
        OSError: The supplied local profile cannot be read.
    """

    record = WorkspaceFields(ReadConfiguration(path),
        {field.name for field in fields(NucleiProfile)}, "Nuclei profile")
    templates = record["templates"]

    if not isinstance(templates, list) or not 1 <= len(templates) <= 32:
        raise ValueError("Nuclei profile requires a finite template array")

    records = tuple(WorkspaceFields(value, {field.name for field in fields(NucleiTemplate)},
                                    "Nuclei template") for value in templates)
    selected = tuple(NucleiTemplate(
        RequireWorkspaceText(value["template_id"], "template_id"),
        RequireWorkspaceText(value["path"], "path"),
        RequireWorkspaceText(value["sha256"], "sha256"),
        RequireInteger(value["size_bytes"], 1, 256 * 1024, "size_bytes"),
        RequireWorkspaceText(value["source_reference"], "source_reference"),
        RequireWorkspaceText(value["source_revision"], "source_revision"),
        RequireWorkspaceText(value["review_reference"], "review_reference"),
        RequireWorkspaceText(value["reviewed_profile"], "reviewed_profile"),
    ) for value in records)

    return NucleiProfile(
        RequireWorkspaceText(record["profile_id"], "profile_id"), selected,
        RequireWorkspaceText(record["configuration_path"], "configuration_path"),
    )


def ReadNucleiPolicy(path: Path) -> ImpactPolicy:
    """Decode exact existing policy serialization; omissions never imply permissions.

    Args:
        path: Strict JSON matching SerializeContract(ImpactPolicy(...)).

    Returns:
        Typed policy evaluated by the existing policy engine at planning and final launch.

    Raises:
        ValueError: Unknown/missing fields, enums, integer bounds or permissions are invalid.
        OSError: The supplied local policy cannot be read.
    """

    record = WorkspaceFields(ReadConfiguration(path),
        {field.name for field in fields(ImpactPolicy)}, "Nuclei policy")
    values = record["permissions"]

    if not isinstance(values, list) or len(values) > 64:
        raise ValueError("Nuclei policy requires a finite permissions array")

    permissions = []

    for value in values:
        entry = WorkspaceFields(value, {field.name for field in fields(CapabilityPermission)},
                                "Nuclei permission")
        privileges = entry["granted_privileges"]

        if not isinstance(privileges, list) or len(privileges) > 64:
            raise ValueError("Nuclei privileges must be a finite explicit array")

        permissions.append(CapabilityPermission(
            RequireWorkspaceText(entry["capability_id"], "capability_id"),
            RequireWorkspaceText(entry["adapter_id"], "adapter_id"),
            ImpactLevel(RequireWorkspaceText(entry["maximum_impact"], "maximum_impact")),
            tuple(RequireWorkspaceText(item, "privilege") for item in privileges),
        ))

    return ImpactPolicy(
        RequireWorkspaceText(record["policy_id"], "policy_id"),
        cast(int, record["revision"]),
        ImpactLevel(RequireWorkspaceText(record["maximum_impact"], "maximum_impact")),
        tuple(permissions), cast(int, record["max_authorization_seconds"]),
    )


@dataclass(frozen=True, slots=True)
class NucleiScanLimits:
    """Bound one exact endpoint's provider deadline and sequential request rate."""

    timeout_seconds: int = 30
    rate_limit: int = 2

    def __post_init__(self) -> None:
        """Reuse the adapter's finite integer contract without accepting booleans."""

        RequireInteger(self.timeout_seconds, 1, 300, "Nuclei workflow timeout")
        RequireInteger(self.rate_limit, 1, 10, "Nuclei workflow rate limit")


@dataclass(frozen=True, slots=True)
class NucleiScanPlan:
    """Read-only exact invocation and policy intent for explicit STANDARD confirmation."""

    invocation: AdapterInvocation
    policy_plan: PolicyPlan
    profile: NucleiProfile

    def ToDict(self) -> dict[str, object]:
        """Expose all selected material, exact argv and digest; this document grants nothing.

        Returns:
            Schema-v1 detached planning fields without raw target data or resolved secrets.
        """

        return {
            "schema_version": NUCLEI_SCAN_SCHEMA_VERSION, "workflow": "nuclei", "state": "planned",
            "impact": ImpactLevel.STANDARD.value, "confirmation_required": True,
            "intent_sha256": self.policy_plan.intent_sha256,
            "invocation": json.loads(SerializeContract(self.invocation)),
            "policy_plan": json.loads(SerializeContract(self.policy_plan)),
            "profile": json.loads(SerializeContract(self.profile)),
        }


def CurrentContext(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy],
) -> PolicyContext:
    """Reread consent actor, registered URL/IP destinations and current operator policy.

    Args:
        workspace_root: Existing authoritative local workspace.
        scope_id: Persisted scope selected by the operator.
        target: Exact literal-IP URL, without resolution or target contact.
        owner_reference: Operator that must match the current scope consent actor.
        policy_provider: Trusted synchronous fresh policy reader, granting no default permission.

    Returns:
        Existing policy-engine context with both exact URL and its explicit actual address.

    Raises:
        NucleiAuthorityDeniedError: The actor changed or differs from the selected owner.
        ValueError: A reader returns an untyped policy or invalid local state.
        OSError: Current authority cannot be read.
    """

    scope = LocalScopeStore(workspace_root).Open(scope_id)

    if scope.authorization.authority_reference != owner_reference:
        raise NucleiAuthorityDeniedError("Nuclei operator does not match current scope authority")

    return PolicyContext(scope, policy_provider(), target, (
        target, Target(TargetKind.IP, urlsplit(target.value).hostname or ""),
    ))


def PlanNucleiScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    profile: NucleiProfile, executable: str, policy_provider: Callable[[], ImpactPolicy],
    *, limits: NucleiScanLimits = NucleiScanLimits(), clock: Callable[[], datetime] = UtcNow,
) -> NucleiScanPlan:
    """Verify local state/material/version and plan one exact STANDARD operation.

    Args:
        workspace_root: Existing workspace with initialized model and verified old acquisitions.
        scope_id: Existing scope with independently granted current consent.
        target: One operator-selected literal-IP HTTP(S) endpoint.
        owner_reference: Operator matching current consent authority.
        profile: Actual operator-reviewed immutable finite local HTTP template profile.
        executable: Explicit absolute path to an optional locally installed Nuclei 3.x executable.
        policy_provider: Fresh trusted synchronous policy reader; registration grants nothing.
        limits: Finite exact request-rate and execution deadline.
        clock: Aware authority clock; no target process is started during planning.

    Returns:
        Exact plan for subsequent operator confirmation; version probing grants no scan authority.

    Raises:
        ValueError: Input, material, path or stored state is invalid.
        PermissionError: Scope, owner, destination, provider or impact is denied.
        NucleiUnavailableError: The optional provider is absent or not observed compatible 3.x.
        OSError: Initial local state is unreadable.
        EvidenceError: Retained raw acquisition integrity fails.
    """

    if not isinstance(target, Target) or target.kind is not TargetKind.URL:
        raise ValueError("Nuclei workflow requires one exact URL target")

    CanonicalUrl(target.value)

    if not Path(executable).is_absolute() or not isinstance(limits, NucleiScanLimits):
        raise ValueError("Nuclei workflow requires an absolute executable and typed limits")

    RequireWorkspaceText(owner_reference, "owner_reference")
    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Open()
    evidence = LocalEvidenceStore(workspace_store.root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    LocalModelStore(workspace_store.root).Open()
    authority = CurrentContext(workspace_store.root, scope_id, target, owner_reference,
                               policy_provider)
    adapter = NucleiAdapter(evidence.Read, profile, executable)
    health = adapter.CheckHealth()

    if health.state is not AdapterHealthState.AVAILABLE or health.provider_version is None:
        raise NucleiUnavailableError("Selected Nuclei provider is unavailable or incompatible")

    adapter = NucleiAdapter(evidence.Read, profile, executable, health.provider_version)
    invocation = adapter.PrepareInvocation(AdapterRequest(
        "web.http-template-check", target.Reference(), ImpactLevel.STANDARD,
        {"url": target.value, "profile_sha256": profile.Digest,
         "timeout_seconds": limits.timeout_seconds, "rate_limit": limits.rate_limit},
    ))
    plan = PolicyEngine().Plan(invocation, CapabilityDescriptors(adapter.Descriptor)[0],
                               authority, at=clock())

    return NucleiScanPlan(invocation, plan, profile)


@dataclass(frozen=True, slots=True)
class NucleiScanSummary:
    """Terminal owned-job result with durable model counts and exact observed events."""

    snapshot: JobSnapshot
    started_at: str
    finished_at: str
    duration_seconds: float
    model_revision: int
    object_counts: tuple[tuple[str, int], ...]
    events: tuple[JobEvent, ...]

    def ToDict(self) -> dict[str, object]:
        """Serialize existing job state without inventing template coverage or target safety.

        Returns:
            Detached schema-v1 machine output; raw streams stay in immutable evidence.
        """

        return {
            "schema_version": NUCLEI_SCAN_SCHEMA_VERSION, "workflow": "nuclei",
            "state": self.snapshot.state.value, "capabilities": ["web.http-template-check"],
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds, "model_revision": self.model_revision,
            "object_counts": dict(self.object_counts),
            "job": json.loads(SerializeContract(self.snapshot)),
            "events": json.loads(SerializeContract(self.events)),
        }

    def ExitCode(self) -> int:
        """Retain the product's completed/denied/failed/cancelled exit-code convention.

        Returns:
            Zero for completed, three for denial, four for failure, 130 for cancellation.
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
class NucleiWorkflow:
    """Compose existing authority, executor, evidence, findings and model owners."""

    workspace_root: Path
    scope_id: str
    target: Target
    owner_reference: str
    policy_provider: Callable[[], ImpactPolicy]
    adapter: NucleiAdapter
    invocation: AdapterInvocation
    confirmation: PolicyConfirmation | None
    snapshot: Callable[[], JobSnapshot]
    clock: Callable[[], datetime]

    def Context(self) -> PolicyContext:
        """Verify selected artifact bytes and reread authority immediately before launch.

        Returns:
            Fresh scope/consent/actor/policy context; immutable material must still match.
        """

        if self.adapter.PrepareInvocation(self.invocation.request) != self.invocation:
            raise ValueError("Nuclei material changed from the selected invocation")

        return CurrentContext(self.workspace_root, self.scope_id, self.target,
                              self.owner_reference, self.policy_provider)

    async def Run(self, context: JobContext) -> None:
        """Authorize an exact approved plan, acquire truthful streams and save before success.

        Args:
            context: Existing owner of events, cancellation and actual acquisition artifacts.

        Raises:
            JobError: Authority, normalization or durable persistence fails.
            asyncio.CancelledError: Owned cancellation follows actual process cleanup.
        """

        try:
            try:
                capability = CapabilityDescriptors(self.adapter.Descriptor)[0]
                grant = PolicyEngine().Authorize(self.invocation, capability, self.Context(),
                    at=self.clock(), confirmation=self.confirmation)

            except (NucleiAuthorityDeniedError, PolicyDeniedError) as error:
                raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                          "Nuclei exact-plan execution was denied")) from error

            except (OSError, ValueError) as error:
                raise JobError(JobFailure(JobFailureCode.STORAGE,
                                          "Could not verify current Nuclei authority/material")) \
                    from error

            executor = GovernedLocalExecutor(self.workspace_root, clock=self.clock)

            async def Ingest(context: JobContext, report: AdapterReport) -> None:
                """Keep the same exact launch grant for final canonical-model persistence."""

                await self.Ingest(context, report, grant=grant)

            async def Execute(
                request: LocalExecutionRequest, *, on_event: EventCallback | None = None,
                cancellation: asyncio.Event | None = None,
            ) -> LocalExecutionResult:
                """Keep the existing grant and final fresh-context hook at the process owner."""

                try:
                    return await executor.Execute(
                        request, grant=grant, context_provider=self.Context, on_event=on_event,
                        cancellation=cancellation,
                    )

                except (NucleiAuthorityDeniedError, PolicyDeniedError):
                    raise

                except (OSError, ValueError) as error:
                    raise JobError(JobFailure(JobFailureCode.STORAGE,
                                              "Could not verify final Nuclei authority/material")) \
                        from error

            await LocalExecutionJob(LocalExecutionRequest(
                self.invocation, capability, grant.authorization,
                resources=ExecutionResources(NUCLEI_JSONL_MAX_BYTES, 64 * 1024, 0.2),
            ), Execute, Ingest).Run(context)

        finally:
            self.PersistReferences()

    async def Ingest(
        self, context: JobContext, report: AdapterReport, *, grant: PolicyGrant,
    ) -> None:
        """Map actual successful matches to canonical findings through existing model owners.

        Args:
            context: Owning job, receiving only observations and actually saved model deltas.
            report: Exact verified execution envelope referencing stored stdout/stderr.
            grant: The owning invocation's launch grant, revalidated before canonical Save.

        Raises:
            JobError: Normalization or the authoritative model Save fails.
        """

        normalized = self.adapter.NormalizeReport(report)
        provenance = ModelProvenance(
            self.adapter.Descriptor.adapter_id, context.Spec.job_id, self.clock().isoformat(),
            context.Spec.scope_reference, self.target.Reference(),
            report.invocation.provider_version,
            report.evidence, report.execution,
        )
        store = LocalModelStore(self.workspace_root)
        state = store.Open()
        subject = ObjectIdentity(state.workspace_id, ObjectKind.ENDPOINT, self.target.value)
        projected, _ = state.Apply(objects=(SecurityObject(subject, {"url": self.target.value},
                                                            (provenance,)),))
        projected, _ = projected.ApplyAdapterResult(
            normalized, {self.target.Reference(): subject}, provenance,
        )
        findings = []
        observations = []

        for item in normalized.findings:
            severity = item.attributes["severity"]
            findings.append(Finding(
                subject.Reference(), "nuclei." + cast(str, item.attributes["template_id"]),
                cast(str, item.attributes["source_finding_id"]), item.summary, (provenance,),
                severity=FindingSeverity.INFORMATIONAL if severity == "info"
                else FindingSeverity(cast(str, severity)),
            ))
            observations.append(Observation("nuclei.template-match", subject.Reference(),
                {"summary": item.summary, **item.attributes}, provenance))

        projected, _ = ApplyVerifiedFindings(projected, tuple(findings), self.workspace_root)
        projected, _ = projected.Apply(observations=tuple(observations))
        # Pure projections are committed as one CAS transition owned by LocalModelStore.
        updated, delta = state.Apply(objects=projected.objects, relations=projected.relations,
                                      observations=projected.observations)

        try:
            context.CheckCancellation()
            PolicyEngine().Validate(grant, self.invocation,
                CapabilityDescriptors(self.adapter.Descriptor)[0], self.Context(), at=self.clock())

        except (NucleiAuthorityDeniedError, PolicyDeniedError) as error:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                                      "Nuclei authority changed before model persistence")) \
                from error

        except (OSError, ValueError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not verify Nuclei model persistence authority")) \
                from error

        try:
            store.Save(updated, expected_revision=state.revision)

        except (OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not persist Nuclei model findings")) from error

        context.ModelChanged(delta)

        for observation in normalized.observations:
            context.Observe(observation)

        context.Progress(1, 1)

    def PersistReferences(self) -> None:
        """Retain real acquisitions and verify all previous evidence before terminal success.

        Raises:
            JobError: Evidence integrity, model reopen or workspace CAS fails.
        """

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
                    raise ValueError("Nuclei retained acquisition differs from its record")

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

        except (OSError, ValueError, EvidenceError, WorkspaceBusyError,
                WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                                      "Could not preserve Nuclei workspace references")) from error


async def RunNucleiScan(
    workspace_root: Path, scope_id: str, target: Target, owner_reference: str,
    profile: NucleiProfile, executable: str, policy_provider: Callable[[], ImpactPolicy],
    *, confirmation: PolicyConfirmation | None = None,
    limits: NucleiScanLimits = NucleiScanLimits(),
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow,
) -> NucleiScanSummary:
    """Rebuild a current exact plan and run one explicitly confirmed optional-provider job.

    Args:
        workspace_root: Existing authoritative workspace with initialized model/evidence.
        scope_id: Persisted explicitly granted URL/IP scope selected by the operator.
        target: One exact literal-IP HTTP(S) endpoint; no discovery or resolution occurs.
        owner_reference: Operator matching the current consent actor at every check.
        profile: Finite reviewed immutable local template/configuration metadata.
        executable: Explicit absolute locally installed optional provider path.
        policy_provider: Fresh synchronous policy reader, rechecked at authorization and launch.
        confirmation: Explicit existing PolicyConfirmation for the exact previously shown plan.
        limits: Finite whole-provider deadline and request rate.
        on_event: Fast synchronous presentation sink; failure cancels and awaits owned cleanup.
        clock: Aware authority clock used for fresh policy checks.

    Returns:
        Truthful terminal summary after persistence and actual owned process cleanup.

    Raises:
        ValueError: Initial inputs/material/state are invalid.
        PermissionError: Planning fails current authority before a job starts.
        NucleiUnavailableError: Selected provider fails the bounded local version probe.
        EvidenceError: Previous raw acquisitions fail initial integrity verification.
        OSError: Initial local state cannot be opened.
        Exception: A presentation sink fails, after owned cancellation and cleanup.
    """

    plan = PlanNucleiScan(workspace_root, scope_id, target, owner_reference, profile, executable,
                         policy_provider, limits=limits, clock=clock)
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    evidence = LocalEvidenceStore(store.root / "evidence")
    adapter = NucleiAdapter(evidence.Read, profile, executable, plan.invocation.provider_version)
    spec = JobSpec("job:nuclei-" + uuid4().hex, workspace.workspace_id,
                   plan.policy_plan.scope_reference, owner_reference, adapter.Descriptor.adapter_id,
                   timeout_seconds=limits.timeout_seconds + 5)

    def Snapshot() -> JobSnapshot:
        """Bind the wrapper to its owning job before any provider task starts."""

        return job.Snapshot()

    provider = NucleiWorkflow(store.root, scope_id, target, owner_reference, policy_provider,
                             adapter, plan.invocation, confirmation, Snapshot, clock)
    job = ScanJob(spec, provider, evidence_store=evidence)
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    cursor = -1
    job.Start()

    def Observe(event: JobEvent) -> None:
        """Retain the exact presentation cursor and forward only owned job metadata."""

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

    return NucleiScanSummary(
        snapshot, started_at, datetime.now(UTC).isoformat(), time.monotonic() - started,
        model.revision, tuple((kind.value, len(model.Objects(kind))) for kind in ObjectKind),
        job.EventsSince(),
    )
