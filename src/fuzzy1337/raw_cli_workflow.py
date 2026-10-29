# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Governed exact-native Nmap jobs, attributable original receipts and offline replay."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    ExecutionState,
    SerializeContract,
)
from fuzzy1337.adapters.nmap import NMAP_XML_MAX_BYTES
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceError,
    EvidenceRecord,
    LocalEvidenceStore,
    ParseEvidenceManifest,
)
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
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
    Digest,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyConfirmation,
    PolicyContext,
    PolicyEngine,
    PolicyGrant,
    PolicyPlan,
    UtcNow,
)
from fuzzy1337.portscan import CurrentContext, PortScanUnavailableError
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.raw_cli import RAW_NMAP_PROFILE, RawNmapAdapter, RawNmapSelection
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RejectWorkspaceConstant,
    RequireWorkspaceText,
    UniqueWorkspaceObject,
    WorkspaceBusyError,
    WorkspaceConflictError,
)

RAW_CLI_RECEIPT_ROLE = "raw-cli-receipt"
RAW_CLI_RECEIPT_MAX_BYTES = 64 * 1024
RAW_CLI_STDERR_MAX_BYTES = 64 * 1024
_RECEIPT_FIELDS = frozenset({"schema_version", "profile", "tool", "workspace_id",
    "scope_reference", "owner_reference", "job_id", "policy_reference", "policy_plan",
    "intent_sha256",
    "invocation", "invocation_sha256", "execution", "termination", "original_role_ids",
    "custody", "model_commit", "model_basis", "model_revision", "workspace_basis",
    "reference_persistence", "version_basis"})
_PLAN_FIELDS = frozenset({"invocation_sha256", "capability_sha256", "scope_reference",
    "scope_revision", "scope_sha256", "policy_reference", "policy_revision", "policy_sha256",
    "target_reference", "destination_references", "granted_privileges", "confirmation_required",
    "intent_sha256"})


@dataclass(frozen=True, slots=True)
class RawCliPlan:
    """Exact original native invocation and current separate STANDARD confirmation intent."""

    invocation: AdapterInvocation
    policy_plan: PolicyPlan

    def ToDict(self) -> dict[str, object]:
        """Return descriptive exact native metadata without an execution grant.

        Returns:
            Schema-one native plan, observed version and explicit confirmation requirement.
        """

        return {"schema_version": 1, "workflow": "raw", "profile": RAW_NMAP_PROFILE,
            "tool": "nmap", "state": "planned", "execution_authorized": False,
            "confirmation_required": True, "intent_sha256": self.policy_plan.intent_sha256,
            "version_basis": "bounded-local-adapter-health",
            "invocation": json.loads(SerializeContract(self.invocation)),
            "policy_plan": json.loads(SerializeContract(self.policy_plan))}


def PlanRawCli(workspace_root: Path, scope_id: str, owner_reference: str,
    executable: str, selection: RawNmapSelection, policy_provider: Callable[[], ImpactPolicy],
    *, clock: Callable[[], datetime] = UtcNow) -> RawCliPlan:
    """Check current scope before local health metadata and bind exact original argv.

    Args:
        workspace_root: Existing initialized authoritative workspace.
        scope_id: Explicit existing IP scope, never automatically expanded.
        owner_reference: Executing actor matching the current recorded consent authority.
        executable: Explicit trusted absolute optional Nmap binary.
        selection: Validated exact native argument tokens and derived finite profile.
        policy_provider: Fresh typed current policy reader; no default permissions.
        clock: Current aware authority clock.

    Returns:
        Exact observed-version invocation and current confirmation intent; no target contact.
    """

    RequireWorkspaceText(owner_reference, "owner_reference")
    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    LocalModelStore(store.root).Open()
    evidence = LocalEvidenceStore(store.root / "evidence")
    VerifyWorkspaceEvidence(workspace, evidence)
    adapter = RawNmapAdapter(evidence.Read, selection, executable)
    invocation = adapter.PrepareInvocation(selection.Request())
    capability = next(item for item in CapabilityDescriptors(adapter.Descriptor)
        if item.identifier == selection.capability)
    PolicyEngine().Plan(invocation, capability, CurrentContext(store.root, scope_id,
        selection.Target, owner_reference, policy_provider), at=clock())
    health = adapter.CheckHealth()

    if health.state is not AdapterHealthState.AVAILABLE or health.provider_version is None:
        raise PortScanUnavailableError("Selected raw Nmap is unavailable or unhealthy")

    adapter = RawNmapAdapter(evidence.Read, selection, executable, health.provider_version)
    invocation = adapter.PrepareInvocation(selection.Request())
    plan = PolicyEngine().Plan(invocation, capability, CurrentContext(store.root, scope_id,
        selection.Target, owner_reference, policy_provider), at=clock())

    return RawCliPlan(invocation, plan)


@dataclass(frozen=True, slots=True)
class RawCliSummary:
    """Actual native status, original evidence references and independent wrapper outcome."""

    snapshot: JobSnapshot
    invocation: AdapterInvocation
    receipt_id: str | None
    model_commit: str
    workspace_acknowledged: bool
    result: LocalExecutionResult | None

    def ExitCode(self) -> int:
        """Preserve native status only after complete custody and required wrapper acknowledgements.

        Returns:
            Native process status after complete collection, or existing wrapper 3/4/130 status.
        """

        if self.snapshot.state is JobState.CANCELLED:
            return 130

        failure = self.snapshot.failure

        if failure is not None and failure.code is JobFailureCode.AUTHORIZATION:
            return 3

        if self.result is not None and self.receipt_id is not None and (
            self.workspace_acknowledged and self.result.termination is (
                ExecutionTermination.PROCESS_EXIT)
            and (self.snapshot.state is JobState.COMPLETED or (
                failure is not None and failure.code is JobFailureCode.PROVIDER))
        ):
            status = self.result.execution.exit_code

            if type(status) is int and -127 <= status <= 255:
                return status if status >= 0 else 128 - status

        return 4

    def ToDict(self) -> dict[str, object]:
        """Expose safe selected metadata and original IDs without embedding raw tool streams.

        Returns:
            Actual native exit separately from wrapper state, failure and acknowledged custody.
        """

        return {"schema_version": 1, "workflow": "raw", "profile": RAW_NMAP_PROFILE,
            "tool": "nmap", "state": self.snapshot.state.value, "exit_code": self.ExitCode(),
            "native_exit_code": None if self.result is None else self.result.execution.exit_code,
            "termination": None if self.result is None else self.result.termination.value,
            "receipt_id": self.receipt_id, "model_commit": self.model_commit,
            "workspace_commit": "acknowledged" if self.workspace_acknowledged else "unconfirmed",
            "invocation": json.loads(SerializeContract(self.invocation)),
            "job": json.loads(SerializeContract(self.snapshot))}


class RawCliWorkflow:
    """Own one exact governed execution and one attempt per canonical persistence owner."""

    def __init__(self, root: Path, scope_id: str, owner: str, adapter: RawNmapAdapter,
        plan: RawCliPlan, grant: PolicyGrant, policy_provider: Callable[[], ImpactPolicy],
        snapshot: Callable[[], JobSnapshot], clock: Callable[[], datetime]) -> None:
        """Freeze the original bases and exact launch intent before the job begins.

        Args:
            root: Existing physical workspace root.
            scope_id: Explicit original scope identifier.
            owner: Executing recorded consent actor.
            adapter: Exact-original-argv adapter with observed version.
            plan: Original native invocation and policy intent.
            grant: Separately confirmed original launch grant, never renewed.
            policy_provider: Fresh typed policy reader used at launch and persistence.
            snapshot: Original owning job snapshot callback.
            clock: Current aware policy clock.
        """

        self.root, self.scope_id, self.owner = root, scope_id, owner
        self.adapter, self.plan, self.grant = adapter, plan, grant
        self.policy_provider, self.snapshot, self.clock = policy_provider, snapshot, clock
        self.workspace = LocalWorkspaceStore(root).Open()
        self.model = LocalModelStore(root).Open()
        self.committed_model = self.model
        self.result: LocalExecutionResult | None = None
        self.receipt_id: str | None = None
        self.model_commit = "not-attempted"
        self.model_revision = self.model.revision
        self.workspace_acknowledged = False

    def Context(self) -> PolicyContext:
        """Revalidate the original native arguments and fresh actual target/owner/policy.

        Returns:
            Existing current policy context for the exact original single IP destination.
        """

        if self.adapter.PrepareInvocation(self.adapter.selection.Request()) != self.plan.invocation:
            raise ValueError("raw native invocation changed after exact confirmation")

        return CurrentContext(self.root, self.scope_id, self.adapter.selection.Target,
            self.owner, self.policy_provider)

    def Validate(self) -> None:
        """Recheck the original fixed grant immediately before a canonical persistence attempt."""

        capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
            if item.identifier == self.adapter.selection.capability)
        try:
            PolicyEngine().Validate(self.grant, self.plan.invocation, capability,
                self.Context(), at=self.clock())

        except PermissionError as error:
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Raw CLI authority changed before persistence")) from error

    async def Run(self, context: JobContext) -> None:
        """Collect original execution before normalization and preserve actual failure custody.

        Args:
            context: The sole original running job and evidence publication owner.
        """

        capability = next(item for item in CapabilityDescriptors(self.adapter.Descriptor)
            if item.identifier == self.adapter.selection.capability)
        executor = GovernedLocalExecutor(self.root, clock=self.clock)

        async def Execute(request: LocalExecutionRequest, *, on_event: EventCallback | None = None,
            cancellation: asyncio.Event | None = None) -> LocalExecutionResult:
            """Retain the original executor return without reconstructing its terminal facts."""

            self.result = await executor.Execute(request, grant=self.grant,
                context_provider=self.Context, on_event=on_event, cancellation=cancellation)

            return self.result

        try:
            await LocalExecutionJob(LocalExecutionRequest(self.plan.invocation, capability,
                self.grant.authorization, resources=ExecutionResources(NMAP_XML_MAX_BYTES,
                    RAW_CLI_STDERR_MAX_BYTES, 0.2)), Execute, self.Ingest).Run(context)

        finally:
            if self.result is not None:
                try:
                    self.PublishReceipt(context)
                    self.PersistReferences()

                except JobError:
                    raise

                except (OSError, ValueError, EvidenceError, WorkspaceBusyError,
                    WorkspaceConflictError) as error:
                    raise JobError(JobFailure(JobFailureCode.STORAGE,
                        "Raw CLI original custody or reference persistence failed")) from error

    async def Ingest(self, context: JobContext, report: AdapterReport) -> None:
        """Normalize the actual native report and commit only under the original model CAS basis.

        Args:
            context: Original job owner receiving acknowledged model delta events.
            report: Actual exact-native invocation and independently verified original streams.
        """

        normalized = self.adapter.NormalizeReport(report)
        subject = self.adapter.selection.Target.Reference()
        bindings = {subject: ObjectIdentity(self.model.workspace_id, ObjectKind.HOST,
            self.adapter.selection.address)}

        for port in self.adapter.selection.ports:
            provider_port = f"{subject}:tcp:{port}"
            natural_port = f"host:{self.adapter.selection.address}/tcp/{port}"
            bindings[provider_port] = ObjectIdentity(self.model.workspace_id,
                ObjectKind.PORT, natural_port)
            bindings[provider_port + ":service"] = ObjectIdentity(self.model.workspace_id,
                ObjectKind.SERVICE, natural_port)

        projected = normalized if normalized.object_enrichments else replace(
            normalized, observations=())
        updated, delta = self.model.ApplyAdapterResult(projected, bindings, ModelProvenance(
            self.adapter.Descriptor.adapter_id, context.Spec.job_id, self.clock().isoformat(),
            context.Spec.scope_reference, subject, report.invocation.provider_version,
            report.evidence, report.execution))
        context.CheckCancellation()
        self.Validate()
        self.model_commit = "unconfirmed"

        try:
            saved = LocalModelStore(self.root).Save(updated, expected_revision=self.model.revision)

        except (OSError, ValueError, WorkspaceBusyError, WorkspaceConflictError) as error:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Raw CLI model persistence was not acknowledged")) from error

        if saved != updated:
            raise JobError(JobFailure(JobFailureCode.STORAGE,
                "Raw model acknowledgement differs from its original proposal"))

        self.model_commit, self.model_revision = "acknowledged", saved.revision
        self.committed_model = saved
        context.ModelChanged(delta)

        for observation in normalized.observations:
            context.Observe(observation)

    def PublishReceipt(self, context: JobContext) -> None:
        """Retain original arguments and independent actual output/exit/custody state exactly once.

        Args:
            context: Original still-running job, including failure cleanup before terminal state.
        """

        assert self.result is not None, "A raw receipt requires an actual original executor return"
        records = tuple(item.evidence for item in self.snapshot().artifacts)
        roles = {record.reference.role: record.evidence_id for record in records}
        complete = len(records) == 2 and set(roles) == {"stdout", "stderr"}

        if not records:
            return

        original = records[0].provenance
        data = {"schema_version": 1, "profile": RAW_NMAP_PROFILE, "tool": "nmap",
            "workspace_id": self.workspace.workspace_id,
            "scope_reference": context.Spec.scope_reference, "owner_reference": self.owner,
            "job_id": context.Spec.job_id, "policy_reference": self.grant.plan.policy_reference,
            "policy_plan": json.loads(SerializeContract(self.grant.plan)),
            "intent_sha256": self.grant.plan.intent_sha256,
            "invocation": json.loads(SerializeContract(self.plan.invocation)),
            "invocation_sha256": InvocationDigest(self.plan.invocation),
            "execution": json.loads(SerializeContract(self.result.execution)),
            "termination": self.result.termination.value, "original_role_ids": roles,
            "custody": "complete" if complete else "partial", "model_commit": self.model_commit,
            "model_basis": self.model.revision, "model_revision": self.model_revision,
            "workspace_basis": self.workspace.revision,
            "reference_persistence": "not-yet-acknowledged",
            "version_basis": "bounded-local-adapter-health"}
        raw = SerializeContract(data).encode("utf-8")

        if len(raw) > RAW_CLI_RECEIPT_MAX_BYTES:
            raise ValueError("raw CLI receipt exceeds its fixed bound")

        self.receipt_id = context.CaptureEvidence(raw, RAW_CLI_RECEIPT_ROLE,
            "application/json", original).evidence.evidence_id

    def PersistReferences(self) -> None:
        """Attempt one guarded original workspace CAS, preserving every available acquisition."""

        store = LocalWorkspaceStore(self.root)
        evidence = LocalEvidenceStore(self.root / "evidence")
        references = {(item.locator, item.role): item
            for item in self.workspace.evidence_references}
        record_ids = set(self.workspace.evidence_record_references)

        for artifact in self.snapshot().artifacts:
            record = artifact.evidence

            if evidence.Get(record.evidence_id) != record:
                raise ValueError("raw CLI acquisition differs from its original record")

            references[(record.reference.locator, record.reference.role)] = record.reference
            record_ids.add(record.evidence_id)

        proposal = replace(self.workspace,
            scope_references=tuple(sorted({*self.workspace.scope_references,
                self.snapshot().spec.scope_reference})),
            object_references=tuple(sorted({*self.workspace.object_references,
                *(item.Reference() for item in self.committed_model.objects)})),
            job_references=tuple(sorted({*self.workspace.job_references,
                self.snapshot().spec.job_id})),
            evidence_references=tuple(references[key] for key in sorted(references)),
            evidence_record_references=tuple(sorted(record_ids)))
        self.Validate()
        saved = store.Save(proposal)

        if saved != replace(proposal, revision=proposal.revision + 1):
            raise ValueError("raw workspace acknowledgement differs from its original proposal")

        self.workspace_acknowledged = True


async def RunRawCli(workspace_root: Path, scope_id: str, owner_reference: str,
    executable: str, selection: RawNmapSelection, policy_provider: Callable[[], ImpactPolicy],
    *, confirmation: PolicyConfirmation | None = None,
    on_event: Callable[[JobEvent], None] | None = None,
    clock: Callable[[], datetime] = UtcNow) -> RawCliSummary:
    """Run one exact confirmed raw command through existing policy, process and storage owners.

    Args:
        workspace_root: Existing initialized authoritative workspace.
        scope_id: Explicit original single-IP scope.
        owner_reference: Executing recorded consent actor, reread at authority boundaries.
        executable: Explicit trusted absolute Nmap binary.
        selection: Exact validated native tokens, never a shell command string.
        policy_provider: Fresh typed current policy reader.
        confirmation: Separate exact native plan confirmation and non-secret approval reference.
        on_event: Optional synchronous original safe job-event presentation callback.
        clock: Current aware authority clock; grants are never renewed during the attempt.

    Returns:
        Actual native result and independent wrapper/evidence/persistence outcomes after cleanup.
    """

    plan = PlanRawCli(workspace_root, scope_id, owner_reference, executable, selection,
        policy_provider, clock=clock)
    store = LocalWorkspaceStore(workspace_root)
    evidence = LocalEvidenceStore(store.root / "evidence")
    adapter = RawNmapAdapter(evidence.Read, selection, executable, plan.invocation.provider_version)
    capability = next(item for item in CapabilityDescriptors(adapter.Descriptor)
        if item.identifier == selection.capability)
    grant = PolicyEngine().Authorize(plan.invocation, capability, CurrentContext(store.root,
        scope_id, selection.Target, owner_reference, policy_provider), at=clock(),
        confirmation=confirmation)
    spec = JobSpec("job:raw-" + uuid4().hex, store.Open().workspace_id,
        grant.plan.scope_reference, owner_reference, adapter.Descriptor.adapter_id,
        selection.timeout_seconds + 5)

    def Snapshot() -> JobSnapshot:
        """Return the original job snapshot without substituting a synthetic owner."""

        return job.Snapshot()

    provider = RawCliWorkflow(store.root, scope_id, owner_reference, adapter, plan, grant,
        policy_provider, Snapshot, clock)
    job = ScanJob(spec, provider, evidence_store=evidence)
    job.Start()
    cleanup: asyncio.Task[JobSnapshot] | None = None

    try:
        async for event in job.Events():
            if on_event is not None:
                on_event(event)

    except BaseException:
        cleanup = asyncio.create_task(job.CancelAndWait(owner_reference))

        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)

            except asyncio.CancelledError:
                continue

        cleanup.result()

        raise

    snapshot = await job.Wait()

    return RawCliSummary(snapshot, plan.invocation, provider.receipt_id, provider.model_commit,
        provider.workspace_acknowledged, provider.result)


def ReadRawRecord(store: LocalEvidenceStore, evidence_id: str, role: str,
    maximum: int) -> tuple[EvidenceRecord, bytes]:
    """Preflight an exact original manifest role and cap before any eager raw payload read.

    Args:
        store: Explicit original workspace evidence partition.
        evidence_id: Exact SHA-256 manifest identity.
        role: One exact original raw stream or receipt role.
        maximum: Inclusive original role byte bound.

    Returns:
        Original independently verified record and complete admitted raw bytes.
    """

    if type(evidence_id) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", evidence_id) is None:
        raise ValueError("raw CLI original record identity is invalid")

    record = ParseEvidenceManifest(store.ReadStoredBytes(("records", evidence_id[7:] + ".json"),
        EVIDENCE_MANIFEST_MAX_BYTES))
    media = "application/json" if role == RAW_CLI_RECEIPT_ROLE else "application/octet-stream"

    if record.evidence_id != evidence_id or record.reference.role != role or (
        record.reference.media_type != media or record.reference.size_bytes > maximum
    ):
        raise ValueError("raw CLI original record role or bound differs")

    raw = store.Read(record.reference)

    return record, raw


def ReplayRawCli(workspace_root: Path, receipt_id: str) -> dict[str, object]:
    """Verify one original exact-native receipt and its streams offline without a tool or Save.

    Args:
        workspace_root: Existing or relocated authoritative workspace.
        receipt_id: Exact original receipt manifest already attached to this workspace.

    Returns:
        Verified original invocation, native status, custody and historical normalization facts.
    """

    store = LocalWorkspaceStore(workspace_root)
    workspace = store.Open()
    evidence = LocalEvidenceStore(store.root / "evidence")

    if receipt_id not in workspace.evidence_record_references:
        raise ValueError("raw CLI receipt is not attached to this workspace")

    receipt, raw = ReadRawRecord(evidence, receipt_id, RAW_CLI_RECEIPT_ROLE,
        RAW_CLI_RECEIPT_MAX_BYTES)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
        parse_constant=RejectWorkspaceConstant)

    if type(value) is not dict or set(value) != _RECEIPT_FIELDS or (
        SerializeContract(value).encode("utf-8") != raw or type(value["schema_version"]) is not int
        or value["schema_version"] != 1 or value["profile"] != RAW_NMAP_PROFILE
        or value["tool"] != "nmap" or value["workspace_id"] != workspace.workspace_id
        or value["scope_reference"] not in workspace.scope_references
        or value["job_id"] not in workspace.job_references
        or value["custody"] != "complete"
        or value["reference_persistence"] != "not-yet-acknowledged"
        or value["version_basis"] != "bounded-local-adapter-health"
    ):
        raise ValueError("raw CLI original receipt context or closed schema differs")

    invocation = value["invocation"]

    for name in ("owner_reference", "job_id", "policy_reference"):
        RequireWorkspaceText(value[name], name)

    if value["model_commit"] not in {"not-attempted", "acknowledged", "unconfirmed"} or any(
        type(value[key]) is not int or value[key] < 0 for key in (
            "model_basis", "model_revision", "workspace_basis")
    ) or value["workspace_basis"] >= workspace.revision:
        raise ValueError("raw CLI original persistence metadata is invalid")

    if type(invocation) is not dict or type(invocation.get("argv")) is not list or (
        not invocation["argv"] or type(invocation.get("provider_version")) is not str
        or not invocation["provider_version"]
    ):
        raise ValueError("raw CLI original invocation metadata is invalid")

    selection = RawNmapSelection(tuple(invocation["argv"][1:]))
    adapter = RawNmapAdapter(evidence.Read, selection, invocation["argv"][0],
        invocation["provider_version"])
    actual = adapter.PrepareInvocation(selection.Request())
    plan = value["policy_plan"]
    capability = next(item for item in CapabilityDescriptors(adapter.Descriptor)
        if item.identifier == selection.capability)

    if type(plan) is not dict or set(plan) != _PLAN_FIELDS or (
        Digest({key: item for key, item in plan.items() if key != "intent_sha256"}) != (
            plan["intent_sha256"]) or plan["intent_sha256"] != value["intent_sha256"]
        or plan["invocation_sha256"] != InvocationDigest(actual)
        or plan["capability_sha256"] != Digest(capability)
        or plan["scope_reference"] != value["scope_reference"]
        or plan["policy_reference"] != value["policy_reference"]
        or plan["target_reference"] != selection.Target.Reference()
        or plan["destination_references"] != [selection.Target.Reference()]
        or plan["confirmation_required"] is not True
    ):
        raise ValueError("raw CLI original confirmation context differs")

    if json.loads(SerializeContract(actual)) != invocation or (
        InvocationDigest(actual) != value["invocation_sha256"]
        or receipt.provenance.invocation_sha256 != value["invocation_sha256"]
        or receipt.provenance.workspace_id != workspace.workspace_id
        or receipt.provenance.scope_reference != value["scope_reference"]
        or receipt.provenance.source_id != "native.nmap"
        or receipt.provenance.tool_version != actual.provider_version
        or json.loads(SerializeContract(receipt.provenance.execution)) != value["execution"]
        or set(value["original_role_ids"]) != {"stdout", "stderr"}
        or receipt.reference not in workspace.evidence_references
    ):
        raise ValueError("raw CLI actual invocation or original provenance differs")

    original = []

    for role, maximum in (("stdout", NMAP_XML_MAX_BYTES), ("stderr", RAW_CLI_STDERR_MAX_BYTES)):
        evidence_id = value["original_role_ids"][role]

        if evidence_id not in workspace.evidence_record_references:
            raise ValueError("raw CLI original stream is not acknowledged by this workspace")

        record, _ = ReadRawRecord(evidence, evidence_id, role, maximum)

        if record.provenance != receipt.provenance or (
            record.reference not in workspace.evidence_references
        ):
            raise ValueError("raw CLI original stream context differs")

        original.append(record.reference)

    execution = receipt.provenance.execution

    if type(execution) is not AdapterExecution:
        raise ValueError("raw CLI original native execution is unavailable")

    termination = ExecutionTermination(value["termination"])
    normalized = None

    if execution.state is ExecutionState.SUCCEEDED and (
        termination is ExecutionTermination.PROCESS_EXIT and value["model_commit"] == "acknowledged"
    ):
        normalized = adapter.NormalizeReport(AdapterReport(actual, execution, tuple(original)))

    return {"schema_version": 1, "workflow": "raw-replay", "profile": RAW_NMAP_PROFILE,
        "state": "verified", "receipt_id": receipt_id, "invocation": invocation,
        "native_exit_code": execution.exit_code, "termination": termination.value,
        "model_commit": value["model_commit"], "original_role_ids": value["original_role_ids"],
        "historical_observations": None if normalized is None else len(normalized.observations)}
