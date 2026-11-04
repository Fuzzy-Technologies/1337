# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Evaluate original current owned SQL sample evidence without issuing work."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from urllib.parse import unquote, urlsplit

from fuzzy1337.adapters import AdapterReport
from fuzzy1337.adapters.native_web import (
    NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    NATIVE_WEB_VERSION,
    NativeWebAdapter,
    NativeWebEndpoint,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.jobs import JobEventKind, JobState
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
)
from fuzzy1337.native_web import NativeWebScanPlan, NativeWebScanSummary
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceState

_PROBE_VALUES = (
    "public", "public' AND 1=1 AND 'a'='a", "public' AND 1=0 AND 'a'='a", "public",
)


class SqlBooleanOutcome(StrEnum):
    """Finite digest-only assessment states for the existing owned profile."""

    PARTIAL = "partial"
    UNSTABLE_BASELINE = "unstable-baseline"
    NO_DIFFERENTIAL = "no-differential"
    DIFFERENTIAL_CANDIDATE = "differential-candidate"
    INCONCLUSIVE = "inconclusive"


def ClassifySqlBooleanDigests(digests: tuple[str, ...]) -> SqlBooleanOutcome:
    """Compare only the ordered digests of already verified original samples.

    Args:
        digests: Verified baseline, true, false and repeated baseline digests,
            or a verified prefix of that sequence.

    Returns:
        The finite evidence pattern, without making a vulnerability assertion.
    """

    if len(digests) < len(_PROBE_VALUES):
        return SqlBooleanOutcome.PARTIAL

    baseline, trueControl, falseControl, repeated = digests

    if baseline != repeated:
        return SqlBooleanOutcome.UNSTABLE_BASELINE

    if trueControl == falseControl:
        return SqlBooleanOutcome.NO_DIFFERENTIAL

    if baseline == trueControl:
        return SqlBooleanOutcome.DIFFERENTIAL_CANDIDATE

    return SqlBooleanOutcome.INCONCLUSIVE


def RequireSqlBooleanPlans(
    plans: tuple[NativeWebScanPlan, ...], adapter: NativeWebAdapter,
) -> None:
    """Require the four ordered roles on one approved coordinate and authority revision.

    Args:
        plans: Exact caller-selected native plans recorded before execution.
        adapter: Existing adapter for the finite loopback profile.

    Raises:
        ValueError: The role, coordinate, authority or finite plan does not match.
    """

    if len(plans) != len(_PROBE_VALUES):
        raise ValueError("SQL assessment requires four exact probe plans")

    basis = None

    for plan, value in zip(plans, _PROBE_VALUES, strict=True):
        invocation = plan.invocation
        policy = plan.policy_plan
        parameters = invocation.request.parameters

        if parameters.get("check_id") != NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID or (
            invocation != adapter.PrepareInvocation(invocation.request)
            or policy.invocation_sha256 != InvocationDigest(invocation)
            or policy.target_reference != invocation.request.target_reference
            or policy.confirmation_required is not True
        ):
            raise ValueError("SQL assessment requires exact confirmed native sample plans")

        target, _, _, _ = NativeWebEndpoint(parameters["url"],
                                             check_id=NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID)
        parsed = urlsplit(target.value)
        path, _, encodedValue = parsed.path.rpartition("/")

        if path not in {"/sql-boolean/vulnerable", "/sql-boolean/fixed"} or (
            unquote(encodedValue) != value
        ):
            raise ValueError("SQL assessment probe route differs from its planned role")

        coordinate = (parsed.scheme, parsed.netloc, path, parameters["timeout_seconds"],
            policy.scope_reference, policy.scope_revision, policy.scope_sha256,
            policy.policy_reference, policy.policy_revision, policy.policy_sha256)

        if basis is None:
            basis = coordinate

        elif basis != coordinate:
            raise ValueError("SQL assessment plans do not share one coordinate and authority")


def AssessSqlBooleanEvidence(
    workspaceRoot: Path, before: WorkspaceState, plans: tuple[NativeWebScanPlan, ...],
    runs: tuple[NativeWebScanSummary, ...],
) -> SqlBooleanOutcome:
    """Verify a trusted current run prefix and compare its original worker evidence.

    Args:
        workspaceRoot: Owned workspace of the current assessment.
        before: State captured by the trusted owner before any sample job.
        plans: Four exact operations the trusted owner confirmed and launched in order.
        runs: Actual terminal summaries received directly by that owner.

    Returns:
        The bounded response pattern, or a partial assessment on an incomplete run.

    Raises:
        ValueError: The receipts cannot belong to the same exact current assessment.
        EvidenceError: An original acquisition manifest or its bytes fail verification.
        OSError: Required saved state is unavailable.
    """

    if len(runs) > len(_PROBE_VALUES):
        raise ValueError("SQL assessment requires at most four current sample receipts")

    workspace = LocalWorkspaceStore(workspaceRoot).Open()
    store = LocalEvidenceStore(workspaceRoot / "evidence")
    adapter = NativeWebAdapter(store.Read)
    RequireSqlBooleanPlans(plans, adapter)
    expectedJobs = before.job_references + tuple(run.snapshot.spec.job_id for run in runs)

    if before.workspace_id != workspace.workspace_id or (
        expectedJobs != workspace.job_references
    ):
        raise ValueError("SQL assessment requires the exact ordered current job suffix")

    model = LocalModelStore(workspaceRoot).Open()

    if model.workspace_id != workspace.workspace_id:
        raise ValueError("SQL assessment workspace and saved model differ")

    acquisitionIds = set(before.evidence_record_references)
    digests: list[str] = []

    for index, run in enumerate(runs):
        plan = plans[index]
        snapshot = run.snapshot
        spec = snapshot.spec

        if run.check_id != NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID or (
            spec.provider_id != NATIVE_WEB_PROVIDER_ID
            or spec.workspace_id != workspace.workspace_id
            or spec.scope_reference != plan.policy_plan.scope_reference
            or spec.owner_reference != runs[0].snapshot.spec.owner_reference
            or spec.timeout_seconds != runs[0].snapshot.spec.timeout_seconds
        ):
            raise ValueError("SQL assessment sample job differs from its planned owner and scope")

        if not run.events or (
            run.events[-1].kind is not JobEventKind.STATE
            or run.events[-1].data is not snapshot.state
            or run.events[-1].sequence != snapshot.last_sequence
            or any(event.job_id != spec.job_id for event in run.events)
            or tuple(event.data for event in run.events if event.kind is JobEventKind.ARTIFACT)
                != snapshot.artifacts
        ):
            raise ValueError("SQL assessment requires a truthful terminal sample receipt")

        if snapshot.state in {JobState.FAILED, JobState.CANCELLED} and index == len(runs) - 1:
            return SqlBooleanOutcome.PARTIAL

        if snapshot.state is not JobState.COMPLETED or snapshot.failure is not None or (
            snapshot.cancellation_requested
        ):
            raise ValueError("SQL assessment requires a successful sample before subsequent probes")

        records = tuple(item.evidence for item in snapshot.artifacts)

        if tuple(record.reference.role for record in records) != ("stdout", "stderr"):
            raise ValueError("SQL assessment requires both original ordered worker streams")

        original = records[0].provenance
        invocation = plan.invocation

        if original.workspace_id != spec.workspace_id or original.scope_reference != (
            spec.scope_reference
        ) or original.source_id != NATIVE_WEB_PROVIDER_ID or (
            original.source_version != NATIVE_WEB_VERSION
            or original.tool_version != NATIVE_WEB_VERSION
            or original.invocation_sha256 != InvocationDigest(invocation)
            or original.execution is None
        ):
            raise ValueError("SQL assessment acquisition differs from its native invocation")

        for artifact in snapshot.artifacts:
            record = artifact.evidence

            if artifact.job_id != spec.job_id or record.provenance != original or (
                record.evidence_id in acquisitionIds
                or record.evidence_id not in workspace.evidence_record_references
                or record.reference not in workspace.evidence_references
                or store.Get(record.evidence_id) != record
            ):
                raise ValueError("SQL assessment acquisition is stale, reused or misattributed")

            acquisitionIds.add(record.evidence_id)

        references = tuple(record.reference for record in records)
        normalized = adapter.NormalizeReport(
            AdapterReport(invocation, original.execution, references))
        sample = normalized.observations[0]
        observed = tuple(item for item in model.observations if (
            item.kind == sample.kind and item.provenance.run_reference == spec.job_id
        ))

        if len(observed) != 1:
            raise ValueError("SQL assessment requires the original current saved observation")

        provenance = ModelProvenance(NATIVE_WEB_PROVIDER_ID, spec.job_id,
            observed[0].provenance.observed_at, spec.scope_reference,
            invocation.request.target_reference, NATIVE_WEB_VERSION, references, original.execution)
        endpoint = ObjectIdentity(workspace.workspace_id, ObjectKind.ENDPOINT,
                                  str(invocation.request.parameters["url"]))
        expected = Observation(sample.kind, endpoint.Reference(), dict(sample.attributes),
                               provenance)

        if observed[0] != expected:
            raise ValueError("SQL assessment saved observation differs from worker evidence")

        digests.append(str(sample.attributes["body_sha256"]))

    return ClassifySqlBooleanDigests(tuple(digests))
