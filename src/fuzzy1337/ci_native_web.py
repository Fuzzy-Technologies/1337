# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""1337Scope native web CI predicates over original current-run metadata and saved evidence."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import math
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterReport,
    ExecutionState,
    SerializeContract,
)
from fuzzy1337.adapters.native_web import (
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    NATIVE_WEB_VERSION,
    NativeWebAdapter,
    NativeWebEndpoint,
)
from fuzzy1337.ci_gate import (
    CiFindingCriterion,
    CiPredicateResult,
    EvaluatePredicate,
    RequireModelContracts,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.jobs import JobArtifact, JobFailure, JobSnapshot, JobSpec, JobState
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
)
from fuzzy1337.native_web import (
    NativeWebAuthorityDeniedError,
    NativeWebScanLimits,
    NativeWebScanPlan,
    NativeWebScanSummary,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import (
    ImpactPolicy,
    PolicyConfirmation,
    PolicyDeniedError,
    PolicyPlan,
    RequireDigest,
)
from fuzzy1337.report_commands import (
    CheckReportSnapshot,
    OpenReportInput,
    PublishReport,
    ReportFailure,
    ReportOutputPath,
    RequireReportPath,
)
from fuzzy1337.report_formats import SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.scan_commands import WriteJson
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, RequireWorkspaceText

__all__ = ["EvaluateNativeWebCriterion"]

_CHECKS = {"git-head-exposure": NATIVE_WEB_CHECK_ID,
           "prometheus-exposition": NATIVE_PROMETHEUS_CHECK_ID}


def RequireNativeSummary(summary: NativeWebScanSummary) -> None:
    """Validate exact terminal job facts before trusting a native workflow result.

    Args:
        summary: Actual first-party native web workflow return value.

    Raises:
        ValueError: Nested contracts or terminal facts cannot represent one owned job.
    """

    if type(summary) is not NativeWebScanSummary or type(summary.snapshot) is not JobSnapshot:
        raise ValueError("CI native web requires the exact owning workflow summary")

    snapshot = summary.snapshot

    if type(snapshot.spec) is not JobSpec or type(snapshot.state) is not JobState or (
        snapshot.state not in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
        or type(snapshot.schema_version) is not int or snapshot.schema_version != 1
        or type(snapshot.cancellation_requested) is not bool
        or type(snapshot.artifacts) is not tuple
        or snapshot.failure is not None and type(snapshot.failure) is not JobFailure
        or type(summary.model_revision) is not int or summary.model_revision < 0
        or type(summary.duration_seconds) not in {int, float}
        or not math.isfinite(summary.duration_seconds) or summary.duration_seconds < 0
        or type(summary.check_id) is not str or summary.check_id not in _CHECKS.values()
        or snapshot.spec.provider_id != NATIVE_WEB_PROVIDER_ID
        or snapshot.state is JobState.COMPLETED and (
            snapshot.failure is not None or snapshot.cancellation_requested)
    ):
        raise ValueError("CI native web terminal facts violate their owning contracts")

    snapshot.spec.__post_init__()

    for artifact in snapshot.artifacts:
        if type(artifact) is not JobArtifact or type(artifact.evidence) is not EvidenceRecord or (
            artifact.job_id != snapshot.spec.job_id
            or artifact.workspace_id != snapshot.spec.workspace_id
            or type(artifact.evidence.provenance) is not EvidenceProvenance
        ):
            raise ValueError("CI native web evidence belongs to a different job")


def RequirePlan(plan: NativeWebScanPlan) -> None:
    """Require the exact finite invocation and confirmation intent without issuing a grant.

    Args:
        plan: Native owner-produced read-only plan for one selected operation.

    Raises:
        ValueError: The plan uses foreign types or a non-CI check profile.
    """

    if type(plan) is not NativeWebScanPlan or type(plan.invocation) is not AdapterInvocation or (
        type(plan.policy_plan) is not PolicyPlan
        or plan.invocation.adapter_id != NATIVE_WEB_PROVIDER_ID
        or plan.invocation.request.parameters.get("check_id", NATIVE_WEB_CHECK_ID)
            not in _CHECKS.values()
        or plan.policy_plan.invocation_sha256 != InvocationDigest(plan.invocation)
        or plan.policy_plan.confirmation_required is not True
    ):
        raise ValueError("CI native web requires the exact supported native plan")


def EvaluateNativeWebCriterion(
    model: ModelState, summary: NativeWebScanSummary, plan: NativeWebScanPlan,
    workspace_root: Path, *, expected_snapshot_sha256: str, criterion: CiFindingCriterion,
    expected_owner_reference: str, expected_limits: NativeWebScanLimits,
    current_plan: Callable[[], NativeWebScanPlan],
) -> CiPredicateResult:
    """Select only re-normalized detections of this exact successful native web job.

    Original worker metadata is reparsed; the deliberately unretained HTTP body is
    not independently re-evaluated. Persisted metadata and constructor equality do
    not grant permission to execute. Current authority must still yield the exact
    original plan, and execution remains owned by the unchanged native workflow.

    Args:
        model: Exact saved model used by all three report artifacts.
        summary: Actual successful current native workflow summary and original acquisitions.
        plan: Exact invocation/confirmation intent selected before the current execution.
        workspace_root: Existing owning physical workspace and evidence partition.
        expected_snapshot_sha256: Complete canonical saved model digest.
        criterion: Explicit severity/status/count predicate and completeness acknowledgement.
        expected_owner_reference: Original caller identity used by the current plan reader.
        expected_limits: Original request and owning-job deadlines selected before execution.
        current_plan: Trusted fresh owner/scope/policy reader that only replans this operation.

    Returns:
        Current-run-only predicate facts with saved manual triage preserved.

    Raises:
        ValueError: Original source, current authority, saved model or detection proof differs.
        PermissionError: Current native authority is no longer admissible.
        EvidenceError: Original source manifest or bytes cannot be verified.
        OSError: Original workspace, model, policy or evidence storage is unavailable.
    """

    RequireNativeSummary(summary)
    RequirePlan(plan)

    if type(model) is not ModelState or type(criterion) is not CiFindingCriterion or (
        type(expected_snapshot_sha256) is not str
        or type(expected_limits) is not NativeWebScanLimits
    ):
        raise ValueError("CI native web requires exact model and criterion contracts")

    criterion.__post_init__()
    expected_limits.__post_init__()
    RequireWorkspaceText(expected_owner_reference, "expected_owner_reference")
    RequireDigest(expected_snapshot_sha256)
    fresh = current_plan()
    RequirePlan(fresh)

    if fresh != plan:
        raise ValueError("CI native web current authority differs from the original plan")

    snapshot = summary.snapshot
    invocation = plan.invocation
    checkId = str(invocation.request.parameters.get("check_id", NATIVE_WEB_CHECK_ID))

    if snapshot.state is not JobState.COMPLETED or summary.check_id != checkId or (
        len(snapshot.artifacts) != 2 or snapshot.spec.workspace_id != model.workspace_id
        or snapshot.spec.scope_reference != plan.policy_plan.scope_reference
        or summary.model_revision != model.revision
        or snapshot.spec.owner_reference != expected_owner_reference
        or type(snapshot.spec.timeout_seconds) is not int
        or snapshot.spec.timeout_seconds != expected_limits.timeout_seconds
        or invocation.request.parameters.get("timeout_seconds") != (
            expected_limits.request_timeout_seconds)
    ):
        raise ValueError("CI native web requires one exact successful current job")

    RequireModelContracts(model)
    rebuilt = ModelState.FromDict(model.ToDict())

    if rebuilt != model or ReportSnapshot(rebuilt).SnapshotDigest() != (
        expected_snapshot_sha256
    ) or LocalModelStore(workspace_root).Open() != rebuilt:
        raise ValueError("CI native web requires the complete current saved snapshot")

    workspace = LocalWorkspaceStore(workspace_root).Open()
    store = LocalEvidenceStore(workspace_root / "evidence")
    records = tuple(item.evidence for item in snapshot.artifacts)

    if snapshot.spec.job_id not in workspace.job_references or tuple(
        item.reference.role for item in records
    ) != ("stdout", "stderr"):
        raise ValueError("CI native web requires its original retained job and ordered streams")

    original = records[0].provenance

    for record in records:
        collection = record.provenance

        if store.Get(record.evidence_id) != record or (
            record.evidence_id not in workspace.evidence_record_references
            or record.reference not in workspace.evidence_references
            or collection != original
            or collection.workspace_id != model.workspace_id
            or collection.scope_reference != snapshot.spec.scope_reference
            or collection.source_id != NATIVE_WEB_PROVIDER_ID
            or collection.source_version != NATIVE_WEB_VERSION
            or collection.tool_version != NATIVE_WEB_VERSION
            or collection.invocation_sha256 != InvocationDigest(invocation)
            or type(collection.execution) is not AdapterExecution
            or collection.execution.state is not ExecutionState.SUCCEEDED
            or collection.execution.exit_code != 0
        ):
            raise ValueError("CI native web source differs from this invocation and execution")

        store.Read(record.reference)

    assert original.execution is not None, "Verified original acquisition has an execution"
    references = tuple(item.reference for item in records)
    report = AdapterReport(invocation, original.execution, references)
    normalized = NativeWebAdapter(store.Read).NormalizeReport(report)
    target = str(invocation.request.parameters["url"])
    subject = ObjectIdentity(model.workspace_id, ObjectKind.ENDPOINT, target)
    observations = tuple(item for item in rebuilt.observations
        if item.provenance.run_reference == snapshot.spec.job_id
        and item.kind == "native.web-response-check")

    if len(observations) != 1 or len(normalized.observations) != 1:
        raise ValueError("CI native web requires its exact current source observation")

    observed = observations[0]
    provenance = ModelProvenance(NATIVE_WEB_PROVIDER_ID, snapshot.spec.job_id,
        observed.provenance.observed_at, snapshot.spec.scope_reference,
        invocation.request.target_reference, NATIVE_WEB_VERSION, references, original.execution)
    expectedObservation = normalized.observations[0]
    objects = {item.Reference(): item for item in rebuilt.objects}
    endpoint = objects.get(subject.Reference())

    if observed != Observation(expectedObservation.kind, subject.Reference(),
        dict(expectedObservation.attributes), provenance) or endpoint is None or (
        endpoint.attributes.get("url") != target or provenance not in endpoint.provenance
    ):
        raise ValueError("CI native web saved endpoint/source proof differs from original metadata")

    selected = []
    detectionReferences = set()

    for item in normalized.findings:
        candidate = Finding(subject.Reference(), checkId, target, item.summary,
                            (provenance,), severity=FindingSeverity.LOW)
        reference = candidate.ToObject(model.workspace_id).Reference()
        entity = objects.get(reference)
        detection = Observation("finding-detection", reference,
                                candidate.ToAttributes(), provenance)

        if entity is None or provenance not in entity.provenance or (
            detection not in rebuilt.observations
        ):
            raise ValueError("CI native web has no exact saved current detection proof")

        current = Finding.FromObject(entity)
        actualAttributes = current.ToAttributes()
        expectedAttributes = candidate.ToAttributes()

        for fieldName in ("status", "status_reason"):
            actualAttributes.pop(fieldName)
            expectedAttributes.pop(fieldName)

        if actualAttributes != expectedAttributes:
            raise ValueError("CI native web saved finding differs from its original detection")

        selected.append(current)
        detectionReferences.add(detection.Reference())

    actualDetections = {item.Reference() for item in rebuilt.observations
        if item.kind == "finding-detection"
        and item.provenance.run_reference == snapshot.spec.job_id}

    if actualDetections != detectionReferences:
        raise ValueError("CI native web current detections differ from the original worker verdict")

    runDigest = hashlib.sha256(CanonicalModelJson({"profile": "native-web", "schema_version": 1,
        "job_id": snapshot.spec.job_id, "workspace_id": model.workspace_id,
        "invocation_sha256": InvocationDigest(invocation),
        "stdout": SerializeContract(records[0].reference),
        "stderr": SerializeContract(records[1].reference)})).hexdigest()

    return EvaluatePredicate(rebuilt, tuple(selected), criterion, expected_snapshot_sha256,
                             "native-web:" + runDigest)


def RunNativeWebCiCommands(
    options: argparse.Namespace, output: TextIO, *, json_output: bool = False,
) -> int:
    """Compose the existing confirmed native workflow with bounded CI artifacts and criterion.

    Args:
        options: Namespace from the canonical CI parser, selecting only this finite profile.
        output: Caller-owned machine/human presentation stream.
        json_output: Emit one detached JSON outcome rather than concise human text.

    Returns:
        Existing CI exit taxonomy 0/1/2/3/4/130 with truthful partial report outcomes.
    """

    empty: dict[str, object] = {"status": "not-run", "model_revision": None,
        "snapshot_sha256": None, "report_sha256": None, "size_bytes": None,
        "output_published": False, "failure": None}
    reports = {name: dict(empty) for name in ("json", "sarif", "junit")}
    outcome: dict[str, object] = {"schema_version": 1, "command": "ci.scan", "status": "failed",
        "scope": "selected-profile-finding-predicate", "scan_completeness": "not-assessed",
        "acknowledge_unassessed_completeness": False, "policy": None,
        "criterion": {"status": "indeterminate"}, "scan": None, "reports": reports,
        "model_revision": None, "snapshot_sha256": None, "failure": None, "exit_code": 4}
    phase = "configuration"
    publishing: str | None = None
    status = 4

    try:
        forbidden = (options.executable, options.producer, options.material, options.source,
            options.logical_path, options.archive, options.cache_directory,
            options.read_consent_reference)

        if any(item is not None for item in forbidden) or options.approve_safe_configuration or (
            options.approve_safe_image or options.check not in _CHECKS or options.target is None
            or options.policy is None or not options.policy.is_absolute()
        ):
            raise ReportFailure("configuration", 2)

        criterion = CiFindingCriterion(tuple(FindingSeverity(item) for item in options.severity),
            tuple(FindingStatus(item) for item in options.status), options.max_matches,
            options.acknowledge_unassessed_completeness)
        limits = NativeWebScanLimits(3.0 if options.request_timeout is None else (
            options.request_timeout), options.timeout)
        root = RequireReportPath(options.workspace)
        checkId = _CHECKS[options.check]
        NativeWebEndpoint(options.target, check_id=checkId)
        target = Target(TargetKind.URL, options.target)
        destinations = {name: ReportOutputPath(getattr(options, "report_" + name), root)
                        for name in reports}

        if len(set(destinations.values())) != 3:
            raise ReportFailure("configuration", 2)

        outcome["policy"] = criterion.ToDict()
        outcome["acknowledge_unassessed_completeness"] = True

        def CurrentPlan() -> NativeWebScanPlan:
            """Reopen the same current selected scope, policy and exact one-GET invocation."""

            def Policy() -> ImpactPolicy:
                """Read the strict explicitly selected native policy without implicit grants."""

                return ReadNucleiPolicy(options.policy)

            return PlanNativeWebScan(root, options.scope, target, options.owner, Policy,
                                     check_id=checkId, limits=limits)

        phase = "authorization"
        plan = CurrentPlan()
        confirmation = None

        if options.confirm_plan is not None or options.confirmation_reference is not None:
            if options.confirm_plan is None or options.confirmation_reference is None:
                raise ReportFailure("configuration", 2)

            confirmation = PolicyConfirmation(options.confirm_plan, options.confirmation_reference)

        phase = "scan"

        def Policy() -> ImpactPolicy:
            """Reread current caller-selected permission at every native authority boundary."""

            return ReadNucleiPolicy(options.policy)

        summary = asyncio.run(RunNativeWebScan(root, options.scope, target, options.owner,
            Policy, confirmation=confirmation, check_id=checkId, limits=limits))
        RequireNativeSummary(summary)
        outcome["scan"] = summary.ToDict()
        outcome["model_revision"] = summary.model_revision
        status = summary.ExitCode()

        if status != 0:
            failure = summary.snapshot.failure
            raise ReportFailure(failure.code.value if failure is not None else "cancelled", status)

        phase = "gate-integrity"
        original = OpenReportInput(root)
        pin = original.report.SnapshotDigest()
        result = EvaluateNativeWebCriterion(original.report.state, summary, plan, root,
            expected_snapshot_sha256=pin, criterion=criterion,
            expected_owner_reference=options.owner, expected_limits=limits,
            current_plan=CurrentPlan)
        outcome["criterion"] = result.ToDict()
        outcome["snapshot_sha256"] = pin
        phase = "rendering"
        payloads = {"json": SerializeJson(original.report),
                    "sarif": SerializeSarif(original.report),
                    "junit": SerializeJunit(original.report)}

        for name, payload in payloads.items():
            reports[name].update({"model_revision": original.report.state.revision,
                "snapshot_sha256": pin, "report_sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload)})

        for name, payload in payloads.items():
            phase = "gate-integrity"
            CheckReportSnapshot(root, original)

            if CurrentPlan() != plan:
                raise ReportFailure("authorization", 3)

            phase = "publication"
            publishing = name
            PublishReport(destinations[name], payload)
            reports[name].update({"status": "completed", "output_published": True})
            publishing = None

        phase = "gate-integrity"
        CheckReportSnapshot(root, original)
        EvaluateNativeWebCriterion(original.report.state, summary, plan, root,
            expected_snapshot_sha256=pin, criterion=criterion,
            expected_owner_reference=options.owner, expected_limits=limits,
            current_plan=CurrentPlan)
        status = 0 if result.satisfied else 1
        outcome["status"] = "criterion-satisfied" if result.satisfied else "criterion-violated"

    except ReportFailure as error:
        status = error.status
        outcome["failure"] = error.kind

        if publishing is not None:
            reports[publishing].update({"status": "failed", "failure": error.kind,
                                       "output_published": error.published})

    except (NativeWebAuthorityDeniedError, PolicyDeniedError):
        status = 3
        outcome["failure"] = "authorization"

    except (EvidenceError, OSError, ValueError, TypeError, RecursionError):
        status = 2 if phase == "configuration" else 4
        outcome["failure"] = phase

    except KeyboardInterrupt:
        status = 130
        outcome["failure"] = "interrupted"

    except Exception:
        status = 4
        outcome["failure"] = "internal"

    outcome["exit_code"] = status

    if json_output:
        WriteJson(output, outcome)

    else:
        output.write(f"CI scan {outcome['status']} (exit {status}); selected finding predicate; "
                     "global scan completeness was not assessed.\n")
        output.flush()

    return status
