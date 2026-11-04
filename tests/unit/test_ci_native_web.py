# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Current-run native CI source proof, triage preservation and deterministic command failures."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from dataclasses import replace

import pytest

from fuzzy1337 import ci_commands, ci_native_web
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.ci_commands import RunCiCommands
from fuzzy1337.ci_gate import CiFindingCriterion
from fuzzy1337.ci_native_web import EvaluateNativeWebCriterion
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus, TransitionFinding
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import NativeWebScanLimits, PlanNativeWebScan, RunNativeWebScan
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.reporting import ReportSnapshot
from tests.ci_helpers import CiArguments
from tests.configuration_helpers import LiveConfiguration
from tests.unit.test_native_web import Policy
from tests.unit.test_native_web import owned_loop as owned_loop  # noqa: F401
from tests.unit.test_native_web import runner as runner  # noqa: F401
from tests.unit.test_native_web import workflow as workflow  # noqa: F401


def Criterion(*, status=FindingStatus.OPEN, maximum=0):
    """Choose the exact finite low-severity conjunction without asserting completeness."""

    return CiFindingCriterion((FindingSeverity.LOW,), (status,), maximum, True)


def ActualSource(workflow, runner):
    """Exercise actual job/model/evidence owners with only the transport supplied by its fixture."""

    root, target, approval, _ = workflow
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", Policy)
    summary = runner.run(RunNativeWebScan(root, "local", target, "operator:owned", Policy,
                                         confirmation=approval))
    model = LocalModelStore(root).Open()

    return root, target, plan, summary, model


def Evaluate(root, target, plan, summary, model, *, criterion=None):
    """Reopen fresh authority and evaluate only the supplied current original execution."""

    return EvaluateNativeWebCriterion(model, summary, plan, root,
        expected_snapshot_sha256=ReportSnapshot(model).SnapshotDigest(),
        expected_owner_reference="operator:owned", expected_limits=NativeWebScanLimits(),
        criterion=Criterion() if criterion is None else criterion,
        current_plan=lambda: PlanNativeWebScan(root, "local", target, "operator:owned", Policy))


def Arguments(workflow, parent):
    """Select the explicit native profile, exact confirmation and three new physical outputs."""

    root, target, approval, _ = workflow
    policy = root / "native-policy.json"
    policy.write_text(SerializeContract(Policy()), encoding="utf-8")

    return ["scan", str(root), "--profile", "native-web", "--check", "git-head-exposure",
        "--target", target.value, "--scope", "local", "--owner", "operator:owned",
        "--policy", str(policy), "--timeout", "10", "--confirm-plan", approval.intent_sha256,
        "--confirmation-reference", approval.record_reference, "--severity", "low", "--status",
        "open", "--max-matches", "0", "--acknowledge-unassessed-completeness",
        "--report-json", str(parent / "ci.json"), "--report-sarif", str(parent / "ci.sarif"),
        "--report-junit", str(parent / "ci.xml")]


def Invoke(arguments):
    """Call the registered command handler and parse one original machine outcome."""

    output = io.StringIO()
    status = RunCiCommands(arguments, output, json_output=True)

    return status, json.loads(output.getvalue())


@pytest.mark.parametrize("mode,expected", [("match", False), ("negative", True)])
def test_CurrentOriginalMetadataSelectsOnlyActualCurrentDetections(
    workflow, runner, mode, expected,
):
    """Negative worker metadata is an empty selection, not a retained-model search."""

    workflow[3]["mode"] = mode
    root, target, plan, summary, model = ActualSource(workflow, runner)
    result = Evaluate(root, target, plan, summary, model)
    assert result.satisfied is expected, "The criterion must reflect the current worker verdict"
    assert len(result.selected_finding_references) == int(not expected), (
        "Only re-normalized original current detections may enter the CI predicate"
    )
    assert result.run_reference.startswith("native-web:") and (
        result.snapshot_sha256 == ReportSnapshot(model).SnapshotDigest()
    ), "CI result must identify its own run domain and complete saved model"


def test_CurrentNegativeExcludesOldPositiveAtTheSameEndpoint(workflow, runner):
    """An old real detection remains in the full report without becoming a current detection."""

    root, target, plan, _, _ = ActualSource(workflow, runner)
    workflow[3]["mode"] = "negative"
    _, _, _, summary, model = ActualSource(workflow, runner)
    result = Evaluate(root, target, plan, summary, model)
    assert len(Findings(model)) == 1 and result.satisfied and not (
        result.selected_finding_references
    ), "A retained positive cannot fail the criterion for a new negative acquisition"


def test_AdditionalContradictoryCurrentDetectionAtSameReferenceIsRefused(workflow, runner):
    """A subject-reference set cannot hide a second changed original current-job interpretation."""

    root, target, plan, summary, model = ActualSource(workflow, runner)
    original = next(item for item in model.observations if item.kind == "finding-detection")
    attributes = dict(original.attributes)
    attributes["summary"] = "Contradictory source attribution"
    contradictory = replace(original, attributes=attributes)
    changed, _ = model.Apply(observations=(contradictory,))
    LocalModelStore(root).Save(changed, expected_revision=model.revision)
    summary = replace(summary, model_revision=changed.revision)

    with pytest.raises(ValueError, match="current detections"):
        Evaluate(root, target, plan, summary, changed)


def test_CurrentPositiveRetainsSavedManualTriage(workflow, runner):
    """Source reconstruction checks detection facts while preserving the current triage state."""

    root, target, plan, _, model = ActualSource(workflow, runner)
    finding = Findings(model)[0]
    decision = replace(finding.provenance[0], source_id="operator.triage",
        run_reference="decision:ci-native", execution=None, provider_version=None)
    triaged, _ = TransitionFinding(model, finding.ToObject(model.workspace_id).Reference(),
        FindingStatus.DISMISSED, decision, "Reviewed bounded exposure")
    LocalModelStore(root).Save(triaged, expected_revision=model.revision)
    _, _, _, summary, model = ActualSource(workflow, runner)
    result = Evaluate(root, target, plan, summary, model)
    accepted = Evaluate(root, target, plan, summary, model,
                        criterion=Criterion(status=FindingStatus.DISMISSED))
    assert result.satisfied and not accepted.satisfied, (
        "Saved manual acceptance must remain current"
    )
    assert len(result.selected_finding_references) == 1, "Triage cannot erase the source selection"


@pytest.mark.parametrize("mutation", ["failed", "cancelled", "revision", "check", "missing-stream",
    "swapped-streams", "job", "scope", "workspace", "owner", "timeout", "valid-timeout",
    "source", "invocation", "execution"])
def test_ChangedOriginalJobAndAcquisitionFactsFailClosed(workflow, runner, mutation):
    """Original source/job joins reject wrong terminal facts and detached receipts."""

    root, target, plan, summary, model = ActualSource(workflow, runner)
    snapshot = summary.snapshot

    if mutation in {"failed", "cancelled"}:
        snapshot = replace(snapshot, state=JobState.FAILED if mutation == "failed" else (
            JobState.CANCELLED))

    elif mutation == "revision":
        summary = replace(summary, model_revision=summary.model_revision + 1)

    elif mutation == "check":
        summary = replace(summary, check_id="native.prometheus-exposition")

    elif mutation == "missing-stream":
        snapshot = replace(snapshot, artifacts=snapshot.artifacts[:1])

    elif mutation == "swapped-streams":
        snapshot = replace(snapshot, artifacts=tuple(reversed(snapshot.artifacts)))

    elif mutation in {"owner", "timeout", "valid-timeout"}:
        spec = replace(snapshot.spec, **({"owner_reference": "operator:other"}
            if mutation == "owner" else {"timeout_seconds": 999 if mutation == "timeout" else 11}))
        snapshot = replace(snapshot, spec=spec)

    elif mutation in {"job", "scope", "workspace"}:
        field = {"job": "job_id", "scope": "scope_reference", "workspace": "workspace_id"}[
            mutation]
        spec = replace(snapshot.spec, **{field: "job:other" if mutation == "job" else (
            "scope:other" if mutation == "scope" else "other")})
        snapshot = replace(snapshot, spec=spec)

    else:
        artifact = snapshot.artifacts[0]
        record = artifact.evidence
        changes = {"source_id": "another-source"} if mutation == "source" else (
            {"invocation_sha256": "0" * 64} if mutation == "invocation" else {"execution": None})
        changed = replace(record, provenance=replace(record.provenance, **changes))
        snapshot = replace(snapshot, artifacts=(replace(artifact, evidence=changed),
                                                snapshot.artifacts[1]))

    summary = replace(summary, snapshot=snapshot)

    with pytest.raises((ValueError, EvidenceError)):
        Evaluate(root, target, plan, summary, model)


@pytest.mark.parametrize("mutation", ["observation", "detection", "endpoint", "finding"])
def test_ExactSavedSourceAndDetectionProofCannotBeRemoved(workflow, runner, mutation):
    """A complete current saved-model digest does not replace required original source joins."""

    root, target, plan, summary, model = ActualSource(workflow, runner)

    if mutation in {"observation", "detection"}:
        kind = "native.web-response-check" if mutation == "observation" else "finding-detection"
        changed = replace(model, observations=tuple(item for item in model.observations
                                                    if item.kind != kind))

    else:
        kind = "endpoint" if mutation == "endpoint" else "finding"
        objects = tuple(item for item in model.objects if item.identity.kind.value != kind
            and (kind != "endpoint" or item.identity.kind.value != "finding"))
        references = {item.Reference() for item in objects}
        changed = replace(model, objects=objects,
            relations=tuple(item for item in model.relations
                            if item.source_reference in references
                            and item.target_reference in references),
            observations=tuple(item for item in model.observations
                               if item.subject_reference in references))

    changed = replace(changed, revision=model.revision + 1)
    LocalModelStore(root).Save(changed, expected_revision=model.revision)
    summary = replace(summary, model_revision=changed.revision)

    with pytest.raises(ValueError):
        Evaluate(root, target, plan, summary, changed)


@pytest.mark.parametrize("mode,expected", [("match", 1), ("negative", 0), ("fail", 4),
    ("invalid", 4), ("process-timeout", 4), ("output-limit", 4)])
def test_CommandPreservesCriterionAndActualExecutionTaxonomy(
    workflow, runner, monkeypatch, tmp_path, mode, expected,
):
    """Success and threshold failure export one snapshot; failed work never produces a verdict."""

    workflow[3]["mode"] = mode
    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    status, outcome = Invoke(Arguments(workflow, tmp_path))
    assert status == expected == outcome["exit_code"], "Native CI changed the terminal taxonomy"

    if expected in {0, 1}:
        assert all(item["status"] == "completed" for item in outcome["reports"].values()), (
            "Both finite predicate outcomes require three actual snapshot exports"
        )
        assert {item["snapshot_sha256"] for item in outcome["reports"].values()} == {
            outcome["snapshot_sha256"]
        }, "All formats must bind the identical complete saved model"

        for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
            assert outcome["reports"][name]["report_sha256"] == hashlib.sha256(
                (tmp_path / filename).read_bytes()).hexdigest(), (
                    "Report outcome must identify actual published bytes"
                )

    else:
        assert outcome["criterion"] == {"status": "indeterminate"} and not (
            tmp_path / "ci.json"
        ).exists(), "Failed execution must not become an empty satisfied predicate"


@pytest.mark.parametrize("mutation,expected", [("no-ack", 2), ("no-confirm", 3),
    ("wrong-confirm", 3), ("wrong-owner", 3), ("one-confirm-field", 2),
    ("artifact-flag", 2), ("bad-url", 2), ("relative-policy", 2), ("bad-budget", 2)])
def test_CommandConfigurationAndAuthorityRefuseBeforeTransport(
    workflow, runner, monkeypatch, tmp_path, mutation, expected,
):
    """A finite criterion, exact confirmation and closed profile are required before execution."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)

    if mutation == "no-ack":
        arguments.remove("--acknowledge-unassessed-completeness")

    elif mutation == "no-confirm":
        for flag in ("--confirm-plan", "--confirmation-reference"):
            position = arguments.index(flag)
            del arguments[position:position + 2]

    elif mutation in {"wrong-confirm", "wrong-owner", "bad-url", "relative-policy", "bad-budget"}:
        flag, value = {"wrong-confirm": ("--confirm-plan", "0" * 64),
            "wrong-owner": ("--owner", "operator:other"),
            "bad-url": ("--target", "http://example.invalid/.git/HEAD"),
            "relative-policy": ("--policy", "policy.json"), "bad-budget": ("--timeout", "1")
        }[mutation]
        arguments[arguments.index(flag) + 1] = value

    elif mutation == "one-confirm-field":
        position = arguments.index("--confirmation-reference")
        del arguments[position:position + 2]

    else:
        arguments.extend(("--executable", "/usr/bin/python"))

    status, outcome = Invoke(arguments)
    assert status == expected and outcome["exit_code"] == expected, (
        "Invalid configuration or missing authority changed its documented refusal category"
    )
    assert workflow[3]["executed"] is False and not (tmp_path / "ci.json").exists(), (
        "A refused native CI operation cannot reach transport or publish reports"
    )


def test_ExistingReportRefusesBeforeExecutionAndPreservesBytes(
    workflow, runner, monkeypatch, tmp_path,
):
    """Native preflight preserves existing reports and never scans for unusable outputs."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)
    (tmp_path / "ci.json").write_bytes(b"retained\n")
    status, _ = Invoke(arguments)
    assert status == 2 and not workflow[3]["executed"], "Existing output must fail before execution"
    assert (tmp_path / "ci.json").read_bytes() == b"retained\n", "Original report was overwritten"


def test_DifferentFreshPlanRefusesAnOtherwiseOriginalCurrentRun(workflow, runner):
    """A successful historical acquisition cannot stand in for the same current authority."""

    root, _, plan, summary, model = ActualSource(workflow, runner)
    changed = replace(plan, policy_plan=replace(plan.policy_plan,
        policy_revision=plan.policy_plan.policy_revision + 1))

    with pytest.raises(ValueError, match="current authority"):
        EvaluateNativeWebCriterion(model, summary, plan, root,
            expected_snapshot_sha256=ReportSnapshot(model).SnapshotDigest(), criterion=Criterion(),
            expected_owner_reference="operator:owned", expected_limits=NativeWebScanLimits(),
                current_plan=lambda: changed)


@pytest.mark.parametrize("after_first_export", [False, True])
def test_RevokedPolicyAfterScanCannotYieldCriterionSuccess(
    workflow, runner, monkeypatch, tmp_path, after_first_export,
):
    """Recheck current permission before and throughout publication, preserving partial truth."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)
    policyPath = workflow[0] / "native-policy.json"

    def Revoke():
        """Remove only this owned policy's finite capability permission."""

        policyPath.write_text(SerializeContract(replace(Policy(), permissions=())),
                               encoding="utf-8")

    if after_first_export:
        originalPublish = ci_native_web.PublishReport

        def PublishThenRevoke(destination, payload):
            """Perform the real first publication before changing the independent current policy."""

            originalPublish(destination, payload)
            Revoke()

        monkeypatch.setattr(ci_native_web, "PublishReport", PublishThenRevoke)

    else:
        originalRun = ci_native_web.RunNativeWebScan

        async def ScanThenRevoke(*args, **kwargs):
            """Retain the actual completed native result, then change current permission."""

            summary = await originalRun(*args, **kwargs)
            Revoke()

            return summary

        monkeypatch.setattr(ci_native_web, "RunNativeWebScan", ScanThenRevoke)

    status, outcome = Invoke(arguments)
    assert status == 3 and outcome["status"] == "failed", (
        "Revoked current native permission must never yield a satisfied/violated gate result"
    )
    assert (tmp_path / "ci.json").exists() is after_first_export, (
        "The report outcome must retain exactly the already completed prefix of publications"
    )
    assert outcome["reports"]["json"]["output_published"] is after_first_export and not (
        tmp_path / "ci.sarif"
    ).exists(), "Authority loss must preserve completed artifact truth and stop subsequent exports"


def test_CorruptedOriginalWorkerBlobFailsBeforeAnyReport(
    workflow, runner, monkeypatch, tmp_path,
):
    """Original source hashes must be verified even after an actual successful canonical commit."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)
    originalRun = ci_native_web.RunNativeWebScan

    async def ScanThenCorrupt(*args, **kwargs):
        """Replace one owned original blob after the genuine job/evidence/model path completed."""

        summary = await originalRun(*args, **kwargs)
        reference = summary.snapshot.artifacts[0].evidence.reference
        (workflow[0] / "evidence" / reference.locator).write_bytes(b"corrupt\n")

        return summary

    monkeypatch.setattr(ci_native_web, "RunNativeWebScan", ScanThenCorrupt)
    status, outcome = Invoke(arguments)
    assert status == 4 and outcome["criterion"] == {"status": "indeterminate"}, (
        "Lost original source integrity must remain unassessed, not no-findings success"
    )
    assert not (tmp_path / "ci.json").exists(), (
        "Corrupt source produced a successful snapshot export"
    )


def test_IdenticalHistoricalWorkerBytesCannotReplaceCurrentAcquisitions(
    workflow, runner, monkeypatch, tmp_path,
):
    """Retained manifests with the same bytes and execution still belong to their own run."""

    workflow[3]["mode"] = "negative"
    _, _, _, previous, _ = ActualSource(workflow, runner)
    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    originalRun = ci_native_web.RunNativeWebScan
    captured = []

    async def ScanThenSubstituteAcquisitions(*args, **kwargs):
        """Keep the current job events and swap only its terminal artifact manifests."""

        current = await originalRun(*args, **kwargs)
        substituted = tuple(replace(artifact, evidence=historical.evidence)
            for historical, artifact in zip(previous.snapshot.artifacts, current.snapshot.artifacts,
                                            strict=True))
        captured.append(current)

        return replace(current, snapshot=replace(current.snapshot, artifacts=substituted))

    monkeypatch.setattr(ci_native_web, "RunNativeWebScan", ScanThenSubstituteAcquisitions)
    status, outcome = Invoke(Arguments(workflow, tmp_path))
    assert len(captured) == 1 and (
        previous.snapshot.spec.job_id != captured[0].snapshot.spec.job_id
    ), (
        "The test must substitute receipts from a different owning job."
    )

    for historical, artifact in zip(previous.snapshot.artifacts, captured[0].snapshot.artifacts,
                                    strict=True):
        before, after = historical.evidence, artifact.evidence
        assert before.reference == after.reference and (
            before.provenance.execution == after.provenance.execution
        ), "Only acquisition identity may distinguish these two executions."
        assert before.evidence_id != after.evidence_id, (
            "The evidence store must retain separate original acquisition manifests."
        )

    assert status == 4 and outcome["failure"] == "scan" and (
        outcome["criterion"] == {"status": "indeterminate"}
    ), (
        "An earlier byte-identical acquisition must not satisfy the current gate."
    )
    assert all(item["status"] == "not-run" for item in outcome["reports"].values()) and not (
        tmp_path / "ci.json"
    ).exists(), "A mismatched acquisition must fail before report publication."


@pytest.mark.parametrize("ack_lost", [False, True])
def test_ReportPublicationFailureRetainsActualCompletedPrefix(
    workflow, runner, monkeypatch, tmp_path, ack_lost,
):
    """The second publication may fail before write or lose ACK after an actual complete write."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)
    originalPublish = ci_native_web.PublishReport
    published = []

    def PartialPublication(destination, payload):
        """Keep actual atomic publication and inject one independently selected receipt failure."""

        if len(published) == 1:
            if ack_lost:
                originalPublish(destination, payload)

            raise ReportFailure("publication", published=ack_lost)

        originalPublish(destination, payload)
        published.append(destination)

    monkeypatch.setattr(ci_native_web, "PublishReport", PartialPublication)
    status, outcome = Invoke(arguments)
    assert status == 4 and outcome["status"] == "failed", "Incomplete artifact set became PASS"
    assert outcome["reports"]["json"]["output_published"] is True and (
        outcome["reports"]["sarif"]["output_published"] is ack_lost
    ), "Each original publication receipt must retain its independent known state"
    assert (tmp_path / "ci.sarif").exists() is ack_lost and not (
        tmp_path / "ci.xml"
    ).exists(), "A failed publication must stop forward artifact work"


def test_ActualCallerCancellationSettlesNativeJobAndReturns130(
    workflow, runner, monkeypatch, tmp_path,
):
    """Cancellation goes through the actual owning job's await-and-cleanup path."""

    monkeypatch.setattr(ci_native_web.asyncio, "run", runner.run)
    arguments = Arguments(workflow, tmp_path)
    workflow[3]["mode"] = "wait"
    originalRun = ci_native_web.RunNativeWebScan

    async def CancelOwnedRun(*args, **kwargs):
        """Cancel only after the controlled native execution has actually started."""

        task = asyncio.create_task(originalRun(*args, **kwargs))

        async with asyncio.timeout(2):
            while not workflow[3]["executed"]:
                await asyncio.sleep(0)

        task.cancel()

        return await task

    monkeypatch.setattr(ci_native_web, "RunNativeWebScan", CancelOwnedRun)
    status, outcome = Invoke(arguments)
    assert status == 130 and outcome["scan"]["state"] == "cancelled", (
        "Actual native cancellation must remain a settled cancelled job, not empty success"
    )
    assert not (tmp_path / "ci.json").exists(), "Cancelled current native work produced a report"


@pytest.mark.parametrize("flag,value", [
    ("--executable", None), ("--read-consent-reference", None),
    ("--check", "git-head-exposure"), ("--target", "http://127.0.0.1/.git/HEAD"),
    ("--request-timeout", "3"), ("--confirm-plan", "0" * 64),
    ("--confirmation-reference", "approval:foreign"),
])
def test_LegacyProfileStillRequiresArtifactInputsAndRefusesNewWebFlags(
    tmp_path, monkeypatch, flag, value,
):
    """Conditional parser fields preserve old configuration rejection before provider execution."""

    root, selection, _ = LiveConfiguration(tmp_path, "dockerfile.root-user")
    arguments = CiArguments(root, selection, tmp_path)

    if value is None:
        position = arguments.index(flag)
        del arguments[position:position + 2]

    else:
        arguments.extend((flag, value))

    async def RefuseUnexpectedExecution(*args, **kwargs):
        """Reject a test regression that reaches a legacy provider from invalid mixed inputs."""

        pytest.fail("Invalid legacy CI inputs reached provider execution")

    monkeypatch.setattr(ci_commands, "RunSyntheticConfigurationScan", RefuseUnexpectedExecution)
    status, outcome = Invoke(arguments)
    assert status == 2 and outcome["scan"] is None, (
        "Legacy missing inputs and native-only flags must remain configuration errors"
    )
