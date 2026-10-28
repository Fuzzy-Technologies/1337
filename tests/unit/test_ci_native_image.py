# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Native CI contracts with explicit provider/observer doubles; never genuine Trivy acceptance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from xml.etree import ElementTree

import pytest

import fuzzy1337.ci_commands as commands
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.ci_gate import CiFindingCriterion, EvaluateNativeImageCriterion
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_image_workflow import ScanNativeImage
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from tests.ci_helpers import InvokeCi
from tests.unit import test_native_image_bounded_capture as provider_unit
from tests.unit.test_native_image_policy import AT
from tests.unit.test_native_image_policy import authority as authority
from tests.unit.test_native_image_policy import collector as collector
from tests.unit.test_native_image_policy import material_control as material_control
from tests.unit.test_native_image_policy import observation_runner as observation_runner
from tests.unit.test_native_image_policy import simulated_observer as simulated_observer


def NativeArguments(root: Path, policy: Path, parent: Path) -> list[str]:
    """Select every owned native input and the existing explicit high/open zero-match predicate."""

    return ["scan", str(root), "--profile", "native-trivy", "--archive", "image.tar",
        "--executable", str(root / "trivy"), "--cache-directory", "cache", "--policy", str(policy),
        "--scope", "native-unit", "--owner", "actor:unit", "--read-consent-reference",
        "read:ci-native-unit", "--approve-safe-image", "--severity", "high", "--status", "open",
        "--max-matches", "0", "--acknowledge-unassessed-completeness", "--report-json",
        str(parent / "ci.json"), "--report-sarif", str(parent / "ci.sarif"),
        "--report-junit", str(parent / "ci.xml")]


@pytest.fixture
def native_ci(authority, monkeypatch):
    """Keep real governance, storage and report owners around explicit offline process doubles."""

    root = authority.root
    LocalModelStore(root).Create()
    policy = root / "ci-policy.json"
    policy.write_text(SerializeContract(authority.context.policy), encoding="utf-8")
    monkeypatch.setattr(commands.asyncio, "run", authority.collector.run)

    async def Scan(*args, **kwargs):
        """Select only the fixture authority clock; leave native product ownership unchanged."""

        return await ScanNativeImage(*args, **kwargs, clock=lambda: AT)

    monkeypatch.setattr(commands, "ScanNativeImage", Scan)

    return authority, policy


def Revoke(root: Path) -> None:
    """Change the existing recorded scope, without manufacturing another authority record."""

    store = LocalScopeStore(root)
    scope = store.Open("native-unit")
    store.Save(replace(scope,
        authorization=replace(scope.authorization, state=AuthorizationState.REVOKED)))


@pytest.mark.parametrize("limit,expected", [(0, 1), (1, 0)])
def test_ControlledNativePairPublishesOneSavedSnapshotAndExplicitPredicate(
    native_ci, tmp_path, limit, expected,
):
    """Real report files and canonical model agree under explicitly doubled engine execution."""

    authority, policy = native_ci
    arguments = NativeArguments(authority.root, policy, tmp_path)
    arguments[arguments.index("--max-matches") + 1] = str(limit)
    status, outcome = InvokeCi(arguments)
    assert status == expected == outcome["exit_code"], outcome
    assert outcome["scan"]["workflow"] == "native-image" and (
        outcome["scan"]["state"] == "completed" and not outcome["scan"]["custody_uncertain"]
    ), "CI must preserve the actual native workflow and certain original custody"
    assert len(authority.collector.state.calls) == 2 and (
        outcome["criterion"]["selected_count"] == outcome["criterion"]["matched_count"] == 1
    ), "The controlled pair produces one original high/open detection, independent of the limit"
    assert outcome["criterion"]["run_reference"].startswith("native-scan:") and (
        "acceptance" not in outcome["scan"]
    ), "Native source attribution cannot serialize the live original acceptance association"
    saved = LocalModelStore(authority.root).Open()
    exported = json.loads((tmp_path / "ci.json").read_bytes())
    sarif = json.loads((tmp_path / "ci.sarif").read_bytes())
    junit = ElementTree.parse(tmp_path / "ci.xml").getroot()
    properties = {item.attrib["name"]: item.attrib["value"]
                  for item in junit.findall("properties/property")}
    assert exported["model"] == saved.ToDict() and len(sarif["runs"][0]["results"]) == (
        len(junit.findall("testcase"))
    ) == 1, "All three real formats preserve the same current complete saved native model"
    assert exported["snapshot_sha256"] == outcome["snapshot_sha256"] == (
        properties["snapshot_sha256"]
    ) == sarif["runs"][0]["properties"]["canonicalSnapshotSha256"], (
        "The exact saved snapshot digest must bind every published artifact"
    )
    assert properties["scan_completeness"] == "not-assessed", (
        "A criterion result cannot imply complete vulnerability discovery"
    )

    for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
        report = outcome["reports"][name]
        assert report["output_published"] is True and report["status"] == "completed" and (
            report["report_sha256"] == hashlib.sha256(
                (tmp_path / filename).read_bytes()).hexdigest()
        ), "Per-artifact facts must match independently reopened actually published bytes"


@pytest.mark.parametrize("mode", ["dismissed", "absent"])
def test_NativeCurrentSelectionPreservesTriageAndHistoricalFullReportFacts(
    native_ci, tmp_path, monkeypatch, mode,
):
    """Controlled repeated runs retain triage and history without adding absent current matches."""

    authority, policy = native_ci
    summary = authority.collector.run(ScanNativeImage(authority.root, "native-unit", "actor:unit",
        authority.collector.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    assert summary.ExitCode() == 0, summary.ToDict()
    store = LocalModelStore(authority.root)
    original = store.Open()
    finding = Findings(original)[0]
    operator = replace(finding.provenance[0], source_id="operator.test", run_reference="run:triage",
                       execution=None)

    if mode == "dismissed":
        saved, _ = TransitionFinding(original, finding.ToObject(original.workspace_id).Reference(),
            FindingStatus.DISMISSED, operator, "Owned native CI dismissal")
        store.Save(saved, expected_revision=original.revision)
        unrelated = Finding(finding.subject_reference, "ci.unrelated", "other:position",
            "Unrelated retained high finding", (operator,), severity=FindingSeverity.HIGH)
        updated, _ = ApplyFindings(saved, (unrelated,))
        store.Save(updated, expected_revision=saved.revision)

    else:
        report = json.loads(json.dumps(provider_unit.REPORT))
        report["Results"][0]["Vulnerabilities"] = []
        monkeypatch.setattr(provider_unit, "REPORT", report)

    status, outcome = InvokeCi(NativeArguments(authority.root, policy, tmp_path))
    assert status == 0 and outcome["criterion"]["selected_count"] == (
        1 if mode == "dismissed" else 0
    ) and outcome["criterion"]["matched_count"] == 0, outcome
    current = next(item for item in Findings(store.Open()) if item.check_id == finding.check_id)
    assert current.status is (FindingStatus.DISMISSED if mode == "dismissed" else
                              FindingStatus.OPEN), (
        "Repeated or absent detection must preserve the original saved operator disposition"
    )
    assert len(json.loads((tmp_path / "ci.json").read_bytes())["findings"]) == (
        2 if mode == "dismissed" else 1
    ), "The complete report retains unrelated and historical findings outside the predicate"


@pytest.mark.parametrize("mode", ["producer", "material", "source", "logical-path",
    "approve-safe-configuration", "missing-policy", "missing-cache-directory", "missing-archive",
    "relative-executable", "relative-policy", "archive-traversal", "archive-alias", "cache-alias"])
def test_NativeGrammarRefusesBeforeWorkflowLaunchOrSelectedContentRead(
    native_ci, tmp_path, monkeypatch, mode,
):
    """Native input exclusions and original relative spelling are preflight configuration facts."""

    authority, policy = native_ci
    arguments = NativeArguments(authority.root, policy, tmp_path)

    if mode.startswith("missing-"):
        position = arguments.index("--" + mode.removeprefix("missing-"))
        del arguments[position:position + 2]

    elif mode.startswith("relative-"):
        arguments[arguments.index("--" + mode.removeprefix("relative-")) + 1] = "relative-file"

    elif mode in {"archive-traversal", "archive-alias", "cache-alias"}:
        option = "--cache-directory" if mode == "cache-alias" else "--archive"
        arguments[arguments.index(option) + 1] = {
            "archive-traversal": "../image.tar", "archive-alias": "./image.tar",
            "cache-alias": "cache//nested"}[mode]

    else:
        arguments.append("--" + mode)

        if mode != "approve-safe-configuration":
            arguments.append(str(authority.root / "excluded-input"))

    async def Forbidden(*_args, **_kwargs):
        """Trip any scanner call made before an incompatible declaration was refused."""

        pytest.fail("Invalid native CI arguments reached workflow execution")

    monkeypatch.setattr(commands, "ScanNativeImage", Forbidden)
    status, outcome = InvokeCi(arguments)
    assert status == 2 and outcome["scan"] is None and not authority.collector.state.calls, outcome
    assert not (tmp_path / "ci.json").exists(), "Invalid declarations publish no scan artifact"


@pytest.mark.parametrize("mode,expected", [("failed", 4), ("unknown", 4), ("no-approval", 3)])
def test_NativeFailedOrUnapprovedExecutionCannotBecomeSatisfiedEmptyPredicate(
    native_ci, tmp_path, mode, expected,
):
    """Explicit provider doubles retain failed/uncertain execution truth without clean claims."""

    authority, policy = native_ci
    arguments = NativeArguments(authority.root, policy, tmp_path)

    if mode == "no-approval":
        arguments.remove("--approve-safe-image")

    else:
        authority.collector.state.mode = mode

    status, outcome = InvokeCi(arguments)
    assert status == expected and outcome["criterion"]["status"] == "indeterminate", outcome
    assert len(authority.collector.state.calls) == (0 if mode == "no-approval" else 1), (
        "No unapproved or failed VERSION may start a second native operation"
    )
    assert not (tmp_path / "ci.json").exists(), "Failed acquisition cannot publish a success report"


@pytest.mark.parametrize("mode,expected", [("scope", 3), ("policy", 3), ("material", 4),
                                          ("snapshot", 4)])
def test_LateNativeRefusalPreservesActuallyPublishedReportsAndReturnsNonzero(
    native_ci, tmp_path, monkeypatch, mode, expected,
):
    """Fresh original authority and saved snapshot are required after every actual export."""

    authority, policy = native_ci
    publish = commands.PublishReport

    def Publish(destination, payload):
        """Publish unchanged bytes, then mutate only explicit owned facts after the final file."""

        publish(destination, payload)

        if destination.suffix != ".xml":
            return

        if mode == "scope":
            Revoke(authority.root)

        elif mode == "policy":
            changed = replace(authority.context.policy, max_authorization_seconds=200)
            policy.write_text(SerializeContract(changed), encoding="utf-8")

        elif mode == "material":
            authority.collector.selection.executable.write_bytes(b"changed owned unit binary")

        else:
            store = LocalModelStore(authority.root)
            original = store.Open()
            finding = Findings(original)[0]
            changed = replace(finding, summary="Changed saved current finding")
            updated, _ = original.Apply(objects=(changed.ToObject(original.workspace_id),))
            store.Save(updated, expected_revision=original.revision)

    monkeypatch.setattr(commands, "PublishReport", Publish)
    status, outcome = InvokeCi(NativeArguments(authority.root, policy, tmp_path))
    assert status == expected and outcome["scan"]["state"] == "completed", outcome
    assert all(item["output_published"] is True for item in outcome["reports"].values()), (
        "Late refusal cannot erase independently confirmed publication of all three artifacts"
    )
    assert all((tmp_path / filename).is_file() for filename in ("ci.json", "ci.sarif", "ci.xml")), (
        "Actually published native artifacts remain available after the final barrier refuses"
    )


def test_NativeGateRefusalAfterJsonRetainsOriginalPublication(native_ci, tmp_path, monkeypatch):
    """The native owner's JSON export precedes returned-handle checking and remains factual."""

    authority, policy = native_ci
    evaluate = commands.EvaluateNativeImageCriterion

    def Evaluate(*args, **kwargs):
        """Revoke only after original acquisition and JSON publication, before predicate use."""

        Revoke(authority.root)

        return evaluate(*args, **kwargs)

    monkeypatch.setattr(commands, "EvaluateNativeImageCriterion", Evaluate)
    status, outcome = InvokeCi(NativeArguments(authority.root, policy, tmp_path))
    assert status == 3 and outcome["reports"]["json"]["output_published"] is True and (
        outcome["criterion"]["status"] == "indeterminate"
    ), outcome
    assert (tmp_path / "ci.json").is_file() and not (tmp_path / "ci.sarif").exists(), (
        "Pre-gate refusal preserves JSON but cannot claim later formats were published"
    )


def test_NativePartialExportRetainsPerFileTruth(native_ci, tmp_path, monkeypatch):
    """A refused second extra artifact preserves original scan, JSON and completed SARIF."""

    authority, policy = native_ci
    publish = commands.PublishReport

    def Publish(destination, payload):
        """Refuse only the selected JUnit boundary without changing earlier published bytes."""

        if destination.suffix == ".xml":
            raise ReportFailure("publication")

        publish(destination, payload)

    monkeypatch.setattr(commands, "PublishReport", Publish)
    status, outcome = InvokeCi(NativeArguments(authority.root, policy, tmp_path))
    assert status == 4 and outcome["scan"]["state"] == "completed" and (
        outcome["reports"]["json"]["output_published"] is True
        and outcome["reports"]["sarif"]["output_published"] is True
        and outcome["reports"]["junit"]["status"] == "failed"
        and outcome["reports"]["junit"]["output_published"] is False
    ), outcome


@pytest.mark.parametrize("mode", ["pin", "inventory", "observation", "detection", "finding",
                                  "records", "captures", "handle"])
def test_NativeGateRequiresOriginalSavedSourceAndCaptureProof(native_ci, mode):
    """Original-handle proof plus complete current candidate facts forbid substituted success."""

    authority, _ = native_ci
    summary = authority.collector.run(ScanNativeImage(authority.root, "native-unit", "actor:unit",
        authority.collector.selection, lambda: authority.context.policy, approve_safe_image=True,
        clock=lambda: AT))
    store = LocalModelStore(authority.root)
    saved = store.Open()
    captures, records, acceptance = summary.captures, summary.retained_records, summary.acceptance
    pin = ReportSnapshot(saved).SnapshotDigest()

    if mode == "pin":
        pin = "0" * 64

    elif mode == "records":
        records = records[:-1]

    elif mode == "captures":
        captures = tuple(replace(item) for item in captures)

    elif mode == "handle":
        acceptance = object.__new__(type(acceptance))

    else:
        if mode in {"observation", "detection"}:
            kind = "image-inventory" if mode == "observation" else "finding-detection"
            saved = replace(saved, observations=tuple(item for item in saved.observations
                                                      if item.kind != kind))

        else:
            target = Findings(saved)[0].ToObject(saved.workspace_id).Reference() if (
                mode == "finding") else saved.relations[0].source_reference
            saved = replace(saved, objects=tuple(replace(item, attributes={**item.attributes,
                "summary": "Changed owned source interpretation"}) if item.Reference() == target
                else item for item in saved.objects))

        # Store a valid next revision so only the saved source proof, not the caller pin, differs.
        saved = store.Save(replace(saved, revision=saved.revision + 1),
                           expected_revision=saved.revision)
        pin = ReportSnapshot(saved).SnapshotDigest()

    with pytest.raises((ValueError, PermissionError)):
        EvaluateNativeImageCriterion(saved, captures, records, authority.root,
            expected_snapshot_sha256=pin,
            criterion=CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True),
            acceptance=acceptance)
