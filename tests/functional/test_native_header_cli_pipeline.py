# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Six genuine installed CLI identities; explicit native discovery/source/Finding handoffs."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337.findings import Findings, FindingStatus
from fuzzy1337.model import LocalModelStore, ObjectIdentity, ObjectKind
from fuzzy1337.requests import Endpoint
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract.native_header_cli_consumer import OWNER, SCOPE, WORKSPACE
from tests.contract.native_header_cli_evidence import (
    CliControl,
    CliJson,
    CliProcess,
)
from tests.contract.native_header_cli_evidence import header_cli_evidence as header_cli_evidence
from tests.contract.native_header_cli_evidence import header_cli_platform as header_cli_platform
from tests.contract.native_header_cli_evidence import header_cli_run as header_cli_run
from tests.contract.native_header_cli_evidence import installed_header_cli as installed_header_cli
from tests.contract.native_header_cli_target import CASES, SEED, HeaderPipelineTarget
from tests.contract.native_response_header_oracle import (
    AssertInterpretation,
    FrozenOriginals,
    HeaderAbsent,
    OriginalState,
)
from tests.integration.test_owned_response_worker_execution import ExpectedRequest
from tests.native_crawl_acceptance_helpers import NativeGet

pytestmark = pytest.mark.integration


def Policies(directory: Path) -> dict[str, Path]:
    """Write three explicit current permissions; no action derives authority from another."""

    result = {}

    for name, provider, capability, impact in (
        ("crawl", "native.crawl", "http.owned-loopback-crawl", "SAFE"),
        ("capture", "native.loopback-response", "http.synthetic-response-capture", "SAFE"),
        ("header", "native.response-passive", "http.owned-response-header-check", "PASSIVE"),
    ):
        path = directory / (name + "-policy.json")
        path.write_text(json.dumps({"policy_id": "explicit-cli-" + name, "revision": 0,
            "maximum_impact": impact, "permissions": [{"capability_id": capability,
                "adapter_id": provider, "maximum_impact": impact, "granted_privileges": []}],
            "max_authorization_seconds": 300}))
        result[name] = path

    return result


def CheckArguments(root: Path, receipt: str, url: str, policy: Path,
    analysis: str) -> tuple[str, ...]:
    """Select one actual original and a distinct explicit analysis, without an implicit opt-in."""

    return ("response", "check-headers", str(root), "--receipt", receipt, "--target", url,
        "--scope", SCOPE, "--owner", OWNER, "--policy", str(policy),
        "--analysis-reference", analysis)


def Setup(python: Path, directory: Path, evidence, target) -> tuple[Path, dict[str, Path]]:
    """Create real empty canonical state and independent consent through the installed owner."""

    root = directory / "workspace"
    output = CliControl(python, directory, evidence, "setup", {"workspace": str(root),
        "selected_urls": list(target.graph.SelectedUrls())})
    assert output["model"]["objects"] == [] and output["model"]["observations"] == [], (
        "Setup must fabricate no detection, original source, execution or job history")
    assert output["workspace"]["job_references"] == [] and (
        output["workspace"]["evidence_record_references"] == []), "Only real work earns custody"

    return root, Policies(directory)


def Capture(python: Path, directory: Path, evidence, root: Path, policy: Path,
    target, case: str) -> tuple[str, str]:
    """Use actual installed capture CLI and its acknowledged receipt, never a reconstructed ACK."""

    url = target.graph.Url("/zap-passive/" + case)
    process = CliProcess(python, directory, evidence, "capture-" + case,
        ("response", "capture", str(root), "--target", url, "--scope", SCOPE,
            "--owner", OWNER, "--policy", str(policy), "--approve-safe-response-capture", "--json"))
    output = json.loads(process.stdout)
    evidence.Json("capture-" + case + "-result.json", output)
    retained = {}

    try:
        from fuzzy1337.evidence import LocalEvidenceStore

        store = LocalEvidenceStore(root / "evidence")

        for role, identity in output.get("original_role_ids", {}).items():
            if identity is not None:
                record = store.Get(identity)
                retained[role] = {"evidence_id": identity, "manifest": record.ToDict(),
                    "data_hex": store.Read(record.reference).hex()}

    finally:
        evidence.Json("capture-" + case + "-originals.json", retained)

    assert process.returncode == 0 and process.stderr == b"", (
        "Actual capture failed; original process and every returned retained role remain evidence")
    assert output["state"] == "completed" and output["acquisition_outcome"] == "captured" and (
        output["custody_status"] == "complete" and output["model_persistence_status"] ==
        output["workspace_persistence_status"] == "acknowledged"), (
            "Capture must actually succeed with complete original custody and both Save ACKs")
    receipt = output["original_receipt_id"]
    original = OriginalState(root, receipt)
    frozen = FrozenOriginals()[case]
    assert original["bytes"]["owned-response-headers"] == frozen["header_section"] and (
        original["bytes"]["owned-response-wire"] == frozen["response"] and
        original["bytes"]["owned-response-body"] == frozen["body"]), (
            "Actual retained originals must equal independently frozen bytes")
    assert target.state.WaitIdle(), "Capture EOF cannot substitute for dispatch-slot settlement"
    contact = target.state.Observe()[-1]
    request = ExpectedRequest(SimpleNamespace(authority=target.graph.origin[7:]), case)
    assert original["bytes"]["owned-response-request"] == contact.request_bytes == request and (
        contact.response_bytes == frozen["response"] and
        contact.sent_bytes == len(frozen["response"])
    ), "Exact original GET and actual sent wire must agree with the independent byte oracle"

    return url, receipt


def AssertClosedTarget(evidence, expected: int) -> dict:
    """Require measured post-both-cleanup contact, send, socket and mechanism facts."""

    final = json.loads((evidence.local / "target-final.json").read_bytes())
    assert final["owner_state"] == "settled" and not any(final["listener_alive"].values()), (
        "Both original listener and handler owners must actually settle")
    main, sentinel = final["main"], final["sentinel"]
    assert main["counters"]["contacts"] == expected == len(main["contacts"]) and (
        main["counters"]["contact_overflow"] == main["counters"]["errors"] == 0 and
        main["errors"] == []), "Exact original contacts and mechanism failures must stay visible"
    assert sentinel["counters"]["contacts"] == sentinel["counters"]["contact_overflow"] == 0 and (
        sentinel["contacts"] == sentinel["errors"] == []), "The other held origin has zero accepts"

    for contact in main["contacts"]:
        assert contact["socket_closed"] and contact["failure"] is None and (
            contact["sent_bytes"] == len(bytes.fromhex(contact["response_hex"])) and
            contact["admission_state"] == "completed"), "Only complete original sends earn success"

    return final


def AssertHeaderAcknowledgements(directory: Path, label: str, result: dict,
    positive: bool) -> None:
    """Require observed real model/reference ACKs, never infer them from reopened content."""

    metrics = json.loads((directory / (label + "-offline-metrics.json")).read_bytes())
    expected = ["model", "workspace"] if positive else ["model"]
    assert [item["kind"] for item in metrics["saves"]] == expected and all(
        item["acknowledgement_returned"] for item in metrics["saves"]), (
            "One real model Save and only required reference Save must actually acknowledge")
    assert result["model_commit"] == "acknowledged" and result["workspace_commit"] == (
        "acknowledged" if positive else "not-attempted"), (
            "CLI commit classification must preserve both actual owner acknowledgements")


@pytest.mark.parametrize("case,expected", [("missing", 1), ("fixed", 0), ("body-decoy", 1)])
def test_InstalledHeaderCliScoresActualOriginalFields(
    installed_header_cli, tmp_path, header_cli_evidence, case, expected,
) -> None:
    """Acquire with capture CLI, close both origins, then assess through the real entry point."""

    evidence = header_cli_evidence

    with HeaderPipelineTarget(evidence) as target:
        root, policies = Setup(installed_header_cli, tmp_path, evidence, target)
        url, receipt = Capture(installed_header_cli, tmp_path, evidence, root,
            policies["capture"], target, case)

    final = AssertClosedTarget(evidence, 1)
    original = OriginalState(root, receipt)
    assert HeaderAbsent(original["bytes"]["owned-response-headers"]) is bool(expected), (
        "Handwritten field-name grammar must distinguish the independent1/0/1 originals")
    analysis = "analysis:installed-cli-" + case
    result = CliJson(installed_header_cli, tmp_path, evidence, "check-" + case,
        (*CheckArguments(root, receipt, url, policies["header"], analysis),
            "--approve-passive-header-check"), offline=True)
    assert result["state"] == "completed", "Required actual CLI work must complete, not skip/refuse"
    AssertHeaderAcknowledgements(tmp_path, "check-" + case, result, bool(expected))
    fact, findings = AssertInterpretation(root, original, analysis, url)
    assert len(findings) == expected and result["assessment_reference"] == fact.Reference(), (
        "Score actual saved Findings and the retained assessment, not CLI-reported counts")
    replay = CliJson(installed_header_cli, tmp_path, evidence, "replay-" + case,
        ("response", "replay-headers", str(root), "--assessment", fact.Reference()), offline=True)
    assert replay["state"] == "verified", "Actual installed historical verification must succeed"
    assert json.loads((evidence.local / "target-final.json").read_bytes()) == final and (
        target.state.Counters()["contacts"] == 1), "Offline check/replay adds zero contacts"
    evidence.Json("accuracy.json", {"completed": True, "tp": expected, "tn": 1 - expected,
        "fp": 0, "fn": 0, "truth_source": "complete-original-header-field-names"})


@pytest.mark.parametrize("denial,status", [("missing-opt-in", 3), ("raw-url", 2)])
def test_InstalledHeaderCliDeniesBeforeStoreReadsOrOriginalContacts(
    installed_header_cli, tmp_path, header_cli_evidence, denial, status,
) -> None:
    """Invalid local intent cannot touch a store, create a workspace or contact either origin."""

    evidence = header_cli_evidence
    root = tmp_path / "never-created-workspace"
    policies = Policies(tmp_path)

    with HeaderPipelineTarget(evidence) as target:
        url = target.graph.Url("/zap-passive/missing")
        args = CheckArguments(root, "sha256:" + "0" * 64,
            url + "?" if denial == "raw-url" else url, policies["header"], "analysis:denied-cli")

        if denial == "raw-url":
            args = (*args, "--approve-passive-header-check")

        result = CliJson(installed_header_cli, tmp_path, evidence, denial, args,
            offline=True, status=status)
        metrics = json.loads((tmp_path / (denial + "-offline-metrics.json")).read_bytes())
        assert metrics["store_reads"] == metrics["saves"] == [] and not root.exists(), (
            "No receipt/source/store may be read or created before the raw intent gate")
        assert result["failure"]["code"] == ("authorization" if status == 3 else
            "invalid_configuration"), "Failed intent must keep its truthful fixed classification"

    AssertClosedTarget(evidence, 0)


def test_InstalledOwnNativePipelineRetainsDistinctSourcesTriageAndRelocatedReplay(
    installed_header_cli, tmp_path, header_cli_evidence,
) -> None:
    """Join discovery, separately approved originals and offline CLI Findings in one model."""

    evidence = header_cli_evidence

    with HeaderPipelineTarget(evidence) as target:
        root, policies = Setup(installed_header_cli, tmp_path, evidence, target)
        selected = tuple(item for url in target.graph.SelectedUrls()
            for item in ("--selected", url))
        crawl = CliJson(installed_header_cli, tmp_path, evidence, "crawl",
            ("scan", "crawl", str(root), "--seed", target.graph.Url(SEED), *selected,
                "--scope", SCOPE, "--owner", OWNER, "--policy", str(policies["crawl"]),
                "--approve-safe-crawl", "--max-pages", "4", "--concurrency", "2"))
        assert crawl["state"] == "completed" and crawl["custody_status"] == "complete" and (
            set(crawl["completed_urls"]) == set(target.graph.SelectedUrls())), (
                "Actual finite owned discovery must finish before any separate capture handoff")
        assert target.state.WaitIdle(), "Original crawl dispatch owners must settle"
        assert len(target.state.Observe()) == 4 and not Findings(LocalModelStore(root).Open()), (
            "Discovery alone creates no header Findings or automatic response capture")
        captured = {case: Capture(installed_header_cli, tmp_path, evidence, root,
            policies["capture"], target, case) for case in CASES}

    final = AssertClosedTarget(evidence, 7)
    contacts = final["main"]["contacts"]
    assert contacts[0]["target"] == SEED and Counter(item["target"] for item in contacts) == {
        SEED: 1, "/zap-passive/missing": 2, "/zap-passive/fixed": 2,
        "/zap-passive/body-decoy": 2}, (
            "Seed starts discovery; separate capture adds exactly one GET per source")
    assert bytes.fromhex(contacts[0]["request_hex"]) == NativeGet(target.graph.origin, SEED), (
        "Retain and verify the original crawl GET without production request builders")

    for contact in contacts[:4]:
        assert bytes.fromhex(contact["request_hex"]) == NativeGet(target.graph.origin,
            contact["target"]), "Every actual crawl GET uses the independent fixed grammar"
    assessments = {}
    positive = []

    for case in CASES:
        url, receipt = captured[case]
        original = OriginalState(root, receipt)
        analysis = "analysis:joined-cli-" + case
        result = CliJson(installed_header_cli, tmp_path, evidence, "joined-check-" + case,
            (*CheckArguments(root, receipt, url, policies["header"], analysis),
                "--approve-passive-header-check"), offline=True)
        assert result["state"] == "completed", "No unexecuted/failed source earns a clean outcome"
        AssertHeaderAcknowledgements(tmp_path, "joined-check-" + case, result,
            HeaderAbsent(original["bytes"]["owned-response-headers"]))
        fact, findings = AssertInterpretation(root, original, analysis, url)
        assessments[case] = fact.Reference()
        positive.extend(findings)
        model = LocalModelStore(root).Open()
        structural = Endpoint(WORKSPACE, target.graph.origin, "/zap-passive/" + case).Identity()
        legacy = ObjectIdentity(WORKSPACE, ObjectKind.ENDPOINT, url)
        assert structural.Reference() != legacy.Reference() == fact.subject_reference and {
            structural, legacy} <= {item.identity for item in model.objects}, (
                "Selected structural and exact-URL identities must remain distinct")

    assert len(positive) == 2, "Actual original-header grammar must yield two native Findings"
    selected_finding = positive[0].ToObject(WORKSPACE).Reference()
    CliControl(installed_header_cli, tmp_path, evidence, "triage", {"workspace": str(root),
        "finding_reference": selected_finding})
    before_model, before_workspace = LocalModelStore(root).Open(), LocalWorkspaceStore(root).Open()
    url, receipt = captured["missing"]
    reused = CliJson(installed_header_cli, tmp_path, evidence, "reuse",
        (*CheckArguments(root, receipt, url, policies["header"], "analysis:joined-cli-missing"),
            "--approve-passive-header-check"), offline=True)
    metrics = json.loads((tmp_path / "reuse-offline-metrics.json").read_bytes())
    assert reused["state"] == "already-applied" and metrics["saves"] == [] and (
        LocalModelStore(root).Open() == before_model and
        LocalWorkspaceStore(root).Open() == before_workspace), "Reuse cannot Save or change triage"
    finding = next(item for item in Findings(before_model)
        if item.ToObject(WORKSPACE).Reference() == selected_finding)
    assert finding.status is FindingStatus.CONFIRMED, "Attributed operator triage must survive"
    originals = {case: OriginalState(root, item[1])["bytes"] for case, item in captured.items()}
    relocated = tmp_path / "relocated-workspace"
    shutil.move(str(root), relocated)
    assert not root.exists(), "Replay requires removal of the original canonical root"

    for case, assessment in assessments.items():
        replay = CliJson(installed_header_cli, tmp_path, evidence, "relocated-" + case,
            ("response", "replay-headers", str(relocated), "--assessment", assessment),
            offline=True)
        metrics_path = tmp_path / ("relocated-" + case + "-offline-metrics.json")
        metrics = json.loads(metrics_path.read_bytes())
        assert replay["state"] == "verified" and metrics["saves"] == [], (
            "Relocated historical replay verifies actual originals without persistence")
        assert OriginalState(relocated, captured[case][1])["bytes"] == originals[case], (
            "Relocation must retain every original source byte and identity")

    report_path = tmp_path / "actual-native-report.json"
    report = CliJson(installed_header_cli, tmp_path, evidence, "report",
        ("report", "export", str(relocated), "--format", "json", "--output", str(report_path)),
        offline=True)
    raw_report = report_path.read_bytes()
    evidence.Write("actual-native-report.json", raw_report)
    rendered = json.loads(raw_report)
    assert report["status"] == "completed" and report["report_sha256"] == (
        hashlib.sha256(raw_report).hexdigest()) and rendered["summary"]["findings"] == 2, (
            "Installed report export must describe the two actual persisted native Findings")
    assert LocalModelStore(relocated).Open() == before_model and (
        LocalWorkspaceStore(relocated).Open() == before_workspace and
        target.state.Counters()["contacts"] == 7 and
        json.loads((evidence.local / "target-final.json").read_bytes()) == final), (
            "Offline replay/report changes no model, originals, requests or contacts")
    evidence.Json("accuracy.json", {"completed": True, "tp": 2, "tn": 1, "fp": 0, "fn": 0,
        "truth_source": "complete-original-header-field-names", "actual_contacts": 7})
