# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real 1337Scope demo detection, original custody, offline reports and truthful failure paths."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import demo_assessment, report_commands
from fuzzy1337.cli import Main
from fuzzy1337.demo import DemoFailure, OwnedDemoTarget
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
from fuzzy1337.model import LocalModelStore, ObjectKind, SecurityObject
from fuzzy1337.report_commands import ReportFailure
from tests.e2e.test_operator_onboarding import installed_onboarding as installed_onboarding


def Files(root: Path) -> dict[str, bytes]:
    """Capture the finite acquired demo tree to prove refusal and inspection preserve its bytes."""

    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def Run(root: Path) -> tuple[int, dict]:
    """Execute the actual SDK composition and return its sole original JSON outcome."""

    output = StringIO()
    status = demo_assessment.RunAssessmentDemo(
        root, output, approve_standard_http=True, json_output=True,
    )

    return status, json.loads(output.getvalue())


def Read(root: Path, name: str) -> dict:
    """Load one original owned command or derived report without synthesizing another result."""

    return json.loads((root / name).read_bytes())


def AssertStopped(root: Path, expected_requests: int) -> None:
    """Verify actual receipt, finite request count and refusal by the original closed listener."""

    target = Read(root, "target.json")
    assert target["bind_host"] == "127.0.0.1" and target["teardown_completed"] is True, (
        "A retained successful teardown receipt must identify the actual owned loopback fixture"
    )
    assert len(target["requests"]) == expected_requests, (
        "The closed fixture must retain exactly the requests the product actually completed"
    )

    if target["port"] is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.2)
            assert connection.connect_ex(("127.0.0.1", target["port"])) != 0, (
                "The original listening port must refuse connections after target teardown"
            )


def AssertSuccess(root: Path, outcome: dict) -> None:
    """Join real jobs, exact original acquisitions, canonical Finding and all offline exports."""

    assert outcome["state"] == "completed" and outcome["exit_status"] == 0, (
        "Demo success requires both actual native checks, source verification, exports and cleanup"
    )
    assert outcome["target_teardown_completed"] is True, (
        "Success must retain confirmed owned target teardown"
    )
    AssertStopped(root, 2)
    target = Read(root, "target.json")
    assert target["requests"] == [
        {"method": "GET", "path": "/.git/HEAD", "status": 200},
        {"method": "GET", "path": "/fixed/.git/HEAD", "status": 404},
    ], "The fixture must receive precisely the separately confirmed exposed and control requests"
    exposedPlan = Read(root, "exposed-plan.json")
    fixedPlan = Read(root, "fixed-plan.json")
    assert exposedPlan["policy_plan"]["intent_sha256"] != (
        fixedPlan["policy_plan"]["intent_sha256"]
    ), "Different endpoints must receive independent actual invocation confirmation identities"
    assert exposedPlan["impact"] == fixedPlan["impact"] == "STANDARD", (
        "The real predicate must preserve ordinary STANDARD policy classification"
    )
    exposed = Read(root, "exposed-scan.json")
    fixed = Read(root, "fixed-scan.json")
    assert exposed["state"] == fixed["state"] == "completed", (
        "Both actual product invocations must complete without substituting a plan for execution"
    )
    assert exposed["job"]["spec"]["job_id"] != fixed["job"]["spec"]["job_id"], (
        "Each check must retain its own actual governed job"
    )
    urls = [f"http://127.0.0.1:{target['port']}/.git/HEAD",
            f"http://127.0.0.1:{target['port']}/fixed/.git/HEAD"]
    workspace = root / "workspace"
    model = LocalModelStore(workspace).Open()
    finding, = Findings(model)
    assert finding.location_key == urls[0] and finding.check_id == "native.git-head-exposure", (
        "The sole Finding must identify the actual exposed endpoint and first-party predicate"
    )
    assert finding.severity is FindingSeverity.LOW and finding.status is FindingStatus.OPEN, (
        "A different fixed endpoint must not resolve or reclassify the original LOW Finding"
    )
    assert len(model.Objects(ObjectKind.ENDPOINT)) == 2 and model.revision == 2, (
        "The actual jobs must persist only the two selected endpoints and original Finding"
    )
    normalized = demo_assessment.ReadAssessmentFinding(workspace, urls[0], exposed)
    assert outcome["assessment"]["finding"] == normalized, (
        "The final derived outcome must bind the independently reopened original Finding"
    )
    assert outcome["assessment"]["resolution"] == "not-assessed", (
        "The negative control cannot become an invented remediation verdict"
    )
    for label, scan, url, matched in (("exposed", exposed, urls[0], True),
                                     ("fixed", fixed, urls[1], False)):
        _, references, _ = demo_assessment.ReadAssessmentExecution(
            workspace, url, scan, matched=matched,
        )
        assert {item.role for item in references} == {"stdout", "stderr"}, (
            "Each original governed job must retain its own exact stdout and stderr acquisitions"
        )
        plan = Read(root, label + "-plan.json")
        assert all(item["evidence"]["provenance"]["invocation_sha256"] == (
            plan["policy_plan"]["invocation_sha256"]
        ) for item in scan["job"]["artifacts"]), (
            "Actual original acquisition metadata must bind the separately confirmed invocation"
        )

    report = Read(root, "reports/model.json")
    assert report["model"] == model.ToDict() and len(report["findings"]) == 1, (
        "JSON must project the exact independently reopened saved model"
    )
    assert report["findings"][0] == {key: normalized[key] for key in ("reference", "normalized")}, (
        "The readable report must retain the same actual original detector Finding"
    )
    sarif = Read(root, "reports/model.sarif")
    assert len(sarif["runs"][0]["results"]) == 1, (
        "SARIF must include the actual detection rather than an empty discovery-only result"
    )

    class Text(HTMLParser):
        """Read real rendered report text without counting scripts or hidden technical markup."""

        def __init__(self) -> None:
            """Initialize a separate parser over the actual published self-contained report."""

            super().__init__()
            self.parts = []

        def handle_data(self, data: str) -> None:
            """Collect original parser-delivered text from the actual HTML artifact."""

            self.parts.append(data)

    parser = Text()
    parser.feed((root / "reports/model.html").read_text(encoding="utf-8"))
    rendered = " ".join(parser.parts)
    assert "native.git-head-exposure" in rendered and "LOW" in rendered, (
        "The human-readable HTML must expose the real first-party Finding and original severity"
    )
    receipts = [Read(root, "reports/" + name + "-export.json")
                for name in ("json", "html", "sarif")]
    assert all(receipt["output_published"] is True for receipt in receipts), (
        "Every actual exporter must acknowledge publication independently"
    )
    assert len({receipt["snapshot_sha256"] for receipt in receipts}) == 1, (
        "All three exports must bind one unchanged saved-model snapshot"
    )
    index = Read(root, "evidence-index.json")
    assert index["verified_acquisitions"] == len(index["records"]) == 4, (
        "Two native checks must retain their four actual registered acquisitions"
    )

    for entry in index["records"]:
        reference = entry["record"]["reference"]
        payload = (root / entry["material_path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == reference["sha256"], (
            "The derived evidence navigation must match independently read original material"
        )
        assert b"ref: refs/heads/main\n" not in payload, (
            "Native evidence retains original worker metadata and body hashes, not HTTP bodies"
        )


@pytest.fixture(scope="module")
def completed_assessment(tmp_path_factory):
    """Acquire one real immutable assessment result for independent read-only negative checks."""

    root = tmp_path_factory.mktemp("assessment-original") / "demo"
    status, outcome = Run(root)
    assert status == 0, "The actual native assessment fixture must complete before read-only cases"

    return root, outcome


def test_ActualAssessmentJoinsNativeFindingOriginalEvidenceAndOfflineHtml(completed_assessment):
    """The real assembled composition satisfies every actual detection and retention invariant."""

    root, outcome = completed_assessment
    AssertSuccess(root, outcome)


def test_ExistingAssessmentRootRefusesWithoutChangingAnyRetainedBytes(completed_assessment):
    """An ordinary repeated approved invocation cannot overwrite evidence or prior reports."""

    root, _ = completed_assessment
    before = Files(root)
    status, outcome = Run(root)
    assert status == 2 and outcome["phase"] == "configuration", (
        "A repeated approved run must refuse its existing root before starting another fixture"
    )
    assert Files(root) == before, "No-clobber refusal must preserve every acquired prior byte"


def test_TargetIsStoppedBeforeOfflineReopenAndEveryExport(tmp_path, monkeypatch):
    """The real reopen and exporters succeed only after the original listener was closed."""

    invoke = demo_assessment.RunCommands
    export = demo_assessment.RunReportCommands
    observed = []
    root = tmp_path / "offline"

    def Product(namespace, arguments, output, *, json_output):
        """Inspect the original fixture before allowing the real saved workspace reopen."""

        if namespace == "workspace" and arguments[0] == "open":
            AssertStopped(root, 2)
            observed.append("reopen")

        return invoke(namespace, arguments, output, json_output=json_output)

    def Export(arguments, output, *, json_output):
        """Inspect the original fixture before allowing each ordinary real report export."""

        AssertStopped(root, 2)
        observed.append(arguments[arguments.index("--format") + 1])

        return export(arguments, output, json_output=json_output)

    monkeypatch.setattr(demo_assessment, "RunCommands", Product)
    monkeypatch.setattr(demo_assessment, "RunReportCommands", Export)
    status, outcome = Run(root)
    assert status == 0, "The actual offline composition must complete with its target already gone"
    assert observed == ["reopen", "json", "html", "sarif"], (
        "Fixture shutdown must precede the one actual reopen and all three separate exporters"
    )
    AssertSuccess(root, outcome)


def test_ActualExpiredConsentPreventsAnyTargetRequestAndRetainsDenial(tmp_path, monkeypatch):
    """Ordinary scope consent remains independently enforced under the demo's explicit opt-in."""

    invoke = demo_assessment.RunCommands

    def Expire(namespace, arguments, output, *, json_output):
        """Register actually expired consent through the ordinary scope product interface."""

        if namespace == "scope":
            arguments = list(arguments)
            now = datetime.now(UTC)
            arguments[arguments.index("--valid-from") + 1] = (
                now - timedelta(seconds=10)).isoformat()
            arguments[arguments.index("--valid-until") + 1] = (
                now - timedelta(seconds=5)).isoformat()

        return invoke(namespace, arguments, output, json_output=json_output)

    monkeypatch.setattr(demo_assessment, "RunCommands", Expire)
    root = tmp_path / "expired"
    status, outcome = Run(root)
    assert status == 3 and outcome["state"] == "denied", (
        "Demo opt-in cannot bypass the ordinary current-consent denial"
    )
    assert outcome["phase"] == "exposed-plan", "The unapproved plan must stop before execution"
    AssertStopped(root, 0)
    assert not LocalModelStore(root / "workspace").Open().objects, (
        "Denied current consent must create no model objects or fabricated Findings"
    )
    assert not list((root / "reports").iterdir()), "Denied work must publish no successful reports"


def test_ExposedConfirmationCannotBeReusedForTheDifferentFixedEndpoint(tmp_path, monkeypatch):
    """The ordinary policy owner denies a changed target despite the closed demo opt-in."""

    invoke = demo_assessment.RunCommands
    exposed_intent = None

    def Reuse(namespace, arguments, output, *, json_output):
        """Substitute the first real confirmation only at the second actual execution boundary."""

        nonlocal exposed_intent

        if namespace == "scan" and "--confirm-plan" in arguments:
            arguments = list(arguments)
            position = arguments.index("--confirm-plan") + 1

            if exposed_intent is None:
                exposed_intent = arguments[position]

            else:
                arguments[position] = exposed_intent

        return invoke(namespace, arguments, output, json_output=json_output)

    monkeypatch.setattr(demo_assessment, "RunCommands", Reuse)
    root = tmp_path / "changed-intent"
    status, outcome = Run(root)
    assert status == 3 and outcome["phase"] == "fixed-scan", (
        "A different selected endpoint must reject the first endpoint's confirmation"
    )
    AssertStopped(root, 1)
    assert len(Findings(LocalModelStore(root / "workspace").Open())) == 1, (
        "Second-invocation denial must preserve the actual first detected Finding"
    )
    assert not list((root / "reports").iterdir()), (
        "A denied second check cannot become demo success"
    )


def test_InterruptAfterFirstActualDetectionPreservesOriginalFindingAndCleanup(
    tmp_path, monkeypatch,
) -> None:
    """A real first acquisition survives interruption before the second endpoint is planned."""

    invoke = demo_assessment.RunCommands

    def Interrupt(namespace, arguments, output, *, json_output):
        """Interrupt before the fixed endpoint while retaining completed original product work."""

        if namespace == "scan" and "/fixed/" in arguments[arguments.index("--target") + 1]:
            raise KeyboardInterrupt

        return invoke(namespace, arguments, output, json_output=json_output)

    monkeypatch.setattr(demo_assessment, "RunCommands", Interrupt)
    root = tmp_path / "interrupted"
    status, outcome = Run(root)
    assert status == 130 and outcome["state"] == "cancelled", (
        "Interruption must remain nonzero rather than becoming a partial-success demo"
    )
    AssertStopped(root, 1)
    finding, = Findings(LocalModelStore(root / "workspace").Open())
    assert finding.status is FindingStatus.OPEN, (
        "Interruption must retain the original open Finding"
    )
    assert not list((root / "reports").iterdir()), (
        "Interrupted checks cannot publish success reports"
    )


def test_PostPublicationHtmlFailureRetainsActualReportAndNonzeroOutcome(tmp_path, monkeypatch):
    """A complete actual HTML file with failed publication acknowledgement cannot mean success."""

    publish = report_commands.PublishReport

    def PublishThenFail(path, payload):
        """Publish actual bytes before reporting the owner's original lost acknowledgement."""

        result = publish(path, payload)

        if path.name == "model.html":
            raise ReportFailure("publication", 4, published=True)

        return result

    monkeypatch.setattr(report_commands, "PublishReport", PublishThenFail)
    root = tmp_path / "html-publication"
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "export", (
        "A failed HTML publication acknowledgement must prevent entire-demo success"
    )
    AssertStopped(root, 2)
    assert "reports/model.html" in outcome["artifacts"] and (
        root / "reports/model.html").is_file(), (
            "The published report must remain accessible after acknowledgement failure"
        )
    receipt = Read(root, "reports/html-export.json")
    assert receipt["output_published"] is True and receipt["status"] == "failed", (
        "The actual export receipt must retain both publication and failure truth"
    )
    assert not (root / "reports/model.sarif").exists(), (
        "A failed second exporter must stop before the third format"
    )


def test_LateCleanupFailurePreventsExportsAndCannotBecomeSuccess(tmp_path, monkeypatch):
    """An owned cleanup error remains failure even after both native checks really completed."""

    close = OwnedDemoTarget.Close

    def CloseThenFail(self):
        """Reap the actual service before reporting a cleanup acknowledgement failure."""

        close(self)

        raise OSError("owned teardown acknowledgement failed")

    monkeypatch.setattr(OwnedDemoTarget, "Close", CloseThenFail)
    root = tmp_path / "cleanup"
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "teardown", (
        "A cleanup failure after successful scans must remain nonzero teardown failure"
    )
    assert outcome["target_teardown_completed"] is False, (
        "Failed cleanup acknowledgement must not claim confirmed demo teardown"
    )
    assert not list((root / "reports").iterdir()), (
        "Mandatory teardown failure must prevent later offline export publication"
    )
    assert len(Findings(LocalModelStore(root / "workspace").Open())) == 1, (
        "Teardown failure must not remove completed actual detector work"
    )


def test_StartupFailureAfterRealBindStillClosesTheOwnedFixture(tmp_path, monkeypatch):
    """A started listener remains owned even if startup acknowledgement fails before scanning."""

    start = OwnedDemoTarget.Start

    def StartThenFail(self):
        """Bind the real local fixture before injecting one deterministic startup failure."""

        start(self)

        raise OSError("owned startup acknowledgement failed")

    monkeypatch.setattr(OwnedDemoTarget, "Start", StartThenFail)
    root = tmp_path / "startup"
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "target", (
        "A failed acknowledgement after real bind must remain startup failure"
    )
    AssertStopped(root, 0)
    assert not (root / "workspace").exists(), (
        "Failed fixture startup must prevent workspace creation and every scan"
    )


def test_ChangedOriginalWorkerBytesCannotProduceSuccessfulAssessment(tmp_path, monkeypatch):
    """Real persisted original-byte corruption is refused before the control or report stage."""

    invoke = demo_assessment.RunCommands

    def Corrupt(namespace, arguments, output, *, json_output):
        """Change one actually registered original stdout only after the real worker completed."""

        status = invoke(namespace, arguments, output, json_output=json_output)

        if namespace == "scan" and "--confirm-plan" in arguments:
            receipt = json.loads(output.getvalue())
            record = next(item["evidence"] for item in receipt["job"]["artifacts"]
                          if item["evidence"]["reference"]["role"] == "stdout")
            material = Path(arguments[1]) / "evidence" / record["reference"]["locator"]
            material.write_bytes(b"changed original worker metadata")

        return status

    monkeypatch.setattr(demo_assessment, "RunCommands", Corrupt)
    root = tmp_path / "corrupted"
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "assessment", (
        "Original-byte corruption must fail the actual owner-read integrity barrier"
    )
    AssertStopped(root, 1)
    assert not (root / "fixed-plan.json").exists() and not list((root / "reports").iterdir()), (
        "Invalid original evidence must stop before another check or derived successful report"
    )


def test_ExistingForeignHtmlRefusesOverwriteAfterActualChecks(tmp_path, monkeypatch):
    """A competing derived output remains intact even after two valid actual native checks."""

    export = demo_assessment.RunReportCommands

    def Compete(arguments, output, *, json_output):
        """Place another writer's file immediately before the ordinary HTML no-clobber check."""

        if arguments[arguments.index("--format") + 1] == "html":
            Path(arguments[arguments.index("--output") + 1]).write_bytes(b"foreign HTML bytes")

        return export(arguments, output, json_output=json_output)

    monkeypatch.setattr(demo_assessment, "RunReportCommands", Compete)
    root = tmp_path / "foreign-html"
    status, outcome = Run(root)
    assert status == 2 and outcome["phase"] == "export", (
        "The real exporter must preserve no-clobber configuration failure"
    )
    AssertStopped(root, 2)
    assert (root / "reports/model.html").read_bytes() == b"foreign HTML bytes", (
        "A competing report output must remain byte-identical"
    )
    assert "reports/model.html" not in outcome["artifacts"], (
        "Foreign HTML must not be attributed as a demo-published report"
    )


def test_SummaryPublicationAcknowledgementFailurePreservesTerminalFailure(tmp_path, monkeypatch):
    """Retain the published summary while exposing actual lost acknowledgement to the caller."""

    save = demo_assessment.SaveDemoArtifact

    def SaveThenFail(root, name, document, artifacts):
        """Publish the original final summary before injecting its owner acknowledgement failure."""

        save(root, name, document, artifacts)

        if name == "demo-summary.json":
            raise ReportFailure("publication", 4, published=True)

    monkeypatch.setattr(demo_assessment, "SaveDemoArtifact", SaveThenFail)
    root = tmp_path / "summary"
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "summary", (
        "A lost summary acknowledgement cannot become whole-invocation success"
    )
    assert outcome["summary_output_published"] is True, (
        "The terminal outcome must distinguish actual publication from failed acknowledgement"
    )
    assert Read(root, "demo-summary.json")["state"] == "completed", (
        "Published original summary bytes must not be rewritten to hide acknowledgement loss"
    )
    AssertStopped(root, 2)


def test_RealConcurrentModelCommitBetweenExportsRefusesMixedSnapshotSuccess(tmp_path, monkeypatch):
    """A real model-owner update cannot produce a successful bundle of different report states."""

    export = demo_assessment.RunReportCommands
    root = tmp_path / "changed-model"

    def CommitAfterJson(arguments, output, *, json_output):
        """Publish the actual first report then commit an unrelated endpoint annotation normally."""

        status = export(arguments, output, json_output=json_output)

        if arguments[arguments.index("--format") + 1] == "json" and status == 0:
            store = LocalModelStore(root / "workspace")
            state = store.Open()
            endpoint = state.Objects(ObjectKind.ENDPOINT)[0]
            attributes = {**dict(endpoint.attributes), "concurrent_demo_note": "changed"}
            changed = SecurityObject(endpoint.identity, attributes, endpoint.provenance)
            proposed, _ = state.Apply(objects=(changed,))
            store.Save(proposed, expected_revision=state.revision)

        return status

    monkeypatch.setattr(demo_assessment, "RunReportCommands", CommitAfterJson)
    status, outcome = Run(root)
    assert status == 4 and outcome["phase"] == "export", (
        "A successful first exporter cannot hide later real saved-model drift"
    )
    assert outcome["failure"] == "input-changed", (
        "The composition must expose the report owner's exact stale-input refusal"
    )
    AssertStopped(root, 2)
    original = Read(root, "reports/model.json")
    assert original["model_revision"] == 2 and (
        LocalModelStore(root / "workspace").Open().revision == 3), (
            "The retained original report and concurrent saved update must remain distinct"
        )
    assert "reports/model.json" in outcome["artifacts"] and not (
        root / "reports/model.html").exists(), (
            "The first original artifact must remain while a mixed-snapshot continuation is refused"
        )


@pytest.mark.parametrize("path,value", [
    (("state",), "failed"),
    (("check_id",), "native.other"),
    (("job", "state"), "running"),
    (("job", "spec"), None),
    (("job", "spec", "provider_id"), "other-provider"),
    (("job", "spec", "workspace_id"), "other-workspace"),
    (("job", "spec", "owner_reference"), "operator:other"),
    (("job", "spec", "scope_reference"), "scope:other"),
    (("job", "spec", "job_id"), None),
    (("job", "artifacts"), []),
    (("job", "artifacts", 0), None),
    (("job", "artifacts", 0, "job_id"), "job:other"),
    (("job", "artifacts", 0, "workspace_id"), "other-workspace"),
    (("job", "artifacts", 0, "evidence"), None),
    (("job", "artifacts", 0, "evidence", "evidence_id"), None),
    (("job", "artifacts", 0, "evidence", "evidence_id"), "sha256:" + "a" * 64),
    (("job", "artifacts", 0, "evidence", "provenance", "source_version"), "other"),
])
def test_OriginalJobAndCustodyJoinsRejectChangedCommandReceipts(
    completed_assessment, path, value,
) -> None:
    """A changed derived receipt cannot substitute another job, source, scope or acquisition."""

    root, _ = completed_assessment
    scan = copy.deepcopy(Read(root, "exposed-scan.json"))
    parent = scan

    for key in path[:-1]:
        parent = parent[key]

    parent[path[-1]] = value
    target = Read(root, "target.json")
    url = f"http://127.0.0.1:{target['port']}/.git/HEAD"
    before = Files(root)

    with pytest.raises(DemoFailure):
        demo_assessment.ReadAssessmentExecution(root / "workspace", url, scan, matched=True)

    assert Files(root) == before, "Rejected derived metadata must not rewrite any original material"


@pytest.mark.parametrize("mutation", ["location", "subject", "severity", "status", "run",
                                      "provider", "scope", "target", "version", "evidence"])
def test_RightCountAndCheckCannotHideWrongFindingAttribution(
    completed_assessment, monkeypatch, mutation,
) -> None:
    """The composition rejects a wrong detector projection despite a real successful source job."""

    root, _ = completed_assessment
    model = LocalModelStore(root / "workspace").Open()
    finding, = Findings(model)
    provenance = finding.provenance[0]

    if mutation == "location":
        finding = replace(finding, location_key=finding.location_key.replace(
            "/.git", "/other/.git"))

    elif mutation == "subject":
        finding = replace(finding, subject_reference=next(
            item.Reference() for item in model.Objects(ObjectKind.ENDPOINT)
            if item.Reference() != finding.subject_reference))

    elif mutation == "severity":
        finding = replace(finding, severity=FindingSeverity.HIGH)

    elif mutation == "status":
        finding = replace(finding, status=FindingStatus.RESOLVED, status_reason="test:other")

    else:
        changed = {"run": {"run_reference": "job:other"},
                   "provider": {"source_id": "other-provider"},
                   "scope": {"scope_reference": "scope:other"},
                   "target": {"target_reference": "target:other"},
                   "version": {"provider_version": "2"},
                   "evidence": {"evidence_references": ()}}[mutation]
        finding = replace(finding, provenance=(replace(provenance, **changed),))

    def ChangedProjection(state):
        """Return one deliberately altered immutable interpretation over the real saved source."""

        return (finding,)

    monkeypatch.setattr(demo_assessment, "Findings", ChangedProjection)
    url = f"http://127.0.0.1:{Read(root, 'target.json')['port']}/.git/HEAD"

    with pytest.raises(DemoFailure):
        demo_assessment.ReadAssessmentFinding(
            root / "workspace", url, Read(root, "exposed-scan.json"),
        )


@pytest.mark.integration
def test_CleanInstalledAssessmentCliRefusesThenDetectsAndReopensOffline(
    installed_onboarding, tmp_path,
) -> None:
    """The clean wheel exposes real planning, native detection, offline reports and refusal."""

    root = tmp_path / "installed-assessment"

    def Console(arguments, expected):
        """Invoke only the clean installed entry point with finite capture and actual statuses."""

        result = subprocess.run(
            [str(installed_onboarding), "-I", "-m", "fuzzy1337", *arguments],
            cwd=tmp_path, capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == expected and not result.stderr, (
            result.returncode, result.stdout, result.stderr,
        )

        return json.loads(result.stdout)

    plan = Console(["demo", "assessment", str(root), "--json"], 3)
    assert plan["state"] == "denied" and not root.exists(), (
        "The installed unapproved plan must start no fixture and acquire no root"
    )
    invalid = Console(["demo", "assessment", str(root), "--approve-safe-http", "--json"], 2)
    assert invalid["phase"] == "configuration" and not root.exists(), (
        "The installed CLI cannot convert existing SAFE opt-in into STANDARD approval"
    )
    outcome = Console(["demo", "assessment", str(root), "--approve-standard-http", "--json"], 0)
    AssertSuccess(root, outcome)
    before = Files(root)
    reopened = Console(["workspace", "open", str(root / "workspace"), "--json"], 0)
    assert reopened["model_revision"] == 2, "Installed offline reopen must retain both real jobs"
    refused = Console(["demo", "assessment", str(root), "--approve-standard-http", "--json"], 2)
    assert refused["phase"] == "configuration" and Files(root) == before, (
        "Installed repeated approval must preserve all acquired material after no-clobber refusal"
    )

    reviewDirectory = tmp_path / "review"
    reviewDirectory.mkdir()
    relocated = root.rename(reviewDirectory / root.name)
    assert not root.exists(), "Offline review must succeed with the original path absent"
    moved = Console(["workspace", "open", str(relocated / "workspace"), "--json"], 0)
    assert moved == reopened, "Moving the bundle must preserve the verified workspace outcome"

    html = relocated / "reports" / "relocated-model.html"
    export = Console(["report", "export", str(relocated / "workspace"), "--format", "html",
                      "--output", str(html), "--json"], 0)
    original = Read(relocated, "reports/html-export.json")
    assert export == original and export["verified_retained_acquisitions"] == 4, (
        "The relocated export must verify the same four acquisitions and pin the same snapshot"
    )
    assert html.read_bytes() == before[str(Path("reports") / "model.html")], (
        "Offline HTML must render the same retained Finding byte-for-byte at the new location"
    )
    assert Files(relocated) == {**before, str(html.relative_to(relocated)): html.read_bytes()}, (
        "Offline review must preserve the original bundle and publish only the requested new file"
    )


def test_RootCliHumanAssessmentNamesActualFindingAndHtml(tmp_path, capsys):
    """Human root routing exposes the new actual assessment without changing machine commands."""

    root = tmp_path / "human"
    assert Main(["demo", "assessment", str(root)]) == 3, (
        "The human product command must require explicit independent STANDARD approval"
    )
    assert "1337Scope" in capsys.readouterr().out, (
        "The new human plan should identify the built-in scanner by its accepted product name"
    )
    assert Main(["demo", "assessment", str(root), "--approve-standard-http"]) == 0, (
        "The explicitly approved human root command must run the real closed assessment"
    )
    presented = capsys.readouterr().out
    assert "open LOW Finding" in presented and "reports/model.html" in presented, (
        "Human output must identify the actual result and the readable offline report"
    )
