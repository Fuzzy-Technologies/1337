# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise 1337Scope directory-index jobs against an independent filesystem-backed oracle."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event, Thread

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
from fuzzy1337.functional_metrics import (
    BuildReport,
    FunctionalRun,
    OracleCheck,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    ScenarioOracle,
    SerializeReport,
)
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import (
    NATIVE_DIRECTORY_INDEX_CAPABILITY,
    NATIVE_DIRECTORY_INDEX_CHECK_ID,
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_PROVIDER_ID,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.policy import (
    CapabilityPermission,
    ImpactPolicy,
    PolicyConfirmation,
    PolicyDenialReason,
    PolicyDeniedError,
)
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeDecisionReason,
    Target,
    TargetKind,
)
from tests.functional.test_native_web_checks import NativeRunEvidence, NativeWorkspace

PACK = Path(__file__).resolve().parents[2] / "labs/targets/directory-index"
OUTPUT = Path("functional-evidence/native-directory-index")


def DirectoryOracle():
    """Read handwritten case truth without consulting the target or production detector."""

    return json.loads((PACK / "oracle.v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def directory_target(tmp_path):
    """Own two non-secret filesystem entries and unconditional bounded loopback lifecycle."""

    root = tmp_path / "owned-directory"
    root.mkdir()
    (root / "owned-visible-note.txt").write_text("owned non-secret file contents", encoding="utf-8")
    (root / "owned-visible-subdir").mkdir()
    spec = importlib.util.spec_from_file_location(
        "owned_directory_index_target", PACK / "server.py")
    assert spec is not None and spec.loader is not None, "Owned target module is unavailable."
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.DirectoryTarget(root)
    ready = Event()

    def Serve():
        """Signal the already-bound ephemeral listener and run only its owned service loop."""

        ready.set()
        server.serve_forever(poll_interval=0.01)

    thread = Thread(target=Serve, name="owned-directory-index-target", daemon=False)

    try:
        thread.start()
        assert ready.wait(2) and thread.is_alive(), "Owned index listener did not become ready."

        yield server, f"http://127.0.0.1:{server.server_address[1]}"

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive(), "Owned directory target leaked its listener thread."


def DirectoryPolicy():
    """Permit only the explicit new STANDARD check under existing exact-plan confirmation."""

    return ImpactPolicy("owned-directory-index", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_DIRECTORY_INDEX_CAPABILITY,
            NATIVE_WEB_PROVIDER_ID, ImpactLevel.STANDARD),))


def PreserveDirectoryCase(case, root, plan, summary, observed, duration):
    """Keep actual original streams, one-cell metrics and target observations for every outcome."""

    metadata = DirectoryOracle()
    scenario = ScenarioOracle(case["id"], metadata["target_pack"], metadata["target_version"],
        metadata["provenance"], complete=True, checks=(OracleCheck(
            NATIVE_DIRECTORY_INDEX_CHECK_ID, NATIVE_DIRECTORY_INDEX_CAPABILITY,
            case["expected_match"]),))
    findings = Findings(LocalModelStore(root).Open())
    raw = NativeRunEvidence(root, plan, summary)
    run = FunctionalRun(case["id"], NATIVE_WEB_PROVIDER_ID, "development-contract-1",
        RunStatus.COMPLETED if summary.snapshot.state is JobState.COMPLETED else RunStatus.CRASHED,
        duration, detected_checks=tuple(finding.check_id for finding in findings), evidence=raw)
    report = BuildReport((scenario,), (run,))
    output = OUTPUT / case["id"]
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    (output / "report.json").write_text(SerializeReport(report), encoding="utf-8")
    (output / "matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
    (output / "matrix.html").write_text(RenderHtml(report), encoding="utf-8")
    (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(summary.ToDict(), indent=2), encoding="utf-8")
    (output / "target.json").write_text(json.dumps(observed, indent=2), encoding="utf-8")

    return report, raw


@pytest.mark.parametrize("case", DirectoryOracle()["cases"], ids=lambda case: case["id"])
def test_ActualNativeJobsDistinguishFilesystemIndexControlsAndUnassessedTransport(
    tmp_path, directory_target, case,
):
    """Execute the actual isolated worker, preserve truthful outcomes and reopen exact evidence."""

    server, baseUrl = directory_target
    root = tmp_path / "workspace"
    target = NativeWorkspace(root, baseUrl + case["route"])
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
                             check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID)
    assert server.Observe()["requests"] == [], "Read-only planning contacted the owned listener."
    assert plan.invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.native_web_worker"), (
        "Acceptance substituted a detector stub for the isolated installed worker."
    )
    started = time.monotonic()
    summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
        check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID, confirmation=PolicyConfirmation(
            plan.policy_plan.intent_sha256, "approval:owned-directory-index")))
    observed = server.Observe()
    report, raw = PreserveDirectoryCase(case, root, plan, summary, observed,
                                        time.monotonic() - started)
    assert observed["requests"] == [case["route"]], "An entry or redirect was followed or retried."
    assert not observed["errors"], "The independent target failed its owned mechanism."
    assert len(observed["directory_reads"]) == case["directory_reads"], (
        "Only the positive may actually enumerate the owned filesystem directory."
    )

    if case["directory_reads"]:
        assert observed["directory_reads"] == [
            DirectoryOracle()["configuration"]["owned_entries"]
        ], "Actual filesystem names differ from the independent fixture contract."

    expectedState = JobState.COMPLETED if case["assessed"] else JobState.FAILED
    assert summary.snapshot.state is expectedState, (
        f"The {case['id']} job must end in the terminal state specified by the owned case."
    )
    assert summary.ExitCode() == (0 if case["assessed"] else 4), "Native exit truth changed."
    findings = Findings(LocalModelStore(root).Open())
    assert len(findings) == int(case["expected_match"]), "Saved Findings differ from the oracle."

    for finding in findings:
        assert (finding.check_id, finding.severity, finding.status, finding.confidence) == (
            NATIVE_DIRECTORY_INDEX_CHECK_ID, FindingSeverity.LOW, FindingStatus.OPEN, 0.0,
        ), "An index format was upgraded into unsupported data-access or exploit certainty."

    streams = {item.role: item.content for item in raw}

    for entry in DirectoryOracle()["configuration"]["owned_entries"]:
        assert entry not in streams["stdout"] and entry not in streams["stderr"], (
            "A transient directory entry leaked into original worker streams."
        )

    assert "owned-" not in streams["stdout"] and "owned-" not in streams["stderr"], (
        "A positive, hidden, comment or failed-wire fixture name leaked into worker output."
    )

    worker = json.loads(streams["stdout"])

    if case["assessed"]:
        response = observed["responses"][0]
        assert worker["check_id"] == NATIVE_DIRECTORY_INDEX_CHECK_ID, (
            "The actual worker reported another check identity."
        )
        assert worker["matched"] is case["expected_match"], "Worker match differs from the oracle."
        assert worker["status"] == case["expected_status"], "Worker lost the actual HTTP status."
        assert (worker["body_bytes"], worker["body_sha256"]) == (
            response["body_size"], response["body_sha256"]), "Original response digest changed."
        verified = VerifyReportEvidence(ReportSnapshot(LocalModelStore(root).Open()), root)
        assert len(verified.EvidenceReferences()) == 2, "Report lost actual worker-stream custody."
        metrics = report["runs"][0]["metrics"]
        assert metrics["fp"] == metrics["fn"] == 0, "Finite target classification regressed."

    else:
        assert worker == {"schema_version": 1, "error": "protocol"}, (
            f"Original worker evidence must preserve the {case['id']} protocol refusal."
        )
        assert report["runs"][0]["run"]["status"] == "crashed", (
            "The failed cell was omitted or presented as a completed true negative."
        )

    assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
        "Original evidence did not reopen."
    )

    if case["expected_match"] or not case["assessed"]:
        relocated = tmp_path / "relocated"
        shutil.copytree(root, relocated)
        assert OpenWorkspace(relocated)["verified_evidence_records"] == 2, (
            "Relocated workspace did not verify its original worker acquisitions."
        )
        assert len(Findings(LocalModelStore(relocated).Open())) == int(case["expected_match"]), (
            "Offline relocation changed the original index Finding count."
        )
        assert server.Observe()["requests"] == [case["route"]], (
            "Offline replay contacted the target."
        )


@pytest.mark.parametrize("denial", ["wrong-capability", "revoked-consent", "wrong-owner"])
def test_NewCheckStillRequiresItsOwnCapabilityCurrentConsentAndOperator(
    tmp_path, directory_target, denial,
):
    """Refuse each authority change before any listener contact or new exposure Finding."""

    server, baseUrl = directory_target
    root = tmp_path / "workspace"
    target = NativeWorkspace(root, baseUrl + "/listing/listed/")
    owner = "operator:changed" if denial == "wrong-owner" else "operator:owned"

    if denial == "revoked-consent":
        store = LocalScopeStore(root)
        scope = store.Open("local")
        store.Save(replace(scope, authorization=replace(scope.authorization,
            state=AuthorizationState.REVOKED)))

    def SelectedPolicy():
        """Return the selected typed policy without inferring a grant for another capability."""

        if denial == "wrong-capability":
            return ImpactPolicy("wrong-native-capability", maximum_impact=ImpactLevel.STANDARD,
                permissions=(CapabilityPermission(NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                                   ImpactLevel.STANDARD),))

        return DirectoryPolicy()

    with pytest.raises(PermissionError):
        PlanNativeWebScan(root, "local", target, owner, SelectedPolicy,
                          check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID)

    assert server.Observe()["requests"] == [], "Denied directory work contacted the target."
    assert Findings(LocalModelStore(root).Open()) == (), "Denied work fabricated a Finding."


def test_DirectoryIndexRejectsExactConfirmationAtConsentExpiry(tmp_path, directory_target):
    """Recheck persisted consent before running an exactly confirmed directory index query."""

    server, baseUrl = directory_target
    root = tmp_path / "workspace"
    url = baseUrl + "/listing/listed/"
    target = NativeWorkspace(root, url)
    validUntil = LocalScopeStore(root).Open("local").authorization.valid_until
    assert validUntil is not None, "The owned consent must have a finite expiry."
    expiry = datetime.fromisoformat(validUntil)
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
        check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID, clock=lambda: expiry - timedelta(seconds=1))
    assert plan.policy_plan.confirmation_required and (
        plan.invocation.request.parameters["url"] == url
    ), "The approval must bind the exact listed directory URL."
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:expiring-index")

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
            check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID, confirmation=approval,
            clock=lambda: expiry))

    assert denied.value.scope_reason is ScopeDecisionReason.AUTHORIZATION_EXPIRED, (
        "Current consent must deny the previously approved query at its expiry."
    )
    observed = server.Observe()
    assert observed["requests"] == [] and observed["directory_reads"] == [], (
        "Expired consent must prevent both listener contact and an owned directory read."
    )
    assert Findings(LocalModelStore(root).Open()) == (), "Expired consent produced a Finding."
    assert OpenWorkspace(root)["verified_evidence_records"] == 0 and not any(
        item.is_file() for item in (root / "evidence").rglob("*")
    ), "The pre-launch denial must leave no worker evidence records or files."


def test_DirectoryIndexRejectsExactConfirmationAfterPeerExclusion(tmp_path, directory_target):
    """Recheck the literal destination after approving the exact directory URL."""

    server, baseUrl = directory_target
    root = tmp_path / "workspace"
    url = baseUrl + "/listing/listed/"
    target = NativeWorkspace(root, url)
    address = Target(TargetKind.IP, "127.0.0.1")
    store = LocalScopeStore(root)
    scope = store.Open("local")
    validUntil = scope.authorization.valid_until
    assert validUntil is not None, "The owned consent must have a finite expiry."
    now = datetime.fromisoformat(validUntil) - timedelta(seconds=1)
    assert scope.authorization.state is AuthorizationState.GRANTED and (
        scope.Check(target, at=now).Allowed() and scope.Check(address, at=now).Allowed()
    ), "The exact directory URL and literal peer must be authorized at planning time."
    plan = PlanNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
        check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID, clock=lambda: now)
    assert plan.policy_plan.confirmation_required and (
        plan.invocation.request.parameters["url"] == url
    ), "The approval must bind the exact listed directory URL."
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:excluded-index-peer")
    store.Save(replace(scope, exclusions=(address,)))
    updated = store.Open("local")
    assert updated.authorization == scope.authorization and updated.allow == scope.allow, (
        "The peer exclusion must preserve consent and the exact directory URL allow rule."
    )
    decision = updated.Check(target, at=now)
    assert decision.reason is ScopeDecisionReason.EXCLUDED and (
        decision.rule_reference == address.Reference()
    ), "The literal peer exclusion must override the registered URL's allow rule."

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", DirectoryPolicy,
            check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID, confirmation=approval, clock=lambda: now))

    assert denied.value.reason is PolicyDenialReason.SCOPE_DENIED and (
        denied.value.scope_reason is ScopeDecisionReason.EXCLUDED
    ), "The saved peer exclusion must deny the exact directory URL before launch."
    observed = server.Observe()
    assert observed["requests"] == [] and observed["directory_reads"] == [], (
        "The excluded peer must receive no request or owned directory read."
    )
    assert Findings(LocalModelStore(root).Open()) == (), "The excluded peer produced a Finding."
    assert OpenWorkspace(root)["verified_evidence_records"] == 0 and not any(
        item.is_file() for item in (root / "evidence").rglob("*")
    ), "The pre-launch denial must leave no worker evidence records or files."


def DirectoryCli(arguments):
    """Run the actual installed isolated package entrypoint with bounded process I/O."""

    return subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", *arguments, "--json"],
        stdin=subprocess.DEVNULL, capture_output=True, check=False, text=True, timeout=30)


@pytest.mark.parametrize("case_id", ["listed", "fixed"])
def test_InstalledCliPlansConfirmsExecutesAndReopensTheNewCheck(
    tmp_path, directory_target, case_id,
):
    """Exercise separate real CLI processes with no target contact before exact STD confirmation."""

    server, baseUrl = directory_target
    case = next(case for case in DirectoryOracle()["cases"] if case["id"] == case_id)
    root = tmp_path / "workspace with spaces"
    url = baseUrl + case["route"]
    NativeWorkspace(root, url)
    policyPath = tmp_path / "directory-policy.json"
    policyPath.write_text(SerializeContract(DirectoryPolicy()), encoding="utf-8")
    arguments = ["scan", "web", str(root), "--check", "directory-index", "--scope", "local",
        "--owner", "operator:owned", "--target", url, "--policy", str(policyPath)]
    planned = DirectoryCli([*arguments, "--plan"])
    assert planned.returncode == 0, "Actual installed CLI failed its new read-only selection."
    plan = json.loads(planned.stdout)
    assert plan["check_id"] == NATIVE_DIRECTORY_INDEX_CHECK_ID, (
        "Actual installed CLI planning selected a different native check."
    )
    denied = DirectoryCli(arguments)
    assert denied.returncode == 3, "Unconfirmed STANDARD directory work was allowed."
    assert server.Observe()["requests"] == [], "Planning or denial contacted the listener."
    accepted = DirectoryCli([*arguments, "--confirm-plan", plan["intent_sha256"],
        "--confirmation-reference", "approval:installed-directory-index"])
    assert accepted.returncode == 0, "Confirmed installed CLI failed its actual native check."
    assert json.loads(accepted.stdout)["state"] == "completed", "CLI lost successful job state."
    assert len(Findings(LocalModelStore(root).Open())) == int(case["expected_match"]), (
        "The installed CLI's canonical Finding differs from independent case truth."
    )
    assert server.Observe()["requests"] == [case["route"]], "CLI expanded its selected request."
    relocated = tmp_path / "cli-relocated"
    shutil.copytree(root, relocated)
    reopened = DirectoryCli(["workspace", "open", str(relocated)])
    assert reopened.returncode == 0, "Actual installed CLI could not reopen relocated evidence."
    assert json.loads(reopened.stdout)["verified_evidence_records"] == 2, (
        "Actual installed CLI reopen did not verify both original acquisitions."
    )
    assert server.Observe()["requests"] == [case["route"]], (
        "CLI reopen performed a network request."
    )
