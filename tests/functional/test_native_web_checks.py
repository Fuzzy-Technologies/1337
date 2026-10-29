# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise first-party Git checks through real governed jobs and independent owned targets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
from fuzzy1337.functional_metrics import (
    BuildReport,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    SerializeReport,
)
from fuzzy1337.jobs import JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import (
    NATIVE_WEB_CAPABILITY,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_PROVIDER_ID,
    NativeWebScanLimits,
    PlanNativeWebScan,
    RunNativeWebScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from tests.functional.native_web_metrics import NativeCheckRun, NativeScenario
from tests.web_vulnerability_helpers import Oracle, OwnedWebVulnerabilityTarget

EVIDENCE = Path("functional-evidence/native-web-checks")


def NativePolicy():
    """Allow only the explicit STANDARD first-party Git check, with exact-plan confirmation."""

    return ImpactPolicy("owned-native-web", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))


def NativeWorkspace(root, url):
    """Create one independently authorized exact URL/IP scope without inferring target expansion."""

    CreateWorkspace(root, "native-web-checks", "Owned first-party web-check acceptance")
    target = Target(TargetKind.URL, url)
    assert target.value == url, "The explicitly selected target spelling must already be canonical."
    address = Target(TargetKind.IP, "127.0.0.1")
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "native-web-checks", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-native-web",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target, address), allow=(target, address)))

    return target


def ConfirmedNativeRun(root, target, *, limits=NativeWebScanLimits()):
    """Plan and explicitly confirm only the selected first-party invocation under current scope."""

    plan = PlanNativeWebScan(root, "local", target, "operator:owned", NativePolicy, limits=limits)
    summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", NativePolicy,
        confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:owned-native"),
        limits=limits))

    return plan, summary


def NativeRunEvidence(root, plan, summary):
    """Verify original worker streams and invocation, without claiming raw HTTP body custody."""

    store = LocalEvidenceStore(root / "evidence")
    evidence = []

    for artifact in summary.snapshot.artifacts:
        record = artifact.evidence
        assert store.Get(record.evidence_id) == record, "Worker acquisition identity drifted."
        assert record.provenance.invocation_sha256 == InvocationDigest(plan.invocation), (
            "Worker evidence must bind the actual exact approved invocation."
        )
        assert record.provenance.tool_version == plan.invocation.provider_version, (
            "Worker streams must retain the actual first-party contract version."
        )
        evidence.append(RawEvidence(record.reference.role, record.reference.media_type,
                                    store.Read(record.reference).decode("utf-8")))

    evidence.append(RawEvidence("invocation", "application/json",
                                SerializeContract(plan.invocation)))

    return tuple(evidence)


def PersistNativeMatrix(scenarios, runs):
    """Keep failed/not-run cells and original native acquisition metadata visible in all reports."""

    report = BuildReport(scenarios, runs)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "report.json").write_text(SerializeReport(report), encoding="utf-8")
    (EVIDENCE / "matrix.md").write_text(RenderMarkdown(report), encoding="utf-8")
    (EVIDENCE / "matrix.html").write_text(RenderHtml(report), encoding="utf-8")

    return report


def HoldOwnedFileRead(service, monkeypatch):
    """Pause the owned target read until released, without changing scanner behavior."""

    entered = Event()
    release = Event()
    original = service.server.state.ReadHead

    def ReadHead():
        """Signal real request arrival and hold only this owned fixture's file-read mechanism."""

        entered.set()

        if not release.wait(5):
            raise OSError("Owned test did not release its paused file read")

        return original()

    monkeypatch.setattr(service.server.state, "ReadHead", ReadHead)

    return entered, release


def test_FirstPartyGitChecksMatchIndependentOracleAndDurablyReopen(tmp_path):
    """Run actual native checks, score persisted Findings, and verify original worker evidence."""

    metadata = Oracle()
    cases = [case for case in metadata["cases"] if case["family"] == "git"]
    scenarios = tuple(NativeScenario(metadata, case) for case in cases)
    runs = []
    report = PersistNativeMatrix(scenarios, runs)

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        for case in cases:
            root = tmp_path / ("workspace-" + case["id"])
            target = NativeWorkspace(root, service.Url(case))
            before = service.Observe()
            plan = PlanNativeWebScan(root, "local", target, "operator:owned", NativePolicy)
            assert service.Observe() == before, "Read-only native planning contacted the target."
            assert plan.invocation.adapter_id == NATIVE_WEB_PROVIDER_ID, (
                "Native acceptance must run the packaged first-party worker rather than Nuclei."
            )
            started = time.monotonic()
            summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned",
                NativePolicy, confirmation=PolicyConfirmation(
                    plan.policy_plan.intent_sha256, "approval:owned-" + case["id"])))
            observed = service.Observe()
            model = LocalModelStore(root).Open()
            actual_findings = Findings(model)
            detected = tuple(case["id"] if finding.check_id == NATIVE_WEB_CHECK_ID else
                             finding.check_id for finding in actual_findings)
            status = RunStatus.COMPLETED if summary.snapshot.state is JobState.COMPLETED else (
                RunStatus.TIMED_OUT if summary.snapshot.failure is not None and
                summary.snapshot.failure.code is JobFailureCode.TIMEOUT else RunStatus.CRASHED
            )
            raw = NativeRunEvidence(root, plan, summary)
            runs.append(NativeCheckRun(case["id"], plan.invocation.provider_version, status,
                time.monotonic() - started, detected_checks=detected, evidence=raw))
            report = PersistNativeMatrix(scenarios, runs)
            output = EVIDENCE / case["id"]
            output.mkdir(parents=True, exist_ok=True)
            shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
            (output / "plan.json").write_text(json.dumps(plan.ToDict(), indent=2), encoding="utf-8")
            (output / "summary.json").write_text(json.dumps(summary.ToDict(), indent=2),
                                                  encoding="utf-8")
            (output / "target-observations.json").write_text(json.dumps(observed, indent=2),
                                                             encoding="utf-8")
            assert summary.ExitCode() == 0, "Native acquisition failure must fail acceptance."
            assert observed["requests"][len(before["requests"]):] == [case["route"]], (
                "Native check changed, expanded, retried or followed its single approved GET."
            )
            assert not observed["errors"], "A target mechanism failed during native acceptance."
            reads = observed["file_reads"][len(before["file_reads"]):]
            assert [item["path"] for item in reads] == case["expected_behavior"]["file_reads"], (
                "Only the exposed positive may perform the actual owned HEAD file read."
            )
            assert len(actual_findings) == int(case["expected_match"]), (
                "Persisted native Findings disagree with independent target truth."
            )
            assert {item.role for item in raw} == {"stdout", "stderr", "invocation"}, (
                "Original native report, empty stderr and exact invocation must all survive."
            )
            worker = json.loads(next(item.content for item in raw if item.role == "stdout"))
            expected_body = case["expected_behavior"]["body"].encode("utf-8")
            assert worker["check_id"] == NATIVE_WEB_CHECK_ID and worker["matched"] is (
                case["expected_match"]), "Derived worker match must preserve its check identity."
            assert worker["status"] == case["expected_status"], "Worker lost the HTTP status."
            assert worker["body_bytes"] == len(expected_body) and worker["body_sha256"] == (
                hashlib.sha256(expected_body).hexdigest()), "Derived body attribution changed."
            stdout = next(item.content for item in raw if item.role == "stdout")
            assert "owned-fixture" not in stdout, (
                "The native report must not retain the transient branch reference or response body."
            )

            for finding in actual_findings:
                assert (finding.check_id, finding.severity, finding.status, finding.confidence) == (
                    NATIVE_WEB_CHECK_ID, FindingSeverity.LOW, FindingStatus.OPEN, 0.0,
                ), "Native exposure must not invent source recovery or operator confirmation."
                assert len(finding.provenance) == 1 and {
                    item.role for item in finding.provenance[0].evidence_references
                } == {"stdout", "stderr"}, "Finding provenance must retain actual worker streams."

            assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
                "Actual original worker acquisitions must survive workspace reopen."
            )
            verified = VerifyReportEvidence(ReportSnapshot(model), root)
            assert len(verified.EvidenceReferences()) == 2, (
                "Report verification must reuse the saved original worker evidence."
            )
            metrics = next(item["metrics"] for item in report["runs"]
                           if item["run"]["scenario_id"] == case["id"])
            assert metrics["fp"] == metrics["fn"] == metrics["unexpected_detection_count"] == 0, (
                "Native check missed the positive or invented a negative-control finding."
            )
            assert metrics["evidence_completeness"] == 1, "An assessed case lost execution proof."

    metrics = [item["metrics"] for item in report["runs"]]
    assert sum(item["tp"] for item in metrics) == 1 and sum(item["tn"] for item in metrics) == 3, (
        "The native finite matrix must score exactly one true positive and three true negatives."
    )
    assert not service.root.exists() and not service.thread.is_alive(), (
        "Native functional acceptance must remove owned files and join its target thread."
    )


def test_NativeCheckRequiresConfirmationBeforeAnyTargetContact(tmp_path):
    """A packaged first-party check grants no implicit permission to contact an owned target."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        summary = asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned",
                                              NativePolicy))
        assert summary.ExitCode() == 3, "Missing STANDARD confirmation must deny native execution."
        assert service.Observe()["requests"] == [], "Unconfirmed native work contacted the target."
        assert Findings(LocalModelStore(root).Open()) == (), "Denied work invented native Findings."
        assert summary.snapshot.artifacts == (), "Denied execution invented worker acquisitions."


def test_NativeCheckRejectsConsentRevocationAfterPlanning(tmp_path):
    """A previously shown plan cannot authorize a current revoked scope."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        plan = PlanNativeWebScan(root, "local", target, "operator:owned", NativePolicy)
        store = LocalScopeStore(root)
        scope = store.Open("local")
        store.Save(replace(scope, authorization=replace(scope.authorization,
            state=AuthorizationState.REVOKED)))

        with pytest.raises(PermissionError):
            asyncio.run(RunNativeWebScan(root, "local", target, "operator:owned", NativePolicy,
                confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256,
                                                  "approval:revoked")))

        assert service.Observe()["requests"] == [], "Revoked consent reached the native listener."
        assert Findings(LocalModelStore(root).Open()) == (), "Revoked work invented Findings."


def test_NativeWorkerIgnoresWorkspacePythonModuleShadowing(tmp_path):
    """Run the installed native worker despite an inert same-named package in the owned cwd."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        shadow = root / "fuzzy1337"
        shadow.mkdir()
        marker = root / "shadow-module-executed"
        source = (
            '"""Inert owned shadow module that records only its accidental execution."""\n'
            "from pathlib import Path\n"
            'Path(__file__).parent.parent.joinpath("shadow-module-executed").write_text(\n'
            '    "owned-shadow-was-executed", encoding="utf-8")\n'
        )
        fake_negative = json.dumps({
            "schema_version": 1, "check_id": "native.git-head-exposure", "profile_version": "1",
            "url": target.value, "address": "127.0.0.1", "port": service.server.server_port,
            "scheme": "http", "status": 200, "media_type": "other", "body_bytes": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest(), "matched": False,
        }, sort_keys=True, separators=(",", ":")) + "\n"
        (shadow / "__init__.py").write_text(source, encoding="utf-8")
        (shadow / "native_web_worker.py").write_text(
            source + "import sys\nsys.stdout.write(" + repr(fake_negative) + ")\n",
            encoding="utf-8")
        plan, summary = ConfirmedNativeRun(root, target)

        assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED, (
            "Owned workspace Python files must not replace the installed native worker."
        )
        assert not marker.exists(), "The worker imported executable input from its workspace cwd."
        observed = service.Observe()
        assert observed["requests"] == ["/git/vulnerable/.git/HEAD"], (
            "The actual installed worker must make exactly the selected owned GET."
        )
        assert observed["file_reads"] == [{
            "path": "public/.git/HEAD",
            "sha256": hashlib.sha256(b"ref: refs/heads/owned-fixture\n").hexdigest(),
        }], "The native positive must arise from the independent actual target file read."
        findings = Findings(LocalModelStore(root).Open())
        assert len(findings) == 1 and findings[0].check_id == NATIVE_WEB_CHECK_ID, (
            "A saved native Finding must come from the actual owned response, not shadow output."
        )
        raw = NativeRunEvidence(root, plan, summary)
        worker = json.loads(next(item.content for item in raw if item.role == "stdout"))
        assert worker["matched"] is True and worker["check_id"] == NATIVE_WEB_CHECK_ID, (
            "Original evidence must retain the genuine first-party worker's bounded report."
        )
        assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
            "The real worker evidence must survive reopen despite unrelated owned input files."
        )


@pytest.mark.parametrize("body,matched", [
    (b"ref: refs/heads/team/release_1\r\n", True),
    (b"ref: refs/heads/owned", True),
    (b"ref: refs/tags/owned\n", False),
    (b"ref: refs/heads/owned\nextra", False),
    (b"ref: refs/heads/owned\n\n", False),
    (b"ref: refs/heads/team//owned\n", False),
    (b"ref: refs/heads/owned.lock\n", False),
    (b"1" * 40 + b"\n", False),
])
def test_NativeCheckUsesActualChangedOwnedFileRatherThanFixtureLabels(tmp_path, body, matched):
    """Change only temporary disk bytes and compare actual saved Findings to handwritten answers."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        (service.root / "public/.git/HEAD").write_bytes(body)
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        _, summary = ConfirmedNativeRun(root, target)
        assert summary.ExitCode() == 0, "The native worker must assess the supported response."
        assert len(Findings(LocalModelStore(root).Open())) == int(matched), (
            "Native Git detection followed a fixture label instead of actual complete file bytes."
        )
        observed = service.Observe()
        assert observed["file_reads"] == [{
            "path": "public/.git/HEAD", "sha256": hashlib.sha256(body).hexdigest(),
        }], "Every semantic probe must arise from an actual independent owned file read."
        assert observed["requests"] == ["/git/vulnerable/.git/HEAD"], (
            "A body grammar probe must issue only the exact explicit target request."
        )


def test_NativeServerFailureIsIncompleteAndCreatesNoCleanVerdict(tmp_path):
    """An unavailable actual target file must not become a completed native negative assessment."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        (service.root / "public/.git/HEAD").unlink()
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        plan, summary = ConfirmedNativeRun(root, target)
        assert summary.ExitCode() != 0 and summary.snapshot.state is not JobState.COMPLETED, (
            "A 500 target mechanism failure must remain an incomplete native operation."
        )
        assert Findings(LocalModelStore(root).Open()) == (), "Failed target work invented Findings."
        assert service.Observe()["errors"] == ["owned-head-unavailable"], (
            "The separate target truth must explain the native incomplete assessment."
        )
        raw = NativeRunEvidence(root, plan, summary)
        assert {item.role for item in raw} == {"stdout", "stderr", "invocation"}, (
            "A failed native attempt must retain its truthful original terminal streams."
        )


def test_NativeRequestDeadlineRetainsTruthfulTimeoutEvidence(tmp_path, monkeypatch):
    """An actual accepted request that stalls must remain a timed-out incomplete assessment."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        entered, release = HoldOwnedFileRead(service, monkeypatch)
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))

        try:
            plan, summary = ConfirmedNativeRun(root, target,
                limits=NativeWebScanLimits(request_timeout_seconds=0.1, timeout_seconds=5))

        finally:
            release.set()

        assert entered.is_set(), "The deadline test must reach the actual owned HTTP target."
        assert summary.ExitCode() != 0 and summary.snapshot.state is JobState.FAILED, (
            "A request timeout must never become a completed clean scan."
        )
        assert summary.snapshot.failure is not None and (
            summary.snapshot.failure.code is JobFailureCode.TIMEOUT
        ), "A verified worker request deadline must retain its distinct timeout classification."
        assert Findings(LocalModelStore(root).Open()) == (), "Timed-out work invented Findings."
        raw = NativeRunEvidence(root, plan, summary)
        report = json.loads(next(item.content for item in raw if item.role == "stdout"))
        assert report == {"schema_version": 1, "error": "timeout"}, (
            "The original fixed worker timeout report must survive classification unchanged."
        )


def test_NativeCancellationWaitsForOwnedWorkerAndKeepsAttemptEvidence(tmp_path, monkeypatch):
    """Cancel after actual contact and verify terminal cleanup without a clean verdict."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        entered, release = HoldOwnedFileRead(service, monkeypatch)
        root = tmp_path / "workspace"
        target = NativeWorkspace(root, service.Url("git-exposed"))
        plan = PlanNativeWebScan(root, "local", target, "operator:owned", NativePolicy)

        async def CancelAfterContact():
            """Wait for independent target arrival before cancelling the actual workflow."""

            operation = asyncio.create_task(RunNativeWebScan(root, "local", target,
                "operator:owned", NativePolicy, confirmation=PolicyConfirmation(
                    plan.policy_plan.intent_sha256, "approval:cancel-owned")))

            try:
                assert await asyncio.to_thread(entered.wait, 3), (
                    "The cancellation probe must reach the actual owned target before cancellation."
                )
                operation.cancel()

                return await asyncio.wait_for(operation, 3)

            finally:
                if not operation.done():
                    operation.cancel()
                    await asyncio.gather(operation, return_exceptions=True)

        try:
            summary = asyncio.run(CancelAfterContact())

        finally:
            release.set()

        assert summary.ExitCode() == 130 and summary.snapshot.state is JobState.CANCELLED, (
            "Cancellation must await the owned process and retain the actual cancelled outcome."
        )
        assert Findings(LocalModelStore(root).Open()) == (), "Cancelled work invented Findings."
        assert {item.role for item in NativeRunEvidence(root, plan, summary)} == {
            "stdout", "stderr", "invocation",
        }, "An actually launched cancelled worker must retain original attempt evidence."
