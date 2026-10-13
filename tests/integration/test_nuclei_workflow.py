# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual owned synthetic execution connects Nuclei workflow to canonical durable findings."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from fuzzy1337 import nucleiscan
from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters.nuclei import NucleiProfile, NucleiTemplate
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind
from fuzzy1337.nucleiscan import (
    NucleiScanLimits,
    NucleiUnavailableError,
    PlanNucleiScan,
    ReadNucleiProfile,
    RunNucleiScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation, PolicyEngine
from fuzzy1337.report_formats import RenderHtml, SerializeJson
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace, RunCommands
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Owned producer uses a POSIX shebang")
FIXTURES = Path(__file__).parents[1] / "fixtures/nuclei"


def Policy() -> ImpactPolicy:
    """Permit only reviewed STANDARD checks; exact operation confirmation remains mandatory."""

    return ImpactPolicy("owned-nuclei", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission("web.http-template-check", "native.nuclei",
                                          ImpactLevel.STANDARD),))


def Setup(root: Path, target: Target | None = None) -> tuple[Target, NucleiProfile, str]:
    """Create explicit owned scope and immutable synthetic material, without target contact."""

    CreateWorkspace(root, "nuclei-demo", "Owned synthetic Nuclei workflow")
    target = target or Target(TargetKind.URL, "http://127.0.0.1:8080/")
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "nuclei-demo", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:pytest-owned",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target, Target(TargetKind.IP, "127.0.0.1")),
        allow=(target, Target(TargetKind.IP, "127.0.0.1"))))
    raw = (FIXTURES / "reviewed-get.yaml").read_bytes()
    template_path = root / "reviewed-get.yaml"
    template_path.write_bytes(raw)
    configuration_path = root / "nuclei-empty.yaml"
    configuration_path.write_bytes(b"{}\n")
    profile = NucleiProfile("owned-synthetic", (NucleiTemplate(
        "owned-http-marker", str(template_path), hashlib.sha256(raw).hexdigest(), len(raw),
        "fixture:reviewed-get", "1", "review:source-controlled-exact-get",
        "single-get-exact-url",
    ),), str(configuration_path))
    executable = root / "owned-nuclei-producer"
    executable.write_text(f"#!{sys.executable}\n"
                          + (FIXTURES / "workflow_nuclei.py").read_text(encoding="utf-8"),
                          encoding="utf-8")
    executable.chmod(0o700)

    return target, profile, str(executable)


def Confirm(root: Path, target: Target, profile: NucleiProfile, executable: str,
            *, limits: NucleiScanLimits = NucleiScanLimits()) -> PolicyConfirmation:
    """Supply a test-owned explicit approval of the exact shown synthetic operation."""

    plan = PlanNucleiScan(root, "local", target, "operator:owned", profile, executable,
                         Policy, limits=limits)
    assert not (root / "nuclei-launched").exists(), "Planning must never start target execution."
    assert plan.ToDict()["confirmation_required"] is True, "STANDARD requires exact confirmation."

    return PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:pytest-exact-plan")


def test_OwnedProducerFindingsRepeatTriageReopenAndReport(tmp_path: Path) -> None:
    """Actual synthetic stdout persists as canonical findings and independently verified reports."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    metadata = root / "profile.json"
    metadata.write_text(SerializeContract(profile), encoding="utf-8")
    assert ReadNucleiProfile(metadata) == profile, "Existing profile metadata must round trip."
    confirmation = Confirm(root, target, profile, executable)
    events = []
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=confirmation,
                                       on_event=events.append))
    assert summary.ExitCode() == 0, "The explicitly approved owned-format operation must complete."
    assert events == list(summary.events), "Presentation must follow exact contiguous owned events."
    assert len(summary.snapshot.artifacts) == 2, "Both actual terminal streams must be acquired."
    assert summary.object_counts, "Machine counts must describe authoritative saved model state."
    assert "no network activity" not in json.dumps(summary.ToDict()), (
        "Raw streams stay in evidence."
    )
    assert summary.model_revision == 1, "Composite ingestion must use one canonical CAS transition."
    store = LocalModelStore(root)
    state = store.Open()
    finding = Findings(state)[0]
    assert finding.severity.value == "informational", "Provider info maps to the canonical enum."
    assert finding.confidence == 0.0, "A template match does not invent vulnerability confidence."
    assert finding.status is FindingStatus.OPEN, "Detector ingestion cannot fabricate triage."
    assert len(state.Objects(ObjectKind.ENDPOINT)) == 1, (
        "The exact subject is one canonical endpoint."
    )
    provenance = ModelProvenance(
        "operator.triage", "decision:pytest-owned", datetime.now(UTC).isoformat(),
        "scope:local", target.Reference(),
        evidence_references=finding.provenance[0].evidence_references,
    )
    triaged, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
                                  FindingStatus.DISMISSED, provenance, "Synthetic marker")
    store.Save(triaged, expected_revision=state.revision)
    repeated = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                        executable, Policy, confirmation=confirmation))
    assert repeated.ExitCode() == 0, "Unchanged exact-plan scope/policy permits recollection."
    reopened = store.Open()
    current = Findings(reopened)
    assert len(current) == 1, "Recollection must retain canonical finding identity."
    assert current[0].Fingerprint() == finding.Fingerprint(), (
        "Mutable triage does not change identity."
    )
    assert current[0].status is FindingStatus.DISMISSED, (
        "Recollection must preserve operator triage."
    )
    assert len(current[0].provenance) == 3, "Both acquisitions and triage retain actual provenance."
    workspace = OpenWorkspace(root)
    assert workspace["verified_evidence_records"] == 4, "Each run retains two actual acquisitions."
    report = VerifyReportEvidence(ReportSnapshot(reopened), root)
    assert len(report.EvidenceReferences()) == 2, "Identical raw streams may share immutable bytes."
    assert b"nuclei.owned-http-marker" in SerializeJson(report), (
        "Reports consume canonical Findings."
    )
    assert b"Owned synthetic HTTP marker" in RenderHtml(report), "HTML renders the shared finding."
    assert LocalWorkspaceStore(root).Open().job_references, (
        "Durable metadata retains owning job IDs."
    )


@pytest.mark.parametrize("confirmation", [None, PolicyConfirmation("0" * 64, "approval:wrong")])
def test_MissingOrMismatchedConfirmationNeverLaunches(tmp_path: Path, confirmation) -> None:
    """STANDARD permission and registered targets cannot stand in for exact operation approval."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=confirmation))
    assert summary.ExitCode() == 3, "Missing/stale confirmation retains explicit authority denial."
    assert not (root / "nuclei-launched").exists(), (
        "Denied plans must not launch even owned fixtures."
    )
    assert summary.snapshot.artifacts == (), "No target execution means no fabricated acquisitions."
    assert summary.model_revision == 0, "Denial cannot fabricate model progress."


@pytest.mark.parametrize("mode,code", [
    ("fail", JobFailureCode.PROVIDER), ("invalid", JobFailureCode.NORMALIZATION),
    ("wait", JobFailureCode.TIMEOUT), ("output-limit", JobFailureCode.OUTPUT_LIMIT),
])
def test_RealTerminalFailuresKeepRawEvidenceAndNoFindings(
    tmp_path: Path, mode: str, code: JobFailureCode,
) -> None:
    """Actual failure, malformed success, deadline and overflow retain truthful terminal state."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    (root / "nuclei-workflow-mode").write_text(mode, encoding="utf-8")
    limits = NucleiScanLimits(1 if mode == "wait" else 30)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
        executable, Policy, confirmation=Confirm(root, target, profile, executable, limits=limits),
        limits=limits))
    assert summary.ExitCode() == 4, (
        "Process and storage/normalization failures are not completed scans."
    )
    assert summary.snapshot.failure is not None, "Failed terminal jobs retain the actual reason."
    assert summary.snapshot.failure.code is code, "Failure must preserve its owned classification."
    assert len(summary.snapshot.artifacts) == 2, "Actual terminal streams must survive failed runs."
    assert summary.model_revision == 0, "Incomplete provider output cannot create trusted findings."
    assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
        "Failed acquisitions remain reopenable."
    )


def test_EmptyProviderOutputDoesNotClaimSecurityCoverage(tmp_path: Path) -> None:
    """Successful empty JSONL reports no matches while preserving run metadata and actual bytes."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    (root / "nuclei-workflow-mode").write_text("empty", encoding="utf-8")
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
        executable, Policy, confirmation=Confirm(root, target, profile, executable)))
    assert summary.ExitCode() == 0, (
        "An empty successful provider report remains a completed operation."
    )
    assert Findings(LocalModelStore(root).Open()) == (), (
        "Zero provider matches must not invent findings."
    )
    observation = next(event.data for event in summary.events
                       if event.kind is JobEventKind.OBSERVATION)
    assert observation.attributes["reported_matches"] == 0, (
        "No coverage or security claim is inferred."
    )


@pytest.mark.parametrize("stage", ["launch", "save"])
@pytest.mark.parametrize("mutation", ["owner", "consent", "policy", "material"])
def test_CurrentAuthorityAndMaterialRecheckedAtLaunchAndSave(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, mutation: str,
) -> None:
    """Mutations after grant or evidence reads cannot bypass final launch/model authority checks."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    confirmation = Confirm(root, target, profile, executable)
    policy = [Policy()]

    def ReadPolicy() -> ImpactPolicy:
        """Return the current same-revision policy to test content binding independently."""

        return policy[0]

    def Mutate() -> None:
        """Change one authoritative input after its previous valid check."""

        if mutation == "policy":
            policy[0] = replace(policy[0], permissions=())

        elif mutation == "material":
            Path(profile.templates[0].path).write_bytes(b"changed-reviewed-template")

        else:
            scope_store = LocalScopeStore(root)
            scope = scope_store.Open("local")
            authorization = replace(scope.authorization,
                authority_reference="operator:changed") if mutation == "owner" else replace(
                    scope.authorization, state=AuthorizationState.REVOKED)
            scope_store.Save(replace(scope, authorization=authorization))

    if stage == "launch":
        original = PolicyEngine.Authorize

        def Authorize(self, *args, **kwargs):
            """Mutate only after the genuine unchanged engine issued a valid grant."""

            grant = original(self, *args, **kwargs)
            Mutate()

            return grant

        monkeypatch.setattr(PolicyEngine, "Authorize", Authorize)

    else:
        original_ingest = nucleiscan.ApplyVerifiedFindings

        def Apply(*args, **kwargs):
            """Mutate after actual raw evidence has been read and pure Findings projected."""

            result = original_ingest(*args, **kwargs)
            Mutate()

            return result

        monkeypatch.setattr(nucleiscan, "ApplyVerifiedFindings", Apply)

    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, ReadPolicy, confirmation=confirmation))
    assert summary.ExitCode() == (4 if mutation == "material" else 3), (
        "Fresh authority/material failure must remain explicit."
    )
    assert summary.model_revision == 0, "Revoked or changed exact plans cannot commit new Findings."
    assert (root / "nuclei-launched").exists() is (stage == "save"), (
        "Only the grant-to-launch mutation must stop the real process before creation."
    )
    assert len(summary.snapshot.artifacts) == (2 if stage == "save" else 0), (
        "Post-run denial retains real acquired bytes; prelaunch denial creates none."
    )


def test_CancelledPresentationAwaitsOwnedProcessAndRetainsEvidence(tmp_path: Path) -> None:
    """Caller cancellation terminates the owned child before returning a cancelled summary."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    (root / "nuclei-workflow-mode").write_text("wait", encoding="utf-8")
    confirmation = Confirm(root, target, profile, executable)

    async def Scenario():
        """Wait for genuine process liveness, then cancel only its owning presentation task."""

        launched = asyncio.Event()

        def OnEvent(event):
            """Observe an actual child launch marker without copying raw output."""

            if event.kind is JobEventKind.HEARTBEAT and (root / "nuclei-launched").exists():
                launched.set()

        task = asyncio.create_task(RunNucleiScan(root, "local", target, "operator:owned", profile,
            executable, Policy, confirmation=confirmation, on_event=OnEvent))

        await asyncio.wait_for(launched.wait(), 5)

        task.cancel()

        return await task

    summary = asyncio.run(Scenario())
    assert summary.snapshot.state is JobState.CANCELLED, "Owned cancellation must remain terminal."
    assert summary.ExitCode() == 130, "Cancelled work must retain the user-level exit convention."
    assert len(summary.snapshot.artifacts) == 2, "Cancellation retains real terminal stream bytes."
    assert OpenWorkspace(root)["verified_evidence_records"] == 2, (
        "Cleanup must save acquired references."
    )


def test_PresentationFailureCancelsAndReapsOwnedJob(tmp_path: Path) -> None:
    """An event consumer failure cannot leave the owned scan running in the background."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    confirmation = Confirm(root, target, profile, executable)

    def Fail(event):
        """Reject the first actually published event before any target execution."""

        raise RuntimeError("synthetic-presentation-failure")

    with pytest.raises(RuntimeError, match="presentation"):
        asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                 executable, Policy, confirmation=confirmation, on_event=Fail))

    assert not (root / "nuclei-launched").exists(), (
        "Presentation failure before launch must cancel job."
    )


@pytest.mark.parametrize("owner,policy", [
    ("operator:other", Policy()), ("operator:owned", ImpactPolicy("no-permission")),
])
def test_DeniedPlanningNeverStartsTargetProcess(tmp_path: Path, owner: str, policy) -> None:
    """Wrong actor and absent STANDARD permission fail the existing authoritative policy engine."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)

    with pytest.raises(PermissionError):
        PlanNucleiScan(root, "local", target, owner, profile, executable, lambda: policy)

    assert not (root / "nuclei-launched").exists(), "Planning never scans the selected endpoint."


def test_OptionalProviderAbsenceIsAnActualFailure(tmp_path: Path) -> None:
    """An unavailable selected binary cannot be confused with a compatible installed scanner."""

    root = tmp_path / "workspace"
    target, profile, _ = Setup(root)

    with pytest.raises(NucleiUnavailableError):
        PlanNucleiScan(root, "local", target, "operator:owned", profile,
                       str(root / "not-installed"), Policy)


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("error_type", [OSError, PermissionError])
@pytest.mark.parametrize("published", [False, True])
def test_DurableStorageFailureBlocksTerminalSuccess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str, error_type, published: bool,
) -> None:
    """A provider match cannot become completed when canonical Save or references fail."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    confirmation = Confirm(root, target, profile, executable)

    storage_owner = LocalModelStore if owner == "model" else LocalWorkspaceStore
    original = storage_owner.Save

    def FailSave(*args, **kwargs):
        """Inject actual producer storage/acknowledgement failure at the selected owner."""

        if published:
            original(*args, **kwargs)

        raise error_type(13, "private-storage-path")

    monkeypatch.setattr(storage_owner, "Save", FailSave)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=confirmation))
    assert summary.ExitCode() == 4, "Actual storage failure must prevent terminal completion."
    assert summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "Owner failure remains classified."
    )
    assert len(summary.snapshot.artifacts) == 2, (
        "Raw acquired evidence survives owner Save failure."
    )
    assert "private-storage-path" not in json.dumps(summary.ToDict()), (
        "Material paths stay private."
    )
    assert summary.model_revision == (0 if owner == "model" and not published else 1), (
        "Failed Save acknowledgement must reopen published state without claiming completion."
    )


def test_CliPlanExplicitConfirmationAndReopen(tmp_path: Path) -> None:
    """The namespace dispatch presents exact plans and reuses existing product reopen behavior."""

    root = tmp_path / "workspace"
    target, profile, executable = Setup(root)
    profile_file = root / "profile.json"
    profile_file.write_text(SerializeContract(profile), encoding="utf-8")
    policy_file = root / "policy.json"
    policy_file.write_text(SerializeContract(Policy()), encoding="utf-8")
    argv = ["nuclei", str(root), "--scope", "local", "--owner", "operator:owned",
            "--target", target.value, "--profile", str(profile_file), "--policy", str(policy_file),
            "--executable", executable]
    planned = io.StringIO()
    assert RunCommands("scan", [*argv, "--plan"], planned) == 0, (
        "Planning must succeed without scanning."
    )
    document = json.loads(planned.getvalue())
    contract_root = Path(__file__).parents[2] / "contracts"
    Draft202012Validator(json.loads((contract_root / "nuclei-scan-plan.schema.json").read_text()),
                         format_checker=FormatChecker()).validate(document)
    assert document["state"] == "planned", "Read-only plans must not report completed scans."
    output = io.StringIO()
    assert RunCommands("scan", [*argv, "--confirm-plan", document["intent_sha256"],
        "--confirmation-reference", "approval:pytest-cli-exact", "--events-json"], output) == 0, (
        "The exact confirmed product namespace must execute the owned synthetic provider."
    )
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    summary_schema = json.loads((contract_root / "nuclei-scan-summary.schema.json").read_text())
    Draft202012Validator(summary_schema, format_checker=FormatChecker()).validate(
        lines[-1]["summary"],
    )
    assert lines[0]["event"]["data"] == "queued", "Live output begins with an actual queued event."
    assert lines[-1]["summary"]["object_counts"]["finding"] == 1, (
        "Summary describes saved Findings."
    )
    assert lines[-1]["summary"]["state"] == "completed", "Terminal summary follows actual cleanup."
    assert OpenWorkspace(root)["verified_evidence_records"] == 2, "CLI acquisitions survive reopen."
    assert LocalEvidenceStore(root / "evidence").Read(
        LocalWorkspaceStore(root).Open().evidence_references[0]), (
        "Actual bytes remain independently readable."
    )
