# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict finite operator metadata and planning inputs never imply scan authority."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fuzzy1337 import nucleiscan
from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobEventKind
from fuzzy1337.model import LocalModelStore
from fuzzy1337.nucleiscan import (
    NucleiScanLimits,
    NucleiUnavailableError,
    PlanNucleiScan,
    ReadConfiguration,
    ReadNucleiPolicy,
    ReadNucleiProfile,
    RunNucleiScan,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation, PolicyEngine
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore


def Policy() -> ImpactPolicy:
    """Declare only the finite provider capability; no invocation is approved here."""

    return ImpactPolicy("owned-nuclei", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission("web.http-template-check", "native.nuclei",
                                          ImpactLevel.STANDARD),))


def test_ExactExistingPolicySerializationRoundTrips(tmp_path: Path) -> None:
    """CLI metadata reuses the unchanged typed policy rather than a new permission schema."""

    path = tmp_path / "policy.json"
    path.write_text(SerializeContract(Policy()), encoding="utf-8")
    assert ReadNucleiPolicy(path) == Policy(), "Policy serialization must retain all exact fields."


@pytest.mark.parametrize("raw", [
    b'{"key":1,"key":2}', b'{"key":NaN}', b'{"key":Infinity}', b'{"key":1e999}', b'\xff',
    b'null null', b'[' * 19 + b'0' + b']' * 19, b'[' + b'0,' * 4100 + b'0]',
    b' ' * (256 * 1024 + 1), b'1.2',
])
def test_StrictBoundedJsonRejectsAmbiguity(tmp_path: Path, raw: bytes) -> None:
    """Duplicate, nonfinite, oversized, deep and unsupported values fail closed."""

    path = tmp_path / "bad.json"
    path.write_bytes(raw)

    with pytest.raises(ValueError):
        ReadConfiguration(path)


def test_ConfigurationRejectsSymlinkDirectoryAndHardlink(tmp_path: Path) -> None:
    """Observed filesystem indirection cannot substitute operator configuration material."""

    original = tmp_path / "original.json"
    original.write_bytes(b"{}")
    link = tmp_path / "link.json"

    try:
        link.symlink_to(original)

    except OSError:
        pytest.skip("Symlink creation is unavailable to this test account")

    with pytest.raises(ValueError):
        ReadConfiguration(link)

    with pytest.raises(ValueError):
        ReadConfiguration(tmp_path)

    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(original)

    with pytest.raises(ValueError):
        ReadConfiguration(hardlink)


@pytest.mark.parametrize("field,value", [
    ("unknown", "private-detail"), ("revision", True), ("revision", -1),
    ("maximum_impact", "standard"), ("maximum_impact", True),
    ("max_authorization_seconds", False), ("permissions", {}),
    ("permissions", [{}] * 65), ("permissions", [{"unknown": "private-detail"}]),
])
def test_InvalidPolicyMetadataNeverImpliesPermissions(
    tmp_path: Path, field: str, value: object,
) -> None:
    """Existing validation rejects integer/bool aliases and missing/unknown policy fields."""

    document = json.loads(SerializeContract(Policy()))
    document[field] = value
    path = tmp_path / "invalid-policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        ReadNucleiPolicy(path)


@pytest.mark.parametrize("field,value", [
    ("granted_privileges", "root"), ("granted_privileges", ["root"] * 65),
    ("granted_privileges", [False]), ("adapter_id", False), ("maximum_impact", True),
])
def test_InvalidPermissionEntriesFailClosed(
    tmp_path: Path, field: str, value: object,
) -> None:
    """An explicit permission array must contain precisely typed finite entries."""

    document = json.loads(SerializeContract(Policy()))
    document["permissions"][0][field] = value
    path = tmp_path / "invalid-policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        ReadNucleiPolicy(path)


@pytest.mark.parametrize("document", [
    {}, {"profile_id": "owned", "templates": [], "configuration_path": "/owned"},
    {"profile_id": "owned", "templates": {}, "configuration_path": "/owned"},
    {"profile_id": "owned", "templates": [{}] * 33, "configuration_path": "/owned"},
    {"profile_id": "owned", "templates": [{}], "configuration_path": "/owned"},
])
def test_InvalidProfileNeverManufacturesTemplateReview(tmp_path: Path, document: object) -> None:
    """Every selected finite template needs complete exact review-bound metadata."""

    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        ReadNucleiProfile(path)


@pytest.mark.parametrize("timeout,rate", [(True, 2), (0, 2), (301, 2), (1, True), (1, 0), (1, 11)])
def test_WorkflowBoundsUseFiniteIntegerBudgets(timeout: int, rate: int) -> None:
    """Booleans, zero and excessive budgets cannot widen a selected profile."""

    with pytest.raises(ValueError):
        NucleiScanLimits(timeout, rate)


@pytest.mark.parametrize("target,executable", [
    (Target(TargetKind.IP, "127.0.0.1"), "/owned/nuclei"),
    (Target(TargetKind.URL, "http://example.test/"), "/owned/nuclei"),
    (Target(TargetKind.URL, "http://127.0.0.1/"), "nuclei"),
])
def test_InvalidPlanningInputsCannotReachProvider(
    tmp_path: Path, target: Target, executable: str,
) -> None:
    """Explicit exact literal-IP target and selected absolute executable are mandatory."""

    with pytest.raises(ValueError):
        PlanNucleiScan(tmp_path, "local", target, "operator:owned", None, executable, Policy)


@pytest.fixture
def portable_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Bind a clearly synthetic portable executor boundary without any provider process/network.

    The policy engine, owned job, evidence store, finding ingestion and model/workspace
    persistence are real first-party components. This stub is not native scanner acceptance.
    """

    root = tmp_path / "workspace"
    CreateWorkspace(root, "owned-nuclei", "Synthetic portable workflow")
    target = Target(TargetKind.URL, "http://127.0.0.1:8080/")
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "owned-nuclei", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:pytest-unit-owned",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target, Target(TargetKind.IP, "127.0.0.1")),
        allow=(target, Target(TargetKind.IP, "127.0.0.1"))))
    template_path = root / "reviewed-get.yaml"
    raw = (Path(__file__).parents[1] / "fixtures/nuclei/reviewed-get.yaml").read_bytes()
    template_path.write_bytes(raw)
    config_path = root / "nuclei-empty.yaml"
    config_path.write_bytes(b"{}\n")
    profile = NucleiProfile("owned-synthetic", (NucleiTemplate(
        "owned-http-marker", str(template_path), hashlib.sha256(raw).hexdigest(), len(raw),
        "fixture:owned-review", "1", "review:source-controlled-exact-get", "single-get-exact-url",
    ),), str(config_path))
    executable = str(root / "synthetic-executor-boundary")
    probe = {"mode": "match", "executed": False, "mutate": None}

    def Health(self):
        """Declare only the synthetic adapter-health stub for portable orchestration tests."""

        return AdapterHealth(self.Descriptor.adapter_id, AdapterHealthState.AVAILABLE,
                             "3.4.10-synthetic")

    class SyntheticExecutor:
        """Replace only the subprocess transport with explicit no-network terminal fixtures."""

        def __init__(self, workspace_root, *, clock):
            """Retain the real policy clock while creating no worker or target side effect."""

            self.clock = clock

        async def Execute(self, request, *, grant, context_provider, on_event, cancellation):
            """Perform unchanged core grant validation and return explicitly synthetic streams."""

            if probe["mutate"] is not None:
                probe["mutate"]()

            PolicyEngine().Validate(grant, request.invocation, request.capability,
                                    context_provider(), at=self.clock())
            probe["executed"] = True
            on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
            mode = probe["mode"]

            await asyncio.sleep(0)

            if mode == "wait":
                await cancellation.wait()

                state, code, termination = ExecutionState.CANCELLED, None, \
                    ExecutionTermination.CANCELLATION

            elif mode == "timeout":
                state, code, termination = (ExecutionState.TIMED_OUT, None,
                                             ExecutionTermination.TIMEOUT)

            elif mode == "fail":
                state, code, termination = (ExecutionState.FAILED, 7,
                                             ExecutionTermination.PROCESS_EXIT)

            elif mode == "output-limit":
                state, code, termination = (ExecutionState.FAILED, 7,
                                             ExecutionTermination.OUTPUT_LIMIT)

            else:
                state, code, termination = (ExecutionState.SUCCEEDED, 0,
                                             ExecutionTermination.PROCESS_EXIT)

            stdout = json.dumps({"template-id": "owned-http-marker", "type": "http",
                "host": target.value, "matched-at": target.value, "matcher-status": True,
                "info": {"name": "Owned synthetic HTTP marker", "severity": "info"}}).encode()

            if mode == "invalid":
                stdout = b"invalid-jsonl"

            elif mode == "empty":
                stdout = b""

            return LocalExecutionResult(AdapterExecution(state, code, 0.01), termination,
                stdout, b"portable synthetic executor; no process/network",
                (ExecutionEvent(0, ExecutionEventKind.STARTED),
                 ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination)))

    monkeypatch.setattr(NucleiAdapter, "CheckHealth", Health)
    monkeypatch.setattr(nucleiscan, "GovernedLocalExecutor", SyntheticExecutor)
    metadata = root / "profile.json"
    metadata.write_text(SerializeContract(profile), encoding="utf-8")
    assert ReadNucleiProfile(metadata) == profile, "Profile metadata uses existing adapter fields."
    plan = PlanNucleiScan(root, "local", target, "operator:owned", profile, executable, Policy)
    approval = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:pytest-unit-exact")
    assert plan.ToDict()["intent_sha256"] == approval.intent_sha256, (
        "Exact intent must be presented."
    )

    return root, target, profile, executable, approval, probe


@pytest.mark.parametrize("mode,expected", [
    ("match", 0), ("empty", 0), ("invalid", 4), ("fail", 4), ("timeout", 4), ("output-limit", 4),
])
def test_PortableWorkflowComposesTruthfulOwnedBoundaries(portable_workflow, mode, expected):
    """Portable synthetic transport exercises actual job/evidence/core/model outcomes."""

    root, target, profile, executable, approval, probe = portable_workflow
    probe["mode"] = mode
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=approval))
    assert summary.ExitCode() == expected, "Synthetic transport must preserve its actual outcome."
    assert len(summary.snapshot.artifacts) == 2, "Every returned terminal stream is retained."
    assert summary.ToDict()["state"] == summary.snapshot.state.value, "Presentation is truthful."
    findings = Findings(LocalModelStore(root).Open())
    assert len(findings) == (1 if mode == "match" else 0), "Incomplete output is never trusted."


@pytest.mark.parametrize("approval", [None, PolicyConfirmation("0" * 64, "approval:wrong")])
def test_PortableMissingAndStalePlanDenial(portable_workflow, approval):
    """Portable policy tests preserve the actual unchanged exact-confirmation boundary."""

    root, target, profile, executable, _, probe = portable_workflow
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=approval))
    assert summary.ExitCode() == 3, "STANDARD cannot execute without an exact-plan confirmation."
    assert not probe["executed"], "The denied transport boundary must never be invoked."


@pytest.mark.parametrize("stage", ["authorize", "launch", "save"])
@pytest.mark.parametrize("mutation", ["owner", "policy", "material"])
def test_PortableFreshAuthorityAndMaterialBeforeLaunchAndSave(
    portable_workflow, monkeypatch: pytest.MonkeyPatch, stage: str, mutation: str,
) -> None:
    """Every portable critical policy/material seam rejects changes without target execution."""

    root, target, profile, executable, approval, probe = portable_workflow
    policy = [Policy()]

    def CurrentPolicy():
        """Read same-revision current policy metadata for the real policy engine."""

        if stage == "authorize" and not probe.get("changed"):
            probe["changed"] = True

            return policy[0]

        if stage == "authorize":
            Mutate()

        return policy[0]

    def Mutate():
        """Replace one exact authority or artifact after an earlier valid observation."""

        if mutation == "policy":
            policy[0] = replace(policy[0], permissions=())

        elif mutation == "material":
            Path(profile.templates[0].path).write_bytes(b"changed")

        else:
            store = LocalScopeStore(root)
            scope = store.Open("local")
            store.Save(replace(scope, authorization=replace(scope.authorization,
                                                           authority_reference="operator:changed")))

    if stage == "launch":
        probe["mutate"] = Mutate

    elif stage == "save":
        original = nucleiscan.ApplyVerifiedFindings

        def Apply(*args, **kwargs):
            """Mutate after the real evidence verification and pure canonical projection."""

            result = original(*args, **kwargs)
            Mutate()

            return result

        monkeypatch.setattr(nucleiscan, "ApplyVerifiedFindings", Apply)

    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, CurrentPolicy, confirmation=approval))
    assert summary.ExitCode() in (3, 4), "Changed exact scope/policy/material cannot claim success."
    assert summary.model_revision == 0, "New canonical Findings require final current authority."


@pytest.mark.parametrize("owner", ["model", "workspace"])
def test_PortableStorageOwnerFailureRemainsExplicit(portable_workflow, monkeypatch, owner):
    """Portable Save failures retain actual acquired bytes and never report completion."""

    root, target, profile, executable, approval, _ = portable_workflow

    def FailSave(*args, **kwargs):
        """Inject a source-independent model or workspace Save failure."""

        raise OSError("synthetic-private-path")

    monkeypatch.setattr(LocalModelStore if owner == "model" else LocalWorkspaceStore,
                        "Save", FailSave)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=approval))
    assert summary.ExitCode() == 4, "Durable owner failure must prevent completed state."
    assert len(summary.snapshot.artifacts) == 2, "Synthetic transport raw streams remain acquired."


def test_PortablePresentationCancellationAndFailure(portable_workflow):
    """Portable owner cleanup handles consumer cancellation and failure without orphaned work."""

    root, target, profile, executable, approval, probe = portable_workflow
    probe["mode"] = "wait"

    async def Scenario():
        """Cancel after an actual synthetic transport heartbeat while the owned job is running."""

        entered = asyncio.Event()

        def Observe(event):
            """Signal only genuine published transport liveness within this fixture."""

            if event.kind is JobEventKind.HEARTBEAT:
                entered.set()

        task = asyncio.create_task(RunNucleiScan(root, "local", target, "operator:owned", profile,
            executable, Policy, confirmation=approval, on_event=Observe))

        await entered.wait()

        task.cancel()

        return await task

    summary = asyncio.run(Scenario())
    assert summary.ExitCode() == 130, "Cancellation must await owned terminal cleanup."

    def Fail(event):
        """A failed presentation consumer must trigger owned cleanup before propagation."""

        raise RuntimeError("synthetic-presentation-failure")

    with pytest.raises(RuntimeError, match="presentation"):
        asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                 executable, Policy, confirmation=approval, on_event=Fail))


def test_PortableUnavailableProviderFailsBeforeJob(portable_workflow, monkeypatch):
    """Optional provider absence never becomes a synthetic scan completion."""

    root, target, profile, executable, _, probe = portable_workflow

    def Health(self):
        """Return an unavailable synthetic version probe."""

        return AdapterHealth(self.Descriptor.adapter_id, AdapterHealthState.UNAVAILABLE)

    monkeypatch.setattr(NucleiAdapter, "CheckHealth", Health)

    with pytest.raises(NucleiUnavailableError):
        PlanNucleiScan(root, "local", target, "operator:owned", profile, executable, Policy)

    assert not probe["executed"], "An unavailable provider grants no process authority."


def test_PortableGrantExpiryAfterEvidenceReadBlocksCanonicalSave(
    portable_workflow, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh time after expensive evidence/projection work denies an expired launch grant."""

    root, target, profile, executable, approval, probe = portable_workflow
    clock = [datetime.now(UTC)]
    original = nucleiscan.ApplyVerifiedFindings

    def Apply(*args, **kwargs):
        """Advance beyond granted consent only after real raw-evidence verification."""

        projected = original(*args, **kwargs)
        clock[0] += timedelta(minutes=20)

        return projected

    monkeypatch.setattr(nucleiscan, "ApplyVerifiedFindings", Apply)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
        executable, Policy, confirmation=approval, clock=lambda: clock[0]))
    assert summary.ExitCode() == 3, "Final clock/scope/grant checks must deny expired authority."
    assert probe["executed"], "This probe expires authority after the approved synthetic transport."
    assert summary.model_revision == 0, "Expired final acceptance cannot add canonical Findings."
    assert len(summary.snapshot.artifacts) == 2, (
        "Actual returned streams remain independently acquired."
    )


def test_PortableSaveAcknowledgementFailureReopensActualPublishedState(
    portable_workflow, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic publication followed by an owner acknowledgement failure is truthful failed state."""

    root, target, profile, executable, approval, _ = portable_workflow
    original = LocalModelStore.Save

    def SaveAndFail(self, *args, **kwargs):
        """Commit through the model owner, then fail its synthetic acknowledgement."""

        original(self, *args, **kwargs)

        raise OSError("synthetic-acknowledgement-failure")

    monkeypatch.setattr(LocalModelStore, "Save", SaveAndFail)
    summary = asyncio.run(RunNucleiScan(root, "local", target, "operator:owned", profile,
                                       executable, Policy, confirmation=approval))
    assert summary.ExitCode() == 4, (
        "Publication uncertainty cannot become terminal completed state."
    )
    assert summary.model_revision == 1, (
        "The summary must reopen the actually authoritative revision."
    )
    assert len(Findings(LocalModelStore(root).Open())) == 1, (
        "Published state cannot be silently undone."
    )
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 2, (
        "Actual captured raw acquisitions remain retained despite failed acknowledgement."
    )
