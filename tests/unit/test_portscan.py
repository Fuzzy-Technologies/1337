# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable finite port-workflow composition with deterministic synthetic process results."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from fuzzy1337 import portscan
from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.jobs import JobFailureCode
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation, PolicyEngine
from fuzzy1337.portscan import (
    PORT_SCAN_CAPABILITY,
    PORT_SCAN_PROVIDER_ID,
    PlanPortScan,
    PortScanAuthorityDeniedError,
    PortScanLimits,
    PortScanUnavailableError,
    RunPortScan,
)
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


@pytest.fixture(scope="module")
def owned_loop():
    """Initialize event-loop self-pipes before the unchanged unit network-denial guard."""

    with asyncio.Runner() as runner:
        yield runner


@pytest.fixture
def runner(owned_loop):
    """Reap each scenario's owned tasks while preserving unit network isolation."""

    yield owned_loop

    async def Cleanup():
        """Cancel and await remaining owned tasks before the next deterministic scenario."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_loop.run(Cleanup())


def Policy():
    """Declare only the explicit STANDARD TCP-connect capability."""

    return ImpactPolicy("owned-ports", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(PORT_SCAN_CAPABILITY, PORT_SCAN_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))


def Output(mode):
    """Return original synthetic XML, including explicitly grouped or absent provider facts."""

    if mode == "invalid":
        return b"not XML"

    port = ('<port protocol="tcp" portid="80"><state state="open" reason="synthetic"/>'
            '<service name="http" method="table" conf="3"/></port>')
    closed = ('<extraports state="closed" count="1"/>' if mode == "grouped" else
              '<port protocol="tcp" portid="443"><state state="closed" reason="synthetic"/></port>')
    host = ('<host><status state="up" reason="user-set"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/>'
            f'<ports>{port}{closed}</ports></host>')

    if mode == "absent":
        host = ""

    return (f'<nmaprun scanner="nmap" version="7.95-synthetic">{host}'
            '<runstats><finished exit="success"/></runstats></nmaprun>').encode()


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    """Keep real policy/job/evidence/model owners and substitute only process health/transport."""

    root = tmp_path / "workspace"
    CreateWorkspace(root, "owned-ports", "Synthetic governed port workflow")
    target = Target(TargetKind.IP, "127.0.0.1")
    now = datetime(2026, 10, 23, tzinfo=UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "owned-ports", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-ports",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target,), allow=(target,)))
    probe = {"mode": "success", "executed": 0, "before_launch": None, "after_launch": None,
             "policy": Policy(), "health": AdapterHealthState.AVAILABLE, "health_calls": 0}

    def Health(self):
        """Label every provider observation as synthetic without starting a local process."""

        probe["health_calls"] += 1

        return AdapterHealth(PORT_SCAN_PROVIDER_ID, probe["health"], "7.95-synthetic")

    class SyntheticExecutor:
        """Return controlled terminal facts after genuine current-context policy validation."""

        def __init__(self, root, *, clock):
            """Retain only the original authority clock; no process or socket is created."""

            self.clock = clock

        async def Execute(self, request, *, grant, context_provider, on_event, cancellation):
            """Check launch authority, then emit a bounded original synthetic execution result."""

            if probe["before_launch"] is not None:
                probe["before_launch"]()

            PolicyEngine().Validate(grant, request.invocation, request.capability,
                                    context_provider(), at=self.clock())
            probe["executed"] += 1

            if probe["after_launch"] is not None:
                probe["after_launch"]()

            mode = probe["mode"]
            state, code, termination = (ExecutionState.SUCCEEDED, 0,
                                        ExecutionTermination.PROCESS_EXIT)

            if mode == "fail":
                state, code = ExecutionState.FAILED, 7

            elif mode == "timeout":
                state, code, termination = (ExecutionState.TIMED_OUT, None,
                                             ExecutionTermination.TIMEOUT)

            elif mode == "cancel":
                state, code, termination = (ExecutionState.CANCELLED, None,
                                             ExecutionTermination.CANCELLATION)

            elif mode == "output-limit":
                state, code, termination = (ExecutionState.FAILED, 7,
                                             ExecutionTermination.OUTPUT_LIMIT)

            return LocalExecutionResult(AdapterExecution(state, code, 0.01), termination,
                Output(mode), b"Owned synthetic process; no network activity\n",
                (ExecutionEvent(0, ExecutionEventKind.STARTED),
                 ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination)))

    def ReadPolicy():
        """Reread the explicit selected policy at every real authority boundary."""

        return probe["policy"]

    def Clock():
        """Return a fixed aware authority time, independent of scheduler timing."""

        return now

    monkeypatch.setattr(portscan.NmapAdapter, "CheckHealth", Health)
    monkeypatch.setattr(portscan, "GovernedLocalExecutor", SyntheticExecutor)
    arguments = (root, "local", target, "operator:owned", (443, 80), str(root / "owned-nmap"),
                 ReadPolicy)

    return root, arguments, probe, Clock


def Confirmed(workflow, runner):
    """Use the actual current policy intent and separate explicit confirmation reference."""

    _, arguments, _, clock = workflow
    plan = PlanPortScan(*arguments, clock=clock)

    return runner.run(RunPortScan(*arguments, clock=clock,
        confirmation=PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:owned-ports")))


@pytest.mark.parametrize("value", [False, 0, 3601, 1.0])
def test_LimitsKeepExistingAdapterBounds(value):
    """Timeout defaults never turn invalid numeric values into an accepted execution budget."""

    with pytest.raises(ValueError):
        PortScanLimits(value)


def test_PlanningIsReadOnlyAndKeepsExactSelectedIntent(workflow):
    """Only explicit selected IP/ports and observed synthetic provider version enter the plan."""

    root, arguments, probe, clock = workflow
    plan = PlanPortScan(*arguments, clock=clock)
    document = plan.ToDict()
    assert document["workflow"] == "ports" and document["confirmation_required"], (
        "STANDARD planning must expose its separate confirmation requirement."
    )
    assert plan.invocation.argv[1:] == ("--unprivileged", "-n", "-Pn", "-sT", "-p", "80,443",
        "--host-timeout", "30s", "-oX", "-", "127.0.0.1"), "Finite adapter argv changed."
    assert plan.policy_plan.destination_references == (arguments[2].Reference(),), (
        "Actual destination must be the same explicitly selected IP."
    )
    assert probe["executed"] == 0 and LocalModelStore(root).Open().revision == 0, (
        "Planning must neither contact a target nor change its canonical model."
    )


@pytest.mark.parametrize("ports", [(), (80, 80), (True,), (0,), (65536,), [80]])
def test_InvalidSelectionRefusesBeforeHealthOrExecution(workflow, ports):
    """The sole finite request owner validates explicit ports before probing a provider."""

    _, arguments, probe, clock = workflow
    selected = (*arguments[:4], ports, *arguments[5:])

    with pytest.raises(ValueError):
        PlanPortScan(*selected, clock=clock)

    assert probe["health_calls"] == probe["executed"] == 0, (
        "Invalid selection must not reach a provider process."
    )


@pytest.mark.parametrize("state", [AdapterHealthState.UNAVAILABLE, AdapterHealthState.DEGRADED])
def test_OptionalProviderAbsenceIsExplicit(workflow, state):
    """An unavailable or unhealthy selected tool cannot become a successful empty scan."""

    _, arguments, probe, clock = workflow
    probe["health"] = state

    with pytest.raises(PortScanUnavailableError):
        PlanPortScan(*arguments, clock=clock)

    assert probe["executed"] == 0, "Provider absence must not launch target execution."


@pytest.mark.parametrize("confirmation", [None, PolicyConfirmation("0" * 64, "approval:other")])
def test_ExactStandardConfirmationIsRequiredBeforeContact(workflow, runner, confirmation):
    """Missing or mismatched approval creates a truthful denied job with no acquisitions."""

    root, arguments, probe, clock = workflow
    summary = runner.run(RunPortScan(*arguments, clock=clock, confirmation=confirmation))
    assert summary.ExitCode() == 3 and (
        summary.snapshot.failure.code is JobFailureCode.AUTHORIZATION
    ), (
        "Missing exact STANDARD confirmation must be an authorization failure."
    )
    assert probe["executed"] == 0 and summary.snapshot.artifacts == (), (
        "Denied target execution cannot create acquired stdout/stderr."
    )
    assert LocalModelStore(root).Open().revision == 0, "Denied execution mutated the model."


def test_ReportedObjectsReuseNativeIdentitiesAndOriginalCustody(workflow, runner):
    """Repeated projections preserve canonical objects, unrelated metadata, and raw evidence."""

    root, _, probe, _ = workflow
    model = LocalModelStore(root)
    first = Confirmed(workflow, runner)
    state = model.Open()
    host = state.Objects(ObjectKind.HOST)[0]
    seeded, _ = state.Apply(objects=(replace(host,
        attributes={**host.attributes, "owner_note": "preserve"}),))
    model.Save(seeded, expected_revision=state.revision)
    references = tuple(item.Reference() for item in state.objects)
    second = Confirmed(workflow, runner)
    reopened = model.Open()
    assert first.ExitCode() == second.ExitCode() == 0 and probe["executed"] == 2, (
        "Approved finite synthetic executions did not complete their actual workflow."
    )
    assert references == tuple(item.Reference() for item in reopened.objects), (
        "Repeated observations created duplicated logical objects."
    )
    assert len(reopened.Objects(ObjectKind.HOST)) == 1 and (
        len(reopened.Objects(ObjectKind.PORT)) == 2
    ), (
        "Reported host and explicit TCP ports did not reach canonical model families."
    )
    assert reopened.Objects(ObjectKind.HOST)[0].attributes["owner_note"] == "preserve", (
        "Enrichment overwrote unrelated existing metadata."
    )
    assert {item.identity.key for item in reopened.Objects(ObjectKind.PORT)} == {
        "host:127.0.0.1/tcp/80", "host:127.0.0.1/tcp/443"}, (
            "Port natural keys differ from discovery."
        )
    assert reopened.Objects(ObjectKind.SERVICE)[0].identity.key == "host:127.0.0.1/tcp/80", (
        "Service identity differs from the existing native discovery mapping."
    )
    assert reopened.Objects(ObjectKind.FINDING) == (), "Open ports must never become Findings."
    workspace = LocalWorkspaceStore(root).Open()
    assert len(workspace.evidence_record_references) == 4, "Original acquisitions were lost."
    assert second.ToDict()["state"] == "completed", "Summary disagrees with durable completion."


@pytest.mark.parametrize("mode,expected_ports", [("grouped", 1), ("absent", 0)])
def test_OmittedProviderFactsRemainUnassessed(workflow, runner, mode, expected_ports):
    """Grouped ports and absent hosts cannot be expanded into invented canonical results."""

    root, _, probe, _ = workflow
    probe["mode"] = mode
    summary = Confirmed(workflow, runner)
    state = LocalModelStore(root).Open()
    assert summary.ExitCode() == 0 and len(state.Objects(ObjectKind.PORT)) == expected_ports, (
        "The product fabricated an individual assessment omitted by the actual provider."
    )

    if mode == "grouped":
        assert state.Objects(ObjectKind.HOST)[0].attributes["extraports"][0]["state"] == "closed", (
            "Faithful grouped provider metadata was lost."
        )


@pytest.mark.parametrize("mode,exit_code", [("fail", 4), ("timeout", 4), ("cancel", 130),
                                           ("output-limit", 4), ("invalid", 4)])
def test_FailuresKeepOriginalEvidenceWithoutCanonicalSuccess(workflow, runner, mode, exit_code):
    """Execution and normalization failure retain acquired originals without model enrichment."""

    root, _, probe, _ = workflow
    probe["mode"] = mode
    summary = Confirmed(workflow, runner)
    assert summary.ExitCode() == exit_code and len(summary.snapshot.artifacts) == 2, (
        "Failure classification or raw stdout/stderr acquisition truth changed."
    )
    assert LocalModelStore(root).Open().revision == 0, "Failed execution changed canonical state."
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 2, (
        "Failure discarded available original acquisitions."
    )


@pytest.mark.parametrize("boundary", ["before_launch", "after_launch"])
def test_CurrentPolicyIsRequiredAtLaunchAndCanonicalSave(workflow, runner, boundary):
    """Revoking the selected permission blocks contact or persistence at its owning boundary."""

    root, _, probe, _ = workflow

    def Revoke():
        """Remove the actual explicit current permission without altering old approval bytes."""

        probe["policy"] = replace(probe["policy"], revision=1, permissions=())

    probe[boundary] = Revoke
    summary = Confirmed(workflow, runner)
    assert summary.ExitCode() == 3, "A stale permission survived the current authority check."
    assert probe["executed"] == (boundary == "after_launch"), (
        "Revocation was checked at the wrong execution boundary."
    )
    assert LocalModelStore(root).Open().revision == 0, "Revoked authority changed canonical state."


def test_CurrentConsentActorIsRequired(workflow):
    """A selected operator must match the existing scope consent actor before provider health."""

    _, arguments, probe, clock = workflow
    selected = (*arguments[:3], "operator:other", *arguments[4:])

    with pytest.raises(PortScanAuthorityDeniedError):
        PlanPortScan(*selected, clock=clock)

    assert probe["health_calls"] == 0, "Wrong actor reached provider health execution."


def test_StorageFailureIsNotCompletion(workflow, runner, monkeypatch):
    """An actual model Save refusal preserves originals and remains a failed owning job."""

    root, _, _, _ = workflow

    def Refuse(self, *args, **kwargs):
        """Refuse only the attempted canonical save after original acquisition."""

        raise OSError("owned model persistence refusal")

    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    summary = Confirmed(workflow, runner)
    assert summary.ExitCode() == 4 and summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "Canonical Save refusal became successful completion."
    )
    assert LocalModelStore(root).Open().revision == 0 and len(summary.snapshot.artifacts) == 2, (
        "Failed persistence lost original acquisition truth."
    )
