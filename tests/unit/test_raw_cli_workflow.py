# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual raw workflow owners using the explicitly synthetic existing Nmap transport fixture."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import raw_cli_workflow as product
from fuzzy1337.adapters import AdapterHealthState, ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.jobs import JobFailureCode
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.raw_cli import SelectRawNmap
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.unit import test_portscan as synthetic
from tests.unit.test_raw_cli import TCP


@pytest.fixture(scope="module")
def owned_loop():
    """Initialize event-loop self-pipes before the unchanged unit network-denial guard."""

    with asyncio.Runner() as runner:
        yield runner


@pytest.fixture
def environment(tmp_path, monkeypatch, owned_loop):
    """Reuse labeled no-process Nmap returns while keeping all raw workflow owners real."""

    root, old, state, clock = synthetic.workflow.__wrapped__(tmp_path, monkeypatch)
    state["policy"] = replace(state["policy"], permissions=(*state["policy"].permissions,
        CapabilityPermission("network.service-discovery", "native.nmap", ImpactLevel.STANDARD)))
    monkeypatch.setattr(product, "GovernedLocalExecutor", synthetic.portscan.GovernedLocalExecutor)

    def Arguments(selection=None):
        """Bind only the raw interface inputs to the actual original synthetic workspace."""

        return (root, old[1], old[3], old[5],
            SelectRawNmap(TCP) if selection is None else selection, old[6])

    def Run(selection=None, confirmation=None):
        """Use the actual current exact raw plan and separate explicit confirmation."""

        arguments = Arguments(selection)

        if confirmation is None:
            plan = product.PlanRawCli(*arguments, clock=clock)
            confirmation = PolicyConfirmation(plan.policy_plan.intent_sha256, "approval:raw-test")

        return owned_loop.run(product.RunRawCli(*arguments, confirmation=confirmation, clock=clock))

    return SimpleNamespace(root=root, state=state, clock=clock, Arguments=Arguments,
        Run=Run, runner=owned_loop)


@pytest.mark.parametrize("service", [False, True])
def test_ExactOriginalArgumentsAndParsedObjectsRetainOfflineReplay(environment, service):
    """Both existing Nmap capabilities preserve original synthetic bytes and exact invocation."""

    selected = SelectRawNmap(TCP + (("-sV", "--version-light") if service else ()))
    plan = product.PlanRawCli(*environment.Arguments(selected), clock=environment.clock)
    assert plan.ToDict()["execution_authorized"] is False and environment.state["executed"] == 0, (
        "Planning must not execute the selected target command")
    summary = environment.Run(selected)
    assert summary.ExitCode() == 0 and summary.workspace_acknowledged, (
        "Native zero requires complete original custody and workspace acknowledgement")
    assert summary.invocation == plan.invocation and (
        summary.invocation.argv[1:] == selected.arguments), (
        "The actual authorized invocation must retain the original native tokens and their order")
    store = LocalEvidenceStore(environment.root / "evidence")
    records = {item.evidence.reference.role: item.evidence for item in summary.snapshot.artifacts}
    assert set(records) == {"stdout", "stderr", product.RAW_CLI_RECEIPT_ROLE}, (
        "Both original streams and the native receipt require original acquisition records")
    assert store.Read(records["stdout"].reference) == synthetic.Output("success"), (
        "SOM interpretation cannot replace the exact original synthetic XML")
    assert all(record.provenance.invocation_sha256 == InvocationDigest(plan.invocation)
        for record in records.values()), "Every original acquisition must bind actual native argv"
    model = LocalModelStore(environment.root).Open()
    assert len(model.Objects(ObjectKind.HOST)) == 1 and len(model.Objects(ObjectKind.PORT)) == 2, (
        "Only the two individually reported original ports must enter the authoritative SOM")
    assert len(model.Objects(ObjectKind.SERVICE)) == 1 and not model.Objects(ObjectKind.FINDING), (
        "Reported service metadata must remain separate from vulnerability Findings")
    prior = LocalWorkspaceStore(environment.root).Open()
    replay = product.ReplayRawCli(environment.root, summary.receipt_id)
    assert replay["state"] == "verified" and replay["native_exit_code"] == 0, (
        "Historical replay must independently verify original invocation and raw acquisitions")
    assert LocalWorkspaceStore(environment.root).Open() == prior and (
        environment.state["executed"] == 1), "Historical replay must not Save, launch or repair"


@pytest.mark.parametrize("mode, status, failure", [
    ("fail", 7, JobFailureCode.PROVIDER), ("invalid", 4, JobFailureCode.NORMALIZATION),
    ("timeout", 4, JobFailureCode.TIMEOUT), ("output-limit", 4, JobFailureCode.OUTPUT_LIMIT),
    ("cancel", 130, None),
])
def test_NativeAndWrapperFailuresCannotBecomePositiveFacts(environment, mode, status, failure):
    """Actual native failure status remains distinct from malformed, limited or cancelled work."""

    environment.state["mode"] = mode
    summary = environment.Run()
    assert summary.ExitCode() == status and (summary.snapshot.failure is None if failure is None
        else summary.snapshot.failure.code is failure), (
        "Native failure may survive custody but must not mask an independent wrapper failure")
    assert not LocalModelStore(environment.root).Open().objects, (
        "Failed, malformed, timed-out, cancelled or oversized work must not create positive facts")
    replay = product.ReplayRawCli(environment.root, summary.receipt_id)
    assert replay["native_exit_code"] == summary.result.execution.exit_code and (
        replay["historical_observations"] is None), (
        "Raw verification must preserve original failure and never claim successful normalization")


def test_GroupedClosedPortsRemainUnassessedIndividually(environment):
    """A complete provider report cannot invent individual closed ports from its grouped count."""

    environment.state["mode"] = "grouped"
    summary = environment.Run()
    assert summary.ExitCode() == 0 and len(LocalModelStore(environment.root).Open().Objects(
        ObjectKind.PORT)) == 1, "Grouped closed output must retain only the one explicit open port"


@pytest.mark.parametrize("kind", ["policy", "health", "confirmation", "missing-confirmation"])
def test_DeniedOrUnavailableSelectionsNeverExecute(environment, kind):
    """Current permission, local availability and exact separate confirmation remain mandatory."""

    confirmation = PolicyConfirmation("0" * 64, "approval:wrong")

    if kind == "policy":
        environment.state["policy"] = ImpactPolicy("denied-raw")

    elif kind == "health":
        environment.state["health"] = AdapterHealthState.UNAVAILABLE

    elif kind == "missing-confirmation":
        confirmation = None

    with pytest.raises((PermissionError, product.PortScanUnavailableError)):
        environment.runner.run(product.RunRawCli(*environment.Arguments(),
            confirmation=confirmation, clock=environment.clock))

    assert environment.state["executed"] == 0, (
        "Denied or unavailable native execution must not start")

    if kind == "policy":
        assert environment.state["health_calls"] == 0, (
            "Current policy denial must precede even the bounded local version observation")


@pytest.mark.parametrize("boundary", ["launch", "persistence"])
def test_RevokedCurrentPermissionStopsTheSelectedBoundary(environment, boundary):
    """An exact confirmation cannot renew or substitute for revoked current capability authority."""

    def Revoke():
        """Change the trusted current policy at the selected original launch or Save boundary."""

        environment.state["policy"] = ImpactPolicy("revoked-raw")

    environment.state["before_launch" if boundary == "launch" else "after_launch"] = Revoke
    summary = environment.Run()
    assert summary.ExitCode() == 3 and (
        summary.snapshot.failure.code is JobFailureCode.AUTHORIZATION), (
        "Fresh authority revocation must remain a denial rather than clean native completion")
    assert environment.state["executed"] == (0 if boundary == "launch" else 1), (
        "The recorded launch count must match the actual independently selected denial boundary")
    assert not LocalModelStore(environment.root).Open().objects, (
        "Revoked authority must prevent normalized model persistence")


@pytest.mark.parametrize("owner", ["model", "workspace"])
def test_LostSaveAcknowledgementsRemainUnconfirmedWithoutRetry(environment, monkeypatch, owner):
    """Real committed state with an injected missing ACK cannot inherit the native zero status."""

    storage = LocalModelStore if owner == "model" else LocalWorkspaceStore
    original = storage.Save
    calls = []

    def Lost(self, *arguments, **options):
        """Commit using the actual storage owner once and then lose its acknowledgement."""

        calls.append(True)
        original(self, *arguments, **options)

        raise OSError("synthetic lost acknowledgement")

    monkeypatch.setattr(storage, "Save", Lost)
    summary = environment.Run()
    assert summary.ExitCode() == 4 and summary.snapshot.failure.code is JobFailureCode.STORAGE, (
        "Missing canonical persistence acknowledgement must remain a wrapper storage failure")
    assert calls == [True] and summary.ToDict()[owner + "_commit"] == "unconfirmed", (
        "A lost ACK must remain attributed to its original owner without Save retry or repair")


@pytest.mark.parametrize("receipt_id", ["", "../record", "sha256:short", "sha256:" + "0" * 64])
def test_UnknownHistoricalReceiptCannotInferOriginalCustody(environment, receipt_id):
    """A path, malformed hash or unattached identity cannot select historical native evidence."""

    with pytest.raises(ValueError):
        product.ReplayRawCli(environment.root, receipt_id)


@pytest.mark.parametrize("role", ["stdout", "stderr", product.RAW_CLI_RECEIPT_ROLE])
def test_TamperedOriginalBytesRefuseHistoricalReplay(environment, role):
    """Changed raw stream or receipt bytes cannot retain their original evidence identity."""

    summary = environment.Run()
    record = next(item.evidence for item in summary.snapshot.artifacts
        if item.evidence.reference.role == role)
    (environment.root / "evidence" / record.reference.locator).write_bytes(b"tampered")

    with pytest.raises((ValueError, product.EvidenceError)):
        product.ReplayRawCli(environment.root, summary.receipt_id)


@pytest.mark.parametrize("field", ["profile", "extra", "custody", "model_commit", "model_basis",
    "version_basis", "policy_reference", "intent_sha256", "invocation", "stream", "plan"])
def test_RehashedReceiptCannotReplaceIndependentOriginalAssociations(environment, field):
    """A self-consistent new blob cannot invent the original command, profile or confirmation."""

    summary = environment.Run()
    store = LocalEvidenceStore(environment.root / "evidence")
    receipt = store.Get(summary.receipt_id)
    document = json.loads(store.Read(receipt.reference))

    if field == "extra":
        document["extra"] = "not an original field"

    elif field == "invocation":
        document["invocation"]["argv"][-1] = "127.0.0.2"

    elif field == "stream":
        document["original_role_ids"]["stdout"] = document["original_role_ids"]["stderr"]

    elif field == "plan":
        document["policy_plan"]["confirmation_required"] = False

    else:
        document[field] = {"profile": "wrong.v1", "custody": "partial", "model_commit": "false",
            "model_basis": True, "version_basis": "assumed", "policy_reference": "foreign:policy",
            "intent_sha256": "0" * 64}[field]

    forged = store.Put(SerializeContract(document).encode(), product.RAW_CLI_RECEIPT_ROLE,
        "application/json", receipt.provenance)
    owner = LocalWorkspaceStore(environment.root)
    workspace = owner.Open()
    owner.Save(replace(workspace, evidence_references=(*workspace.evidence_references,
        forged.reference), evidence_record_references=(*workspace.evidence_record_references,
            forged.evidence_id)))

    with pytest.raises(ValueError):
        product.ReplayRawCli(environment.root, forged.evidence_id)
