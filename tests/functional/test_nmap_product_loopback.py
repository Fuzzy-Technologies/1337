# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent genuine Nmap product oracle using only two pytest-owned loopback sockets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobState
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
from fuzzy1337.portscan import PlanPortScan, PortScanLimits, RunPortScan
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

EVIDENCE = Path("functional-evidence/nmap-product")
PINNED_VERSION = "7.992"
pytestmark = pytest.mark.skipif(
    os.environ.get("FUZZY1337_RUN_NMAP_ACCEPTANCE") != "1",
    reason="Genuine Nmap product acceptance requires an explicit installed-provider opt-in",
)


def Policy() -> ImpactPolicy:
    """Permit only the exact STANDARD TCP-connect capability; confirmation remains separate."""

    return ImpactPolicy("owned-nmap-product", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission("network.tcp-connect", "native.nmap",
                                          ImpactLevel.STANDARD),))


def ScopedWorkspace(root: Path) -> Target:
    """Record explicit current owned-loopback consent without granting unrelated targets."""

    CreateWorkspace(root, "nmap-product", "Owned two-port Nmap product oracle")
    target = Target(TargetKind.IP, "127.0.0.1")
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", "nmap-product", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned-nmap-product",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=10)).isoformat(),
    ), targets=(target,), allow=(target,)))

    return target


def NoConnection(listener: socket.socket) -> None:
    """Require that planning has not established a connection to the owned target."""

    listener.setblocking(False)

    try:
        connection, _ = listener.accept()

    except BlockingIOError:
        return

    connection.close()
    pytest.fail("Read-only port-scan planning contacted the owned listener")


def Console(arguments: list[str]) -> dict:
    """Require machine-readable success from the actual installed isolated product entry point."""

    result = subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", *arguments, "--json"],
        capture_output=True, timeout=40, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")

    return json.loads(result.stdout)


def test_GenuineSdkAndInstalledConsolePreserveOwnedTwoPortOracleAndRelocatedReopen(tmp_path):
    """Preserve real TCP observations through SDK/CLI, custody, model persistence and reopen."""

    selected = os.environ.get("F1337_NMAP_TEST_EXECUTABLE")
    assert selected and Path(selected).is_absolute() and Path(selected).is_file(), (
        "Required genuine Nmap acceptance cannot skip a missing explicit provider"
    )
    root = tmp_path / "workspace with spaces"
    target = ScopedWorkspace(root)
    limits = PortScanLimits(timeout_seconds=15)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    policy_path = root / "owned-policy.json"
    policy_path.write_text(SerializeContract(Policy()), encoding="utf-8")

    with socket.socket() as listening, socket.socket() as closed:
        listening.bind(("127.0.0.1", 0))
        listening.listen(8)
        closed.bind(("127.0.0.1", 0))
        open_port, closed_port = listening.getsockname()[1], closed.getsockname()[1]
        ports = (open_port, closed_port)
        plan = PlanPortScan(root, "local", target, "operator:owned", ports, selected,
                            Policy, limits=limits)
        NoConnection(listening)
        assert plan.invocation.provider_version == PINNED_VERSION, "Provider version differs"
        assert plan.invocation.argv == (selected, "--unprivileged", "-n", "-Pn", "-sT",
            "-p", ",".join(str(port) for port in sorted(ports)), "--host-timeout", "15s",
            "-oX", "-", "127.0.0.1"), "The product changed the reviewed finite command"
        confirmation = PolicyConfirmation(plan.policy_plan.intent_sha256,
                                            "approval:owned-nmap-sdk")
        observed = []
        summary = asyncio.run(RunPortScan(root, "local", target, "operator:owned", ports,
            selected, Policy, limits=limits, confirmation=confirmation, on_event=observed.append))
        assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED, (
            "The confirmed genuine SDK job must complete successfully"
        )
        assert observed == list(summary.events), "Actual presentation events lost their owner order"
        assert len(summary.snapshot.artifacts) == 2, "Both original streams need durable custody"
        store = LocalEvidenceStore(root / "evidence")
        roles = {item.evidence.reference.role: item.evidence for item in summary.snapshot.artifacts}
        assert set(roles) == {"stdout", "stderr"}, "Actual stream custody roles differ"

        for role, record in roles.items():
            assert store.Get(record.evidence_id) == record, "Original acquisition record changed"
            assert record.provenance.invocation_sha256 == InvocationDigest(plan.invocation), (
                "Raw custody must bind the exact planned invocation"
            )
            assert record.provenance.tool_version == PINNED_VERSION, "Custody version differs"
            raw = store.Read(record.reference)
            assert hashlib.sha256(raw).hexdigest() == record.reference.sha256, (
                "The actual original stream no longer matches its retained digest"
            )
            (EVIDENCE / (role + ".raw")).write_bytes(raw)

        xml = ElementTree.fromstring(store.Read(roles["stdout"].reference))
        assert xml.get("scanner") == "nmap" and xml.get("version") == PINNED_VERSION, (
            "Original XML provider identity differs from the pinned genuine binary"
        )
        assert xml.find("runstats/finished").get("exit") == "success", "XML completion differs"
        host = xml.find("host")
        assert host is not None and host.find("address").get("addr") == "127.0.0.1", (
            "Original host observation escaped the exact approved loopback target"
        )
        explicit = {int(item.get("portid")): item.find("state").get("state")
                    for item in host.findall("ports/port")}
        assert set(explicit) <= set(ports), "Original tool output escaped the selected finite ports"
        assert explicit.get(open_port) == "open", "The known listening socket must be detected"
        closed_assessment = explicit.get(closed_port)
        assert closed_assessment in (None, "closed"), "The bound non-listener cannot be open"

        if closed_assessment is None:
            assert any(item.get("state") == "closed" and item.get("count") == "1"
                       for item in host.findall("ports/extraports")), (
                "A grouped closed result must retain its actual original provider observation"
            )

        state = LocalModelStore(root).Open()
        hosts = state.Objects(ObjectKind.HOST)
        assert len(hosts) == 1 and hosts[0].identity.key == "127.0.0.1", (
            "Canonical Host must use the existing exact address identity"
        )
        actual_ports = {int(item.attributes["number"]): item
                        for item in state.Objects(ObjectKind.PORT)}
        assert set(actual_ports) == set(explicit), "Grouped output cannot invent individual ports"

        for port, item in actual_ports.items():
            assert item.identity.key == f"host:127.0.0.1/tcp/{port}", "Canonical Port key differs"
            assert item.attributes["state"] == explicit[port], "Canonical port state was invented"
            assert item.provenance and item.provenance[-1].evidence_references, (
                "Canonical port observations require original evidence attribution"
            )

        assert not Findings(state), "Open ports are discovery observations, not vulnerabilities"
        identities = {item.Reference() for item in state.objects}
        arguments = ["scan", "ports", str(root), "--scope", "local", "--owner", "operator:owned",
            "--target", "127.0.0.1", "--ports", ",".join(map(str, ports)), "--timeout", "15",
            "--policy", str(policy_path), "--executable", selected]
        cli_plan = Console([*arguments, "--plan"])
        assert cli_plan["intent_sha256"] == plan.policy_plan.intent_sha256, (
            "Installed CLI and SDK must present the same exact operation intent"
        )
        cli_summary = Console([*arguments, "--confirm-plan", cli_plan["intent_sha256"],
                              "--confirmation-reference", "approval:owned-nmap-console"])
        assert cli_summary["state"] == "completed" and cli_summary["workflow"] == "ports", (
            "The installed genuine port-scan command did not complete its owned workflow"
        )
        repeated = LocalModelStore(root).Open()
        assert {item.Reference() for item in repeated.objects} == identities, (
            "Repeated genuine scans must preserve canonical logical object identities"
        )
        assert not Findings(repeated), "Repeated port discovery cannot create vulnerabilities"
        (EVIDENCE / "sdk-summary.json").write_text(
            json.dumps(summary.ToDict(), sort_keys=True), encoding="utf-8")
        (EVIDENCE / "cli-summary.json").write_text(json.dumps(cli_summary, sort_keys=True),
                                                  encoding="utf-8")
        canonical = CanonicalModelJson(repeated)

    relocated = tmp_path / "relocated workspace"
    shutil.move(str(root), relocated)
    reopened = OpenWorkspace(relocated)
    assert reopened["verified_evidence_records"] == 4, "Relocated reopen lost original acquisitions"
    assert CanonicalModelJson(LocalModelStore(relocated).Open()) == canonical, (
        "Relocation must preserve the exact saved canonical model"
    )
    assert Console(["workspace", "open", str(relocated)]) == reopened, (
        "Installed CLI and SDK must independently verify the same relocated workspace"
    )
    oracle = {"schema_version": 1, "profile": "nmap-owned-two-port-product.v1",
        "target": "127.0.0.1", "open_port": open_port, "bound_closed_port": closed_port,
        "expected": {"listening": "open", "bound_nonlistener": "closed_or_grouped_unassessed",
                     "findings": 0}, "observed": {"explicit_ports": explicit,
                     "bound_closed_assessment": closed_assessment},
        "provider_version": PINNED_VERSION, "invocation_sha256": InvocationDigest(plan.invocation),
        "relocated_reopen": reopened, "result": "passed"}
    (EVIDENCE / "oracle.json").write_text(json.dumps(oracle, sort_keys=True), encoding="utf-8")
    (EVIDENCE / "model.json").write_bytes(canonical)
