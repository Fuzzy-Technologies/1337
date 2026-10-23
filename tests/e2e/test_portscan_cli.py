# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual finite TCP-connect CLI composition with the existing no-network synthetic producer."""

from __future__ import annotations

import json
import os
import shlex
import sys
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337.adapters import ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.portscan import PORT_SCAN_CAPABILITY, PORT_SCAN_PROVIDER_ID
from fuzzy1337.scan_commands import Ports, RunCommands
from fuzzy1337.shell import InteractiveShell


def Setup(root: Path) -> list[str]:
    """Create explicit IP authority and the original loopback-only synthetic executable."""

    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "ports-cli",
        "--name", "Owned synthetic ports CLI"], output) == 0, "Workspace creation failed."
    now = datetime.now(UTC)
    assert RunCommands("scope", ["create", str(root), "--id", "local", "--allow-ip", "127.0.0.1",
        "--grant-consent", "--owner", "operator:owned", "--consent-reference", "consent:ports-cli",
        "--valid-from", (now - timedelta(minutes=1)).isoformat(),
        "--valid-until", (now + timedelta(minutes=10)).isoformat()], output) == 0, (
            "Explicit IP scope creation failed."
        )
    policy = ImpactPolicy("ports-cli", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(PORT_SCAN_CAPABILITY, PORT_SCAN_PROVIDER_ID,
                                          ImpactLevel.STANDARD),))
    policy_path = root / "policy.json"
    policy_path.write_text(SerializeContract(policy), encoding="utf-8")
    fixture = Path(__file__).parents[1] / "fixtures/nmap/synthetic_nmap.py"
    executable = root / "owned synthetic nmap"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text(encoding="utf-8"),
                          encoding="utf-8")
    executable.chmod(0o700)

    return ["ports", str(root), "--scope", "local", "--owner", "operator:owned",
        "--target", "127.0.0.1", "--ports", "443,80", "--timeout", "10",
        "--policy", str(policy_path), "--executable", str(executable)]


@pytest.mark.parametrize("value", ["", "80-90", "http", "80,", "+80", "80, 443", "８０"])
def test_PortGrammarAcceptsOnlyExplicitDecimalLiterals(value):
    """Ranges, names, empty entries, and ambiguous numeric spellings stay outside the CLI."""

    with pytest.raises(ValueError):
        Ports(value)


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_ActualCliPlansConfirmsSavesAndReopens(workspace_path, capsys):
    """The real CLI denies unconfirmed work, then persists the genuine synthetic process result."""

    root = workspace_path
    arguments = Setup(root)
    assert Main(["scan", *arguments, "--plan", "--json"]) == 0, "Actual planning failed."
    plan = json.loads(capsys.readouterr().out)
    assert plan["workflow"] == "ports" and plan["confirmation_required"], (
        "Finite STANDARD planning omitted its explicit approval boundary."
    )
    assert LocalModelStore(root).Open().revision == 0, "Planning changed canonical model state."
    assert Main(["scan", *arguments, "--json"]) == 3, "Unconfirmed STANDARD work executed."
    denied = json.loads(capsys.readouterr().out)
    assert denied["job"]["artifacts"] == [], "Denied execution invented acquisitions."
    approved = [*arguments, "--confirm-plan", plan["intent_sha256"],
                "--confirmation-reference", "approval:owned-ports-cli"]
    assert Main(["scan", *approved, "--events-json"]) == 0, "Confirmed actual CLI execution failed."
    documents = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    summary = documents[-1]["summary"]
    assert summary["state"] == "completed" and summary["object_counts"]["port"] == 2, (
        "Real synthetic process results did not reach the canonical model."
    )
    assert summary["object_counts"]["finding"] == 0, "An open port became a Finding."
    assert Main(["workspace", "open", str(root), "--json"]) == 0, "Evidence reopen failed."
    capsys.readouterr()


@pytest.fixture
def workspace_path(tmp_path):
    """Keep executable shebang paths simple while exercising a workspace path containing spaces."""

    return tmp_path / "owned ports workspace"


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_ForegroundShellUsesTheSameGovernedProductRoute(workspace_path):
    """The interactive entry point preserves exact planning/approval and canonical identities."""

    arguments = Setup(workspace_path)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd("scan " + shlex.join([*arguments, "--plan"]))
    plan = json.loads(output.getvalue())
    output.seek(0)
    output.truncate()
    shell.onecmd("scan " + shlex.join([*arguments, "--confirm-plan", plan["intent_sha256"],
        "--confirmation-reference", "approval:ports-shell"]))
    assert "TCP Port Scan completed" in output.getvalue(), "Foreground shell did not complete."
    assert len(LocalModelStore(workspace_path).Open().Objects(ObjectKind.PORT)) == 2, (
        "Foreground shell bypassed the shared canonical projection."
    )


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_MissingProviderAndUnsupportedProfileRemainTruthful(workspace_path, capsys):
    """Missing optional software is a provider failure and arbitrary Nmap flags remain refused."""

    arguments = Setup(workspace_path)
    selected = [*arguments[:-1], str(workspace_path / "missing-nmap")]
    assert Main(["scan", *selected, "--plan", "--json"]) == 4, "Missing provider became success."
    unavailable = json.loads(capsys.readouterr().out)
    assert unavailable["failure"]["code"] == "provider", "Provider absence was misclassified."
    with pytest.raises(SystemExit) as refused:
        Main(["scan", *arguments, "--script", "unselected-value", "--json"])

    assert refused.value.code == 2, "Arbitrary Nmap flags entered the finite product grammar."
    captured = capsys.readouterr()
    assert "unselected-value" not in captured.out + captured.err, (
        "Rejected argument values leaked into product diagnostics."
    )


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
def test_ActualExecutorTimeoutPreservesFlushedPartialStreamsAndReopens(workspace_path, capsys):
    """The process deadline leaves bounded owning-job time to retain acquired partial evidence."""

    root = workspace_path
    arguments = Setup(root)
    fixture = Path(__file__).parents[1] / "fixtures/nmap/delayed_nmap.py"
    executable = root / "owned delayed nmap"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text(encoding="utf-8"),
                          encoding="utf-8")
    executable.chmod(0o700)
    arguments[-1] = str(executable)
    arguments[arguments.index("--timeout") + 1] = "1"
    assert Main(["scan", *arguments, "--plan", "--json"]) == 0, "Timeout plan failed."
    plan = json.loads(capsys.readouterr().out)
    assert plan["invocation"]["timeout_seconds"] == 1, "Process deadline changed."
    assert not executable.with_suffix(".ready").exists(), "Planning launched the delayed producer."
    assert Main(["scan", *arguments, "--confirm-plan", plan["intent_sha256"],
        "--confirmation-reference", "approval:timeout-custody", "--json"]) == 4, (
            "An actual executor deadline must remain a failed product run."
        )
    summary = json.loads(capsys.readouterr().out)
    assert executable.with_suffix(".ready").read_text(encoding="utf-8") == (
        "partial-streams-flushed\n"
    ), "The owned process never confirmed that both partial streams were flushed."
    assert summary["job"]["failure"]["code"] == "timeout", "Process timeout truth was lost."
    artifacts = summary["job"]["artifacts"]
    assert len(artifacts) == 2, "Owning-job cancellation discarded original partial streams."
    store = LocalEvidenceStore(root / "evidence")
    streams = {artifact["evidence"]["reference"]["role"]:
               store.Read(store.Get(artifact["evidence"]["evidence_id"]).reference)
               for artifact in artifacts}
    assert streams == {
        "stdout": b'<nmaprun scanner="nmap">owned-timeout-partial\n',
        "stderr": b"Owned delayed synthetic stderr; no network activity\n",
    }, "Original timed-out process bytes changed or disappeared."

    for artifact in artifacts:
        record = store.Get(artifact["evidence"]["evidence_id"])
        assert record.provenance.execution.state is ExecutionState.TIMED_OUT, (
            "Evidence changed the actual executor timeout into another terminal state."
        )
        assert record.provenance.invocation_sha256 == plan["policy_plan"]["invocation_sha256"], (
            "Retained timeout output lost its original approved invocation binding."
        )

    assert LocalModelStore(root).Open().revision == 0, "Timeout produced canonical success."
    assert summary["object_counts"]["finding"] == 0, "Partial XML produced a Finding."
    assert Main(["workspace", "open", str(root), "--json"]) == 0, (
        "A timed-out workspace could not reopen and verify its retained originals."
    )
    capsys.readouterr()
