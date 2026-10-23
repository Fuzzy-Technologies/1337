# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise first-party web detection through the actual CLI and foreground shell."""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.cli import Main
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.shell import InteractiveShell
from tests.web_vulnerability_helpers import OwnedWebVulnerabilityTarget


def Setup(root: Path, url: str) -> list[str]:
    """Create explicit local scope and serialized capability policy through product commands."""

    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Owned native CLI acceptance"], output) == 0, "Workspace creation failed."
    now = datetime.now(UTC)
    scope_arguments = ["create", str(root), "--id", "local", "--allow-url", url,
        "--allow-ip", "127.0.0.1", "--grant-consent", "--owner", "operator:owned",
        "--consent-reference", "consent:owned-native-cli",
        "--valid-from", (now - timedelta(minutes=1)).isoformat(),
        "--valid-until", (now + timedelta(minutes=10)).isoformat()]
    assert RunCommands("scope", scope_arguments, output) == 0, "Explicit scope creation failed."
    policy = ImpactPolicy("owned-native-web", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                           ImpactLevel.STANDARD),))
    policy_path = root / "native-policy.json"
    policy_path.write_text(SerializeContract(policy), encoding="utf-8")

    return ["web", str(root), "--check", "git-head-exposure", "--scope", "local",
        "--owner", "operator:owned", "--target", url, "--policy", str(policy_path)]


def Plan(arguments: list[str]) -> dict:
    """Obtain the real read-only plan with a machine-readable intent digest."""

    output = StringIO()
    assert RunCommands("scan", [*arguments, "--plan"], output) == 0, "Planning failed."

    return json.loads(output.getvalue())


def Confirm(arguments: list[str], plan: dict) -> list[str]:
    """Use the existing policy intent hash and a separate explicit confirmation reference."""

    return [*arguments, "--confirm-plan", plan["policy_plan"]["intent_sha256"],
        "--confirmation-reference", "approval:owned-native-cli"]


def test_NativeWebCliRequiresConfirmationThenPersistsARealFinding(tmp_path, capsys):
    """Deny before contact, then execute the first-party worker and reopen its canonical Finding."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace with spaces"
        arguments = Setup(root, service.Url("git-exposed"))
        before = service.Observe()
        plan = Plan(arguments)
        assert service.Observe() == before, "Read-only planning contacted the target."
        assert Main(["scan", *arguments, "--json"]) == 3, "Unconfirmed STANDARD work ran."
        denied = json.loads(capsys.readouterr().out)
        assert denied["state"] == "failed", "Denial must retain a truthful failure state."
        assert service.Observe() == before, "Missing confirmation allowed a network request."
        assert Main(["scan", *Confirm(arguments, plan), "--json"]) == 0, (
            "The confirmed first-party CLI failed its owned positive case."
        )
        summary = json.loads(capsys.readouterr().out)
        assert summary["state"] == "completed", "A successful worker did not complete its job."
        findings = Findings(LocalModelStore(root).Open())
        assert len(findings) == 1 and findings[0].check_id == "native.git-head-exposure", (
            "Native detection must create the canonical first-party Finding."
        )
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "Actual workspace reopening failed to verify retained acquisitions."
        )
        capsys.readouterr()


def test_NativeWebForegroundShellUsesTheSamePlanAndExecution(tmp_path):
    """The foreground shell dispatches the same first-party check without a second scan engine."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        arguments = Setup(root, service.Url("git-fixed"))
        plan = Plan(arguments)
        output = StringIO()
        shell = InteractiveShell(stdin=StringIO(), stdout=output)
        assert not shell.onecmd(shlex.join(["scan", *Confirm(arguments, plan), "--json"])), (
            "The foreground scan must keep the interactive shell alive."
        )
        summary = json.loads(output.getvalue())
        assert summary["state"] == "completed" and not Findings(LocalModelStore(root).Open()), (
            "The fixed route must complete the finite predicate without a false Finding."
        )
        assert shell.lastcmd == "scan", "Shell history must retain only the scan namespace."


@pytest.mark.parametrize("extra", [
    ["--confirm-plan", "a" * 64],
    ["--confirmation-reference", "approval:owned"],
    ["--plan", "--confirm-plan", "a" * 64, "--confirmation-reference", "approval:owned"],
    ["--plan", "--events-json"],
    ["--events-json", "--json"],
])
def test_NativeWebCliRejectsAmbiguousConfirmationWithoutContact(tmp_path, extra):
    """Reject incomplete or conflicting confirmation/output modes at the argument boundary."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        arguments = Setup(tmp_path / "workspace", service.Url("git-exposed"))
        before = service.Observe()

        with pytest.raises(SystemExit) as error:
            Main(["scan", *arguments, *extra])

        assert error.value.code == 2, "Invalid command combinations must exit with usage status."
        assert service.Observe() == before, "Invalid CLI arguments must prevent target contact."


def test_NativeWebCliStreamsActualEventsAndTerminalSummary(tmp_path):
    """Separate event records from the terminal summary without copying transient HTTP bytes."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        arguments = Setup(tmp_path / "workspace", service.Url("git-exposed"))
        output = StringIO()
        assert RunCommands("scan", [*Confirm(arguments, Plan(arguments)), "--events-json"],
                           output) == 0, "The confirmed event-stream workflow failed."
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        assert records[-1]["type"] == "summary", "The stream lost its terminal summary."
        assert records[-1]["summary"]["state"] == "completed", "Terminal state is inconsistent."
        assert any(record["type"] == "event" for record in records), "No real job events emitted."
        assert "refs/heads/owned-fixture" not in output.getvalue(), (
            "Transient Git HEAD response material leaked into CLI presentation."
        )


@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://127.0.0.1:80/",
                                "HTTP://127.0.0.1/"])
def test_NativeWebCliRefusesCanonicalizingRawSelectedUrls(tmp_path, url):
    """Raw operator spelling must be validated before Target canonicalization can hide drift."""

    arguments = Setup(tmp_path / "workspace", "http://127.0.0.1/")
    arguments[arguments.index("--target") + 1] = url
    output = StringIO()
    assert RunCommands("scan", [*arguments, "--plan"], output) == 2, (
        "The native CLI silently canonicalized an unsupported selected URL spelling."
    )
    assert json.loads(output.getvalue())["failure"]["code"] == "invalid_configuration", (
        "Raw spelling refusal must retain the invalid-input classification."
    )
