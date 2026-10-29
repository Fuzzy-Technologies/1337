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
from fuzzy1337.adapters.native_web import NATIVE_FILE_CANARY_CAPABILITY, NATIVE_FILE_CANARY_CHECK_ID
from fuzzy1337.cli import Main
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.shell import InteractiveShell
from tests.web_file_access_helpers import OwnedWebFileAccessTarget
from tests.web_vulnerability_helpers import OwnedWebVulnerabilityTarget


def Setup(root: Path, url: str, *, check: str = "git-head-exposure") -> list[str]:
    """Create explicit local scope and serialized capability policy through product commands."""

    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Owned native CLI acceptance"], output) == 0, "Workspace creation failed."
    now = datetime.now(UTC)
    scope_flag = "--allow-canary-url" if check == "file-canary-disclosure" else "--allow-url"
    scope_arguments = ["create", str(root), "--id", "local", scope_flag, url,
        "--allow-ip", "127.0.0.1", "--grant-consent", "--owner", "operator:owned",
        "--consent-reference", "consent:owned-native-cli",
        "--valid-from", (now - timedelta(minutes=1)).isoformat(),
        "--valid-until", (now + timedelta(minutes=10)).isoformat()]
    assert RunCommands("scope", scope_arguments, output) == 0, "Explicit scope creation failed."
    policy = ImpactPolicy("owned-native-web", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(NATIVE_FILE_CANARY_CAPABILITY
            if check == "file-canary-disclosure" else NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                           ImpactLevel.STANDARD),))
    policy_path = root / "native-policy.json"
    policy_path.write_text(SerializeContract(policy), encoding="utf-8")

    return ["web", str(root), "--check", check, "--scope", "local",
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


def test_CanaryScopeFlagsKeepExplicitAllowAndExclusion(tmp_path):
    """Dedicated registration preserves full query targets and explicit exclusion rules."""

    root = tmp_path / "workspace"
    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Closed scope registration"], output) == 0, "Workspace creation failed."
    output.seek(0)
    output.truncate()
    url = "http://127.0.0.1/files/vulnerable?name=..%2Fprivate%2Fcanary.txt"
    assert RunCommands("scope", ["create", str(root), "--id", "local",
        "--allow-canary-url", url, "--exclude-canary-url", url], output,
        json_output=True) == 0, (
            "Dedicated closed-profile registration failed."
        )
    scope = json.loads(output.getvalue())
    expected = [{"kind": "url", "value": url}]
    assert scope["targets"] == scope["allow"] == scope["exclusions"] == expected, (
        "Registration changed the exact selected allow/exclusion URL."
    )


@pytest.mark.parametrize("flag", ["--allow-canary-url", "--exclude-canary-url",
                                  "--allow-url", "--exclude-url"])
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/files/vulnerable?name=..%2fprivate%2fcanary.txt",
    "http://192.0.2.1/files/vulnerable?name=..%2Fprivate%2Fcanary.txt",
    "http://127.0.0.1/other?name=..%2Fprivate%2Fcanary.txt",
])
def test_CanaryScopeFlagsRefuseOutOfProfileAndKeepGenericQueryRefusal(tmp_path, flag, url):
    """New flags stay closed while generic flags continue refusing every supplied query."""

    root = tmp_path / "workspace"
    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Closed scope rejection"], output) == 0, "Workspace creation failed."
    assert RunCommands("scope", ["create", str(root), "--id", "local",
        "--allow-ip", "127.0.0.1", flag, url], output) == 2, (
            "Scope registration admitted an unsupported raw query URL."
        )


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


def test_CanaryCliRequiresExactConfirmationAndReopensItsFinding(tmp_path, capsys):
    """The installed CLI exposes the closed owned check through the existing confirmation owner."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        arguments = Setup(root, service.Url("private-traversal"), check="file-canary-disclosure")
        before = service.Observe()
        plan = Plan(arguments)
        assert plan["check_id"] == NATIVE_FILE_CANARY_CHECK_ID, "CLI selected a different check."
        assert service.Observe() == before, "CLI planning contacted the owned target."
        assert Main(["scan", *arguments, "--json"]) == 3, "Unconfirmed local canary work ran."
        capsys.readouterr()
        assert service.Observe() == before, "Missing confirmation caused target contact."
        assert Main(["scan", *Confirm(arguments, plan), "--json"]) == 0, (
            "The explicitly confirmed closed canary CLI failed."
        )
        result = json.loads(capsys.readouterr().out)
        assert result["check_id"] == NATIVE_FILE_CANARY_CHECK_ID, "Summary lost check identity."
        findings = Findings(LocalModelStore(root).Open())
        assert len(findings) == 1 and findings[0].check_id == NATIVE_FILE_CANARY_CHECK_ID, (
            "Actual canary execution did not persist its canonical Finding."
        )
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "CLI reopen failed to verify the original canary execution evidence."
        )
        capsys.readouterr()


@pytest.mark.parametrize("mutation", ["lowercase-escape", "extra-query", "other-path", "remote"])
def test_CanaryCliRefusesRawInputsBeforeCanonicalizationOrContact(tmp_path, capsys, mutation):
    """Raw malformed spelling and out-of-pack destinations cannot hide behind Target rewriting."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        original = service.Url("private-traversal")
        arguments = Setup(tmp_path / "workspace", original, check="file-canary-disclosure")
        changed = original

        if mutation == "lowercase-escape":
            changed = original.replace("%2F", "%2f")

        elif mutation == "extra-query":
            changed += "&extra=hello.txt"

        elif mutation == "other-path":
            changed = original.replace("/files/vulnerable", "/other")

        else:
            changed = original.replace("127.0.0.1", "192.0.2.1")

        arguments[arguments.index("--target") + 1] = changed
        before = service.Observe()
        assert Main(["scan", *arguments, "--plan", "--json"]) == 2, (
            "The raw CLI admitted an input outside its exact local request profile."
        )
        capsys.readouterr()
        assert service.Observe() == before, "Refused raw input caused an owned target request."


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
