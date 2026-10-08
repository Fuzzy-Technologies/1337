# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real CLI and shell consumer contracts for read-only component inspection."""

from __future__ import annotations

import json
import socket
import subprocess
from io import StringIO

import pytest

from fuzzy1337 import cli, component_health
from fuzzy1337.cli import Main
from fuzzy1337.shell import InteractiveShell, WorkbenchUpdate


@pytest.fixture
def local_inspection(monkeypatch):
    """Provide deterministic metadata and deny network/process side effects."""

    def ForbiddenOperation(*_args, **_kwargs):
        """Fail if component inspection attempts a remote or executable operation."""

        raise AssertionError(
            "Component inspection must not contact a network or execute processes."
        )

    monkeypatch.setattr(component_health, "version", lambda _: "0.1.8")
    monkeypatch.setattr(socket, "create_connection", ForbiddenOperation)
    monkeypatch.setattr(socket.socket, "connect", ForbiddenOperation)
    monkeypatch.setattr(socket.socket, "connect_ex", ForbiddenOperation)
    monkeypatch.setattr(subprocess, "run", ForbiddenOperation)
    monkeypatch.setattr(subprocess, "Popen", ForbiddenOperation)


def test_CliJsonPreservesVersionedLocalFactsAndUncheckedUpdateState(local_inspection, capsys):
    """Exercise the real CLI collector and JSON renderer without hidden actions."""

    assert Main(["update", "--json"]) == 0, "Healthy required core checks must return zero."
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert set(report) == {
        "schemaVersion", "mode", "updateAvailability", "mutationsPerformed", "components",
        "exitCode",
    }, "The versioned JSON report fields must remain explicit for its consumers."
    assert (report["schemaVersion"], report["mode"], report["updateAvailability"]) == (
        1, "inspect", "not_checked"
    ), "Local metadata cannot establish remote update freshness."
    assert report["mutationsPerformed"] is False and report["exitCode"] == 0, (
        "The update foundation must inspect without performing updates."
    )
    assert report["components"][1]["installedVersion"] == "0.1.8", (
        "Machine output must retain actual installed core metadata."
    )
    assert [value["health"] for value in report["components"][2:]] == ["unavailable"] * 3, (
        "Unimplemented inventories must be explicit rather than fabricated healthy results."
    )
    assert not captured.err, "A successful local inspection must not write an error."


def test_CliHumanOutputExplainsManualReviewWithoutPromisingFreshness(local_inspection, capsys):
    """Exercise the human entry point and preserve the update mutation boundary."""

    assert Main(["update"]) == 0, "The human command must share the required-check result."
    output = capsys.readouterr().out

    assert "read-only inspection" in output and "No updates were performed." in output, (
        "The update command must make its non-mutation behavior visible."
    )
    assert "not checked" in output and "approved environment/package workflow" in output, (
        "Operators need a truthful manual next step without an invented latest version."
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["update", "--apply"], ["update", "--force"], ["update", "--check"],
        ["update", "arbitrary-tool"], ["doctor", "--json"], ["--json"],
    ],
)
def test_CliRejectsUnsupportedMutationAndUnrelatedJsonOptions(arguments, capsys):
    """Reject unsupported update modes before any component operation occurs."""

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == 2, (
        "Unsupported update and output options must fail argument parsing."
    )
    assert "error:" in capsys.readouterr().err, "Rejected options need an actionable CLI error."


def test_MissingCoreFailsBothConsumersWithoutLeavingTheShell(local_inspection, monkeypatch, capsys):
    """Preserve required failure status and keep interactive recovery available."""

    def MissingMetadata(_distribution):
        """Represent an installation whose core distribution cannot be found."""

        raise component_health.PackageNotFoundError

    monkeypatch.setattr(component_health, "version", MissingMetadata)
    monkeypatch.setattr(cli, "version", MissingMetadata)
    assert Main(["update", "--json"]) == 1, "Missing core metadata must fail the CLI check."
    assert json.loads(capsys.readouterr().out)["exitCode"] == 1, (
        "JSON must retain the failing required-check status."
    )
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)

    assert not shell.onecmd("update"), "A failed inspection must keep the shell available."
    assert "required core checks failed" in output.getvalue(), (
        "The interactive consumer cannot turn a failed core check into success."
    )


def test_VersionKeepsImmediateExitAndItsMetadataFailureContract(monkeypatch, capsys):
    """Read version metadata only for --version and preserve its existing failure."""

    calls = []

    def InstalledMetadata(distribution):
        """Record the specific requested distribution lookup."""

        calls.append(distribution)

        return "0.1.8"

    monkeypatch.setattr(cli, "version", InstalledMetadata)
    assert Main(["help"]) == 0, "Help must work without requiring distribution metadata."
    capsys.readouterr()
    assert not calls, "Unrelated commands must not eagerly resolve version metadata."

    with pytest.raises(SystemExit) as caught:
        Main(["--version", "unknown-command"])

    assert caught.value.code == 0 and calls == ["1337"], (
        "Version must retain argparse's immediate zero exit and exact distribution lookup."
    )
    captured = capsys.readouterr()
    assert captured.out == "1337 0.1.8\n" and not captured.err, (
        "The lazy version action must preserve the existing version output stream."
    )

    def MissingMetadata(_distribution):
        """Preserve the existing explicit missing-distribution exception."""

        raise component_health.PackageNotFoundError

    monkeypatch.setattr(cli, "version", MissingMetadata)

    with pytest.raises(component_health.PackageNotFoundError):
        Main(["--version"])


def test_ShellSharesJsonOutputWithoutDrainingWorkbenchEvents(local_inspection, capsys):
    """Keep singular component inspection separate from plural event rendering."""

    assert Main(["update", "--json"]) == 0, "The reference CLI inspection must succeed."
    expected = json.loads(capsys.readouterr().out)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.PublishUpdate(WorkbenchUpdate("progress", "queued event"))
    shell.onecmd("update --json")

    assert json.loads(output.getvalue()) == expected, (
        "CLI and shell must consume the same local report and JSON boundary."
    )
    output.seek(0)
    output.truncate()
    shell.onecmd("update --apply")
    shell.onecmd("updates")
    shell.onecmd("help update")

    assert output.getvalue().splitlines() == [
        "usage: update [--json]",
        "[progress] queued event",
        "update [--json]: inspect local component health without installing updates.",
    ], "Rejected update modes must preserve queued events and explain supported usage."
    assert "update" in shell.completenames("upd"), (
        "Interactive component inspection must appear in command discovery."
    )
