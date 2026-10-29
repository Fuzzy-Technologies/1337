# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local export namespace grammar and shared dispatch over explicitly inert process outcomes."""

import io
import json
import shlex

import pytest

from fuzzy1337 import local_image_commands
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY
from fuzzy1337.shell import InteractiveShell
from tests.unit.test_local_image_material import LINUX
from tests.unit.test_local_image_material import SelectedMaterial as SelectedMaterial
from tests.unit.test_local_image_policy import NOW
from tests.unit.test_local_image_policy import OriginalOperation as OriginalOperation
from tests.unit.test_local_image_workflow import ExportCase as ExportCase


def Arguments(root):
    """Select a source descriptor without discovering Docker or granting authority."""

    return ["image", "export-local", str(root), "--reference", "owned:local", "--owner",
        "actor:local", "--executable", str(root.parent / "selected-docker"),
        "--socket", str(root.parent / "docker.sock"), "--read-consent-reference", "read:local"]


def test_PureLocalSourcePlanNeedsNoWorkspaceOrDaemon(tmp_path, capsys):
    """Installed grammar can print a registrable descriptor without any selected reads."""

    root = tmp_path / "absent"
    assert Main([*Arguments(root), "--plan", "--json"]) == 0, (
        "Explicit source planning must remain pure and nonexecuting."
    )
    plan = json.loads(capsys.readouterr().out)
    assert not root.exists() and plan["execution_authorized"] is False and (
        plan["archive_scan_requires_separate_scope"] is True
    ), "A source descriptor must not create a workspace, launch Docker or authorize a scan."


@pytest.mark.parametrize("options", ([], ["--plan", "--approve-local-image"],
    ["--plan", "--scope", "local"], ["--plan", "--policy", "policy.json"],
    ["--plan", "--events-json"], ["--scope", "local", "--policy", "policy.json"]))
def test_InvalidAuthorityCombinationsRefuseBeforeWorkspaceReads(tmp_path, capsys, options):
    """Pure planning and independently approved execution have closed separate declarations."""

    root = tmp_path / "absent"
    assert Main([*Arguments(root), *options, "--json"]) == 2, (
        "Ambiguous or missing explicit authority must remain configuration refusal."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration" and (
        not root.exists()
    ), "Configuration refusal must precede selected material and workspace creation."


@pytest.mark.parametrize("option,value", (("--reference", "implicit-latest"),
    ("--reference", "https://remote.invalid/owned:local"), ("--executable", "relative"),
    ("--socket", "/run//docker.sock"), ("--socket", "/run/../docker.sock")))
def test_OriginalLocalSelectionSpellingRefusesBeforeReads(tmp_path, capsys, option, value):
    """Normalization must not hide an ambiguous endpoint or implicit image identity."""

    root = tmp_path / "absent"
    assert Main([*Arguments(root), option, value, "--plan", "--json"]) == 2, (
        "Malformed exact source declarations must fail before selected reads."
    )
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "invalid_configuration" and (
        not root.exists()
    ), "Rejected source syntax must not become a missing workspace or execution failure."


@LINUX
def test_CliAndShellDispatchSameInertExportOwner(export_case, tmp_path, capsys, monkeypatch):
    """The CLI and interactive route share one explicit product owner and source descriptor."""

    selection, context, _, _ = export_case
    policy = tmp_path / "policy.json"
    policy.write_text(SerializeContract(context.policy))
    arguments = [*Arguments(selection.workspace_root), "--scope", context.scope.scope_id,
        "--policy", str(policy), "--approve-local-image", "--json"]
    original = local_image_commands.ExportLocalImage

    async def Export(*args, **kwargs):
        """Select only the inert fixture clock while delegating the actual product owner."""

        return await original(*args, **kwargs, clock=lambda: NOW)

    monkeypatch.setattr(local_image_commands, "ExportLocalImage", Export)
    assert Main(arguments) == 0, (
        "The CLI must delegate the actual explicitly approved export owner."
    )
    document = json.loads(capsys.readouterr().out)
    assert document["state"] == "completed" and document["archive_sha256"] is not None, (
        "The CLI must expose the actual acknowledged product archive pin."
    )
    output = io.StringIO()
    shell = InteractiveShell(stdin=io.StringIO(), stdout=output)
    shell.onecmd("image " + shlex.join(
        [*Arguments(selection.workspace_root)[1:], "--plan", "--json"]))
    plan = json.loads(output.getvalue())
    assert plan["execution_authorized"] is False and (
        COMMAND_REGISTRY.Resolve("image") is not None
    ), (
        "Interactive dispatch and central discovery must expose the same pure source plan."
    )
