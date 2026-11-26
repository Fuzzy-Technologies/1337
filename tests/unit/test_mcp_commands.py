# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the actual offline MCP CLI adapter against isolated local workspace owners."""

from __future__ import annotations

import json
import shlex
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from fuzzy1337 import mcp_commands
from fuzzy1337.bridge_commands import RunBridgeCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.shell import InteractiveShell
from tests.mcp_cli_helpers import (
    BASELINE,
    CHANGED,
    ApproveArguments,
    ImportArguments,
    McpSelection,
)


def Receipt(arguments: list[str], expected: int) -> dict[str, Any]:
    """Run the shared bridge foreground and verify its exact machine exit status.

    Args:
        arguments: Bridge profile and operator selections.
        expected: Exact terminal exit code.

    Returns:
        The decoded version-one machine receipt.
    """

    output = StringIO()
    code = RunBridgeCommands(arguments, output, jsonOutput=True)
    assert code == expected, f"Unexpected MCP status {code}: {output.getvalue()}"
    receipt = json.loads(output.getvalue())
    assert receipt["schema_version"] == 1, "The CLI receipt must declare its version"

    return receipt


def Selection(receipt: dict[str, Any]) -> McpSelection:
    """Use the exact returned immutable handles as the next CLI input.

    Args:
        receipt: A completed import, approval, or review receipt.

    Returns:
        Exact server, snapshot and model revision selection.
    """

    return McpSelection(receipt["server_reference"], receipt["snapshot_reference"],
                        receipt["model_revision"])


def Workspace(root: Path) -> None:
    """Create the real workspace, model and attribution scope for isolated operations.

    Args:
        root: A new test workspace directory.
    """

    CreateWorkspace(root, "mcp-clitest", "Offline MCP test")
    LocalScopeStore(root).Create(ScopeSnapshot("catalog", "mcp-clitest"))


def test_OfflineReceiptSeparatesUnchangedDriftIncompleteAndMissingBaseline(tmp_path: Path) -> None:
    """Exercise the exact exit and receipt contract through imported and stored first-party data.

    Args:
        tmp_path: Unique workspace and fixture output parent.
    """

    root = tmp_path / "work"
    Workspace(root)
    original = Receipt(ImportArguments(root, BASELINE, 0), 0)
    baseline = Selection(original)
    assert original["status"] == "imported" and original["model_changed"], (
        "The import receipt must acknowledge the actual new model revision"
    )
    repeated = Receipt(ImportArguments(root, BASELINE, baseline.revision), 0)
    assert Selection(repeated) == baseline and repeated["model_changed"] is False, (
        "Reacquiring the same baseline must retain the exact immutable selection"
    )
    missing = Receipt(["mcp", "review", str(root), *baseline.Arguments()], 3)
    assert missing["status"] == "no-baseline" and missing["review_reference"] is None, (
        "An unapproved snapshot cannot yield a successful comparison"
    )
    approved = Receipt(ApproveArguments(root, baseline), 0)
    unchanged = Receipt(["mcp", "review", str(root), *Selection(approved).Arguments()], 0)
    assert unchanged["status"] == "unchanged" and unchanged["changes"] == [], (
        "A complete unchanged inventory must yield a successful clean comparison"
    )
    assert unchanged["baseline_decision_reference"] == approved["decision_reference"], (
        "The receipt must identify the exact operator approval"
    )
    source = json.loads(BASELINE.read_bytes())
    source["tools"]["status"] = "incomplete"
    source["tools"]["items"].pop()
    partialFile = tmp_path / "partial.json"
    partialFile.write_text(json.dumps(source), encoding="utf-8")
    partial = Receipt(ImportArguments(root, partialFile, unchanged["model_revision"]), 0)
    incomplete = Receipt(["mcp", "review", str(root), *Selection(partial).Arguments()], 5)
    assert incomplete["status"] == "incomplete" and incomplete["failure"] is None, (
        "Verified incomplete coverage must not be confused with an operational failure"
    )
    assert incomplete["changes"] == [] and incomplete["finding_references"] == [], (
        "Missing declarations under incomplete enumeration cannot establish removal"
    )
    changed = Receipt(ImportArguments(root, CHANGED, incomplete["model_revision"]), 0)
    drift = Receipt(["mcp", "review", str(root), *Selection(changed).Arguments()], 1)
    assert drift["status"] == "drift" and drift["changes"][0]["check_id"] == "mcp.tool-added", (
        "A declared positive change must return the drift predicate status and canonical rule"
    )
    outcome = StringIO()
    code = RunBridgeCommands(
        ["mcp", "review", str(root), *Selection(drift).Arguments()], outcome,
    )
    assert code == 1 and "MCP review: drift." in outcome.getvalue(), (
        "Human output must expose the same verified outcome"
    )
    assert drift["changes"][0]["subject_reference"] in outcome.getvalue(), (
        "Human output must identify the same changed object"
    )


def test_InteractiveMcpApprovalRequiresTheSavedReviewAndPreservesPrivateHistory(
    tmp_path: Path,
) -> None:
    """Use the same foreground bridge from shell and enforce explicit reviewed advancement.

    Args:
        tmp_path: Unique temporary workspace path.
    """

    root = tmp_path / "workspace with space"
    Workspace(root)
    baseline = Receipt(ImportArguments(root, BASELINE, 0), 0)
    initial = Receipt(ApproveArguments(root, Selection(baseline)), 0)
    updated = Receipt(ImportArguments(root, CHANGED, initial["model_revision"]), 0)
    drift = Receipt(["mcp", "review", str(root), *Selection(updated).Arguments()], 1)
    arguments = ApproveArguments(root, Selection(drift), "approval:advance")
    refused = Receipt(arguments, 4)
    assert refused["status"] == "failed" and refused["model_revision"] is None, (
        "Selecting a candidate without its exact review must fail"
    )
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd("bridge " + shlex.join([*arguments, "--review-reference",
                                         drift["review_reference"], "--json"]))
    approved = json.loads(output.getvalue())
    assert approved["status"] == "approved" and approved["model_changed"], (
        "The interactive shell must submit the same exact local approval"
    )
    assert list(shell._history) == ["bridge"] and shell.lastcmd == "bridge", (
        "Private local selections cannot become shell command history"
    )
    nowClean = Receipt(["mcp", "review", str(root), *Selection(approved).Arguments()], 0)
    assert nowClean["baseline_decision_reference"] == approved["decision_reference"], (
        "The reviewed CLI approval must become the active baseline"
    )


@pytest.mark.parametrize("topic", [[], ["import"], ["approve"], ["review"]])
def test_McpHelpRequiresNoLocalWorkspace(topic: list[str]) -> None:
    """Resolve static help topics without requiring any configured source or workspace.

    Args:
        topic: Canonical optional MCP action after the profile name.
    """

    output = StringIO()
    assert RunBridgeCommands(["mcp", *topic, "--help"], output) == 0, (
        "Documented help must work before creating a workspace"
    )
    assert "usage: 1337 bridge mcp" in output.getvalue(), "Help must expose the MCP command route"


@pytest.mark.parametrize("kind", ["omitted", "duplicate", "revision", "namespace", "review-pin"])
def test_InvalidMcpSelectionsFailBeforePhysicalAccess(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    """Keep malformed input from reaching a workspace or selected source path.

    Args:
        monkeypatch: Scoped replacement of the first physical owner boundary.
        kind: Invalid shape whose selection must be rejected as configuration.
    """

    def Denied(path: Path) -> Path:
        """Trip if a malformed command reaches physical path selection.

        Args:
            path: Unreachable caller-controlled path.

        Returns:
            Never returns a physical selection.
        """

        raise AssertionError("Malformed MCP grammar attempted to access the filesystem")

    monkeypatch.setattr(mcp_commands, "IntelPath", Denied)
    root = Path("never-open")
    selected = McpSelection("object:" + "a" * 64, "observation:" + "b" * 64, 0)
    arguments = ["mcp", "review", str(root), *selected.Arguments()]

    if kind == "omitted":
        arguments = arguments[:-2]

    elif kind == "duplicate":
        arguments += ["--server-reference=" + selected.serverReference]

    elif kind == "revision":
        arguments[-1] = "-1"

    elif kind == "namespace":
        arguments[4] = selected.snapshotReference

    else:
        arguments = [
            *ApproveArguments(root, selected), "--review-reference", selected.serverReference,
        ]

    refused = Receipt(arguments, 2)
    assert refused["status"] == "failed" and refused["failure"] == "configuration", (
        "Malformed MCP options must return a fixed configuration refusal"
    )
    assert "never-open" not in json.dumps(refused), "Rejected input must not be echoed"


@pytest.mark.parametrize("fault", ["stale", "missing-source", "interrupted"])
def test_FailedMcpOperationsLeaveNoModelChange(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Distinguish confirmed incomplete evidence from operational failures and interruption.

    Args:
        tmp_path: Fully initialized temporary workspace parent.
        monkeypatch: Scoped interruption injection at the real command owner.
        fault: Chosen failure source.
    """

    def Aborted(*arguments: object, **options: object) -> Any:
        """Interrupt acquisition before it can publish model or evidence.

        Args:
            arguments: Unused owner positional parameters.
            options: Unused owner keyword parameters.

        Returns:
            Never returns an acquisition.
        """

        raise KeyboardInterrupt

    root = tmp_path / "work"
    Workspace(root)
    source = BASELINE
    revision = 0
    expected, failure = 4, "integrity"

    if fault == "stale":
        revision = 42
        failure = "model-conflict"

    elif fault == "missing-source":
        source = tmp_path / "missing.json"

    else:
        expected, failure = 130, "interrupted"
        monkeypatch.setattr(mcp_commands, "ImportMcpInventory", Aborted)

    refused = Receipt(ImportArguments(root, source, revision), expected)
    assert refused["status"] == "failed" and refused["failure"] == failure, (
        "Failed operations must report the phase or interruption rather than a review verdict"
    )
    assert LocalModelStore(root).Open().revision == 0, "A rejected acquisition mutated the model"
