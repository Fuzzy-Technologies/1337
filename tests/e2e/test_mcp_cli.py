# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify the shared offline catalog example through the installed command and report owners."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from tests.mcp_cli_helpers import (
    BASELINE,
    CHANGED,
    ApproveArguments,
    ImportArguments,
    McpSelection,
)


def Console(
    parent: Path, arguments: list[str], expected: int = 0, *, jsonOutput: bool = True,
) -> str:
    """Invoke the installed console with an explicit local workspace and bounded runtime.

    Args:
        parent: Isolated working directory outside package source lookup.
        arguments: Exact installed command arguments without the executable.
        expected: Exact process exit code.
        jsonOutput: Request the versioned machine receipt when selected.

    Returns:
        Complete stdout from the installed process.
    """

    console = Path(sys.executable).parent / ("1337.exe" if os.name == "nt" else "1337")
    selected = [str(console), *arguments] + (["--json"] if jsonOutput else [])
    result = subprocess.run(selected, cwd=parent, capture_output=True, text=True, timeout=30,
                            check=False)
    assert result.returncode == expected and not result.stderr, (
        f"Installed MCP command returned {result.returncode} instead of {expected}: {result.stderr}"
    )

    return result.stdout


def InvokeMcp(
    parent: Path, arguments: list[str], expected: int = 0,
) -> tuple[dict[str, Any], McpSelection]:
    """Reuse server and snapshot identities returned by the installed MCP command.

    Args:
        parent: Isolated workspace parent.
        arguments: Explicit bridge profile and action selections.
        expected: Exact installed process exit code.

    Returns:
        Decoded command receipt and selection of its acknowledged model revision.
    """

    result = json.loads(Console(parent, ["bridge", *arguments], expected))
    selection = McpSelection(
        result["server_reference"], result["snapshot_reference"], result["model_revision"],
    )

    return result, selection


def test_InstalledMcpExampleAgreesWithCanonicalJsonAndSarif(tmp_path: Path) -> None:
    """Verify human and CI entry points using one checked-in baseline/change example.

    Args:
        tmp_path: New workspace and report output parent.
    """

    root = tmp_path / "owned catalog"
    Console(tmp_path, ["workspace", "create", str(root), "--id", "mcp-catalog",
                      "--name", "Offline MCP example"])
    Console(tmp_path, ["scope", "create", str(root), "--id", "catalog", "--allow-ip", "192.0.2.1"])
    _, baseline = InvokeMcp(tmp_path, ImportArguments(root, BASELINE, 0))
    _, approved = InvokeMcp(tmp_path, ApproveArguments(root, baseline))
    clean, current = InvokeMcp(tmp_path, ["mcp", "review", str(root), *approved.Arguments()])
    assert clean["status"] == "unchanged", "Installed CI must acknowledge clean input"

    partialSource = json.loads(BASELINE.read_bytes())
    partialSource["tools"]["status"] = "incomplete"
    partialFile = tmp_path / "partial.json"
    partialFile.write_text(json.dumps(partialSource), encoding="utf-8")
    _, partial = InvokeMcp(tmp_path, ImportArguments(root, partialFile, current.revision))
    incomplete, covered = InvokeMcp(tmp_path, ["mcp", "review", str(root), *partial.Arguments()], 5)
    failed = json.loads(Console(
        tmp_path, ["bridge", "mcp", "review", str(root), *current.Arguments()], 4,
    ))
    assert incomplete["status"] == "incomplete" and failed["status"] == "failed", (
        "Installed CI must distinguish incomplete coverage from a stale model failure"
    )

    _, changed = InvokeMcp(tmp_path, ImportArguments(root, CHANGED, covered.revision))
    drift, reviewed = InvokeMcp(tmp_path, ["mcp", "review", str(root), *changed.Arguments()], 1)
    assert drift["status"] == "drift", "Installed CI must distinguish proven drift from clean input"
    assert len(drift["changes"]) == len(drift["finding_references"]) == 1, (
        "The checked-in change declares exactly one additional tool"
    )
    change = drift["changes"][0]
    finding = drift["finding_references"][0]
    assert change["check_id"] == "mcp.tool-added" and change["object_key"] == "catalog_tags", (
        "The reviewed example must identify the exact added declaration"
    )
    human = Console(
        tmp_path, ["bridge", "mcp", "review", str(root), *reviewed.Arguments()], 1,
        jsonOutput=False,
    )
    assert all(value in human for value in (
        "MCP review: drift.", change["subject_reference"], change["object_key"],
    )), (
        "The human command must display the same verified status and affected object"
    )

    reportPath = tmp_path / "model.json"
    sarifPath = tmp_path / "model.sarif"
    jsonExport = json.loads(Console(tmp_path, ["report", "export", str(root), "--format", "json",
                                               "--output", str(reportPath)]))
    sarifExport = json.loads(Console(tmp_path, ["report", "export", str(root), "--format", "sarif",
                                                "--output", str(sarifPath)]))
    assert jsonExport["snapshot_sha256"] == sarifExport["snapshot_sha256"], (
        "Both installed exporters must read the same saved model snapshot"
    )
    assert jsonExport["model_revision"] == reviewed.revision, (
        "Repeating the human comparison must preserve the saved revision for export"
    )
    report = json.loads(reportPath.read_bytes())["findings"]
    results = json.loads(sarifPath.read_bytes())["runs"][0]["results"]
    assert len(report) == len(results) == 1, "The saved model must contain one canonical finding"
    saved, exported = report[0], results[0]
    assert saved["reference"] == exported["properties"]["canonicalReference"] == finding, (
        "Command, standard JSON report and SARIF must share the same canonical finding"
    )
    assert saved["normalized"]["check_id"] == exported["ruleId"] == change["check_id"], (
        "All terminal and exported projections must use the same canonical rule"
    )
    assert (
        saved["normalized"]["subject_reference"]
        == exported["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        == change["subject_reference"]
    ), "All saved projections must identify the same affected model object"
