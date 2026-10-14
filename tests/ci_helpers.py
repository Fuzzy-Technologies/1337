# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit owned CI command selections shared by independent product-boundary tests."""

from __future__ import annotations

import io
import json
from pathlib import Path

from fuzzy1337.artifact_inputs import ArtifactProfile
from fuzzy1337.ci_commands import RunCiCommands
from fuzzy1337.configuration_workflow import ConfigurationScanSelection


def CiArguments(root: Path, selection: ConfigurationScanSelection, parent: Path) -> list[str]:
    """Select every existing owner input, explicit criterion and distinct report destination.

    Args:
        root: Existing isolated owning workspace with approved synthetic artifact scope.
        selection: Reviewed explicit source/runtime/worker/material/read-consent selection.
        parent: Existing physical test directory outside the owning workspace.

    Returns:
        Canonical CI namespace arguments with explicit zero-match high/open criterion.
    """

    profile = "synthetic-dockerfile" if (
        selection.profile is ArtifactProfile.SYNTHETIC_DOCKERFILE
    ) else "synthetic-kubernetes"

    return ["scan", str(root), "--profile", profile, "--logical-path", selection.logical_path,
        "--source", str(selection.source), "--executable", str(selection.executable),
        "--producer", str(selection.producer), "--material", str(selection.material),
        "--scope", "config-scope", "--owner", "owner:test", "--read-consent-reference",
        selection.read_consent.record_ref, "--approve-safe-configuration",
        "--severity", "high", "--status", "open", "--max-matches", "0",
        "--acknowledge-unassessed-completeness", "--report-json", str(parent / "ci.json"),
        "--report-sarif", str(parent / "ci.sarif"), "--report-junit", str(parent / "ci.xml")]


def InvokeCi(arguments: list[str]) -> tuple[int, dict]:
    """Exercise the actual public command handler and decode its one machine outcome.

    Args:
        arguments: Explicit namespace inputs, including all owned source and output selections.

    Returns:
        Actual terminal exit and independent decoded command outcome.
    """

    output = io.StringIO()
    status = RunCiCommands(arguments, output, json_output=True)

    return status, json.loads(output.getvalue())
