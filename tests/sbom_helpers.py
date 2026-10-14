# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual owned SPDX graph source, workspace and explicit product selections for boundary tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from fuzzy1337.model import LocalModelStore
from fuzzy1337.sbom_commands import RunSbomCommands
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURES = Path(__file__).parent / "contract/fixtures"
IMAGE_DIGEST = "sha256:" + "a" * 64


@dataclass(frozen=True, slots=True)
class OwnedSbom:
    """One exact test-owned workspace and original non-secret SPDX file selection."""

    root: Path
    source: Path


def Context(parent: Path) -> OwnedSbom:
    """Initialize actual stores and one explicit existing offline attribution scope.

    Args:
        parent: Test-owned existing scratch directory.

    Returns:
        Explicit owning workspace and independent handwritten source fixture copy.
    """

    root = parent / "owned workspace"
    workspace = LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("Owned SPDX graph import"), "owned-sbom")
    LocalModelStore(root).Create()
    LocalScopeStore(root).Create(ScopeSnapshot("owned", workspace.workspace_id))
    source = parent / "original graph.json"
    source.write_bytes((FIXTURES / "spdx.graph.v2.3.json").read_bytes())

    return OwnedSbom(root, source)


def Arguments(owned: OwnedSbom, *, evidence_id: str | None = None,
              digest_kind: str = "config") -> list[str]:
    """Select both actual current bases and every source/image/run/custody field explicitly.

    Args:
        owned: Actual owning workspace and original file selected by this test.
        evidence_id: Original product acquisition manifest, or absent for first file acquisition.
        digest_kind: Explicit config/manifest interpretation of the unchanged root checksum.

    Returns:
        Canonical namespace arguments without implicit source, execution or digest-kind defaults.
    """

    arguments = ["import", "spdx-graph", str(owned.root), "--image-digest", IMAGE_DIGEST,
        "--image-digest-kind", digest_kind, "--scope", "owned", "--run", "run:owned-spdx",
        "--expected-revision", str(LocalModelStore(owned.root).Open().revision),
        "--expected-workspace-revision", str(LocalWorkspaceStore(owned.root).Open().revision)]

    if evidence_id is None:
        arguments.extend(["--file", str(owned.source), "--owner", "owner:test",
            "--read-consent-reference", "read:owned-spdx", "--source-id", "inventory.owned-spdx",
            "--source-version", "owned-export-v1", "--provider-version", "declared-exporter-v1"])

    else:
        arguments.extend(["--evidence", evidence_id])

    return arguments


def Run(arguments: list[str], *, clock=None, json_output: bool = True):
    """Execute the actual handler and decode its sole safe terminal outcome.

    Args:
        arguments: Explicit import selections without central namespace dispatch.
        clock: Optional owning test observation clock for original file reads.
        json_output: Decode the actual machine outcome or return concise human text.

    Returns:
        Actual exit status and independent decoded JSON or human output.
    """

    output = StringIO()
    options = {"json_output": json_output}

    if clock is not None:
        options["clock"] = clock

    status = RunSbomCommands(arguments, output, **options)

    return status, json.loads(output.getvalue()) if json_output else output.getvalue()


def Value(arguments: list[str], flag: str, value: object) -> list[str]:
    """Replace one selected value while preserving the independently constructed other fields."""

    updated = list(arguments)
    updated[updated.index(flag) + 1] = str(value)

    return updated
