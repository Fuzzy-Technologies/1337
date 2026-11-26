# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Share explicit inert MCP selections between unit and installed-console acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_FIXTURES = Path(__file__).parent / "contract" / "fixtures"
BASELINE = _FIXTURES / "mcp.inventory.v1.json"
CHANGED = _FIXTURES / "mcp.inventory.changed.v1.json"
OBSERVED_AT = "2026-11-26T12:30:00+00:00"
APPROVED_AT = "2026-11-26T12:45:00+00:00"


@dataclass(frozen=True)
class McpSelection:
    """Keep the verified server and selected acquisition handles explicit in test invocations."""

    serverReference: str
    snapshotReference: str
    revision: int

    def Arguments(self) -> list[str]:
        """Return the exact selections accepted by both review and approval.

        Returns:
            Canonical reference switches and selected model CAS basis.
        """

        return [
            "--server-reference", self.serverReference,
            "--snapshot-reference", self.snapshotReference,
            "--expected-model-revision", str(self.revision),
        ]


def ImportArguments(root: Path, source: Path, revision: int) -> list[str]:
    """Build the shared benign acquisition command with explicit local attribution.

    Args:
        root: Operator-owned temporary workspace.
        source: One checked-in or synthetic inert declaration file.
        revision: Exact existing model revision.

    Returns:
        Bridge arguments for the import action.
    """

    return [
        "mcp", "import", str(root), str(source), "--server-key", "catalog", "--scope", "catalog",
        "--owner", "actor:collector", "--read-consent-reference", "read:catalog-example",
        "--observed-at", OBSERVED_AT, "--expected-model-revision", str(revision),
    ]


def ApproveArguments(
    root: Path, selection: McpSelection, approval: str = "approval:baseline",
) -> list[str]:
    """Build an explicit human approval command for one verified acquisition.

    Args:
        root: Operator-owned temporary workspace.
        selection: Verified server, acquisition and model CAS basis.
        approval: Unique non-secret label for this human decision.

    Returns:
        Bridge arguments for an approval, ready for an exact review reference on advancement.
    """

    return [
        "mcp", "approve", str(root), *selection.Arguments(), "--owner", "actor:operator",
        "--approval-reference", approval, "--approved-at", APPROVED_AT,
    ]
