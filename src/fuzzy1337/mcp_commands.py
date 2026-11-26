# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Expose owned offline MCP review through the existing workspace CLI transport."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceError, NormalizeEvidenceTime
from fuzzy1337.intelligence_commands import IntelArgumentParser, IntelFailure, IntelPath
from fuzzy1337.mcp_drift import ApproveMcpBaseline, McpDriftChange, McpDriftUnknown, ReviewMcpDrift
from fuzzy1337.mcp_inventory import ImportMcpInventory
from fuzzy1337.model import LocalModelStore, ModelDelta, RequireModelReference
from fuzzy1337.workspace import (
    RequireWorkspaceInteger,
    WorkspaceBusyError,
    WorkspaceConflictError,
)

__all__ = ()

_PROFILE = "bridge-mcp-offline-cli-v1"
_REVIEW_EXIT = {"unchanged": 0, "drift": 1, "no-baseline": 3, "incomplete": 5}


def AddMcpBridgeActions(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    """Declare explicit offline MCP commands inside the shared bridge parser.

    Args:
        parser: Static MCP subparser provided by the bridge namespace.

    Returns:
        Action parsers used for focused help generation.
    """

    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    importer = actions.add_parser("import", add_help=False, allow_abbrev=False,
                                  help="Import one explicitly selected local JSON inventory.")
    importer.add_argument("workspace", type=Path)
    importer.add_argument("file", type=Path)
    importer.add_argument("--server-key", required=True)
    importer.add_argument("--scope", required=True)
    importer.add_argument("--owner", required=True)
    importer.add_argument("--read-consent-reference", required=True)
    importer.add_argument("--observed-at", required=True,
                          help="Acquisition time with a UTC offset.")
    approve = actions.add_parser("approve", add_help=False, allow_abbrev=False,
                                 help="Approve the exact selected verified snapshot.")
    review = actions.add_parser("review", add_help=False, allow_abbrev=False,
                                help="Compare the selected snapshot against the active approval.")

    for action in (approve, review):
        action.add_argument("workspace", type=Path)
        action.add_argument("--server-reference", required=True)
        action.add_argument("--snapshot-reference", required=True)

    approve.add_argument("--owner", required=True)
    approve.add_argument("--approval-reference", required=True)
    approve.add_argument("--approved-at", required=True, help="Decision time with a UTC offset.")
    approve.add_argument("--review-reference",
                         help="Exact saved review needed to advance a baseline.")

    for action in (importer, approve, review):
        action.add_argument("--expected-model-revision", type=int, required=True)

    return dict(actions.choices)


def McpChangeFields(change: McpDriftChange | McpDriftUnknown) -> dict[str, object]:
    """Project one safe declaration comparison onto the version-one CLI receipt.

    Args:
        change: Already normalized comparison from the saved review.

    Returns:
        Stable object, rule and metadata fields; schema paths stay in verified diff evidence.
    """

    result: dict[str, object] = {
        "subject_reference": change.subjectReference,
        "section": change.section,
        "field": change.field,
        "object_key": change.objectKey,
        "before": change.before,
        "after": change.after,
    }

    if isinstance(change, McpDriftChange):
        result["check_id"] = change.checkId

    return result


def WriteMcpReceipt(output: TextIO, receipt: dict[str, object], jsonOutput: bool) -> None:
    """Publish a complete receipt without source strings or raw evidence values.

    Args:
        output: Caller-owned text stream.
        receipt: Fixed command fields and detached comparison references.
        jsonOutput: Emit one JSON line instead of a human readable summary.

    Raises:
        OSError: The caller-owned output stream did not accept the complete receipt.
    """

    if jsonOutput:
        text = json.dumps(receipt, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    else:
        lines = [f"MCP {str(receipt['command']).removeprefix('bridge.mcp.')}: {receipt['status']}."]

        if receipt["failure"] is not None:
            lines.append(f"Failure: {receipt['failure']}.")

        for key in (
            "model_revision", "server_reference", "snapshot_reference", "decision_reference",
            "review_reference", "evidence_manifest",
        ):
            if key in receipt and receipt[key] is not None:
                lines.append(f"{key.replace('_', ' ').capitalize()}: {receipt[key]}")

        changes = receipt.get("changes", [])
        unknowns = receipt.get("unknowns", [])

        if isinstance(changes, list) and isinstance(unknowns, list) and "changes" in receipt:
            lines.append(f"Changes: {len(changes)}. Unknown comparisons: {len(unknowns)}.")

            for item in changes:
                label = f" ({item['object_key']})" if item["object_key"] is not None else ""
                lines.append(
                    f"  {item['check_id']} {item['subject_reference']} {item['field']}{label}"
                )

        text = "\n".join(lines) + "\n"

    if output.write(text) != len(text):
        raise OSError("MCP command output was not written completely")

    output.flush()


def RunMcpBridge(
    arguments: Sequence[str], output: TextIO, *,
    parseArguments: Callable[[Sequence[str]], argparse.Namespace], jsonOutput: bool,
) -> int:
    """Run one selected offline import, explicit approval, or saved declaration review.

    Args:
        arguments: Bridge command tokens beginning with the MCP profile.
        output: Caller-owned stream for a complete human or JSON outcome.
        parseArguments: Shared strict bridge parser and duplicate-argument boundary.
        jsonOutput: Select the one-line version-one machine receipt.

    Returns:
        Zero for completed import, approval or unchanged review; one for verified drift;
        two for invalid configuration; three for no baseline; four for failed
        storage or integrity; five for incomplete review; 130 for interruption.
    """

    receipt: dict[str, object] = {
        "schema_version": 1,
        "profile": _PROFILE,
        "command": "bridge.mcp",
        "status": "failed",
        "failure": None,
        "model_revision": None,
        "model_changed": None,
    }
    phase = "configuration"
    exitCode = 2

    try:
        options = parseArguments(arguments)
        action = options.action
        receipt["command"] = f"bridge.mcp.{action}"
        revision = RequireWorkspaceInteger(
            options.expected_model_revision, "expected model revision",
        )

        if action == "import":
            RequireIdentifier(options.server_key, "MCP server key")
            RequireIdentifier(options.scope, "scope")
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
            observedAt = NormalizeEvidenceTime(options.observed_at)
            source = IntelPath(options.file)

        else:
            server = RequireModelReference(options.server_reference)
            selected = RequireModelReference(options.snapshot_reference)

            if not server.startswith("object:") or not selected.startswith("observation:"):
                raise ValueError("MCP server and snapshot must use typed model references")

            if action == "approve":
                approvedAt = NormalizeEvidenceTime(options.approved_at)

                if options.review_reference is not None and not RequireModelReference(
                    options.review_reference,
                ).startswith("observation:"):
                    raise ValueError("MCP review must select an observation reference")

        model = LocalModelStore(IntelPath(options.workspace))
        phase = "integrity"
        delta: ModelDelta

        if action == "import":
            acquisition = ImportMcpInventory(
                model, source, serverKey=options.server_key, scopeId=options.scope,
                consent=consent, observedAt=observedAt, expectedRevision=revision,
            )
            delta = acquisition.delta
            receipt.update({
                "status": "imported",
                "server_reference": acquisition.serverReference,
                "snapshot_reference": acquisition.snapshotReference,
                "evidence_manifest": acquisition.evidence.evidence_id,
            })
            exitCode = 0

        elif action == "approve":
            approval = ApproveMcpBaseline(
                model, serverReference=server, snapshotReference=selected,
                actorReference=options.owner, approvalReference=options.approval_reference,
                approvedAt=approvedAt, expectedRevision=revision,
                reviewReference=options.review_reference,
            )
            delta = approval.delta
            receipt.update({
                "status": "approved",
                "server_reference": approval.serverReference,
                "snapshot_reference": approval.snapshotReference,
                "decision_reference": approval.decisionReference,
            })
            exitCode = 0

        else:
            review = ReviewMcpDrift(
                model, serverReference=server, snapshotReference=selected,
                expectedRevision=revision,
            )
            delta = review.delta
            status = "incomplete" if review.status == "unknown" else review.status
            receipt.update({
                "status": status,
                "server_reference": review.serverReference,
                "snapshot_reference": review.snapshotReference,
                "baseline_reference": review.baselineReference,
                "baseline_decision_reference": review.baselineDecisionReference,
                "review_reference": review.reviewReference,
                "changes": [McpChangeFields(change) for change in review.changes],
                "unknowns": [McpChangeFields(change) for change in review.unknowns],
                "finding_references": list(review.findingReferences),
                "evidence_manifest": review.evidence.evidence_id if review.evidence else None,
            })
            exitCode = _REVIEW_EXIT[status]

        receipt["model_revision"] = delta.revision
        receipt["model_changed"] = delta.previous_revision != delta.revision

    except IntelFailure as error:
        receipt["failure"] = error.category
        exitCode = error.status

    except (WorkspaceConflictError, WorkspaceBusyError):
        receipt["failure"] = "model-conflict"
        exitCode = 4

    except (EvidenceError, OSError, ValueError, OverflowError, RecursionError):
        receipt["failure"] = phase
        exitCode = 2 if phase == "configuration" else 4

    except KeyboardInterrupt:
        receipt["failure"] = "interrupted"
        exitCode = 130

    WriteMcpReceipt(output, receipt, jsonOutput)

    return exitCode
