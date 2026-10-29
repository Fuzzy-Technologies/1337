# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit original-response acquisition, separate offline header checks and known replay."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.jobs import JobEvent
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.owned_response_workflow import (
    OwnedResponseAuthorityDeniedError,
    PlanOwnedResponseCapture,
    ReplayOwnedResponse,
    RunOwnedResponseCapture,
)
from fuzzy1337.policy import ImpactPolicy, PolicyDenialReason, PolicyDeniedError
from fuzzy1337.scan_commands import ProductArgumentParser, WriteJson
from fuzzy1337.workspace import WorkspaceBusyError, WorkspaceConflictError


def ResponseParser() -> ProductArgumentParser:
    """Declare distinct capture, PASSIVE header check and historical replay operations.

    Returns:
        Finite response namespace parser preserving all other existing command contracts.
    """

    parser = ProductArgumentParser(prog="1337 response")
    actions = parser.add_subparsers(dest="action", required=True)
    capture = actions.add_parser("capture", help="Capture one reviewed owned original response.")
    capture.add_argument("workspace", type=Path)
    capture.add_argument("--target", required=True)
    capture.add_argument("--scope", required=True)
    capture.add_argument("--owner", required=True)
    capture.add_argument("--policy", type=Path, required=True)
    capture.add_argument("--approve-safe-response-capture", action="store_true")
    capture.add_argument("--plan", action="store_true")
    capture.add_argument("--events-json", action="store_true")
    replay = actions.add_parser("replay", help="Verify known original receipt offline; no Save.")
    replay.add_argument("workspace", type=Path)
    replay.add_argument("--receipt", required=True)
    headers = actions.add_parser("check-headers",
        help="Assess acknowledged original headers offline.")
    headers.add_argument("workspace", type=Path)
    headers.add_argument("--receipt", required=True)
    headers.add_argument("--target", required=True)
    headers.add_argument("--scope", required=True)
    headers.add_argument("--owner", required=True)
    headers.add_argument("--policy", type=Path, required=True)
    headers.add_argument("--analysis-reference", required=True)
    headers.add_argument("--approve-passive-header-check", action="store_true")
    header_replay = actions.add_parser("replay-headers",
        help="Verify a retained original-header assessment offline; no Save.")
    header_replay.add_argument("workspace", type=Path)
    header_replay.add_argument("--assessment", required=True)

    return parser


def CheckOriginalHeaders(workspace_root: Path, scope_id: str, receipt_id: str, target_url: str,
                         owner_reference: str, policy_path: Path, analysis_reference: str,
                         approved: bool) -> tuple[dict[str, object], int]:
    """Pass fresh original revision bases to the existing offline SDK exactly once.

    Args:
        workspace_root: Explicit existing workspace, never a new capture destination.
        scope_id: Existing original source scope identity.
        receipt_id: Original acknowledged seven-role receipt manifest ID.
        target_url: Exact original URL spelling, checked before Target normalization.
        owner_reference: Explicit operator attribution, without an authentication claim.
        policy_path: Explicit current typed policy source, reread at each SDK boundary.
        analysis_reference: Explicit independent analysis identity.
        approved: Separate PASSIVE workflow opt-in, default denied by the parser.

    Returns:
        The unchanged SDK summary and its closed CLI exit classification.
    """

    from fuzzy1337.adapters.owned_response_capture import Destination
    from fuzzy1337.model import LocalModelStore
    from fuzzy1337.native_response_header_workflow import ApplyOwnedResponseHeaderCheck
    from fuzzy1337.scope import Target, TargetKind
    from fuzzy1337.workspace import LocalWorkspaceStore

    Destination(target_url)

    if not approved:
        raise PolicyDeniedError(PolicyDenialReason.CONFIRMATION_REQUIRED)

    workspace = LocalWorkspaceStore(workspace_root).Open()
    model = LocalModelStore(workspace_root).Open()

    def ReadHeaderPolicy() -> ImpactPolicy:
        """Refresh only the explicitly selected policy; approval supplies no permission."""

        return ReadNucleiPolicy(policy_path)

    summary = ApplyOwnedResponseHeaderCheck(workspace_root, scope_id, receipt_id,
        Target(TargetKind.URL, target_url), owner_reference, ReadHeaderPolicy,
        analysis_reference=analysis_reference, expected_model_revision=model.revision,
        expected_workspace_revision=workspace.revision, approve_passive_header_check=approved)
    status = 0 if summary.state in ("completed", "already-applied") else (
        3 if summary.state == "denied" else 4)

    return summary.ToDict(), status


def RunResponseCommands(argv: Sequence[str], output: TextIO, *, json_output: bool = False) -> int:
    """Dispatch shared CLI/shell capture, separate PASSIVE interpretation or historical replay.

    Args:
        argv: Exact explicit namespace arguments, excluding global --json.
        output: Existing presentation stream, never a raw evidence destination.
        json_output: Emit the one safe schema-versioned result as JSON.

    Returns:
        Zero for completed/already-applied interpretation or acknowledged capture/verified replay,
        two for invalid inputs, three for denial, four for failed/partial custody or persistence,
        or 130 for capture cancellation.
    """

    parser = ResponseParser()
    args = parser.parse_args(argv)

    if args.action == "capture" and (args.events_json and json_output or args.plan and (
        args.events_json or args.approve_safe_response_capture
    )):
        parser.error("choose read-only plan, one JSON summary or one structured event stream")

    try:
        if args.action in ("replay", "replay-headers"):
            try:
                if args.action == "replay-headers":
                    from fuzzy1337.native_response_header_workflow import (
                        ReplayOwnedResponseHeaderCheck,
                    )

                    document = ReplayOwnedResponseHeaderCheck(args.workspace,
                        args.assessment).ToDict()

                else:
                    document = ReplayOwnedResponse(args.workspace, args.receipt).ToDict()

            except ValueError:
                WriteJson(output, {"schema_version": 1, "state": "failed", "failure": {
                    "code": "integrity", "message": "Original response association is unknown"}})

                return 4

            status = 0

        elif args.action == "check-headers":
            document, status = CheckOriginalHeaders(args.workspace, args.scope, args.receipt,
                args.target, args.owner, args.policy, args.analysis_reference,
                args.approve_passive_header_check)

        else:
            def ReadPolicy() -> ImpactPolicy:
                """Read selected current policy without deriving permission from approval."""

                return ReadNucleiPolicy(args.policy)

            if args.plan:
                document = PlanOwnedResponseCapture(args.workspace, args.scope, args.target,
                    args.owner, ReadPolicy).ToDict()
                WriteJson(output, document)

                return 0

            def OnEvent(event: JobEvent) -> None:
                """Stream only original safe job events, without executor response fragments."""

                if args.events_json:
                    WriteJson(output, {"schema_version": 1, "type": "event",
                                       "event": json.loads(SerializeContract(event))})

            summary = asyncio.run(RunOwnedResponseCapture(args.workspace, args.scope, args.target,
                args.owner, ReadPolicy,
                approve_safe_response_capture=args.approve_safe_response_capture, on_event=OnEvent))
            document = summary.ToDict()
            status = summary.ExitCode()

            if args.events_json:
                WriteJson(output, {"schema_version": 1, "type": "summary", "summary": document})

                return status

        if json_output:
            WriteJson(output, document)

        else:
            output.write(f"Response {args.action}: {document['state']}; "
                         f"model revision {document['model_revision']}; "
                         f"workspace revision {document['workspace_revision']}\n")
            output.flush()

        return status

    except (OwnedResponseAuthorityDeniedError, PolicyDeniedError):
        code, status = "authorization", 3

    except (EvidenceError, OSError, WorkspaceBusyError, WorkspaceConflictError):
        code, status = "storage", 4

    except ValueError:
        code, status = "invalid_configuration", 2

    WriteJson(output, {"schema_version": 1, "state": "failed",
        "failure": {"code": code, "message": "Owned response command could not complete"}})

    return status
