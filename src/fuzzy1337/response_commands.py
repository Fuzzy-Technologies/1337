# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit source-only original-response acquisition and known offline replay commands."""

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
from fuzzy1337.policy import ImpactPolicy, PolicyDeniedError
from fuzzy1337.scan_commands import ProductArgumentParser, WriteJson
from fuzzy1337.workspace import WorkspaceBusyError, WorkspaceConflictError


def ResponseParser() -> ProductArgumentParser:
    """Declare only explicit fixed capture or original receipt replay without inferred authority.

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

    return parser


def RunResponseCommands(argv: Sequence[str], output: TextIO, *, json_output: bool = False) -> int:
    """Dispatch shared CLI/shell original acquisition or read-only historical verification.

    Args:
        argv: Exact explicit namespace arguments, excluding global --json.
        output: Existing presentation stream, never a raw evidence destination.
        json_output: Emit the one safe schema-versioned result as JSON.

    Returns:
        Zero for acknowledged capture/verified replay, two for invalid inputs, three for denial,
        four for failed custody/persistence or 130 for cancellation.
    """

    parser = ResponseParser()
    args = parser.parse_args(argv)

    if args.action == "capture" and (args.events_json and json_output or args.plan and (
        args.events_json or args.approve_safe_response_capture
    )):
        parser.error("choose read-only plan, one JSON summary or one structured event stream")

    try:
        if args.action == "replay":
            try:
                document = ReplayOwnedResponse(args.workspace, args.receipt).ToDict()

            except ValueError:
                WriteJson(output, {"schema_version": 1, "state": "failed", "failure": {
                    "code": "integrity", "message": "Original response association is unknown"}})

                return 4

            status = 0

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
