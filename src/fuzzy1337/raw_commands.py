# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit exact-native Nmap planning, execution and offline receipt commands."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import ImpactPolicy, PolicyConfirmation
from fuzzy1337.portscan import PortScanUnavailableError
from fuzzy1337.raw_cli import SelectRawNmap
from fuzzy1337.raw_cli_workflow import PlanRawCli, ReplayRawCli, RunRawCli
from fuzzy1337.scan_commands import ProductArgumentParser, WriteJson
from fuzzy1337.workspace import WorkspaceBusyError, WorkspaceConflictError


def RawParser() -> ProductArgumentParser:
    """Build wrapper arguments independently from the native token tail.

    Returns:
        Parser requiring explicit workspace, authority and optional native executable selection.
    """

    parser = ProductArgumentParser(prog="1337 raw",
        description="Govern exact Nmap TCP-connect or light service-discovery arguments.")
    commands = parser.add_subparsers(dest="operation", required=True)

    for operation in ("plan", "run"):
        command = commands.add_parser(operation)
        command.add_argument("workspace", type=Path)
        command.add_argument("--tool", choices=("nmap",), required=True)
        command.add_argument("--scope", required=True)
        command.add_argument("--owner", required=True)
        command.add_argument("--policy", type=Path, required=True)
        command.add_argument("--executable", required=True)
        command.add_argument("--json", action="store_true")

        if operation == "run":
            command.add_argument("--confirm-plan")
            command.add_argument("--confirmation-reference")

    replay = commands.add_parser("replay")
    replay.add_argument("workspace", type=Path)
    replay.add_argument("--receipt", required=True)
    replay.add_argument("--json", action="store_true")

    return parser


def WriteNative(output: TextIO, raw: bytes) -> None:
    """Write bounded original tool bytes without a wrapper prefix or lossy replacement.

    Args:
        output: Operator-selected terminal stream or reversible text test stream.
        raw: Original bytes already collected by the existing bounded process owner.
    """

    output.flush()
    binary = getattr(output, "buffer", None)

    if binary is not None:
        binary.write(raw)
        binary.flush()

    else:
        output.write(raw.decode("utf-8", errors="surrogateescape"))
        output.flush()


def RunRawCommands(argv: Sequence[str], output: TextIO, *, error: TextIO | None = None,
    json_output: bool = False) -> int:
    """Execute one explicit raw operation without interpreting native tokens as wrapper flags.

    Args:
        argv: Wrapper arguments followed by mandatory literal separator and native token tail.
        output: Exact native stdout by default; explicit JSON metadata otherwise.
        error: Exact native stderr and safe wrapper diagnostics; defaults to process stderr.
        json_output: Explicit outer machine-readable presentation selection.

    Returns:
        Native process status after complete custody, or wrapper usage/denial/failure status.
    """

    diagnostic = sys.stderr if error is None else error
    parser = RawParser()
    values = list(argv)
    separator = values.index("--") if "--" in values else len(values)
    arguments = parser.parse_args(values[:separator])
    native = values[separator + 1:] if separator < len(values) else []
    structured = json_output or arguments.json

    if arguments.operation == "replay":
        if separator < len(values):
            parser.error("Replay accepts no native argument tail")

    elif separator == len(values) or not native:
        parser.error("Native arguments require an explicit separator")

    if arguments.operation == "run" and bool(arguments.confirm_plan) != bool(
        arguments.confirmation_reference
    ):
        parser.error("Exact confirmation requires both explicit fields")

    try:
        if arguments.operation == "replay":
            WriteJson(output, ReplayRawCli(arguments.workspace, arguments.receipt))

            return 0

        selection = SelectRawNmap(native)

        def Policy() -> ImpactPolicy:
            """Reread the same explicit typed policy at each authority boundary."""

            return ReadNucleiPolicy(arguments.policy)

        inputs = (arguments.workspace, arguments.scope, arguments.owner,
            arguments.executable, selection, Policy)

        if arguments.operation == "plan":
            WriteJson(output, PlanRawCli(*inputs).ToDict())

            return 0

        confirmation = None if arguments.confirm_plan is None else PolicyConfirmation(
            arguments.confirm_plan, arguments.confirmation_reference)
        summary = asyncio.run(RunRawCli(*inputs, confirmation=confirmation))

        if structured:
            WriteJson(output, summary.ToDict())

        elif summary.result is not None:
            WriteNative(output, summary.result.stdout)
            WriteNative(diagnostic, summary.result.stderr)

        return summary.ExitCode()

    except PermissionError:
        status, code, message = 3, "authorization", (
            "Raw command denied; verify current scope, policy and exact separate confirmation.")

    except (KeyboardInterrupt, asyncio.CancelledError):
        status, code, message = 130, "cancelled", "Raw command interrupted after owned cleanup."

    except PortScanUnavailableError:
        status, code, message = 4, "provider", "Selected Nmap is unavailable or unhealthy."

    except (OSError, EvidenceError, WorkspaceBusyError, WorkspaceConflictError):
        status, code, message = 4, "storage", "Raw command storage or original custody failed."

    except (ValueError, TypeError, KeyError):
        status = 4 if arguments.operation == "replay" else 2
        code, message = "invalid", "Invalid raw command inputs or original receipt; verify inputs."

    if structured:
        WriteJson(output, {"schema_version": 1, "workflow": "raw", "state": "failed",
            "exit_code": status, "failure": {"code": code, "message": message}})

    else:
        diagnostic.write(message + "\n")
        diagnostic.flush()

    return status


def Main(argv: Sequence[str] | None = None) -> int:
    """Expose the same dedicated command route for isolated installed-module verification.

    Args:
        argv: Explicit wrapper and native tokens, or actual process arguments.

    Returns:
        The same truthful native or wrapper status as the product command route.
    """

    return RunRawCommands(sys.argv[1:] if argv is None else argv, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(Main())
