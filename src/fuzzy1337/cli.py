# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Minimal installed entry point for 1337 Security Workbench."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import version

from fuzzy1337.command_registry import COMMAND_REGISTRY, CommandRegistry
from fuzzy1337.component_health import RunUpdate
from fuzzy1337.dev_commands import DescribeCommands
from fuzzy1337.doctor import RunDoctor
from fuzzy1337.shell import RunInteractiveShell


class InstalledVersionAction(argparse.Action):
    """Read distribution metadata only when argparse dispatches --version."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        """Preserve argparse's immediate version exit without eager metadata reads.

        Args:
            parser: CLI parser used to write output and exit.
            namespace: Unused argparse destination state.
            values: Unused values for this zero-argument action.
            option_string: Unused spelling of the requested option.

        Raises:
            SystemExit: Installed version output exits with status zero.
            PackageNotFoundError: The requested distribution metadata is absent.
        """

        sys.stdout.write(f"1337 {version('1337')}\n")
        parser.exit()


def GetCommands() -> dict[str, str]:
    """Return descriptions from the deterministic developer-command registry.

    Returns:
        Developer command names mapped to human-readable execution plans.
    """

    return DescribeCommands()


def GetCommandRegistry() -> CommandRegistry:
    """Return the centralized user-command registry without exposing mutable state.

    Returns:
        Shared user-command registry with immutable descriptors.
    """

    return COMMAND_REGISTRY


def CommandEpilog(registry: CommandRegistry) -> str:
    """Render currently available commands from their centralized descriptors.

    Args:
        registry: Command descriptors to display in presentation order.

    Returns:
        Help epilog with usages, summaries and the shell hint.
    """

    lines = ["Currently available commands:"]
    lines.extend(
        f"  {descriptor.usage:<28}{descriptor.summary}" for descriptor in registry.Commands
    )
    lines.append("Run '1337 shell' to start the interactive workbench.")
    return "\n".join(lines)


def Main(argv: Sequence[str] | None = None) -> int:
    """Dispatch help, shell, diagnostics, or read-only component inspection.

    Writes to the terminal and may enter the interactive shell. The default dispatch does not
    start a scan.

    Args:
        argv: Arguments excluding the executable, or None for process arguments.

    Returns:
        Zero for help or shell exit, or the doctor/update required-check status.

    Raises:
        SystemExit: Argument parsing rejects input or handles help/version.
        PackageNotFoundError: Explicit --version output requests absent distribution metadata.
    """

    registry = GetCommandRegistry()
    parser = argparse.ArgumentParser(
        prog="1337",
        description="1337 Security Workbench by Fuzzy Technologies",
        epilog=CommandEpilog(registry),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action=InstalledVersionAction,
        nargs=0,
        help="Show the installed distribution version and exit.",
    )
    parser.add_argument(
        "command",
        choices=("doctor", "help", "shell", "update"),
        nargs="?",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write the experimental JSON inspection report for 'update'.",
    )
    arguments = parser.parse_args(argv)

    if arguments.json and arguments.command != "update":
        parser.error("--json is only available for update")

    if arguments.command == "shell" or (arguments.command is None and sys.stdin.isatty()):
        return RunInteractiveShell()

    if arguments.command == "doctor":
        return RunDoctor(sys.stdout)

    if arguments.command == "update":
        return RunUpdate(sys.stdout, json_output=arguments.json)

    parser.print_help()
    return 0
