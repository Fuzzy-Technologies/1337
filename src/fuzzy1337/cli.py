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
    """Dispatch local workspace/scope commands, bounded scans, explicit CI gates and reports.

    Writes to the terminal and may enter the interactive shell. The default dispatch does not
    start a scan.

    Args:
        argv: Arguments excluding the executable, or None for process arguments.

    Returns:
        Zero for completed commands or satisfied explicit CI predicates; one for CI violation,
        two for invalid setup, three for scan denial,
        four for scan/export integrity, execution or storage failure, 130 for interruption,
        or inspection status.

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
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show command help and exit.")
    parser.add_argument(
        "--version",
        action=InstalledVersionAction,
        nargs=0,
        help="Show the installed distribution version and exit.",
    )
    parser.add_argument(
        "command",
        choices=("doctor", "help", "shell", "update", "workspace", "scope", "scan", "report",
                 "demo", "intel", "ci", "runtime", "api", "trace"),
        nargs="?",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write experimental JSON for update or an explicit product command outcome.",
    )
    arguments, remaining = parser.parse_known_args(argv)

    if arguments.command == "api":
        from fuzzy1337.api_commands import RunApiCommands

        if arguments.help:
            remaining.append("--help")

        return RunApiCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "runtime":
        from fuzzy1337.runtime_commands import RunRuntimeCommands

        if arguments.help:
            remaining.append("--help")

        return RunRuntimeCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "trace":
        from fuzzy1337.ioc_commands import RunIocCommands

        if arguments.help:
            remaining.append("--help")

        return RunIocCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "ci":
        from fuzzy1337.ci_commands import RunCiCommands

        if arguments.help:
            remaining.append("--help")

        return RunCiCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "intel":
        from fuzzy1337.intelligence_commands import RunIntelCommands

        if arguments.help:
            remaining.append("--help")

        return RunIntelCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "demo":
        from fuzzy1337.demo_commands import RunDemoCommands

        if arguments.help:
            remaining.append("--help")

        return RunDemoCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command == "report":
        from fuzzy1337.report_commands import RunReportCommands

        if arguments.help:
            remaining.append("--help")

        return RunReportCommands(remaining, sys.stdout, json_output=arguments.json)

    if arguments.command in {"workspace", "scope", "scan"}:
        from fuzzy1337.scan_commands import RunCommands

        if arguments.help:
            remaining.append("--help")

        return RunCommands(arguments.command, remaining, sys.stdout, json_output=arguments.json)

    if arguments.help:
        parser.print_help()
        parser.exit()

    if remaining:
        parser.error("unrecognized arguments: " + " ".join(remaining))

    if arguments.json and arguments.command != "update":
        parser.error(
            "--json is only available for update, workspace, scope, scan, report, demo, "
            "intel, ci, runtime, api and trace"
        )

    if arguments.command == "shell" or (arguments.command is None and sys.stdin.isatty()):
        return RunInteractiveShell()

    if arguments.command == "doctor":
        return RunDoctor(sys.stdout)

    if arguments.command == "update":
        return RunUpdate(sys.stdout, json_output=arguments.json)

    parser.print_help()
    return 0
