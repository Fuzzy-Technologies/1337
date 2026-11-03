# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit CLI for the command-owned local Workbench demo, with safe parse diagnostics."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from fuzzy1337.demo import DemoFailure, RunLocalDemo
from fuzzy1337.demo_assessment import RunAssessmentDemo

__all__ = ["RunDemoCommands"]


class DemoArgumentParser(argparse.ArgumentParser):
    """Keep untrusted rejected argument values outside terminal and saved demo artifacts."""

    def Error(self, message: str) -> NoReturn:
        """Raise a fixed configuration category without reflecting argparse's raw diagnostic.

        Args:
            message: Untrusted parser diagnostic, deliberately excluded from output.

        Returns:
            This callback never returns; it raises the fixed configuration failure.
        """

        raise DemoFailure("configuration", 2)

    error = Error


def RunDemoCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Parse the selected closed demo plan; action-specific approval precedes all mutations.

    Args:
        arguments: A closed action, a new root and its optional separate HTTP approval flag.
        output: Caller-owned terminal stream.
        json_output: Write one schema-v1 outcome instead of live presentation.

    Returns:
        Actual demo exit status, or two for malformed arguments and zero for local help.
    """

    parser = DemoArgumentParser(prog="1337 demo", add_help=False)
    parser.add_argument("action", choices=("local", "assessment"))
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--approve-safe-http", action="store_true",
                        help="Approve only the command-owned localhost SAFE HTTP demo.")
    parser.add_argument("--approve-standard-http", action="store_true",
                        help="Approve only the closed command-owned 1337Scope STANDARD assessment.")

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    try:
        options = parser.parse_args(arguments)

        if (options.action == "local" and options.approve_standard_http
                or options.action == "assessment" and options.approve_safe_http):
            raise DemoFailure("configuration", 2)

    except DemoFailure:
        if json_output:
            output.write(json.dumps({"schema_version": 1, "command": "demo.assessment" if (
                arguments and arguments[0] == "assessment") else "demo.local",
                                     "state": "failed", "exit_status": 2,
                                     "phase": "configuration", "failure": "configuration"}) + "\n")

        else:
            output.write("Invalid demo arguments; use '1337 demo --help'.\n")
        output.flush()

        return 2

    if options.action == "assessment":
        return RunAssessmentDemo(options.output_root, output,
                                 approve_standard_http=options.approve_standard_http,
                                 json_output=json_output)

    return RunLocalDemo(options.output_root, output,
                        approve_safe_http=options.approve_safe_http, json_output=json_output)
