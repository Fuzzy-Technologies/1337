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
    """Parse only the bounded local demo plan; explicit approval precedes all mutations.

    Args:
        arguments: `local`, a new output root and optional `--approve-safe-http`.
        output: Caller-owned terminal stream.
        json_output: Write one schema-v1 outcome instead of live presentation.

    Returns:
        Actual demo exit status, or two for malformed arguments and zero for local help.
    """

    parser = DemoArgumentParser(prog="1337 demo", add_help=False)
    parser.add_argument("action", choices=("local",))
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--approve-safe-http", action="store_true",
                        help="Approve only the command-owned localhost SAFE HTTP demo.")

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    try:
        options = parser.parse_args(arguments)

    except DemoFailure:
        if json_output:
            output.write(json.dumps({"schema_version": 1, "command": "demo.local",
                                     "state": "failed", "exit_status": 2,
                                     "phase": "configuration", "failure": "configuration"}) + "\n")

        else:
            output.write("Invalid demo arguments; use '1337 demo --help'.\n")
        output.flush()

        return 2

    return RunLocalDemo(options.output_root, output,
                        approve_safe_http=options.approve_safe_http, json_output=json_output)
