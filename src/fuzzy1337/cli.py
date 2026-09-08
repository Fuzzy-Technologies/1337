"""Minimal installed entry point for 1337 Security Workbench."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from importlib.metadata import version

from fuzzy1337.dev_commands import describe_commands


def get_commands() -> dict[str, str]:
    """Return descriptions from the single developer-command registry."""
    return describe_commands()


def main(argv: Sequence[str] | None = None) -> int:
    """Show bootstrap help or the installed distribution version."""
    parser = argparse.ArgumentParser(
        prog="1337",
        description="1337 Security Workbench by Fuzzy Technologies",
        epilog="Pre-alpha bootstrap. Interactive shell and scanners are not available yet.",
    )
    parser.add_argument("--version", action="version", version=f"1337 {version('1337')}")
    parser.parse_args(argv)

    parser.print_help()
    return 0
