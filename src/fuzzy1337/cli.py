"""Minimal installed entry point for 1337 Security Workbench."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from importlib.metadata import version

from fuzzy1337.command_registry import COMMAND_REGISTRY, CommandRegistry
from fuzzy1337.dev_commands import describe_commands


def get_commands() -> dict[str, str]:
    """Return descriptions from the deterministic developer-command registry."""
    return describe_commands()


def get_command_registry() -> CommandRegistry:
    """Return the centralized user-command registry without exposing mutable state."""
    return COMMAND_REGISTRY


def _command_epilog(registry: CommandRegistry) -> str:
    """Render currently available commands from their centralized descriptors."""
    lines = ["Currently available commands:"]
    lines.extend(f"  {descriptor.usage:<18}{descriptor.summary}" for descriptor in registry.commands)
    lines.append("Interactive shell and scanners are not available yet.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Show bootstrap help or the installed distribution version."""
    registry = get_command_registry()
    parser = argparse.ArgumentParser(
        prog="1337",
        description="1337 Security Workbench by Fuzzy Technologies",
        epilog=_command_epilog(registry),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"1337 {version('1337')}")
    parser.add_argument("command", choices=("help",), nargs="?", help=argparse.SUPPRESS)
    parser.parse_args(argv)

    parser.print_help()
    return 0
