"""Developer command interface for 1337."""

from __future__ import annotations


COMMANDS = {
    "test": "pytest",
    "lint": "ruff check .",
    "format": "ruff format .",
    "check": "pytest && ruff check . && mypy src",
}


def get_commands() -> dict[str, str]:
    """Return supported developer commands."""

    return COMMANDS.copy()
