"""Developer command helpers for the 1337 project."""

from __future__ import annotations

import subprocess
import sys


COMMANDS = {
    "test": [sys.executable, "-m", "pytest"],
    "lint": [sys.executable, "-m", "ruff", "check", "."],
    "format": [sys.executable, "-m", "ruff", "format", "."],
    "check": [sys.executable, "-m", "ruff", "check", "."],
}


def run(command: str) -> int:
    """Run a registered developer command."""
    if command not in COMMANDS:
        raise ValueError(f"Unknown developer command: {command}")
    return subprocess.call(COMMANDS[command])
