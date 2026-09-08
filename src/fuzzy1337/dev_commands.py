"""Developer command helpers for the 1337 project."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "compile": (("-m", "compileall", "-q", "src", "tests"),),
    "lint": (("-m", "ruff", "check", "."),),
    "typecheck": (("-m", "mypy"),),
    "test": (
        ("-m", "pytest"),
        ("-m", "fuzzy1337.coverage_gate", "coverage/coverage.json", "src/fuzzy1337"),
    ),
    "build": (("-m", "build", "--no-isolation"),),
}
COMMANDS["check"] = (
    COMMANDS["compile"] + COMMANDS["lint"] + COMMANDS["typecheck"]
    + COMMANDS["test"] + COMMANDS["build"]
)


def describe_commands() -> dict[str, str]:
    """Describe execution steps without exposing mutable registry state."""
    return {
        name: " then ".join("python " + " ".join(step) for step in steps)
        for name, steps in COMMANDS.items()
    }


def run(command: str) -> int:
    """Run one gate from the repository root and stop at the first failure."""
    if command not in COMMANDS:
        raise ValueError(f"Unknown developer command: {command}")
    if not Path("pyproject.toml").is_file() or not Path("src/fuzzy1337").is_dir():
        print("Run developer commands from the 1337 repository root.", file=sys.stderr)
        return 2

    for step in COMMANDS[command]:
        if step[:2] == ("-m", "pytest"):
            Path("coverage/coverage.json").unlink(missing_ok=True)
        print("Running: python " + " ".join(step), flush=True)
        try:
            result = subprocess.run([sys.executable, *step], shell=False, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            print("Developer command exceeded its 300-second limit.", file=sys.stderr)
            return 124
        except OSError as error:
            print(f"Could not start developer command: {error.strerror}", file=sys.stderr)
            return 127
        if result.returncode:
            return 128 - result.returncode if result.returncode < 0 else result.returncode

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Select a developer gate without accepting arbitrary shell commands."""
    parser = argparse.ArgumentParser(prog="1337-dev", description="1337 repository quality gates")
    parser.add_argument("command", choices=COMMANDS)
    return run(parser.parse_args(argv).command)


if __name__ == "__main__":
    raise SystemExit(main())
