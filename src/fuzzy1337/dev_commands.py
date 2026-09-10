"""Developer command helpers for the 1337 project."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Executable = Literal["python", "uv"]


@dataclass(frozen=True, slots=True)
class CommandStep:
    """One deterministic process invocation in a developer command."""

    executable: Executable
    arguments: tuple[str, ...]

    def display(self) -> str:
        """Return the human-readable command without exposing local paths."""
        return " ".join((self.executable, *self.arguments))


def python_step(*arguments: str) -> CommandStep:
    """Create a step executed by the current Python interpreter."""
    return CommandStep("python", arguments)


def uv_step(*arguments: str) -> CommandStep:
    """Create a step executed by the pinned external uv installation."""
    return CommandStep("uv", arguments)


_coverage_gate = python_step(
    "-m",
    "fuzzy1337.coverage_gate",
    "coverage/coverage.json",
    "src/fuzzy1337",
)

COMMANDS: dict[str, tuple[CommandStep, ...]] = {
    "setup": (uv_step("sync", "--locked", "--extra", "dev"),),
    "compile": (python_step("-m", "compileall", "-q", "src", "tests"),),
    "lint": (python_step("-m", "ruff", "check", "."),),
    "typecheck": (python_step("-m", "mypy"),),
    "unit": (python_step("-m", "pytest", "tests/unit"), _coverage_gate),
    "test": (python_step("-m", "pytest", "tests"), _coverage_gate),
    "build": (python_step("-m", "build", "--no-isolation"),),
}
COMMANDS["check"] = (
    COMMANDS["compile"]
    + COMMANDS["lint"]
    + COMMANDS["typecheck"]
    + COMMANDS["test"]
    + COMMANDS["build"]
)


def describe_commands() -> dict[str, str]:
    """Describe execution steps without exposing mutable registry state."""
    return {
        name: " then ".join(step.display() for step in steps)
        for name, steps in COMMANDS.items()
    }


def _resolve_step(step: CommandStep) -> list[str] | None:
    """Resolve a step to an argv list, failing closed when a tool is absent."""
    if step.executable == "python":
        return [sys.executable, *step.arguments]

    executable = shutil.which(step.executable)
    if executable is None:
        print(
            f"Required developer tool was not found: {step.executable}",
            file=sys.stderr,
        )
        return None

    return [executable, *step.arguments]


def run(command: str) -> int:
    """Run one gate from the repository root and stop at the first failure."""
    if command not in COMMANDS:
        raise ValueError(f"Unknown developer command: {command}")

    if not Path("pyproject.toml").is_file() or not Path("src/fuzzy1337").is_dir():
        print("Run developer commands from the 1337 repository root.", file=sys.stderr)
        return 2

    for step in COMMANDS[command]:
        if step.executable == "python" and step.arguments[:2] == ("-m", "pytest"):
            Path("coverage/coverage.json").unlink(missing_ok=True)

        print(f"Running: {step.display()}", flush=True)
        arguments = _resolve_step(step)
        if arguments is None:
            return 127

        try:
            result = subprocess.run(
                arguments,
                shell=False,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print("Developer command exceeded its 300-second limit.", file=sys.stderr)
            return 124
        except OSError as error:
            detail = error.strerror or str(error)
            print(f"Could not start developer command: {detail}", file=sys.stderr)
            return 127

        if result.returncode:
            return 128 - result.returncode if result.returncode < 0 else result.returncode

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Select a developer gate without accepting arbitrary shell commands."""
    parser = argparse.ArgumentParser(
        prog="1337-dev",
        description="1337 repository quality gates",
    )
    parser.add_argument("command", choices=COMMANDS)
    return run(parser.parse_args(argv).command)


if __name__ == "__main__":
    raise SystemExit(main())
