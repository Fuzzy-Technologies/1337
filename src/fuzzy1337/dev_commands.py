"""Вспомогательные команды разработчика проекта 1337."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fuzzy1337.test_runner import RunTests, TestOptions

Executable = Literal["python", "uv"]


@dataclass(frozen=True, slots=True)
class CommandStep:
    """Описывает один детерминированный запуск процесса."""

    executable: Executable
    arguments: tuple[str, ...]

    def Display(self) -> str:
        """Возвращает читаемую команду без раскрытия локальных путей."""

        return " ".join((self.executable, *self.arguments))


def PythonStep(*arguments: str) -> CommandStep:
    """Создаёт шаг для выполнения текущим интерпретатором Python."""

    return CommandStep("python", arguments)


def UvStep(*arguments: str) -> CommandStep:
    """Создаёт шаг для выполнения закреплённой внешней установкой uv."""

    return CommandStep("uv", arguments)


coverageGate = PythonStep(
    "-m",
    "fuzzy1337.coverage_gate",
    "coverage/coverage.json",
    "src/fuzzy1337",
)

COMMANDS: dict[str, tuple[CommandStep, ...]] = {
    "setup": (UvStep("sync", "--locked", "--extra", "dev"),),
    "compile": (PythonStep("-m", "compileall", "-q", "src", "tests"),),
    "lint": (PythonStep("-m", "ruff", "check", "."),),
    "typecheck": (PythonStep("-m", "mypy"),),
    "unit": (coverageGate,),
    "test": (coverageGate,),
    "build": (PythonStep("-m", "build", "--no-isolation"),),
}
COMMANDS["check"] = (
    COMMANDS["compile"]
    + COMMANDS["lint"]
    + COMMANDS["typecheck"]
    + COMMANDS["test"]
    + COMMANDS["build"]
)


def DescribeCommands() -> dict[str, str]:
    """Описывает шаги без раскрытия изменяемого состояния реестра."""

    descriptions = {
        name: " then ".join(step.Display() for step in steps)
        for name, steps in COMMANDS.items()
    }
    descriptions["unit"] = (
        "python -m pytest tests/unit -n auto --dist=loadscope then "
        "python -m pytest tests/unit -m serial -n 0 then "
        "python -m fuzzy1337.coverage_gate coverage/coverage.json src/fuzzy1337"
    )
    descriptions["test"] = (
        "python -m pytest tests -n auto --dist=loadscope then "
        "python -m pytest tests -m serial -n 0 then "
        "python -m fuzzy1337.coverage_gate coverage/coverage.json src/fuzzy1337"
    )
    descriptions["check"] = " then ".join(
        (
            descriptions["compile"],
            descriptions["lint"],
            descriptions["typecheck"],
            descriptions["test"],
            descriptions["build"],
        )
    )
    return descriptions


def ResolveStep(step: CommandStep) -> list[str] | None:
    """Преобразует шаг в argv и безопасно завершается без инструмента."""

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


def Run(command: str, testOptions: TestOptions | None = None) -> int:
    """Запускает проверку из корня репозитория до первой ошибки."""

    if command not in COMMANDS:
        raise ValueError(f"Unknown developer command: {command}")

    if not Path("pyproject.toml").is_file() or not Path("src/fuzzy1337").is_dir():
        print("Run developer commands from the 1337 repository root.", file=sys.stderr)
        return 2

    if command == "check":
        for nestedCommand in ("compile", "lint", "typecheck", "test", "build"):
            nestedResult = Run(nestedCommand, testOptions)
            if nestedResult:
                return nestedResult
        return 0

    if command in {"unit", "test"}:
        Path("coverage/coverage.json").unlink(missing_ok=True)
        testResult = RunTests(
            "tests/unit" if command == "unit" else "tests",
            testOptions or TestOptions(),
        )
        if testResult:
            return 128 - testResult if testResult < 0 else testResult

    for step in COMMANDS[command]:
        print(f"Running: {step.Display()}", flush=True)
        arguments = ResolveStep(step)
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


def Main(argv: Sequence[str] | None = None) -> int:
    """Выбирает проверку без допуска произвольных команд оболочки."""

    parser = argparse.ArgumentParser(
        prog="1337-dev",
        description="1337 repository quality gates",
    )
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--jobs", default="auto", metavar="auto|N")
    parser.add_argument("--timeout", default=120, type=int, metavar="N")
    parser.add_argument("--serial", action="store_true")
    parser.add_argument("--fail-fast", dest="failFast", action="store_true")
    arguments = parser.parse_args(argv)
    testOptions = TestOptions(
        jobs=arguments.jobs,
        timeoutSeconds=arguments.timeout,
        serialOnly=arguments.serial,
        failFast=arguments.failFast,
    )
    if arguments.command not in {"unit", "test"} and testOptions != TestOptions():
        parser.error("test execution options are only valid with 'unit' or 'test'")
    return Run(arguments.command, testOptions)

if __name__ == "__main__":
    raise SystemExit(Main())
