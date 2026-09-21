"""Детерминированный запуск pytest в изолированных процессах."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import xml.etree.ElementTree as elementTree
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULTTIMEOUTSECONDS = 120
DEFAULTMAXWORKERS = 12


@dataclass(frozen=True, slots=True)
class TestOptions:
    """Хранит проверенные настройки выполнения слоя pytest."""

    jobs: str = "auto"
    timeoutSeconds: int = DEFAULTTIMEOUTSECONDS
    serialOnly: bool = False
    failFast: bool = False

    def __post_init__(self) -> None:
        """Отклоняет небезопасные настройки до запуска pytest."""

        if self.jobs != "auto" and (not self.jobs.isdecimal() or int(self.jobs) < 1):
            raise ValueError("jobs must be 'auto' or a positive integer")
        if self.timeoutSeconds < 1:
            raise ValueError("timeout must be a positive integer")


@dataclass(frozen=True, slots=True)
class TestSummary:
    """Хранит стабильный итог одного или нескольких процессов pytest."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    timeout: int = 0
    durationSeconds: float = 0.0

    def Combine(self, other: TestSummary) -> TestSummary:
        """Возвращает сумму двух независимых отчётов pytest."""

        return TestSummary(
            total=self.total + other.total,
            passed=self.passed + other.passed,
            failed=self.failed + other.failed,
            skipped=self.skipped + other.skipped,
            timeout=self.timeout + other.timeout,
            durationSeconds=self.durationSeconds + other.durationSeconds,
        )

    def Display(self) -> str:
        """Формирует стабильную машиночитаемую строку итогов."""

        return (
            "Test summary: "
            f"total={self.total} passed={self.passed} failed={self.failed} "
            f"skipped={self.skipped} timeout={self.timeout} "
            f"duration={self.durationSeconds:.3f}s"
        )


def AutoWorkerCount(cpuCount: int | None = None) -> int:
    """Возвращает ограниченное число workers для планирования xdist."""

    return min(cpuCount if cpuCount is not None else (os.cpu_count() or 1), DEFAULTMAXWORKERS)


def PytestArguments(
    target: str,
    options: TestOptions,
    reportPath: Path,
    *,
    serial: bool,
) -> list[str]:
    """Формирует явный argv pytest без интерполяции оболочки."""

    arguments = [
        sys.executable,
        "-m",
        "pytest",
        target,
        "--junitxml",
        str(reportPath),
        f"--timeout={options.timeoutSeconds}",
    ]
    if options.failFast:
        arguments.append("-x")
    if serial:
        # Общий ресурс остаётся вне пула процессов, чтобы не маскировать гонки.
        arguments.extend(("-m", "serial", "-n", "0", "--cov-append"))

    else:
        arguments.extend(("-m", "not serial", "-n", options.jobs, "--dist=loadscope"))
    return arguments


def ReadJunitSummary(reportPath: Path) -> TestSummary:
    """Читает JUnit XML, не считая код процесса достаточным доказательством."""

    if not reportPath.is_file():
        return TestSummary(failed=1)
    root = elementTree.parse(reportPath).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall(".//testsuite"))
    total = sum(int(suite.attrib.get("tests", 0)) for suite in suites)
    failed = sum(
        int(suite.attrib.get("failures", 0)) + int(suite.attrib.get("errors", 0))
        for suite in suites
    )
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in suites)
    duration = sum(float(suite.attrib.get("time", 0.0)) for suite in suites)
    timeout = sum(
        1
        for case in root.findall(".//testcase")
        for failure in (*case.findall("failure"), *case.findall("error"))
        if "timeout" in (failure.text or "").lower()
        or "timeout" in failure.attrib.get("message", "").lower()
    )
    return TestSummary(
        total=total,
        passed=total - failed - skipped,
        failed=failed,
        skipped=skipped,
        timeout=timeout,
        durationSeconds=duration,
    )


def RunPytest(
    arguments: Sequence[str],
    reportPath: Path,
    timeoutSeconds: int,
) -> tuple[int, TestSummary]:
    """Запускает pytest и возвращает код вместе с разобранным результатом."""

    reportPath.unlink(missing_ok=True)
    started = time.monotonic()
    try:
        result = subprocess.run(
            arguments,
            check=False,
            shell=False,
            timeout=max(300, timeoutSeconds * 3),
        )

    except subprocess.TimeoutExpired:
        return 124, TestSummary(failed=1, timeout=1, durationSeconds=time.monotonic() - started)

    except OSError:
        return 127, TestSummary(failed=1, durationSeconds=time.monotonic() - started)
    summary = ReadJunitSummary(reportPath)
    return result.returncode, summary


def HasSerialTests(target: str) -> bool:
    """Обнаруживает serial-тесты до отдельного последовательного запуска."""

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            target,
            "-m",
            "serial",
            "--collect-only",
            "-q",
            "--no-cov",
        ],
        check=False,
        shell=False,
        timeout=300,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def RunTests(target: str, options: TestOptions) -> int:
    """Запускает xdist, затем serial-тесты и выводит общий итог."""

    reports = Path("coverage")
    reports.mkdir(exist_ok=True)
    summary = TestSummary()
    returnCodes: list[int] = []
    if not options.serialOnly:
        code, result = RunPytest(
            PytestArguments(target, options, reports / "parallel-tests.xml", serial=False),
            reports / "parallel-tests.xml",
            options.timeoutSeconds,
        )
        summary = summary.Combine(result)
        returnCodes.append(code)
    shouldRunSerial = (
        options.serialOnly or not options.failFast or not any(returnCodes)
    ) and HasSerialTests(target)
    if shouldRunSerial:
        code, result = RunPytest(
            PytestArguments(target, options, reports / "serial-tests.xml", serial=True),
            reports / "serial-tests.xml",
            options.timeoutSeconds,
        )
        summary = summary.Combine(result)
        returnCodes.append(code)
    print(summary.Display(), flush=True)
    return next((code for code in returnCodes if code), 0)
