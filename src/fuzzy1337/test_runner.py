# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic process-isolated pytest execution for developer gates."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import xml.etree.ElementTree as element_tree
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_WORKERS = 12


@dataclass(frozen=True, slots=True)
class TestOptions:
    """Validated execution settings for a pytest layer."""

    jobs: str = "auto"
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    serial_only: bool = False
    fail_fast: bool = False

    def __post_init__(self) -> None:
        """Reject unsafe or ambiguous execution settings before spawning pytest."""

        if self.jobs != "auto" and (not self.jobs.isdecimal() or int(self.jobs) < 1):
            raise ValueError("jobs must be 'auto' or a positive integer")
        if self.timeout_seconds < 1:
            raise ValueError("timeout must be a positive integer")


@dataclass(frozen=True, slots=True)
class TestSummary:
    """Stable aggregate evidence from one or more pytest subprocesses."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    timeout: int = 0
    duration_seconds: float = 0.0

    def Combine(self, other: TestSummary) -> TestSummary:
        """Return the deterministic sum of two independent pytest reports.

        Args:
            other: Independent summary to add without mutating either input.

        Returns:
            New summary containing summed counts and subprocess durations.
        """

        return TestSummary(
            total=self.total + other.total,
            passed=self.passed + other.passed,
            failed=self.failed + other.failed,
            skipped=self.skipped + other.skipped,
            timeout=self.timeout + other.timeout,
            duration_seconds=self.duration_seconds + other.duration_seconds,
        )

    def Display(self) -> str:
        """Render one machine-readable, stable terminal-summary line.

        Returns:
            Stable single-line summary of counts and subprocess durations.
        """

        return (
            "Test summary: "
            f"total={self.total} passed={self.passed} failed={self.failed} "
            f"skipped={self.skipped} timeout={self.timeout} "
            f"duration={self.duration_seconds:.3f}s"
        )


def AutoWorkerCount(cpu_count: int | None = None) -> int:
    """Return the bounded worker count used by xdist automatic scheduling.

    Args:
        cpu_count: Detected CPU count, or None to query the operating system.

    Returns:
        Automatic worker count capped at DEFAULT_MAX_WORKERS.
    """

    return min(cpu_count if cpu_count is not None else (os.cpu_count() or 1), DEFAULT_MAX_WORKERS)


def PytestArguments(
    target: str,
    options: TestOptions,
    report_path: Path,
    *,
    serial: bool,
) -> list[str]:
    """Build one explicit pytest argv without shell interpolation.

    Args:
        target: Pytest layer or selection
        options: Validated timeout, worker and fail-fast settings
        report_path: JUnit destination passed as one argv entry
        serial: Select serial tests without workers and with coverage append.

    Returns:
        Explicit pytest argv for a separate interpreter process.
    """

    arguments = [
        sys.executable,
        "-m",
        "pytest",
        target,
        "--junitxml",
        str(report_path),
        f"--timeout={options.timeout_seconds}",
    ]
    if options.fail_fast:
        arguments.append("-x")
    if serial:
        arguments.extend(("-m", "serial", "-n", "0", "--cov-append"))

    else:
        arguments.extend(("-m", "not serial", "-n", options.jobs, "--dist=loadscope"))
    return arguments


def ReadJunitSummary(report_path: Path) -> TestSummary:
    """Read one JUnit XML report without trusting process return codes as evidence.

    Parses persisted evidence; a successful process code alone does not prove a passing report.

    Args:
        report_path: JUnit XML produced by a pytest subprocess.

    Returns:
        Aggregated counts and durations, or one failure if the report is absent.

    Raises:
        element_tree.ParseError: The XML is malformed.
        ValueError: Numeric report attributes cannot be parsed.
    """

    if not report_path.is_file():
        return TestSummary(failed=1)
    root = element_tree.parse(report_path).getroot()
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
        duration_seconds=duration,
    )


def RunPytest(
    arguments: Sequence[str],
    report_path: Path,
    timeout_seconds: int,
) -> tuple[int, TestSummary]:
    """Run one pytest process and return its exit result with parsed evidence.

    Deletes stale report evidence before starting one bounded subprocess. XML parsing failures
    propagate rather than becoming success.

    Args:
        arguments: Explicit subprocess argv without shell interpolation
        report_path: Report to remove before launch and read on completion
        timeout_seconds: Per-test timeout also used to derive the process timeout floor.

    Returns:
        Exit code and summary, with failed summaries for timeout or launch errors.
    """

    report_path.unlink(missing_ok=True)
    started = time.monotonic()
    try:
        result = subprocess.run(
            arguments,
            check=False,
            shell=False,
            timeout=max(300, timeout_seconds * 3),
        )

    except subprocess.TimeoutExpired:
        return 124, TestSummary(failed=1, timeout=1, duration_seconds=time.monotonic() - started)

    except OSError:
        return 127, TestSummary(failed=1, duration_seconds=time.monotonic() - started)
    summary = ReadJunitSummary(report_path)
    return result.returncode, summary


def HasSerialTests(target: str) -> bool:
    """Discover serial tests before running a separate serial process.

    Starts collection with coverage disabled; it does not execute selected test bodies.

    Args:
        target: Selection whose serial-marked cases are collected.

    Returns:
        True only when serial-only collection exits successfully.

    Raises:
        subprocess.TimeoutExpired: Collection exceeds its process limit.
        OSError: The collection subprocess cannot be started.
    """

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
    """Run non-serial tests in xdist, then serial tests, and print aggregate evidence.

    Creates local coverage reports, runs nonserial tests in worker processes, then eligible
    serial tests, and prints aggregate evidence.

    Args:
        target: Pytest layer or selection to run
        options: Validated worker, timeout, serial-only and fail-fast settings.

    Returns:
        First nonzero subprocess status, or zero when selected invocations succeed.
    """

    reports = Path("coverage")
    reports.mkdir(exist_ok=True)
    summary = TestSummary()
    return_codes: list[int] = []
    if not options.serial_only:
        code, result = RunPytest(
            PytestArguments(target, options, reports / "parallel-tests.xml", serial=False),
            reports / "parallel-tests.xml",
            options.timeout_seconds,
        )
        summary = summary.Combine(result)
        return_codes.append(code)
    run_serial = options.serial_only or not options.fail_fast or not any(return_codes)
    if run_serial and HasSerialTests(target):
        code, result = RunPytest(
            PytestArguments(target, options, reports / "serial-tests.xml", serial=True),
            reports / "serial-tests.xml",
            options.timeout_seconds,
        )
        summary = summary.Combine(result)
        return_codes.append(code)
    print(summary.Display(), flush=True)
    return next((code for code in return_codes if code), 0)
