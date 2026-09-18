"""Deterministic local environment diagnostics for the 1337 CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TextIO

MINIMUM_PYTHON_VERSION = (3, 11)
DOCKER_COMPOSE_TIMEOUT_SECONDS = 5


class DoctorStatus(StrEnum):
    """Classify one diagnostic without conflating optional and required tooling."""

    PASS = "PASS"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """Describe one concise, deterministic local diagnostic result."""

    identifier: str
    status: DoctorStatus
    summary: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Collect the complete result of one non-mutating diagnostic run."""

    checks: tuple[DoctorCheck, ...]

    @property
    def exit_code(self) -> int:
        """Fail only when a required local precondition cannot be proven."""

        return int(any(check.status is DoctorStatus.FAIL for check in self.checks))

    def render(self) -> str:
        """Render stable human-readable output for terminals and captured logs."""

        lines = ["1337 doctor"]
        lines.extend(
            f"{check.status:<4} {check.identifier:<20} {check.summary}" for check in self.checks
        )
        lines.append("Result: FAIL" if self.exit_code else "Result: OK")
        return "\n".join(lines)


def collect_doctor_report(working_directory: Path | None = None) -> DoctorReport:
    """Inspect the local runtime without modifying configuration or user state."""

    directory = working_directory or Path.cwd()
    return DoctorReport(
        checks=(
            _check_python_runtime(),
            _check_package_installation(),
            _check_working_directory(directory),
            _check_docker_compose(),
            _check_configuration_boundary(),
        )
    )


def run_doctor(output: TextIO) -> int:
    """Write the diagnostic report and return its fail-closed process status."""

    report = collect_doctor_report()
    output.write(f"{report.render()}\n")
    return report.exit_code


def _check_python_runtime() -> DoctorCheck:
    """Verify the minimum Python runtime required by the package contract."""

    detected = sys.version_info[:3]
    if detected < MINIMUM_PYTHON_VERSION:
        required = ".".join(str(value) for value in MINIMUM_PYTHON_VERSION)
        actual = ".".join(str(value) for value in detected)
        return DoctorCheck(
            identifier="python",
            status=DoctorStatus.FAIL,
            summary=f"Python {actual} is below the required {required}.",
        )

    actual = ".".join(str(value) for value in detected)
    return DoctorCheck(
        identifier="python",
        status=DoctorStatus.PASS,
        summary=f"Python {actual} at {sys.executable}",
    )


def _check_package_installation() -> DoctorCheck:
    """Verify that the command runs from an installed 1337 distribution."""

    try:
        installed_version = version("1337")
    except PackageNotFoundError:
        return DoctorCheck(
            identifier="package",
            status=DoctorStatus.FAIL,
            summary="The 1337 distribution is not installed.",
        )

    return DoctorCheck(
        identifier="package",
        status=DoctorStatus.PASS,
        summary=f"1337 {installed_version} is installed.",
    )


def _check_working_directory(directory: Path) -> DoctorCheck:
    """Report whether the current directory can host future workspace state."""

    if not directory.is_dir() or not os.access(directory, os.R_OK):
        return DoctorCheck(
            identifier="workspace",
            status=DoctorStatus.FAIL,
            summary=f"{directory} is not a readable directory.",
        )

    if not os.access(directory, os.W_OK):
        return DoctorCheck(
            identifier="workspace",
            status=DoctorStatus.WARN,
            summary=f"{directory} is readable but not writable.",
        )

    return DoctorCheck(
        identifier="workspace",
        status=DoctorStatus.PASS,
        summary=f"{directory} is readable and writable.",
    )


def _check_docker_compose() -> DoctorCheck:
    """Check optional Compose support without starting a container or target."""

    if shutil.which("docker") is None:
        return DoctorCheck(
            identifier="docker-compose",
            status=DoctorStatus.WARN,
            summary="Docker is unavailable; target-backed functional tests will skip.",
        )

    try:
        result = subprocess.run(
            ("docker", "compose", "version"),
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            timeout=DOCKER_COMPOSE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return DoctorCheck(
            identifier="docker-compose",
            status=DoctorStatus.WARN,
            summary="Docker Compose could not be queried; functional tests will skip.",
        )

    if result.returncode:
        return DoctorCheck(
            identifier="docker-compose",
            status=DoctorStatus.WARN,
            summary="Docker Compose is unavailable; functional tests will skip.",
        )

    return DoctorCheck(
        identifier="docker-compose",
        status=DoctorStatus.PASS,
        summary="Docker Compose is available for repository-owned synthetic targets.",
    )


def _check_configuration_boundary() -> DoctorCheck:
    """Explain the current configuration boundary without inventing a config format."""

    return DoctorCheck(
        identifier="configuration",
        status=DoctorStatus.INFO,
        summary="Workspace configuration is not available until the M1 workspace model lands.",
    )
