"""Детерминированная диагностика локального окружения для CLI 1337."""

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

MINIMUMPYTHONVERSION = (3, 11)
DOCKERCOMPOSETIMEOUTSECONDS = 5


class DoctorStatus(StrEnum):
    """Классифицирует проверку, разделяя обязательные и необязательные инструменты."""

    PASS = "PASS"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """Описывает краткий детерминированный результат локальной проверки."""

    identifier: str
    status: DoctorStatus
    summary: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Хранит полный результат диагностического запуска без изменений среды."""

    checks: tuple[DoctorCheck, ...]

    @property
    def ExitCode(self) -> int:
        """Возвращает ошибку только при нарушении обязательного условия."""

        return int(any(check.status is DoctorStatus.FAIL for check in self.checks))

    def Render(self) -> str:
        """Формирует стабильный читаемый вывод для терминала и журналов."""

        lines = ["1337 doctor"]
        lines.extend(
            f"{check.status:<4} {check.identifier:<20} {check.summary}" for check in self.checks
        )
        lines.append("Result: FAIL" if self.ExitCode else "Result: OK")
        return "\n".join(lines)


def CollectDoctorReport(workingDirectory: Path | None = None) -> DoctorReport:
    """Проверяет runtime без изменения конфигурации или состояния пользователя."""

    directory = workingDirectory or Path.cwd()
    return DoctorReport(
        checks=(
            CheckPythonRuntime(),
            CheckPackageInstallation(),
            CheckWorkingDirectory(directory),
            CheckDockerCompose(),
            CheckConfigurationBoundary(),
        )
    )


def RunDoctor(output: TextIO) -> int:
    """Записывает отчёт и возвращает безопасный код процесса."""

    report = CollectDoctorReport()
    output.write(f"{report.Render()}\n")
    return report.ExitCode


def CheckPythonRuntime() -> DoctorCheck:
    """Проверяет минимальную версию Python из контракта пакета."""

    detected = sys.version_info[:3]
    if detected < MINIMUMPYTHONVERSION:
        required = ".".join(str(value) for value in MINIMUMPYTHONVERSION)
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


def CheckPackageInstallation() -> DoctorCheck:
    """Проверяет запуск команды из установленного дистрибутива 1337."""

    try:
        installedVersion = version("1337")

    except PackageNotFoundError:
        return DoctorCheck(
            identifier="package",
            status=DoctorStatus.FAIL,
            summary="The 1337 distribution is not installed.",
        )

    return DoctorCheck(
        identifier="package",
        status=DoctorStatus.PASS,
        summary=f"1337 {installedVersion} is installed.",
    )


def CheckWorkingDirectory(directory: Path) -> DoctorCheck:
    """Проверяет пригодность текущего каталога для состояния workspace."""

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


def CheckDockerCompose() -> DoctorCheck:
    """Проверяет необязательный Compose без запуска контейнера или цели."""

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
            timeout=DOCKERCOMPOSETIMEOUTSECONDS,
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


def CheckConfigurationBoundary() -> DoctorCheck:
    """Описывает границу конфигурации без выдумывания её формата."""

    return DoctorCheck(
        identifier="configuration",
        status=DoctorStatus.INFO,
        summary="Workspace configuration is not available until the M1 workspace model lands.",
    )
