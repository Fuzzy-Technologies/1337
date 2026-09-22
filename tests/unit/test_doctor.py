"""Tests for doctor behavior."""

from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path

from fuzzy1337 import doctor
from fuzzy1337.doctor import CollectDoctorReport, DoctorCheck, DoctorReport, DoctorStatus


def test_ReportRendersDeterministicallyAndFailsOnlyForRequiredChecks():
    """Verify report renders deterministically and fails only for required checks."""

    report = DoctorReport(
        checks=(
            DoctorCheck("python", DoctorStatus.PASS, "ready"),
            DoctorCheck("docker-compose", DoctorStatus.WARN, "optional"),
            DoctorCheck("configuration", DoctorStatus.INFO, "not configured"),
        )
    )

    assert report.ExitCode == 0, (
        "report renders deterministically and fails only for required checks invariant failed."
    )
    assert report.Render().splitlines() == [
        "1337 doctor",
        "PASS python               ready",
        "WARN docker-compose       optional",
        "INFO configuration        not configured",
        "Result: OK",
    ], "report renders deterministically and fails only for required checks invariant failed."

    failed = DoctorReport((DoctorCheck("package", DoctorStatus.FAIL, "missing"),))
    assert failed.ExitCode == 1, (
        "report renders deterministically and fails only for required checks invariant failed."
    )
    assert failed.Render().endswith("Result: FAIL"), (
        "report renders deterministically and fails only for required checks invariant failed."
    )


def test_PythonRuntimeReportsSupportedAndUnsupportedVersions(monkeypatch):
    """Verify python runtime reports supported and unsupported versions."""

    monkeypatch.setattr(doctor.sys, "version_info", (3, 10, 9))
    assert doctor.CheckPythonRuntime() == DoctorCheck(
        "python",
        DoctorStatus.FAIL,
        "Python 3.10.9 is below the required 3.11.",
    ), "python runtime reports supported and unsupported versions invariant failed."

    monkeypatch.setattr(doctor.sys, "version_info", (3, 11, 0))
    monkeypatch.setattr(doctor.sys, "executable", "/usr/bin/python")
    assert doctor.CheckPythonRuntime() == DoctorCheck(
        "python",
        DoctorStatus.PASS,
        "Python 3.11.0 at /usr/bin/python",
    ), "python runtime reports supported and unsupported versions invariant failed."


def test_PackageInstallationReportsMissingAndInstalledDistribution(monkeypatch):
    """Verify package installation reports missing and installed distribution."""

    monkeypatch.setattr(doctor, "version", lambda _: "0.1.8")
    assert doctor.CheckPackageInstallation().status is DoctorStatus.PASS, (
        "package installation reports missing and installed distribution invariant failed."
    )

    def RaisePackageNotFound(_: str) -> str:
        """Provide deterministic test support for raise package not found."""

        raise doctor.PackageNotFoundError

    monkeypatch.setattr(doctor, "version", RaisePackageNotFound)
    assert doctor.CheckPackageInstallation() == DoctorCheck(
        "package",
        DoctorStatus.FAIL,
        "The 1337 distribution is not installed.",
    ), "package installation reports missing and installed distribution invariant failed."


def test_WorkspaceCheckHandlesReadabilityAndWriteAccess(monkeypatch, tmp_path):
    """Verify workspace check handles readability and write access."""

    missing = tmp_path / "missing"
    assert doctor.CheckWorkingDirectory(missing).status is DoctorStatus.FAIL, (
        "workspace check handles readability and write access invariant failed."
    )

    monkeypatch.setattr(doctor.os, "access", lambda *_: False)
    assert doctor.CheckWorkingDirectory(tmp_path).status is DoctorStatus.FAIL, (
        "workspace check handles readability and write access invariant failed."
    )

    checks = iter((True, False))
    monkeypatch.setattr(doctor.os, "access", lambda *_: next(checks))
    assert doctor.CheckWorkingDirectory(tmp_path).status is DoctorStatus.WARN, (
        "workspace check handles readability and write access invariant failed."
    )

    monkeypatch.setattr(doctor.os, "access", lambda *_: True)
    assert doctor.CheckWorkingDirectory(tmp_path).status is DoctorStatus.PASS, (
        "workspace check handles readability and write access invariant failed."
    )


def test_DockerComposeCheckHandlesOptionalToolOutcomes(monkeypatch):
    """Verify docker compose check handles optional tool outcomes."""

    monkeypatch.setattr(doctor.shutil, "which", lambda _: None)
    assert doctor.CheckDockerCompose().status is DoctorStatus.WARN, (
        "docker compose check handles optional tool outcomes invariant failed."
    )

    monkeypatch.setattr(doctor.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *_, **__: (_ for _ in ()).throw(OSError()))
    assert doctor.CheckDockerCompose().status is DoctorStatus.WARN, (
        "docker compose check handles optional tool outcomes invariant failed."
    )

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: (_ for _ in ()).throw(subprocess.TimeoutExpired(("docker",), 5)),
    )
    assert doctor.CheckDockerCompose().status is DoctorStatus.WARN, (
        "docker compose check handles optional tool outcomes invariant failed."
    )

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(("docker",), 1, "", "unavailable"),
    )
    assert doctor.CheckDockerCompose().status is DoctorStatus.WARN, (
        "docker compose check handles optional tool outcomes invariant failed."
    )

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(("docker",), 0, "Docker Compose", ""),
    )
    assert doctor.CheckDockerCompose().status is DoctorStatus.PASS, (
        "docker compose check handles optional tool outcomes invariant failed."
    )


def test_CollectAndRunDoctorKeepTheConfigurationBoundaryExplicit(monkeypatch):
    """Verify collect and run doctor keep the configuration boundary explicit."""

    checks = (
        DoctorCheck("python", DoctorStatus.PASS, "ready"),
        DoctorCheck("package", DoctorStatus.PASS, "installed"),
        DoctorCheck("workspace", DoctorStatus.PASS, "writable"),
        DoctorCheck("docker-compose", DoctorStatus.WARN, "optional"),
        DoctorCheck("configuration", DoctorStatus.INFO, "not available"),
    )
    monkeypatch.setattr(doctor, "CheckPythonRuntime", lambda: checks[0])
    monkeypatch.setattr(doctor, "CheckPackageInstallation", lambda: checks[1])
    monkeypatch.setattr(doctor, "CheckWorkingDirectory", lambda _: checks[2])
    monkeypatch.setattr(doctor, "CheckDockerCompose", lambda: checks[3])
    monkeypatch.setattr(doctor, "CheckConfigurationBoundary", lambda: checks[4])

    report = CollectDoctorReport(Path("/workspace"))
    assert report.checks == checks, (
        "collect and run doctor keep the configuration boundary explicit invariant failed."
    )

    monkeypatch.setattr(doctor, "CollectDoctorReport", lambda: DoctorReport(checks))
    output = StringIO()
    assert doctor.RunDoctor(output) == 0, (
        "collect and run doctor keep the configuration boundary explicit invariant failed."
    )
    assert output.getvalue().endswith("Result: OK\n"), (
        "collect and run doctor keep the configuration boundary explicit invariant failed."
    )
