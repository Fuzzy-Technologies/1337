from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path

from fuzzy1337 import doctor
from fuzzy1337.doctor import DoctorCheck, DoctorReport, DoctorStatus, collect_doctor_report


def test_report_renders_deterministically_and_fails_only_for_required_checks():
    report = DoctorReport(
        checks=(
            DoctorCheck("python", DoctorStatus.PASS, "ready"),
            DoctorCheck("docker-compose", DoctorStatus.WARN, "optional"),
            DoctorCheck("configuration", DoctorStatus.INFO, "not configured"),
        )
    )

    assert report.exit_code == 0
    assert report.render().splitlines() == [
        "1337 doctor",
        "PASS python               ready",
        "WARN docker-compose       optional",
        "INFO configuration        not configured",
        "Result: OK",
    ]

    failed = DoctorReport((DoctorCheck("package", DoctorStatus.FAIL, "missing"),))
    assert failed.exit_code == 1
    assert failed.render().endswith("Result: FAIL")


def test_python_runtime_reports_supported_and_unsupported_versions(monkeypatch):
    monkeypatch.setattr(doctor.sys, "version_info", (3, 10, 9))
    assert doctor._check_python_runtime() == DoctorCheck(
        "python",
        DoctorStatus.FAIL,
        "Python 3.10.9 is below the required 3.11.",
    )

    monkeypatch.setattr(doctor.sys, "version_info", (3, 11, 0))
    monkeypatch.setattr(doctor.sys, "executable", "/usr/bin/python")
    assert doctor._check_python_runtime() == DoctorCheck(
        "python",
        DoctorStatus.PASS,
        "Python 3.11.0 at /usr/bin/python",
    )


def test_package_installation_reports_missing_and_installed_distribution(monkeypatch):
    monkeypatch.setattr(doctor, "version", lambda _: "0.1.8")
    assert doctor._check_package_installation().status is DoctorStatus.PASS

    def raise_package_not_found(_: str) -> str:
        raise doctor.PackageNotFoundError

    monkeypatch.setattr(doctor, "version", raise_package_not_found)
    assert doctor._check_package_installation() == DoctorCheck(
        "package",
        DoctorStatus.FAIL,
        "The 1337 distribution is not installed.",
    )


def test_workspace_check_handles_readability_and_write_access(monkeypatch, tmp_path):
    missing = tmp_path / "missing"
    assert doctor._check_working_directory(missing).status is DoctorStatus.FAIL

    monkeypatch.setattr(doctor.os, "access", lambda *_: False)
    assert doctor._check_working_directory(tmp_path).status is DoctorStatus.FAIL

    checks = iter((True, False))
    monkeypatch.setattr(doctor.os, "access", lambda *_: next(checks))
    assert doctor._check_working_directory(tmp_path).status is DoctorStatus.WARN

    monkeypatch.setattr(doctor.os, "access", lambda *_: True)
    assert doctor._check_working_directory(tmp_path).status is DoctorStatus.PASS


def test_docker_compose_check_handles_optional_tool_outcomes(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda _: None)
    assert doctor._check_docker_compose().status is DoctorStatus.WARN

    monkeypatch.setattr(doctor.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *_, **__: (_ for _ in ()).throw(OSError()))
    assert doctor._check_docker_compose().status is DoctorStatus.WARN

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: (_ for _ in ()).throw(subprocess.TimeoutExpired(("docker",), 5)),
    )
    assert doctor._check_docker_compose().status is DoctorStatus.WARN

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(("docker",), 1, "", "unavailable"),
    )
    assert doctor._check_docker_compose().status is DoctorStatus.WARN

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(("docker",), 0, "Docker Compose", ""),
    )
    assert doctor._check_docker_compose().status is DoctorStatus.PASS


def test_collect_and_run_doctor_keep_the_configuration_boundary_explicit(monkeypatch):
    checks = (
        DoctorCheck("python", DoctorStatus.PASS, "ready"),
        DoctorCheck("package", DoctorStatus.PASS, "installed"),
        DoctorCheck("workspace", DoctorStatus.PASS, "writable"),
        DoctorCheck("docker-compose", DoctorStatus.WARN, "optional"),
        DoctorCheck("configuration", DoctorStatus.INFO, "not available"),
    )
    monkeypatch.setattr(doctor, "_check_python_runtime", lambda: checks[0])
    monkeypatch.setattr(doctor, "_check_package_installation", lambda: checks[1])
    monkeypatch.setattr(doctor, "_check_working_directory", lambda _: checks[2])
    monkeypatch.setattr(doctor, "_check_docker_compose", lambda: checks[3])
    monkeypatch.setattr(doctor, "_check_configuration_boundary", lambda: checks[4])

    report = collect_doctor_report(Path("/workspace"))
    assert report.checks == checks

    monkeypatch.setattr(doctor, "collect_doctor_report", lambda: DoctorReport(checks))
    output = StringIO()
    assert doctor.run_doctor(output) == 0
    assert output.getvalue().endswith("Result: OK\n")
