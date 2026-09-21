"""Tests for dev commands behavior."""

import subprocess
import sys
from unittest.mock import Mock

import pytest

from fuzzy1337 import dev_commands as devCommands


@pytest.fixture(name="repository")
def Repository(monkeypatch, tmp_path):
    """Provide the repository test fixture."""

    (tmp_path / "pyproject.toml").write_text("[project]\nname = '1337'\n", encoding="utf-8")
    (tmp_path / "src/fuzzy1337").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_UnknownCommandNeverStartsAProcess(monkeypatch):
    """Verify unknown command never starts a process."""

    Process = Mock()
    monkeypatch.setattr(subprocess, "run", Process)
    with pytest.raises(ValueError, match="Unknown developer command"):
        devCommands.Run("arbitrary shell command")
    Process.assert_not_called()


def test_MissingRepositoryIsReported(monkeypatch, tmp_path, capsys):
    """Verify missing repository is reported."""

    monkeypatch.chdir(tmp_path)
    Process = Mock()
    monkeypatch.setattr(subprocess, "run", Process)
    assert devCommands.Run("lint") == 2, "missing repository is reported invariant failed."
    assert "repository root" in capsys.readouterr().err, (
        "missing repository is reported invariant failed."
    )
    Process.assert_not_called()


def test_CheckRunsAllQualityStepsAndRemovesStaleReport(repository, monkeypatch):
    """Verify check runs all quality steps and removes stale report."""

    report = repository / "coverage/coverage.json"
    report.parent.mkdir()
    report.write_text("stale", encoding="utf-8")
    calls = []

    testProcess = Mock(return_value=0)
    monkeypatch.setattr(devCommands, "RunTests", testProcess)

    def Process(arguments, **kwargs):
        """Provide deterministic test support for process."""

        calls.append(arguments)
        assert arguments[0] == sys.executable, "process invariant failed."
        assert kwargs == {"shell": False, "timeout": 300, "check": False}, (
            "process invariant failed."
        )
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", Process)
    assert devCommands.Run("check") == 0, (
        "check runs all quality steps and removes stale report invariant failed."
    )
    assert [call[2] for call in calls] == [
        "compileall",
        "ruff",
        "mypy",
        "fuzzy1337.coverage_gate",
        "build",
    ], "check runs all quality steps and removes stale report invariant failed."
    testProcess.assert_called_once()
    assert not report.exists(), (
        "check runs all quality steps and removes stale report invariant failed."
    )


def test_UnitRunsOnlyTheUnitSuiteAndCoverageGate(repository, monkeypatch):
    """Verify unit runs only the unit suite and coverage gate."""

    calls = []

    def Process(arguments, **kwargs):
        """Provide deterministic test support for process."""

        calls.append(arguments)
        assert kwargs == {"shell": False, "timeout": 300, "check": False}, (
            "process invariant failed."
        )
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", Process)
    testProcess = Mock(return_value=0)
    monkeypatch.setattr(devCommands, "RunTests", testProcess)

    assert devCommands.Run("unit") == 0, (
        "unit runs only the unit suite and coverage gate invariant failed."
    )
    assert calls == [
        [
            sys.executable,
            "-m",
            "fuzzy1337.coverage_gate",
            "coverage/coverage.json",
            "src/fuzzy1337",
        ],
    ], "unit runs only the unit suite and coverage gate invariant failed."
    testProcess.assert_called_once()


def test_SetupUsesLockedUv(repository, monkeypatch):
    """Verify setup uses locked uv."""

    Process = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", Process)
    monkeypatch.setattr(devCommands.shutil, "which", lambda command: "/tools/uv")

    assert devCommands.Run("setup") == 0, "setup uses locked uv invariant failed."

    Process.assert_called_once_with(
        ["/tools/uv", "sync", "--locked", "--extra", "dev"],
        shell=False,
        timeout=300,
        check=False,
    )


def test_SetupFailsClosedWhenUvIsMissing(repository, monkeypatch, capsys):
    """Verify setup fails closed when uv is missing."""

    Process = Mock()
    monkeypatch.setattr(subprocess, "run", Process)
    monkeypatch.setattr(devCommands.shutil, "which", lambda command: None)

    assert devCommands.Run("setup") == 127, (
        "setup fails closed when uv is missing invariant failed."
    )
    assert "uv" in capsys.readouterr().err, (
        "setup fails closed when uv is missing invariant failed."
    )
    Process.assert_not_called()


@pytest.mark.parametrize(
    "returncode, expected",
    [(1, 1), (42, 42), (-9, 137)],
)
def test_ChildFailureStopsTheGate(repository, monkeypatch, returncode, expected):
    """Verify child failure stops the gate."""

    Process = Mock(return_value=subprocess.CompletedProcess([], returncode))
    monkeypatch.setattr(subprocess, "run", Process)
    assert devCommands.Run("check") == expected, "child failure stops the gate invariant failed."
    assert Process.call_count == 1, "child failure stops the gate invariant failed."


@pytest.mark.parametrize("code", [1, 124, 127])
def test_TestRunnerFailureStopsTheGate(repository, monkeypatch, code):
    """Verify test runner failure stops the gate."""

    Process = Mock()
    monkeypatch.setattr(subprocess, "run", Process)
    monkeypatch.setattr(devCommands, "RunTests", Mock(return_value=code))
    assert devCommands.Run("test") == code, "test runner failure stops the gate invariant failed."
    Process.assert_not_called()


def test_DeveloperEntrypointPropagatesResult(monkeypatch):
    """Verify developer entrypoint propagates result."""

    Process = Mock(return_value=42)
    monkeypatch.setattr(devCommands, "Run", Process)
    assert devCommands.Main(["test"]) == 42, (
        "developer entrypoint propagates result invariant failed."
    )
    Process.assert_called_once_with("test", devCommands.TestOptions())


def test_UnapprovedFormatterIsNotACommand():
    """Verify unapproved formatter is not a command."""

    with pytest.raises(SystemExit) as caught:
        devCommands.Main(["format"])
    assert caught.value.code == 2, "unapproved formatter is not a command invariant failed."
