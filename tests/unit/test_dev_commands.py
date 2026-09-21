"""Tests for dev commands behavior."""

import subprocess
import sys
from unittest.mock import Mock

import pytest

from fuzzy1337 import dev_commands


@pytest.fixture
def repository(monkeypatch, tmp_path):
    """Provide the repository test fixture."""

    (tmp_path / "pyproject.toml").write_text("[project]\nname = '1337'\n", encoding="utf-8")
    (tmp_path / "src/fuzzy1337").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_UnknownCommandNeverStartsAProcess(monkeypatch):
    """Verify unknown command never starts a process."""

    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    with pytest.raises(ValueError, match="Unknown developer command"):
        dev_commands.Run("arbitrary shell command")
    process.assert_not_called()


def test_MissingRepositoryIsReported(monkeypatch, tmp_path, capsys):
    """Verify missing repository is reported."""

    monkeypatch.chdir(tmp_path)
    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.Run("lint") == 2, "missing repository is reported invariant failed."
    assert "repository root" in capsys.readouterr().err, (
        "missing repository is reported invariant failed."
    )
    process.assert_not_called()


def test_CheckRunsAllQualityStepsAndRemovesStaleReport(repository, monkeypatch):
    """Verify check runs all quality steps and removes stale report."""

    report = repository / "coverage/coverage.json"
    report.parent.mkdir()
    report.write_text("stale", encoding="utf-8")
    calls = []

    test_process = Mock(return_value=0)
    monkeypatch.setattr(dev_commands, "RunTests", test_process)

    def Process(arguments, **kwargs):
        """Provide deterministic test support for process."""

        calls.append(arguments)
        assert arguments[0] == sys.executable, "process invariant failed."
        assert kwargs == {"shell": False, "timeout": 300, "check": False}, (
            "process invariant failed."
        )
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", Process)
    assert dev_commands.Run("check") == 0, (
        "check runs all quality steps and removes stale report invariant failed."
    )
    assert [call[2] for call in calls] == [
        "compileall",
        "ruff",
        "ruff",
        "mypy",
        "fuzzy1337.coverage_gate",
        "build",
    ], "check runs all quality steps and removes stale report invariant failed."
    test_process.assert_called_once()
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
    test_process = Mock(return_value=0)
    monkeypatch.setattr(dev_commands, "RunTests", test_process)

    assert dev_commands.Run("unit") == 0, (
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
    test_process.assert_called_once()


def test_SetupUsesLockedUv(repository, monkeypatch):
    """Verify setup uses locked uv."""

    process = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands.shutil, "which", lambda command: "/tools/uv")

    assert dev_commands.Run("setup") == 0, "setup uses locked uv invariant failed."

    process.assert_called_once_with(
        ["/tools/uv", "sync", "--locked", "--extra", "dev"],
        shell=False,
        timeout=300,
        check=False,
    )


def test_SetupFailsClosedWhenUvIsMissing(repository, monkeypatch, capsys):
    """Verify setup fails closed when uv is missing."""

    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands.shutil, "which", lambda command: None)

    assert dev_commands.Run("setup") == 127, (
        "setup fails closed when uv is missing invariant failed."
    )
    assert "uv" in capsys.readouterr().err, (
        "setup fails closed when uv is missing invariant failed."
    )
    process.assert_not_called()


@pytest.mark.parametrize(
    "returncode, expected",
    [(1, 1), (42, 42), (-9, 137)],
)
def test_ChildFailureStopsTheGate(repository, monkeypatch, returncode, expected):
    """Verify child failure stops the gate."""

    process = Mock(return_value=subprocess.CompletedProcess([], returncode))
    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.Run("check") == expected, "child failure stops the gate invariant failed."
    assert process.call_count == 1, "child failure stops the gate invariant failed."


@pytest.mark.parametrize("code", [1, 124, 127])
def test_TestRunnerFailureStopsTheGate(repository, monkeypatch, code):
    """Verify test runner failure stops the gate."""

    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands, "RunTests", Mock(return_value=code))
    assert dev_commands.Run("test") == code, "test runner failure stops the gate invariant failed."
    process.assert_not_called()


def test_DeveloperEntrypointPropagatesResult(monkeypatch):
    """Verify developer entrypoint propagates result."""

    process = Mock(return_value=42)
    monkeypatch.setattr(dev_commands, "Run", process)
    assert dev_commands.Main(["test"]) == 42, (
        "developer entrypoint propagates result invariant failed."
    )
    process.assert_called_once_with("test", dev_commands.TestOptions())


def test_UnapprovedFormatterIsNotACommand():
    """Verify unapproved formatter is not a command."""

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["format"])
    assert caught.value.code == 2, "unapproved formatter is not a command invariant failed."
