import subprocess
import sys
from unittest.mock import Mock

import pytest

from fuzzy1337 import dev_commands


@pytest.fixture
def repository(monkeypatch, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = '1337'\n", encoding="utf-8")
    (tmp_path / "src/fuzzy1337").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_unknown_command_never_starts_a_process(monkeypatch):
    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    with pytest.raises(ValueError, match="Unknown developer command"):
        dev_commands.run("arbitrary shell command")
    process.assert_not_called()


def test_missing_repository_is_reported(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.run("lint") == 2
    assert "repository root" in capsys.readouterr().err
    process.assert_not_called()


def test_check_runs_all_quality_steps_and_removes_stale_report(repository, monkeypatch):
    report = repository / "coverage/coverage.json"
    report.parent.mkdir()
    report.write_text("stale", encoding="utf-8")
    calls = []

    def process(arguments, **kwargs):
        calls.append(arguments)
        assert arguments[0] == sys.executable
        assert kwargs == {"shell": False, "timeout": 300, "check": False}
        if arguments[1:3] == ["-m", "pytest"]:
            assert not report.exists()
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.run("check") == 0
    assert [call[2] for call in calls] == [
        "compileall", "ruff", "mypy", "pytest", "fuzzy1337.coverage_gate", "build",
    ]
    assert calls[3][3:] == ["tests"]


def test_unit_runs_only_the_unit_suite_and_coverage_gate(repository, monkeypatch):
    calls = []

    def process(arguments, **kwargs):
        calls.append(arguments)
        assert kwargs == {"shell": False, "timeout": 300, "check": False}
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", process)

    assert dev_commands.run("unit") == 0
    assert calls == [
        [sys.executable, "-m", "pytest", "tests/unit"],
        [
            sys.executable,
            "-m",
            "fuzzy1337.coverage_gate",
            "coverage/coverage.json",
            "src/fuzzy1337",
        ],
    ]


def test_setup_uses_locked_uv(repository, monkeypatch):
    process = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands.shutil, "which", lambda command: "/tools/uv")

    assert dev_commands.run("setup") == 0

    process.assert_called_once_with(
        ["/tools/uv", "sync", "--locked", "--extra", "dev"],
        shell=False,
        timeout=300,
        check=False,
    )


def test_setup_fails_closed_when_uv_is_missing(repository, monkeypatch, capsys):
    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands.shutil, "which", lambda command: None)

    assert dev_commands.run("setup") == 127
    assert "uv" in capsys.readouterr().err
    process.assert_not_called()


@pytest.mark.parametrize("returncode, expected", [(1, 1), (42, 42), (-9, 137)])
def test_child_failure_stops_the_gate(repository, monkeypatch, returncode, expected):
    process = Mock(return_value=subprocess.CompletedProcess([], returncode))
    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.run("check") == expected
    assert process.call_count == 1


@pytest.mark.parametrize(
    "error, code",
    [(FileNotFoundError(2, "Executable missing"), 127), (subprocess.TimeoutExpired("python", 300), 124)],
)
def test_process_start_and_timeout_fail_closed(repository, monkeypatch, error, code, capsys):
    process = Mock(side_effect=error)
    monkeypatch.setattr(subprocess, "run", process)
    assert dev_commands.run("test") == code
    assert capsys.readouterr().err
    assert process.call_count == 1


def test_developer_entrypoint_propagates_result(monkeypatch):
    process = Mock(return_value=42)
    monkeypatch.setattr(dev_commands, "run", process)
    assert dev_commands.main(["test"]) == 42
    process.assert_called_once_with("test")


def test_unapproved_formatter_is_not_a_command():
    with pytest.raises(SystemExit) as caught:
        dev_commands.main(["format"])
    assert caught.value.code == 2
