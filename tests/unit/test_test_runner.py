"""Tests for test runner behavior."""

from __future__ import annotations

import subprocess

import pytest

from fuzzy1337 import test_runner


def test_AutoWorkerCountIsCappedAtTwelve():
    """Verify auto worker count is capped at twelve."""

    assert test_runner.AutoWorkerCount(64) == 12, (
        "auto worker count is capped at twelve invariant failed."
    )
    assert test_runner.AutoWorkerCount(3) == 3, (
        "auto worker count is capped at twelve invariant failed."
    )


@pytest.mark.parametrize("jobs", ["0", "-1", "many"])
def test_OptionsRejectInvalidWorkerValues(jobs):
    """Verify options reject invalid worker values."""

    with pytest.raises(ValueError, match="jobs"):
        test_runner.TestOptions(jobs=jobs)


def test_OptionsRejectNonPositiveTimeouts():
    """Verify options reject non positive timeouts."""

    with pytest.raises(ValueError, match="timeout"):
        test_runner.TestOptions(timeout_seconds=0)


def test_ParallelArgumentsUseProcessWorkersAndLoadScope(tmp_path):
    """Verify parallel arguments use process workers and load scope."""

    arguments = test_runner.PytestArguments(
        "tests/unit",
        test_runner.TestOptions(jobs="auto", timeout_seconds=42, fail_fast=True),
        tmp_path / "parallel.xml",
        serial=False,
    )
    assert arguments[:4] == [test_runner.sys.executable, "-m", "pytest", "tests/unit"], (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert "-n" in arguments, (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert arguments[arguments.index("-n") + 1] == "auto", (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert "--dist=loadscope" in arguments, (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert "-x" in arguments, (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert "not serial" in arguments, (
        "parallel arguments use process workers and load scope invariant failed."
    )
    assert "--timeout=42" in arguments, (
        "parallel arguments use process workers and load scope invariant failed."
    )


def test_SerialArgumentsNeverStartXdistWorkers(tmp_path):
    """Verify serial arguments never start xdist workers."""

    arguments = test_runner.PytestArguments(
        "tests/unit",
        test_runner.TestOptions(),
        tmp_path / "serial.xml",
        serial=True,
    )
    assert arguments[arguments.index("-n") + 1] == "0", (
        "serial arguments never start xdist workers invariant failed."
    )
    assert "serial" in arguments, "serial arguments never start xdist workers invariant failed."
    assert "--dist=loadscope" not in arguments, (
        "serial arguments never start xdist workers invariant failed."
    )


def test_JunitSummaryIsDeterministicAndCountsTimeout(tmp_path):
    """Verify junit summary is deterministic and counts timeout."""

    report = tmp_path / "report.xml"
    report.write_text(
        """<?xml version=\"1.0\"?>
<testsuite tests=\"4\" failures=\"1\" errors=\"0\" skipped=\"1\" time=\"1.25\">
  <testcase name=\"passed\" />
  <testcase name=\"skipped\"><skipped /></testcase>
  <testcase name=\"timeout\"><failure message=\"Timeout exceeded\" /></testcase>
  <testcase name=\"passed-too\" />
</testsuite>
""",
        encoding="utf-8",
    )
    summary = test_runner.ReadJunitSummary(report)
    assert summary == test_runner.TestSummary(4, 2, 1, 1, 1, 1.25), (
        "junit summary is deterministic and counts timeout invariant failed."
    )
    assert summary.Display() == (
        "Test summary: total=4 passed=2 failed=1 skipped=1 timeout=1 duration=1.250s"
    ), "junit summary is deterministic and counts timeout invariant failed."


def test_DefaultRunExecutesParallelThenSerial(monkeypatch, capsys):
    """Verify default run executes parallel then serial."""

    calls = []

    def RunPytest(arguments, report_path, timeout_seconds):
        """Provide deterministic test support for run pytest."""

        calls.append(arguments)
        return 0, test_runner.TestSummary(total=2, passed=2, duration_seconds=0.5)

    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert test_runner.RunTests("tests/unit", test_runner.TestOptions()) == 0, (
        "default run executes parallel then serial invariant failed."
    )
    assert len(calls) == 2, "default run executes parallel then serial invariant failed."
    assert "not serial" in calls[0], "default run executes parallel then serial invariant failed."
    assert "serial" in calls[1], "default run executes parallel then serial invariant failed."
    assert "total=4" in capsys.readouterr().out, (
        "default run executes parallel then serial invariant failed."
    )


def test_FailFastStopsBeforeSerialTests(monkeypatch):
    """Verify fail fast stops before serial tests."""

    calls = []

    def RunPytest(arguments, report_path, timeout_seconds):
        """Provide deterministic test support for run pytest."""

        calls.append(arguments)
        return 1, test_runner.TestSummary(total=1, failed=1)

    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert test_runner.RunTests("tests/unit", test_runner.TestOptions(fail_fast=True)) == 1, (
        "fail fast stops before serial tests invariant failed."
    )
    assert len(calls) == 1, "fail fast stops before serial tests invariant failed."


def test_SerialOnlyNeverStartsTheParallelPool(monkeypatch):
    """Verify serial only never starts the parallel pool."""

    calls = []

    def RunPytest(arguments, report_path, timeout_seconds):
        """Provide deterministic test support for run pytest."""

        calls.append(arguments)
        return 0, test_runner.TestSummary(total=1, passed=1)

    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert test_runner.RunTests("tests/unit", test_runner.TestOptions(serial_only=True)) == 0, (
        "serial only never starts the parallel pool invariant failed."
    )
    assert len(calls) == 1, "serial only never starts the parallel pool invariant failed."
    assert "serial" in calls[0], "serial only never starts the parallel pool invariant failed."


def test_SerialCollectionDisablesCoverageWithoutDisablingItsPlugin(monkeypatch):
    """Verify serial collection disables coverage without disabling its plugin."""

    calls = []

    def Run(arguments, **kwargs):
        """Provide deterministic test support for run."""

        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(test_runner.subprocess, "run", Run)

    assert test_runner.HasSerialTests("tests"), (
        "serial collection disables coverage without disabling its plugin invariant failed."
    )
    arguments, kwargs = calls[0]
    assert arguments == [
        test_runner.sys.executable,
        "-m",
        "pytest",
        "tests",
        "-m",
        "serial",
        "--collect-only",
        "-q",
        "--no-cov",
    ], "serial collection disables coverage without disabling its plugin invariant failed."
    assert kwargs == {
        "check": False,
        "shell": False,
        "timeout": 300,
        "capture_output": True,
        "text": True,
    }, "serial collection disables coverage without disabling its plugin invariant failed."


def test_SerialCollectionReportsNoTestsWithoutTreatingItAsAnError(monkeypatch):
    """Verify serial collection reports no tests without treating it as an error."""

    monkeypatch.setattr(
        test_runner.subprocess,
        "run",
        lambda arguments, **kwargs: subprocess.CompletedProcess(arguments, 5),
    )

    assert not test_runner.HasSerialTests("tests"), (
        "serial collection reports no tests without treating it as an error invariant failed."
    )
