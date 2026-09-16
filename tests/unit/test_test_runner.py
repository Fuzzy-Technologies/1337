from __future__ import annotations

import pytest

from fuzzy1337 import test_runner


def test_auto_worker_count_is_capped_at_twelve():
    assert test_runner.auto_worker_count(64) == 12
    assert test_runner.auto_worker_count(3) == 3


@pytest.mark.parametrize("jobs", ["0", "-1", "many"])
def test_options_reject_invalid_worker_values(jobs):
    with pytest.raises(ValueError, match="jobs"):
        test_runner.TestOptions(jobs=jobs)


def test_options_reject_non_positive_timeouts():
    with pytest.raises(ValueError, match="timeout"):
        test_runner.TestOptions(timeout_seconds=0)


def test_parallel_arguments_use_process_workers_and_load_scope(tmp_path):
    arguments = test_runner.pytest_arguments(
        "tests/unit",
        test_runner.TestOptions(jobs="auto", timeout_seconds=42, fail_fast=True),
        tmp_path / "parallel.xml",
        serial=False,
    )
    assert arguments[:4] == [test_runner.sys.executable, "-m", "pytest", "tests/unit"]
    assert "-n" in arguments
    assert arguments[arguments.index("-n") + 1] == "auto"
    assert "--dist=loadscope" in arguments
    assert "-x" in arguments
    assert "not serial" in arguments
    assert "--timeout=42" in arguments


def test_serial_arguments_never_start_xdist_workers(tmp_path):
    arguments = test_runner.pytest_arguments(
        "tests/unit",
        test_runner.TestOptions(),
        tmp_path / "serial.xml",
        serial=True,
    )
    assert arguments[arguments.index("-n") + 1] == "0"
    assert "serial" in arguments
    assert "--dist=loadscope" not in arguments


def test_junit_summary_is_deterministic_and_counts_timeout(tmp_path):
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
    summary = test_runner.read_junit_summary(report)
    assert summary == test_runner.TestSummary(4, 2, 1, 1, 1, 1.25)
    assert summary.display() == (
        "Test summary: total=4 passed=2 failed=1 skipped=1 timeout=1 duration=1.250s"
    )


def test_default_run_executes_parallel_then_serial(monkeypatch, capsys):
    calls = []

    def run_pytest(arguments, report_path, timeout_seconds):
        calls.append(arguments)
        return 0, test_runner.TestSummary(total=2, passed=2, duration_seconds=0.5)

    monkeypatch.setattr(test_runner, "_run_pytest", run_pytest)
    monkeypatch.setattr(test_runner, "_has_serial_tests", lambda target: True)
    assert test_runner.run_tests("tests/unit", test_runner.TestOptions()) == 0
    assert len(calls) == 2
    assert "not serial" in calls[0]
    assert "serial" in calls[1]
    assert "total=4" in capsys.readouterr().out


def test_fail_fast_stops_before_serial_tests(monkeypatch):
    calls = []

    def run_pytest(arguments, report_path, timeout_seconds):
        calls.append(arguments)
        return 1, test_runner.TestSummary(total=1, failed=1)

    monkeypatch.setattr(test_runner, "_run_pytest", run_pytest)
    monkeypatch.setattr(test_runner, "_has_serial_tests", lambda target: True)
    assert test_runner.run_tests("tests/unit", test_runner.TestOptions(fail_fast=True)) == 1
    assert len(calls) == 1


def test_serial_only_never_starts_the_parallel_pool(monkeypatch):
    calls = []

    def run_pytest(arguments, report_path, timeout_seconds):
        calls.append(arguments)
        return 0, test_runner.TestSummary(total=1, passed=1)

    monkeypatch.setattr(test_runner, "_run_pytest", run_pytest)
    monkeypatch.setattr(test_runner, "_has_serial_tests", lambda target: True)
    assert test_runner.run_tests("tests/unit", test_runner.TestOptions(serial_only=True)) == 0
    assert len(calls) == 1
    assert "serial" in calls[0]
