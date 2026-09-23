"""Tests for shell performance budgets and evidence."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import Mock

import pytest

from fuzzy1337 import performance
from fuzzy1337.performance import BenchmarkCase, BenchmarkResult


def test_BenchmarkResultUsesMedianBudgetAndStableSchema():
    """Verify stable aggregates govern pass/fail while preserving raw samples."""

    result = BenchmarkResult("palette", 2.0, (1.0, 9.0, 1.5), 100)

    assert result.MedianMs == 1.5, "benchmark median invariant failed."
    assert result.MaximumMs == 9.0, "benchmark maximum invariant failed."
    assert result.Passed, "benchmark budget invariant failed."
    assert result.ToDictionary() == {
        "name": "palette",
        "status": "pass",
        "budget_ms": 2.0,
        "median_ms": 1.5,
        "maximum_ms": 9.0,
        "sample_count": 3,
        "iterations_per_sample": 100,
        "samples_ms": [1.0, 9.0, 1.5],
    }, "benchmark schema invariant failed."


def test_MeasureWarmsUpAndNormalizesIterations(monkeypatch):
    """Verify measurement excludes warm-up and reports per-operation latency."""

    operation = Mock()
    times = iter((1_000_000, 5_000_000, 10_000_000, 16_000_000))
    monkeypatch.setattr(performance.time, "perf_counter_ns", lambda: next(times))
    case = BenchmarkCase("probe", 10.0, 2, 2, operation)

    result = performance.Measure(case)

    assert result.samples_ms == (2.0, 3.0), "measurement normalization invariant failed."
    assert operation.call_count == 5, "measurement warm-up invariant failed."


def test_ProcessProbeValidatesExitAndObservableOutput(monkeypatch):
    """Verify process probes require both success and expected output."""

    process = Mock(
        return_value=subprocess.CompletedProcess(
            args=["python"],
            returncode=0,
            stdout="ready",
            stderr="",
        )
    )
    monkeypatch.setattr(performance.subprocess, "run", process)

    performance.RunProcess(("python",), None, "ready")

    process.assert_called_once_with(
        ("python",),
        input=None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=performance.PROCESS_TIMEOUT_SECONDS,
        check=False,
    )


@pytest.mark.parametrize(
    "result, message",
    [
        (subprocess.CompletedProcess(["python"], 7, "", "broken"), "broken"),
        (subprocess.CompletedProcess(["python"], 0, "not ready", ""), "did not reach"),
    ],
)
def test_ProcessProbeFailsClosed(monkeypatch, result, message):
    """Verify failed or incomplete processes cannot satisfy a budget."""

    monkeypatch.setattr(performance.subprocess, "run", Mock(return_value=result))

    with pytest.raises(RuntimeError, match=message):
        performance.RunProcess(("python",), "quit\n", "expected")


def test_ImplementedCasesCoverOnlyCurrentShellPaths():
    """Verify budgets name the four currently measurable shell paths."""

    cases = performance.PerformanceCases()

    assert tuple(case.name for case in cases) == (
        "cli_cold_start",
        "interactive_readiness",
        "command_palette_search",
        "lens_view_switch",
    ), "implemented performance cases invariant failed."
    cases[2].operation()
    cases[3].operation()


def test_ReportAndRunPreserveMachineReadableEvidence(monkeypatch, tmp_path, capsys):
    """Verify the runner writes JSON evidence and returns a regression failure."""

    passing = BenchmarkResult("passing", 2.0, (1.0, 1.5, 1.25), 1)
    failing = BenchmarkResult("failing", 2.0, (3.0, 4.0, 5.0), 1)
    results = iter((passing, failing))
    monkeypatch.setattr(
        performance,
        "PerformanceCases",
        lambda: (
            BenchmarkCase("passing", 2.0, 1, 1, Mock()),
            BenchmarkCase("failing", 2.0, 1, 1, Mock()),
        ),
    )
    monkeypatch.setattr(performance, "Measure", lambda case: next(results))
    report_path = tmp_path / "nested/performance.json"

    assert performance.Run(report_path) == 1, "performance regression exit invariant failed."
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == performance.PERFORMANCE_SCHEMA_VERSION, (
        "performance report schema invariant failed."
    )
    assert report["status"] == "fail", "performance report status invariant failed."
    assert [entry["name"] for entry in report["benchmarks"]] == ["passing", "failing"], (
        "performance report order invariant failed."
    )
    assert "FAIL failing" in capsys.readouterr().out, "performance output invariant failed."


def test_MainReportsProbeFailure(monkeypatch, capsys):
    """Verify probe infrastructure failures return a distinct non-zero status."""

    def FailRun(report_path):
        """Raise a deterministic probe failure."""

        raise RuntimeError(f"cannot write {report_path.name}")

    monkeypatch.setattr(performance, "Run", FailRun)

    assert performance.Main(["--output", "result.json"]) == 2, (
        "performance probe failure invariant failed."
    )
    assert "cannot write result.json" in capsys.readouterr().err, (
        "performance probe diagnostic invariant failed."
    )
