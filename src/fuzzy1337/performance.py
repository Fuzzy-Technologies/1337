"""Measure deterministic shell paths against explicit performance budgets."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from fuzzy1337.shell import ContextualAction, InteractiveShell

PERFORMANCE_SCHEMA_VERSION = "1.0"
DEFAULT_REPORT_PATH = Path("performance/performance.json")
PROCESS_SAMPLE_COUNT = 5
IN_PROCESS_SAMPLE_COUNT = 7
IN_PROCESS_ITERATIONS = 100
PROCESS_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """Define one implemented shell path and its median latency budget."""

    name: str
    budget_ms: float
    sample_count: int
    iterations_per_sample: int
    operation: Callable[[], None]


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Record stable aggregate statistics for one performance case."""

    name: str
    budget_ms: float
    samples_ms: tuple[float, ...]
    iterations_per_sample: int

    @property
    def MedianMs(self) -> float:
        """Return median per-operation latency in milliseconds."""

        return statistics.median(self.samples_ms)

    @property
    def MaximumMs(self) -> float:
        """Return the slowest observed per-operation latency in milliseconds."""

        return max(self.samples_ms)

    @property
    def Passed(self) -> bool:
        """Return whether the stable aggregate remains within its budget."""

        return self.MedianMs <= self.budget_ms

    def ToDictionary(self) -> dict[str, object]:
        """Return the machine-readable representation of this result."""

        return {
            "name": self.name,
            "status": "pass" if self.Passed else "fail",
            "budget_ms": self.budget_ms,
            "median_ms": round(self.MedianMs, 3),
            "maximum_ms": round(self.MaximumMs, 3),
            "sample_count": len(self.samples_ms),
            "iterations_per_sample": self.iterations_per_sample,
            "samples_ms": [round(sample, 3) for sample in self.samples_ms],
        }


def ProbeColdStart() -> None:
    """Start the installed CLI help path in a fresh Python process."""

    RunProcess((sys.executable, "-m", "fuzzy1337", "help"), None, "Currently available commands:")


def ProbeInteractiveReadiness() -> None:
    """Start the shell in a fresh process and reach its first prompt."""

    RunProcess((sys.executable, "-m", "fuzzy1337", "shell"), "quit\n", "1337> ")


def RunProcess(
    arguments: tuple[str, ...],
    input_text: str | None,
    expected_output: str,
) -> None:
    """Run a bounded process probe and validate its observable completion."""

    result = subprocess.run(
        arguments,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=PROCESS_TIMEOUT_SECONDS,
        check=False,
    )

    if result.returncode:
        detail = result.stderr.strip() or f"exit code {result.returncode}"

        raise RuntimeError(f"Performance probe failed: {detail}")

    if expected_output not in result.stdout:
        raise RuntimeError(f"Performance probe did not reach: {expected_output}")


def PrepareInProcessProbes() -> tuple[Callable[[], None], Callable[[], None]]:
    """Create isolated local probes for implemented palette and view paths."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.SetContextActions(
        "asset:performance",
        (
            ContextualAction("inspect", "Inspect the selected object."),
            ContextualAction("evidence", "Show evidence for the selected object."),
        ),
    )
    shell.do_select("asset:performance")
    ClearOutput(output)

    def ProbePaletteSearch() -> None:
        """Search the current command palette and contextual actions."""

        shell.do_palette("ct")
        ClearOutput(output)

    def ProbeLensViewSwitch() -> None:
        """Switch the currently implemented workflow lens and model slice."""

        shell.do_lens("devsecops")
        shell.do_view("updates")
        ClearOutput(output)

    return ProbePaletteSearch, ProbeLensViewSwitch


def ClearOutput(output: StringIO) -> None:
    """Discard probe output so measurement memory remains bounded."""

    output.seek(0)
    output.truncate(0)


def PerformanceCases() -> tuple[BenchmarkCase, ...]:
    """Return budgets only for shell capabilities implemented today."""

    palette_probe, switch_probe = PrepareInProcessProbes()

    return (
        BenchmarkCase("cli_cold_start", 2000.0, PROCESS_SAMPLE_COUNT, 1, ProbeColdStart),
        BenchmarkCase(
            "interactive_readiness",
            2000.0,
            PROCESS_SAMPLE_COUNT,
            1,
            ProbeInteractiveReadiness,
        ),
        BenchmarkCase(
            "command_palette_search",
            2.0,
            IN_PROCESS_SAMPLE_COUNT,
            IN_PROCESS_ITERATIONS,
            palette_probe,
        ),
        BenchmarkCase(
            "lens_view_switch",
            2.0,
            IN_PROCESS_SAMPLE_COUNT,
            IN_PROCESS_ITERATIONS,
            switch_probe,
        ),
    )


def Measure(case: BenchmarkCase) -> BenchmarkResult:
    """Measure one case as per-operation samples after an unrecorded warm-up."""

    case.operation()
    samples = []
    for _ in range(case.sample_count):
        started = time.perf_counter_ns()
        for _ in range(case.iterations_per_sample):
            case.operation()

        elapsed_ns = time.perf_counter_ns() - started
        samples.append(elapsed_ns / case.iterations_per_sample / 1_000_000)

    return BenchmarkResult(
        name=case.name,
        budget_ms=case.budget_ms,
        samples_ms=tuple(samples),
        iterations_per_sample=case.iterations_per_sample,
    )


def BuildReport(results: Sequence[BenchmarkResult]) -> dict[str, object]:
    """Build a versioned report with deterministic field and result ordering."""

    passed = all(result.Passed for result in results)

    return {
        "schema_version": PERFORMANCE_SCHEMA_VERSION,
        "status": "pass" if passed else "fail",
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.system(),
            "machine": platform.machine(),
        },
        "benchmarks": [result.ToDictionary() for result in results],
    }


def WriteReport(report: dict[str, object], path: Path) -> None:
    """Write standards-compliant JSON without retaining machine-local paths."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def Run(report_path: Path = DEFAULT_REPORT_PATH) -> int:
    """Run all implemented budgets, write evidence, and fail on regression."""

    results = tuple(Measure(case) for case in PerformanceCases())
    report = BuildReport(results)
    WriteReport(report, report_path)

    for result in results:
        status = "PASS" if result.Passed else "FAIL"
        print(
            f"{status} {result.name}: median={result.MedianMs:.3f} ms "
            f"budget={result.budget_ms:.3f} ms"
        )

    print(f"Performance evidence: {report_path.as_posix()}")

    return 0 if report["status"] == "pass" else 1


def Main(argv: Sequence[str] | None = None) -> int:
    """Run the fixed performance suite with an optional report destination."""

    parser = argparse.ArgumentParser(
        prog="1337-performance",
        description="Measure implemented shell paths against regression budgets.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_REPORT_PATH,
        type=Path,
        help="JSON evidence path (default: performance/performance.json)",
    )
    arguments = parser.parse_args(argv)

    try:
        return Run(arguments.output)

    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Performance probe could not complete: {error}", file=sys.stderr)

        return 2


if __name__ == "__main__":
    raise SystemExit(Main())
