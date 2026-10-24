# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

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


@pytest.mark.parametrize("field", ["timeout_seconds", "suite_timeout_seconds"])
@pytest.mark.parametrize("value", [False, True, None, "600", 0, -1, 1.5, float("inf"), 3601,
                                  pytest.param(10**500, id="overflow-integer")])
def test_OptionsRejectUnsupportedTimeoutBudgets(field, value):
    """Both timeout domains reject unsupported values through a fixed diagnostic boundary."""

    with pytest.raises(ValueError, match="timeout") as caught:
        test_runner.TestOptions(**{field: value})

    prefix = "suite timeout" if field == "suite_timeout_seconds" else "timeout"
    assert str(caught.value) == prefix + " must be an integer between 1 and 3600 seconds", (
        "Timeout rejection must not reflect an unsupported caller-supplied value."
    )


def test_OptionsAcceptBothSupportedMaximumBudgets():
    """The exact documented upper bound remains supported for each independent timeout domain."""

    options = test_runner.TestOptions(timeout_seconds=3600, suite_timeout_seconds=3600)
    assert test_runner.MAX_TIMEOUT_SECONDS == 3600, (
        "The shared machine-compatible timeout ceiling must remain explicitly named."
    )
    assert options.timeout_seconds == options.suite_timeout_seconds == 3600, (
        "The exact supported upper bound must remain valid in both timeout domains."
    )


def test_SuiteBudgetAdditionPreservesExistingPositionalOptions():
    """Existing positional test settings retain their meaning when suite budgeting is added."""

    options = test_runner.TestOptions("4", 42, True, True)
    assert (options.jobs, options.timeout_seconds, options.serial_only, options.fail_fast) == (
        "4", 42, True, True,
    ), "The additive suite budget must preserve all existing positional option meanings."
    assert options.suite_timeout_seconds == 600, (
        "Existing callers must receive the independent finite default suite budget."
    )


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
    assert arguments[arguments.index("-p") + 1] == "tools.pytest_progress", (
        "The checkout diagnostic bootstrap must be selected without an eager application import."
    )
    assert "--1337-progress" in arguments, "The fixed diagnostic profile must be explicit."
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


@pytest.mark.parametrize("fail_fast", [False, True])
def test_DefaultRunExecutesParallelThenSerial(monkeypatch, capsys, fail_fast):
    """Successful default and fail-fast selections run both required pytest phases."""

    calls = []

    def RunPytest(arguments, report_path, timeout_seconds):
        """Provide deterministic test support for run pytest."""

        calls.append(arguments)
        return 0, test_runner.TestSummary(total=2, passed=2, duration_seconds=0.5)

    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert test_runner.RunTests("tests/unit", test_runner.TestOptions(fail_fast=fail_fast)) == 0, (
        "default run executes parallel then serial invariant failed."
    )
    assert len(calls) == 2, "default run executes parallel then serial invariant failed."
    assert "not serial" in calls[0], "default run executes parallel then serial invariant failed."
    assert "serial" in calls[1], "default run executes parallel then serial invariant failed."
    assert all(("-x" in arguments) == fail_fast for arguments in calls), (
        "Fail-fast adds only the explicit stop-on-failure control to both successful phases."
    )
    assert "total=4" in capsys.readouterr().out, (
        "default run executes parallel then serial invariant failed."
    )


def test_DefaultSuiteBudgetAllowsCompletionBeyondThreePerTestTimeouts(
    tmp_path, monkeypatch, capsys,
):
    """A healthy expanded suite may exceed 360 seconds while each test retains its deadline."""

    monkeypatch.chdir(tmp_path)
    calls = []

    def Process(arguments, **kwargs):
        """Simulate a complete 420-second suite without delaying deterministic regression tests."""

        if "--collect-only" in arguments:
            return subprocess.CompletedProcess(arguments, 5)

        calls.append((arguments, kwargs))

        if kwargs["timeout"] <= 420:
            raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])

        report = tmp_path / arguments[arguments.index("--junitxml") + 1]
        report.write_text('<testsuite tests="4000" failures="0" errors="0" skipped="0" '
                          'time="420" />', encoding="utf-8")

        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    assert test_runner.RunTests("tests", test_runner.TestOptions()) == 0, (
        "A complete 420-second suite must not inherit three per-test deadlines as its budget."
    )
    assert len(calls) == 1 and calls[0][1]["timeout"] == 600, (
        "The runner must supply one independent 600-second subprocess budget without retries."
    )
    assert "--timeout=120" in calls[0][0], "Every test must retain its 120-second deadline."
    assert "total=4000 passed=4000 failed=0 skipped=0 timeout=0" in capsys.readouterr().out, (
        "The retained terminal summary must describe the actual complete JUnit evidence."
    )


def test_RunTestsForwardsSuiteBudgetToBothInvocationsWithoutChangingPerTestDeadline(
    tmp_path, monkeypatch,
):
    """Parallel and serial invocations receive the selected suite bound independently."""

    monkeypatch.chdir(tmp_path)
    calls = []

    def RunPytest(arguments, report_path, timeout_seconds):
        """Capture both selected budgets at the actual runner dispatch boundary."""

        calls.append((arguments, timeout_seconds))

        return 0, test_runner.TestSummary(total=1, passed=1)

    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert test_runner.RunTests("tests", test_runner.TestOptions(
        timeout_seconds=12, suite_timeout_seconds=37,
    )) == 0, "Both selected invocations must use the explicit valid timeout budgets."
    assert len(calls) == 2 and all(budget == 37 for _, budget in calls), (
        "The whole-suite timeout must be forwarded unchanged to both subprocesses."
    )
    assert all("--timeout=12" in arguments for arguments, _ in calls), (
        "The per-test timeout must remain independently supplied through pytest arguments."
    )


def test_RunPytestTimeoutDiscardsStaleSuccessAndPreservesExactBudget(tmp_path, monkeypatch):
    """A suite timeout remains failure without retrying or reading an earlier successful report."""

    report = tmp_path / "report.xml"
    report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0" time="1" />',
                      encoding="utf-8")
    calls = []

    def Process(arguments, **kwargs):
        """Observe exclusive evidence ownership and raise the actual suite deadline failure."""

        calls.append((arguments, kwargs))
        assert not report.exists(), "A prior invocation's JUnit report must be removed first."

        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])

    ticks = iter((10.0, 47.0))
    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    monkeypatch.setattr(test_runner.time, "monotonic", lambda: next(ticks))
    code, summary = test_runner.RunPytest(["synthetic-pytest"], report, 37)
    assert calls == [(["synthetic-pytest"], {
        "check": False, "shell": False, "timeout": 37,
    })], "The subprocess must receive the exact suite budget once, without hidden floors."
    assert code == 124 and summary == test_runner.TestSummary(
        failed=1, timeout=1, duration_seconds=37.0,
    ), "Suite expiration must preserve timeout status and measured failed evidence."
    assert not report.exists(), "A suite timeout must never restore stale success evidence."


def test_RunPytestZeroExitWithoutNewJunitCannotReportSuccess(tmp_path, monkeypatch):
    """An exit-zero child without fresh evidence must still fail the developer gate."""

    report = tmp_path / "report.xml"
    report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0" time="1" />',
                      encoding="utf-8")
    monkeypatch.setattr(test_runner.subprocess, "run", lambda arguments, **kwargs: (
        subprocess.CompletedProcess(arguments, 0)
    ))
    code, summary = test_runner.RunPytest(["synthetic-pytest"], report, 600)
    assert code == 1 and summary == test_runner.TestSummary(failed=1), (
        "Missing fresh JUnit evidence must prevent success even when the child exits zero."
    )
    assert not report.exists(), "The earlier successful report must not mask missing evidence."


@pytest.mark.parametrize("returncode", [0, 7])
def test_RunPytestFailedFreshReportCannotMaskFailureOrReplaceNonzeroStatus(
    tmp_path, monkeypatch, returncode,
):
    """Failed fresh JUnit evidence forces failure while an actual child failure remains exact."""

    report = tmp_path / "report.xml"

    def Process(arguments, **kwargs):
        """Publish current failure evidence independently of the selected process exit status."""

        report.write_text('<testsuite tests="1" failures="1" errors="0" skipped="0" time="1" />',
                          encoding="utf-8")

        return subprocess.CompletedProcess(arguments, returncode)

    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    code, summary = test_runner.RunPytest(["synthetic-pytest"], report, 600)
    assert code == (returncode or 1), (
        "Failed fresh evidence cannot become success or replace an actual nonzero child status."
    )
    assert summary == test_runner.TestSummary(total=1, failed=1, duration_seconds=1.0), (
        "The terminal summary must preserve the freshly produced failed JUnit counts."
    )


def test_RunPytestLaunchFailureRetainsFailureWithoutRetry(tmp_path, monkeypatch):
    """An unstartable pytest process retains its launch-failure status and measured duration."""

    calls = []

    def Process(arguments, **kwargs):
        """Raise a deterministic launch failure without creating a child process or report."""

        calls.append((arguments, kwargs))

        raise OSError("synthetic-launch-failure")

    ticks = iter((10.0, 10.25))
    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    monkeypatch.setattr(test_runner.time, "monotonic", lambda: next(ticks))
    code, summary = test_runner.RunPytest(["synthetic-pytest"], tmp_path / "report.xml", 600)
    assert code == 127 and summary == test_runner.TestSummary(
        failed=1, duration_seconds=0.25,
    ), "An unstartable suite must remain a measured launch failure rather than success."
    assert len(calls) == 1, "Launch failure must not introduce an automatic retry."


@pytest.mark.parametrize("value", [False, True, None, "600", 0, -1, 1.5, float("inf"), 3601,
                                  pytest.param(10**500, id="overflow-integer")])
def test_RunPytestRejectsInvalidSuiteBudgetBeforeMutatingEvidence(tmp_path, monkeypatch, value):
    """Direct callers share the validated timeout boundary without deleting prior evidence."""

    report = tmp_path / "report.xml"
    report.write_bytes(b"prior-evidence")
    calls = []
    monkeypatch.setattr(test_runner.subprocess, "run", lambda *args, **kwargs: calls.append(args))

    with pytest.raises(ValueError, match="suite timeout") as caught:
        test_runner.RunPytest(["synthetic-pytest"], report, value)

    assert str(caught.value) == "suite timeout must be an integer between 1 and 3600 seconds", (
        "Direct timeout rejection must use a fixed diagnostic without the rejected value."
    )
    assert not calls, "Invalid direct suite budgets must reject before subprocess startup."
    assert report.read_bytes() == b"prior-evidence", (
        "Rejected suite configuration must preserve another invocation's existing evidence."
    )


def test_RunPytestSupportedMaximumReachesSubprocessWithoutExpansion(tmp_path, monkeypatch):
    """A valid maximum suite budget reaches subprocess ownership exactly once without waiting."""

    report = tmp_path / "report.xml"
    calls = []

    def Process(arguments, **kwargs):
        """Publish a tiny successful report while capturing the exact valid timeout ceiling."""

        calls.append((arguments, kwargs))
        report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0" time="1" />',
                          encoding="utf-8")

        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    code, summary = test_runner.RunPytest(["synthetic-pytest"], report, 3600)
    assert code == 0 and summary.passed == 1, (
        "A valid maximum suite budget must preserve actual fresh successful evidence."
    )
    assert calls == [(["synthetic-pytest"], {
        "check": False, "shell": False, "timeout": 3600,
    })], "The exact maximum supported suite budget must not be multiplied or retried."


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


def test_TimeoutRetainsPartialDiagnosticsWithoutPromotingThemToJunit(
    tmp_path, monkeypatch, capsys,
):
    """A hard suite cutoff retains completed phase diagnostics while the gate still fails124."""

    from types import SimpleNamespace

    from fuzzy1337 import test_progress

    report = tmp_path / "owned.xml"

    def Process(arguments, **kwargs):
        """Flush one completed case and simulate interruption before another teardown."""

        recorder = test_progress.ProgressRecorder(
            test_progress.ProgressDirectory(report), "gw0", clock=lambda: 0,
        )
        for phase in ("setup", "call", "teardown"):
            recorder.pytest_runtest_logreport(SimpleNamespace(
                nodeid="test_owned.py::test_Complete[PRIVATE]", when=phase,
                outcome="passed", duration=0.01,
            ))
        recorder.Flush()
        recorder.Close()
        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])

    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    ticks = iter((10.0, 910.0))
    monkeypatch.setattr(test_runner.time, "monotonic", lambda: next(ticks))
    arguments = test_runner.PytestArguments("tests", test_runner.TestOptions(jobs="16"),
                                          report, serial=False)
    code, summary = test_runner.RunPytest(arguments, report, 900)
    assert code == 124 and summary == test_runner.TestSummary(
        failed=1, timeout=1, duration_seconds=900,
    ), "Partial diagnostics must never alter authoritative timeout failure or elapsed duration."
    diagnostic = (test_progress.ProgressDirectory(report) / "summary.json").read_text()
    assert '"completed":1' in diagnostic and '"truncated":true' in diagnostic, (
        "The bounded snapshot must retain completed counts and the explicit worker-cap limit."
    )
    assert "Partial pytest diagnostic (not JUnit): completed=1" in capsys.readouterr().out, (
        "The diagnostic line must explicitly distinguish partial counts from JUnit acceptance."
    )


def test_UnknownProgressFilesDisableOnlyDiagnosticOptIn(tmp_path, monkeypatch, capsys):
    """Unowned diagnostic data is preserved while the exact selected tests still execute."""

    from fuzzy1337.test_progress import ProgressDirectory

    report = tmp_path / "owned.xml"
    directory = ProgressDirectory(report)
    directory.mkdir()
    operator = directory / "operator.txt"
    operator.write_text("keep")
    calls = []

    def Process(arguments, **kwargs):
        """Record the unmodified execution contract and publish independent JUnit evidence."""

        calls.append((arguments, kwargs))
        report.write_text('<testsuite tests="1" failures="0" time="0"/>')
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(test_runner.subprocess, "run", Process)
    arguments = test_runner.PytestArguments("tests", test_runner.TestOptions(jobs="4"),
                                          report, serial=False)
    code, summary = test_runner.RunPytest(arguments, report, 900)
    assert code == 0 and summary.passed == 1, "Diagnostics must not change JUnit acceptance."
    actual, kwargs = calls[0]
    assert actual == [value for value in arguments if value != "--1337-progress"], (
        "Only the diagnostic opt-in may be disabled when its own directory is unavailable."
    )
    assert kwargs == {"check": False, "shell": False, "timeout": 900}, (
        "The whole-suite subprocess deadline must remain exact without retries."
    )
    assert operator.read_text() == "keep", "Unrecognized data must remain untouched."
    assert "diagnostic unavailable" in capsys.readouterr().out, (
        "Unavailable diagnostic output must be explicit without fabricated progress evidence."
    )
