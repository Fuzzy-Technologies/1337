# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for dev commands behavior."""

import subprocess
import sys
from unittest.mock import Mock

import pytest

from fuzzy1337 import dev_commands, test_runner


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


@pytest.mark.parametrize("suite_timeout_seconds", [600, 900])
@pytest.mark.parametrize("fail_fast", [False, True])
def test_CheckRunsAllQualityStepsAndRemovesStaleReport(
    repository, monkeypatch, suite_timeout_seconds, fail_fast,
):
    """Successful default and fail-fast checks retain every quality phase and fresh evidence."""

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
    arguments = ["check"]

    if suite_timeout_seconds != 600:
        arguments.extend(["--suite-timeout", str(suite_timeout_seconds)])

    if fail_fast:
        arguments.append("--fail-fast")

    assert dev_commands.Main(arguments) == 0, (
        "check runs all quality steps and removes stale report invariant failed."
    )
    assert [call[2] for call in calls] == [
        "compileall",
        "ruff",
        "mypy",
        "fuzzy1337.performance",
        "fuzzy1337.coverage_gate",
        "build",
    ], "check runs all quality steps and removes stale report invariant failed."
    test_process.assert_called_once_with(
        "tests", dev_commands.TestOptions(fail_fast=fail_fast,
                                         suite_timeout_seconds=suite_timeout_seconds),
    )
    assert not report.exists(), (
        "check runs all quality steps and removes stale report invariant failed."
    )


@pytest.mark.parametrize("code", [1, 124, 127])
def test_CheckSuiteBudgetPreservesFailureWithoutRetry(repository, monkeypatch, code):
    """A larger full-check suite budget cannot retry failure or proceed to coverage/build."""

    process = Mock(return_value=subprocess.CompletedProcess([], 0))
    test_process = Mock(return_value=code)
    monkeypatch.setattr(subprocess, "run", process)
    monkeypatch.setattr(dev_commands, "RunTests", test_process)

    assert dev_commands.Main(["check", "--suite-timeout", "900"]) == code, (
        "Full-check suite expiration or failure must retain its original exit status."
    )
    test_process.assert_called_once_with(
        "tests", dev_commands.TestOptions(suite_timeout_seconds=900),
    )
    assert [call.args[0][2] for call in process.call_args_list] == [
        "compileall", "ruff", "mypy", "fuzzy1337.performance",
    ], "Failed tests must stop before coverage validation and packaging without retries."


@pytest.mark.parametrize("test_code", [0, 1, 124])
def test_CheckFailFastKeepsEveryPhaseUnlessItsActualTestInvocationFails(
    repository, monkeypatch, test_code,
):
    """Real parser/dispatch/runner composition retains all work on success and stops on failure."""

    processes = []
    invocations = []

    def Process(arguments, **kwargs):
        """Record ordinary quality phases without starting tools or a nested pytest process."""

        processes.append(arguments)

        return subprocess.CompletedProcess(arguments, 0)

    def RunPytest(arguments, report_path, timeout_seconds):
        """Supply one causally selected terminal result at the original pytest boundary."""

        invocations.append((arguments, report_path, timeout_seconds))

        return test_code, test_runner.TestSummary(total=1, passed=int(test_code == 0),
            failed=int(test_code != 0), timeout=int(test_code == 124))

    monkeypatch.setattr(subprocess, "run", Process)
    monkeypatch.setattr(test_runner, "RunPytest", RunPytest)
    monkeypatch.setattr(test_runner, "HasSerialTests", lambda target: True)
    assert dev_commands.Main(["check", "--fail-fast", "--suite-timeout", "900"]) == test_code, (
        "Fail-fast must propagate the original actual test failure or complete success unchanged."
    )
    expected_phases = ["compileall", "ruff", "mypy", "fuzzy1337.performance"]

    if not test_code:
        expected_phases.extend(["fuzzy1337.coverage_gate", "build"])

    assert [arguments[2] for arguments in processes] == expected_phases, (
        "Only an actual nonzero test invocation may prevent later coverage and build phases."
    )
    assert len(invocations) == (1 if test_code else 2), (
        "Successful fail-fast keeps the separate serial selection; failures are not retried."
    )
    assert all(arguments[3] == "tests" and "-x" in arguments and "--timeout=120" in arguments
               and timeout == 900 for arguments, _, timeout in invocations), (
        "Fail-fast cannot narrow the full selection or change the worker/per-test timeout contract."
    )
    assert "not serial" in invocations[0][0] and "--dist=loadscope" in invocations[0][0], (
        "The initial invocation retains its process pool and complete nonserial selection."
    )

    if not test_code:
        assert "serial" in invocations[1][0] and "--cov-append" in invocations[1][0], (
            "Successful fail-fast retains serial coverage append before the unchanged module gate."
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


def test_DeveloperEntrypointKeepsSuiteAndPerTestTimeoutsIndependent(monkeypatch):
    """The developer CLI forwards separate finite budgets without modifying other controls."""

    process = Mock(return_value=0)
    monkeypatch.setattr(dev_commands, "Run", process)
    assert dev_commands.Main(["test", "--timeout", "12", "--suite-timeout", "37"]) == 0, (
        "Explicit independent test budgets must remain valid developer CLI inputs."
    )
    process.assert_called_once_with("test", dev_commands.TestOptions(
        timeout_seconds=12, suite_timeout_seconds=37,
    ))


@pytest.mark.parametrize("command", [
    "setup", "compile", "lint", "typecheck", "performance", "build",
])
@pytest.mark.parametrize("options", [["--suite-timeout", "37"], ["--fail-fast"]])
def test_NontestDeveloperCommandRejectsSuiteTimeoutBeforeDispatch(monkeypatch, command, options):
    """Pytest settings cannot silently alter a developer command that does not run tests."""

    process = Mock()
    monkeypatch.setattr(dev_commands, "Run", process)

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main([command, *options])

    assert caught.value.code == 2, "Nontest commands must reject pytest budgets and fail-fast."
    process.assert_not_called()


@pytest.mark.parametrize("options", [
    ["--jobs", "2"],
    ["--timeout", "30"],
    ["--serial"],
    ["--suite-timeout", "900", "--serial"],
    ["--fail-fast", "--jobs", "2"],
    ["--suite-timeout", "900", "--fail-fast", "--timeout", "30"],
    ["--fail-fast", "--serial"],
])
def test_CheckRejectsOverridesThatAlterFullTestExecution(monkeypatch, options):
    """Full-check budgeting must not admit options that change its required test execution."""

    process = Mock()
    monkeypatch.setattr(dev_commands, "Run", process)

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["check", *options])

    assert caught.value.code == 2, (
        "Suite budgeting or fail-fast must not permit worker, per-test or serial overrides."
    )
    process.assert_not_called()


@pytest.mark.parametrize("value", ["0", "-1", "true", "1.5", "Infinity", "3601"])
def test_CheckRejectsInvalidSuiteBudgetBeforeDispatch(monkeypatch, value):
    """Full checks retain the runner's finite integer suite-budget boundary."""

    process = Mock()
    monkeypatch.setattr(dev_commands, "Run", process)

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["check", "--suite-timeout", value])

    assert caught.value.code == 2, "Invalid full-check budgets must fail before any work starts."
    process.assert_not_called()


@pytest.mark.parametrize("option", ["--timeout", "--suite-timeout"])
@pytest.mark.parametrize("value", ["0", "-1", "true", "1.5", "Infinity", "3601",
                                  pytest.param(str(10**500), id="overflow-integer"),
                                  pytest.param("1" + "0" * 5000, id="conversion-limit-integer")])
def test_DeveloperTimeoutCliRejectsInvalidBudgetsBeforeDispatch(
    monkeypatch, capsys, option, value,
):
    """Invalid timeout values remain ordinary parse failures without starting a gate."""

    process = Mock()
    monkeypatch.setattr(dev_commands, "Run", process)

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["test", option, value])

    assert caught.value.code == 2, "Invalid timeout inputs must retain CLI configuration status."
    process.assert_not_called()
    diagnostic = capsys.readouterr().err
    assert "must be an integer between 1 and 3600 seconds" in diagnostic, (
        "Unsupported CLI budgets must retain their fixed supported-range diagnostic."
    )

    if len(value) > 32:
        assert value not in diagnostic, (
            "An oversized rejected numeric budget must not enter diagnostics."
        )


def test_DeveloperTimeoutCliAcceptsExactSupportedMaximum(monkeypatch):
    """Both explicit CLI timeout domains accept the exact documented maximum before dispatch."""

    process = Mock(return_value=0)
    monkeypatch.setattr(dev_commands, "Run", process)
    assert dev_commands.Main([
        "test", "--timeout", "3600", "--suite-timeout", "3600",
    ]) == 0, "The exact maximum budget must remain supported for both CLI timeout domains."
    process.assert_called_once_with("test", dev_commands.TestOptions(
        timeout_seconds=3600, suite_timeout_seconds=3600,
    ))


def test_DeveloperTimeoutCliPreservesOrdinaryIntegerSpelling(monkeypatch):
    """Sanitized conversion preserves existing whitespace, sign and leading-zero integer inputs."""

    process = Mock(return_value=0)
    monkeypatch.setattr(dev_commands, "Run", process)
    assert dev_commands.Main([
        "test", "--timeout", "+0120", "--suite-timeout", " 0600 ",
    ]) == 0, "Supported ordinary integer spelling must retain its previous CLI meaning."
    process.assert_called_once_with("test", dev_commands.TestOptions())


def test_DeveloperTimeoutCliHelpDocumentsSupportedRange(capsys):
    """CLI help presents the finite supported range together with unchanged domain defaults."""

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["--help"])

    assert caught.value.code == 0, "Timeout range help must remain ordinary non-mutating help."
    output = capsys.readouterr().out
    assert output.count("1-3600") == 2, "Both timeout options must declare the supported range."
    assert "default: 120" in output and "default: 600" in output, (
        "Timeout range documentation must retain the independent unchanged defaults."
    )
    assert "Stop unit/test/check on failure" in output, (
        "Fail-fast help must name supported gates without implying a successful partial check."
    )


def test_UnapprovedFormatterIsNotACommand():
    """Verify unapproved formatter is not a command."""

    with pytest.raises(SystemExit) as caught:
        dev_commands.Main(["format"])
    assert caught.value.code == 2, "unapproved formatter is not a command invariant failed."
