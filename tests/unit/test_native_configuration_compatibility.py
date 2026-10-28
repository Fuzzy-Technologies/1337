# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit process doubles test compatibility harness custody, not genuine native results."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionError,
    LocalExecutionResult,
)
from tests.fixtures.trivy import native_configuration as harness


@pytest.mark.parametrize("scanner,operation", [
    ("helm", "config"), ("kubernetes,helm", "config"), ("dockerfile", "image"),
    ("dockerfile", "--version"), ("terraform", "version"),
])
def test_ClosedCompatibilitySelectionCannotAddScannersOrOperations(tmp_path, scanner, operation):
    """Unsupported check/rendering families and option spellings fail before any reads or launch."""

    with pytest.raises(ValueError, match="closed native configuration"):
        harness.OriginalArguments(tmp_path / "trivy", tmp_path / "cache", tmp_path / "inputs",
                                  scanner, operation)


@pytest.mark.parametrize("scanner", ["dockerfile", "kubernetes"])
def test_CompatibilityArgvIncludesNonfailuresAndOnlyConfigurationFlags(tmp_path, scanner):
    """Fixed argv retains positive processing evidence and excludes other native scan families."""

    arguments = harness.OriginalArguments(tmp_path / "trivy", tmp_path / "cache",
                                          tmp_path / "inputs", scanner, "config")
    assert arguments[arguments.index("--misconfig-scanners") + 1] == scanner, (
        "Exactly one declared configuration scanner must be selected"
    )
    assert {"--config=", "--ignorefile=", "--skip-check-update", "--skip-version-check",
            "--disable-telemetry", "--include-non-failures"}.issubset(arguments), (
        "Native compatibility requires empty overrides, embedded checks and nonfailure evidence"
    )
    assert not set(arguments).intersection({"image", "--offline-scan", "--skip-db-update",
        "--scanners", "--list-all-pkgs", "--config-check", "--config-data", "--file-patterns",
        "--helm-values", "--enable-modules"}), (
        "The fixed config profile cannot borrow image, custom-check or renderer flags"
    )


def test_CompatibilityProcessRootsAreWhollyFreshAndRefuseReuse(tmp_path):
    """Separate empty roots and an explicit environment exclude ambient settings and cache reuse."""

    root = tmp_path / "original-process"
    environment = harness.FreshEnvironment(root)
    assert set(environment) == {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR",
                                "PATH", "LANG", "LC_ALL"}, (
        "Only declared fixed process environment keys may reach the compatibility request"
    )
    assert len(list(root.iterdir())) == 5 and all(not list(path.iterdir())
                                               for path in root.iterdir()), (
        "Every original process starts with five distinct wholly empty owned directories"
    )

    with pytest.raises(FileExistsError):
        harness.FreshEnvironment(root)


@pytest.mark.parametrize("state,termination,exit_code", [
    (ExecutionState.SUCCEEDED, ExecutionTermination.PROCESS_EXIT, 0),
    (ExecutionState.FAILED, ExecutionTermination.OUTPUT_LIMIT, -15),
    (ExecutionState.TIMED_OUT, ExecutionTermination.TIMEOUT, -15),
])
def test_ControlledOriginalResultsPreserveActualStreamsAndTerminalTruth(
    tmp_path, monkeypatch, state, termination, exit_code,
):
    """Explicit executor doubles retain failure/overflow/timeout facts without native acceptance."""

    events = (ExecutionEvent(0, ExecutionEventKind.STARTED),
        ExecutionEvent(1, ExecutionEventKind.STDOUT, b"original controlled stdout"),
        ExecutionEvent(2, ExecutionEventKind.COMPLETED, termination=termination))
    result = LocalExecutionResult(AdapterExecution(state, exit_code, 0.01), termination,
                                  b"original controlled stdout", b"original stderr", events)

    class ControlledExecutor:
        """Return only explicitly labeled controlled process results while inspecting ownership."""

        def __init__(self, root):
            """Require the exact owned root instead of resolving another filesystem selection."""

            assert root == tmp_path, "The compatibility executor must retain its original root"

        async def Execute(self, request, *, on_event, own_descendants):
            """Inspect the fixed request and provide declared test-only events and result."""

            assert own_descendants is True, "Linux descendant ownership must remain explicit"
            assert request.resources.max_stdout_bytes == harness.MAX_CONFIG_STDOUT_BYTES and (
                request.resources.max_stderr_bytes == harness.MAX_STDERR_BYTES
            ), "Original native stream limits cannot expand in the test harness"
            assert request.invocation.timeout_seconds == harness.CONFIG_TIMEOUT_SECONDS, (
                "The fixed native config invocation must keep its finite deadline"
            )

            for event in events:
                on_event(event)

            return result

    monkeypatch.setattr(harness, "LocalExecutor", ControlledExecutor)
    evidence = tmp_path / "evidence"
    observed = asyncio.run(harness.CaptureOriginal(tmp_path, tmp_path / "trivy",
        tmp_path / "cache", tmp_path / "inputs", "dockerfile", "config",
        tmp_path / "process", evidence))
    receipt = json.loads((evidence / "config.receipt.json").read_bytes())
    assert observed is result and receipt["execution"]["state"] == state.value and (
        receipt["termination"] == termination.value and receipt["original_failure"] is None
    ), "Receipt facts must preserve the original result, including non-success terminal outcomes"
    assert receipt["product_authorization"] is False and receipt["classification"] == (
        "test-only-native-compatibility"
    ), "A caller-owned compatibility test cannot claim product native configuration authority"
    assert (evidence / "config.stdout").read_bytes() == result.stdout and (
        receipt["streams"]["stdout"]["sha256"] == hashlib.sha256(result.stdout).hexdigest()
    ), "Actual retained stream bytes must agree with their separate integrity receipt"


def test_ControlledExceptionalCleanupRetainsAvailableEventsWithoutInventedResult(
    tmp_path, monkeypatch,
):
    """An explicit cleanup-error double leaves partial evidence and no successful process facts."""

    class RefusedExecutor:
        """Emit one controlled original fragment, then refuse the declared cleanup boundary."""

        def __init__(self, root):
            """Accept only this test's owned root without touching another selection."""

            assert root == tmp_path, "The compatibility collector changed its test root"

        async def Execute(self, _request, *, on_event, own_descendants):
            """Retain available declared event bytes before a controlled ownership failure."""

            assert own_descendants is True, "Strong cleanup ownership cannot silently disappear"
            on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))
            on_event(ExecutionEvent(1, ExecutionEventKind.STDOUT, b"partial original stdout"))
            raise LocalExecutionError("Controlled cleanup refusal, not a genuine native process")

    monkeypatch.setattr(harness, "LocalExecutor", RefusedExecutor)
    evidence = tmp_path / "evidence"

    with pytest.raises(LocalExecutionError, match="Controlled cleanup"):
        asyncio.run(harness.CaptureOriginal(tmp_path, tmp_path / "trivy", tmp_path / "cache",
            tmp_path / "inputs", "kubernetes", "config", tmp_path / "process", evidence))

    receipt = json.loads((evidence / "config.receipt.json").read_bytes())
    assert receipt["original_failure"] == "LocalExecutionError" and (
        receipt["execution"] is None and receipt["termination"] is None
    ), "Unconfirmed cleanup cannot invent original successful process or termination facts"
    assert (evidence / "config.stdout").read_bytes() == b"partial original stdout", (
        "Cleanup refusal must retain the available bounded original event fragment"
    )
