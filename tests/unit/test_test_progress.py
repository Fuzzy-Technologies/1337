# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic bounded diagnostic checks without executing arbitrary test payloads."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from fuzzy1337 import test_progress as progress


def Report(recorder, node="tests/private/test_owned.py::test_Example[SECRET]", *,
           phase="setup", outcome="passed", duration=0.01):
    """Send one owned synthetic public pytest phase report."""

    recorder.pytest_runtest_logreport(SimpleNamespace(
        nodeid=node, when=phase, outcome=outcome, duration=duration,
    ))


def Complete(recorder, node="tests/private/test_owned.py::test_Example[SECRET]", *,
             outcome="passed", setup="passed"):
    """Send one complete owned setup/call/teardown protocol."""

    Report(recorder, node, outcome=setup)
    if setup == "passed":
        Report(recorder, node, phase="call", outcome=outcome)
    Report(recorder, node, phase="teardown")


def Start(tmp_path, *, worker="serial", clock=lambda: 0.0):
    """Prepare the exact report sibling and open one deterministic worker recorder."""

    report = tmp_path / "owned.xml"
    assert progress.PrepareProgress(report), "The fresh owned directory must be available."
    recorder = progress.ProgressRecorder(progress.ProgressDirectory(report), worker, clock=clock)
    return report, recorder


@pytest.mark.parametrize(("outcome", "setup", "expected"), [
    ("passed", "passed", "passed"), ("failed", "passed", "failed"),
    ("skipped", "passed", "skipped"), ("passed", "skipped", "skipped"),
    ("passed", "failed", "failed"),
])
def test_OnlyCompleteProtocolsContributeSanitizedDiagnosticCounts(
    tmp_path, outcome, setup, expected,
):
    """Normal, skipped and failed setup protocols are distinct from authoritative JUnit."""

    report, recorder = Start(tmp_path)
    Complete(recorder, outcome=outcome, setup=setup)
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=True)
    assert summary["completed"] == summary[expected] == 1, "One complete protocol must be retained."
    assert summary["partial"] and summary["diagnostic_only"] and summary["timed_out"], (
        "A completed diagnostic record must never claim complete invocation acceptance."
    )
    raw = (progress.ProgressDirectory(report) / "serial.jsonl").read_text()
    assert "SECRET" not in raw and "private" not in raw, "Params and directories must not leak."
    assert summary["slowest"][0][1] == "test_owned.py::test_Example", (
        "Only the unparameterized short label may be retained."
    )
    assert summary["slowest"][0][0] == hashlib.sha256(
        b"tests/private/test_owned.py::test_Example[SECRET]"
    ).hexdigest(), "The complete identifier must be represented only by its SHA256."


@pytest.mark.parametrize("phases", [
    ("setup",), ("setup", "teardown"), ("call", "teardown"),
    ("setup", "call", "call", "teardown"),
])
def test_CutoffOrMalformedProtocolNeverInventsCompletedCase(tmp_path, phases):
    """A cutoff during setup/call/teardown cannot inflate the number of completed tests."""

    report, recorder = Start(tmp_path)
    for phase in phases:
        Report(recorder, phase=phase)
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=True)
    assert summary["completed"] == 0 and summary["incomplete"] >= 1, (
        "Incomplete protocol observations must be explicitly partial without completed counts."
    )


def test_TeardownFailureAndChangedIdentifierRemainTruthful(tmp_path):
    """Teardown failure wins, while a mismatched phase cannot finish another test."""

    report, recorder = Start(tmp_path)
    Report(recorder)
    Report(recorder, phase="call")
    Report(recorder, phase="teardown", outcome="failed")
    Report(recorder, "first")
    Report(recorder, "other", phase="teardown")
    Report(recorder, "third")
    Report(recorder, "fourth")
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["completed"] == summary["failed"] == 1, "Teardown failure must remain failed."
    assert summary["incomplete"] == 3, "Each interrupted protocol boundary must be visible."


@pytest.mark.parametrize("duration", [True, -1, float("nan"), float("inf"), 10801, 10**500])
def test_InvalidDurationCannotCrashOrInflateDiagnostic(tmp_path, duration):
    """Unsupported numeric reports are rejected before conversion or aggregation."""

    report, recorder = Start(tmp_path)
    Report(recorder, duration=duration)
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["completed"] == 0 and summary["incomplete"] == 1, (
        "Invalid numeric values must not become completed test evidence."
    )


def test_ChunksFlushByCountOrFakeMonotonicTimeAndCloseLastChunk(tmp_path):
    """Periodic persistence is bounded and deterministic without sleeps or per-case writes."""

    tick = [0.0]
    report, recorder = Start(tmp_path, clock=lambda: tick[0])
    path = progress.ProgressDirectory(report) / "serial.jsonl"
    Complete(recorder, "first")
    assert len(path.read_bytes().splitlines()) == 1, "One case must stay buffered initially."
    tick[0] = 5.0
    Complete(recorder, "second")
    assert len(path.read_bytes().splitlines()) == 3, "Fake elapsed time must flush a small chunk."
    for index in range(32):
        Complete(recorder, f"count{index}")
    assert len(path.read_bytes().splitlines()) == 35, "32 records must trigger a bounded flush."
    Complete(recorder, "last")
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["completed"] == 35, "Normal finish must persist the final buffered case."
    assert len(summary["slowest"]) == 10, "Slowest diagnostics must remain capped at ten records."


def test_WorkerFileCapStopsWritingAndMarksTruncation(tmp_path, monkeypatch):
    """A finite stream cap cannot expand when more tests complete."""

    monkeypatch.setattr(progress, "MAX_BYTES", 700)
    report, recorder = Start(tmp_path)
    for index in range(50):
        Complete(recorder, f"test_{index}")
    recorder.pytest_sessionfinish()
    path = progress.ProgressDirectory(report) / "serial.jsonl"
    assert path.stat().st_size <= 700, "The entire worker stream must remain within its byte cap."
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["truncated"] and 0 < summary["completed"] < 50, (
        "Finite partial retention must explicitly report truncation."
    )


@pytest.mark.parametrize("value", [
    ["bad", "safe", 1, "passed"], ["a" * 64, "safe[param]", 1, "passed"],
    ["a" * 64, "safe", True, "passed"], ["a" * 64, "safe", -1, "passed"],
    ["a" * 64, "safe", 10800001, "passed"], ["a" * 64, "safe", 1, "unknown"],
    {"arbitrary": "record"},
])
def test_StrictReaderRejectsMalformedTypedRecords(tmp_path, value):
    """Bounded parsed JSON never becomes a count unless every field matches the closed grammar."""

    report, recorder = Start(tmp_path)
    recorder.Append(value)
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["malformed"] == 1 and summary["completed"] == 0, (
        "Invalid diagnostic records must not inflate completed counts."
    )


def test_ReaderRejectsDuplicateRecordsAndRetainsOnlyCompleteLines(tmp_path):
    """Duplicate or cutoff writes cannot fabricate extra completed cases."""

    report, recorder = Start(tmp_path)
    Complete(recorder)
    Complete(recorder)
    recorder.pytest_sessionfinish()
    path = progress.ProgressDirectory(report) / "serial.jsonl"
    with path.open("ab") as stream:
        stream.write(b'["unfinished"')
    summary = progress.SaveProgressSummary(report, timed_out=True)
    assert summary["completed"] == summary["malformed"] == 1 and summary["truncated"], (
        "Duplicate complete records count once and an incomplete line must report truncation."
    )


@pytest.mark.parametrize("payload", [b"not-json\n", b'"' + b"x" * 2050 + b'"\n'])
def test_ReaderBoundsMalformedAndOversizedLines(tmp_path, payload):
    """Malformed JSON and oversized lines have finite parsing and never create counts."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    with (progress.ProgressDirectory(report) / "serial.jsonl").open("ab") as stream:
        stream.write(payload)
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["completed"] == 0, "Unsupported lines must never create completed records."
    assert summary["malformed"] or summary["truncated"], "Parsing refusal must remain visible."


def test_ReaderLineBudgetAndWorkerCapAreExplicit(tmp_path, monkeypatch):
    """A bounded reader reports omitted records and unsupported extra worker files."""

    report, recorder = Start(tmp_path)
    Complete(recorder, "one")
    Complete(recorder, "two")
    recorder.pytest_sessionfinish()
    monkeypatch.setattr(progress, "MAX_LINES", 1)
    summary = progress.SaveProgressSummary(report, timed_out=False, worker_limit_exceeded=True)
    assert summary["completed"] == 1 and summary["truncated"], (
        "Omitted records and workers must remain explicit partial diagnostics."
    )


@pytest.mark.parametrize("payload", [b"operator data", b'["1337-test-progress",true,"serial"]\n'])
def test_PrepareRefusesUnknownOrWrongTypedOwnershipWithoutDeletingFiles(tmp_path, payload):
    """An existing same-named file is never deleted merely because it resembles a diagnostic."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    path = progress.ProgressDirectory(report) / "serial.jsonl"
    path.write_bytes(payload)
    assert not progress.PrepareProgress(report), "Unknown ownership must refuse diagnostic cleanup."
    assert path.read_bytes() == payload, "Refused data must remain byte-for-byte unchanged."


def test_PrepareOnlyClearsRecognizedOwnChildrenAndKeepsParent(tmp_path):
    """A rerun removes only recognized phase diagnostics, never the report parent."""

    report, recorder = Start(tmp_path)
    Complete(recorder)
    recorder.pytest_sessionfinish()
    progress.SaveProgressSummary(report, timed_out=False)
    parent_marker = tmp_path / "operator.txt"
    parent_marker.write_text("keep")
    assert progress.PrepareProgress(report), "Recognized diagnostics must allow a fresh rerun."
    assert not list(progress.ProgressDirectory(report).iterdir()), "Old counts must be removed."
    assert parent_marker.read_text() == "keep", "Parent files must remain untouched."


def test_PrepareRefusesUnknownDirectoryChildBeforeAnyDeletion(tmp_path):
    """Two-pass cleanup cannot delete some recognized files before encountering unknown data."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    directory = progress.ProgressDirectory(report)
    (directory / "operator.txt").write_text("keep")
    before = {child.name: child.read_bytes() for child in directory.iterdir()}
    assert not progress.PrepareProgress(report), "Unknown children must refuse preparation."
    assert before == {child.name: child.read_bytes() for child in directory.iterdir()}, (
        "Preparation refusal must leave every child intact."
    )


def test_SummaryExclusiveWriteDoesNotOverwriteOperatorFile(tmp_path):
    """Summary publication refuses a same-named unowned file, including a lost-ack boundary."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    target = progress.ProgressDirectory(report) / "summary.json"
    target.write_text("operator")
    summary = progress.SaveProgressSummary(report, timed_out=False)
    assert summary["unavailable"] and target.read_text() == "operator", (
        "Diagnostics must not overwrite an existing operator-controlled summary."
    )


def test_LinkedDiagnosticPathsAreNotFollowedOrDeleted(tmp_path):
    """A worker path or directory link must not escape the exact owned directory."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    directory = progress.ProgressDirectory(report)
    worker = directory / "serial.jsonl"
    worker.unlink()
    target = tmp_path / "operator.txt"
    target.write_text("keep")
    try:
        worker.symlink_to(target)
    except OSError:
        pytest.skip("This platform does not grant test-owned symlink creation.")
    assert not progress.PrepareProgress(report), "Linked diagnostic files must refuse cleanup."
    summary = progress.SaveProgressSummary(report, timed_out=True)
    assert summary["unavailable"] and target.read_text() == "keep", (
        "Neither reading nor publishing diagnostics may modify a symlink target."
    )
    worker.unlink()
    (directory / "summary.json").unlink()
    directory.rmdir()
    directory.symlink_to(tmp_path, target_is_directory=True)
    assert not progress.PrepareProgress(report), "Linked directories must refuse preparation."
    assert progress.SaveProgressSummary(report, timed_out=False)["unavailable"], (
        "A linked directory must not become diagnostic evidence."
    )


def test_PluginOnlyRegistersForOptedInValidWorkerOrSerial(tmp_path):
    """The xdist controller cannot duplicate worker results and invalid workers cannot write."""

    report, recorder = Start(tmp_path)
    recorder.pytest_sessionfinish()
    assert progress.PrepareProgress(report), "The owned phase must be fresh."
    registered = []
    options = {"--1337-progress": False, "xmlpath": str(report), "numprocesses": 2}
    config = SimpleNamespace(getoption=lambda name, default=None: options.get(name, default),
                             pluginmanager=SimpleNamespace(register=lambda *args: registered.append(
                                 args)))
    progress.pytest_configure(config)
    options["--1337-progress"] = True
    progress.pytest_configure(config)
    config.workerinput = {"workerid": "gw12"}
    progress.pytest_configure(config)
    assert not registered, "Disabled/controller/unsupported worker contexts must not record."
    config.workerinput = {"workerid": "gw1"}
    progress.pytest_configure(config)
    assert len(registered) == 1, "One allowed real worker must get one local recorder."
    registered[0][0].pytest_sessionfinish()
    del config.workerinput
    options["numprocesses"] = 0
    options["xmlpath"] = None
    progress.pytest_configure(config)
    options["xmlpath"] = str(report)
    progress.pytest_configure(config)
    registered[1][0].pytest_sessionfinish()
    assert len(registered) == 2, "An actual serial invocation must have its own recorder."


def test_OptionalHookAddsOnlyFixedBooleanOption():
    """The plugin cannot select arbitrary diagnostic paths through a new option."""

    captured = []
    progress.pytest_addoption(SimpleNamespace(addoption=lambda *args, **kwargs: captured.append(
        (args, kwargs))))
    assert captured[0][0] == ("--1337-progress",), "Only the fixed boolean opt-in may be exposed."
    assert captured[0][1]["action"] == "store_true", "Output paths must derive from JUnit only."


@pytest.mark.parametrize("setup", ["failed", "skipped"])
def test_CallAfterRefusedSetupCannotInventCompletedProtocol(tmp_path, setup):
    """A call after failed or skipped setup is not a complete legal pytest protocol."""

    report, recorder = Start(tmp_path)
    Report(recorder, outcome=setup)
    Report(recorder, phase="call")
    Report(recorder, phase="teardown")
    recorder.pytest_sessionfinish()
    summary = progress.SaveProgressSummary(report, timed_out=True)
    assert summary["completed"] == 0 and summary["incomplete"] >= 1, (
        "Invalid phase ordering must not fabricate a completed case after refused setup."
    )
