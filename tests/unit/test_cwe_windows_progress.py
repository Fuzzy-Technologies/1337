# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise only bounded diagnostic observers, without rerunning the CWE selection."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import xml.etree.ElementTree as xml
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "cwe_windows_progress", Path(__file__).parents[1] / "cwe_windows_progress.py")
assert SPEC is not None and SPEC.loader is not None, "The owned diagnostic module must load."
progress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(progress)


def Start(tmp_path, worker="gw0"):
    """Open a fresh fixed-path worker recorder and return its original evidence path."""

    directory = progress.Directory(tmp_path)

    return progress.Recorder(directory, worker), directory / f"{worker}.jsonl"


def Events(path):
    """Read only the original flushed diagnostic stream for assertions."""

    return [json.loads(line) for line in path.read_text().splitlines()]


def test_StartAndEveryPhaseFlushImmediatelyWithoutSensitiveReportFields(tmp_path):
    """A running case leaves its original start even before any phase completes."""

    recorder, path = Start(tmp_path)
    node = "private/test_owned.py::test_Example[PRIVATE_PARAMETER]"
    recorder.pytest_runtest_logstart(node, ("PRIVATE_LOCATION", 1, "PRIVATE_FUNCTION"))
    assert Events(path)[-1]["event"] == "start", "Starts must persist before phase execution."

    for phase in ("setup", "call", "teardown"):
        recorder.pytest_runtest_logreport(SimpleNamespace(
            nodeid=node, when=phase, outcome="passed", longrepr="PRIVATE_EXCEPTION"))
        assert Events(path)[-1]["phase"] == phase, "Every reported phase must flush immediately."

    recorder.pytest_sessionfinish()
    events = Events(path)
    assert events[0]["partial"] and events[0]["diagnostic_only"], (
        "Worker observations must always be partial diagnostics, never acceptance."
    )
    assert events[-1]["event"] == "session_finished" and events[-1]["partial"], (
        "Session finish must not invent a successful or complete selection."
    )
    assert events[1]["label"] == "test_owned.py::test_Example", "Labels must exclude parameters."
    assert len(events[1]["node_sha256"]) == 64, "Original identity must remain hashed."
    assert "PRIVATE" not in path.read_text() and "private/" not in path.read_text(), (
        "Locations, parameters, paths and exception payloads must not enter progress evidence."
    )


@pytest.mark.parametrize("worker_input", [None, {}, {"workerid": "master"},
    {"workerid": "gw12"}, {"workerid": "../escape"}, {"workerid": 1}])
def test_ControllerAndUnboundedWorkerIdentitiesAreIgnored(tmp_path, monkeypatch, worker_input):
    """The controller, serial process and unsupported replacement workers create no files."""

    monkeypatch.setattr(progress, "ROOT", tmp_path)
    registered = []
    config = SimpleNamespace(workerinput=worker_input,
        pluginmanager=SimpleNamespace(register=lambda *args: registered.append(args)))
    progress.pytest_configure(config)
    assert not registered and not list(tmp_path.iterdir()), (
        "Only an admitted xdist worker may create diagnostic evidence."
    )


def test_AdmittedWorkersAndReplacementsHaveIndependentFixedExclusiveStreams(tmp_path, monkeypatch):
    """Worker replacements cannot overwrite an earlier worker or admit arbitrary filenames."""

    monkeypatch.setattr(progress, "ROOT", tmp_path)
    registered = []

    for worker in ("gw0", "gw1", "gw11", "gw0"):
        config = SimpleNamespace(workerinput={"workerid": worker},
            pluginmanager=SimpleNamespace(register=lambda *args: registered.append(args)))
        progress.pytest_configure(config)

    assert len(registered) == 3, "An existing worker stream must never be overwritten."

    for recorder, name in registered:
        assert name == "cwe-windows-worker-progress", "The plugin ownership name must stay fixed."
        recorder.Close()

    assert {path.name for path in progress.Directory(tmp_path).iterdir()} == {
        "gw0.jsonl", "gw1.jsonl", "gw11.jsonl"}, "Only fixed admitted filenames may be created."


@pytest.mark.parametrize("quota", ["MAX_EVENTS", "MAX_BYTES", "MAX_EVENT_BYTES"])
def test_QuotaCutoffIsFiniteAndExplicitlyTruncated(tmp_path, monkeypatch, quota):
    """Finite caps preserve a truncation marker without converting partial evidence to complete."""

    recorder, path = Start(tmp_path)
    value = {"MAX_EVENTS": 2, "MAX_BYTES": 750, "MAX_EVENT_BYTES": 150}[quota]
    monkeypatch.setattr(progress, quota, value)

    for _ in range(20):
        recorder.pytest_runtest_logstart("test_owned.py::test_Example", None)

    recorder.pytest_sessionfinish()
    events = Events(path)
    assert events[-1] == {"event": "truncated", "partial": True, "diagnostic_only": True}, (
        "Every cap must stop with explicit diagnostic truncation."
    )
    assert path.stat().st_size <= progress.MAX_BYTES, "No worker may exceed its byte quota."
    assert sum(event.get("event") == "truncated" for event in events) == 1, (
        "Closed streams cannot append more truncation or finish records."
    )


@pytest.mark.parametrize("node", ["unsafe\nlabel[param]", "a" * 8193, None, "☃"])
def test_UnsupportedIdentifiersCannotLeakOrCrashTheObserver(tmp_path, node):
    """Unsafe and oversized pytest identities retain only an unavailable label."""

    recorder, path = Start(tmp_path)
    recorder.pytest_runtest_logstart(node, None)
    recorder.pytest_runtest_logreport(SimpleNamespace(
        nodeid=node, when="unknown", outcome="passed"))
    recorder.Close()
    assert Events(path)[1]["label"] == "unavailable", "Untrusted labels must be safely replaced."
    assert Events(path)[2] == {"event": "unsupported_report", "partial": True}, (
        "Unsupported phases must not pretend to be valid pytest reports."
    )


def test_MultiMegabyteIdentityIsExplicitlyPrefixHashedAndLaterStartsRemainVisible(tmp_path):
    """Large selected payload parameters cannot exhaust the journal or masquerade as full hashes."""

    recorder, path = Start(tmp_path)
    recorder.pytest_runtest_logstart("test_owned.py::test_Large[" + "x" * (4 * 1024 * 1024), None)
    recorder.pytest_runtest_logstart("test_owned.py::test_Next", None)
    recorder.Close()
    events = Events(path)
    assert events[1]["identity_truncated"] and events[1]["hash_scope"] == (
        "first_8192_characters"
    ) and len(events[1]["node_sha256"]) == 64, (
        "A bounded prefix digest must explicitly identify its truncated identity scope."
    )
    assert events[2]["label"] == "test_owned.py::test_Next" and path.stat().st_size < 1024, (
        "One large payload identity must leave later case-start observations intact."
    )


@pytest.mark.parametrize("mode, attributes", [(stat.S_IFLNK, 0), (stat.S_IFDIR, 0x400)])
def test_LinkedAndReparseAncestorsAreRejected(tmp_path, monkeypatch, mode, attributes):
    """Reject both POSIX links and Windows reparse metadata before writing any descendants."""

    original = Path.lstat

    def Metadata(path):
        """Substitute only the fixed diagnostic ancestor's owned unsupported metadata."""

        if path == tmp_path / progress.PARTS[0]:
            return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)

        return original(path)

    monkeypatch.setattr(Path, "lstat", Metadata)

    with pytest.raises(OSError):
        progress.Directory(tmp_path)

    assert not list((tmp_path / progress.PARTS[0]).iterdir()), (
        "Rejected linked/reparse ancestors must never acquire descendants."
    )


def test_ExistingFilesCannotBeOverwritten(tmp_path, monkeypatch):
    """Exclusive creation refuses existing final files without following or replacing them."""

    directory = progress.Directory(tmp_path)
    targetFile = directory / "gw0.jsonl"
    targetFile.write_text("unchanged")
    monkeypatch.setattr(progress, "ROOT", tmp_path)
    config = SimpleNamespace(workerinput={"workerid": "gw0"},
        pluginmanager=SimpleNamespace(register=lambda *args: pytest.fail("Existing file admitted")))
    progress.pytest_configure(config)
    assert targetFile.read_text() == "unchanged", "Existing evidence must remain intact."


def test_StorageErrorsDoNotChangeTestOutcomes(tmp_path):
    """A failed diagnostic write must close its stream without raising into pytest."""

    recorder, path = Start(tmp_path)
    recorder.stream.close()
    recorder.stream = SimpleNamespace(write=FailWrite, close=lambda: None)
    recorder.pytest_runtest_logstart("test_owned.py::test_Example", None)
    recorder.pytest_sessionfinish()
    assert recorder.stream is None and Events(path)[0]["partial"], (
        "Unavailable telemetry must stay partial and leave test execution unchanged."
    )


def FailWrite(payload):
    """Raise one deterministic owned I/O failure without external storage dependencies."""

    raise OSError("Owned diagnostic write failure")


def test_RealExplicitPluginProducesOnlyWorkerEvidenceAndKeepsFailedExit(tmp_path):
    """Two real workers observe synthetic owned cases without loading the actual CWE subset."""

    tests = tmp_path / "tests"
    tests.mkdir()
    plugin = tests / "cwe_windows_progress.py"
    plugin.write_bytes((Path(__file__).parents[1] / plugin.name).read_bytes())
    (tests / "test_owned.py").write_text(
        'def test_OwnedPass():\n    """Owned diagnostic pass."""\n    assert True\n\n'
        'def test_OwnedFailure():\n    """Owned diagnostic failure."""\n'
        '    assert False, "Owned failure must preserve exit one."\n')
    environment = {**os.environ, "PYTHONPATH": str(tests), "PYTEST_ADDOPTS": ""}
    result = subprocess.run([
        sys.executable, "-m", "pytest", "tests/test_owned.py", "-p", "cwe_windows_progress",
        "-n", "2", "--dist=load", "-o", "addopts=", "--no-cov", "--timeout=10",
        "--junitxml=owned.xml", "-q",
    ], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 1, "Diagnostic observation must preserve a real failed pytest exit."
    directory = tmp_path.joinpath(*progress.PARTS)
    streams = sorted(directory.glob("*.jsonl"))
    assert {path.name for path in streams} == {"gw0.jsonl", "gw1.jsonl"}, (
        "Only two real workers may write streams; the controller must remain silent."
    )
    events = [event for path in streams for event in Events(path)]
    assert sum(event.get("event") == "start" for event in events) == 2, (
        "Every actual test must flush one start sentinel."
    )
    assert any(event.get("outcome") == "failed" for event in events), (
        "The original failed phase must remain visible without an invented successful selection."
    )
    assert (tmp_path / "owned.xml").is_file(), "Authoritative original JUnit must also be retained."


def Junit(path):
    """Write a synthetic complete original report with the fixed five class populations."""

    root = xml.Element("testsuites")
    suite = xml.SubElement(root, "testsuite", tests="327", failures="0", errors="0", skipped="0")

    for name, count in progress.EXPECTED_CLASSES.items():
        for index in range(count):
            xml.SubElement(suite, "testcase", classname=name, name=f"test_Owned{index}")

    xml.ElementTree(root).write(path, encoding="utf-8")

    return root, suite


def test_ExactSuccessfulJunitAndMainRetainSeparateDiagnosticAcceptance(
    tmp_path, monkeypatch, capsys,
):
    """Only all 327 distinct unskipped cases may pass the independent JUnit verification."""

    assert progress.EXPECTED_CLASSES == {
        "tests.contract.test_intelligence_cwe_selection_contract": 132,
        "tests.integration.test_intelligence_cwe_selection_composition": 13,
        "tests.unit.test_intelligence_cwe_selection": 34,
        "tests.unit.test_intelligence_cwe_xml": 59,
        "tests.unit.test_intelligence_cwe_zip": 89,
    }, "The verifier must retain the exact independently confirmed five-file case population."
    monkeypatch.setattr(progress, "ROOT", tmp_path)
    path = progress.Directory(tmp_path).parent / "selection.xml"
    Junit(path)
    assert progress.VerifyJunit(path), "The exact complete original successful report must pass."
    assert progress.Main() == 0, "Verified diagnostic acceptance must preserve a zero exit."
    facts = json.loads(capsys.readouterr().out)
    assert facts["accepted"] and facts["expected_cases"] == 327 and facts["diagnostic_only"], (
        "Diagnostic verification must explicitly state its limited 327-case acceptance."
    )
    assert facts["full_gate_replaced"] is False, "A subset pass cannot replace the full gate."


@pytest.mark.parametrize("fault", ["failure", "error", "skipped", "xfail", "duplicate", "foreign",
    "missing", "suite_count", "suite_failure", "absent_counter", "wrong_root", "unexpected_suite"])
def test_IncompleteSkippedFailedOrForeignJunitCannotTurnGreen(tmp_path, fault):
    """Require exact unique populations, counters and zero skipped/error/failure cases."""

    path = tmp_path / "selection.xml"
    root, suite = Junit(path)
    first, second = list(suite)[:2]

    if fault in ("failure", "error", "skipped", "xfail"):
        xml.SubElement(first, fault)

    elif fault == "duplicate":
        second.set("name", first.get("name"))

    elif fault == "foreign":
        first.set("classname", "tests.unit.test_unrelated")

    elif fault == "missing":
        suite.remove(first)

    elif fault == "suite_count":
        suite.set("tests", "326")

    elif fault == "suite_failure":
        suite.set("failures", "1")

    elif fault == "absent_counter":
        del suite.attrib["skipped"]

    elif fault == "wrong_root":
        root.tag = "unrelated"

    else:
        xml.SubElement(root, "unexpected")

    xml.ElementTree(root).write(path, encoding="utf-8")
    assert not progress.VerifyJunit(path), "Malformed or incomplete JUnit must fail closed."


@pytest.mark.parametrize("payload", [b"not xml", b"<!DOCTYPE testsuites><testsuites/>",
    b"<!ENTITY owned 'value'><testsuites/>"])
def test_MissingUnsupportedOrOversizedJunitRemainsRefused(tmp_path, monkeypatch, payload):
    """Missing, non-XML, declared entities and byte-budget overflow cannot invent test execution."""

    path = tmp_path / "selection.xml"
    assert not progress.VerifyJunit(path), "Missing JUnit must fail closed."
    path.write_bytes(payload)
    assert not progress.VerifyJunit(path), "Unsupported original report bytes must fail closed."
    Junit(path)
    monkeypatch.setattr(progress, "MAX_JUNIT_BYTES", 100)
    assert not progress.VerifyJunit(path), "Oversized original JUnit must fail its finite budget."


def test_MainMissingReportEmitsTruthfulRefusal(tmp_path, monkeypatch, capsys):
    """Missing original report must produce bounded machine facts and a nonzero verifier status."""

    monkeypatch.setattr(progress, "ROOT", tmp_path)
    assert progress.Main() == 1, "Missing report must prevent a diagnostic green status."
    assert json.loads(capsys.readouterr().out)["accepted"] is False, (
        "Absent original execution evidence cannot be reported as accepted."
    )
