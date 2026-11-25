# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real CLI/shell routes and source-safe, fully verified offline syslog presentation."""

from __future__ import annotations

import json
import shlex
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import syslog_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.shell import InteractiveShell
from tests.syslog_helpers import (
    ORIGINAL,
    Files,
    ImportArguments,
    InspectArguments,
    Owned,
    Run,
)


def test_HandlerShowsOriginalFieldsAndCoordinatesWithExplicitSdValueOptIn(tmp_path):
    """Default records are useful operator inventory without arbitrary message or SD values."""

    root, path = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, path))
    assert status == 0 and imported["record_count"] == 3 and "records" not in imported, (
        "Import must return verified original anchors and count without source payload"
    )
    before = Files(root)
    status, inspected = Run(InspectArguments(root, imported))
    assert status == 0 and inspected["ack_basis"] == "verified-present", (
        "Inspection must distinguish current verified presence from acquisition ACK history"
    )
    first, second, third = inspected["records"]
    assert first["hostname"] == "h" and first["app_name"] == "app" and first["procid"] == "42", (
        "Default inspection lost preserved source header inventory"
    )
    assert first["timestamp_offset"] == "+05:30" and first["byte_offset"] == 0 and (
        second["timestamp"] is None and third["message"]["byte_length"] == 0
    ), "Default output lost original offsets, NIL semantics or present-empty message"
    assert all("value" not in item for item in first["structured_data"][0]["parameters"]), (
        "Default record inventory unexpectedly exposed structured-data values"
    )
    status, exported = Run([*InspectArguments(root, imported), "--export-records"])
    assert status == 0 and [item["value"] for item in exported["records"][0][
        "structured_data"][0]["parameters"]] == ["one", "two", 'x]y"z\\'], (
        "Explicit JSON record export lost ordered repeated original SD values"
    )
    assert "café" not in json.dumps(exported, ensure_ascii=False), (
        "Even explicit record export must never copy arbitrary MSG content"
    )
    assert exported["source"] == imported["source"] and exported["read_declaration"] == (
        imported["read_declaration"]
    ) and exported["provenance"] == imported["provenance"], (
        "Retained CLI inspection refreshed or replaced original source/read/acquisition attribution"
    )
    humanStatus, human = Run(InspectArguments(root, imported), machine=False)
    assert humanStatus == 0 and '"hostname": "h"' in human and '"value":' not in human, (
        "Human output must expose source inventory while withholding SD parameter values"
    )
    assert Files(root) == before, "Inspect or record export changed persisted original bytes"


@pytest.mark.parametrize("selection", ["missing", "override", "abbreviation", "human-export"])
def test_ConfigurationRefusalsAreSafeAndDoNotWrite(tmp_path, selection):
    """Malformed grammar cannot expose rejected arguments or gain an implicit selection."""

    root, path = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, path))
    assert status == 0, "The operator refusal fixture must first import successfully"
    arguments = InspectArguments(root, imported)

    if selection == "missing":
        arguments = ["inspect", str(root)]

    elif selection == "override":
        arguments += ["--source-version", "private-rejected-marker"]

    elif selection == "abbreviation":
        arguments[2] = "--rece"

    else:
        arguments.append("--export-records")

    before = Files(root)
    status, result = Run(arguments, machine=selection != "human-export")
    assert status == 2 and "private-rejected-marker" not in str(result), (
        "Configuration refusal reflected rejected data or accepted incomplete selections"
    )
    assert Files(root) == before, "Invalid CLI configuration changed original evidence"


@pytest.mark.parametrize("payload,pin", [(b"not-syslog-secret-marker", None), (ORIGINAL, "0" * 64)])
def test_ParseAndChecksumRefusalsExposeNoRecordsAndTruthfulStorage(tmp_path, payload, pin):
    """Correct malformed bytes retain their refusal; wrong original pins publish nothing."""

    root, path = Owned(tmp_path, payload)
    arguments = ImportArguments(root, path, payload, "single")

    if pin is not None:
        arguments[arguments.index("--expected-sha256") + 1] = pin

    status, result = Run(arguments)
    assert status == 4 and "records" not in result and "secret-marker" not in str(result), (
        "A parser or checksum refusal falsely exposed success or original message text"
    )
    expected = "parse-rejected" if pin is None else "digest-rejected"
    assert result["acquisition_state"] == expected, (
        "Source checksum and consumed parser refusals must remain distinguishable"
    )
    assert result["receipt_ack"] == ("confirmed" if pin is None else "not-attempted"), (
        "Refusal must preserve actual independent publication acknowledgements"
    )

    if pin is None:
        status, replay = Run(InspectArguments(root, result))
        assert status == 4 and replay["acquisition_state"] == "parse-rejected", (
            "Retained parser refusal became a usable record result"
        )


def test_CorruptOriginalRefusesBeforeAnySourceRecordPresentation(tmp_path):
    """The CLI stages records only after the complete independently anchored original verifies."""

    root, path = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, path))
    assert status == 0, "Corruption fixture import must succeed"
    record = LocalEvidenceStore(root / "evidence").Get(imported["raw_id"])
    (root / "evidence" / record.reference.locator).write_bytes(b"corrupt")
    before = Files(root)
    status, refused = Run([*InspectArguments(root, imported), "--export-records"])
    assert status == 4 and refused["failure"] == "integrity" and (
        "records" not in refused and
        refused["raw_id"] is None and "source" not in refused
    ), "An unverified original leaked records, source attribution or a false original ACK"
    assert Files(root) == before, "Integrity refusal wrote original evidence"


@pytest.mark.parametrize("arguments", [["--help"], ["import", "--help"], ["inspect", "-h"]])
def test_HelpIsExactAndNeverOpensAStore(arguments, monkeypatch):
    """Discover local grammar without a source, workspace, acquisition or external action."""

    def Denied(*arguments, **keywords):
        """Tripwire a help path that attempts to load or acquire any original."""

        raise AssertionError("Help accessed source storage")

    monkeypatch.setattr(commands, "ImportSavedSyslogFile", Denied)
    monkeypatch.setattr(commands, "LoadSavedSyslog", Denied)
    output = StringIO()
    assert commands.RunSyslogCommands(arguments, output) == 0, "Exact help must complete locally"
    assert "1337 trace syslog" in output.getvalue(), "Help must name the real operator namespace"


def test_MainAndShellPreserveExplicitSelectionsAndPrivateHistory(tmp_path, monkeypatch):
    """The established trace route supplies no implicit context or source defaults."""

    root, path = Owned(tmp_path)
    output = StringIO()
    monkeypatch.setattr("sys.stdout", output)
    assert Main(["trace", "syslog", *ImportArguments(root, path), "--json"]) == 0, (
        "The actual module entry route failed the new saved-file operation"
    )
    imported = json.loads(output.getvalue())
    shellOutput = StringIO()
    shell = InteractiveShell(stdout=shellOutput)
    line = "trace syslog " + shlex.join([*InspectArguments(root, imported), "--json"])
    shell.onecmd(line)
    assert json.loads(shellOutput.getvalue())["record_count"] == 3, (
        "The foreground shell did not use the same explicit verified original handler"
    )
    assert shell.lastcmd == "trace" and shell._history[-1] == "trace", (
        "Original file paths and receipt pins entered private shell command history"
    )


def test_ReopenMismatchCannotBecomeAnImportSuccess(tmp_path, monkeypatch):
    """An importer result is not enough without matching original read-back and declarations."""

    root, path = Owned(tmp_path)
    loader = commands.LoadSavedSyslog

    def Substitute(*arguments, **keywords):
        """Return a genuine typed replay with a changed caller-scope declaration."""

        result = loader(*arguments, **keywords)
        return replace(result, source=replace(result.source, sourceVersion="substituted"))

    monkeypatch.setattr(commands, "LoadSavedSyslog", Substitute)
    status, refused = Run(ImportArguments(root, path))
    assert status == 4 and refused["failure"] == "integrity" and "records" not in refused, (
        "CLI trusted a returned acquisition without independently matching original read-back"
    )
    assert refused["raw_ack"] == refused["receipt_ack"] == "confirmed", (
        "Read-back failure must not erase earlier independently verified storage acknowledgements"
    )


def test_PresentationBudgetStagesRecordsAndShortWritesAreNotRetried(tmp_path, monkeypatch):
    """A finite renderer stages output and performs exactly one checked terminal write."""

    root, path = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, path))
    assert status == 0, "The output boundary fixture must acquire its real originals"
    originalRender = commands.RenderSyslog

    def Bounded(outcome, machine):
        """Inject a record presentation ceiling while keeping the safe metadata fallback."""

        if "records" in outcome:
            raise ValueError("inert presentation budget")

        return originalRender(outcome, machine)

    monkeypatch.setattr(commands, "RenderSyslog", Bounded)
    status, refused = Run(InspectArguments(root, imported))
    assert status == 4 and refused["failure"] == "presentation" and "records" not in refused, (
        "Presentation refusal emitted partial original records or claimed successful completion"
    )

    class ShortOutput(StringIO):
        """Record calls and report an incomplete write without copying it a second time."""

        calls = 0

        def write(self, text):
            """Exercise the external TextIO callback's truthful short-write return."""

            self.calls += 1
            super().write(text[:1])

            return 1

    output = ShortOutput()
    status = commands.RunSyslogCommands(InspectArguments(root, imported), output)
    assert status == 4, (
        "A short terminal write must not claim successful operator output"
    )
    assert output.calls == 1, "An incomplete terminal response must never be retried"


def test_InterruptedAndUnavailableSourcesHaveFixedDiagnostics(tmp_path, monkeypatch):
    """Errors never copy source text or turn an unattempted owner write into success."""

    root, path = Owned(tmp_path)
    path.unlink()
    status, refused = Run(ImportArguments(root, path))
    assert status == 2 and refused["raw_ack"] == "not-attempted", (
        "A missing selected original must refuse before publication"
    )

    def Interrupted(*arguments, **keywords):
        """Inject interruption before any acquisition acknowledgement."""

        raise KeyboardInterrupt

    monkeypatch.setattr(commands, "ImportSavedSyslogFile", Interrupted)
    status, refused = Run(ImportArguments(root, path))
    assert status == 130 and refused["failure"] == "interrupted" and "records" not in refused, (
        "Interruption must retain truthful status without reflected selected inputs"
    )


@pytest.mark.parametrize("during", ["write", "flush"])
def test_OutputErrorsReturnFailureWithoutRetry(tmp_path, during):
    """A caller-owned terminal may fail; records are never written again as a fallback."""

    root, path = Owned(tmp_path)

    class BrokenOutput(StringIO):
        """Retain an explicit terminal fault point independently from source storage."""

        calls = 0

        def write(self, text):
            """Implement the external output callback with a controlled physical failure."""

            self.calls += 1

            if during == "write":
                raise OSError("inert terminal failure")

            return super().write(text)

        def flush(self):
            """Implement the external flush callback without reflecting source data."""

            if during == "flush":
                raise OSError("inert terminal failure")

    output = BrokenOutput()
    assert commands.RunSyslogCommands(ImportArguments(root, path), output) == 4, (
        "Output failure must refuse a successful terminal result"
    )
    assert output.calls == 1, "A terminal write or flush failure must not retry source output"


def test_ActualPresentationByteCeilingAndTypedResultGuard(monkeypatch):
    """The renderer and result boundary enforce their real finite domains."""

    outcome = {"status": "failed", "exit_code": 4}
    monkeypatch.setattr(commands, "MAX_SYSLOG_OUTPUT_BYTES", 1)

    with pytest.raises(ValueError):
        commands.RenderSyslog(outcome, True)

    with pytest.raises(ValueError):
        commands.RenderSyslog({**outcome, "records": "foreign"}, False)

    with pytest.raises(ValueError):
        commands.DescribeSyslog("foreign")


def test_LateRenderInterruptionCannotExposeCompletedStatusOrRecords(tmp_path, monkeypatch):
    """A one-shot interrupt while staging successful records gets one safe failed-130 fallback."""

    root, path = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, path))
    assert status == 0, "The late-render fixture must acquire actual original evidence"
    render = commands.RenderSyslog
    calls = []

    def Interrupted(outcome, machine):
        """Interrupt the first complete record render before any terminal write."""

        calls.append((outcome["status"], "records" in outcome))

        if len(calls) == 1:
            raise KeyboardInterrupt

        return render(outcome, machine)

    monkeypatch.setattr(commands, "RenderSyslog", Interrupted)
    status, refused = Run(InspectArguments(root, imported))
    assert status == 130 and refused["status"] == "failed" and (
        refused["failure"] == "interrupted" and refused["record_count"] is None
        and "records" not in refused
    ), "Late presentation interruption leaked records, completed status or a traceback"
    assert calls == [("completed", True), ("failed", False)], (
        "Late interrupt fallback must remove records before a single safe presentation"
    )


@pytest.mark.parametrize("state,expected", [("storage-failed", 4), ("interrupted", 130)])
def test_IndependentStorageFailuresRemainFailuresWithoutAutomaticReplay(
    tmp_path, monkeypatch, state, expected,
):
    """Confirmed earlier originals do not overwrite the original caller's terminal failure."""

    root, path = Owned(tmp_path)
    acquire = commands.ImportSavedSyslogFile

    def Failed(*arguments, **keywords):
        """Preserve genuine owner facts while injecting a final caller-side interruption."""

        acquired = acquire(*arguments, **keywords)

        return replace(acquired, state=state, document=None)

    monkeypatch.setattr(commands, "ImportSavedSyslogFile", Failed)
    status, refused = Run(ImportArguments(root, path))
    assert status == expected and refused["status"] == "failed" and "records" not in refused, (
        "Independent storage failure was automatically recovered or presented as success"
    )
    assert refused["raw_ack"] == refused["receipt_ack"] == "confirmed", (
        "Original truthful publication ACKs must survive a later terminal failure"
    )
