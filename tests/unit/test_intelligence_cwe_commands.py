# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local selected CWE command preflight, owning-store failures and bounded presentation."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import sys
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import intelligence_cwe_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from tests.contract.test_intelligence_cwe_commands_contract import Run
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry


def Body(*, name="Owned source name"):
    """Build an explicitly owned ZIP with matched, known-unsupported and absent selections."""

    return Archive(Catalog(b"<Weaknesses>" + Entry(name=name) + b"</Weaknesses><Views>"
                           + Entry("89", kind="View") + b"</Views>"))


def Arguments(root, source, raw):
    """Pass deliberately unsorted explicit IDs and mandatory exact original digest."""

    return ["import", str(root), str(source), "--catalog-version", "5.0",
            "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--identifier", "CWE-999",
            "--identifier", "CWE-89", "--identifier", "CWE-79", "--scope", "scope:owned"]


def Inspect(root, outcome):
    """Select exact successful immutable roots without replacement source facts."""

    return ["inspect", str(root), "--selection", outcome["selection_id"],
            "--receipt", outcome["receipt_id"]]


def Imported(tmp_path, *, name="Owned source name"):
    """Import one real owned archive through the actual parent router and SDK."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = Body(name=name)
    source.write_bytes(raw)
    status, outcome = Run(Arguments(model.root, source, raw))
    assert status == 0, "Owned fixture import failed"

    return model, source, raw, outcome


@pytest.mark.parametrize("case", ["duplicate", "many", "identifier", "version", "digest",
    "scope", "max-zero", "max-big", "max-type", "scalar", "scalar-equal", "abbreviation"])
def test_SourcePreflightOccursBeforeAnyPathOrStoreRead(tmp_path, monkeypatch, case):
    """Invalid source facts cannot reach path checks, caller files or owning stores."""

    args = Arguments(tmp_path, tmp_path / "untrusted.zip", Body())

    if case == "duplicate":
        args.extend(["--identifier", "CWE-79"])

    elif case == "many":
        args.extend([item for _ in range(62) for item in ("--identifier", "CWE-79")])

    elif case in ("scalar", "scalar-equal"):
        args.extend(["--scope=scope:other"] if case == "scalar-equal" else ["--scope", "other"])

    elif case == "abbreviation":
        args[args.index("--catalog-version")] = "--catalog-ver"

    else:
        option, value = {"identifier": ("--identifier", "CVE-2024-3094"),
            "version": ("--catalog-version", "latest"), "digest": ("--expected-sha256", "A" * 64),
            "scope": ("--scope", ""), "max-zero": ("--max-bytes", "0"),
            "max-big": ("--max-bytes", "4194305"), "max-type": ("--max-bytes", "untrusted")}[case]

        if option in args:
            args[args.index(option) + 1] = value

        else:
            args.extend([option, value])

    def Refuse(*args, **kwargs):
        """Trip on any filesystem preflight reached by invalid source metadata."""

        raise AssertionError("Invalid source reached filesystem")

    monkeypatch.setattr(commands, "IntelPath", Refuse)
    monkeypatch.setattr(commands, "ReadLocalIntel", Refuse)
    status, outcome = Run(args)
    assert status == 2 and outcome["failure"] == "configuration", "Invalid source passed preflight"
    assert "untrusted" not in json.dumps(outcome), "Rejected source value leaked"


@pytest.mark.parametrize("size", [0, 7, 8, 9, 10])
def test_RegularFileEofAndOverflowKeepActualBoundedOriginalDigest(tmp_path, size):
    """The unchanged reader requests one overflow byte; SDK owns retained prefix completeness."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = b"x" * size
    source.write_bytes(raw)
    status, outcome = Run([*Arguments(model.root, source, raw), "--max-bytes", "8"])
    assert status == 4 and outcome["acquisition_state"] == (
        "size-exceeded" if size > 8 else "parse-failed"
    ), "EOF boundary changed complete versus partial SDK state"
    assert outcome["body_complete"] is (size <= 8), "Extra-byte sentinel was ignored"
    assert outcome["received_bytes"] == min(size, 8), "Sentinel became retained original bytes"
    assert outcome["source_sha256"] == hashlib.sha256(raw[:8]).hexdigest(), (
        "Terminal digest used requested pin instead of actual confirmed artifact"
    )
    store = LocalEvidenceStore(model.root / "evidence")
    record = store.Get(outcome["raw_id"])
    assert store.Read(record.reference) == raw[:8], "Original prefix changed"
    assert record.reference.role == (
        "cwe-local-zip-partial" if size > 8 else "cwe-local-zip-source"
    ), (
        "Overflow became a complete original artifact"
    )
    assert "selection" not in outcome and outcome["receipt_ack"] == "confirmed", (
        "Failed import exposed assertions or lost its actual terminal receipt"
    )


def test_DigestMismatchReportsActualRawRatherThanExpectedPin(tmp_path):
    """A requested byte identity does not replace observed original-byte evidence."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = Body()
    source.write_bytes(raw)
    args = Arguments(model.root, source, raw)
    args[args.index("--expected-sha256") + 1] = "0" * 64
    status, outcome = Run(args)
    assert status == 4 and outcome["acquisition_state"] == "digest-mismatch", "Wrong pin passed"
    assert outcome["source_sha256"] == hashlib.sha256(raw).hexdigest(), "Expected pin became fact"


@pytest.mark.parametrize("stage", ["raw", "selection", "receipt"])
@pytest.mark.parametrize("committed", [False, True])
def test_ActualStorePublicationLossPreservesIndependentAcknowledgements(tmp_path, monkeypatch,
                                                                      stage, committed):
    """A write may commit without returning; no guessed rollback or usable selection follows."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = Body()
    source.write_bytes(raw)
    original = LocalEvidenceStore.Put
    role = {"raw": "cwe-local-zip-source", "selection": "cwe-local-selected-envelope",
            "receipt": "cwe-local-selected-acquisition"}[stage]

    def Put(owner, data, selected_role, media_type, provenance):
        """Optionally commit the actual artifact, then lose its acknowledgement."""

        if selected_role != role:
            return original(owner, data, selected_role, media_type, provenance)

        if committed:
            original(owner, data, selected_role, media_type, provenance)

        raise EvidenceError("untrusted storage diagnostic")

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    status, outcome = Run(Arguments(model.root, source, raw))
    assert status == 4 and outcome["acquisition_state"] == "storage-failed", (
        "Lost ACK became success"
    )
    assert outcome[stage + "_ack"] == "unknown" and outcome[stage + "_id"] is None, (
        "Lost acknowledgement acquired an invented returned handle"
    )
    assert outcome["raw_ack"] == ("unknown" if stage == "raw" else "confirmed"), (
        "Earlier confirmed raw publication was erased"
    )
    assert "source" not in outcome and "selection" not in outcome, "Failure exposed usable content"
    assert "untrusted" not in json.dumps(outcome), "Storage diagnostics leaked"


@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
@pytest.mark.parametrize("phase", ["reader", "sdk"])
def test_UnreturnedExecutionNeverInventsAcknowledgements(tmp_path, monkeypatch, phase, failure):
    """Unavailable SDK facts remain null; interruption before SDK has no publication claim."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = Body()
    source.write_bytes(raw)

    def Refuse(*args, **kwargs):
        """Raise an untrusted failure without a terminal result."""

        raise failure("untrusted value")

    monkeypatch.setattr(commands, "ReadLocalIntel" if phase == "reader"
                        else "AcquireLocalCweSelection", Refuse)
    status, outcome = Run(Arguments(model.root, source, raw))
    assert status == (130 if failure is KeyboardInterrupt else 2 if phase == "reader" else 4), (
        "Execution failure had the wrong process status"
    )
    assert all(outcome[name + "_ack"] == ("unknown" if phase == "sdk" else "not-attempted")
               for name in ("raw", "selection", "receipt")), "Unreturned execution guessed ACKs"
    assert outcome["source_sha256"] is None and outcome["raw_id"] is None, (
        "Unavailable facts invented"
    )


def test_SucceededEnumCannotReplaceCompleteReceiptAcknowledgement(tmp_path, monkeypatch):
    """An internally inconsistent terminal outcome is refused by the adapter success predicate."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.zip"
    raw = Body()
    source.write_bytes(raw)
    original = commands.AcquireLocalCweSelection

    def Acquire(*args, **kwargs):
        """Keep actual writes but deliberately remove returned receipt confirmation."""

        return replace(original(*args, **kwargs), receipt=None,
                       receipt_ack=commands.CweAcknowledgement.UNKNOWN)

    monkeypatch.setattr(commands, "AcquireLocalCweSelection", Acquire)
    status, outcome = Run(Arguments(model.root, source, raw))
    assert status == 4 and "selection" not in outcome, "Succeeded enum bypassed receipt requirement"


@pytest.mark.parametrize("human", [False, True])
def test_PresentationLimitStagesBeforeWritingAndPreservesConfirmedFacts(
    tmp_path, monkeypatch, human,
):
    """A finite output refusal never prints partial successful assertions or destroys custody."""

    model, source, raw, imported = Imported(tmp_path, name="Owned é source")
    monkeypatch.setattr(commands, "MAX_TERMINAL_BYTES", 100)
    status, outcome = Run(Inspect(model.root, imported), human=human)
    assert status == 4, "Terminal budget was not enforced"

    if human:
        assert "presentation-limit" in outcome and "source assertions" not in outcome, (
            "Human overflow leaked partial successful output"
        )
        assert imported["raw_id"] in outcome, "Human fallback erased confirmed artifact"

    else:
        assert outcome["failure"] == "presentation-limit" and "selection" not in outcome, (
            "JSON overflow exposed partial selection"
        )
        assert outcome["raw_id"] == imported["raw_id"] and outcome["raw_ack"] == "confirmed", (
            "JSON fallback erased verified custody"
        )


def test_ActualInspectRetainsPartitionsEscapesControlsAndWritesNothing(tmp_path, monkeypatch):
    """Verified-present is distinct from historical ACK return and has no model/network effects."""

    model, source, raw, imported = Imported(tmp_path, name="Owned é source")
    before = Files(model.root)

    def Refuse(*args, **kwargs):
        """Trip if inspection writes a model or any evidence."""

        raise AssertionError("Inspection attempted write")

    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    status, outcome = Run(Inspect(model.root, imported))
    assert status == 0 and outcome["ack_basis"] == "verified-present", (
        "Inspection rewrote ACK basis"
    )
    selected = outcome["selection"]
    assert selected["requested_ids"] == ["CWE-79", "CWE-89", "CWE-999"], "IDs were not sorted"
    assert selected["unsupported_entries"] == [{"identifier": "CWE-89", "source_kind": "View"}], (
        "Unsupported source kind became absent or Weakness"
    )
    assert selected["unmatched_ids"] == ["CWE-999"], "Absent identity became risk"
    status, human = Run(Inspect(model.root, imported), human=True)
    assert status == 0 and "Owned é source" in human, "Readable source prose changed"
    assert all(value in human for value in ("4329", "day precision",
                                           "unsupported source kind View")), (
        "Human output lost notice provenance, date precision or source partitions"
    )
    assert Files(model.root) == before, "Read-only inspection changed owning bytes"


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "hardlink"])
def test_PhysicalFileRefusalDoesNotPublish(tmp_path, kind):
    """Existing observed regular singly-linked input policy remains the actual file boundary."""

    model, _ = Context(tmp_path)
    original = tmp_path / "owned.zip"
    raw = Body()
    original.write_bytes(raw)
    source = tmp_path / "untrusted.zip"

    if kind == "directory":
        source.mkdir()

    elif kind == "symlink":
        source.symlink_to(original)

    elif kind == "hardlink":
        source.hardlink_to(original)

    before = Files(model.root)
    status, outcome = Run(Arguments(model.root, source, raw))
    assert status == 2 and outcome["raw_ack"] == "not-attempted", "Nonphysical file was published"
    assert Files(model.root) == before, "Rejected file changed owning workspace"


@pytest.mark.parametrize("args", [["cwe", "--help", "import"],
    ["cwe", "import", "--help", "--help"], ["cwe", "--json", "--json", "--help"]])
def test_ActualTopLevelInheritsGlobalHelpJsonNormalization(args, capsys):
    """The adapter cannot reject erased global duplicates or original help position."""

    status = Main(["intel", *args])
    output = capsys.readouterr()
    assert status == 0 and "usage:" in output.out and not output.err, "Global normalization changed"


def test_BoundedBufferIncludesActualUtf8AndRejectsBeforeAppend():
    """Actual byte ceilings include multibyte text and preserve already staged content."""

    output = commands.CweTerminalBuffer(2)
    output.Write("é")

    with pytest.raises(ValueError):
        output.Write("x")

    assert output.Text() == "é", "Overflow corrupted staged output"


@pytest.mark.parametrize("human", [False, True])
def test_RenderInterruptionHasSmallHonestTerminalWithoutSelectedContent(
    tmp_path, monkeypatch, human,
):
    """A one-shot staged-render interruption retains returned custody and exits 130."""

    model, source, raw, imported = Imported(tmp_path)
    original = commands.CweTerminal
    attempted = False

    def Render(*args, **kwargs):
        """Interrupt once while staging, then allow the fixed small fallback."""

        nonlocal attempted

        if not attempted:
            attempted = True
            raise KeyboardInterrupt

        return original(*args, **kwargs)

    monkeypatch.setattr(commands, "CweTerminal", Render)
    status, outcome = Run(Inspect(model.root, imported), human=human)
    assert status == 130, "Staged presentation interruption escaped its terminal contract"

    if human:
        assert "interrupted" in outcome and "CWE source assertions" not in outcome, (
            "Interrupted human render exposed partial success"
        )

    else:
        assert outcome["failure"] == "interrupted" and outcome["raw_id"] == imported["raw_id"], (
            "Render interruption erased already verified artifact"
        )
        assert "selection" not in outcome, "Interrupted rendering exposed selected content"


@pytest.mark.parametrize("human", [False, True])
def test_ActualEncodedTerminalLimitIncludesNewlineAndEscaping(tmp_path, monkeypatch, human):
    """Both full output forms fit exactly at their own actual UTF-8 ceiling, including framing."""

    model, source, raw, imported = Imported(tmp_path)
    output = StringIO()
    status = commands.RunCweIntelCommands(
        Inspect(model.root, imported), output, json_output=not human,
    )
    length = len(output.getvalue().encode())
    assert status == 0, "Fixture presentation failed before its exact boundary test"
    monkeypatch.setattr(commands, "MAX_TERMINAL_BYTES", length)
    status, outcome = Run(Inspect(model.root, imported), human=human)
    assert status == 0, "Exact encoded terminal budget was not inclusive"
    monkeypatch.setattr(commands, "MAX_TERMINAL_BYTES", length - 1)
    status, outcome = Run(Inspect(model.root, imported), human=human)
    assert status == 4, "Terminal framing or escaped bytes escaped the actual ceiling"


def test_DefensiveHumanRendererEscapesHostileScalarsBeforeMeasuring():
    """The internal display boundary escapes controls even though admitted CWE names reject them."""

    output = commands.CweTerminalBuffer(100)
    commands.WriteCweMetadata({"name": "Owned\u202e\nname"}, output, "Source")
    assert output.Text() == "Source.name: Owned\\u202e\\u000aname\n", "Controls reached terminal"

    with pytest.raises(ValueError):
        commands.WriteCweMetadata({"name": "\u202e" * 20}, output, "Source")


def test_InvalidSourceControlNameIsNotAUsableHumanAssertion(tmp_path):
    """The actual SDK refuses a nonprintable XML source name without exposing selected content."""

    model, _ = Context(tmp_path)
    raw = Body(name="Owned\u202e source")
    source = tmp_path / "owned.zip"
    source.write_bytes(raw)
    status, human = Run(Arguments(model.root, source, raw), human=True)
    assert status == 4 and "parse-failed" in human and "\u202e" not in human, (
        "Invalid source controls became a usable human assertion"
    )


def test_MissingWorkspaceIsIntegrityAndMalformedPathIsConfiguration(tmp_path):
    """Owning state failures stay separate from invalid explicit lexical paths."""

    args = Arguments(tmp_path / "missing", tmp_path / "owned.zip", Body())
    status, outcome = Run(args)
    assert status == 4 and outcome["failure"] == "integrity", (
        "Missing workspace became configuration"
    )
    args[1] = "../untrusted"
    status, outcome = Run(args)
    assert status == 2 and outcome["failure"] == "configuration", "Invalid lexical path passed"



def test_InterruptedSuccessAssemblyCannotLeaveUsableOutput(tmp_path):
    """An interrupt after success fields assemble still strips selected content on exit 130."""

    model, source, raw, imported = Imported(tmp_path)
    lines, start = inspect.getsourcelines(commands.RunCweIntelCommands)
    target = start + next(index for index, line in enumerate(lines)
                          if line == "        status = 0\n")

    def Interrupt(frame, event, arg):
        """Interrupt at the exact success-update boundary once, without changing production code."""

        if frame.f_code is commands.RunCweIntelCommands.__code__ and event == "line" and (
            frame.f_lineno == target
        ):
            raise KeyboardInterrupt

        return Interrupt

    previous = sys.gettrace()

    try:
        sys.settrace(Interrupt)
        status, outcome = Run(Inspect(model.root, imported))

    finally:
        sys.settrace(previous)

    assert status == 130 and outcome["status"] == "failed", "Assembly interrupt left success"
    assert outcome["raw_id"] == imported["raw_id"] and "selection" not in outcome, (
        "Assembly interruption lost confirmed custody or exposed selected content"
    )


def test_RetainedNoticeCapturePinsExactOriginalAndCompleteProductText():
    """The inert stable fixture preserves historical HTML and the exact full notice bundle text."""

    from fuzzy1337.intelligence_cwe_notice import CweNoticeBundle

    fixture = Path(__file__).parents[1] / "fixtures" / "cwe_notice_capture.json"
    document = json.loads(fixture.read_text())
    expected = {
        "raw_html": (17670, "c572b605b5753cd67b84d12fc64e9ccbfcde0188cf1332118be04c9996a92c45"),
        "full_text": (4329, "d1595d0a2bc408587d9d3ba24974e381547400772693635d4b340f225e068c2f"),
    }

    for key, (size, digest) in expected.items():
        data = base64.b64decode(document[key]["base64"], validate=True)
        assert len(data) == document[key]["bytes"] == size, "Retained original size changed"
        assert hashlib.sha256(data).hexdigest() == document[key]["sha256"] == digest, (
            "Retained original capture identity changed"
        )

    text = base64.b64decode(document["full_text"]["base64"], validate=True).decode("utf-8")
    assert CweNoticeBundle()["text"] == text, "Product notice omitted captured source text"
