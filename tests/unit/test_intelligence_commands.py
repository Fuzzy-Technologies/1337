# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local intelligence dispatcher bounds, owning-store failures and safe presentation."""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import intelligence_commands as commands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_acquisition import AcquisitionState
from fuzzy1337.model import LocalModelStore, Observation
from fuzzy1337.shell import InteractiveShell
from tests.e2e.test_intelligence_cli import ApplyArguments, Files, ImportArguments, Selection
from tests.integration.test_intelligence_acquisition_persistence import Context, FeedBody


def Run(arguments: list[str], *, json_output: bool = True) -> tuple[int, dict | str]:
    """Exercise the dispatcher in process so its actual Python control flow is measured."""

    output = StringIO()
    status = commands.RunIntelCommands(arguments, output, json_output=json_output)

    return status, json.loads(output.getvalue()) if json_output else output.getvalue()


def Imported(tmp_path: Path) -> tuple[LocalModelStore, str, dict]:
    """Produce actual owning acquisition records through this invocation's dispatcher."""

    model, finding = Context(tmp_path)
    source = tmp_path / "owned.csv"
    source.write_bytes(FeedBody(IntelligenceFeed.EPSS))
    status, outcome = Run(ImportArguments(model.root, source, IntelligenceFeed.EPSS))
    assert status == 0 and isinstance(outcome, dict), "Owned import setup failed."

    return model, finding, outcome


@pytest.mark.parametrize("feed", list(IntelligenceFeed))
def test_DispatcherImportsAndVerifiesActualOwningRecords(tmp_path, feed):
    """Measure actual bounded local dispatch, source decoding and immutable owning replay."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.data"
    source.write_bytes(FeedBody(feed))
    status, imported = Run(ImportArguments(model.root, source, feed))
    assert status == 0 and isinstance(imported, dict), "Local format dispatch failed."
    before = Files(model.root)
    status, inspected = Run(Selection("inspect", model.root, imported))
    assert status == 0 and isinstance(inspected, dict) and inspected["feed"] == feed.value, (
        "Owning replay changed the explicitly selected source family."
    )
    assert Files(model.root) == before, "Read-only replay changed retained files."


@pytest.mark.parametrize("arguments", [
    [], ["remote", "untrusted-value"], ["import", "untrusted-value"],
    ["inspect", "untrusted-value"], ["apply", "untrusted-value"],
    ["inspect", "untrusted-value", "--snapshot", "untrusted-value", "--receipt"],
])
def test_InvalidGrammarNeverEchoesRejectedArguments(arguments):
    """Argument failures are one stable JSON record rather than argparse's value-bearing text."""

    status, outcome = Run(arguments)
    assert status == 2 and isinstance(outcome, dict) and outcome["failure"] == "configuration", (
        "Incomplete or unsupported grammar did not fail as configuration."
    )
    assert "untrusted-value" not in json.dumps(outcome), "Rejected values leaked to output."


@pytest.mark.parametrize("action", [None, "import", "inspect", "apply"])
def test_HelpUsesCallerStreamAndDescribesSelectedActionWithoutExecution(action):
    """Command-specific help exposes explicit options without requiring an owning workspace."""

    output = StringIO()
    arguments = ["--help"] if action is None else [action, "--help"]
    assert commands.RunIntelCommands(arguments, output) == 0, "Help returned a failure status."
    expected = "import,inspect,apply" if action is None else (
        "--feed" if action == "import" else "--snapshot"
    )
    assert expected in output.getvalue(), "Action help hid its required explicit selections."


@pytest.mark.parametrize("path", ["../owned", "owned/../source", "owned\x1bsource", "x" * 4097])
def test_PathConfigurationRejectsTraversalControlsAndUnboundedValues(path):
    """Lexical rejection happens before any input file can be opened."""

    with pytest.raises(commands.IntelFailure, match="configuration"):
        commands.IntelPath(Path(path))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_LocalImportRefusesObservedUnsafeInputKinds(tmp_path, kind):
    """Explicit selection does not authorize following links or opening a non-regular file."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.data"
    original = tmp_path / "original.data"
    original.write_bytes(FeedBody(IntelligenceFeed.EPSS))

    if kind == "symlink":
        source.symlink_to(original)

    elif kind == "hardlink":
        os.link(original, source)

    else:
        source.mkdir()

    before = Files(model.root)
    status, outcome = Run(ImportArguments(model.root, source, IntelligenceFeed.EPSS))
    assert status == 2 and isinstance(outcome, dict) and outcome["failure"] == "configuration", (
        "Unsafe explicit input reached acquisition."
    )
    assert Files(model.root) == before, "Rejected input created an acquisition or changed model."


@pytest.mark.parametrize("value", ["0", "16777217", "invalid"])
def test_InvalidImportByteLimitsRefuseBeforeAnyAcquisition(tmp_path, value):
    """A caller cannot replace the finite library bound with an unbounded local file read."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv"
    source.write_bytes(FeedBody(IntelligenceFeed.EPSS))
    before = Files(model.root)
    status, outcome = Run([*ImportArguments(model.root, source, IntelligenceFeed.EPSS),
                           "--max-bytes", value])
    assert status == 2 and isinstance(outcome, dict), "Invalid byte budget passed configuration."
    assert Files(model.root) == before, "Rejected bound published source bytes."


def test_ActualApplyAndHumanInspectionKeepBodiesOutOfTerminal(tmp_path):
    """The dispatcher commits actual verified interpretation and human output remains a summary."""

    model, finding, imported = Imported(tmp_path)
    status, outcome = Run(ApplyArguments(model, finding, imported))
    assert status == 0 and outcome["model_commit"] == "confirmed", (
        "Direct owned application did not persist its verified observation."
    )
    status, human = Run(Selection("inspect", model.root, imported), json_output=False)
    assert status == 0 and "intel.inspect: succeeded" in human, "Human inspection lost success."
    assert "cve,epss" not in human and "https://example.invalid" not in human, (
        "Human presentation exposed source bodies or unrequested source metadata."
    )


def test_ActualBusyModelRefusesSaveWithoutRemovingOriginalWriterLock(tmp_path):
    """A live owner's model lock yields a fixed failure, never a traceback or lock cleanup."""

    model, finding, imported = Imported(tmp_path)
    lock = model.root / "state" / "model" / ".write-lock"
    lock.mkdir()
    before = Files(model.root)
    status, outcome = Run(ApplyArguments(model, finding, imported))
    assert status == 4 and outcome["failure"] == "model-busy", "Busy writer was ignored."
    assert outcome["model_commit"] == "not-committed" and lock.is_dir(), (
        "The command guessed a model commit or removed another owner's writer lock."
    )
    assert Files(model.root) == before, "Busy save changed owning state bytes."


def test_ActualCasConflictPreservesTheConcurrentOwnerState(tmp_path, monkeypatch):
    """A real intervening first-party save cannot be overwritten by the CLI's computed update."""

    model, finding, imported = Imported(tmp_path)
    original = LocalModelStore.Save
    current = model.Open()
    provenance = current.Objects()[0].provenance[0]
    concurrent, _ = current.Apply(observations=(
        Observation("owned-concurrent-update", finding, {"synthetic": True}, provenance),
    ))

    def Save(self, state, *, expected_revision):
        """Commit the owned competitor once, then invoke the original real stale-revision check."""

        original(self, concurrent, expected_revision=expected_revision)

        return original(self, state, expected_revision=expected_revision)

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    status, outcome = Run(ApplyArguments(model, finding, imported))
    assert status == 4 and outcome["failure"] == "revision-conflict", (
        "The stale CLI update did not detect the real competing model commit."
    )
    assert outcome["model_commit"] == "not-committed" and model.Open() == concurrent, (
        "Conflict handling overwrote the concurrent owner's actual saved state."
    )


@pytest.mark.parametrize("failure,committed", [(OSError, False), (OSError, True),
                                               (KeyboardInterrupt, True)])
def test_SaveAcknowledgementFailureReportsUncertaintyAndActualRetainedState(
    tmp_path, monkeypatch, failure, committed,
):
    """A failed save acknowledgement never becomes false atomic rollback or successful output."""

    model, finding, imported = Imported(tmp_path)
    before = model.Open()
    original = LocalModelStore.Save

    def Save(self, state, *, expected_revision):
        """Optionally complete the actual owner save, then lose its caller acknowledgement."""

        if committed:
            original(self, state, expected_revision=expected_revision)

        raise failure("owned acknowledgement failure")

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    status, outcome = Run(ApplyArguments(model, finding, imported))
    assert status == (130 if failure is KeyboardInterrupt else 4), (
        "Failed save acknowledgement was reported as successful application."
    )
    assert outcome["model_commit"] == "unknown" and outcome["status"] == "failed", (
        "The command invented knowledge of atomic rollback after a lost acknowledgement."
    )
    assert model.Open().revision == before.revision + int(committed), (
        "The actual retained model differs from the controlled original owner save."
    )


@pytest.mark.parametrize("failure", ["missing", "storage", "interrupt", "parse", "overflow"])
def test_ImportFailuresNeverClaimAUsableSnapshot(tmp_path, monkeypatch, failure):
    """The dispatcher retains honest acquisition failure and fixed local diagnostics."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv"
    source.write_bytes(FeedBody(IntelligenceFeed.EPSS))

    if failure == "missing":
        source.unlink()

    elif failure == "parse":
        source.write_bytes(b"owned invalid source")

    elif failure == "overflow":
        source.write_bytes(b"source exceeds a small explicit bound")

    else:
        original = commands.AcquireIntelligenceSnapshot

        def Acquire(root, request, *, scope_reference):
            """Model terminal storage refusal or an operator interruption at the owning boundary."""

            if failure == "interrupt":
                raise KeyboardInterrupt

            outcome = original(root, request, scope_reference=scope_reference)

            return replace(outcome, state=AcquisitionState.STORAGE_FAILED, snapshot=None,
                           receipt=None)

        monkeypatch.setattr(commands, "AcquireIntelligenceSnapshot", Acquire)

    arguments = ImportArguments(model.root, source, IntelligenceFeed.EPSS)

    if failure == "overflow":
        arguments.extend(["--max-bytes", "1"])

    status, outcome = Run(arguments)
    assert status != 0 and outcome["status"] == "failed", "Failed import became success."
    assert outcome["source_sha256"] is None, "Failed import supplied a usable source snapshot."


@pytest.mark.parametrize("failure", ["role", "shape", "limits", "pin", "oversize"])
def test_VerifiedReceiptRefusesInvalidTypedFieldsAndReadBounds(tmp_path, failure):
    """Rehashed selected records cannot evade receipt/source consistency or finite read ceilings."""

    model, _, imported = Imported(tmp_path)
    store = LocalEvidenceStore(model.root / "evidence")
    receipt = store.Get(imported["receipt_id"])
    document = json.loads(store.Read(receipt.reference))
    role = receipt.reference.role

    if failure == "role":
        role = "stdout"

    elif failure == "shape":
        document = []

    elif failure == "limits":
        document["limits"]["max_bytes"] = True

    elif failure == "pin":
        document["source"]["expected_sha256"] = "0" * 64

    else:
        document["padding"] = "x" * commands.MAX_RECEIPT_BYTES

    replacement = store.Put(json.dumps(document).encode(), role, "application/json",
                            receipt.provenance)
    imported["receipt_id"] = replacement.evidence_id
    before = Files(model.root)
    status, outcome = Run(Selection("inspect", model.root, imported))
    assert status == 4 and outcome["status"] == "failed", "Invalid receipt passed inspection."
    assert Files(model.root) == before, "Rejected receipt inspection changed owning bytes."


@pytest.mark.parametrize("action", ["inspect", "apply"])
@pytest.mark.parametrize(
    "constraint", ["byte-type", "byte-budget", "hard-ceiling", "pin", "timeout"],
)
def test_SelectionChecksReceiptConstraintsBeforeOriginalLoader(tmp_path, monkeypatch,
                                                             action, constraint):
    """Validate selected receipt limits before entering the original-source loader."""

    model, finding, imported = Imported(tmp_path)
    store = LocalEvidenceStore(model.root / "evidence")
    receipt = store.Get(imported["receipt_id"])
    document = json.loads(store.Read(receipt.reference))

    if constraint == "byte-type":
        document["limits"]["max_bytes"] = True

    elif constraint == "byte-budget":
        document["limits"]["max_bytes"] = 1

    elif constraint == "hard-ceiling":
        document["limits"]["max_bytes"] = commands.MAX_SOURCE_BYTES + 1

    elif constraint == "pin":
        document["source"]["expected_sha256"] = "0" * 64

    else:
        document["limits"]["receiver_timeout_seconds"] = 61

    read = commands.BoundedIntelEvidenceStore.Read
    loader = commands.LoadAcquiredSnapshot
    loaded = []
    source_reads = []

    def ReadSelected(owner, reference):
        """Supply only the selected receipt fields to this validation-order unit test."""

        if reference.role == "intelligence-source":
            source_reads.append(reference)

        return json.dumps(document).encode() if reference == receipt.reference else (
            read(owner, reference)
        )

    def LoadOriginal(root, snapshot_id):
        """Record entry while preserving the real small owned fixture's loader behavior."""

        loaded.append(snapshot_id)

        return loader(root, snapshot_id)

    monkeypatch.setattr(commands.BoundedIntelEvidenceStore, "Read", ReadSelected)
    monkeypatch.setattr(commands, "LoadAcquiredSnapshot", LoadOriginal)
    arguments = Selection("inspect", model.root, imported) if action == "inspect" else (
        ApplyArguments(model, finding, imported)
    )
    before = Files(model.root)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["status"] == "failed", "Invalid receipt constraints passed."
    assert not source_reads, "Original bytes were read before selected receipt constraints."
    assert not loaded, "The original-source loader ran before selected receipt constraints."
    assert Files(model.root) == before, "Receipt preflight changed owning workspace bytes."


def test_ShellIntelDispatchUsesExplicitSelectionsAndRedactsRetainedHistory(tmp_path):
    """The actual shell uses the product dispatcher but keeps only the namespace in history."""

    model, _, imported = Imported(tmp_path)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd(shlex.join(["intel", *Selection("inspect", model.root, imported), "--json"]))
    outcome = json.loads(output.getvalue())
    assert outcome["status"] == "succeeded", "Actual shell did not use owning selection replay."
    output.seek(0)
    output.truncate()
    shell.onecmd("history")
    assert output.getvalue() == "intel\n" and shell.lastcmd == "history", (
        "Shell retained source paths/receipt IDs or enabled empty-line command replay."
    )


@pytest.mark.parametrize("workspace", [
    r"C:\Owned\workspace", r"C:\Owned workspace\intelligence", "/owned workspace/intelligence",
])
def test_QuotedShellSelectionsPreserveWindowsSeparatorsAndSpaces(workspace, monkeypatch):
    """The documented shell grammar preserves an explicitly quoted path on every platform."""

    received = []
    output = StringIO()

    def Dispatch(arguments, stream, *, json_output=False):
        """Observe the actual shared shell parser without opening a foreign filesystem path."""

        received.append((arguments, json_output))
        stream.write('{"status":"succeeded"}\n')

        return 0

    monkeypatch.setattr(commands, "RunIntelCommands", Dispatch)
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    arguments = ["inspect", workspace, "--snapshot", "sha256:" + "a" * 64,
                 "--receipt", "sha256:" + "b" * 64]
    shell.onecmd(shlex.join(["intel", *arguments, "--json"]))
    assert received == [(arguments, True)], (
        "Quoted shell selection removed Windows separators or split one explicit path."
    )
    assert json.loads(output.getvalue()) == {"status": "succeeded"}, (
        "Successful quoted dispatch added a second terminal document."
    )
