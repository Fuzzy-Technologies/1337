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
    sourceReads = []

    def ReadSelected(owner, reference):
        """Supply only the selected receipt fields to this validation-order unit test."""

        if reference.role == "intelligence-source":
            sourceReads.append(reference)

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
    assert not sourceReads, "Original bytes were read before selected receipt constraints."
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


def DetailDocument():
    """Describe a fictional product with independent legacy and current source assessments."""

    document = json.loads(FeedBody(IntelligenceFeed.CVE))
    cna = document["containers"]["cna"]
    cna["descriptions"] = [{"lang": "en", "value": "Owned fictional source assertion"}]
    cna["affected"] = [{"vendor": "Owned vendor", "product": "Owned product", "versions": [
        {"version": "1", "status": "affected", "versionType": "custom", "lessThan": "3",
         "changes": [{"at": "2", "status": "unknown"}]},
        {"version": "0", "status": "unaffected"},
    ]}]
    cna["metrics"] = [
        {"cvssV2_0": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                       "baseScore": 0.1}},
        {"cvssV3_1": {"version": "3.1", "baseScore": 9.8,
                       "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
        {"cvssV4_0": {"version": "4.0", "baseScore": 9.3,
                       "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                                       "SC:N/SI:N/SA:N"}},
    ]

    return document


def ImportedDetails(tmp_path, document=None):
    """Import original fictional CVE bytes through the actual owning product dispatcher."""

    model, finding = Context(tmp_path)
    source = tmp_path / "owned-cve.json"
    source.write_bytes(json.dumps(DetailDocument() if document is None else document).encode())
    status, outcome = Run(ImportArguments(model.root, source, IntelligenceFeed.CVE))
    assert status == 0, "Source setup failed before selected detailed inspection."

    return model, finding, outcome


def test_SelectedCveDetailsKeepSourceStatusesAndIndependentScoresWithoutSnapshotCopies(tmp_path):
    """Detailed inspection connects existing source APIs while remaining read-only and bounded."""

    model, _, imported = ImportedDetails(tmp_path)
    before = Files(model.root)
    arguments = Selection("inspect", model.root, imported)
    _, default = Run(arguments)
    status, selected = Run([*arguments, "--identifier", "CVE-1900-9999"])
    assert status == 0 and set(selected) == set(default) | {"details"}, (
        "Explicit inspection changed the default terminal contract rather than adding detail."
    )
    details = selected["details"]
    assert details["target_applicability"] == "not-evaluated" and details[
        "publisher_authentication"
    ] == "not-assessed", "Source inspection manufactured target or publisher verification."
    assert details["source"]["origin"] == "synthetic", "Source origin was hidden or upgraded."
    record = details["records"][0]
    assert [(item["version"], item["base_score"]) for item in record["data"]["cvss"]] == [
        ("4.0", 9.3), ("3.1", 9.8),
    ], "Separate current source scores were recalculated, selected, or combined."
    profiles = details["cve_source_profiles"]
    product = profiles["applicability"]["containers"][0]["affected"][0]
    assert product == DetailDocument()["containers"]["cna"]["affected"][0], (
        "Affected/unaffected/unknown source declarations changed or became a target verdict."
    )
    legacy = profiles["cvss2"]
    assert legacy["assessments"][0]["metric"]["cvssV2_0"]["baseScore"] == 0.1, (
        "Calculated CVSS2 base score overwrote the publisher's asserted score."
    )
    assert legacy["base_calculations"] == [{"assessment_index": 0,
                                            "algorithm": "cvss2-base-2.10",
                                            "base_score_tenths": 75}], (
        "The existing exact CVSS2 arithmetic was replaced by source score interpretation."
    )
    assert '"snapshot":' not in json.dumps(details) and len(json.dumps(details)) < 10000, (
        "Detailed inspection duplicated whole snapshots or original source bytes."
    )
    assert Files(model.root) == before, "Read-only details changed evidence or canonical state."


@pytest.mark.parametrize("feed", list(IntelligenceFeed))
def test_SelectedDetailsPreserveExactRecordsAndExplicitUnmatchedIdentifiers(tmp_path, feed):
    """Every supported source family exposes only requested records and keeps absence uncertain."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.data"
    source.write_bytes(FeedBody(feed))
    _, imported = Run(ImportArguments(model.root, source, feed))
    selectedId = "CWE-89" if feed is IntelligenceFeed.CWE else "CVE-1900-9999"
    status, outcome = Run([*Selection("inspect", model.root, imported),
                           "--identifier", selectedId, "--identifier", "CVE-1900-8888"])
    assert status == 0, "Selected source inspection failed its verified owning-store boundary."
    details = outcome["details"]
    assert [item["identifier"] for item in details["records"]] == [selectedId], (
        "Selected details included unrelated source assertions."
    )
    assert details["unmatched_identifiers"] == ["CVE-1900-8888"], (
        "Missing source membership became affected, unaffected, or silently vanished."
    )
    status, absent = Run([*Selection("inspect", model.root, imported),
                          "--identifier", "CVE-1900-8888"])
    assert status == 0 and absent["details"]["records"] == [], (
        "An absent requested identifier manufactured a source record or failed the whole source."
    )
    assert "cve_source_profiles" not in absent["details"], (
        "Unmatched CVE selection disclosed unrelated source declarations."
    )


@pytest.mark.parametrize("version", ["5.0", "5.1", "5.1.1"])
def test_OlderCveFormatsRetainAssertionsWithoutInventingNewProfileSupport(tmp_path, version):
    """Unsupported extended source formats remain explicit while original snapshot support works."""

    document = DetailDocument()
    document["dataVersion"] = version
    model, _, imported = ImportedDetails(tmp_path, document)
    status, outcome = Run([*Selection("inspect", model.root, imported),
                           "--identifier", "CVE-1900-9999"])
    assert status == 0 and outcome["details"]["records"], "Existing CVE assertions were lost."
    assert outcome["details"]["cve_source_profiles"] == {
        "format_version": version, "state": "unsupported-format",
    }, "The CLI claimed extra source declaration support for an unimplemented format."


@pytest.mark.parametrize("profile", ["applicability", "cvss2"])
def test_UnsupportedProfileContentKeepsIndependentVerifiedSourceAssertions(tmp_path, profile):
    """Strict profile refusals remain explicit without changing source bytes or other profiles."""

    document = DetailDocument()

    if profile == "applicability":
        document["containers"]["cna"]["affected"][0]["unsupportedQualifier"] = "unknown"

    else:
        document["containers"]["cna"]["metrics"][0]["cvssV2_0"]["unsupportedMetric"] = 1

    model, _, imported = ImportedDetails(tmp_path, document)
    status, outcome = Run([*Selection("inspect", model.root, imported),
                           "--identifier", "CVE-1900-9999"])
    assert status == 0, "Unsupported additional profile content hid all verified base assertions."
    profiles = outcome["details"]["cve_source_profiles"]
    assert profiles[profile] == {"profile_version": 1, "state": "unsupported-content"}, (
        "An unsupported declaration was guessed, silently dropped, or interpreted as absence."
    )
    other = "cvss2" if profile == "applicability" else "applicability"
    assert profiles[other]["state"] == "inspected", "One profile failure erased another profile."


def test_RejectedCveDetailedInspectionDoesNotCreatePositiveAssessments(tmp_path):
    """Rejected source records retain their state with empty declaration and calculation arrays."""

    document = DetailDocument()
    document["cveMetadata"]["state"] = "REJECTED"
    model, _, imported = ImportedDetails(tmp_path, document)
    status, outcome = Run([*Selection("inspect", model.root, imported),
                           "--identifier", "CVE-1900-9999"])
    assert status == 0 and outcome["details"]["records"][0]["data"]["state"] == "REJECTED", (
        "Rejected source state was hidden by selected inspection."
    )
    profiles = outcome["details"]["cve_source_profiles"]
    assert profiles["applicability"]["containers"] == [] and profiles["cvss2"][
        "assessments"
    ] == profiles["cvss2"]["base_calculations"] == [], (
        "Rejected CVE inspection invented positive source assertions or zero-score assessments."
    )


@pytest.mark.parametrize("identifiers", [
    ["cve-1900-9999"], ["CVE-1900-9999", "CVE-1900-9999"],
    [f"CVE-1900-{1000 + index}" for index in range(65)], ["untrusted-value"],
])
def test_InvalidDetailSelectionsRefuseBeforeOriginalSourceVerification(tmp_path, monkeypatch,
                                                                     identifiers):
    """Malformed, repeated or excessive explicit selections do not reach owning source reads."""

    model, _, imported = Imported(tmp_path)
    entered = []

    def Verify(*arguments):
        """Fail the test if malformed configuration crosses the original-source boundary."""

        entered.append(arguments)
        raise AssertionError("Invalid detail selection reached source verification.")

    monkeypatch.setattr(commands, "VerifiedIntelSelection", Verify)
    arguments = Selection("inspect", model.root, imported)

    for identifier in identifiers:
        arguments.extend(["--identifier", identifier])

    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration" and not entered, (
        "Invalid identifier selection was not rejected before source verification."
    )
    assert "untrusted-value" not in json.dumps(outcome), "Rejected selection leaked to output."


def test_ExactSelectionCountBoundAndDetailByteCeilingRemainIndependent(tmp_path, monkeypatch):
    """At most 64 selected records may render, and excessive detail refuses without truncation."""

    model, _, imported = Imported(tmp_path)
    arguments = Selection("inspect", model.root, imported)

    for index in range(64):
        arguments.extend(["--identifier", f"CVE-1900-{1000 + index}"])

    status, outcome = Run(arguments)
    assert status == 0 and len(outcome["details"]["unmatched_identifiers"]) == 64, (
        "The inclusive 64-identifier bound was reduced or silently truncated."
    )
    before = Files(model.root)
    monkeypatch.setattr(commands, "MAX_INSPECTION_BYTES", 1)
    status, refused = Run([*Selection("inspect", model.root, imported),
                           "--identifier", "CVE-1900-9999"])
    assert status == 4 and refused["failure"] == "inspection-limit" and "details" not in refused, (
        "Excessive source details were partially printed or reported as successful."
    )
    assert Files(model.root) == before, "Detail-size refusal changed owning state."


@pytest.mark.parametrize("feed", list(IntelligenceFeed))
def test_HumanSelectedDetailsExplainFeedMeaningAndEscapeTerminalControls(tmp_path, feed):
    """Human inspection explains separate measures without terminal-active source content."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.data"
    source.write_bytes(json.dumps(DetailDocument()).encode() if feed is IntelligenceFeed.CVE
                       else FeedBody(feed))
    _, imported = Run(ImportArguments(model.root, source, feed))
    identifier = "CWE-89" if feed is IntelligenceFeed.CWE else "CVE-1900-9999"
    status, human = Run([*Selection("inspect", model.root, imported),
                         "--identifier", identifier, "--identifier", "CVE-1900-8888"],
                        json_output=False)
    assert status == 0 and "target applicability has not been evaluated" in human, (
        "Human detail lost the source-versus-target interpretation boundary."
    )
    expected = {IntelligenceFeed.EPSS: "next 30 days", IntelligenceFeed.KEV: "Listed in",
                IntelligenceFeed.CWE: "Weakness:", IntelligenceFeed.CVE: "Source CVSS 3.1"}
    assert expected[feed] in human and "CVE-1900-8888" in human, (
        "Human detail omitted the source measure's meaning or unmatched selection."
    )
    assert commands.IntelDisplay("source\x1b[31m\u202e") == "source\\u001b[31m\\u202e", (
        "Selected source metadata could execute terminal controls or hide directional text."
    )
