# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""One multi-feed proposal/CAS, original-pair integrity and deterministic all-or-nothing refusal."""

from __future__ import annotations

import json
import shlex
import shutil
from dataclasses import replace
from io import StringIO
from unittest.mock import Mock

import pytest

from fuzzy1337 import intelligence_set_commands as commands
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Finding, FindingStatus, TransitionFinding
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import MAX_ATTRIBUTE_BYTES, CanonicalModelJson, LocalModelStore, ObjectKind
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import WorkspaceBusyError, WorkspaceConflictError
from tests.e2e.test_intelligence_cli import ImportArguments
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.intelligence_set_helpers import Arguments, Body, Files, Owned, Run


def test_FourOriginalFeedsProduceOneDeterministicProposalAndOneExactCas(tmp_path, monkeypatch):
    """The complete installed operation adds only the reviewed combined candidate observation."""

    model, finding, imported, paths = Owned(tmp_path)
    state = model.Open()
    actualFinding = Finding.FromObject(state.Objects(ObjectKind.FINDING)[0])
    state, delta = TransitionFinding(state, finding, FindingStatus.DISMISSED,
        replace(actualFinding.provenance[0], source_id="operator", run_reference="run:triage"),
        "Owned pre-existing triage")
    model.Save(state, expected_revision=delta.previous_revision)
    moved = tmp_path / "moved"
    shutil.move(model.root, moved)
    model = LocalModelStore(moved)

    for path in paths:
        path.unlink()

    before = Files(moved)
    originalFinding = model.Open().Objects(ObjectKind.FINDING)
    arguments = Arguments("preview-set", model, finding, imported)
    status, outcome = Run(arguments)
    assert status == 0 and outcome["model_commit"] == "not-attempted" and (
        outcome["evidence_commit"] == "not-attempted"
    ), "A combined preview must verify original owners without saving any state"
    preview = outcome["preview"]
    assert len(preview["observations"]) == 1 and not preview["already_applied"], (
        "Four source feeds must form one candidate observation through the existing SDK"
    )
    observation = preview["observations"][0]
    attributes = observation["attributes"]
    assertions = attributes["source_assertions"]
    assert {item["record"]["feed"] for item in assertions} == {
        feed.value for feed in IntelligenceFeed
    } and len(assertions) == 4, "The combined proposal lost a selected original source feed"
    assert attributes["unmatched_identifiers"] == ["CVE-1900-8888"], (
        "A genuinely unmatched ID became a zero score or disappeared"
    )
    assert [item["snapshot_reference"] for item in assertions] == sorted(
        item["snapshot_reference"] for item in assertions
    ), "The SDK must canonically sort source assertions independently of caller pair order"
    assert [(item["snapshot_id"], item["receipt_id"]) for item in outcome["selections"]] == [
        (item["snapshot_id"], item["receipt_id"]) for item in imported
    ], "Terminal metadata must preserve the caller's explicit original pair order"
    byFeed = {item["record"]["feed"]: item for item in assertions}
    cve = byFeed[IntelligenceFeed.CVE.value]
    assert cve["record"]["data"]["cvss"] == [{
        "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8, "assessor": "synthetic-cna",
    }], "The source CVSS assessor/vector/score were recomputed or lost"
    assert byFeed[IntelligenceFeed.KEV.value]["record"]["data"]["ransomware_use"] == (
        "Unknown"
    ), "Unknown source ransomware use acquired a product verdict"

    for assertion in assertions:
        feed = assertion["record"]["feed"]
        freshAt = assertion["record"]["effective_at"] if feed == IntelligenceFeed.EPSS.value else (
            assertion["source"]["acquired_at"])
        assert assertion["freshness_at"] == freshAt and assertion["association_state"] == (
            "candidate"
        ) and assertion["review"] is None, (
            "The combined owner changed freshness or review semantics"
        )
        assert assertion["canonical_url"] and assertion["evidence"]["sha256"] in {
            item["source_sha256"] for item in imported
        }, "A candidate lost its canonical URL or original retained source pin"

    assert byFeed[IntelligenceFeed.EPSS.value]["stale"] is True and all(
        not item["stale"] for feed, item in byFeed.items() if feed != IntelligenceFeed.EPSS.value
    ), "Recent acquisition replaced the EPSS score clock or made fresh source facts stale"
    assert Files(moved) == before and Run(arguments) == (status, outcome), (
        "The combined unsaved preview mutated owning bytes or used a new interpretation clock"
    )
    reverse = Arguments("preview-set", model, finding, list(reversed(imported)))
    reverseStatus, reversedResult = Run(reverse)
    assert reverseStatus == 0 and reversedResult["preview"] == preview, (
        "Caller source order changed the SDK's deterministic combined observation"
    )
    assert [(item["snapshot_id"], item["receipt_id"]) for item in reversedResult[
        "selections"]] == [
        (item["snapshot_id"], item["receipt_id"]) for item in reversed(imported)
    ], "Reversed caller metadata must not silently become canonical SDK order"
    saves = []
    save = LocalModelStore.Save

    def Save(self, proposal, **options):
        """Observe the genuine single CAS operation and its exact previously read revision."""

        assert set(options) == {"expected_revision"}, "CAS must receive only its owned revision key"
        assert options["expected_revision"] == self.Open().revision, (
            "The caller must forward its actual current saved revision to the real CAS"
        )
        saves.append(options["expected_revision"])

        return save(self, proposal, **options)

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    arguments[0] = "apply-set"
    status, applied = Run(arguments)
    saved = model.Open()
    assert status == 0 and applied["model_commit"] == "confirmed" and saves == [state.revision], (
        "Combined apply must perform one existing CAS, rather than independently save each source"
    )
    stored = [item for item in saved.observations if item.Reference() == observation["reference"]]
    assert len(stored) == 1 and JsonValue(stored[0]) == {
        key: value for key, value in observation.items() if key != "reference"
    }, "The single saved observation differs from the fully verified preview"
    assert saved.Objects(ObjectKind.FINDING) == originalFinding and saved.revision == (
        state.revision + 1
    ), "Combined enrichment changed finding identity, severity, confidence or operator disposition"
    assert applied["preview"] == preview and Files(moved / "evidence") == {
        key.removeprefix("evidence/"): value for key, value in before.items()
        if key.startswith("evidence/")
    }, "Apply changed the reviewed proposal or reacquired original evidence"
    arguments[arguments.index("--expected-revision") + 1] = str(saved.revision)
    replayBefore = Files(moved)
    status, replayed = Run(arguments)
    assert status == 0 and replayed["preview"]["already_applied"] and (
        replayed["preview"]["observations"] == [] and model.Open().revision == saved.revision
    ), "Exact combined replay added a duplicate revision or observation"
    assert Files(moved) == replayBefore, "Exact already-saved replay rewrote persisted bytes"


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("fault", ["mixed-receipt", "raw-corrupt"])
def test_EveryOriginalPairFailureRefusesTheWholeSetBeforeAnySave(
    tmp_path, monkeypatch, index, fault,
):
    """No valid prefix is saved or presented if any explicitly selected original is invalid."""

    model, finding, imported, _ = Owned(tmp_path)
    selected = [dict(item) for item in imported]

    if fault == "mixed-receipt":
        otherPath = tmp_path / "other-original.data"
        otherPath.write_bytes(Body(IntelligenceFeed.EPSS))
        status, other = Run(ImportArguments(model.root, otherPath, IntelligenceFeed.EPSS))
        assert status == 0, "A separate genuine local receipt must precede mixed-root refusal"
        selected[index]["receipt_id"] = other["receipt_id"]

    else:
        store = LocalEvidenceStore(model.root / "evidence")
        raw = store.Get(imported[index]["raw_id"])
        (model.root / "evidence" / raw.reference.locator).write_bytes(b"corrupted")

    before = Files(model.root)

    def Denied(*arguments, **keywords):
        """Tripwire any save or combined SDK proposal after a failed original selection."""

        raise AssertionError("A refused original reached combined interpretation or storage")

    monkeypatch.setattr(commands, "ApplyVerifiedEnrichment", Denied)
    monkeypatch.setattr(LocalModelStore, "Save", Denied)
    status, refused = Run(Arguments("apply-set", model, finding, selected))
    assert status == 4 and refused["status"] == "failed" and all(
        key not in refused for key in ("preview", "selections")
    ), "One invalid original leaked a successful or partial combined result"
    assert refused["model_commit"] == "not-attempted" and Files(model.root) == before, (
        "A failed source set changed retained model or evidence bytes"
    )


@pytest.mark.parametrize("fault", [
    "one", "many", "duplicate-snapshot", "duplicate-receipt", "id", "negative-revision",
    "age", "identifier", "time", "abbreviation",
])
def test_CompleteSelectionGrammarFailsBeforeAnyOwningRead(tmp_path, monkeypatch, fault):
    """Set count, independent roots and interpretation grammar are finite before preflight."""

    model, finding, imported, _ = Owned(tmp_path)
    selected = [dict(item) for item in imported]

    if fault == "one":
        selected = selected[:1]

    elif fault == "many":
        selected *= 5

    elif fault == "duplicate-snapshot":
        selected[-1]["snapshot_id"] = selected[0]["snapshot_id"]

    elif fault == "duplicate-receipt":
        selected[-1]["receipt_id"] = selected[0]["receipt_id"]

    elif fault == "id":
        selected[-1]["receipt_id"] = "private-invalid-selection"

    arguments = Arguments("preview-set", model, finding, selected)

    if fault == "negative-revision":
        arguments[arguments.index("--expected-revision") + 1] = "-1"

    elif fault == "age":
        arguments[arguments.index("--max-age-seconds") + 1] = "-1"

    elif fault == "identifier":
        arguments += ["--identifier", "CWE-89"]

    elif fault == "time":
        arguments[arguments.index("--as-of") + 1] = "not-a-clock"

    elif fault == "abbreviation":
        arguments[arguments.index("--selection")] = "--select"

    def Denied(*arguments, **keywords):
        """Prove malformed configuration never accesses the owning physical source paths."""

        raise AssertionError("Invalid set grammar reached storage")

    monkeypatch.setattr(commands, "IntelPath", Denied)
    monkeypatch.setattr(commands, "PreflightSet", Denied)
    status, refused = Run(arguments)
    assert status == 2 and "private-invalid-selection" not in str(refused) and (
        "preview" not in refused and "selections" not in refused
    ), "Malformed set grammar reached storage or reflected private rejected arguments"


@pytest.mark.parametrize("kind", ["snapshots", "receipts", "originals"])
def test_AggregateCeilingsPrecedeBodiesAndOriginalReparse(tmp_path, monkeypatch, kind):
    """All finite set totals are checked before their expensive body domain is opened."""

    model, finding, imported, _ = Owned(tmp_path)
    before = Files(model.root)
    reads = []
    read = commands.BoundedIntelEvidenceStore.Read

    def Read(self, reference):
        """Observe only source-body domain reads while preserving actual owner verification."""

        reads.append(reference.role)

        return read(self, reference)

    monkeypatch.setattr(commands.BoundedIntelEvidenceStore, "Read", Read)
    limit = {"snapshots": "MAX_SET_SNAPSHOT_BYTES", "receipts": "MAX_SET_RECEIPT_BYTES",
             "originals": "MAX_SET_RAW_BYTES"}[kind]
    monkeypatch.setattr(commands, limit, 1)
    status, refused = Run(Arguments("apply-set", model, finding, imported))
    assert status == 4 and refused["failure"] == "selection-limit" and all(
        role == "intelligence-snapshot" for role in reads
    ), "Aggregate refusal read an original or receipt body before all declared ceilings passed"
    assert (not reads) == (kind != "originals"), (
        "Snapshot and receipt aggregate sizes must precede every selected body read"
    )
    assert refused["model_commit"] == "not-attempted" and Files(model.root) == before, (
        "Aggregate source refusal saved a partial combined interpretation"
    )


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, WorkspaceConflictError,
                                    WorkspaceBusyError])
def test_SaveFailureKeepsCasTruthAndNoPartialResult(tmp_path, monkeypatch, failure):
    """A single attempted CAS has distinct unknown, interrupted and known-not-committed outcomes."""

    model, finding, imported, _ = Owned(tmp_path)
    before = Files(model.root)
    calls = []

    def Save(*arguments, **keywords):
        """Reject only the existing save boundary without running any acquisition again."""

        calls.append(keywords["expected_revision"])
        raise failure("private-fault-marker")

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    status, refused = Run(Arguments("apply-set", model, finding, imported))
    assert status == (130 if failure is KeyboardInterrupt else 4) and len(calls) == 1, (
        "Failed combined save was retried or lost its actual terminal status"
    )
    expected = "not-committed" if failure in (WorkspaceConflictError, WorkspaceBusyError) else (
        "unknown")
    assert refused["model_commit"] == expected and refused["model_revision"] is None and (
        "preview" not in refused and "selections" not in refused
        and "private-fault-marker" not in str(refused)
    ), "Failed CAS exposed a partial proposal, a fabricated revision or exception text"
    assert Files(model.root) == before, "A simulated uncommitted save altered saved state"


def test_LostSaveAcknowledgementDoesNotClaimRollbackAndExplicitReplayIsIdempotent(
    tmp_path, monkeypatch,
):
    """The genuine model may commit before a lost response; only explicit reopening resolves it."""

    model, finding, imported, _ = Owned(tmp_path)
    arguments = Arguments("apply-set", model, finding, imported)
    revision = model.Open().revision
    save = LocalModelStore.Save

    def Lost(self, proposal, **options):
        """Perform the genuine single save, then lose its caller acknowledgement."""

        assert set(options) == {"expected_revision"}, "Lost-ACK save must retain its owned CAS key"
        assert options["expected_revision"] == revision, (
            "Lost-ACK save must forward the explicitly selected original saved revision"
        )
        save(self, proposal, **options)
        raise OSError("inert lost acknowledgement")

    monkeypatch.setattr(LocalModelStore, "Save", Lost)
    status, refused = Run(arguments)
    assert status == 4 and refused["model_commit"] == "unknown" and (
        model.Open().revision == revision + 1
    ), "A lost model-save response falsely implied rollback or reported confirmed success"
    monkeypatch.setattr(LocalModelStore, "Save", save)
    arguments[arguments.index("--expected-revision") + 1] = str(model.Open().revision)
    status, replay = Run(arguments)
    assert status == 0 and replay["preview"]["already_applied"], (
        "Explicit replay after actual commit must use the existing idempotent observation owner"
    )


def test_PreflightIdentityAndRoleFailuresCannotBecomeUsableSelections(tmp_path, monkeypatch):
    """The metadata-only stage cannot skip manifest identity or admit another receipt family."""

    model, finding, imported, _ = Owned(tmp_path)
    owner = commands.BoundedIntelEvidenceStore(model.root / "evidence")
    record = owner.Get(imported[0]["snapshot_id"])

    def Metadata(*arguments, **keywords):
        """Return a genuine other manifest to exercise exact selected-ID binding."""

        return record.Serialize()

    with monkeypatch.context() as patch:
        patch.setattr(owner, "ReadStoredBytes", Metadata)

        with pytest.raises(commands.IntelFailure, match="integrity"):
            commands.SetManifest(owner, imported[1]["snapshot_id"])

    # A wrong-role original is genuinely saved and independently selected, never a fabricated body.
    raw = LocalEvidenceStore(model.root / "evidence").Get(imported[0]["raw_id"])
    selected = [dict(item) for item in imported]
    selected[0]["receipt_id"] = raw.evidence_id
    before = Files(model.root)
    status, refused = Run(Arguments("apply-set", model, finding, selected))
    assert status == 4 and refused["failure"] == "integrity" and Files(model.root) == before, (
        "Another genuine evidence role impersonated an original successful local receipt"
    )


def test_ActualMainShellHelpAndPrivateHistoryUseTheSameExplicitSetRoute(
    tmp_path, monkeypatch,
):
    """The installed transport and interactive shell never infer sources from selected context."""

    model, finding, imported, _ = Owned(tmp_path)
    arguments = Arguments("preview-set", model, finding, imported)
    output = StringIO()
    monkeypatch.setattr("sys.stdout", output)
    assert Main(["intel", *arguments, "--json"]) == 0, "Actual Main refused the original source set"
    expected = json.loads(output.getvalue())
    shellOutput = StringIO()
    shell = InteractiveShell(stdout=shellOutput)
    shell.onecmd("intel " + shlex.join([*arguments, "--json"]))
    assert json.loads(shellOutput.getvalue()) == expected and shell.lastcmd == "intel" and (
        list(shell._history) == ["intel"]
    ), "The shell changed the result or retained original source/receipt/finding arguments"
    helpOutput = StringIO()
    assert commands.RunIntelSetCommands(["preview-set", "--help"], helpOutput) == 0, (
        "Set help must expose the explicit grammar without a workspace"
    )
    assert "--selection SNAPSHOT RECEIPT" in helpOutput.getvalue(), (
        "Set help hid its independent original pair requirement"
    )


def test_PresentationLimitsAndLateInterruptionsNeverSaveOrExposePartialSets(tmp_path, monkeypatch):
    """A complete candidate output is bounded before CAS, and late staging faults expose no data."""

    model, finding, imported, _ = Owned(tmp_path)
    before = Files(model.root)
    monkeypatch.setattr(commands, "MAX_INSPECTION_BYTES", 1)
    status, refused = Run(Arguments("apply-set", model, finding, imported))
    assert status == 4 and refused["model_commit"] == "not-attempted" and (
        "preview" not in refused and Files(model.root) == before
    ), "An oversized combined proposal reached storage or partial presentation"


@pytest.mark.parametrize("during", ["write", "flush", "short", "interrupt"])
def test_RealOutputProtocolFailureIsOneAttemptWithoutAutomaticReplay(tmp_path, during):
    """Protocol adapters preserve actual short, write and flush failure behavior."""

    model, finding, imported, _ = Owned(tmp_path)
    output = Mock(spec=StringIO)
    sink = StringIO()

    def Write(text):
        """Use a real text sink and report the selected external terminal failure truthfully."""

        if during == "write":
            raise OSError("inert output failure")

        if during == "interrupt":
            raise KeyboardInterrupt

        return sink.write(text[:1] if during == "short" else text)

    def Flush():
        """Exercise the real flush callback after a successful complete write only."""

        if during == "flush":
            raise OSError("inert flush failure")

        sink.flush()

    output.write.side_effect = Write
    output.flush.side_effect = Flush
    status = commands.RunIntelSetCommands(
        Arguments("preview-set", model, finding, imported), output)
    assert status == (130 if during == "interrupt" else 4) and output.write.call_count == 1, (
        "Terminal failure retried output or reported a false successful operation"
    )
    assert output.flush.call_count == (1 if during == "flush" else 0), (
        "Incomplete or interrupted writes must not proceed to flush"
    )


@pytest.mark.parametrize("action", ["preview-set", "apply-set"])
@pytest.mark.parametrize("fault", [ValueError, KeyboardInterrupt])
def test_LateTerminalStagingFailurePreservesActualSaveTruthWithoutData(
    tmp_path, monkeypatch, action, fault,
):
    """The final renderer cannot leak a staged set after an interrupt or other late refusal."""

    model, finding, imported, _ = Owned(tmp_path)
    revision = model.Open().revision
    render = commands.SetRender
    calls = []

    def Render(outcome, machine):
        """Fail the final render only, after the exact successful result's pre-save bound check."""

        calls.append(outcome["status"])

        if len(calls) == 2:
            raise fault("inert late terminal fault")

        return render(outcome, machine)

    monkeypatch.setattr(commands, "SetRender", Render)
    status, refused = Run(Arguments(action, model, finding, imported))
    assert status == (130 if fault is KeyboardInterrupt else 4) and (
        refused["status"] == "failed" and "preview" not in refused and "selections" not in refused
    ), "Late terminal staging failure emitted a successful or partial set"
    assert refused["model_commit"] == ("confirmed" if action == "apply-set" else "not-attempted"), (
        "A presentation failure erased the actual independent CAS acknowledgement"
    )
    assert model.Open().revision == revision + (1 if action == "apply-set" else 0), (
        "Late presentation failure retried or rolled back the actual single model operation"
    )


def test_SetCountAndOutputBudgetsKeepTheirRealFiniteBoundaries(tmp_path, monkeypatch):
    """The exact source-count ceiling is admitted and full-output overflow never saves."""

    values = [[f"sha256:{index:064x}", f"sha256:{index + 16:064x}"] for index in range(16)]
    assert commands.SetSelections(values) == tuple(tuple(pair) for pair in values), (
        "The profile's exact existing-SDK source-count ceiling was silently lowered"
    )

    with pytest.raises(commands.IntelFailure):
        commands.SetSelections([values[0], ["sha256:" + "0" * 64]])

    model, finding, imported, _ = Owned(tmp_path)
    before = Files(model.root)
    monkeypatch.setattr(commands, "MAX_SET_OUTPUT_BYTES", 1)
    status, refused = Run(Arguments("apply-set", model, finding, imported))
    assert status == 4 and refused["model_commit"] == "not-attempted" and (
        "preview" not in refused and Files(model.root) == before
    ), "Whole terminal response overflow crossed the irreversible save boundary"


def test_StaleRevisionAndEarlierKnowledgeTimeRefuseBeforeSaving(tmp_path):
    """The same explicit concurrency and source chronology rules apply to the whole source set."""

    model, finding, imported, _ = Owned(tmp_path)
    arguments = Arguments("apply-set", model, finding, imported)
    before = Files(model.root)
    arguments[arguments.index("--expected-revision") + 1] = str(model.Open().revision + 1)
    status, refused = Run(arguments)
    assert status == 4 and refused["failure"] == "revision-conflict", (
        "The combined operation ignored its explicit saved revision"
    )
    arguments = Arguments("apply-set", model, finding, imported)
    arguments[arguments.index("--as-of") + 1] = "2026-10-12T00:00:00Z"
    status, refused = Run(arguments)
    assert status == 4 and refused["model_commit"] == "not-attempted" and (
        "preview" not in refused and Files(model.root) == before
    ), "Historical enrichment used source knowledge acquired after its explicit as-of time"


def Identifiers(arguments, identifiers):
    """Replace only explicit identifier selections while preserving every original source pin."""

    result = []
    cursor = 0

    while cursor < len(arguments):
        if arguments[cursor] == "--identifier":
            cursor += 2

        else:
            result.append(arguments[cursor])
            cursor += 1

    for identifier in identifiers:
        result += ["--identifier", identifier]

    return result


def test_RequestedIdentifierCeilingIsSeparateFromMatchedSourceAssertionCount(tmp_path, monkeypatch):
    """Sixty-four requested IDs pass with four facts; sixty-five requests fail before I/O."""

    model, finding, imported, _ = Owned(tmp_path)
    identifiers = ["CVE-1900-9999", "CWE-89"] + [
        "CVE-1900-" + str(index + 2000) for index in range(62)]
    arguments = Identifiers(Arguments("preview-set", model, finding, imported), identifiers)
    status, accepted = Run(arguments)
    assert status == 0 and len(accepted["preview"]["observations"][0]["attributes"][
        "source_assertions"]) == 4, (
        "The exact requested-ID ceiling must not be confused with one match per identifier"
    )
    assert len(accepted["preview"]["observations"][0]["attributes"][
        "unmatched_identifiers"]) == 62, "Unmatched requested identifiers were silently dropped"

    def Denied(*arguments, **keywords):
        """Tripwire any original preflight after the requested-identifier count has overflowed."""

        raise AssertionError("An excessive identifier selection reached storage")

    monkeypatch.setattr(commands, "PreflightSet", Denied)
    status, refused = Run([*arguments, "--identifier", "CVE-1900-9000"])
    assert status == 2 and "preview" not in refused and "selections" not in refused, (
        "Sixty-five requested identifiers reached storage or produced a partial set"
    )


@pytest.mark.parametrize("matched", [64, 65])
def test_MatchedAssertionsAndExistingModelByteLimitAreIndependentWholeSetBounds(
    tmp_path, monkeypatch, matched,
):
    """Count source assertions separately and preserve the existing model attribute byte bound."""

    model, finding = Context(tmp_path)
    imported = []

    for index, count in enumerate((32, matched - 32)):
        raw = (b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" '
            b'Version="synthetic-1" Date="2026-10-12"><Weaknesses>' + b"".join(
                f'<Weakness ID="{item}" Name="Owned fixture" Status="Stable"/>'.encode()
                for item in range(1, count + 1)) + b"</Weaknesses></Weakness_Catalog>")
        path = tmp_path / (str(index) + ".xml")
        path.write_bytes(raw)
        arguments = ImportArguments(model.root, path, IntelligenceFeed.CWE)
        arguments[arguments.index("--publisher") + 1] = ("Owned synthetic boundary " * 5).strip()
        licenseIndex = arguments.index("--license-name") + 1
        arguments[licenseIndex] = ("Synthetic fixture license " * 5).strip()
        status, result = Run(arguments)
        assert status == 0, "The genuine model-boundary source acquisition must precede selection"
        imported.append(result)

    arguments = Identifiers(Arguments("apply-set", model, finding, imported),
                            ["CWE-" + str(index) for index in range(1, max(32, matched - 32) + 1)])
    owner = commands.ApplyVerifiedEnrichment
    failures = []

    def Verify(*arguments, **keywords):
        """Observe the unchanged SDK refusal without substituting its original checks or limits."""

        try:
            return owner(*arguments, **keywords)

        except ValueError as error:
            failures.append(str(error))

            raise

    monkeypatch.setattr(commands, "ApplyVerifiedEnrichment", Verify)
    before = Files(model.root)
    status, refused = Run(arguments)
    assert status == 4 and refused["model_commit"] == "not-attempted" and (
        "preview" not in refused and "selections" not in refused and Files(model.root) == before
    ), "An excessive complete assertion set was truncated or partially saved"
    assert len(failures) == 1, "The full set must reach the unchanged combined SDK exactly once"

    if matched == 65:
        assert "selected intelligence exceeds its observation record bound" in failures[0], (
            "The sixty-four matched-assertion ceiling was incorrectly applied separately per source"
        )

    else:
        # Required original fields alone establish a lower bound, excluding freshness and review.
        required = []

        for item in imported:
            snapshot, _, _ = commands.VerifiedIntelSelection(
                model.root, item["snapshot_id"], item["receipt_id"])

            for record in snapshot.records:
                required.append({"snapshot_reference": snapshot.Reference(),
                    "record_reference": record.Reference(), "record": record.ToDict(),
                    "source": snapshot.source.ToDict(), "canonical_url": record.CanonicalUrl(),
                    "evidence": JsonValue(snapshot.evidence)})

        assert len(required) == 64 and len(CanonicalModelJson(required)) > MAX_ATTRIBUTE_BYTES, (
            "The actual complete original facts must independently exceed the unchanged model limit"
        )
        assert "attributes" in failures[0], (
            "A count-admitted set must still honor the existing smaller model attribute byte budget"
        )


def test_FinalReceiptBodyMismatchAfterAllEarlierReadsNeverPublishesAValidPrefix(
    tmp_path, monkeypatch,
):
    """A hash-bound final receipt with a mismatched original join refuses atomically."""

    model, finding, imported, _ = Owned(tmp_path)
    store = LocalEvidenceStore(model.root / "evidence")
    last = store.Get(imported[-1]["receipt_id"])
    body = json.loads(store.Read(last.reference))
    first = store.Get(imported[0]["receipt_id"])
    body["snapshot_reference"] = json.loads(store.Read(first.reference))["snapshot_reference"]
    substituted = store.Put(CanonicalModelJson(body), "intelligence-acquisition",
                            "application/json", last.provenance)
    selected = [dict(item) for item in imported]
    selected[-1]["receipt_id"] = substituted.evidence_id
    before = Files(model.root)
    verify = commands.VerifiedIntelSelection
    calls = []

    def Verify(root, snapshotId, receiptId):
        """Retain the genuine verifier and observe that the final join is actually reached."""

        calls.append((snapshotId, receiptId))

        return verify(root, snapshotId, receiptId)

    def Denied(*arguments, **keywords):
        """Fail if an unverified final pair crosses into proposal or save."""

        raise AssertionError("A bad final receipt reached the combined SDK or save boundary")

    monkeypatch.setattr(commands, "VerifiedIntelSelection", Verify)
    monkeypatch.setattr(commands, "ApplyVerifiedEnrichment", Denied)
    monkeypatch.setattr(LocalModelStore, "Save", Denied)
    status, refused = Run(Arguments("apply-set", model, finding, selected))
    assert len(calls) == 4 and calls[-1][1] == substituted.evidence_id, (
        "The final original receipt join must be exercised after genuine successful earlier reads"
    )
    assert status == 4 and refused["model_commit"] == "not-attempted" and all(
        key not in refused for key in ("preview", "selections")
    ) and Files(model.root) == before, "A bad final receipt leaked or saved its valid prefix"


def test_ConcurrentTriageAfterProposalCausesOneRealCasConflictAndPreservesTheWinner(
    tmp_path, monkeypatch,
):
    """Resolve a post-proposal race with the model CAS while preserving concurrent triage."""

    model, finding, imported, _ = Owned(tmp_path)
    owner = commands.ApplyVerifiedEnrichment
    save = LocalModelStore.Save
    winner = []

    def Propose(*arguments, **keywords):
        """Create the genuine proposal, then commit an independent actual operator disposition."""

        result = owner(*arguments, **keywords)
        state = model.Open()
        actualFinding = Finding.FromObject(state.Objects(ObjectKind.FINDING)[0])
        changed, delta = TransitionFinding(state, finding, FindingStatus.DISMISSED,
            replace(actualFinding.provenance[0], source_id="operator", run_reference="run:race"),
            "Independent actual concurrent triage")
        winner.append(save(model, changed, expected_revision=delta.previous_revision))

        return result

    monkeypatch.setattr(commands, "ApplyVerifiedEnrichment", Propose)
    status, refused = Run(Arguments("apply-set", model, finding, imported))
    assert status == 4 and refused["failure"] == "revision-conflict" and (
        refused["model_commit"] == "not-committed" and refused["model_revision"] is None
        and "preview" not in refused and "selections" not in refused
    ), "The actual post-proposal CAS race overwrote triage or emitted the rejected candidate"
    assert model.Open() == winner[0] and not any(
        item.kind == "finding-intelligence" for item in model.Open().observations
    ), "Combined enrichment changed the independent winner or saved part of its rejected set"
