# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise local CWE custody through actual owning stores and original-source replay."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceError, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_acquisition import LoadAcquiredSnapshot
from fuzzy1337.intelligence_cwe_acquisition import (
    ENVELOPE_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    AcquireLocalCweSelection,
    CweAcknowledgement,
    CweAcquiredSelection,
    CweAcquisitionState,
    CweLocalRequest,
    CweLocalSource,
    LoadAcquiredCweSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = "CWE-79"
MISSING = "CWE-999"
def Request(payload: bytes | None = None) -> CweLocalRequest:
    """Construct an independently owned finite ZIP fixture with explicit local-byte identity."""

    from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry

    if payload is None:
        payload = Archive(Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses>"))

    source = CweLocalSource("5.0", hashlib.sha256(payload).hexdigest())

    return CweLocalRequest(source, payload, (FIRST, MISSING))


def Workspace(tmp_path: Path, name: str = "owned") -> Path:
    """Create an actual owning workspace without canonical model state or target actions."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned CWE integration"), name)

    return root


def Imported(tmp_path):
    """Publish one complete actual local source and return its acknowledged custody handles."""

    root = Workspace(tmp_path)
    outcome = AcquireLocalCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweAcquisitionState.SUCCEEDED, "Owned local acquisition failed"
    assert outcome.raw and outcome.selection_record and outcome.receipt and outcome.envelope, (
        "Successful acquisition omitted required exact custody handles"
    )

    return root, outcome


def Files(root):
    """Hash the original workspace files to detect read-only consumer mutations."""

    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_ActualLocalSdkPublishesOriginalZipSelectionReceiptAndReopensWithoutWrites(tmp_path):
    """All product SDK boundaries use owning stores, exact original bytes and a separate family."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    before = Files(root)
    reopened = LoadAcquiredCweSelection(
        root, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Original-source replay changed the selected envelope"
    assert Files(root) == before, "Read-only inspection mutated the owning workspace"
    assert store.Read(outcome.raw.reference) == Request().payload, "Original ZIP bytes changed"
    assert reopened.selection.records[0].name == "Owned name", "Source name changed"
    assert reopened.selection.unmatched_ids == (MISSING,), "Missing ID acquired a zero score"
    assert outcome.raw_ack is outcome.selection_ack is outcome.receipt_ack is (
        CweAcknowledgement.CONFIRMED
    ), "Complete custody did not acknowledge all original publications"
    assert json.loads(store.Read(outcome.receipt.reference)) == outcome.ReceiptContent(), (
        "Stored terminal receipt disagrees with observed acquisition facts"
    )
    assert not (root / "state/model").exists(), "Local import created canonical model state"

    with pytest.raises(ValueError):
        LoadAcquiredSnapshot(root, outcome.selection_record.evidence_id)


def test_OriginalCustodySurvivesRelocationWithoutOriginalInputOrMutableSourceFile(tmp_path):
    """Only retained original evidence is needed; no absolute source path becomes authority."""

    root, outcome = Imported(tmp_path)
    relocated = tmp_path / "relocated"
    shutil.move(root, relocated)
    reopened = LoadAcquiredCweSelection(
        relocated, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Relocation lost original source custody"


@pytest.mark.parametrize("failure", ["digest", "ZIP", "overflow"])
def test_LocalFailureRetainsHonestOriginalReceiptAndNoUsableSelection(tmp_path, failure):
    """Complete digest/parse refusal differs from a bounded partial original prefix."""

    root = Workspace(tmp_path)
    request = Request()

    if failure == "digest":
        request = replace(request, source=replace(request.source, expected_sha256="0" * 64))
        expected = CweAcquisitionState.DIGEST_MISMATCH

    elif failure == "ZIP":
        request = Request(b"not ZIP")
        expected = CweAcquisitionState.PARSE_FAILED

    else:
        request = replace(request, max_bytes=len(request.payload) - 1)
        expected = CweAcquisitionState.SIZE_EXCEEDED

    outcome = AcquireLocalCweSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is expected and outcome.envelope is None, "Failure became usable success"
    assert outcome.raw and outcome.receipt and outcome.selection_record is None, (
        "Failure lost original raw custody or fabricated selected content"
    )
    assert outcome.selection_ack is CweAcknowledgement.NOT_ATTEMPTED, (
        "Failed decode saved selection"
    )
    assert outcome.body_complete is (failure != "overflow"), "Partial source became complete"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(outcome.raw.reference) == request.payload[:request.max_bytes], (
        "Failure changed retained original bytes"
    )
    expectedRole = RAW_ROLE if outcome.body_complete else "cwe-local-zip-partial"
    assert outcome.raw.reference.role == expectedRole, (
        "Partial raw evidence adopted complete-source role"
    )


@pytest.mark.parametrize("stage", [1, 2, 3])
@pytest.mark.parametrize("lost_ack", [False, True])
def test_EachPublicationFailureReportsUnknownWithoutAssumingRollback(
    tmp_path, monkeypatch, stage, lost_ack,
):
    """A write may publish then lose acknowledgement; earlier confirmed handles remain factual."""

    root = Workspace(tmp_path)
    original = LocalEvidenceStore.Put
    calls = []

    def Put(store, *args, **kwargs):
        """Inject actual storage refusal before or after original committed publication."""

        number = len(calls) + 1
        calls.append(None)

        if number == stage and not lost_ack:
            raise EvidenceStorageError("Owned synthetic before-commit refusal")

        record = original(store, *args, **kwargs)
        calls[-1] = record

        if number == stage:
            raise EvidenceStorageError("Owned synthetic commit-then-lost-ack refusal")

        return record

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    outcome = AcquireLocalCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweAcquisitionState.STORAGE_FAILED and outcome.envelope is None, (
        "Unacknowledged publication became successful acquisition"
    )
    acknowledgements = [outcome.raw_ack, outcome.selection_ack, outcome.receipt_ack]
    assert acknowledgements[stage - 1] is CweAcknowledgement.UNKNOWN, "Lost ack became confirmed"
    assert all(value is CweAcknowledgement.CONFIRMED for value in acknowledgements[:stage - 1]), (
        "Confirmed earlier publications were incorrectly rolled back"
    )
    assert all(value is CweAcknowledgement.NOT_ATTEMPTED for value in acknowledgements[stage:]), (
        "Publication continued after uncertain storage failure"
    )

    if stage == 3 and lost_ack:
        reopened = LoadAcquiredCweSelection(root, calls[1].evidence_id, calls[2].evidence_id)
        assert reopened.selection.unmatched_ids == (MISSING,), (
            "Physically committed successful receipt could not recover exact durable custody"
        )


@pytest.mark.parametrize("key,value", [
    ("body_complete", False), ("received_bytes", 1), ("transport", "https"),
    ("http_status", 200), ("state", "parse-failed"), ("raw_ack", "unknown"),
    ("requested_ids", [FIRST]), ("schema_version", True), ("profile_version", 2),
    ("publisher_authentication", "verified"), ("unexpected", True),
])
def test_RehashedReceiptTamperingRefusesBeforeOriginalRawReads(tmp_path, monkeypatch, key, value):
    """A public content hash is not permission to alter original selected acquisition facts."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    document = outcome.ReceiptContent()
    document[key] = value
    forged = store.Put(CanonicalReferenceJson(document), RECEIPT_ROLE, "application/json",
                        outcome.receipt.provenance)
    original = LocalEvidenceStore.Get
    visited = []

    def Get(store, evidence_id):
        """Observe original-source admission while retaining the real owning store path."""

        visited.append(evidence_id)

        return original(store, evidence_id)

    monkeypatch.setattr(LocalEvidenceStore, "Get", Get)

    with pytest.raises(ValueError):
        LoadAcquiredCweSelection(root, outcome.selection_record.evidence_id, forged.evidence_id)

    assert outcome.raw.evidence_id not in visited, "Invalid receipt reached original raw admission"


def test_RehashedSelectionAndReceiptStillRequireActualOriginalZipAgreement(tmp_path):
    """Coordinated valid-looking selected artifacts cannot replace original source assertions."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    record = replace(outcome.envelope.selection.records[0], name="Other name")
    selected = replace(outcome.envelope.selection, records=(record,))
    envelope = CweAcquiredSelection(outcome.envelope.source, outcome.raw, selected,
                                    outcome.max_bytes)
    forgedSelection = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                                 outcome.selection_record.provenance)
    changed = replace(outcome, envelope=envelope, selection_record=forgedSelection)
    receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError, match="original ZIP"):
        LoadAcquiredCweSelection(root, forgedSelection.evidence_id, receipt.evidence_id)


def test_SameWorkspaceAcquisitionSpliceRefusesBeforeOriginalRawAdmission(tmp_path, monkeypatch):
    """Valid source bytes and rehashed wrappers cannot exchange original acquisition attribution."""

    root, first = Imported(tmp_path)
    second = AcquireLocalCweSelection(root, Request(), scope_reference="scope:other-acquisition")
    assert second.state is CweAcquisitionState.SUCCEEDED and second.raw and second.receipt, (
        "Second independent acquisition did not produce valid owning custody"
    )
    assert first.raw.provenance.workspace_id == second.raw.provenance.workspace_id, (
        "Counterexample must stay inside the same owning workspace"
    )
    assert first.raw.evidence_id != second.raw.evidence_id, (
        "Distinct acquisition attribution unexpectedly reused an original manifest identity"
    )
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(first.raw.reference) == store.Read(second.raw.reference), (
        "Counterexample must preserve identical valid original source bytes"
    )
    assert LoadAcquiredCweSelection(root, second.selection_record.evidence_id,
        second.receipt.evidence_id) == second.envelope, "Second original acquisition is not valid"

    wrapper = store.Put(first.envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                        second.raw.provenance)
    spliced = replace(second, source=first.source, requested_ids=first.requested_ids,
        received_bytes=first.received_bytes, raw=first.raw, envelope=first.envelope,
        selection_record=wrapper)
    terminal = store.Put(CanonicalReferenceJson(spliced.ReceiptContent()), RECEIPT_ROLE,
                         "application/json", second.raw.provenance)
    assert json.loads(store.Read(wrapper.reference)) == json.loads(first.envelope.Serialize()), (
        "Spliced wrapper must retain the complete original valid source and decoder content"
    )
    assert json.loads(store.Read(terminal.reference)) == spliced.ReceiptContent(), (
        "Spliced receipt must be fully rehashed and internally consistent, not stale evidence"
    )
    original = LocalEvidenceStore.Get
    visited = []

    def Get(store, evidence_id):
        """Observe original-manifest admission through the actual owning store implementation."""

        visited.append(evidence_id)

        return original(store, evidence_id)

    monkeypatch.setattr(LocalEvidenceStore, "Get", Get)

    with pytest.raises(ValueError, match="original raw facts disagree"):
        LoadAcquiredCweSelection(root, wrapper.evidence_id, terminal.evidence_id)

    assert visited == [wrapper.evidence_id, terminal.evidence_id], (
        "Mixed acquisition attribution reached original raw manifest admission"
    )
    assert first.raw.evidence_id not in visited, "Spliced raw acquisition was read before refusal"


def test_ForeignWorkspaceCannotAdoptCopiedOriginalManifests(tmp_path):
    """Identical raw bytes and full copied manifests do not establish another owner's custody."""

    root, outcome = Imported(tmp_path)
    foreign = Workspace(tmp_path, "foreign")
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)

    with pytest.raises(ValueError, match="owning"):
        LoadAcquiredCweSelection(foreign, outcome.selection_record.evidence_id,
                                  outcome.receipt.evidence_id)


@pytest.mark.parametrize("artifact", ["raw", "selection_record", "receipt"])
@pytest.mark.parametrize("mutation", ["missing", "corrupt"])
def test_MissingOrCorruptActualArtifactsCannotBecomeReplayableSuccess(tmp_path, artifact, mutation):
    """Every original selected content hash is checked through the actual filesystem owner."""

    root, outcome = Imported(tmp_path)
    record = getattr(outcome, artifact)
    path = root / "evidence" / record.reference.locator

    if mutation == "missing":
        path.unlink()

    else:
        path.write_bytes(b"owned corruption")

    with pytest.raises((EvidenceError, ValueError)):
        LoadAcquiredCweSelection(root, outcome.selection_record.evidence_id,
                                  outcome.receipt.evidence_id)


@pytest.mark.parametrize("role,limit", [(ENVELOPE_ROLE, 2 * 1024 * 1024),
                                       (RECEIPT_ROLE, 64 * 1024)])
def test_ActualOwningGetCannotLoadOverLimitRehashedArtifactContent(
    tmp_path, monkeypatch, role, limit,
):
    """Owning Get's implicit content verification must remain inside selected role byte ceilings."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    malicious = store.Put(b"x" * (limit + 1), role, "application/json", outcome.raw.provenance)
    original = LocalEvidenceStore.Read
    reads = []

    def Read(store, reference):
        """Observe the actual base content reader rather than only a wrapper sentinel."""

        reads.append(reference.sha256)

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    selectionId = malicious.evidence_id if role == ENVELOPE_ROLE else (
        outcome.selection_record.evidence_id
    )
    receiptId = malicious.evidence_id if role == RECEIPT_ROLE else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadAcquiredCweSelection(root, selectionId, receiptId)

    assert malicious.reference.sha256 not in reads, "Owning Get loaded oversized artifact bytes"


@pytest.mark.parametrize("selected_root", [True, False])
def test_WrongRoleRootCannotSelectItsOwnMorePermissiveContentBudget(
    tmp_path, monkeypatch, selected_root,
):
    """Artifact roles are caller-expected domains before owning Get's implicit content read."""

    root, outcome = Imported(tmp_path)
    original = LocalEvidenceStore.Read
    reads = []

    def Read(store, reference):
        """Observe whether a wrong-role root ever reaches actual blob verification."""

        reads.append(reference.sha256)

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    selectionId = outcome.raw.evidence_id if selected_root else (
        outcome.selection_record.evidence_id
    )
    receiptId = outcome.receipt.evidence_id if selected_root else outcome.raw.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadAcquiredCweSelection(root, selectionId, receiptId)

    assert outcome.raw.reference.sha256 not in reads, "Wrong-role root selected its own byte budget"


@pytest.mark.parametrize("field,value", [("requested_ids", [FIRST]),
    ("state", "succeeded"), ("raw_ack", "confirmed"), ("receipt_ack", None),
    ("body_complete", 1), ("received_bytes", True), ("received_bytes", -1),
    ("received_bytes", 4 * 1024 * 1024 + 1), ("started_at", "2026-11-02"),
    ("finished_at", "2020-11-02T00:00:00.000000+00:00"),
    ("raw", {}), ("selection_record", {}), ("receipt", {}), ("envelope", {})])
def test_OutcomeConstructorsCannotAdoptMutableOrUntypedExecutionFacts(tmp_path, field, value):
    """Frozen SDK outputs reject aliases and malformed direct replacement without implying proof."""

    _, outcome = Imported(tmp_path)

    with pytest.raises(ValueError):
        replace(outcome, **{field: value})


def test_ValidLargeWorkspaceAttributionKeepsConfirmedHandlesWhenReceiptCannotFit(tmp_path):
    """Finite profile receipts cannot erase earlier publication facts for valid large owners."""

    root = tmp_path / "large-owner"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Large valid CWE owner"), "a" * 40000)
    outcome = AcquireLocalCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweAcquisitionState.STORAGE_FAILED and outcome.envelope is None, (
        "Oversized receipt escaped without an honest failure or retained a usable success envelope"
    )
    assert outcome.raw is not None and outcome.selection_record is not None, (
        "Receipt ceiling erased confirmed original or selected publication handles"
    )
    assert outcome.raw_ack is CweAcknowledgement.CONFIRMED and (
        outcome.selection_ack is CweAcknowledgement.CONFIRMED
        and outcome.receipt_ack is CweAcknowledgement.NOT_ATTEMPTED
        and outcome.receipt is None
    ), "Receipt allocation failure fabricated rollback, publication or acknowledgement"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Get(outcome.raw.evidence_id) == outcome.raw and (
        store.Get(outcome.selection_record.evidence_id) == outcome.selection_record
    ), "Receipt refusal made earlier immutable publications inaccessible"


@pytest.mark.parametrize("version,kind", [("5.0", "Grouping"), ("4.21", "Category")])
def test_ZeroWeaknessMixedUnsupportedAndAbsentPartitionsReopenExactly(tmp_path, version, kind):
    """Actual replay preserves unsupported identities and unmatched IDs as separate source facts."""

    from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry

    container = "Groupings" if kind == "Grouping" else "Categories"
    xml = Catalog(f"<{container}>".encode() + Entry("79", kind=kind)
                  + f"</{container}>".encode(), version)
    payload = Archive(xml, version)
    request = CweLocalRequest(CweLocalSource(version, hashlib.sha256(payload).hexdigest()),
                              payload, ("CWE-79", "CWE-999"))
    root = Workspace(tmp_path)
    outcome = AcquireLocalCweSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is CweAcquisitionState.SUCCEEDED, "CWE custody invariant changed"
    selected = LoadAcquiredCweSelection(root, outcome.selection_record.evidence_id,
                                        outcome.receipt.evidence_id).selection
    assert selected.records == () and selected.unmatched_ids == ("CWE-999",), (
        "Unsupported or absent source identities acquired fabricated Weaknesses"
    )
    assert tuple((item.identifier, item.source_kind) for item in selected.unsupported_entries) == (
        ("CWE-79", kind),), "CWE custody invariant changed"
