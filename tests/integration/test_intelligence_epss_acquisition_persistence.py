# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise local EPSS custody through actual owning stores and original-source replay."""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import intelligence_epss_acquisition as acquisition
from fuzzy1337.evidence import EvidenceError, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson, SourceOrigin
from fuzzy1337.intelligence_acquisition import LoadAcquiredSnapshot
from fuzzy1337.intelligence_epss_acquisition import (
    ENVELOPE_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    AcquireLocalEpssSelection,
    EpssAcknowledgement,
    EpssAcquiredSelection,
    EpssAcquisitionState,
    EpssLocalRequest,
    EpssLocalSource,
    LoadAcquiredEpssSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = "CVE-1900-0001"
MISSING = "CVE-1900-9999"
RAW_CSV = (b"#model_version:synthetic-model,score_date:2026-11-02T12:00:30Z\n"
           b"cve,epss,percentile\nCVE-1900-0001,0.0006,6e-05\n")


def Request(payload: bytes | None = None) -> EpssLocalRequest:
    """Construct explicit synthetic local bytes and metadata, never a network selection."""

    source = EpssLocalSource(SourceOrigin.SYNTHETIC, "Owned EPSS source",
        "https://example.invalid/source.csv.gz", "Apache-2.0 synthetic fixture only",
        "https://example.invalid/LICENSE", ("https://example.invalid/terms",),
        "synthetic-model", "2026-11-02")

    return EpssLocalRequest(source, gzip.compress(RAW_CSV, mtime=0) if payload is None else payload,
                            (FIRST, MISSING))


def Workspace(tmp_path: Path, name: str = "owned") -> Path:
    """Create an actual owning workspace without canonical model state or target actions."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned EPSS integration"), name)

    return root


def Imported(tmp_path):
    """Publish one complete actual local source and return its acknowledged custody handles."""

    root = Workspace(tmp_path)
    outcome = AcquireLocalEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is EpssAcquisitionState.SUCCEEDED, "Owned local acquisition failed"
    assert outcome.raw and outcome.selection_record and outcome.receipt and outcome.envelope, (
        "Successful acquisition omitted required exact custody handles"
    )

    return root, outcome


def Files(root):
    """Hash the original workspace files to detect read-only consumer mutations."""

    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_ActualLocalSdkPublishesOriginalGzipSelectionReceiptAndReopensWithoutWrites(tmp_path):
    """All product SDK boundaries use owning stores, exact original bytes and a separate family."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    before = Files(root)
    reopened = LoadAcquiredEpssSelection(
        root, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Original-source replay changed the selected envelope"
    assert Files(root) == before, "Read-only inspection mutated the owning workspace"
    assert store.Read(outcome.raw.reference) == Request().payload, "Original gzip bytes changed"
    assert reopened.selection.records[0].percentile == "6e-05", "Scientific assertion changed"
    assert reopened.selection.unmatched_ids == (MISSING,), "Missing ID acquired a zero score"
    assert outcome.raw_ack is outcome.selection_ack is outcome.receipt_ack is (
        EpssAcknowledgement.CONFIRMED
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
    reopened = LoadAcquiredEpssSelection(
        relocated, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Relocation lost original source custody"


@pytest.mark.parametrize("failure", ["digest", "gzip", "overflow"])
def test_LocalFailureRetainsHonestOriginalReceiptAndNoUsableSelection(tmp_path, failure):
    """Complete digest/parse refusal differs from a bounded partial original prefix."""

    root = Workspace(tmp_path)
    request = Request()

    if failure == "digest":
        request = replace(request, source=replace(request.source, expected_sha256="0" * 64))
        expected = EpssAcquisitionState.DIGEST_MISMATCH

    elif failure == "gzip":
        request = Request(b"not gzip")
        expected = EpssAcquisitionState.PARSE_FAILED

    else:
        request = replace(request, max_bytes=len(request.payload) - 1)
        expected = EpssAcquisitionState.SIZE_EXCEEDED

    outcome = AcquireLocalEpssSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is expected and outcome.envelope is None, "Failure became usable success"
    assert outcome.raw and outcome.receipt and outcome.selection_record is None, (
        "Failure lost original raw custody or fabricated selected content"
    )
    assert outcome.selection_ack is EpssAcknowledgement.NOT_ATTEMPTED, (
        "Failed decode saved selection"
    )
    assert outcome.body_complete is (failure != "overflow"), "Partial source became complete"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(outcome.raw.reference) == request.payload[:request.max_bytes], (
        "Failure changed retained original bytes"
    )
    expected_role = RAW_ROLE if outcome.body_complete else "epss-gzip-partial"
    assert outcome.raw.reference.role == expected_role, (
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
    outcome = AcquireLocalEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is EpssAcquisitionState.STORAGE_FAILED and outcome.envelope is None, (
        "Unacknowledged publication became successful acquisition"
    )
    acknowledgements = [outcome.raw_ack, outcome.selection_ack, outcome.receipt_ack]
    assert acknowledgements[stage - 1] is EpssAcknowledgement.UNKNOWN, "Lost ack became confirmed"
    assert all(value is EpssAcknowledgement.CONFIRMED for value in acknowledgements[:stage - 1]), (
        "Confirmed earlier publications were incorrectly rolled back"
    )
    assert all(value is EpssAcknowledgement.NOT_ATTEMPTED for value in acknowledgements[stage:]), (
        "Publication continued after uncertain storage failure"
    )

    if stage == 3 and lost_ack:
        reopened = LoadAcquiredEpssSelection(root, calls[1].evidence_id, calls[2].evidence_id)
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
        LoadAcquiredEpssSelection(root, outcome.selection_record.evidence_id, forged.evidence_id)

    assert outcome.raw.evidence_id not in visited, "Invalid receipt reached original raw admission"


def test_RehashedSelectionAndReceiptStillRequireActualOriginalGzipAgreement(tmp_path):
    """Coordinated valid-looking selected artifacts cannot replace original source assertions."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    record = replace(outcome.envelope.selection.records[0], probability="0.9")
    selected = replace(outcome.envelope.selection, records=(record,))
    envelope = EpssAcquiredSelection(outcome.envelope.source, outcome.raw, selected)
    forged_selection = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                                 outcome.selection_record.provenance)
    changed = replace(outcome, envelope=envelope, selection_record=forged_selection)
    receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError, match="original gzip"):
        LoadAcquiredEpssSelection(root, forged_selection.evidence_id, receipt.evidence_id)


def test_ForeignWorkspaceCannotAdoptCopiedOriginalManifests(tmp_path):
    """Identical raw bytes and full copied manifests do not establish another owner's custody."""

    root, outcome = Imported(tmp_path)
    foreign = Workspace(tmp_path, "foreign")
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)

    with pytest.raises(ValueError, match="owning"):
        LoadAcquiredEpssSelection(foreign, outcome.selection_record.evidence_id,
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
        LoadAcquiredEpssSelection(root, outcome.selection_record.evidence_id,
                                  outcome.receipt.evidence_id)


@pytest.mark.parametrize("role,limit", [(ENVELOPE_ROLE, 128 * 1024),
                                       (RECEIPT_ROLE, 32 * 1024)])
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
    selection_id = malicious.evidence_id if role == ENVELOPE_ROLE else (
        outcome.selection_record.evidence_id
    )
    receipt_id = malicious.evidence_id if role == RECEIPT_ROLE else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadAcquiredEpssSelection(root, selection_id, receipt_id)

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
    selection_id = outcome.raw.evidence_id if selected_root else (
        outcome.selection_record.evidence_id
    )
    receipt_id = outcome.receipt.evidence_id if selected_root else outcome.raw.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadAcquiredEpssSelection(root, selection_id, receipt_id)

    assert outcome.raw.reference.sha256 not in reads, "Wrong-role root selected its own byte budget"


def test_FutureSourceClockRetainsRawWithHonestParseFailedReceipt(tmp_path, monkeypatch):
    """Custody refuses future assessments while preserving original raw failure evidence."""

    clock = SimpleNamespace(now=lambda zone: datetime(2026, 11, 2, 13, tzinfo=timezone.utc))
    monkeypatch.setattr(acquisition, "datetime", clock)
    request = Request(gzip.compress(RAW_CSV.replace(b"2026-11-02", b"2030-11-02"), mtime=0))
    request = replace(request, source=replace(request.source, score_date="2030-11-02"))
    root = Workspace(tmp_path)
    outcome = AcquireLocalEpssSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is EpssAcquisitionState.PARSE_FAILED and outcome.raw and outcome.receipt, (
        "Future score time became accepted custody or lost original failure evidence"
    )
    assert outcome.selection_record is None and outcome.envelope is None, (
        "Future score time produced a usable attributed selection"
    )


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
