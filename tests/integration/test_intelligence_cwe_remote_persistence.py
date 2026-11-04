# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise remote CWE custody through actual owning stores and original-source replay."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.evidence import EvidenceError, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_acquisition import LoadAcquiredSnapshot
from fuzzy1337.intelligence_cwe_remote import (
    ENVELOPE_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    AcquireHttpsCweSelection,
    CweHttpsAcknowledgement,
    CweHttpsRequest,
    CweHttpsSelection,
    CweHttpsSource,
    CweHttpsState,
    LoadHttpsCweSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = "CWE-79"
MISSING = "CWE-999"
def Payload(version="5.0"):
    """Build an independent original ZIP with a Weakness, unsupported View and absent ID."""

    from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry

    xml = Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses><Views>"
                  + Entry("1000", kind="View") + b"</Views>", version)

    return Archive(xml, version)


def Request(payload=None, version="5.0"):
    """Select an explicit source pin without admitting supplied bytes into the public request."""

    if payload is None:
        payload = Payload(version)

    source = CweHttpsSource(version, hashlib.sha256(payload).hexdigest())

    return CweHttpsRequest(source, ("CWE-1000", FIRST, MISSING))


@pytest.fixture(autouse=True)
def owned_receiver(monkeypatch):
    """Replace only network acquisition with an explicit deterministic synthetic source seam."""

    calls = []

    def Receive(url, maximum, timeout, *, accept_kind):
        """Return owned originals while binding exactly delegated URL, budget, time and kind."""

        calls.append((url, maximum, timeout, accept_kind))
        version = "4.21" if "v4.21" in url else "5.0"
        payload = Payload(version)

        if len(payload) > maximum:
            return payload[:maximum], "size-exceeded", 200

        return payload, "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)

    return calls


def Workspace(tmp_path: Path, name: str = "owned") -> Path:
    """Create an actual owning workspace without canonical model state or target actions."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned CWE integration"), name)

    return root


def Imported(tmp_path):
    """Publish one complete actual remote source and return its acknowledged custody handles."""

    root = Workspace(tmp_path)
    outcome = AcquireHttpsCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweHttpsState.SUCCEEDED, "Owned remote acquisition failed"
    assert outcome.raw and outcome.selection_record and outcome.receipt and outcome.envelope, (
        "Successful acquisition omitted required exact custody handles"
    )

    return root, outcome


def Files(root):
    """Hash the original workspace files to detect read-only consumer mutations."""

    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_ActualRemoteSdkPublishesOriginalZipSelectionReceiptAndReopensWithoutWrites(tmp_path):
    """All product SDK boundaries use owning stores, exact original bytes and a separate family."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    before = Files(root)
    reopened = LoadHttpsCweSelection(
        root, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Original-source replay changed the selected envelope"
    assert Files(root) == before, "Read-only inspection mutated the owning workspace"
    assert store.Read(outcome.raw.reference) == Payload(), "Original ZIP bytes changed"
    assert reopened.selection.records[0].name == "Owned name", "Source name changed"
    assert reopened.selection.unmatched_ids == (MISSING,), "Missing ID acquired a zero score"
    assert outcome.raw_ack is outcome.selection_ack is outcome.receipt_ack is (
        CweHttpsAcknowledgement.CONFIRMED
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
    reopened = LoadHttpsCweSelection(
        relocated, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
    assert reopened == outcome.envelope, "Relocation lost original source custody"


@pytest.mark.parametrize("failure", ["digest", "ZIP", "overflow"])
def test_RemoteFailureRetainsHonestOriginalReceiptAndNoUsableSelection(
    tmp_path, monkeypatch, failure,
):
    """Complete digest/parse refusal differs from a bounded partial original prefix."""

    root = Workspace(tmp_path)
    request = Request()

    if failure == "digest":
        request = replace(request, source=replace(request.source, expected_sha256="0" * 64))
        expected = CweHttpsState.DIGEST_MISMATCH

    elif failure == "ZIP":
        request = Request(b"not ZIP")
        monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                            lambda *args, **kwargs: (b"not ZIP", "succeeded", 200))
        expected = CweHttpsState.PARSE_FAILED

    else:
        request = replace(request, max_bytes=len(Payload()) - 1)
        expected = CweHttpsState.SIZE_EXCEEDED

    outcome = AcquireHttpsCweSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is expected and outcome.envelope is None, "Failure became usable success"
    assert outcome.raw and outcome.receipt and outcome.selection_record is None, (
        "Failure lost original raw custody or fabricated selected content"
    )
    assert outcome.selection_ack is CweHttpsAcknowledgement.NOT_ATTEMPTED, (
        "Failed decode saved selection"
    )
    assert outcome.body_complete is (failure != "overflow"), "Partial source became complete"
    store = LocalEvidenceStore(root / "evidence")
    expectedBody = b"not ZIP" if failure == "ZIP" else Payload()[:request.max_bytes]
    assert store.Read(outcome.raw.reference) == expectedBody, (
        "Failure changed retained original bytes"
    )
    expectedRole = RAW_ROLE if outcome.body_complete else "cwe-https-zip-partial"
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
    outcome = AcquireHttpsCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        "Unacknowledged publication became successful acquisition"
    )
    acknowledgements = [outcome.raw_ack, outcome.selection_ack, outcome.receipt_ack]
    assert acknowledgements[stage - 1] is CweHttpsAcknowledgement.UNKNOWN, (
        "Lost ack became confirmed"
    )
    assert all(value is CweHttpsAcknowledgement.CONFIRMED
               for value in acknowledgements[:stage - 1]), (
        "Confirmed earlier publications were incorrectly rolled back"
    )
    assert all(value is CweHttpsAcknowledgement.NOT_ATTEMPTED
               for value in acknowledgements[stage:]), (
        "Publication continued after uncertain storage failure"
    )

    if stage == 3 and lost_ack:
        reopened = LoadHttpsCweSelection(root, calls[1].evidence_id, calls[2].evidence_id)
        assert reopened.selection.unmatched_ids == (MISSING,), (
            "Physically committed successful receipt could not recover exact durable custody"
        )


@pytest.mark.parametrize("key,value", [
    ("body_complete", False), ("received_bytes", 1), ("transport", "remote-bytes"),
    ("http_status", 201), ("state", "parse-failed"), ("raw_ack", "unknown"),
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
        LoadHttpsCweSelection(root, outcome.selection_record.evidence_id, forged.evidence_id)

    assert outcome.raw.evidence_id not in visited, "Invalid receipt reached original raw admission"


def test_RehashedSelectionAndReceiptStillRequireActualOriginalZipAgreement(tmp_path):
    """Coordinated valid-looking selected artifacts cannot replace original source assertions."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    record = replace(outcome.envelope.selection.records[0], name="Other name")
    selected = replace(outcome.envelope.selection, records=(record,))
    envelope = CweHttpsSelection(outcome.envelope.source, outcome.raw, selected,
                                    outcome.max_bytes, outcome.timeout_seconds)
    forgedSelection = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                                 outcome.selection_record.provenance)
    changed = replace(outcome, envelope=envelope, selection_record=forgedSelection)
    receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError, match="original ZIP"):
        LoadHttpsCweSelection(root, forgedSelection.evidence_id, receipt.evidence_id)


def test_SameWorkspaceAcquisitionSpliceRefusesBeforeOriginalRawAdmission(tmp_path, monkeypatch):
    """Valid source bytes and rehashed wrappers cannot exchange original acquisition attribution."""

    root, first = Imported(tmp_path)
    second = AcquireHttpsCweSelection(root, Request(), scope_reference="scope:other-acquisition")
    assert second.state is CweHttpsState.SUCCEEDED and second.raw and second.receipt, (
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
    assert LoadHttpsCweSelection(root, second.selection_record.evidence_id,
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
        LoadHttpsCweSelection(root, wrapper.evidence_id, terminal.evidence_id)

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
        LoadHttpsCweSelection(foreign, outcome.selection_record.evidence_id,
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
        LoadHttpsCweSelection(root, outcome.selection_record.evidence_id,
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
        LoadHttpsCweSelection(root, selectionId, receiptId)

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
        LoadHttpsCweSelection(root, selectionId, receiptId)

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
    outcome = AcquireHttpsCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        "Oversized receipt escaped without an honest failure or retained a usable success envelope"
    )
    assert outcome.raw is not None and outcome.selection_record is not None, (
        "Receipt ceiling erased confirmed original or selected publication handles"
    )
    assert outcome.raw_ack is CweHttpsAcknowledgement.CONFIRMED and (
        outcome.selection_ack is CweHttpsAcknowledgement.CONFIRMED
        and outcome.receipt_ack is CweHttpsAcknowledgement.NOT_ATTEMPTED
        and outcome.receipt is None
    ), "Receipt allocation failure fabricated rollback, publication or acknowledgement"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Get(outcome.raw.evidence_id) == outcome.raw and (
        store.Get(outcome.selection_record.evidence_id) == outcome.selection_record
    ), "Receipt refusal made earlier immutable publications inaccessible"


@pytest.mark.parametrize("version,kind", [("5.0", "Grouping"), ("4.21", "Category")])
def test_ZeroWeaknessMixedUnsupportedAndAbsentPartitionsReopenExactly(
    tmp_path, monkeypatch, version, kind,
):
    """Actual replay preserves unsupported identities and unmatched IDs as separate source facts."""

    from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry

    container = "Groupings" if kind == "Grouping" else "Categories"
    xml = Catalog(f"<{container}>".encode() + Entry("79", kind=kind)
                  + f"</{container}>".encode(), version)
    payload = Archive(xml, version)
    request = CweHttpsRequest(CweHttpsSource(version, hashlib.sha256(payload).hexdigest()),
                              ("CWE-79", "CWE-999"))
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (payload, "succeeded", 200))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsCweSelection(root, request, scope_reference="scope:owned")
    assert outcome.state is CweHttpsState.SUCCEEDED, "CWE custody invariant changed"
    selected = LoadHttpsCweSelection(root, outcome.selection_record.evidence_id,
                                        outcome.receipt.evidence_id).selection
    assert selected.records == () and selected.unmatched_ids == ("CWE-999",), (
        "Unsupported or absent source identities acquired fabricated Weaknesses"
    )
    assert tuple((item.identifier, item.source_kind) for item in selected.unsupported_entries) == (
        ("CWE-79", kind),), "CWE custody invariant changed"


@pytest.mark.parametrize("version", ["5.0", "4.21"])
def test_ExactlyOneFixedZipReceiveAndCompletePartitions(tmp_path, owned_receiver, version):
    """Real storage and decoder consume the one source selected by the remote typed request."""

    root = Workspace(tmp_path)
    request = replace(Request(version=version), max_bytes=len(Payload(version)), timeout_seconds=15)
    outcome = AcquireHttpsCweSelection(root, request, scope_reference="scope:owned")
    assert owned_receiver == [(request.source.SourceUrl, request.max_bytes, 15.0, "zip")], (
        "Source acquisition retried, changed the source or bypassed ZIP transport"
    )
    assert outcome.state is CweHttpsState.SUCCEEDED and outcome.body_complete, (
        "Complete source was not retained as complete"
    )
    reopened = LoadHttpsCweSelection(root, outcome.selection_record.evidence_id,
                                    outcome.receipt.evidence_id)
    assert reopened.selection.records[0].identifier == FIRST, "Selected Weakness changed"
    assert reopened.selection.unsupported_entries[0].source_kind == "View", (
        "Unsupported View became a Weakness or absent identity"
    )
    assert reopened.selection.unmatched_ids == (MISSING,), "Absent identity became zero-risk data"
    value = reopened.ToDict()
    assert value["transport_profile"] == remote.TRANSPORT_PROFILE, "ZIP gate profile was lost"
    assert value["limits"] == {"max_zip_bytes": len(Payload(version)), "timeout_seconds": 15.0}, (
        "Remote CWE custody invariant changed"
    )
    assert "content_type" not in value, "SDK invented observed literal server media telemetry"
    assert reopened.Reference().startswith("cwe-https-selection:"), "Local family was reused"
    assert reopened.selection.Reference().startswith("cwe-selection:"), "Inner contract changed"


@pytest.mark.parametrize("state,status", [
    ("redirect-rejected", 302), ("http-rejected", 500), ("format-rejected", 200),
    ("size-exceeded", 200), ("transport-failed", None), ("timed-out", 200),
])
@pytest.mark.parametrize("size", [0, 3, 10])
def test_ActualFailedTransportBytesStayPartialWithOriginalObservedStatus(
    tmp_path, monkeypatch, state, status, size,
):
    """Empty and bounded nonempty transport failures cannot become complete or clean negatives."""

    root = Workspace(tmp_path)
    payload = b"owned-body"[:size]
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (payload, state, status))
    request = replace(Request(), max_bytes=10)
    outcome = AcquireHttpsCweSelection(root, request, scope_reference="scope:owned")
    assert outcome.state.value == state and outcome.receive_state == state, "Failure was hidden"
    assert outcome.received_bytes == size and outcome.http_status == status, "Facts changed"
    assert not outcome.body_complete and outcome.envelope is outcome.selection_record is None, (
        "Remote CWE custody invariant changed"
    )
    assert outcome.selection_ack is CweHttpsAcknowledgement.NOT_ATTEMPTED, (
        "Remote CWE custody invariant changed"
    )
    store = LocalEvidenceStore(root / "evidence")
    assert outcome.raw.reference.role == remote.PARTIAL_ROLE, "Partial adopted complete role"
    assert store.Read(outcome.raw.reference) == payload, "Partial was padded or truncated"
    assert json.loads(store.Read(outcome.receipt.reference)) == outcome.ReceiptContent(), (
        "Remote CWE custody invariant changed"
    )


@pytest.mark.parametrize("result", [
    (bytearray(b"owned"), "succeeded", 200), (b"x" * 11, "succeeded", 200),
    (b"owned", "unknown", None), (b"owned", True, 200),
    (b"owned", "succeeded", None), (b"owned", "succeeded", 201),
    (b"owned", "transport-failed", True), (b"owned", "timed-out", 600),
])
def test_InvalidReceiverFactsRefuseBeforeAnyEvidencePublication(tmp_path, monkeypatch, result):
    """The family validates its shared helper contract instead of trusting forged success facts."""

    root = Workspace(tmp_path)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs: result)

    def Forbidden(*args, **kwargs):
        """Observe whether invalid transport facts ever reach original publication."""

        raise AssertionError("Invalid receiver result reached evidence publication")

    monkeypatch.setattr(LocalEvidenceStore, "Put", Forbidden)

    with pytest.raises(ValueError):
        AcquireHttpsCweSelection(root, replace(Request(), max_bytes=10),
                                scope_reference="scope:owned")


@pytest.mark.parametrize("which", ["envelope", "receipt"])
def test_SerializationRefusalDoesNotBecomeUnknownPublication(tmp_path, monkeypatch, which):
    """A bounded serializer must finish before the corresponding Put is considered attempted."""

    root = Workspace(tmp_path)
    monkeypatch.setattr(remote, "MAX_ENVELOPE_BYTES" if which == "envelope" else
                        "MAX_RECEIPT_BYTES", 1)
    outcome = AcquireHttpsCweSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CweHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        "Remote CWE custody invariant changed"
    )
    assert outcome.raw is not None and outcome.raw_ack is CweHttpsAcknowledgement.CONFIRMED, (
        "Remote CWE custody invariant changed"
    )
    assert outcome.receipt_ack is CweHttpsAcknowledgement.NOT_ATTEMPTED, (
        "Remote CWE custody invariant changed"
    )
    expected = CweHttpsAcknowledgement.NOT_ATTEMPTED if which == "envelope" else (
        CweHttpsAcknowledgement.CONFIRMED
    )
    assert outcome.selection_ack is expected, "Serialization refusal fabricated uncertain Put"


@pytest.mark.parametrize("mutation", ["integer-timeout", "changed-timeout", "changed-max"])
@pytest.mark.parametrize("artifact", ["envelope", "receipt"])
def test_ValidButChangedLimitsAndNoncanonicalTimeoutRefuseBeforeRawRead(
    tmp_path, monkeypatch, mutation, artifact,
):
    """Canonical byte comparisons catch int/float aliases and independently changed valid limits."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    document = json.loads(outcome.envelope.Serialize()) if artifact == "envelope" else (
        outcome.ReceiptContent()
    )

    if mutation == "integer-timeout":
        document["limits"]["timeout_seconds"] = 15

    elif mutation == "changed-timeout":
        document["limits"]["timeout_seconds"] = 16.0

    else:
        document["limits"]["max_zip_bytes"] -= 1

    role = ENVELOPE_ROLE if artifact == "envelope" else RECEIPT_ROLE
    forged = store.Put(CanonicalReferenceJson(document), role, "application/json",
                       outcome.raw.provenance)
    original = LocalEvidenceStore.Read
    visited = []

    def Read(store, reference):
        """Observe actual original blob reads behind owning Get and explicit Read."""

        visited.append(reference.sha256)

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)

    with pytest.raises(ValueError):
        LoadHttpsCweSelection(root,
            forged.evidence_id if artifact == "envelope" else outcome.selection_record.evidence_id,
            forged.evidence_id if artifact == "receipt" else outcome.receipt.evidence_id)

    assert outcome.raw.reference.sha256 not in visited, "Changed limits reached raw interpretation"


def test_RelocatedReplayForbidsReceiverProcessSocketEvidenceAndModelWrites(tmp_path, monkeypatch):
    """Existing original custody suffices after relocation without fresh execution authority."""

    import socket
    import subprocess

    root, outcome = Imported(tmp_path)
    relocated = tmp_path / "relocated-offline"
    shutil.move(root, relocated)
    before = Files(relocated)

    def Forbidden(*args, **kwargs):
        """Fail on an operation outside read-only original evidence verification."""

        raise AssertionError("Read-only replay attempted resource or publication work")

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Forbidden)
    monkeypatch.setattr(socket, "socket", Forbidden)
    monkeypatch.setattr(subprocess, "Popen", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Forbidden)
    reopened = LoadHttpsCweSelection(relocated, outcome.selection_record.evidence_id,
                                    outcome.receipt.evidence_id)
    assert reopened == outcome.envelope and Files(relocated) == before, "Replay changed custody"
    assert not (relocated / "state/model").exists(), "Replay mutated canonical model"


@pytest.mark.parametrize("key", [
    "requested_ids", "records", "unsupported_entries", "unmatched_ids",
])
def test_AdversarialSelectionArraysRefuseBeforeDtoConstructionAndOriginalReads(
    tmp_path, monkeypatch, key,
):
    """Finite selection partitions are bounded before tuple copies and source interpretation."""

    root, outcome = Imported(tmp_path)
    document = json.loads(outcome.envelope.Serialize())
    document["selection"][key] = [None] * 65
    store = LocalEvidenceStore(root / "evidence")
    forged = store.Put(CanonicalReferenceJson(document), ENVELOPE_ROLE, "application/json",
                       outcome.raw.provenance)

    def Forbidden(*args, **kwargs):
        """Catch premature immutable DTO or original parser reconstruction."""

        raise AssertionError("Oversized array reached immutable selection reconstruction")

    import fuzzy1337.intelligence_cwe_acquisition as local_helpers

    monkeypatch.setattr(local_helpers, "CweSelection", Forbidden)
    monkeypatch.setattr(remote, "ParseCweSelection", Forbidden)

    with pytest.raises(ValueError, match="arrays"):
        LoadHttpsCweSelection(root, forged.evidence_id, outcome.receipt.evidence_id)


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff",
    b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}", b"[]"])
def test_StrictMalformedEnvelopeJsonCannotReachOriginalInterpretation(
    tmp_path, monkeypatch, payload,
):
    """New custody uses the unchanged strict byte/depth/numeric parser and no permissive JSON."""

    root, outcome = Imported(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    forged = store.Put(payload, ENVELOPE_ROLE, "application/json", outcome.raw.provenance)

    def Forbidden(*args, **kwargs):
        """Expose any attempt to interpret raw ZIP after malformed envelope admission."""

        raise AssertionError("Malformed envelope reached original parser")

    monkeypatch.setattr(remote, "ParseCweSelection", Forbidden)

    with pytest.raises(ValueError):
        LoadHttpsCweSelection(root, forged.evidence_id, outcome.receipt.evidence_id)


@pytest.mark.parametrize("field,value", [("receive_state", True), ("receive_state", "unknown"),
    ("http_status", True), ("http_status", 600), ("http_status", None),
    ("body_complete", False)])
def test_OutcomeRefusesForgedObservedTransportFacts(tmp_path, field, value):
    """Observed source completeness and status remain separate from storage or decoder states."""

    _, outcome = Imported(tmp_path)

    with pytest.raises(ValueError):
        replace(outcome, **{field: value})
