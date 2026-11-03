# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise pinned HTTPS EPSS publication, failure custody and offline owning replay."""

from __future__ import annotations

import gzip
import hashlib
import shutil
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337.evidence import EvidenceError, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_epss_remote import (
    ENVELOPE_ROLE,
    PARTIAL_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    AcquireHttpsEpssSelection,
    EpssHttpsAcknowledgement,
    EpssHttpsRequest,
    EpssHttpsSelection,
    EpssHttpsSource,
    EpssHttpsState,
    LoadHttpsEpssSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = "CVE-1900-0001"
MISSING = "CVE-1900-9999"
RAW_CSV = (b"#model_version:synthetic-model,score_date:2026-11-02T12:00:30Z\n"
           b"cve,epss,percentile\nCVE-1900-0001,0.0006,6e-05\n")
PAYLOAD = gzip.compress(RAW_CSV, mtime=0)


def Request(payload=PAYLOAD):
    """Pin owned fixture bytes under the exact immutable archive locator grammar."""

    return EpssHttpsRequest(EpssHttpsSource("a" * 40, "2026-11-02", "synthetic-model",
        hashlib.sha256(payload).hexdigest()), (FIRST, MISSING))


def Workspace(tmp_path, name="owned"):
    """Create an actual owning workspace without model state or target actions."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned HTTPS fixture"), name)

    return root


def Imported(tmp_path, monkeypatch):
    """Use an owned receive fixture and actual stores for a complete acknowledged acquisition."""

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is EpssHttpsState.SUCCEEDED, "Complete owned receive failed"
    assert outcome.raw and outcome.selection_record and outcome.receipt and outcome.envelope, (
        "Successful publication omitted exact custody handles"
    )

    return root, outcome


def test_ReceiveUsesOnlyFixedResourceAndObservedClockThenReplaysOfflineAfterRelocation(
    tmp_path, monkeypatch,
):
    """The product boundary supplies only the pinned resource and preserves original custody."""

    calls = []
    times = iter((datetime(2026, 11, 2, 13, tzinfo=timezone.utc),
                  datetime(2026, 11, 2, 13, 0, 1, tzinfo=timezone.utc)))
    monkeypatch.setattr(remote, "datetime", SimpleNamespace(now=lambda zone: next(times)))

    def Receive(url, maximum, timeout, *, accept_kind):
        """Record exact delegation while returning synthetic owned gzip resource bytes."""

        calls.append((url, maximum, timeout, accept_kind))

        return PAYLOAD, "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    root = Workspace(tmp_path)
    request = Request()
    outcome = AcquireHttpsEpssSelection(root, request, scope_reference="scope:owned")
    assert calls == [(request.source.SourceUrl, request.max_bytes, 15.0, "gzip")], (
        'Receiver delegation changed the pinned locator, byte cap, timeout or gzip kind'
    )
    assert outcome.started_at == "2026-11-02T13:00:00.000000+00:00", (
        'Acquisition start did not record the observed clock before receive'
    )
    assert outcome.finished_at == "2026-11-02T13:00:01.000000+00:00", (
        'Acquisition finish did not record the observed clock after receive'
    )
    moved = tmp_path / "relocated"
    shutil.move(root, moved)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        pytest.fail("Offline replay attempted a receive"))
    assert LoadHttpsEpssSelection(moved, outcome.selection_record.evidence_id,
                                 outcome.receipt.evidence_id) == outcome.envelope, (
        'Relocated offline replay changed the acknowledged original HTTPS envelope'
    )
    assert not (moved / "model").exists(), "Acquisition created a model"


@pytest.mark.parametrize("state,status", [("redirect-rejected", 302), ("http-rejected", 503),
    ("format-rejected", 200), ("size-exceeded", 200), ("transport-failed", None),
    ("timed-out", 200)])
@pytest.mark.parametrize("partial", [b"", b"bounded partial gzip"])
def test_ReceiverNegativeFactsPreserveBoundedPartialOriginalsWithoutSuccessEnvelope(
    tmp_path, monkeypatch, state, status, partial,
):
    """Every isolated refusal retains honest status/completeness without parsing partial data."""

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (partial, state, status))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state.value == state and outcome.http_status == status, (
        'Receiver refusal lost its observed terminal state or HTTP status'
    )
    assert outcome.receive_state == state and not outcome.body_complete, (
        'Receiver refusal claimed complete body custody or lost its observed state'
    )
    assert outcome.raw.reference.role == PARTIAL_ROLE and outcome.receipt, (
        'Receiver refusal lost bounded partial source evidence or its receipt'
    )
    assert LocalEvidenceStore(root / "evidence").Read(outcome.raw.reference) == partial, (
        'Partial-source evidence did not retain the actual bounded receiver bytes'
    )
    assert outcome.received_bytes == len(partial), (
        'Recorded receive length disagreed with actual bounded partial bytes'
    )
    assert outcome.selection_ack is EpssHttpsAcknowledgement.NOT_ATTEMPTED, (
        'A refused receive attempted selected-envelope publication'
    )
    assert outcome.envelope is None and outcome.selection_record is None, (
        'A refused receive exposed a usable successful selected envelope'
    )


@pytest.mark.parametrize("payload,pin,state", [(b"invalid gzip", None, "parse-failed"),
    (PAYLOAD[:-1], None, "parse-failed"), (PAYLOAD, "b" * 64, "digest-mismatch"),
    (gzip.compress(RAW_CSV.replace(b"0.0006", b"invalid"), mtime=0), None, "parse-failed"),
    (gzip.compress(RAW_CSV, mtime=0) * 2, None, "parse-failed")])
def test_CompleteHashOrDecodeFailurePreservesOriginalBytesAndFailureReceipt(
    tmp_path, monkeypatch, payload, pin, state,
):
    """Complete HTTP success cannot bypass the mandatory pin, gzip EOF or full CSV validation."""

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (payload, "succeeded", 200))
    request = Request(payload)

    if pin is not None:
        request = replace(request, source=replace(request.source, expected_sha256=pin))

    root = Workspace(tmp_path)
    outcome = AcquireHttpsEpssSelection(root, request, scope_reference="scope:owned")
    assert outcome.state.value == state and outcome.raw and outcome.receipt, (
        'Complete hash or parse failure lost its terminal state, original bytes or receipt'
    )
    assert outcome.raw.reference.role == RAW_ROLE and outcome.body_complete, (
        'Complete failed source was incorrectly recorded as partial transport custody'
    )
    assert LocalEvidenceStore(root / "evidence").Read(outcome.raw.reference) == payload, (
        'Hash or parse failure changed the retained original received bytes'
    )
    assert outcome.envelope is None and outcome.selection_record is None, (
        'Hash or parse failure published a usable successful selected envelope'
    )


@pytest.mark.parametrize("stage", [1, 2, 3])
@pytest.mark.parametrize("lost_ack", [False, True])
def test_StorageFailuresBeforeAndAfterCommitExposeIndependentUnknownAcknowledgements(
    tmp_path, monkeypatch, stage, lost_ack,
):
    """Durable artifacts can outlive failed acknowledgement without a claimed success result."""

    original = LocalEvidenceStore.Put
    calls = []

    def Put(store, *args, **kwargs):
        """Inject one controlled publication error before or after the actual owning commit."""

        if len(calls) + 1 == stage and not lost_ack:
            calls.append(None)

            raise EvidenceStorageError("owned precommit failure")

        record = original(store, *args, **kwargs)
        calls.append(record)

        if len(calls) == stage:
            raise EvidenceStorageError("owned lost acknowledgement")

        return record

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    root = Workspace(tmp_path)
    outcome = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:owned")
    acks = (outcome.raw_ack, outcome.selection_ack, outcome.receipt_ack)
    assert outcome.state is EpssHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        'Publication failure returned success or exposed a usable successful envelope'
    )
    assert acks[stage - 1] is EpssHttpsAcknowledgement.UNKNOWN, (
        'The failed publication did not retain its unknown acknowledgement'
    )
    assert all(ack is EpssHttpsAcknowledgement.CONFIRMED for ack in acks[:stage - 1]), (
        'Earlier successful publications lost their confirmed acknowledgements'
    )
    assert all(ack is EpssHttpsAcknowledgement.NOT_ATTEMPTED for ack in acks[stage:]), (
        'Publications after the failure were incorrectly recorded as attempted'
    )

    if stage == 3 and lost_ack:
        loaded = LoadHttpsEpssSelection(root, calls[1].evidence_id, calls[2].evidence_id)
        assert loaded.selection.unmatched_ids == (MISSING,), (
            'Recovered receipt with a lost acknowledgement changed the unmatched selection'
        )


@pytest.mark.parametrize("key,value", [("body_complete", False), ("received_bytes", 1),
    ("transport", "local-bytes"), ("http_status", 201), ("http_status", True),
    ("receive_state", "timed-out"), ("state", "parse-failed"), ("raw_ack", "unknown"),
    ("selection_ack", "unknown"), ("requested_ids", [FIRST]), ("schema_version", True),
    ("profile_version", 2), ("publisher_authentication", "verified"), ("unexpected", True)])
def test_RehashedNetworkReceiptTamperingRefusesBeforeOriginalRawAdmission(
    tmp_path, monkeypatch, key, value,
):
    """Content addressing alone cannot replace the successful receiver's exact terminal facts."""

    root, outcome = Imported(tmp_path, monkeypatch)
    document = outcome.ReceiptContent()
    document[key] = value
    forged = LocalEvidenceStore(root / "evidence").Put(CanonicalReferenceJson(document),
        RECEIPT_ROLE, "application/json", outcome.receipt.provenance)
    original = LocalEvidenceStore.Get
    visited = []

    def Get(store, evidence_id):
        """Observe selected manifest admission through the actual owning implementation."""

        visited.append(evidence_id)

        return original(store, evidence_id)

    monkeypatch.setattr(LocalEvidenceStore, "Get", Get)

    with pytest.raises(ValueError):
        LoadHttpsEpssSelection(root, outcome.selection_record.evidence_id, forged.evidence_id)

    assert outcome.raw.evidence_id not in visited, (
        'Tampered receipt reached original raw-manifest admission before refusal'
    )


@pytest.mark.parametrize("limit,value", [("max_compressed_bytes", True),
    ("max_compressed_bytes", 1), ("max_compressed_bytes", 4194305),
    ("timeout_seconds", 0), ("timeout_seconds", True), ("max_decoded_bytes", 1),
    ("max_csv_rows", 500001)])
def test_RehashedRequestLimitsCannotBroadenOrContradictRecordedCustody(
    tmp_path, monkeypatch, limit, value,
):
    """Replay validates request limits and exact decoder ceilings before original gzip loading."""

    root, outcome = Imported(tmp_path, monkeypatch)
    document = outcome.ReceiptContent()
    document["limits"][limit] = value
    forged = LocalEvidenceStore(root / "evidence").Put(CanonicalReferenceJson(document),
        RECEIPT_ROLE, "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError):
        LoadHttpsEpssSelection(root, outcome.selection_record.evidence_id, forged.evidence_id)


def test_ConsistentlyRehashedSelectedTamperingStillRequiresFullOriginalGzipReparse(
    tmp_path, monkeypatch,
):
    """A forged normalized decimal and consistent receipt cannot replace original assertions."""

    root, outcome = Imported(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    record = replace(outcome.envelope.selection.records[0], probability="0.9")
    selected = replace(outcome.envelope.selection, records=(record,))
    envelope = EpssHttpsSelection(outcome.source, outcome.raw, selected)
    forged = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                       outcome.selection_record.provenance)
    changed = replace(outcome, envelope=envelope, selection_record=forged)
    receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError, match="original gzip"):
        LoadHttpsEpssSelection(root, forged.evidence_id, receipt.evidence_id)


@pytest.mark.parametrize("splice", ["roots", "nested-raw"])
def test_SameWorkspaceDistinctAcquisitionsCannotSpliceOwningCustody(
    tmp_path, monkeypatch, splice,
):
    """Identical valid bytes retain separate acquisition provenance inside one workspace."""

    root, first = Imported(tmp_path, monkeypatch)
    second = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:other")
    store = LocalEvidenceStore(root / "evidence")
    assert first.raw.evidence_id != second.raw.evidence_id, (
        'Distinct acquisition provenance reused the same original evidence identity'
    )

    if splice == "roots":
        selected_id, receipt_id = first.selection_record.evidence_id, second.receipt.evidence_id

    else:
        wrapper = store.Put(first.envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                            second.raw.provenance)
        changed = replace(second, raw=first.raw, envelope=first.envelope, selection_record=wrapper)
        receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                            "application/json", second.raw.provenance)
        selected_id, receipt_id = wrapper.evidence_id, receipt.evidence_id

    with pytest.raises(ValueError, match="provenance"):
        LoadHttpsEpssSelection(root, selected_id, receipt_id)


@pytest.mark.parametrize("artifact", ["raw", "selection_record", "receipt"])
@pytest.mark.parametrize("mutation", ["missing", "corrupt"])
def test_MissingOrCorruptArtifactsCannotReplay(tmp_path, monkeypatch, artifact, mutation):
    """Each original selected blob remains verified through actual filesystem custody."""

    root, outcome = Imported(tmp_path, monkeypatch)
    path = root / "evidence" / getattr(outcome, artifact).reference.locator

    if mutation == "missing":
        path.unlink()

    else:
        path.write_bytes(b"controlled corruption")

    with pytest.raises((EvidenceError, ValueError)):
        LoadHttpsEpssSelection(root, outcome.selection_record.evidence_id,
                              outcome.receipt.evidence_id)


@pytest.mark.parametrize("role,maximum", [(ENVELOPE_ROLE, 128 * 1024),
                                         (RECEIPT_ROLE, 32 * 1024)])
@pytest.mark.parametrize("denial", ["size", "role", "media"])
def test_RoleMediaAndBudgetRefuseBeforeOwningGetAllocatesBlobContent(
    tmp_path, monkeypatch, role, maximum, denial,
):
    """Untrusted root manifests cannot choose a larger domain or reach the actual blob reader."""

    root, outcome = Imported(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    malicious = store.Put(b"x" * (maximum + 1) if denial == "size" else b"small",
        RAW_ROLE if denial == "role" else role,
        "text/plain" if denial == "media" else "application/json", outcome.raw.provenance)
    original = LocalEvidenceStore.Read
    reads = []

    def Read(store, reference):
        """Record actual base blob read delegation while preserving all real integrity checks."""

        reads.append(reference.sha256)

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    selected_id = (malicious.evidence_id if role == ENVELOPE_ROLE
                   else outcome.selection_record.evidence_id)
    receipt_id = malicious.evidence_id if role == RECEIPT_ROLE else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadHttpsEpssSelection(root, selected_id, receipt_id)

    assert malicious.reference.sha256 not in reads, (
        'Invalid role, media or budget delegated actual malicious blob loading'
    )


def test_FutureSourceClockPreservesRawWithParseFailedReceipt(tmp_path, monkeypatch):
    """Original source assertions cannot come after the actual isolated receiver's finish."""

    clock = SimpleNamespace(now=lambda zone: datetime(2026, 11, 2, 12, tzinfo=timezone.utc))
    monkeypatch.setattr(remote, "datetime", clock)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is EpssHttpsState.PARSE_FAILED and outcome.raw and outcome.receipt, (
        'Future source clock was accepted or lost original bytes and failure receipt'
    )
    assert outcome.envelope is None and outcome.selection_record is None, (
        'Future source clock produced a usable selected envelope'
    )


def test_ForeignWorkspaceCannotAdoptCopiedManifests(tmp_path, monkeypatch):
    """Copying original evidence to another workspace does not establish new ownership."""

    root, outcome = Imported(tmp_path, monkeypatch)
    foreign = Workspace(tmp_path, "foreign")
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)

    with pytest.raises(ValueError, match="owning"):
        LoadHttpsEpssSelection(foreign, outcome.selection_record.evidence_id,
                              outcome.receipt.evidence_id)


@pytest.mark.parametrize("root_kind", ["selection", "receipt"])
def test_HttpsLoaderRefusesOriginalLocalProfileRootsBeforeBlobReads(
    tmp_path, monkeypatch, root_kind,
):
    """Actual local acquisition artifacts retain their original family after HTTPS is added."""

    from fuzzy1337.intel_references import SourceOrigin
    from fuzzy1337.intelligence_epss_acquisition import (
        AcquireLocalEpssSelection,
        EpssLocalRequest,
        EpssLocalSource,
    )

    root, outcome = Imported(tmp_path, monkeypatch)
    local_source = EpssLocalSource(SourceOrigin.SYNTHETIC, "Fixture",
        "https://example.invalid/source", "Fixture only", "https://example.invalid/LICENSE",
        ("https://example.invalid/terms",), "synthetic-model", "2026-11-02")
    request = EpssLocalRequest(local_source, PAYLOAD, (FIRST, MISSING))
    local = AcquireLocalEpssSelection(root, request, scope_reference="scope:local")
    selected_id = (local.selection_record.evidence_id if root_kind == "selection"
                   else outcome.selection_record.evidence_id)
    receipt_id = (local.receipt.evidence_id if root_kind == "receipt"
                  else outcome.receipt.evidence_id)

    with pytest.raises(ValueError, match="role-specific"):
        LoadHttpsEpssSelection(root, selected_id, receipt_id)


@pytest.mark.parametrize("root_kind", ["selection", "receipt"])
def test_ForeignImporterRootIsRejectedBeforeNestedInterpretation(
    tmp_path, monkeypatch, root_kind,
):
    """Right-role and bounded root bytes cannot adopt a different producer's provenance."""

    root, outcome = Imported(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    original = outcome.selection_record if root_kind == "selection" else outcome.receipt
    forged = store.Put(store.Read(original.reference), original.reference.role, "application/json",
        replace(original.provenance, source_id="foreign"))
    selected_id = (forged.evidence_id if root_kind == "selection"
                   else outcome.selection_record.evidence_id)
    receipt_id = forged.evidence_id if root_kind == "receipt" else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="provenance"):
        LoadHttpsEpssSelection(root, selected_id, receipt_id)


@pytest.mark.parametrize("content", [b"[]", b'{"duplicate":1,"duplicate":2}', b'{"x":NaN}'])
def test_HttpsRootsRequireStrictBoundedJsonObjects(tmp_path, monkeypatch, content):
    """A valid owning root still refuses non-object, duplicate-key or nonfinite JSON content."""

    root, outcome = Imported(tmp_path, monkeypatch)
    forged = LocalEvidenceStore(root / "evidence").Put(content, ENVELOPE_ROLE,
        "application/json", outcome.selection_record.provenance)

    with pytest.raises(ValueError):
        LoadHttpsEpssSelection(root, forged.evidence_id, outcome.receipt.evidence_id)


def test_UntypedRequestIsRejectedBeforeReceiverOrWorkspaceAccess(tmp_path):
    """The remote entry point cannot duck-type a local or caller-built acquisition object."""

    with pytest.raises(ValueError, match="typed HTTPS request"):
        AcquireHttpsEpssSelection(tmp_path / "absent", object(), scope_reference="scope:owned")


def test_ValidLargeWorkspaceIdentityCannotHideConfirmedPublicationsOnReceiptBudgetFailure(
    tmp_path, monkeypatch,
):
    """Generated receipt overflow from valid owning identifiers returns truthful ACK facts."""

    root = tmp_path / "owned"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Large owned identity"), "a" * 20000)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    outcome = AcquireHttpsEpssSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is EpssHttpsState.STORAGE_FAILED, (
        'Receipt byte-budget failure did not return storage failure'
    )
    assert outcome.raw and outcome.selection_record and outcome.envelope is None, (
        'Receipt byte-budget failure lost earlier artifacts or retained a usable envelope'
    )
    assert outcome.raw_ack is EpssHttpsAcknowledgement.CONFIRMED, (
        'Receipt byte-budget failure lost the confirmed raw publication acknowledgement'
    )
    assert outcome.selection_ack is EpssHttpsAcknowledgement.CONFIRMED, (
        'Receipt byte-budget failure lost the confirmed selection acknowledgement'
    )
    assert (outcome.receipt_ack is EpssHttpsAcknowledgement.NOT_ATTEMPTED
            and outcome.receipt is None), (
        'Oversized receipt was published or recorded as attempted'
    )
    store = LocalEvidenceStore(root / "evidence")
    assert store.Get(outcome.raw.evidence_id) == outcome.raw, (
        'Confirmed raw publication was not retrievable after receipt-budget refusal'
    )
    assert store.Get(outcome.selection_record.evidence_id) == outcome.selection_record, (
        'Confirmed selected publication was not retrievable after receipt-budget refusal'
    )
