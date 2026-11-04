# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise pinned HTTPS CVE publication, failure custody and offline owning replay."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_cve_remote import (
    ENVELOPE_ROLE,
    PARTIAL_ROLE,
    RAW_ROLE,
    RECEIPT_ROLE,
    AcquireHttpsCveSelection,
    CveHttpsAcknowledgement,
    CveHttpsRequest,
    CveHttpsSelection,
    CveHttpsSource,
    CveHttpsState,
    LoadHttpsCveSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = "CVE-1900-0001"
DOCUMENT = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
    "cveMetadata": {"cveId": FIRST, "state": "PUBLISHED", "dateUpdated": "2026-11-02T12:00:30Z"},
    "containers": {"cna": {"providerMetadata": {"orgId": "owned-cna"},
        "descriptions": [{"lang": "en", "value": "Owned original source statement"}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
        "metrics": [{"other": {"type": "owned-unsupported", "content": {"value": "retained"}}}]},
        "adp": [{"providerMetadata": {"orgId": "owned-adp"},
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}]}}
PAYLOAD = CanonicalReferenceJson(DOCUMENT)


def Request(payload=PAYLOAD):
    """Pin owned fixture bytes under the exact immutable archive locator grammar."""

    return CveHttpsRequest(CveHttpsSource("a" * 40, FIRST,
        hashlib.sha256(payload).hexdigest()))


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
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CveHttpsState.SUCCEEDED, "Complete owned receive failed"
    assert outcome.raw and outcome.snapshot_record and outcome.receipt and outcome.envelope, (
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

    def Receive(url, maximum, timeout, *, accept_kind="json"):
        """Record exact delegation while returning synthetic owned JSON bytes."""

        calls.append((url, maximum, timeout, accept_kind))

        return PAYLOAD, "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    root = Workspace(tmp_path)
    request = Request()
    outcome = AcquireHttpsCveSelection(root, request, scope_reference="scope:owned")
    assert calls == [(request.source.SourceUrl, request.max_bytes, 15.0, "json")], (
        'Receiver delegation changed the pinned locator, byte cap, timeout or JSON kind'
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
    assert LoadHttpsCveSelection(moved, outcome.snapshot_record.evidence_id,
                                 outcome.receipt.evidence_id) == outcome.envelope, (
        'Relocated offline replay changed the acknowledged original HTTPS envelope'
    )
    assert not (moved / "model").exists(), "Acquisition created a model"


@pytest.mark.parametrize("state,status", [("redirect-rejected", 302), ("http-rejected", 503),
    ("format-rejected", 200), ("size-exceeded", 200), ("transport-failed", None),
    ("timed-out", 200)])
@pytest.mark.parametrize("partial", [b"", b"bounded partial JSON"])
def test_ReceiverNegativeFactsPreserveBoundedPartialOriginalsWithoutSuccessEnvelope(
    tmp_path, monkeypatch, state, status, partial,
):
    """Every isolated refusal retains honest status/completeness without parsing partial data."""

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (partial, state, status))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:owned")
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
    assert outcome.snapshot_ack is CveHttpsAcknowledgement.NOT_ATTEMPTED, (
        'A refused receive attempted selected-envelope publication'
    )
    assert outcome.envelope is None and outcome.snapshot_record is None, (
        'A refused receive exposed a usable successful selected envelope'
    )


@pytest.mark.parametrize("payload,pin,state", [(b"invalid JSON", None, "parse-failed"),
    (PAYLOAD[:-1], None, "parse-failed"), (PAYLOAD, "b" * 64, "digest-mismatch"),
    (b'{"duplicate":1,"duplicate":2}', None, "parse-failed"),
    (b'{"number":NaN}', None, "parse-failed"), (b"\xff", None, "parse-failed")])
def test_CompleteHashOrDecodeFailurePreservesOriginalBytesAndFailureReceipt(
    tmp_path, monkeypatch, payload, pin, state,
):
    """Complete HTTP success cannot bypass the mandatory pin or strict original JSON parser."""

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (payload, "succeeded", 200))
    request = Request(payload)

    if pin is not None:
        request = replace(request, source=replace(request.source, expected_sha256=pin))

    root = Workspace(tmp_path)
    outcome = AcquireHttpsCveSelection(root, request, scope_reference="scope:owned")
    assert outcome.state.value == state and outcome.raw and outcome.receipt, (
        "Complete source failure lost original bytes or its failure receipt"
    )
    assert outcome.raw.reference.role == RAW_ROLE and outcome.body_complete, (
        "Complete source failure was incorrectly recorded as partial transport custody"
    )
    assert LocalEvidenceStore(root / "evidence").Read(outcome.raw.reference) == payload, (
        "Hash or parse failure changed retained original bytes"
    )
    assert outcome.envelope is None and outcome.snapshot_record is None, (
        "Hash or parse failure exposed a usable selected envelope"
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
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:owned")
    acks = (outcome.raw_ack, outcome.snapshot_ack, outcome.receipt_ack)
    assert outcome.state is CveHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        'Publication failure returned success or exposed a usable successful envelope'
    )
    assert acks[stage - 1] is CveHttpsAcknowledgement.UNKNOWN, (
        'The failed publication did not retain its unknown acknowledgement'
    )
    assert all(ack is CveHttpsAcknowledgement.CONFIRMED for ack in acks[:stage - 1]), (
        'Earlier successful publications lost their confirmed acknowledgements'
    )
    assert all(ack is CveHttpsAcknowledgement.NOT_ATTEMPTED for ack in acks[stage:]), (
        'Publications after the failure were incorrectly recorded as attempted'
    )

    if stage == 3 and lost_ack:
        loaded = LoadHttpsCveSelection(root, calls[1].evidence_id, calls[2].evidence_id)
        assert loaded.snapshot.records[0].identifier == FIRST, (
            'Recovered receipt with a lost acknowledgement changed the selected CVE'
        )


@pytest.mark.parametrize("key,value", [("body_complete", False), ("received_bytes", 1),
    ("transport", "local-bytes"), ("http_status", 201), ("http_status", True),
    ("receive_state", "timed-out"), ("state", "parse-failed"), ("raw_ack", "unknown"),
    ("snapshot_ack", "unknown"), ("identifier", "CVE-1900-0002"), ("schema_version", True),
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
        LoadHttpsCveSelection(root, outcome.snapshot_record.evidence_id, forged.evidence_id)

    assert outcome.raw.evidence_id not in visited, (
        'Tampered receipt reached original raw-manifest admission before refusal'
    )


@pytest.mark.parametrize("limit,value", [("max_source_bytes", True),
    ("max_source_bytes", 1), ("max_source_bytes", 1048577),
    ("timeout_seconds", 0), ("timeout_seconds", True),
    ("timeout_seconds", 14.0), ("max_source_bytes", 524288)])
def test_RehashedRequestLimitsCannotBroadenOrContradictRecordedCustody(
    tmp_path, monkeypatch, limit, value,
):
    """Replay validates request limits and exact decoder ceilings before original JSON loading."""

    root, outcome = Imported(tmp_path, monkeypatch)
    document = outcome.ReceiptContent()
    document["limits"][limit] = value
    forged = LocalEvidenceStore(root / "evidence").Put(CanonicalReferenceJson(document),
        RECEIPT_ROLE, "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError):
        LoadHttpsCveSelection(root, outcome.snapshot_record.evidence_id, forged.evidence_id)


def test_ConsistentlyRehashedSelectedTamperingStillRequiresFullOriginalJsonReparse(
    tmp_path, monkeypatch,
):
    """A forged normalized description and receipt cannot replace original JSON assertions."""

    root, outcome = Imported(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    original = outcome.envelope.snapshot
    data = dict(original.records[0].data)
    data["description"] = "Owned rehashed normalized tamper"
    record = replace(original.records[0], data=data)
    selected = replace(original, records=(record,))
    envelope = CveHttpsSelection(outcome.source, outcome.raw, selected)
    forged = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                       outcome.snapshot_record.provenance)
    changed = replace(outcome, envelope=envelope, snapshot_record=forged)
    receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError, match="original JSON"):
        LoadHttpsCveSelection(root, forged.evidence_id, receipt.evidence_id)


@pytest.mark.parametrize("splice", ["roots", "nested-raw"])
def test_SameWorkspaceDistinctAcquisitionsCannotSpliceOwningCustody(
    tmp_path, monkeypatch, splice,
):
    """Identical valid bytes retain separate acquisition provenance inside one workspace."""

    root, first = Imported(tmp_path, monkeypatch)
    second = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:other")
    store = LocalEvidenceStore(root / "evidence")
    assert first.raw.evidence_id != second.raw.evidence_id, (
        'Distinct acquisition provenance reused the same original evidence identity'
    )

    if splice == "roots":
        selectedId, receiptId = first.snapshot_record.evidence_id, second.receipt.evidence_id

    else:
        wrapper = store.Put(first.envelope.Serialize(), ENVELOPE_ROLE, "application/json",
                            second.raw.provenance)
        changed = replace(second, raw=first.raw, envelope=first.envelope, snapshot_record=wrapper)
        receipt = store.Put(CanonicalReferenceJson(changed.ReceiptContent()), RECEIPT_ROLE,
                            "application/json", second.raw.provenance)
        selectedId, receiptId = wrapper.evidence_id, receipt.evidence_id

    with pytest.raises(ValueError, match="provenance"):
        LoadHttpsCveSelection(root, selectedId, receiptId)


@pytest.mark.parametrize("artifact", ["raw", "snapshot_record", "receipt"])
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
        LoadHttpsCveSelection(root, outcome.snapshot_record.evidence_id,
                              outcome.receipt.evidence_id)


@pytest.mark.parametrize("role,maximum", [(ENVELOPE_ROLE, 2 * 1024 * 1024),
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
    selectedId = (malicious.evidence_id if role == ENVELOPE_ROLE
                   else outcome.snapshot_record.evidence_id)
    receiptId = malicious.evidence_id if role == RECEIPT_ROLE else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="role-specific"):
        LoadHttpsCveSelection(root, selectedId, receiptId)

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
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CveHttpsState.PARSE_FAILED and outcome.raw and outcome.receipt, (
        'Future source clock was accepted or lost original bytes and failure receipt'
    )
    assert outcome.envelope is None and outcome.snapshot_record is None, (
        'Future source clock produced a usable selected envelope'
    )


def test_ForeignWorkspaceCannotAdoptCopiedManifests(tmp_path, monkeypatch):
    """Copying original evidence to another workspace does not establish new ownership."""

    root, outcome = Imported(tmp_path, monkeypatch)
    foreign = Workspace(tmp_path, "foreign")
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)

    with pytest.raises(ValueError, match="owning"):
        LoadHttpsCveSelection(foreign, outcome.snapshot_record.evidence_id,
                              outcome.receipt.evidence_id)


@pytest.mark.parametrize("root_kind", ["selection", "receipt"])
def test_HttpsLoaderRefusesOriginalLocalProfileRootsBeforeBlobReads(
    tmp_path, monkeypatch, root_kind,
):
    """Actual local source custody keeps its original artifact domain after HTTPS is added."""

    from fuzzy1337.intel_references import SourceOrigin
    from fuzzy1337.intelligence import IntelligenceFeed
    from fuzzy1337.intelligence_acquisition import (
        AcquireIntelligenceSnapshot,
        SnapshotRequest,
        SnapshotSource,
    )

    root, outcome = Imported(tmp_path, monkeypatch)
    localSource = SnapshotSource(IntelligenceFeed.CVE, "a" * 40, SourceOrigin.SYNTHETIC,
        "Owned fixture", "https://example.invalid/source", "Owned fixture only",
        "https://example.invalid/LICENSE")
    local = AcquireIntelligenceSnapshot(root, SnapshotRequest(localSource, PAYLOAD),
                                       scope_reference="scope:local")
    selectedId = (local.snapshot_record.evidence_id if root_kind == "selection"
                   else outcome.snapshot_record.evidence_id)
    receiptId = (local.receipt.evidence_id if root_kind == "receipt"
                  else outcome.receipt.evidence_id)

    with pytest.raises(ValueError, match="role-specific"):
        LoadHttpsCveSelection(root, selectedId, receiptId)


@pytest.mark.parametrize("root_kind", ["selection", "receipt"])
def test_ForeignImporterRootIsRejectedBeforeNestedInterpretation(
    tmp_path, monkeypatch, root_kind,
):
    """Right-role and bounded root bytes cannot adopt a different producer's provenance."""

    root, outcome = Imported(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    original = outcome.snapshot_record if root_kind == "selection" else outcome.receipt
    forged = store.Put(store.Read(original.reference), original.reference.role, "application/json",
        replace(original.provenance, source_id="foreign"))
    selectedId = (forged.evidence_id if root_kind == "selection"
                   else outcome.snapshot_record.evidence_id)
    receiptId = forged.evidence_id if root_kind == "receipt" else outcome.receipt.evidence_id

    with pytest.raises(ValueError, match="provenance"):
        LoadHttpsCveSelection(root, selectedId, receiptId)


@pytest.mark.parametrize("content", [b"[]", b'{"duplicate":1,"duplicate":2}', b'{"x":NaN}'])
def test_HttpsRootsRequireStrictBoundedJsonObjects(tmp_path, monkeypatch, content):
    """A valid owning root still refuses non-object, duplicate-key or nonfinite JSON content."""

    root, outcome = Imported(tmp_path, monkeypatch)
    forged = LocalEvidenceStore(root / "evidence").Put(content, ENVELOPE_ROLE,
        "application/json", outcome.snapshot_record.provenance)

    with pytest.raises(ValueError):
        LoadHttpsCveSelection(root, forged.evidence_id, outcome.receipt.evidence_id)


def test_UntypedRequestIsRejectedBeforeReceiverOrWorkspaceAccess(tmp_path):
    """The remote entry point cannot duck-type a local or caller-built acquisition object."""

    with pytest.raises(ValueError, match="typed HTTPS request"):
        AcquireHttpsCveSelection(tmp_path / "absent", object(), scope_reference="scope:owned")


def test_ValidLargeWorkspaceIdentityCannotHideConfirmedPublicationsOnReceiptBudgetFailure(
    tmp_path, monkeypatch,
):
    """Generated receipt overflow from valid owning identifiers returns truthful ACK facts."""

    root = tmp_path / "owned"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Large owned identity"), "a" * 20000)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="scope:owned")
    assert outcome.state is CveHttpsState.STORAGE_FAILED, (
        'Receipt byte-budget failure did not return storage failure'
    )
    assert outcome.raw and outcome.snapshot_record and outcome.envelope is None, (
        'Receipt byte-budget failure lost earlier artifacts or retained a usable envelope'
    )
    assert outcome.raw_ack is CveHttpsAcknowledgement.CONFIRMED, (
        'Receipt byte-budget failure lost the confirmed raw publication acknowledgement'
    )
    assert outcome.snapshot_ack is CveHttpsAcknowledgement.CONFIRMED, (
        'Receipt byte-budget failure lost the confirmed selection acknowledgement'
    )
    assert (outcome.receipt_ack is CveHttpsAcknowledgement.NOT_ATTEMPTED
            and outcome.receipt is None), (
        'Oversized receipt was published or recorded as attempted'
    )
    store = LocalEvidenceStore(root / "evidence")
    assert store.Get(outcome.raw.evidence_id) == outcome.raw, (
        'Confirmed raw publication was not retrievable after receipt-budget refusal'
    )
    assert store.Get(outcome.snapshot_record.evidence_id) == outcome.snapshot_record, (
        'Confirmed selected publication was not retrievable after receipt-budget refusal'
    )


@pytest.mark.parametrize("where,field,value", [("root", "dataType", "other"),
    ("root", "dataVersion", "5.1"), ("root", "dataVersion", "5.2.0"),
    ("root", "dataVersion", 5.2), ("metadata", "state", "REJECTED"),
    ("metadata", "state", "RESERVED"), ("metadata", "state", None),
    ("metadata", "cveId", "CVE-1900-0002"), ("metadata", "cveId", "CWE-79")])
def test_ExactWireVersionPublishedStateAndRequestedCveAreRequiredBeforeUsableEnvelope(
    tmp_path, monkeypatch, where, field, value,
):
    """The first profile rejects other wire versions, source states and selected identities."""

    document = json.loads(PAYLOAD)
    target = document if where == "root" else document["cveMetadata"]
    target[field] = value
    payload = CanonicalReferenceJson(document)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (payload, "succeeded", 200))
    root = Workspace(tmp_path)
    outcome = AcquireHttpsCveSelection(root, Request(payload), scope_reference="scope:owned")
    assert outcome.state is CveHttpsState.PARSE_FAILED and outcome.raw and outcome.receipt, (
        "Unsupported wire/state/identifier became accepted or lost original failure custody"
    )
    assert outcome.envelope is None and outcome.snapshot_record is None, (
        "Unsupported wire/state/identifier exposed a usable selected envelope"
    )
    assert LocalEvidenceStore(root / "evidence").Read(outcome.raw.reference) == payload, (
        "Unsupported source failure changed its original pinned bytes"
    )


def test_SuccessPreservesOriginalCnaAdpAssertionsAndUnsupportedMetrics(tmp_path, monkeypatch):
    """Existing parser output and original context remain source assertions without model writes."""

    root, outcome = Imported(tmp_path, monkeypatch)
    record = outcome.envelope.snapshot.records[0]
    assert record.identifier == FIRST and record.data["cwe_ids"] == ("CWE-79",), (
        "Selected snapshot changed its exact CVE or source CWE assertion"
    )
    assert record.data["unsupported_metrics"] == ("other",), (
        "Selected snapshot erased the existing parser's explicit unsupported metric names"
    )
    assert record.data["cvss"][0]["assessor"] == "owned-adp", (
        "ADP assessment was reassigned to the CNA or a synthetic publisher"
    )
    assert LocalEvidenceStore(root / "evidence").Read(outcome.raw.reference) == PAYLOAD, (
        "Original full CNA/ADP source context was reconstructed or changed"
    )


@pytest.mark.parametrize("version", ["5.1", "5.2.0"])
def test_ConsistentlyRehashedOldWireSourceCannotBorrowPublishedSchemaOneSnapshot(
    tmp_path, monkeypatch, version,
):
    """Original replay repeats the narrower wire-version check that the old parser does not own."""

    from fuzzy1337.intelligence import IntelligenceFeed, ParseIntelligenceSnapshot
    from fuzzy1337.intelligence_cve_remote import SourceAttribution

    root, outcome = Imported(tmp_path, monkeypatch)
    payload = CanonicalReferenceJson({**DOCUMENT, "dataVersion": version})
    source = replace(outcome.source, expected_sha256=hashlib.sha256(payload).hexdigest())
    store = LocalEvidenceStore(root / "evidence")
    raw = store.Put(payload, RAW_ROLE, "application/json", outcome.raw.provenance)
    snapshot = ParseIntelligenceSnapshot(payload, IntelligenceFeed.CVE, source.commit,
                                         SourceAttribution(source, raw), raw.reference)
    envelope = CveHttpsSelection(source, raw, snapshot)
    selected = store.Put(envelope.Serialize(), ENVELOPE_ROLE, "application/json", raw.provenance)
    forged = replace(outcome, source=source, raw=raw, received_bytes=len(payload),
                     envelope=envelope, snapshot_record=selected)
    receipt = store.Put(CanonicalReferenceJson(forged.ReceiptContent()), RECEIPT_ROLE,
                        "application/json", raw.provenance)

    with pytest.raises(ValueError, match="wire-5.2 PUBLISHED"):
        LoadHttpsCveSelection(root, selected.evidence_id, receipt.evidence_id)


def test_SupportedLargeWorkspaceReceivesOwningManifestBudgetRefusalHonestly(tmp_path, monkeypatch):
    """The evidence owner's documented ValueError leaves unknown raw ACK and no usable success."""

    root = tmp_path / "owned"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Large owned identity"),
                                     "a" * (1024 * 1024 - 700))
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (PAYLOAD, "succeeded", 200))
    outcome = AcquireHttpsCveSelection(root, Request(), scope_reference="s" * 512)
    assert outcome.state is CveHttpsState.STORAGE_FAILED and outcome.envelope is None, (
        "Owning manifest size refusal raised or became a usable successful envelope"
    )
    assert outcome.raw_ack is CveHttpsAcknowledgement.UNKNOWN and outcome.raw is None, (
        "Rejected raw manifest returned a confirmed handle or hid attempted publication"
    )
    assert outcome.snapshot_ack is outcome.receipt_ack is CveHttpsAcknowledgement.NOT_ATTEMPTED, (
        "Raw publication refusal claimed later publications had been attempted"
    )


def test_ConsistentlyRehashedEnvelopeLimitRefusesRawCustodyBeforeOriginalGet(tmp_path, monkeypatch):
    """Even fully rehashed metadata cannot admit original bytes above the envelope's own limit."""

    root, outcome = Imported(tmp_path, monkeypatch)
    document = outcome.envelope.ToDict()
    document["limits"]["max_source_bytes"] = 1
    document["reference"] = "cve-https-selection:" + hashlib.sha256(
        CanonicalReferenceJson(document),
    ).hexdigest()
    store = LocalEvidenceStore(root / "evidence")
    forged = store.Put(CanonicalReferenceJson(document), ENVELOPE_ROLE, "application/json",
                       outcome.raw.provenance)

    terminal = outcome.ReceiptContent()
    terminal["limits"]["max_source_bytes"] = 1
    terminal["snapshot_record"] = forged.ToDict()
    terminal["envelope_reference"] = document["reference"]
    receipt = store.Put(CanonicalReferenceJson(terminal), RECEIPT_ROLE, "application/json",
                        outcome.raw.provenance)
    original = LocalEvidenceStore.Get
    visited = []

    def Get(store, evidence_id):
        """Observe actual owning manifest admission without replacing integrity checks."""

        visited.append(evidence_id)

        return original(store, evidence_id)

    monkeypatch.setattr(LocalEvidenceStore, "Get", Get)

    with pytest.raises(ValueError, match="receipt constraints"):
        LoadHttpsCveSelection(root, forged.evidence_id, receipt.evidence_id)

    assert outcome.raw.evidence_id not in visited, (
        "Over-limit source reached original raw admission"
    )
