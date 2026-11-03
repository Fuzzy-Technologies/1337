# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify the distinct selected CVE envelope and immutable original-custody joins."""

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.adapters import AdapterExecution, EvidenceReference, ExecutionState
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence import IntelligenceFeed, IntelligenceRecord, ParseIntelligenceSnapshot
from fuzzy1337.intelligence_cve_remote import (
    IMPORTER_ID,
    RAW_ROLE,
    CveHttpsOutcome,
    CveHttpsSelection,
    CveHttpsSource,
    CveHttpsState,
    SourceAttribution,
)


def Envelope():
    """Build owned synthetic raw attribution and unchanged parser output without any I/O."""

    payload = CanonicalReferenceJson({"dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"cveId": "CVE-1900-0001", "state": "PUBLISHED",
            "dateUpdated": "2026-11-02T12:00:30Z"},
        "containers": {"cna": {"providerMetadata": {"orgId": "owned-cna"},
            "descriptions": [{"lang": "en", "value": "Owned original description"}]}}})
    digest = hashlib.sha256(payload).hexdigest()
    source = CveHttpsSource("a" * 40, "CVE-1900-0001", digest)
    raw = EvidenceRecord(EvidenceReference(RAW_ROLE, f"blobs/sha256/{digest}", digest,
        "application/json", len(payload)), EvidenceProvenance("owned", "scope:owned",
        IMPORTER_ID, "1", None, "2026-11-02T13:00:00Z", "2026-11-02T13:00:01Z"))
    snapshot = ParseIntelligenceSnapshot(payload, IntelligenceFeed.CVE, source.commit,
                                         SourceAttribution(source, raw), raw.reference)

    return CveHttpsSelection(source, raw, snapshot)


def Outcome():
    """Construct exact immutable successful receive facts independently of persisted proof."""

    envelope = Envelope()

    return CveHttpsOutcome(CveHttpsState.SUCCEEDED, envelope.source,
        envelope.raw.provenance.started_at, envelope.raw.provenance.finished_at,
        envelope.raw.reference.size_bytes, True, 1048576, 15.0, "succeeded", 200,
        raw=envelope.raw, envelope=envelope)


def test_EnvelopeKeepsOwnProfileAndUnchangedNestedSnapshotReference():
    """The new envelope carries the exact schema-one snapshot without changing its old decoder."""

    envelope = Envelope()
    document = envelope.ToDict()
    assert document["schema_version"] == document["profile_version"] == 1, (
        "Selected CVE envelope version changed"
    )
    assert document["format_version"] == "5.2", "Selected CVE wire format was generalized"
    assert document["snapshot"]["schema_version"] == 1, "Existing snapshot schema was migrated"
    assert document["snapshot"]["reference"] == envelope.snapshot.Reference(), (
        "Nested snapshot lost its unchanged content reference"
    )
    assert envelope.Reference() == "cve-https-selection:" + hashlib.sha256(
        CanonicalReferenceJson(document),
    ).hexdigest(), "Envelope reference omitted full source/custody/snapshot identity"
    assert envelope.Serialize() == CanonicalReferenceJson(
        {**document, "reference": envelope.Reference()},
    ), "Envelope serialization disagreed with exact canonical content and reference"


@pytest.mark.parametrize("field,value", [("source", {}), ("raw", {}), ("snapshot", {})])
def test_EnvelopeRequiresExactTypedImmutableComponents(field, value):
    """Mutable dictionaries cannot impersonate original source or custody handles."""

    with pytest.raises(ValueError):
        replace(Envelope(), **{field: value})


@pytest.mark.parametrize("field,value", [("role", "intelligence-source"),
    ("role", "epss-https-gzip-source"), ("media_type", "text/plain")])
def test_EnvelopeRefusesForeignRolesAndMedia(field, value):
    """Identical digest and source facts cannot erase artifact domains."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            reference=replace(envelope.raw.reference, **{field: value})))


@pytest.mark.parametrize("field,value", [("source_id", "intelligence-acquisition"),
    ("source_version", "2"), ("tool_version", "foreign"),
    ("invocation_sha256", "b" * 64),
    ("execution", AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1))])
def test_EnvelopeRefusesForeignImporterAndExecutionFacts(field, value):
    """Raw provenance requires the exact receive profile rather than executor attribution."""

    envelope = Envelope()
    provenance = replace(envelope.raw.provenance, **{field: value})

    with pytest.raises(ValueError, match="provenance"):
        replace(envelope, raw=replace(envelope.raw, provenance=provenance))


@pytest.mark.parametrize("field,value", [("commit", "b" * 40),
    ("identifier", "CVE-1900-0002"), ("expected_sha256", "b" * 64)])
def test_EnvelopeBindsExactRequestedCommitCveAndMandatoryPin(field, value):
    """Valid source components still must match all original normalized attribution joins."""

    envelope = Envelope()

    with pytest.raises(ValueError, match="source snapshot"):
        replace(envelope, source=replace(envelope.source, **{field: value}))


@pytest.mark.parametrize("field,value", [("publisher", "foreign"), ("importer_version", "2"),
    ("source_url", "https://evil.invalid/source"), ("license_name", "CC0-1.0"),
    ("license_url", "https://evil.invalid/license"), ("importer_id", "foreign"),
    ("acquired_at", "2026-11-02T14:00:00Z")])
def test_NestedSnapshotAttributionMustExactlyReconstructFromOriginalRaw(field, value):
    """Digest equality cannot substitute full importer, clock or data license attribution."""

    envelope = Envelope()
    attribution = replace(envelope.snapshot.source, **{field: value})
    snapshot = replace(envelope.snapshot, source=attribution)

    with pytest.raises(ValueError, match="source snapshot"):
        replace(envelope, snapshot=snapshot)


def test_NestedSnapshotCannotBorrowDifferentRawRoleOrByteLength():
    """A valid nested snapshot must retain the exact original EvidenceReference."""

    envelope = Envelope()
    evidence = replace(envelope.snapshot.evidence, size_bytes=1)
    snapshot = replace(envelope.snapshot, evidence=evidence)

    with pytest.raises(ValueError, match="source snapshot"):
        replace(envelope, snapshot=snapshot)


@pytest.mark.parametrize("change", ["no-records", "other-id", "rejected", "wrong-feed"])
def test_EnvelopeRequiresOnePublishedCveInTheRequestedFeed(change):
    """Existing schema-one DTOs still require this profile's finite selected source admission."""

    envelope = Envelope()
    snapshot = envelope.snapshot

    if change == "no-records":
        snapshot = replace(snapshot, records=())

    elif change == "wrong-feed":
        record = IntelligenceRecord(IntelligenceFeed.CWE, "CWE-79", snapshot.catalog_version,
            snapshot.records[0].effective_at, {"name": "Owned weakness", "status": "Stable"})
        snapshot = replace(snapshot, feed=IntelligenceFeed.CWE, records=(record,))

    else:
        record = snapshot.records[0]

        if change == "other-id":
            record = replace(record, identifier="CVE-1900-0002")

        else:
            record = replace(record, data={**dict(record.data), "state": "REJECTED"})

        snapshot = replace(snapshot, records=(record,))

    with pytest.raises(ValueError, match="source snapshot"):
        replace(envelope, snapshot=snapshot)


@pytest.mark.parametrize("field,value", [("state", "succeeded"), ("raw_ack", "confirmed"),
    ("snapshot_ack", None), ("receipt_ack", {}), ("body_complete", 1),
    ("received_bytes", True), ("received_bytes", -1), ("received_bytes", 1048577),
    ("started_at", "2026-11-02"), ("finished_at", "2020-11-02T00:00:00.000000+00:00"),
    ("receive_state", []), ("receive_state", "unknown"), ("http_status", True),
    ("http_status", 99), ("http_status", 600), ("http_status", None),
    ("http_status", 201), ("body_complete", False), ("raw", {}),
    ("snapshot_record", {}), ("receipt", {}), ("envelope", {})])
def test_OutcomeRefusesUntypedUnboundedAndContradictoryReceiveFacts(field, value):
    """Frozen outputs cannot adopt mutable aliases or false HTTP completeness facts."""

    with pytest.raises(ValueError):
        replace(Outcome(), **{field: value})


def test_EnvelopeByteBudgetBoundsLargeValidRawProvenance():
    """Provenance strings are not intrinsically short, so final envelope bytes remain bounded."""

    envelope = Envelope()
    raw = replace(envelope.raw, provenance=replace(envelope.raw.provenance,
        scope_reference="a" * (2 * 1024 * 1024)))
    oversized = replace(envelope, raw=raw)

    with pytest.raises(ValueError, match="envelope exceeds"):
        oversized.Serialize()


@pytest.mark.parametrize("maximum,raw_size", [(1, 2), (1048576, 1048577)])
def test_EnvelopeRefusesConsistentTypedRawLengthOutsideItsOwnSourceBudget(maximum, raw_size):
    """All raw/snapshot joins can agree while the independent profile byte ceiling still refuses."""

    envelope = Envelope()
    raw = replace(envelope.raw, reference=replace(envelope.raw.reference, size_bytes=raw_size))
    snapshot = replace(envelope.snapshot, evidence=raw.reference)

    with pytest.raises(ValueError, match="source snapshot"):
        CveHttpsSelection(envelope.source, raw, snapshot, maximum)


def test_EnvelopeReferenceBindsActualRequestLimitsIndependentlyOfReceipt():
    """A valid changed timeout is a different envelope identity before any receipt is consulted."""

    envelope = Envelope()
    altered = replace(envelope, timeout_seconds=14.0)
    assert altered.Reference() != envelope.Reference(), (
        "Envelope identity omitted actual receive limits and allowed receipt self-reconstruction"
    )
