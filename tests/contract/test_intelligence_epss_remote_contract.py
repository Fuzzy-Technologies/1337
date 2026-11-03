# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify distinct HTTPS EPSS envelopes and strict immutable custody joins."""

import gzip
import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.intel_references import CanonicalReferenceJson, SourceOrigin
from fuzzy1337.intelligence_epss_acquisition import EpssAcquiredSelection, EpssLocalSource
from fuzzy1337.intelligence_epss_remote import (
    IMPORTER_ID,
    RAW_ROLE,
    EpssHttpsOutcome,
    EpssHttpsSelection,
    EpssHttpsSource,
    EpssHttpsState,
)
from fuzzy1337.intelligence_epss_selection import ParseEpssSelection


def Envelope():
    """Build synthetic original receive custody without a filesystem or real network request."""

    payload = gzip.compress(b"#model_version:model,score_date:2026-11-02T12:00:30Z\n"
                           b"cve,epss,percentile\nCVE-1900-0001,0.1,0.2\n", mtime=0)
    digest = hashlib.sha256(payload).hexdigest()
    source = EpssHttpsSource("a" * 40, "2026-11-02", "model", digest)
    raw = EvidenceRecord(EvidenceReference(RAW_ROLE, f"blobs/sha256/{digest}", digest,
        "application/gzip", len(payload)), EvidenceProvenance("owned", "scope:owned",
        IMPORTER_ID, "1", None, "2026-11-02T13:00:00Z", "2026-11-02T13:00:01Z"))
    selected = ParseEpssSelection(payload, ("CVE-1900-0001",), model_version="model",
                                  score_date="2026-11-02")

    return EpssHttpsSelection(source, raw, selected)


def Outcome():
    """Build exact immutable terminal facts independent of storage acknowledgement."""

    envelope = Envelope()

    return EpssHttpsOutcome(EpssHttpsState.SUCCEEDED, envelope.source,
        envelope.selection.requested_ids, envelope.raw.provenance.started_at,
        envelope.raw.provenance.finished_at, envelope.raw.reference.size_bytes, True,
        4194304, 15.0, "succeeded", 200, raw=envelope.raw, envelope=envelope)


def test_EnvelopeKeepsOwnProfileReferenceImporterAndNestedUnchangedDecoder():
    """HTTPS identity cannot collide with the local family even for the exact same source bytes."""

    envelope = Envelope()
    document = envelope.ToDict()
    assert document["schema_version"] == document["profile_version"] == 1
    assert document["profile"] == "epss-https-selected-acquisition"
    assert document["selection"]["schema_version"] == 2
    assert envelope.Reference() == "epss-https-selection:" + hashlib.sha256(
        CanonicalReferenceJson(document),
    ).hexdigest()
    assert envelope.Serialize() == CanonicalReferenceJson(
        {**document, "reference": envelope.Reference()},
    )
    altered = replace(envelope, source=replace(envelope.source, commit="b" * 40))
    assert altered.Reference() != envelope.Reference()


@pytest.mark.parametrize("field,value", [("source", {}), ("raw", {}), ("selection", {})])
def test_EnvelopeRequiresExactTypedOriginalSourceRawAndSelection(field, value):
    """Detached mutable aliases cannot become original acquisition handles."""

    with pytest.raises(ValueError):
        replace(Envelope(), **{field: value})


@pytest.mark.parametrize("field,value", [("role", "epss-gzip-source"),
    ("media_type", "text/csv")])
def test_EnvelopeRefusesLocalRolesAndForeignMedia(field, value):
    """Matching source digests never erase separate artifact domains."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            reference=replace(envelope.raw.reference, **{field: value})))


@pytest.mark.parametrize("field,value", [("source_id", "epss-selection-acquisition"),
    ("source_version", "2"), ("tool_version", "foreign"),
    ("invocation_sha256", "b" * 64), ("execution", "typed-execution")])
def test_EnvelopeRefusesForeignImporterAndUnrelatedExecutionFacts(field, value):
    """Only original profile-owned receive provenance is admitted into this envelope family."""

    envelope = Envelope()

    if field == "execution":
        from fuzzy1337.adapters import AdapterExecution, ExecutionState

        value = AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1)

    provenance = replace(envelope.raw.provenance, **{field: value})

    with pytest.raises(ValueError, match="provenance"):
        replace(envelope, raw=replace(envelope.raw, provenance=provenance))


@pytest.mark.parametrize("field,value", [("expected_sha256", "b" * 64),
    ("model_version", "other"), ("score_date", "2026-11-03")])
def test_EnvelopeBindsMandatoryPinExpectedModelAndCalendarDay(field, value):
    """Valid-looking source metadata still must match actual original selection facts."""

    envelope = Envelope()

    with pytest.raises(ValueError, match="source selection"):
        replace(envelope, source=replace(envelope.source, **{field: value}))


@pytest.mark.parametrize("field,value", [("raw_sha256", "b" * 64), ("raw_size", 1)])
def test_EnvelopeBindsOriginalDigestAndLength(field, value):
    """A selection cannot borrow a different original raw artifact."""

    envelope = Envelope()

    with pytest.raises(ValueError, match="source selection"):
        replace(envelope, selection=replace(envelope.selection, **{field: value}))


@pytest.mark.parametrize("field,value", [("requested_ids", []), ("state", "succeeded"),
    ("raw_ack", "confirmed"), ("selection_ack", None), ("receipt_ack", {}),
    ("body_complete", 1), ("received_bytes", True), ("received_bytes", -1),
    ("received_bytes", 4194305), ("started_at", "2026-11-02"),
    ("finished_at", "2020-11-02T00:00:00.000000+00:00"),
    ("receive_state", []), ("receive_state", "unknown"), ("http_status", True),
    ("http_status", 99), ("http_status", 600), ("http_status", None),
    ("http_status", 201), ("body_complete", False),
    ("raw", {}), ("selection_record", {}), ("receipt", {}), ("envelope", {})])
def test_OutcomeRejectsUntypedUnboundedOrContradictoryObservedFacts(field, value):
    """Frozen returned facts cannot be replaced with mutable state or false network completeness."""

    with pytest.raises(ValueError):
        replace(Outcome(), **{field: value})


def test_LocalEnvelopeCannotBeDirectlyRelabeledIntoHttpsFamily():
    """The local source type and importer remain semantically distinct from the HTTPS profile."""

    remote = Envelope()
    source = EpssLocalSource(SourceOrigin.SYNTHETIC, "Fixture", "https://example.invalid/source",
        "Fixture only", "https://example.invalid/LICENSE", ("https://example.invalid/terms",),
        "model", "2026-11-02", remote.source.expected_sha256)
    raw = replace(remote.raw, reference=replace(remote.raw.reference, role="epss-gzip-source"),
        provenance=replace(remote.raw.provenance, source_id="epss-selection-acquisition"))
    local = EpssAcquiredSelection(source, raw, remote.selection)

    with pytest.raises(ValueError):
        EpssHttpsSelection(local.source, local.raw, local.selection)


def test_EnvelopeBudgetBoundsLargeValidProvenanceBeforeSerializationPublication():
    """The owning provenance grammar has no text cap, while this envelope remains byte-bounded."""

    envelope = Envelope()
    provenance = replace(envelope.raw.provenance, scope_reference="a" * (128 * 1024))
    oversized = replace(envelope, raw=replace(envelope.raw, provenance=provenance))

    with pytest.raises(ValueError, match="envelope exceeds"):
        oversized.Serialize()
