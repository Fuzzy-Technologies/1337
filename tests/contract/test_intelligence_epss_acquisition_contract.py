# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify separate EPSS envelope decoding, strict artifact bounds and original-custody admission."""

from __future__ import annotations

import gzip
import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.intel_references import CanonicalReferenceJson, SourceOrigin
from fuzzy1337.intelligence_epss_acquisition import (
    IMPORTER_ID,
    DecodeSelection,
    DecodeSource,
    EpssAcquiredSelection,
    EpssLocalSource,
    JsonObject,
    ReadBounded,
)
from fuzzy1337.intelligence_epss_selection import ParseEpssSelection
from fuzzy1337.workspace import EvidenceReference


def Envelope():
    """Build typed original synthetic custody without a filesystem or publisher claim."""

    payload = gzip.compress(b"#model_version:synthetic-model,score_date:2026-11-02T12:00:30Z\n"
        b"cve,epss,percentile\nCVE-1900-0001,0.1,0.2\n", mtime=0)
    source = EpssLocalSource(SourceOrigin.SYNTHETIC, "Owned synthetic source",
        "https://example.invalid/source", "Synthetic fixture only",
        "https://example.invalid/LICENSE", ("https://example.invalid/terms",),
        "synthetic-model", "2026-11-02")
    digest = hashlib.sha256(payload).hexdigest()
    raw = EvidenceRecord(EvidenceReference("epss-gzip-source", f"blobs/sha256/{digest}",
        digest, "application/gzip", len(payload)),
        EvidenceProvenance("owned", "scope:owned", IMPORTER_ID, "1", None,
                           "2026-11-02T13:00:00Z", "2026-11-02T13:00:01Z"))
    selection = ParseEpssSelection(payload, ("CVE-1900-0001",),
        model_version=source.model_version, score_date=source.score_date)

    return EpssAcquiredSelection(source, raw, selection)


def test_EnvelopeFamilyBindsOriginalManifestSourceTermsAndUnchangedDecoderProfile():
    """New schema-one envelope nests decoder schema two without masquerading as legacy Intel."""

    envelope = Envelope()
    content = envelope.ToDict()
    assert content["schema_version"] == content["profile_version"] == 1, "Envelope profile changed"
    assert content["selection"]["schema_version"] == 2, "Decoder family was rewritten"
    assert envelope.Reference() == "epss-acquired-selection:" + hashlib.sha256(
        CanonicalReferenceJson(content),
    ).hexdigest(), "Envelope identity omitted source custody facts"
    parsed = JsonObject(envelope.Serialize(), 128 * 1024)
    assert DecodeSource(parsed["source"]) == envelope.source, "Declared source did not round-trip"
    assert DecodeSelection(parsed["selection"]) == envelope.selection, "Selected DTO changed"
    altered = replace(envelope, source=replace(envelope.source,
        terms_urls=("https://example.invalid/changed",)))
    assert altered.Reference() != envelope.Reference(), "Source terms were absent from identity"


@pytest.mark.parametrize("payload,maximum", [(b"{}", 1), ("{}", 10),
    (b"[]", 10), (b'{"same":1,"same":2}', 100), (b'{"number":NaN}', 100),
    (b"\xff", 100)])
def test_JsonProfileRefusesOversizeWrongTypeDuplicateKeysAndNonfiniteConstants(payload, maximum):
    """Structured decoder failures cannot silently normalize adversarial custody records."""

    with pytest.raises((ValueError, UnicodeError)):
        JsonObject(payload, maximum)


@pytest.mark.parametrize("change", [{"terms_urls": "https://example.invalid/terms"},
    {"origin": "unknown"}, {"extra": True}])
def test_DeclaredSourceDecodingRequiresExactExplicitVersionedFields(change):
    """Source declarations cannot adopt defaults, ignored keys or scalar array coercion."""

    document = Envelope().source.ToDict()
    document.update(change)

    with pytest.raises(ValueError):
        DecodeSource(document)


@pytest.mark.parametrize("change", [None, {"requested_ids": None}, {"records": None},
    {"unmatched_ids": None}, {"records": [{"identifier": "CVE-1900-0001"}]},
    {"extra": True}, {"schema_version": True}, {"profile_version": 2}])
def test_SelectedDtoDecodingCannotAdoptUnversionedFieldsOrPermissiveArrays(change):
    """Nested selection preserves its exact independent decoder content contract."""

    document = Envelope().selection.ToDict()

    if change is None:
        document = None

    else:
        document.update(change)

    with pytest.raises(ValueError):
        DecodeSelection(document)


@pytest.mark.parametrize("change", [{"source": None}, {"raw": None}, {"selection": None},
    {"source": "wrong"}])
def test_EnvelopeDirectConstructionRequiresTypedOriginalCustody(change):
    """A detached dictionary cannot masquerade as a validated attributed envelope."""

    with pytest.raises(ValueError):
        replace(Envelope(), **change)


@pytest.mark.parametrize("field,value", [("role", "intelligence-source"),
    ("media_type", "text/csv")])
def test_RawRoleAndMediaCannotAdoptLegacyOrPartialCustody(field, value):
    """Identical content hashes do not erase role or content-format domains."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            reference=replace(envelope.raw.reference, **{field: value})))


@pytest.mark.parametrize("field,value", [("source_id", "foreign"), ("source_version", "2"),
    ("tool_version", "tool"), ("invocation_sha256", "a" * 64)])
def test_RawImporterProvenanceCannotBeManufacturedByRehashedMetadata(field, value):
    """The original acquisition manifest requires exact profile-owned receiver attribution."""

    envelope = Envelope()

    with pytest.raises(ValueError):
        replace(envelope, raw=replace(envelope.raw,
            provenance=replace(envelope.raw.provenance, **{field: value})))


@pytest.mark.parametrize("field,value", [("raw_sha256", "a" * 64), ("raw_size", 1),
    ("model_version", "other"), ("score_date", "2026-11-03")])
def test_EnvelopeRequiresSourceDigestLengthModelAndDayJoins(field, value):
    """Source metadata and original custody cannot disagree with selected decoder facts."""

    envelope = Envelope()

    if field in ("model_version", "score_date"):
        changes = {"source": replace(envelope.source, **{field: value})}

    else:
        changes = {"selection": replace(envelope.selection, **{field: value})}

    with pytest.raises(ValueError):
        replace(envelope, **changes)


def test_RoleBudgetIsCheckedBeforeAnyOwningContentRead():
    """Oversized references fail before a reader can allocate or access selected source bytes."""

    class Store:
        """Sentinel owner that must never receive an over-limit content read."""

        def Read(self, reference):
            """Fail if the preflight boundary delegates its oversized content request."""

            raise AssertionError("Oversized role entered the content reader")

    with pytest.raises(ValueError, match="role-specific"):
        ReadBounded(Store(), Envelope().raw, 1)


@pytest.mark.parametrize("finished,accepted", [("2026-11-02T12:00:29Z", False),
    ("2026-11-02T12:00:30Z", True), ("2026-11-02T12:00:31Z", True)])
def test_SourceScoreClockCannotFollowOriginalObservedAcquisition(finished, accepted):
    """The explicit source clock may equal acquisition completion but cannot be in its future."""

    envelope = Envelope()
    raw = replace(envelope.raw, provenance=replace(envelope.raw.provenance,
        started_at="2026-11-02T12:00:00Z", finished_at=finished))

    if accepted:
        valid = replace(envelope, raw=raw)
        assert valid.selection.effective_at <= raw.provenance.finished_at, "Source time is future"

    else:
        with pytest.raises(ValueError, match="source selection"):
            replace(envelope, raw=raw)
