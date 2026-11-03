# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify separate CWE envelope decoding, strict artifact bounds and original-custody admission."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_cwe_acquisition import (
    IMPORTER_ID,
    CweAcquiredSelection,
    DecodeSelection,
    DecodeSource,
    JsonObject,
    ReadBounded,
)
from fuzzy1337.intelligence_cwe_selection import ParseCweSelection
from fuzzy1337.workspace import EvidenceReference


def Envelope():
    """Build typed original synthetic custody without a filesystem or publisher claim."""

    from tests.integration.test_intelligence_cwe_acquisition_persistence import Request

    request = Request()
    payload = request.payload
    source = request.source
    digest = hashlib.sha256(payload).hexdigest()
    raw = EvidenceRecord(EvidenceReference("cwe-local-zip-source", f"blobs/sha256/{digest}",
        digest, "application/zip", len(payload)),
        EvidenceProvenance("owned", "scope:owned", IMPORTER_ID, "1", None,
                           "2026-11-02T13:00:00Z", "2026-11-02T13:00:01Z"))
    selection = ParseCweSelection(payload, ("CWE-79",),
        catalog_version=source.catalog_version)

    return CweAcquiredSelection(source, raw, selection, 4 * 1024 * 1024)


def test_EnvelopeFamilyBindsOriginalManifestSourceTermsAndUnchangedDecoderProfile():
    """New schema-one envelope nests decoder schema two without masquerading as legacy Intel."""

    envelope = Envelope()
    content = envelope.ToDict()
    assert content["schema_version"] == content["profile_version"] == 1, "Envelope profile changed"
    assert content["selection"]["schema_version"] == 1, "Decoder family was rewritten"
    assert envelope.Reference() == "cwe-local-selection:" + hashlib.sha256(
        CanonicalReferenceJson(content),
    ).hexdigest(), "Envelope identity omitted source custody facts"
    parsed = JsonObject(envelope.Serialize(), 2 * 1024 * 1024)
    assert DecodeSource(parsed["source"]) == envelope.source, "Declared source did not round-trip"
    assert DecodeSelection(parsed["selection"]) == envelope.selection, "Selected DTO changed"
    altered = replace(envelope, max_bytes=envelope.max_bytes - 1)
    assert altered.Reference() != envelope.Reference(), "Effective limit was absent from identity"


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
    {"unmatched_ids": None}, {"records": [{"identifier": "CWE-79"}]},
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


@pytest.mark.parametrize("field,value", [("raw_sha256", "a" * 64), ("raw_size", 1000),
    ("catalog_version", "4.21"), ("max_bytes", 1)])
def test_EnvelopeRequiresSourceDigestLengthCatalogAndLimitJoins(field, value):
    """Source metadata and original custody cannot disagree with selected decoder facts."""

    envelope = Envelope()

    if field == "catalog_version":
        changes = {"source": replace(envelope.source, **{field: value})}

    elif field == "max_bytes":
        changes = {"max_bytes": value}

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




def test_ReconstructedWeaknessCannotAdoptOtherSourceKind():
    """Even otherwise valid selected records retain their non-overridable Weakness kind."""

    document = Envelope().selection.ToDict()
    document["records"][0]["source_kind"] = "Category"

    with pytest.raises(ValueError, match="Weakness"):
        DecodeSelection(document)
