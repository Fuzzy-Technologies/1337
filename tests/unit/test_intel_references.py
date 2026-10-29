# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline reference identity, provenance, review pinning, and validation boundaries."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.intel_references import (
    ReferenceCatalog,
    ReferenceIdentity,
    ReferenceKind,
    ReferenceNamespace,
    ReferenceRecord,
    ReferenceReview,
    ReferenceSource,
    SourceOrigin,
)


def Record(namespace: ReferenceNamespace = ReferenceNamespace.CAPEC) -> ReferenceRecord:
    """Build explicitly synthetic content without asserting a real MITRE identifier or license."""

    return ReferenceRecord(
        ReferenceIdentity(namespace, "SYNTHETIC-EXAMPLE-1", "synthetic-2026.10"),
        ReferenceKind.ATTACK_PATTERN, "Synthetic input pattern",
        "Repository-only synthetic knowledge; this is not an observed vulnerability.",
        ReferenceSource(
            SourceOrigin.SYNTHETIC, "1337 synthetic fixtures",
            "https://example.invalid/synthetic/catalog-v1.json", "a" * 64,
            "Apache-2.0 (repository synthetic fixture only)",
            "https://example.invalid/synthetic/LICENSE",
            "2026-10-11T13:00:00+03:00", "synthetic-importer", "1",
        ),
    )


def Review(record: ReferenceRecord) -> ReferenceReview:
    """Create a labeled fictional fixture attestation, never a human approval claim."""

    return ReferenceReview(
        "synthetic-reviewer-not-a-person", "2026-10-11T10:05:00Z", record.ContentDigest(),
    )


def test_IdentitySeparatesNamespacesVersionsAndPreservesOpaqueCase():
    """External identity is independent of content and installation paths, but not release/case."""

    record = Record()
    identities = [
        record.identity,
        replace(record.identity, namespace=ReferenceNamespace.ATTACK),
        replace(record.identity, namespace=ReferenceNamespace.ATLAS),
        replace(record.identity, catalog_version="synthetic-2026.11"),
        replace(record.identity, external_id="synthetic-example-1"),
    ]

    assert len({identity.Reference() for identity in identities}) == len(identities), (
        "Namespace, release, and external case must remain distinct identity inputs"
    )
    assert ReferenceIdentity.FromDict(record.identity.ToDict()) == record.identity, (
        "Identity round trip changed exact namespace/identifier/version values"
    )
    assert record.identity.Reference().startswith("intel:"), "Reference lost its intel namespace"
    assert replace(record, title="Changed interpretation").identity.Reference() == (
        record.identity.Reference()
    ), "Description changes must preserve identity"
    assert (
        replace(record, title="Changed interpretation").ContentDigest() != record.ContentDigest()
    ), (
        "Description changes must alter the exact content digest"
    )


def test_CatalogFreezesDeterministicOrderAndDetachedOutput():
    """Caller mutation cannot rewrite accepted records or source provenance."""

    records = [Record(namespace) for namespace in ReferenceNamespace]
    catalog = ReferenceCatalog(records)
    backwards = ReferenceCatalog(tuple(reversed(records)))
    records.clear()
    document = catalog.ToDict()
    document["records"].clear()

    assert len(catalog.records) == 3, "Caller mutation changed accepted catalog records"
    assert catalog.Serialize() == backwards.Serialize(), "Catalog ordering is not deterministic"

    with pytest.raises(FrozenInstanceError):
        catalog.records[0].title = "Mutation"

    assert Record().source.acquired_at == "2026-10-11T10:00:00.000000+00:00", (
        "Acquisition timestamp did not normalize the explicit offset to UTC"
    )


def test_ReviewMustBindExactContentAndExplicitAcquisitionOrder():
    """Data parsing never manufactures review; content drift invalidates an existing attestation."""

    record = Record()
    assert record.review is None, "Constructing a record must never manufacture review metadata"
    reviewed = replace(record, review=Review(record))

    assert reviewed.ContentDigest() == record.ContentDigest(), (
        "Review metadata must not alter the exact content it attests"
    )
    assert ReferenceRecord.FromDict(reviewed.ToDict()) == reviewed, (
        "Record round trip lost the explicitly supplied fixture attestation"
    )

    with pytest.raises(ValueError, match="exact reference content"):
        replace(reviewed, title="Edited after attestation")

    with pytest.raises(ValueError, match="precede source acquisition"):
        replace(record, review=replace(Review(record), reviewed_at="2026-10-11T09:59:00Z"))

    with pytest.raises(ValueError, match="ReferenceReview"):
        replace(record, review={"reviewer": "invented"})


def test_ResolutionRequiresCanonicalIdentityAndOptionallyPinnedContent():
    """A consuming interpretation can reject content drift while using a stable identity."""

    record = Record()
    catalog = ReferenceCatalog((record,))

    assert catalog.Resolve(record.identity.Reference(), record.ContentDigest()) == record, (
        "Pinned resolution did not return the exact attributed record"
    )
    assert catalog.Resolve(record.identity.Reference()) == record, (
        "Identity-only resolution returned another record"
    )

    with pytest.raises(ValueError, match="pinned revision"):
        catalog.Resolve(record.identity.Reference(), "f" * 64)

    with pytest.raises(KeyError):
        catalog.Resolve("intel:" + "f" * 64)

    with pytest.raises(ValueError, match="canonical intel"):
        catalog.Resolve("object:" + "f" * 64)

    with pytest.raises(ValueError, match="digest"):
        catalog.Resolve(record.identity.Reference(), "not-a-digest")


@pytest.mark.parametrize("fields", [
    {"namespace": "capec"}, {"external_id": ""}, {"catalog_version": " "},
    {"external_id": "a" * 129}, {"external_id": " identifier"},
    {"catalog_version": "one\nsecond"}, {"external_id": "bad\x7f"},
    {"external_id": "\ud800"}, {"catalog_version": True},
])
def test_IdentityRejectsUntypedOrInvalidText(fields):
    """Malformed and coercible identifiers cannot acquire an accepted canonical reference."""

    with pytest.raises(ValueError):
        replace(Record().identity, **fields)


@pytest.mark.parametrize("fields", [
    {"origin": "external"}, {"publisher": ""}, {"artifact_sha256": "A" * 64},
    {"artifact_sha256": None}, {"license_name": " "}, {"importer_id": "a\t"},
    {"source_url": "http://example.invalid/catalog"},
    {"source_url": "https://user:secret@example.invalid/catalog"},
    {"source_url": "https://example.invalid/catalog?token=secret"},
    {"source_url": "https://example.invalid/catalog#fragment"},
    {"source_url": "https://example.invalid:wrong/catalog"},
    {"source_url": "https://[broken/catalog"},
    {"source_url": "https:///catalog"},
    {"license_url": "https://example.invalid/a b"},
    {"license_url": "https://example.invalid/a\\b"},
    {"acquired_at": "2026-10-11"}, {"acquired_at": "not-a-date"},
    {"acquired_at": "0001-01-01T00:00:00+01:00"},
])
def test_SourceRejectsMalformedAttributionAndUnsafeLocators(fields):
    """Provenance refuses implicit versions, credentials, malformed URL syntax, and naive times."""

    with pytest.raises(ValueError):
        replace(Record().source, **fields)


@pytest.mark.parametrize("fields", [
    {"identity": "synthetic"}, {"kind": "behavior"}, {"source": {}},
    {"title": ""}, {"summary": "a" * 8193},
])
def test_RecordRejectsInvalidTypedBoundaries(fields):
    """Invalid reference content cannot enter an immutable catalog."""

    with pytest.raises(ValueError):
        replace(Record(), **fields)


@pytest.mark.parametrize("fields", [
    {"schema_version": 2}, {"schema_version": True}, {"schema_version": "1"},
    {"records": "text"}, {"records": ({},)},
])
def test_CatalogRejectsCoercibleVersionsAndUntypedCollections(fields):
    """Schema and collection validation never silently coerce values into supported state."""

    with pytest.raises(ValueError):
        ReferenceCatalog(**fields)


def test_CatalogRejectsDuplicateIdentityAndHashCollisions(monkeypatch):
    """Duplicate keys and simulated hash collisions never overwrite earlier attributed records."""

    record = Record()

    with pytest.raises(ValueError, match="duplicate or colliding"):
        ReferenceCatalog((record, record))

    with pytest.raises(ValueError, match="duplicate or colliding"):
        ReferenceCatalog((record, replace(record, summary="Conflicting interpretation")))

    monkeypatch.setattr(ReferenceIdentity, "Reference", lambda self: "intel:" + "a" * 64)

    with pytest.raises(ValueError, match="duplicate or colliding"):
        ReferenceCatalog((record, Record(ReferenceNamespace.ATLAS)))


def test_CatalogEnforcesBoundOnRuntimeAndSerializedPayloads(monkeypatch):
    """The supported byte limit applies before parsing and after direct runtime construction."""

    monkeypatch.setattr("fuzzy1337.intel_references.MAX_CATALOG_BYTES", 10)

    with pytest.raises(ValueError, match="byte limit"):
        ReferenceCatalog((Record(),))

    with pytest.raises(ValueError, match="bounded bytes"):
        ReferenceCatalog.Deserialize(b" " * 11)


def test_ExternalSourceDoesNotAcquireReviewOrOfficialAuthority():
    """Declaring an external source does not verify existence, publisher, license, or behavior."""

    record = replace(Record(), source=replace(Record().source, origin=SourceOrigin.EXTERNAL))
    catalog = ReferenceCatalog.Deserialize(ReferenceCatalog((record,)).Serialize())

    assert catalog.records[0].review is None, "An external source label must not confer approval"
    assert catalog.records[0].source.origin is SourceOrigin.EXTERNAL, (
        "Transport changed the caller-supplied source origin"
    )
    assert not hasattr(catalog.records[0], "evidence"), "Taxonomy records must not infer evidence"
    assert not hasattr(catalog.records[0], "infrastructure_relations"), (
        "Reference knowledge must remain separate from infrastructure relations"
    )
