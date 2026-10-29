# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict standalone attack-reference schema, exact round trips, and corruption rejection."""

from __future__ import annotations

import json
from dataclasses import replace

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


def Catalog() -> ReferenceCatalog:
    """Build a small explicitly synthetic namespace catalog with no real identifier claims."""

    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/catalog/1",
        "b" * 64, "Apache-2.0 (synthetic fixture)", "https://example.invalid/LICENSE",
        "2026-10-11T12:00:00Z", "synthetic", "1",
    )

    return ReferenceCatalog(tuple(
        ReferenceRecord(
            ReferenceIdentity(namespace, "SYNTHETIC-1", "fixture-1"), ReferenceKind.BEHAVIOR,
            "Synthetic behavior reference", "No observed behavior or human approval is implied.",
            source,
        ) for namespace in ReferenceNamespace
    ))


def test_StrictSchemaRoundTripIsIndependentPortableAndDeterministic():
    """All namespaces preserve typed attribution and exact content hashes across byte transport."""

    catalog = Catalog()
    document = catalog.ToDict()

    assert set(document) == {"schema_version", "records"}, "Schema-v1 top-level fields drifted"
    assert ReferenceCatalog.FromDict(document) == catalog, "Dictionary round trip lost attribution"
    assert ReferenceCatalog.Deserialize(catalog.Serialize()).Serialize() == catalog.Serialize(), (
        "Exact byte round trip changed identity or content hashes"
    )
    assert ReferenceCatalog.Deserialize(json.dumps(document, indent=2).encode()) == catalog, (
        "Noncanonical whitespace must not change accepted record content"
    )
    assert ReferenceCatalog.Deserialize(ReferenceCatalog().Serialize()) == ReferenceCatalog(), (
        "Empty catalogs must remain valid versioned portable values"
    )

    for record in catalog.records:
        assert set(record.ToDict()) == {
            "identity", "kind", "title", "summary", "source", "reference_id",
            "content_sha256", "review",
        }, "Schema-v1 exact record fields drifted"
        assert record.review is None, "Transport must not invent review attestations"
        assert catalog.Resolve(record.identity.Reference(), record.ContentDigest()) == record, (
            "Namespace-specific round trip changed the pinned attributed record"
        )


@pytest.mark.parametrize("field,value", [
    ("reference_id", "intel:" + "f" * 64), ("reference_id", True),
    ("content_sha256", "f" * 64), ("kind", "unknown"),
    ("title", "Tampered title"), ("identity", {}), ("source", {}),
    ("review", {"reviewer": "invented"}),
])
def test_SchemaRejectsTamperedContentAndUnresolvedTypedValues(field, value):
    """Changed identities/content cannot retain original accepted integrity hashes."""

    document = Catalog().ToDict()
    document["records"][0][field] = value

    with pytest.raises(ValueError):
        ReferenceCatalog.FromDict(document)


@pytest.mark.parametrize("path", [(), ("records", 0), ("records", 0, "identity"),
                                  ("records", 0, "source")])
@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_ExactFieldsRejectUnknownOrMissingMembersAtEveryBoundary(path, mutation):
    """Nested versioned objects do not silently ignore fields or supply missing attribution."""

    document = Catalog().ToDict()
    nested = document

    for part in path:
        nested = nested[part]

    if mutation == "extra":
        nested["unknown_field"] = "ignored?"

    else:
        nested.pop(next(iter(nested)))

    with pytest.raises(ValueError):
        ReferenceCatalog.FromDict(document)


@pytest.mark.parametrize("payload", [
    b'{"schema_version":1,"schema_version":1,"records":[]}',
    b'{"schema_version":1,"records":[{"identity":{"namespace":"capec","namespace":"atlas"}}]}',
    b'{"schema_version":NaN,"records":[]}', b'{"schema_version":Infinity,"records":[]}',
    b'{"schema_version":true,"records":[]}', b'{"schema_version":2,"records":[]}',
    b'{"schema_version":"1","records":[]}', b'{"schema_version":1,"records":{}}',
    b"[]", b"null", b"not JSON", b"\xff", b"[" * 2000,
    "not bytes",
])
def test_ParserRejectsDuplicateKeysNonstandardNumbersAndMalformedPayloads(payload):
    """The real byte parser fails closed before unsupported structure acquires trusted meaning."""

    with pytest.raises(ValueError):
        ReferenceCatalog.Deserialize(payload)


def test_SchemaRejectsDuplicateRecordsAndChangedSourceProvenance():
    """Duplicate identity and source drift fail rather than supersede an earlier reference."""

    document = Catalog().ToDict()
    document["records"].append(document["records"][0])

    with pytest.raises(ValueError, match="duplicate or colliding"):
        ReferenceCatalog.FromDict(document)

    document = Catalog().ToDict()
    document["records"][0]["source"]["artifact_sha256"] = "c" * 64

    with pytest.raises(ValueError, match="canonical content"):
        ReferenceCatalog.FromDict(document)


@pytest.mark.parametrize("source_changes", [
    {"origin": SourceOrigin.EXTERNAL}, {"publisher": "Different synthetic publisher"},
    {"source_url": "https://example.invalid/replaced-catalog"},
    {"artifact_sha256": "c" * 64}, {"license_name": "Changed synthetic fixture license"},
    {"license_url": "https://example.invalid/replaced-license"},
    {"acquired_at": "2026-10-11T12:01:00Z"},
    {"importer_id": "different-synthetic-importer"}, {"importer_version": "2"},
])
def test_RehashedSourceCannotReuseReviewFromAnEarlierAttribution(source_changes):
    """Recomputing public hashes after changing provenance cannot transfer an existing review."""

    record = Catalog().records[0]
    review = ReferenceReview(
        "synthetic-reviewer-not-a-person", "2026-10-11T12:05:00Z", record.ContentDigest(),
    )
    changed = replace(record, source=replace(record.source, **source_changes))
    document = ReferenceCatalog((changed,)).ToDict()
    document["records"][0]["review"] = review.ToDict()

    with pytest.raises(ValueError, match="exact reference content"):
        ReferenceCatalog.Deserialize(json.dumps(document).encode("utf-8"))

    document["records"][0]["review"] = None
    parsed = ReferenceCatalog.Deserialize(json.dumps(document).encode("utf-8"))

    assert parsed.records[0].review is None, "Removing a stale review must not create approval"
    assert parsed.records[0].identity.Reference() == record.identity.Reference(), (
        "Attribution updates must preserve the version-bound external identity"
    )
    assert parsed.records[0].ContentDigest() != record.ContentDigest(), (
        "Every source fact must remain bound to the interpreted content"
    )
