# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Versioned mapping documents reject ambiguous, stale, nonfinite, and tampered imports."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fuzzy1337.standards_mapping import (
    MAX_MAPPING_BYTES,
    MAX_MAPPING_RECORDS,
    CandidateBaseline,
    MappingPack,
    MappingReview,
    MappingReviewState,
    StandardIdentity,
)


def test_ExactSchemaRoundTripPreservesSourcesVersionsAndReview():
    """Portable mappings retain exact content references and real supplied review metadata."""

    pack = CandidateBaseline()
    mapping = pack.mappings[0]
    approved = replace(mapping, review=MappingReview(
        MappingReviewState.APPROVED, "synthetic-reviewer", "2026-10-11T12:00:00+00:00",
        mapping.Reference(), "synthetic-decision:one",
    ))
    approved = replace(approved, review=None,
                       provenance=tuple(replace(source, artifact_sha256="c" * 64)
                                        for source in approved.provenance))
    approved = replace(approved, review=MappingReview(
        MappingReviewState.APPROVED, "synthetic-reviewer", "2026-10-11T12:00:00+00:00",
        approved.Reference(), "synthetic-decision:two",
    ))
    pack = replace(pack, mappings=(approved, *pack.mappings[1:]))

    assert set(pack.ToDict()) == {"schema_version", "pack_id", "pack_version", "mappings",
                                  "reference"}, (
        'Portable mappings retain exact content references and real supplied review metadata.'
    )
    assert MappingPack.FromDict(pack.ToDict()) == pack, (
        'Portable mappings retain exact content references and real supplied review metadata.'
    )
    assert MappingPack.FromBytes(pack.ToBytes()).ToBytes() == pack.ToBytes(), (
        'Portable mappings retain exact content references and real supplied review metadata.'
    )
    assert MappingPack.FromBytes(pack.ToBytes()).mappings[0].review == approved.review, (
        'Portable mappings retain exact content references and real supplied review metadata.'
    )


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("schema_version", "1"),
    ("mappings", {}), ("reference", "mapping-pack:" + "f" * 64), ("pack_version", None),
])
def test_PackRejectsUnsupportedSchemasTypesAndTamperedDigest(field, value):
    """No decoding path may guess a version or retain an obsolete pack reference."""

    document = CandidateBaseline().ToDict()
    document[field] = value

    with pytest.raises(ValueError):
        MappingPack.FromDict(document)


@pytest.mark.parametrize("boundary", ["pack", "mapping", "standard", "source", "review"])
@pytest.mark.parametrize("mutation", ["add", "remove"])
def test_EveryObjectBoundaryRejectsUnknownAndMissingFields(boundary, mutation):
    """Exact field sets keep future extension semantics separate from schema-v1 import."""

    pack = CandidateBaseline()
    mapping = pack.mappings[0]
    mapping = replace(mapping, review=MappingReview(
        MappingReviewState.APPROVED, "synthetic-reviewer", "2026-10-11T12:00:00+00:00",
        mapping.Reference(), "synthetic-decision:one",
    ))
    document = replace(pack, mappings=(mapping,)).ToDict()
    selected = {"pack": document, "mapping": document["mappings"][0],
                "standard": document["mappings"][0]["source"],
                "source": document["mappings"][0]["provenance"][0],
                "review": document["mappings"][0]["review"]}[boundary]

    if mutation == "add":
        selected["unsupported"] = "value"

    else:
        selected.pop(next(iter(selected)))

    with pytest.raises(ValueError):
        MappingPack.FromDict(document)


@pytest.mark.parametrize("field,value", [
    ("reference", "mapping:" + "f" * 64), ("relation", "proves-compliance"),
    ("provenance", "source"), ("rationale", "Changed interpretation"),
    ("source", {"family": "cwe", "catalog_version": "4.19", "external_id": "CWE-89"}),
])
def test_MappingRejectsSemanticAndContentAddressTampering(field, value):
    """Changed relation content cannot inherit an earlier stable content reference."""

    document = CandidateBaseline().ToDict()
    document["mappings"][0][field] = value

    with pytest.raises(ValueError):
        MappingPack.FromDict(document)


@pytest.mark.parametrize("payload", [
    b"not json", b"\xff", b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":NaN}', b'{"schema_version":Infinity}', b"[]",
    b"[" * 2000, "json text", b"x" * (MAX_MAPPING_BYTES + 1),
])
def test_ImportRejectsMalformedDuplicateNonfiniteOrUnboundedInput(payload):
    """Pack parsing is strictly local and accepts only bounded unambiguous UTF-8 JSON."""

    with pytest.raises(ValueError):
        MappingPack.FromBytes(payload)


def test_RecordAndByteLimitsApplyBeforeAConsumerPublishesThePack():
    """Large direct constructions cannot evade the finite interchange boundary."""

    pack = CandidateBaseline()
    document = pack.ToDict()
    document["mappings"] = [document["mappings"][0]] * (MAX_MAPPING_RECORDS + 1)

    with pytest.raises(ValueError, match="bounded"):
        MappingPack.FromDict(document)

    mappings = tuple(replace(pack.mappings[0], mapping_id=f"synthetic.mapping-{index}",
                             rationale="x" * 4096) for index in range(300))
    oversized = MappingPack("synthetic", "1", mappings)

    with pytest.raises(ValueError, match="byte limit"):
        oversized.ToBytes()


def test_NewPackFamiliesDoNotChangeSecurityObjectIdentityOrPretendToValidateCatalogExistence():
    """External national/vendor families remain versioned descriptive context."""

    mapping = CandidateBaseline().mappings[0]
    extended = replace(mapping, target=StandardIdentity("national-standard", "2026", "Control-1"))
    pack = MappingPack("synthetic.national", "1", (extended,))

    assert MappingPack.FromBytes(pack.ToBytes()) == pack, (
        'External national/vendor families remain versioned descriptive context.'
    )
    assert json.loads(pack.ToBytes())["mappings"][0]["target"]["external_id"] == "Control-1", (
        'External national/vendor families remain versioned descriptive context.'
    )
