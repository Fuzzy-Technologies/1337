# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline standards mapping identity, attributable review, and bounded selection behavior."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.standards_mapping import (
    MAX_MAPPING_RECORDS,
    BindFindingMappings,
    CandidateBaseline,
    FindingMappingBinding,
    MappingPack,
    MappingRelation,
    MappingReview,
    MappingReviewState,
    MappingSource,
    StandardIdentity,
)

FINDING_REFERENCE = "object:" + "a" * 64


def Reviewed(state: MappingReviewState = MappingReviewState.APPROVED):
    """Build a clearly synthetic review for contract tests, never production approval."""

    mapping = CandidateBaseline().mappings[0]
    review = MappingReview(state, "synthetic-reviewer", "2026-10-11T12:50:00+00:00",
                           mapping.Reference(), "synthetic-decision:one")

    return replace(mapping, review=review)


def test_CandidateBaselineNeverCreatesHumanApproval():
    """The first baseline exposes every source and withholds all unreviewed default bindings."""

    pack = CandidateBaseline()
    cwe = StandardIdentity("cwe", "4.20", "CWE-89")

    assert len(pack.mappings) == 5, (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert all(item.ReviewState() is MappingReviewState.CANDIDATE for item in pack.mappings), (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert all(item.review is None for item in pack.mappings), (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert all(source.artifact_sha256 is None
               for mapping in pack.mappings for source in mapping.provenance), (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert {item.target.family for item in pack.mappings} == {
        "owasp-top10", "owasp-asvs", "capec", "nist-csf", "attack",
    }, (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert BindFindingMappings(pack, FINDING_REFERENCE, cwe) == (), (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    bindings = BindFindingMappings(pack, FINDING_REFERENCE, cwe, include_candidates=True)

    assert len(bindings) == 4, (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert all(item.classifier == cwe and item.pack_reference == pack.Reference()
               and item.finding_reference == FINDING_REFERENCE for item in bindings), (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )
    assert "attack" not in {item.mapping.target.family for item in bindings}, (
        'The first baseline exposes every source and withholds all unreviewed default bindings.'
    )


def test_ExactVersionAndDirectionPreventTransitiveOrHistoricalInference():
    """Lookup preserves upstream catalog versions and never reverses or chains relations."""

    pack = CandidateBaseline()

    assert BindFindingMappings(pack, FINDING_REFERENCE,
                               StandardIdentity("cwe", "4.19", "CWE-89"),
                               include_candidates=True) == (), (
        'Lookup preserves upstream catalog versions and never reverses or chains relations.'
    )
    assert BindFindingMappings(pack, FINDING_REFERENCE,
                               StandardIdentity("owasp-top10", "2021", "A03:2021"),
                               include_candidates=True) == (), (
        'Lookup preserves upstream catalog versions and never reverses or chains relations.'
    )
    capec_bindings = BindFindingMappings(pack, FINDING_REFERENCE,
                                        StandardIdentity("capec", "3.9", "CAPEC-66"),
                                        include_candidates=True)

    assert len(capec_bindings) == 1, (
        'Lookup preserves upstream catalog versions and never reverses or chains relations.'
    )
    assert capec_bindings[0].mapping.target.external_id == "T1190", (
        'Lookup preserves upstream catalog versions and never reverses or chains relations.'
    )


def test_RecordedReviewBindsContentAndChangesOnlyPackRevision():
    """Review updates preserve relation content identity while changing the auditable pack."""

    candidate = CandidateBaseline().mappings[0]
    approved = Reviewed()
    rejected = Reviewed(MappingReviewState.REJECTED)
    original = MappingPack("synthetic", "1", (candidate,))
    reviewed = MappingPack("synthetic", "2", (approved,))

    assert candidate.Reference() == approved.Reference() == rejected.Reference(), (
        'Review updates preserve relation content identity while changing the auditable pack.'
    )
    assert original.Reference() != reviewed.Reference(), (
        'Review updates preserve relation content identity while changing the auditable pack.'
    )
    assert len(BindFindingMappings(reviewed, FINDING_REFERENCE, approved.source)) == 1, (
        'Review updates preserve relation content identity while changing the auditable pack.'
    )
    assert BindFindingMappings(MappingPack("synthetic", "3", (rejected,)),
                               FINDING_REFERENCE, rejected.source, include_candidates=True) == (), (
        'Review updates preserve relation content identity while changing the auditable pack.'
    )


@pytest.mark.parametrize("change", [
    {"rationale": "Changed interpretation"},
    {"target": StandardIdentity("national-standard", "2026", "control-1")},
    {"relation": MappingRelation.CLASSIFIED_BY},
])
def test_ChangingReviewedContentRejectsStaleApproval(change):
    """Content or source changes cannot silently retain an old human decision."""

    mapping = Reviewed()

    with pytest.raises(ValueError, match="stale"):
        replace(mapping, **change)


def test_SourceChangesInvalidateReviewAndMutableInputIsFrozen():
    """A changed source revision is new content, and caller lists cannot mutate a pack."""

    mapping = Reviewed()

    with pytest.raises(ValueError, match="stale"):
        replace(mapping, provenance=(replace(mapping.provenance[0], source_version="new"),))

    mappings = [replace(mapping, review=None)]
    pack = MappingPack("synthetic", "1", mappings)
    mappings.clear()

    assert len(pack.mappings) == 1, (
        'A changed source revision is new content, and caller lists cannot mutate a pack.'
    )

    with pytest.raises(FrozenInstanceError):
        pack.pack_version = "2"


def test_DeclarationOrderDoesNotChangeCanonicalPackIdentity():
    """Consumers get the same bytes and references from equivalent declaration orders."""

    pack = CandidateBaseline()

    assert replace(pack, mappings=tuple(reversed(pack.mappings))).ToBytes() == pack.ToBytes(), (
        'Consumers get the same bytes and references from equivalent declaration orders.'
    )
    mapping = pack.mappings[0]

    assert replace(mapping, provenance=tuple(reversed(mapping.provenance))).Reference() == (
        mapping.Reference()
    ), (
        'Consumers get the same bytes and references from equivalent declaration orders.'
    )


@pytest.mark.parametrize("field,value", [
    ("family", "CWE"), ("catalog_version", " "), ("external_id", "a\tb"),
    ("external_id", "a" * 4097), ("catalog_version", True), ("external_id", "x\x7f"),
    ("external_id", "x\x85"), ("external_id", "x\u202e"), ("external_id", "x\u2028"),
], ids=[
    "uppercase-family", "blank-version", "tab-in-identifier", "oversize-identifier",
    "boolean-version", "del-in-identifier", "c1-in-identifier", "bidi-in-identifier",
    "separator-in-identifier",
])
def test_StandardIdentityRejectsCoercionControlCharactersAndUnboundedText(field, value):
    """Machine identities stay explicit, printable, and bounded."""

    identity = CandidateBaseline().mappings[0].source

    with pytest.raises(ValueError):
        replace(identity, **{field: value})


@pytest.mark.parametrize("url", ["http://example.invalid/doc", "relative/path",
                                  "https://user:password@example.invalid/doc", "https:///doc",
                                  "https://@example.invalid/doc", "https://example.invalid/a b",
                                  "https://example.invalid/a\\b", "https://example.invalid/?key=x",
                                  "https://example.invalid:wrong/doc",
                                  "https://example.invalid:65536/doc"])
def test_SourceRejectsCredentialsOrUnqualifiedUrls(url):
    """Metadata citations cannot embed URL credentials or implicitly resolve relative paths."""

    source = CandidateBaseline().mappings[0].provenance[0]

    with pytest.raises(ValueError):
        replace(source, source_url=url)


@pytest.mark.parametrize("change", [
    {"artifact_sha256": "unknown"}, {"retrieved_at": "2026-10-11"},
    {"publisher": ""}, {"locator": 1},
])
def test_SourceRejectsAbsentAttributionInvalidTimesAndFalseDigests(change):
    """Keep sources attributable and express unpinned bytes with None rather than a fake hash."""

    with pytest.raises(ValueError):
        replace(CandidateBaseline().mappings[0].provenance[0], **change)


def test_SourceAndReviewTimesNormalizeToUtc():
    """Equivalent explicit time offsets serialize as one UTC provenance timestamp."""

    source = MappingSource("synthetic", "1", "https://example.invalid/source", "row:1",
                           "2026-10-11T15:00:00+03:00", "b" * 64)
    review = replace(Reviewed().review, reviewed_at="2026-10-11T15:00:00+03:00")

    assert source.retrieved_at == "2026-10-11T12:00:00.000000+00:00", (
        'Equivalent explicit time offsets serialize as one UTC provenance timestamp.'
    )
    assert review.reviewed_at == source.retrieved_at, (
        'Equivalent explicit time offsets serialize as one UTC provenance timestamp.'
    )


@pytest.mark.parametrize("state", [MappingReviewState.APPROVED, MappingReviewState.REJECTED])
def test_ReviewCannotPrecedeAcquisitionOfAnyCitedSource(state):
    """A claimed decision cannot cover source material retrieved after the decision time."""

    mapping = CandidateBaseline().mappings[0]
    later_source = replace(mapping.provenance[0], retrieved_at="2026-10-11T16:00:00+03:00")
    mapping = replace(mapping, provenance=(later_source, *mapping.provenance[1:]))
    review = MappingReview(
        state, "synthetic-reviewer", "2026-10-11T12:59:59Z",
        mapping.Reference(), "synthetic-decision:too-early",
    )

    with pytest.raises(ValueError, match="precede source acquisition"):
        replace(mapping, review=review)

    valid = replace(mapping, review=replace(review, reviewed_at="2026-10-11T13:00:00Z"))

    assert valid.ReviewState() is state, "A decision at the latest acquisition must stay explicit"


@pytest.mark.parametrize("timestamp", [
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00",
])
def test_SourceAndReviewUtcOverflowRaiseDocumentedValidationError(timestamp):
    """UTC range overflow remains a validation failure at both public metadata boundaries."""

    source = CandidateBaseline().mappings[0].provenance[0]

    with pytest.raises(ValueError, match="UTC datetime range"):
        replace(source, retrieved_at=timestamp)

    with pytest.raises(ValueError, match="UTC datetime range"):
        MappingReview(
            MappingReviewState.APPROVED, "synthetic-reviewer", timestamp,
            CandidateBaseline().mappings[0].Reference(), "synthetic-decision:overflow",
        )


@pytest.mark.parametrize("change", [
    {"state": MappingReviewState.CANDIDATE}, {"state": "approved"}, {"reviewer": ""},
    {"mapping_reference": "mapping:unknown"}, {"decision_reference": ""},
    {"reviewed_at": "invalid"},
])
def test_ReviewRequiresAnExplicitFreshAttributableDecision(change):
    """Approval-shaped strings and unattributed decisions are rejected at construction."""

    with pytest.raises(ValueError):
        replace(Reviewed().review, **change)


@pytest.mark.parametrize("change", [
    {"source": "CWE-89"}, {"target": "CAPEC-66"}, {"relation": "classified-by"},
    {"provenance": ()}, {"provenance": "unknown"}, {"provenance": ("source",)},
    {"review": "approved"}, {"mapping_id": "Invalid ID"},
])
def test_MappingRejectsUntypedOrUnattributedRelations(change):
    """Malformed endpoints, sources, and decisions cannot produce a typed relation."""

    with pytest.raises(ValueError):
        replace(CandidateBaseline().mappings[0], **change)


def test_MappingRejectsSelfEdgesAndDuplicateCitations():
    """Redundant relation declarations cannot create misleading provenance coverage."""

    mapping = CandidateBaseline().mappings[0]

    with pytest.raises(ValueError):
        replace(mapping, target=mapping.source)

    with pytest.raises(ValueError):
        replace(mapping, provenance=(mapping.provenance[0],) * 2)


@pytest.mark.parametrize("mappings", ["unknown", ("mapping",)])
def test_PackRejectsMalformedCollections(mappings):
    """Pack declarations freeze only finite typed relation sequences."""

    with pytest.raises(ValueError):
        MappingPack("synthetic", "1", mappings)


def test_PackRejectsDuplicateIdsAndExcessiveCollections():
    """Pack import cannot reinterpret duplicate identifiers or exceed the record bound."""

    mapping = CandidateBaseline().mappings[0]

    with pytest.raises(ValueError, match="duplicate"):
        MappingPack("synthetic", "1", (mapping,) * 2)

    with pytest.raises(ValueError, match="bounded"):
        MappingPack("synthetic", "1", (mapping,) * (MAX_MAPPING_RECORDS + 1))


@pytest.mark.parametrize("arguments", [
    {"pack": "pack"}, {"classifier": "CWE-89"}, {"include_candidates": 1},
    {"finding_reference": "finding:one"},
    {"finding_reference": "relation:" + "a" * 64},
])
def test_BindingRejectsImplicitTypesOrNonObjectSubjects(arguments):
    """Finding associations must be explicit without coercing caller-controlled metadata."""

    mapping = CandidateBaseline().mappings[0]
    options = {"pack": CandidateBaseline(), "classifier": mapping.source,
               "finding_reference": FINDING_REFERENCE, **arguments}

    with pytest.raises(ValueError):
        BindFindingMappings(**options)


@pytest.mark.parametrize("change", [
    {"finding_reference": "relation:" + "a" * 64}, {"mapping": "mapping"},
    {"classifier": None},
    {"classifier": StandardIdentity("atlas", "2026.09", "AML.T0051")},
    {"pack_reference": "pack:one"},
])
def test_DirectBindingRejectsMismatchedContext(change):
    """Direct binding construction also enforces canonical subject and exact classifier."""

    mapping = CandidateBaseline().mappings[0]
    binding = FindingMappingBinding(FINDING_REFERENCE, mapping.source,
                                    CandidateBaseline().Reference(), mapping)

    with pytest.raises(ValueError):
        replace(binding, **change)
