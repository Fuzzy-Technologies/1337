# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline standards mapping identity, attributable review, and bounded selection behavior."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337 import standards_mapping
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.standards_mapping import (
    MAX_MAPPING_BYTES,
    MAX_MAPPING_RECORDS,
    BindFindingMappings,
    BindFindingObjectMappings,
    CandidateBaseline,
    FindingMappingBinding,
    MappingPack,
    MappingRelation,
    MappingReview,
    MappingReviewState,
    MappingSource,
    ReviewedBaseline,
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


def FindingObject(status=FindingStatus.OPEN):
    """Supply an explicitly synthetic canonical finding without a scanner or live target."""

    provenance = ModelProvenance(
        "synthetic", "run:owned-fixture", "2026-10-13T17:00:00Z", "scope:owned", "target:owned",
        evidence_references=(EvidenceReference(
            "stdout", "blobs/sha256/" + "a" * 64, "a" * 64, "application/json", 2,
        ),),
    )
    subject = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"), {}, (provenance,),
    )
    finding = Finding(
        subject.Reference(), "synthetic.explicit-classifier", "owned-fixture",
        "Synthetic explicitly classified finding", (provenance,),
        severity=FindingSeverity.MEDIUM, confidence=0.75, status=status,
        status_reason=None if status is FindingStatus.OPEN else "Synthetic operator disposition",
    )

    return finding.ToObject("synthetic")


def ResourceOverride(monkeypatch, tmp_path, payload):
    """Replace only the owned resource locator to exercise installed-resource failure paths."""

    resource = tmp_path / "data" / "standards_baseline_0_2_0.json"
    resource.parent.mkdir()
    resource.write_bytes(payload)
    monkeypatch.setattr(standards_mapping, "PackageFiles", lambda package: tmp_path)


def test_ReviewedBaselineRetainsExactVersionsPinsAndActualAccountableDecisions():
    """The distributed baseline covers every required family without synthetic approvals."""

    pack = ReviewedBaseline()
    sources = {source for mapping in pack.mappings for source in mapping.provenance}

    assert pack.pack_id == "fuzzy1337.baseline" and pack.pack_version == "0.2.0", (
        "The reviewed revision must have its own explicit version"
    )
    assert len(pack.mappings) == 6 and len({source.source_url for source in sources}) == 7, (
        "The reviewed baseline lost a selected relation or primary source"
    )
    assert {mapping.target.family for mapping in pack.mappings} == {
        "owasp-top10", "owasp-asvs", "capec", "attack", "atlas", "nist-csf",
    }, "The baseline must include all requested standards families"
    assert all(source.artifact_sha256 is not None for source in sources), (
        "Every reviewed source must retain its actually acquired byte digest"
    )
    assert all(mapping.review is not None
               and mapping.review.reviewer == "Tim55667757"
               and mapping.review.decision_reference.startswith(
                   "https://github.com/Fuzzy-Technologies/1337/issues/68#issuecomment-"
               )
               and mapping.review.mapping_reference == mapping.Reference()
               and mapping.ReviewState() is MappingReviewState.APPROVED
               for mapping in pack.mappings), (
        "An approved baseline relation lost its exact external owner-account decision"
    )
    assert MappingPack.FromBytes(pack.ToBytes()) == pack, (
        "Portable schema-v1 import changed reviewed content or decision provenance"
    )
    assert CandidateBaseline().pack_version == "0.1.0-candidate", (
        "The new reviewed revision must not rewrite the historical candidate API"
    )


@pytest.mark.parametrize("classifier,expected_count", [
    (StandardIdentity("cwe", "4.20", "CWE-89"), 4),
    (StandardIdentity("cwe", "4.20", "CWE-1427"), 1),
    (StandardIdentity("capec", "3.9", "CAPEC-66"), 1),
    (StandardIdentity("cwe", "4.19", "CWE-89"), 0),
    (StandardIdentity("cwe", "4.20", "CWE-79"), 0),
])
def test_RealFindingProjectionRequiresExplicitExactClassifierWithoutTransitiveExpansion(
    classifier, expected_count,
):
    """A canonical finding receives only its selected approved exact-source relations."""

    pack = ReviewedBaseline()
    finding = FindingObject()
    bindings = BindFindingObjectMappings(pack, finding, classifier)

    assert len(bindings) == expected_count, "Implicit version matching or graph expansion occurred"
    assert all(binding.finding_reference == finding.Reference()
               and binding.pack_reference == pack.Reference()
               and binding.mapping.review is not None
               for binding in bindings), (
        "A binding lost its finding, revision, or review attribution"
    )


@pytest.mark.parametrize("status", list(FindingStatus))
def test_MappingInterpretationNeverChangesFindingTriageOrCanonicalIdentity(status):
    """Confirmed, dismissed, and resolved findings retain their owning subsystem decisions."""

    finding = FindingObject(status)
    original = CanonicalModelJson(finding)
    bindings = BindFindingObjectMappings(
        ReviewedBaseline(), finding, StandardIdentity("cwe", "4.20", "CWE-89"),
    )

    assert len(bindings) == 4, "Mapping selection unexpectedly depended on finding disposition"
    assert (
        CanonicalModelJson(finding) == original and Finding.FromObject(finding).status is status
    ), (
        "Descriptive mapping context modified finding identity, evidence, or operator triage"
    )


@pytest.mark.parametrize("invalid", ["reference-only", "wrong-kind", "malformed-finding"])
def test_ObjectBinderRejectsUnvalidatedOrNonFindingObjects(invalid):
    """Opaque references and plausible object kinds cannot bypass finding schema validation."""

    finding = FindingObject()

    if invalid == "reference-only":
        finding = finding.Reference()

    elif invalid == "wrong-kind":
        finding = replace(
            finding, identity=ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
        )

    else:
        object.__setattr__(finding, "attributes", {})

    with pytest.raises(ValueError):
        BindFindingObjectMappings(
            CandidateBaseline(), finding, StandardIdentity("cwe", "4.20", "CWE-89"),
        )


def test_CandidateRejectedAndStaleDecisionsCannotBecomeDefaultFindingBindings():
    """Default consumers require a fresh supplied approval and never synthesize review state."""

    pack = ReviewedBaseline()
    mapping = next(item for item in pack.mappings if item.mapping_id == "sql-injection.top10")
    candidate = replace(mapping, review=None)
    rejected = replace(mapping, review=replace(
        mapping.review, state=MappingReviewState.REJECTED, reviewer="synthetic-reviewer",
        decision_reference="synthetic-decision:rejected",
    ))
    finding = FindingObject()

    for selected in (candidate, rejected):
        selected_pack = MappingPack("synthetic.review-state", "1", (selected,))
        assert BindFindingObjectMappings(selected_pack, finding, mapping.source) == (), (
            "A missing or rejected decision reached the default finding consumer"
        )

    assert len(BindFindingMappings(
        MappingPack("synthetic.candidate", "1", (candidate,)), finding.Reference(),
        mapping.source, include_candidates=True,
    )) == 1, "Explicit exploratory candidate behavior changed"

    with pytest.raises(ValueError, match="stale"):
        replace(mapping, rationale="Synthetic changed interpretation")


def test_LoaderRejectsValidButDifferentPackRatherThanSilentlyAdoptingNewContent(
    monkeypatch, tmp_path,
):
    """Even a correctly recomputed schema digest cannot replace the exact bundled revision."""

    pack = replace(ReviewedBaseline(), pack_version="synthetic-alternate")
    ResourceOverride(monkeypatch, tmp_path, pack.ToBytes())

    with pytest.raises(ValueError, match="baseline content reference mismatch"):
        ReviewedBaseline()


@pytest.mark.parametrize("empty", [False, True])
def test_LoaderExplicitlyRejectsCandidateOrEmptyApprovalSet(monkeypatch, tmp_path, empty):
    """The reviewed API cannot turn a packaging mistake into an empty or candidate fallback."""

    pack = CandidateBaseline()

    if empty:
        pack = replace(pack, mappings=())

    ResourceOverride(monkeypatch, tmp_path, pack.ToBytes())
    monkeypatch.setattr(standards_mapping, "_REVIEWED_BASELINE_REFERENCE", pack.Reference())

    with pytest.raises(ValueError, match="approved mapping decisions"):
        ReviewedBaseline()


def test_LoaderUsesFiniteResourceReadAndRejectsOversizedInput(monkeypatch, tmp_path):
    """Package resources are bounded at the existing interchange limit before JSON parsing."""

    ResourceOverride(monkeypatch, tmp_path, b"x" * (MAX_MAPPING_BYTES + 2))

    with pytest.raises(ValueError, match="bounded bytes"):
        ReviewedBaseline()


def test_LoaderReportsMissingInstalledResourceWithoutCandidateFallback(monkeypatch, tmp_path):
    """A missing wheel resource must be an observable packaging failure."""

    monkeypatch.setattr(standards_mapping, "PackageFiles", lambda package: tmp_path)

    with pytest.raises(FileNotFoundError):
        ReviewedBaseline()
