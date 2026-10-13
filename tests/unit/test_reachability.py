# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Disprove unsafe offline reachability proof, admission and bounded-search assumptions."""

from __future__ import annotations

import copy
import hashlib
import json
import traceback
from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceStorageError,
    LocalEvidenceStore,
)
from fuzzy1337.model import (
    MAX_MODEL_BYTES,
    CanonicalModelJson,
    LocalModelStore,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.reachability import (
    Confidence,
    JsonScalarSize,
    ModelSnapshotSize,
    ProjectReachability,
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
    SearchReachabilityPaths,
)
from tests.contract.reachability_fixture import Fixture
from tests.contract.test_reachability_contract import Projection


@pytest.fixture
def fixture(tmp_path):
    """Persist independent source/model fixtures without constructing derived output records."""

    return Fixture.Create(tmp_path / "workspace")


def Read(fixture, records, **changes):
    """Exercise the public owning read with explicit independent version/context/time inputs.

    Args:
        fixture: Existing independent source producer fixture.
        records: Explicit source assessments.
        changes: Intentional supported or hostile public argument overrides.

    Returns:
        Public immutable source claims after actual owning verification.
    """

    fields = {"workspace_root": fixture.root,
        "expected_model_version": ReachabilityModelVersion(**fixture.Version()),
        "context_reference": fixture.graph["context_reference"],
        "scope_reference": fixture.graph["scope_reference"], "at": fixture.graph["query_at"],
        **changes}

    return ReadReachabilityClaims(fixture.model, records, **fields)


def Edge(projection, fixture, alias="source-portal"):
    """Identify one output transition by its independent existing core reference.

    Args:
        projection: Public derived graph.
        fixture: Independent original core model.
        alias: Explicit symbolic relation alias.

    Returns:
        Attributed transition output.
    """

    reference = fixture.relations[alias].Reference()

    return next(item for item in projection.transitions if item.relation_reference == reference)


@pytest.mark.parametrize("state,value", [
    ("UNKNOWN", 0), ("UNKNOWN", 0.0), ("POTENTIAL", 0.40), ("POTENTIAL", 0.69),
    ("LIKELY", 0.70), ("LIKELY", 0.89), ("CONFIRMED", 0.90), ("CONFIRMED", 1),
    ("BLOCKED", 0.90), ("BLOCKED", 1.0),
])
def test_LiteralInclusiveConfidenceEndpointsRemainSourceEstimates(state, value):
    """Endpoint values survive unchanged without scoring, coercion or probability composition."""

    actual = Confidence(value, ReachabilityState(state))
    assert actual == value and type(actual) is type(value), "Exact supplied numeric value changed"


@pytest.mark.parametrize("value", [True, False, "0.9", None, float("nan"), float("inf"),
    -float("inf"), -1, 0.899999, 1.00001, 10 ** 10000], ids=["true", "false", "text", "none",
    "nan", "infinity", "negative-infinity", "negative", "below-band", "above-band", "huge-int"])
def test_ConfidenceRefusesInvalidValuesBeforeOverflowOrRounding(value):
    """Huge direct integers and nonfinite/coerced inputs raise sanitized ValueError only."""

    with pytest.raises(ValueError):
        Confidence(value, ReachabilityState.CONFIRMED)


@pytest.mark.parametrize("state,value", [("POTENTIAL", 0.695), ("LIKELY", 0.895),
    ("UNKNOWN", 0.01), ("BLOCKED", 0.89999)])
def test_InterBandConfidenceGapsAreNotSilentlyRounded(state, value):
    """The independent profile's literal closed intervals reject values in every gap."""

    with pytest.raises(ValueError):
        Confidence(value, ReachabilityState(state))


@pytest.mark.parametrize("field", ["max_depth", "max_paths", "max_work", "max_frontier"])
@pytest.mark.parametrize("value", [True, 0, -1, 1.0, "1", None, 10 ** 10000],
    ids=["boolean", "zero", "negative", "float", "text", "none", "huge-integer"])
def test_QueryLimitsRefuseCoercionAndNonpositiveOrHugeCounts(field, value):
    """All resource controls use exact bounded positive integers, including direct API calls."""

    with pytest.raises(ValueError):
        ReachabilityLimits(**{field: value})


@pytest.mark.parametrize("field,value", [("max_depth", 33), ("max_paths", 257),
    ("max_work", 20001), ("max_frontier", 4097)])
def test_QueryLimitHardMaximumCannotBeExceeded(field, value):
    """Every inclusive public maximum refuses its first unsupported successor value."""

    with pytest.raises(ValueError):
        ReachabilityLimits(**{field: value})


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 2),
    ("revision", True), ("revision", -1), ("revision", "1"), ("snapshot_sha256", "private"),
    ("workspace_id", ""), ("snapshot_sha256", "A" * 64)])
def test_CompleteModelVersionRejectsCoercedOrMalformedFields(fixture, field, value):
    """Full model pins reject bool schemas/revisions and noncanonical snapshot digests."""

    with pytest.raises(ValueError):
        ReachabilityModelVersion(**{**fixture.Version(), field: value})


@pytest.mark.parametrize("raw", [b"{", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}',
    b'{"x":1e999}', b'{"x":"\\ud800"}', b'\xff', b"[" * 2000,
    b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}',
    b'{"x":[' + b'0,' * 8000 + b'0]}', b" " * (256 * 1024 + 1)], ids=["syntax",
    "top-level", "duplicate-key", "nonfinite", "overflow", "surrogate", "utf8",
    "parser-depth", "profile-depth", "profile-nodes", "profile-bytes"])
def test_StrictHostileJsonCannotProducePartialClaimsOrPrivateTracebacks(fixture, raw):
    """Strict whole-input JSON budgets refuse before any partial verified output is returned."""

    record = fixture.Assessment(raw=raw)
    with pytest.raises(ValueError) as failure:
        Read(fixture, (record,))

    rendered = "".join(traceback.format_exception(failure.value))
    assert "synthetic-private-source-value" not in rendered, "Raw source appeared in diagnostics"


@pytest.mark.parametrize("case", ["profile-bool", "profile-version", "kind", "envelope-extra",
    "envelope-missing", "version-extra", "context", "scope", "workspace", "state",
    "claim-extra", "confidence-bool", "confidence-band", "confidence-huge", "rule-wrong-state",
    "rule-missing", "rule-unsafe", "basis-extra", "basis-ref", "basis-duplicate",
    "manifest-ref", "manifest-duplicate", "basis-count", "controls-count", "blocked-no-control",
    "nonblocked-control", "duplicate-control", "duplicate-declaration"])
def test_ExactDeclarationGrammarRefusesSubstitutionAndExtensions(fixture, case):
    """Adversarial strict source fields cannot borrow unsupported states, proof or scope meaning."""

    claim = fixture.Declaration("source-portal")
    envelope = fixture.Envelope([claim])
    private = "synthetic-private-source-value"

    if case == "profile-bool":
        envelope["profile_version"] = True
    elif case == "profile-version":
        envelope["profile_version"] = 2
    elif case == "kind":
        envelope["assessment_kind"] = private
    elif case == "envelope-extra":
        envelope[private] = private
    elif case == "envelope-missing":
        del envelope["claims"]
    elif case == "version-extra":
        envelope["model_version"][private] = private
    elif case in {"context", "scope", "workspace"}:
        if case == "workspace":
            envelope["model_version"]["workspace_id"] = private
        else:
            envelope[case + "_reference"] = private
    elif case == "state":
        claim["state"] = private
    elif case == "claim-extra":
        claim[private] = private
    elif case == "confidence-bool":
        claim["confidence"] = True
    elif case == "confidence-band":
        claim["confidence"] = 0.899999
    elif case == "confidence-huge":
        claim["confidence"] = 10 ** 300
    elif case == "rule-wrong-state":
        claim["inference_rule"] = "rule.synthetic"
    elif case in {"rule-missing", "rule-unsafe"}:
        claim.update(state="LIKELY", confidence=0.8,
                     inference_rule=None if case == "rule-missing" else "unsafe rule\n")
    elif case == "basis-extra":
        claim["basis"][0][private] = private
    elif case == "basis-ref":
        claim["basis"][0]["observation_reference"] = private
    elif case == "basis-duplicate":
        claim["basis"].append(copy.deepcopy(claim["basis"][0]))
    elif case == "manifest-ref":
        claim["basis"][0]["evidence_manifest_ids"] = [private]
    elif case == "manifest-duplicate":
        claim["basis"][0]["evidence_manifest_ids"] *= 2
    elif case == "basis-count":
        claim["basis"] *= 17
    elif case == "controls-count":
        claim.update(state="BLOCKED", confidence=1.0,
            blocking_controls=[{"control_reference": fixture.objects["key-control"].Reference(),
                                **fixture.Basis("key-control")}] * 17)
    elif case == "blocked-no-control":
        claim.update(state="BLOCKED", confidence=1.0)
    elif case == "nonblocked-control":
        claim["blocking_controls"] = [{
            "control_reference": fixture.objects["key-control"].Reference(),
            **fixture.Basis("key-control")}]
    elif case == "duplicate-control":
        claim = fixture.Declaration("source-portal", "BLOCKED", 1.0,
                                    controls=("key-control", "key-control"))
        envelope["claims"] = [claim]
    elif case == "duplicate-declaration":
        envelope["claims"].append(copy.deepcopy(claim))

    record = fixture.Assessment(envelope)
    with pytest.raises(ValueError) as failure:
        Read(fixture, (record,))

    assert private not in "".join(traceback.format_exception(failure.value)), (
        "Unsupported source field appeared in full traceback"
    )


@pytest.mark.parametrize("case", ["role", "media", "format", "workspace", "scope",
                                 "invocation", "execution"])
def test_AssessmentManifestContextAndFormatMustMatchExactly(fixture, case):
    """Raw grammar cannot substitute the separately acquired immutable assessment provenance."""

    changes = {"role": {"role": "different-role"}, "media": {"media_type": "text/plain"},
        "format": {"source_version": "2"}, "workspace": {"workspace_id": "different-workspace"},
        "scope": {"scope_reference": "scope:different"},
        "invocation": {"invocation_sha256": "0" * 64},
        "execution": {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.0)}}
    record = fixture.Assessment(**changes[case])

    with pytest.raises(ValueError):
        Read(fixture, (record,))


@pytest.mark.parametrize("field,value", [("source_id", "different-source"),
    ("tool_version", "different-tool"), ("scope_reference", "scope:different"),
    ("finished_at", "2026-10-13T00:00:00.500000Z"),
    ("execution", AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.0))])
def test_SupportProvenanceCannotBorrowAnotherSourceToolTimeOrOutcome(fixture, field, value):
    """The same original blob with another immutable manifest remains different attributed proof."""

    original = fixture.records["source-portal"]
    store = LocalEvidenceStore(fixture.root / "evidence")
    changed = store.Put(store.Read(original.reference), original.reference.role,
        original.reference.media_type, replace(original.provenance, **{field: value}))
    claim = fixture.Declaration("source-portal")
    claim["basis"][0]["evidence_manifest_ids"] = [changed.evidence_id]
    record = fixture.Assessment(fixture.Envelope([claim]))

    with pytest.raises(ValueError):
        Read(fixture, (record,))


def test_FormatVersionAndProviderVersionRemainDistinctPinnedAttribution(fixture):
    """Evidence format-v17 and model/provider review-tool-v3 legitimately match separate fields."""

    record = fixture.Assessment()
    claims = Read(fixture, (record,))
    claim = claims.claims[0]
    proof = claim.basis[0]
    assert not claim.reasons, "Separate evidence format/provider versions caused false refusal"
    assert proof.records[0].provenance.source_version == "format-v17", "Format version dropped"
    assert (proof.records[0].provenance.tool_version
            == proof.observation.provenance.provider_version), (
        "Tool version no longer matches the exact retained provider version"
    )
    assert proof.observation.Reference() == proof.observation_reference, "Observation changed"
    assert claim.assessment == record, "Assessment source attribution was lost"


@pytest.mark.parametrize("case,reason", [("empty-basis", "missing-basis"),
    ("missing-observation", "missing-basis"), ("empty-manifests", "missing-evidence"),
    ("stale-model", "stale-model"), ("stale-support", "stale-support"),
    ("stale-assessment", "stale-assessment")])
def test_MissingOrStaleProofQuarantinesTheTransition(fixture, case, reason):
    """Unusable declarations remain attributed UNKNOWN without a manufactured effective estimate."""

    claim = fixture.Declaration("source-portal")
    envelope = fixture.Envelope([claim])
    changes = {}
    if case == "empty-basis":
        claim["basis"] = []
    elif case == "missing-observation":
        claim["basis"][0]["observation_reference"] = "observation:" + "0" * 64
    elif case == "empty-manifests":
        claim["basis"][0]["evidence_manifest_ids"] = []
    elif case == "stale-model":
        envelope["model_version"]["snapshot_sha256"] = "0" * 64
    elif case in {"stale-support", "stale-assessment"}:
        changes["at"] = "2026-10-13T01:00:04Z"
    record = fixture.Assessment(envelope)
    claims = Read(fixture, (record,), **changes)
    graph = ProjectReachability(fixture.model, (fixture.relations["source-portal"].Reference(),),
        claims, expected_model_version=claims.model_version)
    edge = Edge(graph, fixture)
    assert edge.state is ReachabilityState.UNKNOWN and reason in edge.reasons, "Unusable proof used"
    assert edge.claims[0].confidence == 0.99, "Original source confidence was silently deleted"
    path = SearchReachabilityPaths(graph, fixture.model, fixture.objects["source"].Reference(),
                                   fixture.objects["portal"].Reference()).paths[0]
    assert path.confidence_estimates[0].effective_confidence is None, "Unknown estimate was usable"


@pytest.mark.parametrize("time,reason", [("2026-10-13T00:00:04Z", "future-support"),
                                       ("2026-10-13T00:00:01.500000Z", "time-order")])
def test_FutureOrLateSupportCannotValidateAnEarlierAssessment(tmp_path, time, reason):
    """Measurable source times govern admission without inventing a model creation timestamp."""

    fixture = Fixture.Create(tmp_path / "workspace", support_time=time)
    projection = Projection(fixture, (fixture.Assessment(),))
    edge = Edge(projection, fixture)
    assert edge.state is ReachabilityState.UNKNOWN and reason in edge.reasons, "Temporal proof used"


@pytest.mark.parametrize("state", [ExecutionState.FAILED, ExecutionState.TIMED_OUT,
                                 ExecutionState.CANCELLED])
def test_FailedAcquisitionRemainsUnknownRatherThanSuccessfulProof(tmp_path, state):
    """Every terminal failure remains explicitly unusable despite a supplied confirmed label."""

    outcome = AdapterExecution(state, 1 if state is ExecutionState.FAILED else None, 0.0)
    fixture = Fixture.Create(tmp_path / "workspace", execution=outcome)
    edge = Edge(Projection(fixture, (fixture.Assessment(),)), fixture)
    assert edge.state is ReachabilityState.UNKNOWN and "failed-support" in edge.reasons, (
        "Failed acquisition was promoted to confirmed proof"
    )


def test_ExactReplayDeduplicatesButIndependentProvenanceNeverDisappears(fixture):
    """Deduplicate identical manifest replay while retaining another actor's exact attribution."""

    first = fixture.Assessment()
    second = fixture.Assessment(source_id="second-reachability-attester")
    claims = Read(fixture, (first, first, second))
    assert len(claims.claims) == 2, "Replay or distinct attribution was incorrectly collapsed"
    assert len({claim.claim_reference for claim in claims.claims}) == 2, "Claim identities collided"
    assert {claim.assessment.evidence_id for claim in claims.claims} == {
        first.evidence_id, second.evidence_id,
    }, "Exact source manifests were not retained"


def test_OneStaleSourceCannotBeHiddenByAnotherCurrentSource(fixture):
    """Conservative admission keeps every source and quarantines the entire affected hop."""

    stale_envelope = fixture.Envelope([fixture.Declaration("source-portal")])
    stale_envelope["model_version"]["snapshot_sha256"] = "0" * 64
    stale = fixture.Assessment(stale_envelope)
    fresh = fixture.Assessment(source_id="second-reachability-attester")
    projection = Projection(fixture, (stale, fresh))
    edge = Edge(projection, fixture)
    assert edge.state is ReachabilityState.UNKNOWN, "Current source concealed stale supplied proof"
    assert len(edge.claims) == 2 and "stale-model" in edge.reasons, "Unusable source disappeared"


@pytest.mark.parametrize("kind", ["blob", "manifest", "missing"])
def test_ActualEvidenceIntegrityFailureReturnsNoPartialClaimSet(fixture, kind):
    """Actual stored proof bytes and manifests require owning integrity verification."""

    record = fixture.Assessment()
    support = fixture.records["source-portal"]
    if kind == "blob":
        (fixture.root / "evidence" / support.reference.locator).write_bytes(b"corrupted-source")
    else:
        path = fixture.root / "evidence/records" / (support.evidence_id[7:] + ".json")
        if kind == "manifest":
            path.write_bytes(b'{"private":"synthetic-private-source-value"}')
        else:
            path.unlink()
    with pytest.raises(EvidenceError) as failure:
        Read(fixture, (record,))

    rendered = "".join(traceback.format_exception(failure.value))
    assert "synthetic-private-source-value" not in rendered, (
        "Corrupted raw proof or path leaked through an owning exception cause"
    )


@pytest.mark.parametrize("kind", ["assessment", "support"])
def test_ActualParsedManifestSizesAreGuardedBeforeOwningBlobAllocation(tmp_path, monkeypatch, kind):
    """The owning read facade rejects oversized actual metadata before allocating a blob."""

    if kind == "support":
        fixture = Fixture.Create(tmp_path / "workspace", raw_support=b"x" * (64 * 1024 + 1))
        record = fixture.Assessment()
    else:
        fixture = Fixture.Create(tmp_path / "workspace")
        original = fixture.Assessment(raw=b" " * (256 * 1024 + 1))
        record = copy.copy(original)
        object.__setattr__(record, "reference", replace(record.reference, size_bytes=1))
    owner_read = LocalEvidenceStore.Read
    allocations = []

    def ObserveAllocation(store, reference):
        """Record only allocation sizes, never raw bytes or private evidence paths.

        Args:
            store: Owning storage instance.
            reference: Actual parsed evidence reference.

        Returns:
            Actual owned bytes if the facade admitted their size.
        """

        allocations.append(reference.size_bytes)
        return owner_read(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", ObserveAllocation)
    with pytest.raises(ValueError):
        Read(fixture, (record,))

    ceiling = 256 * 1024 if kind == "assessment" else 64 * 1024
    assert all(size <= ceiling for size in allocations), "Oversized blob reached allocating owner"


def test_OwningFailuresSuppressPrivatePathAndExceptionCause(fixture, monkeypatch):
    """Normal full traceback logging cannot expose an owner's hostile source/path diagnostic."""

    record = fixture.Assessment()
    private = "synthetic-private-source-value"

    def FailRead(store, reference):
        """Inject a private owning error without changing source metadata or producer contracts.

        Args:
            store: Owning storage instance.
            reference: Actual parsed immutable reference.

        Raises:
            EvidenceStorageError: Synthetic private filesystem failure.
        """

        raise EvidenceStorageError(private) from OSError(private)

    monkeypatch.setattr(LocalEvidenceStore, "Read", FailRead)
    with pytest.raises(EvidenceStorageError) as failure:
        Read(fixture, (record,))

    assert private not in "".join(traceback.format_exception(failure.value)), "Private cause leaked"


def test_ProjectionAndQueryRejectSameRevisionDifferentContents(fixture):
    """Stable relation identities and equal revisions cannot substitute a changed snapshot."""

    records = (fixture.Assessment(),)
    claims = Read(fixture, records)
    graph = ProjectReachability(fixture.model, tuple(item.Reference() for item in
        fixture.relations.values()), claims, expected_model_version=claims.model_version)
    original = fixture.model.objects[0]
    changed = replace(original, attributes={**original.attributes, "changed": True})
    substituted = replace(fixture.model, objects=(changed, *fixture.model.objects[1:]))
    assert substituted.revision == fixture.model.revision, "Test accidentally changed the revision"
    with pytest.raises(ValueError):
        ProjectReachability(substituted, (), claims, expected_model_version=claims.model_version)
    with pytest.raises(ValueError):
        SearchReachabilityPaths(graph, substituted, fixture.objects["source"].Reference(),
                                fixture.objects["portal"].Reference())
    with pytest.raises(ValueError):
        Read(fixture, records,
             expected_model_version=ReachabilityModelVersion.FromModel(substituted))


@pytest.mark.parametrize("case", ["duplicate", "nonexistent", "other-kind", "wrong-namespace",
                                 "node-count", "edge-count", "unverified-output"])
def test_ExplicitProjectionSelectionRefusesUnsupportedGraphMeaning(fixture, case):
    """The selected graph remains explicit and bounded, with no inferred native/finding edges."""

    claims = Read(fixture, ())
    selection = (fixture.relations["source-portal"].Reference(),)
    if case == "duplicate":
        selection *= 2
    elif case == "nonexistent":
        selection = ("relation:" + "0" * 64,)
    elif case == "wrong-namespace":
        selection = (fixture.objects["source"].Reference(),)
    elif case == "edge-count":
        selection *= 2049
    elif case == "unverified-output":
        claims = replace(claims, _seal=object())
    elif case in {"other-kind", "node-count"}:
        if case == "other-kind":
            edge = Relation(RelationKind.EXPOSES, fixture.objects["source"].Reference(),
                fixture.objects["portal"].Reference(),
                provenance=fixture.model.relations[0].provenance)
            changed, _ = fixture.model.Apply(relations=(edge,))
            selection = (edge.Reference(),)
        else:
            extra = tuple(SecurityObject(ObjectIdentity(fixture.model.workspace_id,
                ObjectKind.ASSET, "extra:" + str(index)),
                provenance=fixture.model.objects[0].provenance)
                for index in range(503))
            changed, _ = fixture.model.Apply(objects=extra)
        fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                         expected_revision=fixture.model.revision)
        claims = Read(fixture, ())
    with pytest.raises(ValueError):
        ProjectReachability(fixture.model, selection, claims,
                            expected_model_version=claims.model_version)


def test_BareRelationsAreUnknownAndNoAutomaticReverseTransitionExists(fixture):
    """Open graph structure and source attributes do not themselves prove directed reachability."""

    claims = Read(fixture, ())
    graph = ProjectReachability(fixture.model, (fixture.relations["source-portal"].Reference(),),
        claims, expected_model_version=claims.model_version)
    assert graph.unassessed_transitions == 1 and graph.unknown_transitions == 1, "Bare edge known"
    assert Edge(graph, fixture).state is ReachabilityState.UNKNOWN, "Cooccurrence confirmed an edge"
    reverse = SearchReachabilityPaths(graph, fixture.model, fixture.objects["portal"].Reference(),
                                      fixture.objects["source"].Reference())
    assert reverse.complete and reverse.no_candidate_path, "A reverse transition was inferred"
    with pytest.raises(FrozenInstanceError):
        graph.at = "2026-10-13T00:00:04Z"


@pytest.mark.parametrize("case", ["wrong-subject", "wrong-kind", "observation-scope",
                                 "partial-evidence", "wrong-control-type"])
def test_ExactRetainedProofSubjectsAndCoverageCannotBeSubstituted(fixture, case):
    """Retained observation identity, subject, kind and complete evidence bind admission."""

    claim = fixture.Declaration("source-portal")
    original = fixture.observations["source-portal"]
    if case == "wrong-subject":
        claim["basis"] = [fixture.Basis("portal-identity")]
    elif case == "wrong-control-type":
        claim = fixture.Declaration("source-portal", "BLOCKED", 1.0, controls=("key-control",))
        control = replace(fixture.objects["key-control"], attributes={"asset_type": "other-type"})
        changed, _ = fixture.model.Apply(objects=(control,))
        fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                         expected_revision=fixture.model.revision)
    else:
        if case == "wrong-kind":
            updated = replace(original, kind="unrelated-witness")
        elif case == "observation-scope":
            updated = replace(original, provenance=replace(original.provenance,
                                                           scope_reference="scope:other"))
        else:
            evidence_store = LocalEvidenceStore(fixture.root / "evidence")
            old_record = fixture.records["source-portal"]
            extra = evidence_store.Put(b"additional-independent-witness", "second-witness",
                "application/octet-stream", old_record.provenance)
            updated = replace(original, provenance=replace(original.provenance,
                evidence_references=(old_record.reference, extra.reference)))
        changed, _ = fixture.model.Apply(observations=(updated,))
        fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                         expected_revision=fixture.model.revision)
        claim["basis"][0]["observation_reference"] = updated.Reference()
    record = fixture.Assessment(fixture.Envelope([claim]))
    with pytest.raises(ValueError):
        Read(fixture, (record,))


def test_MultipleBasisEntriesCannotConcealAnEmptyRetainedProof(fixture):
    """One valid support entry cannot hide an explicitly supplied unusable basis entry."""

    original = fixture.observations["source-portal"]
    empty = Observation(original.kind, original.subject_reference, {"separate": "empty"},
                        replace(original.provenance, evidence_references=()))
    changed, _ = fixture.model.Apply(observations=(empty,))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)
    claim = fixture.Declaration("source-portal")
    claim["basis"].append({"observation_reference": empty.Reference(), "evidence_manifest_ids": []})
    edge = Edge(Projection(fixture, (fixture.Assessment(fixture.Envelope([claim])),)), fixture)
    assert edge.state is ReachabilityState.UNKNOWN and "missing-evidence" in edge.reasons, (
        "Valid entry concealed absent evidence on a separately supplied retained observation"
    )


@pytest.mark.parametrize("case", ["changed-record", "changed-replay"])
def test_AnInMemoryRecordTypeAloneCannotReplaceTheCanonicalStoredManifest(fixture, case):
    """Forged immutable-wrapper fields still fail the actual owning manifest comparison."""

    original = fixture.Assessment()
    forged = copy.copy(original)
    object.__setattr__(forged, "provenance",
                       replace(original.provenance, source_id="different-source"))
    records = (forged,) if case == "changed-record" else (original, forged)
    with pytest.raises(ValueError):
        Read(fixture, records)


@pytest.mark.parametrize("field,value", [("at", "not-a-time"),
    ("at", "2026-10-13T00:00:03"), ("max_age_seconds", True), ("max_age_seconds", -1),
    ("max_age_seconds", 604801), ("scope_reference", "\ud800"),
    ("context_reference", "x" * 257)])
def test_ExplicitTimeAgeAndMetadataRejectMalformedDirectInputs(fixture, field, value):
    """Temporal and text budgets fail before owning reads without silently consulting a clock."""

    with pytest.raises(ValueError):
        Read(fixture, (), **{field: value})


def test_FreshnessIsInclusiveAndOneExpiredInstantRemainsUnknown(fixture):
    """Boundary admission uses all measured source times and the supplied fixed assessment time."""

    record = fixture.Assessment()
    exact = Read(fixture, (record,), max_age_seconds=3)
    assert not exact.claims[0].reasons, "Support exactly at the allowed age was treated as stale"
    expired = Read(fixture, (record,), max_age_seconds=2)
    assert "stale-support" in expired.claims[0].reasons, "Expired measured support was admitted"


@pytest.mark.parametrize("records", [[], (None,), (None,) * 33],
                         ids=["list", "untyped", "artifact-count"])
def test_OnlyBoundedExplicitAssessmentTuplesEnterOwnedReads(fixture, records):
    """No iterable coercion or unbounded manifest set bypasses the public selection contract."""

    with pytest.raises(ValueError):
        Read(fixture, records)


def test_OwningModelFailureSuppressesPrivateSourceDetails(fixture, monkeypatch):
    """Malformed persisted model diagnostics cannot leak through loader exception chaining."""

    private = "synthetic-private-source-value"

    def FailOpen(store):
        """Refuse a synthetic owning read with a deliberately private diagnostic.

        Args:
            store: Existing owning model store instance.

        Raises:
            ValueError: Synthetic malformed current model.
        """

        raise ValueError(private)

    monkeypatch.setattr(LocalModelStore, "Open", FailOpen)
    with pytest.raises(ValueError) as failure:
        Read(fixture, ())
    assert private not in "".join(traceback.format_exception(failure.value)), "Model cause leaked"


def test_LoaderRefusesHistoricalBasisAfterAnOwningModelAdvance(fixture):
    """Supplying an internally matching old pin does not bypass the current persisted owner read."""

    original = fixture.model
    updated = replace(original.objects[0], attributes={"later_fact": True})
    changed, _ = original.Apply(objects=(updated,))
    LocalModelStore(fixture.root).Save(changed, expected_revision=original.revision)
    with pytest.raises(ValueError):
        Read(fixture, ())


def test_RelationClaimsCannotAddressUnsupportedOrMissingCurrentTransitions(fixture):
    """Acquired source declarations must bind actual explicitly supported relation identity."""

    missing = fixture.Declaration("source-portal")
    missing["relation_reference"] = "relation:" + "0" * 64
    with pytest.raises(ValueError):
        Read(fixture, (fixture.Assessment(fixture.Envelope([missing])),))
    edge = Relation(RelationKind.HAS_PORT, fixture.objects["source"].Reference(),
        fixture.objects["portal"].Reference(), provenance=fixture.model.relations[0].provenance)
    changed, _ = fixture.model.Apply(relations=(edge,))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)
    missing["relation_reference"] = edge.Reference()
    with pytest.raises(ValueError):
        Read(fixture, (fixture.Assessment(fixture.Envelope([missing])),))


def test_QueryRejectsUntypedLimitsAndUnverifiedDerivedView(fixture):
    """An arbitrary Python result wrapper cannot by itself establish the owning-read contract."""

    graph = Projection(fixture, (fixture.Assessment(),))
    source = fixture.objects["source"].Reference()
    target = fixture.objects["portal"].Reference()
    with pytest.raises(ValueError):
        SearchReachabilityPaths(graph, fixture.model, source, target, limits={})
    with pytest.raises(ValueError):
        SearchReachabilityPaths(replace(graph, _seal=object()), fixture.model, source, target)
    with pytest.raises(ValueError):
        ReachabilityModelVersion.FromModel(None)


def test_CopyingVerifiedWrappersCannotAlterDeclaredStateProofOrGraph(fixture):
    """Derived content guards reject copied-record substitutions without authenticating a source."""

    record = fixture.Assessment()
    claims = Read(fixture, (record,))
    original = claims.claims[0]
    altered = replace(original, state=ReachabilityState.BLOCKED, confidence=1.0)
    with pytest.raises(ValueError):
        ProjectReachability(fixture.model, (), replace(claims, claims=(altered,)),
                            expected_model_version=claims.model_version)
    graph = Projection(fixture, (record,))
    changed_hop = replace(graph.transitions[0], state=ReachabilityState.BLOCKED)
    with pytest.raises(ValueError):
        SearchReachabilityPaths(replace(graph, transitions=(changed_hop, *graph.transitions[1:])),
            fixture.model, fixture.objects["source"].Reference(),
            fixture.objects["portal"].Reference())


def test_RealIndependentProofJoinStopsBeforeThe257thSupportingManifest(fixture, monkeypatch):
    """Cross-artifact joins stay bounded even when every assessment fits its own budget."""

    store = LocalEvidenceStore(fixture.root / "evidence")
    original = fixture.observations["source-portal"]
    observations = []
    declarations = []
    support_ids = set()
    for index in range(257):
        record = store.Put(("independent-witness:" + str(index)).encode(), "transition-witness",
            "application/octet-stream", fixture.records["source-portal"].provenance)
        observation = replace(original, attributes={"independent_witness": index},
                              provenance=replace(original.provenance,
                                                 evidence_references=(record.reference,)))
        observations.append(observation)
        claim = fixture.Declaration("source-portal")
        claim["basis"] = [{"observation_reference": observation.Reference(),
                           "evidence_manifest_ids": [record.evidence_id]}]
        declarations.append(claim)
        support_ids.add(record.evidence_id)
    changed, _ = fixture.model.Apply(observations=tuple(observations))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)
    assessments = tuple(fixture.Assessment(fixture.Envelope(declarations[start:start + 120]))
                        for start in range(0, len(declarations), 120))
    owner_get = LocalEvidenceStore.Get
    joined = []

    def CountJoin(evidence, identity):
        """Count only actual support owner calls without bypassing integrity verification.

        Args:
            evidence: Existing owned evidence storage instance.
            identity: Explicit immutable manifest ID.

        Returns:
            Actual canonical owning manifest after original verification.
        """

        if identity in support_ids:
            joined.append(identity)
        return owner_get(evidence, identity)

    monkeypatch.setattr(LocalEvidenceStore, "Get", CountJoin)
    with pytest.raises(ValueError):
        Read(fixture, assessments)
    assert len(set(joined)) == 256, "Proof join allocated or admitted over 256 support manifests"


def test_FullModelSnapshotUsesTheExistingEightMiBSizeBoundary(fixture):
    """A caller-built oversized typed snapshot cannot become a supposedly bounded model pin."""

    objects = tuple(SecurityObject(ObjectIdentity(fixture.model.workspace_id, ObjectKind.ASSET,
        "oversized-basis:" + str(index)), {"padding": "x" * 56000},
        fixture.model.objects[0].provenance) for index in range(150))
    oversized = replace(fixture.model, objects=(*fixture.model.objects, *objects))
    with pytest.raises(ValueError):
        ReachabilityModelVersion.FromModel(oversized)


def test_CanonicalSerializationFailuresUseSanitizedValueError(fixture):
    """Unserializable giant direct revision integers do not expose a parser cause or raw value."""

    oversized_revision = replace(fixture.model, revision=10 ** 10000)
    with pytest.raises(ValueError):
        ReachabilityModelVersion.FromModel(oversized_revision)


def test_EqualStringStateCopiesCannotEraseTheNamedBlockingProof(fixture):
    """Equal JSON string/Enum encodings must not bypass the typed barrier-attribution contract."""

    graph = Projection(fixture, fixture.Phase("initial"))
    source = fixture.objects["source"].Reference()
    target = fixture.objects["key"].Reference()
    original = SearchReachabilityPaths(graph, fixture.model, source, target)
    assert all(path.state is ReachabilityState.BLOCKED and len(path.decisive_blocking_claims) == 1
               for path in original.paths), "Original named barrier lost its exact proof"
    altered = replace(graph, transitions=tuple(replace(hop, state=hop.state.value)
                                               for hop in graph.transitions))
    with pytest.raises(ValueError):
        SearchReachabilityPaths(altered, fixture.model, source, target)


@pytest.mark.parametrize("case", ["basis-none", "basis-list", "records-none", "records-list",
    "observation-untyped", "observation-changed", "assessment-none", "assessment-untyped",
    "version-none", "controls-none", "control-basis-none", "control-reference-none", "rule-untyped",
    "reasons-list", "claims-list", "record-reference-none", "record-provenance-none"])
def test_MalformedCopiedNestedProofsRaiseSanitizedValueError(fixture, case):
    """Every nested proof/record/tuple guard fails explicitly instead of throwing AttributeError."""

    declaration = fixture.Declaration("source-portal", "BLOCKED", 1.0, controls=("key-control",))
    loaded = Read(fixture, (fixture.Assessment(fixture.Envelope([declaration])),))
    original = loaded.claims[0]
    if case == "basis-none":
        changed = replace(original, basis=(None,))
    elif case == "basis-list":
        changed = replace(original, basis=list(original.basis))
    elif case in {"records-none", "records-list"}:
        proof = replace(original.basis[0], records=(None,) if case == "records-none"
                        else list(original.basis[0].records))
        changed = replace(original, basis=(proof,))
    elif case in {"observation-untyped", "observation-changed"}:
        observation = None if case == "observation-untyped" else replace(
            original.basis[0].observation, attributes={"changed": "synthetic-private-source-value"},
        )
        if case == "observation-untyped":
            observation = "synthetic-private-source-value"
        proof = replace(original.basis[0], observation=observation)
        changed = replace(original, basis=(proof,))
    elif case in {"assessment-none", "assessment-untyped"}:
        changed = replace(original, assessment=None if case == "assessment-none" else {})
    elif case == "version-none":
        changed = replace(original, model_version=None)
    elif case == "rule-untyped":
        changed = replace(original, inference_rule={})
    elif case == "controls-none":
        changed = replace(original, blocking_controls=(None,))
    elif case in {"control-basis-none", "control-reference-none"}:
        control = replace(original.blocking_controls[0], **{
            "basis" if case == "control-basis-none" else "control_reference": None,
        })
        changed = replace(original, blocking_controls=(control,))
    elif case == "reasons-list":
        changed = replace(original, reasons=list(original.reasons))
    elif case == "claims-list":
        changed = original
    else:
        forged = copy.copy(original.basis[0].records[0])
        object.__setattr__(forged, "reference" if case == "record-reference-none" else "provenance",
                           None)
        proof = replace(original.basis[0], records=(forged,))
        changed = replace(original, basis=(proof,))
    copied = replace(loaded, claims=[changed] if case == "claims-list" else (changed,))
    with pytest.raises(ValueError) as failure:
        ProjectReachability(fixture.model, (), copied, expected_model_version=loaded.model_version)
    rendered = "".join(traceback.format_exception(failure.value))
    assert "synthetic-private-source-value" not in rendered, "Nested copied proof leaked text"


@pytest.mark.parametrize("case", ["transitions-none", "transitions-list", "nodes-list",
    "claim-list", "claim-none", "reasons-list", "coverage-bool", "version-none"])
def test_MalformedCopiedProjectionFieldsCannotEnterThePureSearch(fixture, case):
    """Query-visible graph, enum, coverage and nested collections retain exact immutable types."""

    graph = Projection(fixture, (fixture.Assessment(),))
    if case == "transitions-none":
        copied = replace(graph, transitions=(None,))
    elif case == "transitions-list":
        copied = replace(graph, transitions=list(graph.transitions))
    elif case == "nodes-list":
        copied = replace(graph, nodes=list(graph.nodes))
    elif case == "coverage-bool":
        copied = replace(graph, unassessed_transitions=True)
    elif case == "version-none":
        copied = replace(graph, model_version=None)
    else:
        hop = next(item for item in graph.transitions if item.claims)
        fields = {"claims": list(hop.claims)} if case == "claim-list" else (
            {"claims": (None,)} if case == "claim-none" else {"reasons": list(hop.reasons)}
        )
        altered = replace(hop, **fields)
        copied = replace(graph, transitions=tuple(altered if item is hop else item
                                                 for item in graph.transitions))
    with pytest.raises(ValueError):
        SearchReachabilityPaths(copied, fixture.model, fixture.objects["source"].Reference(),
                                fixture.objects["portal"].Reference())


@pytest.mark.parametrize("value", [None, True, False, 0, 123, -123, 1.25, -0.0, 1e-30,
    "", "ascii", "\\", '"', "\b\f\n\r\t", "\x00\x01\x1f", "\x7f", "é", "中", "😀",
    "\u2028\u2029", "all:\\\"\x00\n é中😀"], ids=["null", "true", "false", "zero",
    "integer", "negative-integer", "float", "negative-zero", "scientific", "empty", "ascii",
    "backslash", "quote", "short-escapes", "hex-escapes", "del", "two-byte", "three-byte",
    "four-byte", "line-separators", "mixed"])
def test_IndependentCanonicalScalarByteOracle(value):
    """UTF-8 and JSON escaping costs match the standard owning encoder at exact boundaries."""

    actual = json.dumps(value, ensure_ascii=False, allow_nan=False,
                        separators=(",", ":")).encode("utf-8")
    assert JsonScalarSize(value, len(actual)) == len(actual), "Canonical scalar byte count changed"
    with pytest.raises(ValueError):
        JsonScalarSize(value, len(actual) - 1)


@pytest.mark.parametrize("case", ["unicode", "nested", "rich-attribution", "empty-model"])
def test_IndependentOwningModelBytesAndHashMatchThePreflight(fixture, case):
    """Model size prediction never replaces the existing owner's exact canonical hash semantics."""

    if case == "empty-model":
        model = type(fixture.model)(fixture.model.workspace_id)
    else:
        original = fixture.model.objects[0]
        attributes = {"unicode": "é中😀\u2028", "escaped\nkey": 'quote" slash\\ null\x00'}
        if case == "nested":
            attributes = {"nested": [None, True, -4, 2.5, {"emoji": ["😀", {}, []]}]}
        provenance = original.provenance
        if case == "rich-attribution":
            provenance = (replace(provenance[0],
                evidence_references=(fixture.records["source-portal"].reference,),
                execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.125)),)
        changed = replace(original, attributes=attributes, provenance=provenance)
        model = replace(fixture.model, objects=(changed, *fixture.model.objects[1:]))
    expected = CanonicalModelJson(model.ToDict())
    assert ModelSnapshotSize(model) == len(expected), "Preflight differs from owning model bytes"
    version = ReachabilityModelVersion.FromModel(model)
    assert version.snapshot_sha256 == hashlib.sha256(expected).hexdigest(), "Canonical hash changed"


def BoundaryModel(fixture, delta):
    """Build valid typed caller models using independent owning-byte costs, not preflight outputs.

    Args:
        fixture: Existing typed independent model producer.
        delta: Desired byte offset from the owning 8 MiB limit.

    Returns:
        Valid caller-built immutable model at exactly the desired canonical length.
    """

    original = fixture.model
    provenance = original.objects[0].provenance
    empty = SecurityObject(ObjectIdentity(original.workspace_id, ObjectKind.ASSET, "budget:0000"),
                           {"padding": ""}, provenance)
    base_size = len(CanonicalModelJson(original.ToDict()))
    unit_size = len(CanonicalModelJson(replace(original, objects=(
        *original.objects, empty,
    )).ToDict())) - base_size
    block = 60000
    count = (MAX_MODEL_BYTES - base_size - unit_size) // (block + unit_size)
    padding = "x" * block
    full = tuple(SecurityObject(ObjectIdentity(original.workspace_id, ObjectKind.ASSET,
        f"budget:{index:04d}"), {"padding": padding}, provenance) for index in range(count))
    blank = SecurityObject(ObjectIdentity(original.workspace_id, ObjectKind.ASSET,
        f"budget:{count:04d}"), {"padding": ""}, provenance)
    model = replace(original, objects=(*original.objects, *full, blank))
    remainder = MAX_MODEL_BYTES + delta - len(CanonicalModelJson(model.ToDict()))
    assert 0 <= remainder < 64000, "Independent boundary fixture cannot fit one bounded attribute"
    last = replace(blank, attributes={"padding": "y" * remainder})
    result = replace(original, objects=(*original.objects, *full, last))
    assert len(CanonicalModelJson(result.ToDict())) == MAX_MODEL_BYTES + delta, "Boundary mismatch"

    return result


@pytest.mark.parametrize("delta", [-1, 0, 1], ids=["one-byte-below", "exact", "one-byte-above"])
def test_ExactEightMiBBoundariesUseIndependentCanonicalBytes(fixture, delta):
    """The complete owning size fence is inclusive and its accepted hash remains unchanged."""

    model = BoundaryModel(fixture, delta)
    if delta > 0:
        with pytest.raises(ValueError):
            ReachabilityModelVersion.FromModel(model)
        return
    expected = CanonicalModelJson(model.ToDict())
    assert ModelSnapshotSize(model) == len(expected), "Exact boundary byte count changed"
    assert ReachabilityModelVersion.FromModel(model).snapshot_sha256 == hashlib.sha256(
        expected,
    ).hexdigest(), "Exact boundary canonical digest changed"


def test_OversizedCallerModelRefusesBeforeFullMaterialization(fixture, monkeypatch):
    """Reject a valid oversized basis before calling ToDict, JsonValue or Reference."""

    import fuzzy1337.reachability as module

    model = BoundaryModel(fixture, 1)
    attempted = []

    def Refuse(*args, **kwargs):
        """Record and refuse an allocating owner serialization or identity call.

        Args:
            args: Unused attempted positional materialization arguments.
            kwargs: Unused attempted keyword materialization arguments.

        Raises:
            AssertionError: Oversized caller data reached full materialization.
        """

        attempted.append(True)
        raise AssertionError("oversized model reached full canonical materialization")

    with monkeypatch.context() as guard:
        guard.setattr(type(model), "ToDict", Refuse)
        guard.setattr(module, "CanonicalModelJson", Refuse)
        for record_type in (ObjectIdentity, SecurityObject, Relation, Observation):
            guard.setattr(record_type, "Reference", Refuse)
        with pytest.raises(ValueError):
            ReachabilityModelVersion.FromModel(model)
    assert not attempted, "Size admission delegated oversized caller data to an allocating owner"
