# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise outcome declarations through original evidence, persisted models and real paths."""

from __future__ import annotations

import builtins
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.business_events import AnalyzeBusinessEventPaths, ApplyBusinessEvent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.path_analysis import PathAnalysisLimits
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReadReachabilityClaims,
)
from fuzzy1337.workspace import WorkspaceConflictError
from tests.contract.business_event_fixture import Acquire, Create, DefinitionFields, Persist, Read
from tests.contract.test_reachability_contract import Projection
from tests.integration.test_reachability_model import Bytes


@pytest.mark.parametrize("phase,expected_billing,expected_key", [
    ("confirmed", ["CONFIRMED"] * 3, ["BLOCKED"] * 3),
    ("potential", ["POTENTIAL"] * 3, ["BLOCKED"] * 3),
    ("initial", ["UNKNOWN"] * 3, ["BLOCKED"] * 3),
    ("likely", ["LIKELY"] * 3, ["BLOCKED"] * 3),
    ("remediation", ["BLOCKED", "CONFIRMED", "CONFIRMED"], ["BLOCKED"] * 3),
    ("conflicting-barrier", ["UNKNOWN"] * 3, ["UNKNOWN"] * 3),
])
def test_OriginalDefinitionToPersistedScenarioRetainsHandwrittenTechnicalStateOracle(
    tmp_path, phase, expected_billing, expected_key,
):
    """Technical routes retain supplied-hop state without promoting declared impact."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    projection = Projection(fixture, fixture.Phase(phase))
    before = Bytes(fixture.root)
    result = AnalyzeBusinessEventPaths(definition, fixture.model, projection,
                                       (fixture.objects["source"].Reference(),))
    assert result.enumeration_complete and result.cuts_complete, "Small scenario query truncated"
    assert result.semantics == "declared-unacceptable-outcome-scenario", "Outcome became incident"
    assert result.definition_evidence_id == record.evidence_id, "Original owner definition was lost"
    assert result.owner_reference == "owner:synthetic-billing", "Owner attribution changed"
    asset_aliases = {fixture.objects[name].Reference(): name for name in ("billing", "key")}
    aliases = {item.Reference(): name for name, item in fixture.relations.items()}
    expected_routes = [
        ("source-portal", "portal-identity", "identity-billing"),
        ("source-detour", "detour-identity", "identity-billing"),
        ("source-portal", "portal-detour", "detour-identity", "identity-billing"),
    ]

    for item in result.paths_to_assets:
        name = asset_aliases[item.critical_asset_reference]
        routes = [(*route, "billing-key") if name == "key" else route
                  for route in expected_routes]
        expected = list(zip(routes, expected_key if name == "key" else expected_billing,
                            strict=True))
        expected.sort(key=lambda pair: (len(pair[0]),
            tuple(fixture.relations[alias].Reference() for alias in pair[0])))
        actual = [(tuple(aliases[hop.relation_reference] for hop in path.hops), path.state.value)
                  for path in item.technical_analysis.search.paths]
        assert actual == expected, "Declared outcome changed the independently known hop oracle"
        assert item.impact_semantics == "declared-scenario-only", "Impact became technical state"
        assert all(path.nodes[-1] == item.critical_asset_reference
                   and result.declaration_object_reference not in path.nodes
                   and item.membership_relation_reference not in (
                       hop.relation_reference for hop in path.hops
                   ) for path in item.technical_analysis.search.paths), (
            "A descriptive membership became a traversed or confirmed technical impact hop"
        )

    assert Bytes(fixture.root) == before, "Pure impact explanation wrote authoritative state"
    assert LocalEvidenceStore(fixture.root / "evidence").Get(record.evidence_id) == record, (
        "Original owner-definition acquisition was changed"
    )


def test_DefinitionReplayReopenRelocationAndFindingTriageStayWithExistingOwners(tmp_path):
    """Actual CAS persistence preserves finding history and portable declaration identity."""

    fixture, record = Create(tmp_path / "workspace")
    support = fixture.records["source-portal"]
    provenance = ModelProvenance("synthetic-finding", "run:fixture",
        "2026-10-13T00:00:00Z", fixture.graph["scope_reference"], "target:fixture",
        evidence_references=(support.reference,))
    finding = Finding(fixture.objects["portal"].Reference(), "synthetic-policy", "surface:portal",
        "Known unrelated triaged finding", (provenance,), severity=FindingSeverity.HIGH)
    store = LocalModelStore(fixture.root)
    changed, _ = ApplyFindings(fixture.model, (finding,))
    fixture.model = store.Save(changed, expected_revision=fixture.model.revision)
    finding_reference = finding.ToObject(fixture.model.workspace_id).Reference()
    changed, _ = TransitionFinding(fixture.model, finding_reference, FindingStatus.DISMISSED,
                                   provenance, "Owned synthetic disposition")
    fixture.model = store.Save(changed, expected_revision=fixture.model.revision)
    original_findings = fixture.model.Objects(ObjectKind.FINDING)
    original_observations = fixture.model.observations
    definition = Persist(fixture, record)
    persisted = fixture.model
    repeated, delta = ApplyBusinessEvent(definition, fixture.model)
    assert repeated == persisted and not delta.created and not delta.updated, "Replay changed state"
    assert repeated.Objects(ObjectKind.FINDING) == original_findings, "Finding triage changed"
    assert all(item in repeated.observations for item in original_observations), (
        "Observation history lost"
    )
    records = fixture.Phase("confirmed")
    original = AnalyzeBusinessEventPaths(definition, repeated, Projection(fixture, records),
                                         (fixture.objects["source"].Reference(),))
    moved = tmp_path / "relocated"
    fixture.root.rename(moved)
    fixture.root = moved
    fixture.model = LocalModelStore(moved).Open()
    relocated = Read(fixture, record)
    result = AnalyzeBusinessEventPaths(relocated, fixture.model, Projection(fixture, records),
                                      (fixture.objects["source"].Reference(),))
    assert relocated == definition and result == original, "Filesystem location entered identities"
    assert fixture.model == persisted, "Relocation changed the model schema or attributed state"


def test_NewOriginalAcquisitionOrDefinitionVersionCannotCollapseOwnerIdentity(tmp_path):
    """Same bytes under another real source manifest retain distinct accountable declarations."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Read(fixture, record)
    other = Acquire(fixture, source_id="other-synthetic-owner")
    altered = Acquire(fixture, DefinitionFields(fixture, definition_version="2026.2"))
    assert len({definition.definition_reference, Read(fixture, other).definition_reference,
                Read(fixture, altered).definition_reference}) == 3, "Declarations collapsed"
    first = Persist(fixture, record)
    second = Persist(fixture, other)
    assert first.definition_reference != second.definition_reference, "Owner acquisition merged"
    assert len([item for item in fixture.model.objects
                if item.attributes.get("asset_type") == "business-event-definition"]) == 2, (
        "Distinct owner declarations overwrote one another"
    )


def test_ActualCompareAndSwapRefusesStaleCallerWrites(tmp_path):
    """The existing store remains the sole write-conflict owner for the returned delta."""

    fixture, record = Create(tmp_path / "workspace")
    changed, _ = ApplyBusinessEvent(Read(fixture, record), fixture.model)
    store = LocalModelStore(fixture.root)
    later, _ = fixture.model.Apply(objects=(replace(fixture.objects["billing"],
                                                   attributes={"later_owner_change": True}),))
    store.Save(later, expected_revision=fixture.model.revision)

    with pytest.raises(WorkspaceConflictError):
        store.Save(changed, expected_revision=fixture.model.revision)

    assert store.Open() == later, "Stale declaration write replaced the current owner's state"


def test_DescriptiveMembershipIsNeverAReachabilityTransitionOrAttackerPosition(tmp_path):
    """Actual owner projections containing membership links are refused before scenario analysis."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    records = fixture.Phase("confirmed")
    version = ReachabilityModelVersion.FromModel(fixture.model)
    claims = ReadReachabilityClaims(fixture.model, records, workspace_root=fixture.root,
        expected_model_version=version, context_reference=fixture.graph["context_reference"],
        scope_reference=fixture.graph["scope_reference"], at=fixture.graph["query_at"])
    all_relations = tuple(item.Reference() for item in fixture.model.relations)
    with_membership = ProjectReachability(fixture.model, all_relations, claims,
                                          expected_model_version=version)

    with pytest.raises(ValueError):
        AnalyzeBusinessEventPaths(definition, fixture.model, with_membership,
                                  (fixture.objects["source"].Reference(),))

    declaration = next(item for item in fixture.model.objects
                       if item.attributes.get("asset_type") == "business-event-definition")

    with pytest.raises(ValueError):
        AnalyzeBusinessEventPaths(definition, fixture.model, Projection(fixture, records),
                                  (declaration.Reference(),))


@pytest.mark.parametrize("changes", [{"owner_reference": "owner:forged"},
    {"definition_evidence_id": "sha256:" + "a" * 64}, {"unacceptable_outcome": "Forged impact"}])
def test_ChangedPersistedDefinitionCannotOverrideOriginalSourceAttribution(tmp_path, changes):
    """Generic model patches cannot substitute changed profile fields for original evidence."""

    fixture, record = Create(tmp_path / "workspace")
    Persist(fixture, record)
    declaration = next(item for item in fixture.model.objects
                       if item.attributes.get("asset_type") == "business-event-definition")
    changed, _ = fixture.model.Apply(objects=(replace(declaration, attributes=changes),))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)
    definition = Read(fixture, record)

    with pytest.raises(ValueError):
        AnalyzeBusinessEventPaths(definition, fixture.model, Projection(fixture, ()),
                                  (fixture.objects["source"].Reference(),))

    with pytest.raises(ValueError):
        ApplyBusinessEvent(definition, fixture.model)


def test_ChangedMembershipAttributionAndMissingRepresentationFailClosed(tmp_path):
    """Membership requires exact original semantics and source provenance."""

    fixture, record = Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        AnalyzeBusinessEventPaths(Read(fixture, record), fixture.model, Projection(fixture, ()),
                                  (fixture.objects["source"].Reference(),))

    Persist(fixture, record)
    link = next(item for item in fixture.model.relations
                if item.attributes.get("relation_semantics") is not None)
    foreign = replace(link.provenance[0], source_id="foreign-owner")
    changed, _ = fixture.model.Apply(relations=(replace(link, provenance=(foreign,)),))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)

    with pytest.raises(ValueError):
        AnalyzeBusinessEventPaths(Read(fixture, record), fixture.model, Projection(fixture, ()),
                                  (fixture.objects["source"].Reference(),))


def test_BoundedQueriesRetainNoCandidateTruncationCutLimitsAndIndividualEstimates(tmp_path):
    """Per-pair completeness and exact declared confidence remain separate from business impact."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    projection = Projection(fixture, fixture.Phase("confirmed"))
    source = (fixture.objects["source"].Reference(),)
    truncated = AnalyzeBusinessEventPaths(definition, fixture.model, projection, source,
        search_limits=ReachabilityLimits(max_paths=1),
        cut_limits=PathAnalysisLimits(max_cut_work=1))
    assert not truncated.enumeration_complete and not truncated.cuts_complete, "Bounds were hidden"
    assert all(not item.technical_analysis.search.complete
               and not item.technical_analysis.choke_points.complete
               for item in truncated.paths_to_assets), "Pair-level bounds lost"
    complete = AnalyzeBusinessEventPaths(definition, fixture.model, projection, source)
    estimates = [estimate for item in complete.paths_to_assets
                 for path in item.technical_analysis.search.paths
                 for estimate in path.confidence_estimates]
    assert {item.declared_confidence for item in estimates} == {0.99, 1.0}, "Estimates aggregated"
    assert all(item.effective_confidence == item.declared_confidence for item in estimates), (
        "Original valid per-hop estimates changed"
    )
    isolated = AnalyzeBusinessEventPaths(definition, fixture.model, projection,
                                         (fixture.objects["isolated"].Reference(),))
    assert isolated.enumeration_complete and all(
        item.technical_analysis.search.no_candidate_path for item in isolated.paths_to_assets
    ), "Selected-graph disconnection became an unbounded or global safety claim"


def test_StaleOrForeignProjectionAndInvalidAttackerSelectionAreRefused(tmp_path):
    """Exact current query scope, snapshot and explicit eligible positions are required."""

    fixture, record = Create(tmp_path / "workspace")
    stale = Projection(fixture, ())
    definition = Persist(fixture, record)
    projection = Projection(fixture, ())

    for graph in (None, stale, replace(projection, scope_reference="scope:foreign"),
                  replace(projection, at="2026-10-12T00:00:00.000000+00:00"),
                  replace(projection, projection_reference="sha256:" + "a" * 64)):
        with pytest.raises(ValueError):
            AnalyzeBusinessEventPaths(definition, fixture.model, graph,
                                      (fixture.objects["source"].Reference(),))

    source = fixture.objects["source"].Reference()

    for refs in ((), [source], (source, source), ("object:" + "a" * 64,),
                 (fixture.objects["billing"].Reference(),)):
        with pytest.raises(ValueError):
            AnalyzeBusinessEventPaths(definition, fixture.model, projection, refs)


def test_AnalysisAndApplicationRemainPureAfterExplicitOwningReads(tmp_path, monkeypatch):
    """Actual production consumers never open storage or network implicitly during explanation."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    projection = Projection(fixture, fixture.Phase("confirmed"))
    before = Bytes(fixture.root)

    def Refuse(*args, **kwargs):
        """Fail unadvertised I/O while exact guarded first-party output is being consumed."""

        raise AssertionError("pure business event operation attempted I/O")

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", Refuse)
        guard.setattr(Path, "open", Refuse)
        guard.setattr(Path, "stat", Refuse)
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(LocalModelStore, "Open", Refuse)
        guard.setattr(LocalEvidenceStore, "Get", Refuse)
        guard.setattr(LocalEvidenceStore, "Read", Refuse)
        repeated, _ = ApplyBusinessEvent(definition, fixture.model)
        result = AnalyzeBusinessEventPaths(definition, repeated, projection,
                                           (fixture.objects["source"].Reference(),))

    assert result.enumeration_complete and Bytes(fixture.root) == before, "Pure consumer wrote"


def test_ExplicitAttackerPairsAreDeterministicAndAggregateWorkHasAFiniteCeiling(tmp_path):
    """Explicit sources produce separate explanations and oversized products fail early."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    projection = Projection(fixture, fixture.Phase("confirmed"))
    source = fixture.objects["source"].Reference()
    portal = fixture.objects["portal"].Reference()
    first = AnalyzeBusinessEventPaths(definition, fixture.model, projection, (source, portal))
    second = AnalyzeBusinessEventPaths(definition, fixture.model, projection, (portal, source))
    assert first == second and len(first.paths_to_assets) == 4, "Caller order changed pairs"
    critical = ("billing", "key", "identity", "event", "detour")
    larger = Acquire(fixture, DefinitionFields(fixture, critical=critical))
    definition = Persist(fixture, larger)
    projection = Projection(fixture, ())
    attackers = tuple("object:" + f"{index:064x}" for index in range(16))

    with pytest.raises(ValueError, match="at most 64 pairs"):
        AnalyzeBusinessEventPaths(definition, fixture.model, projection, attackers)


def test_NonAssetAndDeclaredOutcomeMembershipCannotStandForACriticalAsset(tmp_path):
    """Generic object presence does not override the explicit ordinary critical Asset contract."""

    fixture, record = Create(tmp_path / "workspace")
    host = SecurityObject(ObjectIdentity(fixture.model.workspace_id, ObjectKind.HOST, "127.0.0.1"),
                          provenance=fixture.objects["billing"].provenance)
    changed, _ = fixture.model.Apply(objects=(host,))
    fixture.model = LocalModelStore(fixture.root).Save(changed,
                                                     expected_revision=fixture.model.revision)

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, DefinitionFields(fixture,
            critical_asset_references=[host.Reference()])))

    Persist(fixture, record)
    declaration = next(item for item in fixture.model.objects
                       if item.attributes.get("asset_type") == "business-event-definition")

    with pytest.raises(ValueError):
        Read(fixture, Acquire(fixture, DefinitionFields(fixture,
            critical_asset_references=[declaration.Reference()])))


def test_UnusableStaleHopSourcesRetainUnknownAndOriginalIndividualEstimates(tmp_path):
    """Stale proof remains visible without promoting an outcome to confirmed state."""

    fixture, record = Create(tmp_path / "workspace")
    definition = Persist(fixture, record)
    records = fixture.Phase("confirmed")
    version = ReachabilityModelVersion.FromModel(fixture.model)
    claims = ReadReachabilityClaims(fixture.model, records, workspace_root=fixture.root,
        expected_model_version=version, context_reference=fixture.graph["context_reference"],
        scope_reference=fixture.graph["scope_reference"], at="2026-10-13T02:00:00Z")
    projection = ProjectReachability(fixture.model,
        tuple(item.Reference() for item in fixture.relations.values()), claims,
        expected_model_version=version)
    result = AnalyzeBusinessEventPaths(definition, fixture.model, projection,
                                       (fixture.objects["source"].Reference(),))
    paths = [path for item in result.paths_to_assets
             for path in item.technical_analysis.search.paths]
    assert paths and {path.state.value for path in paths} == {"UNKNOWN"}, "Stale hops gained impact"
    assert all(estimate.effective_confidence is None for path in paths
               for estimate in path.confidence_estimates), "Stale confidence remained effective"
    assert all(any("stale-assessment" in hop.reasons for hop in path.hops) for path in paths), (
        "Original stale evidence reasons were hidden"
    )
