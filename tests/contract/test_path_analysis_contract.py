# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify handwritten participation and structural-cut semantics through real attributed
producers.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fuzzy1337.path_analysis import (
    AnalyzeReachabilityPaths,
    PathAnalysisLimits,
    PathSemanticGroup,
)
from fuzzy1337.reachability import ReachabilityLimits, ReachabilityState
from tests.contract.reachability_fixture import FIXTURES, Fixture
from tests.contract.test_reachability_contract import Projection


def Analyze(fixture, projection, target="event", **options):
    """Use the actual public interface on an independently persisted source fixture."""

    return AnalyzeReachabilityPaths(projection, fixture.model,
        fixture.objects["source"].Reference(), fixture.objects[target].Reference(), **options)


def Aliases(fixture):
    """Resolve original model identities to handwritten test-only object and relation aliases."""

    return {item.Reference(): name for collection in (fixture.objects, fixture.relations)
            for name, item in collection.items()}


def test_HandwrittenCountsCutsAndSingleRemovalLeverageOracle(tmp_path):
    """The three independent routes produce exact per-element participation and structural cuts."""

    fixture = Fixture.Create(tmp_path / "workspace")
    oracle = json.loads((FIXTURES / "path-analysis.oracle.v1.json").read_text())
    projection = Projection(fixture, fixture.Phase("confirmed"))
    result = Analyze(fixture, projection)
    aliases = Aliases(fixture)

    for kind in ("node", "relation"):
        actual = {aliases[item.reference]: len(item.path_references)
                  for item in result.participation if item.kind == kind}
        assert actual == oracle[kind + "_participation"], "Participation differs from oracle"
        cuts = {aliases[item.reference] for item in result.choke_points.verified
                if item.kind == kind}
        assert cuts == set(oracle[kind + "_choke_points"]), "Selected structural cuts changed"

    assert result.nonblocked_returned_candidates == 3, "Nonblocked candidate denominator changed"
    assert result.search.complete and result.choke_points.complete, "Small oracle was truncated"
    assert result.choke_points.candidate_route_exists is True, "Actual selected route disappeared"
    assert result.leverage_scope == "complete-returned-candidates", "Complete counts became sample"

    for item in result.removal_leverage:
        assert item.remaining_candidate_count == 3 - len(item.removed_path_references), (
            "Structural removal denominator includes a fabricated candidate"
        )
        assert aliases[item.reference] not in oracle["excluded_node_removals"], (
            "Endpoint deletion became a node mitigation recommendation"
        )

    assert all(dict(item.state_counts)[ReachabilityState.CONFIRMED] == len(item.path_references)
               for item in result.participation), "Exact supplied summary state was lost"
    assert result.semantics == "structural-selected-candidate-analysis", "Analysis gained authority"


@pytest.mark.parametrize("phase,state", [("initial", ReachabilityState.UNKNOWN),
    ("potential", ReachabilityState.POTENTIAL), ("likely", ReachabilityState.LIKELY),
    ("conflicting-barrier", ReachabilityState.UNKNOWN)])
def test_UnknownAndAttributedStatesRemainDistinctWithoutProbability(tmp_path, phase, state):
    """Potential or unknown routes remain candidates while all exact confidence stays on paths."""

    fixture = Fixture.Create(tmp_path / "workspace")
    result = Analyze(fixture, Projection(fixture, fixture.Phase(phase)))
    assert result.nonblocked_returned_candidates == 3, "Uncertain routes were dropped or promoted"
    assert all(dict(item.state_counts)[state] == len(item.path_references)
               for item in result.participation), "Supplied uncertainty changed in analysis"
    assert all(path.confidence_estimates for path in result.search.paths), "Attribution was lost"
    assert result.choke_points.complete, "Uncertainty was confused with graph-work truncation"


def test_BlockedCandidatesStayExplainableButAreExcludedFromRemovalLeverage(tmp_path):
    """Already blocked routes retain their named barrier proof without receiving added efficacy."""

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))
    result = Analyze(fixture, projection, "key")
    assert len(result.search.paths) == 3 and result.nonblocked_returned_candidates == 0, (
        "Blocked candidates disappeared or became nonblocked leverage"
    )
    assert not result.removal_leverage, "Blocked paths inflated structural mitigation counts"
    assert result.choke_points.candidate_route_exists is False, "Admitted barrier was traversed"
    assert result.choke_points.complete and not result.choke_points.verified, (
        "An absent nonblocked route became a choke-point recommendation"
    )
    assert all(path.decisive_blocking_claims for path in result.search.paths), "Barrier proof lost"


def test_MixedBlockedPathsUseOnlyNonblockedReturnedDenominator(tmp_path):
    """The remediation phase retains one blocked route and two independently available
    candidates.
    """

    fixture = Fixture.Create(tmp_path / "workspace")
    result = Analyze(fixture, Projection(fixture, fixture.Phase("remediation")))
    assert result.nonblocked_returned_candidates == 2, "Blocked route counted as removable leverage"
    aliases = Aliases(fixture)
    counts = {aliases[item.reference]: len(item.removed_path_references)
              for item in result.removal_leverage if item.kind == "relation"}
    assert "portal-identity" not in counts, "An already blocked relation received leverage"
    assert counts["detour-identity"] == counts["identity-billing"] == 2, (
        "Independent available routes changed after the barrier"
    )
    node_cuts = {aliases[item.reference] for item in result.choke_points.verified
                 if item.kind == "node"}
    assert node_cuts == {"detour", "identity", "billing"}, "Admitted barrier did not constrain cuts"


@pytest.mark.parametrize("limits", [ReachabilityLimits(max_paths=1),
    ReachabilityLimits(max_depth=2), ReachabilityLimits(max_work=1),
    ReachabilityLimits(max_frontier=1)])
def test_TruncatedEnumerationNeverMakesSampleParticipationComplete(tmp_path, limits):
    """Exact graph cut checks stay independently meaningful when returned-path search truncates."""

    fixture = Fixture.Create(tmp_path / "workspace")
    result = Analyze(fixture, Projection(fixture, fixture.Phase("confirmed")), search_limits=limits)
    aliases = Aliases(fixture)
    assert not result.search.complete and result.search.reasons, "Enumeration truncation was hidden"
    assert result.leverage_scope == "truncated-returned-candidates", "Sample counts claim all paths"
    assert result.choke_points.complete and result.choke_points.candidate_route_exists, (
        "Path enumeration budget incorrectly constrained independent graph checks"
    )
    assert {aliases[item.reference] for item in result.choke_points.verified
            if item.kind == "node"} == {"identity", "billing"}, (
        "A sample-only element became an unavoidable selected-graph node"
    )


@pytest.mark.parametrize("budget", [1, 8, 15])
def test_CutWorkExhaustionPreservesUnknownAndExactChargedBudget(tmp_path, budget):
    """Unfinished cut checks remain explicit instead of silently proving absence or completeness."""

    fixture = Fixture.Create(tmp_path / "workspace")
    result = Analyze(fixture, Projection(fixture, fixture.Phase("confirmed")),
                      cut_limits=PathAnalysisLimits(budget))
    cuts = result.choke_points
    assert not cuts.complete and cuts.reasons == ("cut-work-limit",), "Cut truncation was hidden"
    assert cuts.examined_successors == budget, "Cut work escaped or fabricated its shared limit"
    assert cuts.candidate_route_exists is not False, "Unexamined work falsely proved no route"
    assert cuts.witness is None or cuts.unverified, "Known witness lost its unverified candidates"


def test_IsolatedTargetIsOnlyAnEmptySelectedSubgraphResult(tmp_path):
    """An exact complete empty candidate set yields no node or relation recommendation."""

    fixture = Fixture.Create(tmp_path / "workspace")
    result = Analyze(fixture, Projection(fixture, fixture.Phase("confirmed")), "isolated")
    assert result.search.no_candidate_path, "Selected isolated target unexpectedly gained a path"
    assert result.choke_points.candidate_route_exists is False, (
        "Isolated selected target gained a route"
    )
    assert not result.participation and not result.removal_leverage, "Absent paths gained counts"
    assert result.choke_points.claim_scope == "selected-nonblocked-transition-subgraph-only", (
        "Graph absence gained a global infrastructure claim"
    )


def test_DeclaredGroupingRetainsEveryOriginalObjectEdgeDirectionAndState(tmp_path):
    """Grouping exposes exact membership and bundled internal relations without synthetic
    continuity.
    """

    fixture = Fixture.Create(tmp_path / "workspace")
    oracle = json.loads((FIXTURES / "path-analysis.oracle.v1.json").read_text())["group"]
    projection = Projection(fixture, fixture.Phase("initial"))
    declaration = PathSemanticGroup(oracle["group_key"], tuple(
        fixture.objects[name].Reference() for name in oracle["members"]))
    result = Analyze(fixture, projection, semantic_groups=(declaration,))
    aliases = Aliases(fixture)
    grouped = next(item for item in result.groups if item.group_key == declaration.group_key)
    identity = next(item for item in result.groups if
                    fixture.objects["identity"].Reference() in item.member_references)
    internal = next(bundle for bundle in result.transition_bundles if
                    bundle.source_group_reference == bundle.target_group_reference
                    == grouped.group_reference)
    outbound = next(bundle for bundle in result.transition_bundles if
                    bundle.source_group_reference == grouped.group_reference
                    and bundle.target_group_reference == identity.group_reference)
    assert {aliases[edge.relation_reference] for edge in internal.transitions} == set(
        oracle["internal_relations"]), "Internal group edges were dropped"
    assert {aliases[edge.relation_reference] for edge in outbound.transitions} == set(
        oracle["to_identity_relations"]), "Parallel presentation relations were collapsed"
    all_members = [member for group in result.groups for member in group.member_references]
    assert sorted(all_members) == list(projection.nodes), "Grouping lost or duplicated a basis node"
    bundled = [edge for bundle in result.transition_bundles for edge in bundle.transitions]
    actual = sorted(bundled, key=lambda edge: edge.relation_reference)
    assert actual == list(projection.transitions), (
        "Presentation lost exact original transition proof or state"
    )
    assert len(result.search.paths) == 3, "Presentation grouping changed actual route enumeration"


def test_GroupAndInputOrderingDoNotChangeAnalysisIdentityOrOriginalPaths(tmp_path):
    """Caller ordering cannot create a distinct explanation for the same declared membership."""

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))
    first = PathSemanticGroup("entry", tuple(fixture.objects[name].Reference()
                                            for name in ("portal", "detour")))
    second = PathSemanticGroup("exit", (fixture.objects["billing"].Reference(),))
    result = Analyze(fixture, projection, semantic_groups=(first, second))
    reordered = Analyze(fixture, projection, semantic_groups=(second,
        PathSemanticGroup(first.group_key, tuple(reversed(first.member_references)))))
    assert result == reordered, "Declaration or member order changed a deterministic explanation"
    renamed = Analyze(fixture, projection, semantic_groups=(replace(first, group_key="renamed"),))
    assert renamed.analysis_reference != result.analysis_reference, "Group declaration was unpinned"
    assert renamed.search == result.search, "Presentation label changed reachability search"


@pytest.mark.parametrize("case", ["mutable", "wrong-type", "overlap", "same-key", "foreign"])
def test_GroupingRefusesInvalidOrForeignBasisMembership(tmp_path, case):
    """Grouping cannot admit duplicates, overlap or objects outside the exact selected basis."""

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))
    portal = fixture.objects["portal"].Reference()
    first = PathSemanticGroup("entry", (portal,))
    cases = {"mutable": [first], "wrong-type": (True,),
        "overlap": (first, PathSemanticGroup("other", (portal,))),
        "same-key": (first, PathSemanticGroup("entry", (fixture.objects["billing"].Reference(),))),
        "foreign": (PathSemanticGroup("foreign", ("object:" + "0" * 64,)),)}

    with pytest.raises(ValueError):
        Analyze(fixture, projection, semantic_groups=cases[case])


@pytest.mark.parametrize("argument", ["cut_limits", "search_limits"])
def test_PublicAnalysisRefusesUntypedBounds(tmp_path, argument):
    """The actual public consumer rejects untyped resource contracts before analysis."""

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))

    with pytest.raises(ValueError, match="typed"):
        Analyze(fixture, projection, **{argument: True})


def test_ChangedCopiedProjectionAndSameRevisionModelCannotSubstituteTheBasis(tmp_path):
    """The public search owner rejects mutated projection coverage and equal-revision contents."""

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))

    with pytest.raises(ValueError):
        Analyze(fixture, replace(projection, admitted_claims=0))

    changed = replace(fixture.model.objects[0], attributes={"unrelated_changed_content": True})
    substituted = replace(fixture.model, objects=(changed, *fixture.model.objects[1:]))

    with pytest.raises(ValueError, match="pinned"):
        AnalyzeReachabilityPaths(projection, substituted, fixture.objects["source"].Reference(),
                                 fixture.objects["event"].Reference())
