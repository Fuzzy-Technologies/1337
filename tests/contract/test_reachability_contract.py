# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the independently handwritten state/path oracle through actual owning producers."""

from __future__ import annotations

import json

import pytest

from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReadReachabilityClaims,
    SearchReachabilityPaths,
)
from tests.contract.reachability_fixture import FIXTURES, Fixture


def Projection(fixture, records, selected=None):
    """Use public interfaces on independent source fixtures without constructing output records.

    Args:
        fixture: Existing real model/evidence producer fixture.
        records: Original source assessment records.
        selected: Optional explicit symbolic transition selection.

    Returns:
        Exact public derived projection.
    """

    version = ReachabilityModelVersion(**fixture.Version())
    claims = ReadReachabilityClaims(fixture.model, records, workspace_root=fixture.root,
        expected_model_version=version, context_reference=fixture.graph["context_reference"],
        scope_reference=fixture.graph["scope_reference"], at=fixture.graph["query_at"])
    selection = tuple(fixture.relations[name].Reference() for name in
                      (selected if selected is not None else fixture.relations))

    return ProjectReachability(fixture.model, selection, claims, expected_model_version=version)


@pytest.mark.parametrize("phase", ["initial", "potential", "likely", "confirmed",
                                 "remediation", "conflicting-barrier"])
def test_IndependentSixPhasePathAndBarrierOracle(tmp_path, phase):
    """Every state and named barrier matches handwritten routes paired before canonical sorting."""

    fixture = Fixture.Create(tmp_path / "workspace")
    oracle = json.loads((FIXTURES / "reachability.oracle.v1.json").read_text())
    expected = next(item for item in oracle["phase_expectations"] if item["phase"] == phase)
    projection = Projection(fixture, fixture.Phase(phase))
    aliases = {item.Reference(): name for name, item in fixture.relations.items()}

    for target in ("event", "key"):
        result = SearchReachabilityPaths(projection, fixture.model,
            fixture.objects["source"].Reference(), fixture.objects[target].Reference())
        paths = oracle[target + "_paths"]
        paired = [(tuple(fixture.relations[alias].Reference() for alias in path), state)
                  for path, state in zip(paths, expected[target + "_states"], strict=True)]
        paired.sort(key=lambda item: (len(item[0]), item[0]))
        actual = [(tuple(hop.relation_reference for hop in path.hops), path.state.value)
                  for path in result.paths]
        assert actual == paired, "Transition phase differs from independent path/state oracle"
        assert result.complete and not result.no_candidate_path, "Known selected routes truncated"
        assert not result.reasons, "Small fixture unexpectedly left unexamined work"

        for path in result.paths:
            assert len(set(path.nodes)) == len(path.nodes), "Candidate route repeated a node"
            assert all(aliases[hop.relation_reference] not in oracle["cycle_oracle"][
                "forbidden_path_edges"] for hop in path.hops), "Cycle exclusion changed routes"
            assert path.semantics == "attested-hop-summary", "Hop labels gained physical authority"
            assert path.model_version == projection.model_version, "Path dropped its model pin"
            if path.state.value == "BLOCKED":
                assert path.decisive_blocking_claims, "Blocked summary lost its named proof"
                assert all(claim.blocking_controls for claim in path.decisive_blocking_claims), (
                    "Blocked summary retained no modeled control basis"
                )
            if phase == "initial" and target == "key":
                assert [claim.confidence for claim in path.decisive_blocking_claims] == [1.0], (
                    "Unrelated unknown hop lowered the decisive blocking estimate"
                )


@pytest.mark.parametrize("case_id", ["complete-event", "complete-isolated",
    "cycle-edge-valid-other-query", "exact-limit-complete", "depth-truncation", "work-truncation",
    "frontier-truncation", "path-truncation", "zero-hop"])
def test_HandwrittenBoundedSearchCompletenessOracle(tmp_path, case_id):
    """Complete/no-path, cycle, zero-hop and each truncation result follow declared limits."""

    fixture = Fixture.Create(tmp_path / "workspace")
    oracle = json.loads((FIXTURES / "reachability.oracle.v1.json").read_text())
    case = next(item for item in oracle["search_cases"] if item["id"] == case_id)
    projection = Projection(fixture, fixture.Phase(case["phase"]), case.get("selected_transitions"))
    source = fixture.objects[case["source"]].Reference()
    target = fixture.objects[case["target"]].Reference()
    limits = ReachabilityLimits(**case.get("limits", {}))

    if "refusal" in case:
        with pytest.raises(ValueError):
            SearchReachabilityPaths(projection, fixture.model, source, target, limits=limits)

        return

    result = SearchReachabilityPaths(projection, fixture.model, source, target, limits=limits)
    assert len(result.paths) == case["path_count"], "Bounded count differs from handwritten oracle"
    assert result.complete == case["complete"], "Unexamined work was silently marked complete"
    assert result.no_candidate_path == case["no_candidate_path"], "Incomplete claimed absence"
    assert list(result.reasons) == case.get("reasons", []), "Truncation reason changed"
    assert result.claim_scope == "selected-transition-subgraph-only", "No-path claim became global"
    assert result.examined_successors <= limits.max_work, "Successor work exceeded its budget"

    if "expected_paths" in case:
        actual = [tuple(hop.relation_reference for hop in path.hops) for path in result.paths]
        expected = [tuple(fixture.relations[alias].Reference() for alias in path)
                    for path in case["expected_paths"]]
        assert actual == expected, "Exact-limit or cycle-edge query changed its declared route"


def test_SourceAndInsertionOrderCannotChangePathsOrConfidence(tmp_path):
    """Canonical identities preserve all independent source estimates without choosing a winner."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    first = Projection(fixture, records)
    second = Projection(fixture, tuple(reversed(records)), tuple(reversed(fixture.relations)))
    assert first == second, "Source or edge insertion order changed projection identity"
    extra = fixture.Assessment(fixture.Envelope([
        fixture.Declaration("source-portal", confidence=0.90),
    ]), source_id="second-reachability-attester")
    together = Projection(fixture, (*records, extra))
    edge = next(item for item in together.transitions
                if item.relation_reference == fixture.relations["source-portal"].Reference())
    assert edge.state.value == "CONFIRMED", "Compatible independent attestations became a conflict"
    assert {claim.confidence for claim in edge.claims} == {0.90, 0.99}, "Estimate invented or lost"
    assert len({claim.assessment.evidence_id for claim in edge.claims}) == 2, "Source identity lost"
    assert together == Projection(fixture, (extra, *records)), "Claim order changed exact results"
