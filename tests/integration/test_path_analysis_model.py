# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise pure path explanations against reopened real models and independently acquired
evidence.
"""

from __future__ import annotations

import builtins
import socket
from pathlib import Path

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.path_analysis import AnalyzeReachabilityPaths, PathSemanticGroup
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReadReachabilityClaims,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.reachability_fixture import Fixture
from tests.contract.test_reachability_contract import Projection
from tests.integration.test_reachability_model import Bytes


def test_ActualStoredBasisProofAndExplanationReopenAndRelocateWithoutWrites(tmp_path):
    """Existing owners retain evidence and authoritative bytes across actual end-to-end read
    analysis.
    """

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    fixture.model = LocalModelStore(fixture.root).Open()
    before = Bytes(fixture.root)
    projection = Projection(fixture, records)
    group = PathSemanticGroup("declared-entry", tuple(fixture.objects[name].Reference()
                                                    for name in ("portal", "detour")))
    result = AnalyzeReachabilityPaths(projection, fixture.model,
        fixture.objects["source"].Reference(), fixture.objects["event"].Reference(),
        semantic_groups=(group,))
    assert len(result.search.paths) == 3 and len(result.choke_points.verified) == 4, (
        "Reopened attributed model did not produce independently known routes and cuts"
    )
    assert Bytes(fixture.root) == before, "Path analysis changed authoritative workspace contents"
    assert b"synthetic-private-source-value" not in repr(result).encode(), "Raw witness repr leaked"
    moved = tmp_path / "relocated"
    fixture.root.rename(moved)
    fixture.root = moved
    fixture.model = LocalModelStore(moved).Open()
    relocated = AnalyzeReachabilityPaths(Projection(fixture, records), fixture.model,
        fixture.objects["source"].Reference(), fixture.objects["event"].Reference(),
        semantic_groups=(group,))
    assert relocated == result, "Physical workspace path changed portable explanation identity"
    assert Bytes(moved) == before, "Relocated analysis mutated storage"
    evidence = LocalEvidenceStore(moved / "evidence")
    assert all(evidence.Get(record.evidence_id) == record for record in records), (
        "Explanation changed the separately owned source assessment manifests"
    )


def test_PureAnalysisNeverReadsStorageOrPerformsNetworkActivity(tmp_path, monkeypatch):
    """Actual product interface remains pure after the explicit owning model/evidence
    verification.
    """

    fixture = Fixture.Create(tmp_path / "workspace")
    projection = Projection(fixture, fixture.Phase("confirmed"))

    def Refuse(*args, **kwargs):
        """Fail any unadvertised storage, owner or network activity within the pure consumer."""

        raise AssertionError("pure path analysis attempted I/O")

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", Refuse)
        guard.setattr(Path, "open", Refuse)
        guard.setattr(Path, "stat", Refuse)
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(LocalModelStore, "Open", Refuse)
        guard.setattr(LocalEvidenceStore, "Get", Refuse)
        guard.setattr(LocalEvidenceStore, "Read", Refuse)
        result = AnalyzeReachabilityPaths(projection, fixture.model,
            fixture.objects["source"].Reference(), fixture.objects["event"].Reference())

    assert result.search.complete and result.choke_points.complete, "Pure consumer changed results"


def test_ShallowEnumerationCannotHideLongSelectedGraphAlternativeToAnApparentCut(tmp_path):
    """An actual saved 38-hop detour prevents a sample-only node from becoming a graph choke
    point.
    """

    root = tmp_path / "workspace"
    workspace = "owned-long-detour"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned path analysis"), workspace)
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance("owned-graph-declaration", "run:owned",
        "2026-10-13T00:00:00Z", "scope:owned", "target:owned", "1")
    aliases = ("source", "pivot", "target", *(f"detour-{index}" for index in range(37)))
    objects = {name: SecurityObject(ObjectIdentity(workspace, ObjectKind.ASSET,
        "path-analysis:" + name), provenance=(provenance,)) for name in aliases}
    routes = [("source", "pivot"), ("pivot", "target")]
    long_route = ("source", *(f"detour-{index}" for index in range(37)), "target")
    routes.extend(zip(long_route, long_route[1:], strict=False))
    relations = tuple(Relation(RelationKind.RELATED_TO, objects[source].Reference(),
        objects[target].Reference(), provenance=(provenance,)) for source, target in routes)
    changed, _ = initial.Apply(objects=tuple(objects.values()), relations=relations)
    store.Save(changed, expected_revision=initial.revision)
    model = store.Open()
    version = ReachabilityModelVersion.FromModel(model)
    claims = ReadReachabilityClaims(model, (), workspace_root=root, expected_model_version=version,
        context_reference="owned:declared", scope_reference="scope:owned",
        at="2026-10-13T00:00:00Z")
    projection = ProjectReachability(model, tuple(item.Reference() for item in relations), claims,
                                     expected_model_version=version)
    result = AnalyzeReachabilityPaths(projection, model, objects["source"].Reference(),
        objects["target"].Reference(), search_limits=ReachabilityLimits(max_depth=2))
    assert len(result.search.paths) == 1 and not result.search.complete, "Long route was concealed"
    assert result.nonblocked_returned_candidates == 1, "Bare UNKNOWN path gained another count"
    assert result.choke_points.complete and not result.choke_points.verified, (
        "A depth-limited sample falsely proved an unavoidable selected graph element"
    )
    assert any(item.reference == objects["pivot"].Reference()
               for item in result.choke_points.alternatives_exist), "Long alternative not checked"
    assert any(item.reference == objects["pivot"].Reference()
               for item in result.removal_leverage), "Returned sample lost structural leverage"
