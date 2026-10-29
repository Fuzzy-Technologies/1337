# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten independent identity/edge oracle proves original graph observation linkage."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import LocalModelStore, ModelProvenance
from fuzzy1337.sbom_graph import SPDX_GRAPH_IMPORT_VERSION, ApplyVerifiedSpdxGraph
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]


def test_HandwrittenGraphOracleResolvesExactOriginalEdgesAndIndependentCanonicalKeys(tmp_path):
    """Resolve original relationship indexes and expected literal keys without importer helpers."""

    fixtures = ROOT / "tests/contract/fixtures"
    raw = (fixtures / "spdx.graph.v2.3.json").read_bytes()
    source = json.loads(raw)
    oracle = json.loads((fixtures / "spdx.graph.oracle.json").read_bytes())
    root = tmp_path / "ws"
    LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("Owned graph contract"), "graph-contract",
    )
    evidence = LocalEvidenceStore(root / "evidence")
    record = evidence.Put(raw, "sbom", "application/json", EvidenceProvenance(
        "graph-contract", "scope:owned", "inventory.spdx", "1", None,
        "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z",
    ))
    provenance = ModelProvenance("inventory.spdx", "run:contract", record.provenance.finished_at,
        "scope:owned", "target:owned", evidence_references=(record.reference,))
    image = ImageIdentity("sha256:" + "a" * 64)
    state, _ = ApplyVerifiedSpdxGraph(LocalModelStore(root).Create(), record, provenance,
                                     image, root)
    objects = {item.Reference(): item for item in state.objects}
    relations = {item.Reference(): item for item in state.relations}
    aliases = {item.attributes["spdx_id"]: item for item in state.observations
               if item.kind == "spdx-source-alias"}
    assert SPDX_GRAPH_IMPORT_VERSION == 1, "Additive graph profile version changed"
    assert set(aliases) == set(oracle["package_keys"]), "Original package aliases were lost"

    for source_id, expected_key in oracle["package_keys"].items():
        alias = aliases[source_id]
        assert objects[alias.subject_reference].identity.key == expected_key, (
            "Canonical package/image key disagreed with the independent literal identity oracle"
        )
        assert alias.attributes["evidence_id"] == record.evidence_id, "Alias lost original manifest"

    claims = [item for item in state.observations if item.kind == "spdx-relationship-claim"]
    actual_edges = sorted([item.attributes["relationship_index"], item.attributes["source_id"],
                           item.attributes["relationship_type"], item.attributes["target_id"]]
                          for item in claims)
    assert actual_edges == oracle["edges"], "Direct edges disagreed with handwritten oracle"

    for claim in claims:
        facts = claim.attributes
        original = source["relationships"][facts["relationship_index"]]
        original_coordinate = [facts["original_source_id"], facts["original_type"],
                               facts["original_target_id"]]
        assert original_coordinate == [
            original["spdxElementId"], original["relationshipType"], original["relatedSpdxElement"],
        ], "Source relationship index did not resolve exact original inverse direction"
        assert facts["document_sha256"] == record.reference.sha256 and (
            facts["evidence_id"] == record.evidence_id
            and facts["image_reference"] == image.Object(state.workspace_id).Reference()
            and claim.provenance == provenance
        ), "Graph fact lost original content, manifest, image or acquisition bindings"
        relation = relations[claim.subject_reference]
        assert (relation.source_reference, relation.target_reference) == (
            aliases[facts["source_id"]].subject_reference,
            aliases[facts["target_id"]].subject_reference,
        ), "Local source edge endpoints mapped to different canonical packages"

    licenses = sorted(item.attributes["expression"] for item in state.objects
                      if item.attributes["asset_type"] == "license")
    assert licenses == oracle["declared_license_assets"], "Concluded license became a declaration"
    assert len([item for item in state.relations if item.kind.value == "contains"]) == (
        oracle["canonical_contains_count"]
    ), "Containment inference changed the oracle's direct canonical edges"
    assert len([item for item in state.relations
                if item.attributes.get("association") == "spdx-dependency-claim"]) == (
        oracle["canonical_dependency_count"]
    ), "Dependency transitive inference changed the oracle's direct canonical edges"
    assert evidence.Read(record.reference) == raw, "Verified interpretation modified original bytes"
