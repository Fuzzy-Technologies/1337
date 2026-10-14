# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit product grammar and literal handwritten graph oracle over actual saved imports."""

from __future__ import annotations

import json

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sbom_helpers import FIXTURES, Arguments, Context, Run


def test_ActualImportMatchesIndependentNestedInverseAliasDependencyAndLicenseOracle(tmp_path):
    """Actual saved graph resolves exact original arrays and independently declared identities."""

    owned = Context(tmp_path)
    raw = owned.source.read_bytes()
    source = json.loads(raw)
    oracle = json.loads((FIXTURES / "spdx.graph.oracle.json").read_bytes())
    status, outcome = Run(Arguments(owned))
    assert status == 0 and outcome["status"] == "succeeded", "Actual original import must complete"
    model = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    evidence = LocalEvidenceStore(owned.root / "evidence")
    record = evidence.Get(outcome["evidence_id"])
    assert model.revision == outcome["model_revision"] == 1 and workspace.revision == (
        outcome["workspace_revision"]
    ) == 1, "The SDK plus custody fact forms one model revision and one independent workspace save"
    assert evidence.Read(record.reference) == raw and record.provenance.execution is None and (
        record.provenance.invocation_sha256 is None
    ), "Original unmodified input retains actual offline custody without process claims"
    objects = {item.Reference(): item for item in model.objects}
    aliases = {item.attributes["spdx_id"]: item for item in model.observations
               if item.kind == "spdx-source-alias"}
    assert set(aliases) == set(oracle["package_keys"]), "Aliases match the independent oracle"

    for source_id, key in oracle["package_keys"].items():
        assert objects[aliases[source_id].subject_reference].identity.key == key, (
            "Product canonical identity must match the handwritten source-independent key"
        )

    claims = [item for item in model.observations if item.kind == "spdx-relationship-claim"]
    actual = sorted([item.attributes["relationship_index"], item.attributes["source_id"],
        item.attributes["relationship_type"], item.attributes["target_id"]] for item in claims)
    assert actual == oracle["edges"], "Original inverse/direct edges must match the literal oracle"

    for claim in claims:
        fields = claim.attributes
        original = source["relationships"][fields["relationship_index"]]
        actual_coordinate = [fields["original_source_id"], fields["original_type"],
                             fields["original_target_id"]]
        assert actual_coordinate == [
            original["spdxElementId"], original["relationshipType"], original["relatedSpdxElement"]
        ], "Actual retained graph facts must resolve original array index and inverse direction"
        assert fields["evidence_id"] == record.evidence_id and fields["document_sha256"] == (
            record.reference.sha256
        ), "Every source claim retains original manifest custody separately from content digest"

    licenses = sorted(item.attributes["expression"] for item in model.objects
                      if item.attributes.get("asset_type") == "license")
    assert licenses == oracle["declared_license_assets"], "Declared expressions form inert assets"
    assert len([item for item in model.relations if item.kind.value == "contains"]) == (
        oracle["canonical_contains_count"]
    ), "Alias collapse preserves only original direct containment relations"
    assert len([item for item in model.relations
        if item.attributes.get("association") == "spdx-dependency-claim"]) == (
        oracle["canonical_dependency_count"]
    ), "Dependency cycles remain bounded descriptive source claims"
    fact = next(item for item in model.observations if item.kind == "sbom-import-source")
    assert fact.attributes["evidence_id"] == record.evidence_id and all(
        outcome[name] == "confirmed" for name in ("acquisition_commit", "model_commit",
                                                  "workspace_commit")
    ), "Original product custody and each storage owner have independent actual acknowledgements"


@pytest.mark.parametrize("arguments", [[], ["fetch", "SYNTHETIC_PRIVATE_MARKER"],
    ["import", "cyclonedx", "SYNTHETIC_PRIVATE_MARKER"],
    ["import", "spdx-graph", "SYNTHETIC_PRIVATE_MARKER", "--execute"],
])
def test_GrammarRejectsUnknownProfilesAndNeverEchoesRejectedValues(arguments):
    """Source retrieval, other formats and execution options produce safe configuration refusal."""

    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", "Explicit grammar must be valid"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Rejected values stay unreflected"
    assert all(outcome[name] == "not-attempted" for name in (
        "acquisition_commit", "model_commit", "workspace_commit"
    )), "Invalid grammar cannot claim an attempted storage owner operation"
