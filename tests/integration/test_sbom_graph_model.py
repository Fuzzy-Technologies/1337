# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original graph acquisition/application crosses actual evidence/model/CAS/triage consumers."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import (
    ApplyVerifiedFindings,
    Finding,
    Findings,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.images import ApplyVerifiedCycloneDx, ImageIdentity, PackageIdentity
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.sbom_graph import ApplyVerifiedSpdxGraph
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration, WorkspaceConflictError

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ImageIdentity("sha256:" + "a" * 64)


def Acquire(store, workspace_id, raw, source_id, run_reference):
    """Retain independently acquired original document bytes with actual source custody."""

    record = store.Put(raw, "sbom", "application/json", EvidenceProvenance(
        workspace_id, "scope:owned", source_id, "1", None,
        "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z",
    ))
    provenance = ModelProvenance(source_id, run_reference, record.provenance.finished_at,
        "scope:owned", "target:owned", evidence_references=(record.reference,))

    return record, provenance


def test_OriginalGraphSavedPortableReplayReusesPackagesAndPreservesOperatorTriage(tmp_path):
    """Actual store/save/reopen/move/replay consumers retain canonical linkage and disposition."""

    root = tmp_path / "ws"
    LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("Owned graph integration"), "graph-model",
    )
    store = LocalEvidenceStore(root / "evidence")
    model = LocalModelStore(root)
    initial = model.Create()
    raw_flat = (ROOT / "tests/contract/fixtures/spdx.image.v2.3.json").read_bytes()
    flat_record, flat_context = Acquire(store, initial.workspace_id, raw_flat,
                                        "inventory.flat", "run:flat")
    flat, _ = ApplyVerifiedSpdx(initial, flat_record, flat_context, IMAGE, root)
    state = model.Save(flat, expected_revision=initial.revision)
    cyclone = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "container", "hashes": [
            {"alg": "SHA-256", "content": IMAGE.digest[7:]}]}}, "components": [
            {"type": "library", "bom-ref": "owned-1", "name": "Owned_Lib", "version": "1.0",
             "purl": "pkg:pypi/owned-lib@1.0", "licenses": [{"license": {"id": "MIT"}}]}]}
    cyclone_record, cyclone_context = Acquire(store, initial.workspace_id,
        CanonicalModelJson(cyclone), "inventory.cyclonedx", "run:cyclone")
    updated, _ = ApplyVerifiedCycloneDx(state, cyclone_record, cyclone_context, IMAGE, root)
    state = model.Save(updated, expected_revision=state.revision)
    package = PackageIdentity.FromPurl("pkg:pypi/owned-lib@1.0").Object(state.workspace_id)
    detector = store.Put(b"Owned synthetic detector observation; no scanner execution claimed",
        "stdout", "text/plain", EvidenceProvenance(state.workspace_id, "scope:owned",
            "owned.detector", "1", None, "2026-10-14T00:01:00Z", "2026-10-14T00:01:01Z"))
    detected_context = ModelProvenance("owned.detector", "run:detector",
        detector.provenance.finished_at, "scope:owned", "target:owned",
        evidence_references=(detector.reference,))
    finding = Finding(package.Reference(), "owned.synthetic", "owned-package:1.0",
                      "Owned synthetic detector finding", (detected_context,))
    detected, _ = ApplyVerifiedFindings(state, (finding,), root)
    state = model.Save(detected, expected_revision=state.revision)
    operator = ModelProvenance("operator", "decision:owned", "2026-10-14T00:02:00Z",
                               "scope:owned", "target:owned")
    decided, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
        FindingStatus.RESOLVED, operator, "Owned synthetic disposition")
    basis = model.Save(decided, expected_revision=state.revision)
    raw_graph = (ROOT / "tests/contract/fixtures/spdx.graph.v2.3.json").read_bytes()
    record, provenance = Acquire(store, basis.workspace_id, raw_graph,
                                  "inventory.graph", "run:graph")
    immutable_manifest = record.Serialize()
    updated, delta = ApplyVerifiedSpdxGraph(basis, record, provenance, IMAGE, root)
    assert model.Open() == basis, "In-memory graph application implicitly persisted a model"
    assert delta.previous_revision == basis.revision and delta.revision == basis.revision + 1, (
        "Graph did not retain its exact model revision basis"
    )
    state = model.Save(updated, expected_revision=basis.revision)
    assert model.Open() == state, "Saved graph could not reopen through canonical consumer"
    packages = [item for item in state.objects if item.attributes.get("asset_type") == "package"]
    owned_lib = [item for item in packages if item.identity == package]
    assert len(packages) == 3 and len(owned_lib) == 1, "Graph invented competing canonical packages"
    assert {item.source_id for item in owned_lib[0].provenance} == {
        "inventory.flat", "inventory.cyclonedx", "inventory.graph",
    }, "Graph ingestion lost cross-source package provenance"
    assert Findings(state) == Findings(basis), "Graph rewrote existing detector or operator triage"
    assert Findings(state)[0].status is FindingStatus.RESOLVED, "Owner disposition was lost"

    with pytest.raises(WorkspaceConflictError):
        model.Save(replace(updated, revision=updated.revision + 1),
                   expected_revision=basis.revision)

    saved_bytes = (root / "state/model/model.json").read_bytes()
    moved = tmp_path / "moved"
    root.rename(moved)
    reopened = LocalModelStore(moved).Open()
    assert reopened == state, "Relocated saved graph changed canonical consumers"
    relocated_store = LocalEvidenceStore(moved / "evidence")
    original = relocated_store.Get(record.evidence_id)
    assert original.Serialize() == immutable_manifest, "Relocation changed original source manifest"
    assert relocated_store.Read(original.reference) == raw_graph, "Relocation lost original bytes"
    replayed, replay_delta = ApplyVerifiedSpdxGraph(reopened, original, provenance, IMAGE, moved)
    assert replayed == reopened and not replay_delta.created and not replay_delta.updated, (
        "Saved relocated original replay changed state or duplicated source facts"
    )
    assert LocalModelStore(moved).Save(replayed, expected_revision=reopened.revision) == reopened, (
        "Exact graph replay failed canonical model CAS save"
    )
    assert (moved / "state/model/model.json").read_bytes() == saved_bytes, (
        "No-op replay rewrote bytes"
    )
    assert Findings(replayed) == Findings(basis), "Portable replay changed owner triage"
