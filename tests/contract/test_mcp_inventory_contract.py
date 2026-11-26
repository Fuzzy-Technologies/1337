# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the offline MCP file-to-model and redacted evidence contract."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.mcp_inventory import ImportMcpInventory, McpInventoryImport
from fuzzy1337.model import LocalModelStore, ObjectIdentity, ObjectKind, RelationKind
from fuzzy1337.report_commands import OpenReportInput
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

_SAMPLE = Path(__file__).parent / "fixtures" / "mcp.inventory.v1.json"
_CANARY = "synthetic-fixture-value-unfit-for-retention"
_OBSERVED = "2026-11-26T12:30:00+00:00"
_WORKSPACE = "catalog-workspace"


def RefuseExternalWork(*arguments: object, **options: object) -> None:
    """Fail the offline product contract if an external operation is attempted."""

    pytest.fail("Offline MCP inventory attempted process creation or network access")


def ReadSnapshot(model: LocalModelStore, source: Path, revision: int) -> McpInventoryImport:
    """Run the version-one product API with explicit scope, actor and expected revision."""

    return ImportMcpInventory(
        model, source, serverKey="catalog", scopeId="demo",
        consent=ArtifactReadConsent("actor:operator", "consent:owned-file"),
        observedAt=_OBSERVED, expectedRevision=revision,
    )


def test_OfflineInventoryIsIdempotentRedactedAndAttributable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain a repeatable scoped snapshot in the existing model with no external work."""

    root = tmp_path / "work"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Catalog example"), _WORKSPACE)
    LocalScopeStore(root).Create(ScopeSnapshot("demo", _WORKSPACE))
    model = LocalModelStore(root)
    model.Create()
    path = tmp_path / "inventory.json"
    sample = json.loads(_SAMPLE.read_bytes())
    sample["instructions"] += " " + json.dumps({"password": f'quoted "sample" {_CANARY}'})
    tool = sample["tools"]["items"][0]
    tool["inputSchema"]["properties"]["auth"] = {"type": "string", "default": _CANARY}
    tool["inputSchema"]["properties"]["fixture_ghp_" + _CANARY] = {"type": "string"}
    sample["resources"]["items"][0]["uri"] = (
        f"catalog://example:{_CANARY}@documents/index?api_key={_CANARY}"
    )
    path.write_text(json.dumps(sample), encoding="utf-8")
    monkeypatch.setattr(subprocess, "Popen", RefuseExternalWork)
    monkeypatch.setattr(os, "system", RefuseExternalWork)

    if hasattr(os, "posix_spawn"):
        monkeypatch.setattr(os, "posix_spawn", RefuseExternalWork)

    monkeypatch.setattr(socket, "socket", RefuseExternalWork)
    monkeypatch.setattr(socket, "getaddrinfo", RefuseExternalWork)
    first = ReadSnapshot(model, path, 0)
    firstState = model.Open()
    server = ObjectIdentity(_WORKSPACE, ObjectKind.SERVICE, "mcp:v1:catalog")
    toolIdentity = ObjectIdentity(_WORKSPACE, ObjectKind.ASSET, "mcp:v1:catalog:tool:catalog_list")
    assert firstState == first.state, "The product API did not return reopened shared state"
    assert first.serverReference == server.Reference(), "The caller-selected service key drifted"
    assert len(firstState.Objects(ObjectKind.ASSET)) == 8, "A descriptor type was lost"
    assert all(
        edge.kind is RelationKind.CONTAINS and edge.source_reference == first.serverReference
        for edge in firstState.relations
    ) and len(firstState.relations) == 8, "Declared containment must use canonical shared edges"
    assert any(
        edge.target_reference == toolIdentity.Reference() for edge in firstState.relations
    ), (
        "The canonical tool identity is not linked to its declaration server"
    )
    firstObservation = next(
        item for item in firstState.observations if item.Reference() == first.snapshotReference
    )
    assert firstObservation.kind == "mcp-inventory-snapshot", "Snapshot observation is missing"
    assert firstObservation.provenance.execution is None, "An offline import invented execution"
    assert firstObservation.provenance.target_reference == server.Reference(), "Target key drifted"
    assert firstObservation.provenance.scope_reference == "scope:demo", "Scope context was lost"
    assert firstObservation.provenance.run_reference == first.evidence.evidence_id, (
        "The immutable snapshot did not bind its exact acquisition"
    )

    evidence = LocalEvidenceStore(root / "evidence")
    retained = evidence.Get(first.evidence.evidence_id)
    receipt = json.loads(evidence.Read(retained.reference))
    assert retained.reference in OpenReportInput(root).report.EvidenceReferences(), (
        "The standard report reader did not verify model-owned evidence"
    )
    assert firstObservation.provenance.evidence_references == (retained.reference,), (
        "The model observation did not retain a verifiable evidence reference"
    )
    assert receipt["actor_ref"] == "actor:operator" and (
        receipt["read_consent_reference"] == "consent:owned-file"
    ), "Read authorization references were lost from acquisition evidence"
    assert receipt["snapshot_digest"] == firstObservation.attributes["snapshot_digest"], (
        "The model observation must pin the exact normalized snapshot digest"
    )
    assert receipt["inventory"]["sections"]["tools"]["items"][1]["input_schema"][
        "properties"
    ]["auth"]["default"] == "redacted", "Schema defaults appeared in evidence"
    assert receipt["inventory"]["sections"]["resources"]["items"][0]["locator_fingerprint"] == (
        "sha256:" + hashlib.sha256(b"catalog://documents/index").hexdigest()
    ), "Credential-bearing URI components affected resource identity"

    for key in ("capabilities", "tools", "resources", "resource_templates", "prompts"):
        sample[key]["items"].reverse()

    rotated = "other-sample-value"
    path.write_text(json.dumps(sample, indent=2).replace(_CANARY, rotated), encoding="utf-8")
    replay = ReadSnapshot(model, path, 1)
    assert replay.state == firstState and replay.delta.revision == 1, "Exact replay mutated state"
    assert not replay.delta.created and not replay.delta.updated, "Reorder created false drift"
    assert replay.snapshotReference == first.snapshotReference, "Replay replaced the snapshot ID"
    assert replay.evidence == retained, "Replay created an independent acquisition"
    assert len(list((root / "evidence" / "records").iterdir())) == 1, "Replay duplicated evidence"

    for entry in root.rglob("*"):
        if entry.is_file():
            content = entry.read_bytes()
            assert _CANARY.encode() not in content, "A fixture credential entered the workspace"
            assert rotated.encode() not in content, "A rotated credential entered the workspace"
            assert b"catalog://example:" not in content, "A raw URI entered the workspace"


def test_SnapshotCompletenessAndPriorMembershipStayDistinct(tmp_path: Path) -> None:
    """Retain historical membership and distinguish empty, unknown, unsupported and partial."""

    root = tmp_path / "work"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Catalog example"), _WORKSPACE)
    LocalScopeStore(root).Create(ScopeSnapshot("demo", _WORKSPACE))
    model = LocalModelStore(root)
    model.Create()
    path = tmp_path / "inventory.json"
    sample = json.loads(_SAMPLE.read_bytes())
    path.write_text(json.dumps(sample), encoding="utf-8")
    first = ReadSnapshot(model, path, 0)
    changed = {
        "schema_version": 1, "server": sample["server"],
        "instructions": "List only newly added sample catalog entries.",
        "tools": {"status": "incomplete", "items": [{
            **sample["tools"]["items"][0], "inputSchema": {"type": "object"},
        }]},
        "resources": {"status": "unsupported", "items": []},
        "prompts": {"status": "complete", "items": []},
    }
    path.write_text(json.dumps(changed), encoding="utf-8")
    second = ReadSnapshot(model, path, 1)
    assert second.serverReference == first.serverReference, "Changed source broke server identity"
    byReference = {item.Reference(): item for item in second.state.observations}
    baseline = byReference[first.snapshotReference]
    current = byReference[second.snapshotReference]
    sections = current.attributes["sections"]
    assert isinstance(sections, Mapping), "Missing snapshot sections"
    assert sections["tools"]["status"] == "incomplete", "Partial data lost its status"
    assert len(sections["tools"]["objects"]) == 1, "Partial tool membership changed"
    assert sections["prompts"] == {"status": "complete", "objects": ()}, "Empty lost completeness"
    assert sections["resources"] == {"status": "unsupported", "objects": ()}, (
        "Unsupported collapsed"
    )
    assert sections["resource_templates"] == {"status": "unknown", "objects": ()}, (
        "Unknown collapsed"
    )
    assert sections["capabilities"] == {"status": "unknown", "objects": ()}, "Missing collapsed"
    assert baseline.attributes["instructions_fingerprint"] != (
        current.attributes["instructions_fingerprint"]
    ), "An instruction change produced no verifiable snapshot difference"
    assert second.state.Objects(ObjectKind.ASSET), "Later omission erased prior declarations"
    previous = baseline.attributes["sections"]
    assert set(sections["tools"]["objects"]) < set(previous["tools"]["objects"]), (
        "Observed partial tool membership did not reuse stable identities"
    )
    evidence = LocalEvidenceStore(root / "evidence")
    originalRecord = evidence.Get(baseline.provenance.run_reference)
    originalInventory = json.loads(evidence.Read(originalRecord.reference))["inventory"]
    assert originalInventory["sections"]["tools"]["items"][1]["input_schema"]["required"] == [
        "category",
    ], "Historical evidence no longer reproduces the original schema"

    path.write_text(json.dumps(sample), encoding="utf-8")
    historicalReplay = ReadSnapshot(model, path, 2)
    assert historicalReplay.snapshotReference == first.snapshotReference, "Replay lost prior ID"
    assert historicalReplay.state == second.state, "Historical replay rolled back the current view"
