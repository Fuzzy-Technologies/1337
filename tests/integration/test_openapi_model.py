# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline API imports through real request, workspace, evidence, scope and model consumers."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ModelProvenance, SecurityObject
from fuzzy1337.openapi import CheckOpenApiTarget, ImportOpenApi, ProjectOpenApi
from fuzzy1337.requests import RequestsFromObject
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]


def test_RealApiProjectionPreservesRequestsMetadataAndSeparateScopeOwnership(tmp_path):
    """Attribution and request identities survive replay, reopening and relocation."""

    text = (ROOT / "tests/contract/fixtures/openapi.v3.json").read_text(encoding="utf-8")
    imported = ImportOpenApi(text, workspace_id="demo")
    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("API import integration"), "demo")
    target = Target(TargetKind.URL, "http://127.0.0.1:19001/v1/users/1?limit=1")
    scope = LocalScopeStore(root).Create(ScopeSnapshot(
        "api", "demo", ScopeAuthorization(
            AuthorizationState.GRANTED, "operator:synthetic", "consent:synthetic",
        ), targets=(target,), allow=(target,),
    ))
    scope_before = (root / "state/scopes/api.json").read_bytes()
    workspace_before = (root / "workspace.json").read_bytes()
    safe_bytes = json.dumps(imported.ToDict(), sort_keys=True).encode("utf-8")
    evidence = LocalEvidenceStore(root / "evidence").Put(
        safe_bytes, "api-structure", "application/json", EvidenceProvenance(
            "demo", scope.Reference(), "openapi", "1", "synthetic-import",
            "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z",
        ),
    )
    provenance = ModelProvenance(
        "openapi", "synthetic-import", "2026-10-13T00:00:01Z", scope.Reference(),
        target.Reference(), "1", (evidence.reference,),
    )
    patches = ProjectOpenApi(imported, provenance=(provenance,))
    assert len(patches) == 3, "Operation variants created competing endpoint identities"
    store = LocalModelStore(root)
    state = store.Create()
    prior = SecurityObject(patches[0].identity, {"existing": "preserved"}, (provenance,))
    state, _ = state.Apply(objects=(prior,))
    state = store.Save(state, expected_revision=0)
    state, _ = state.Apply(objects=patches)
    saved = store.Save(state, expected_revision=1)
    replayed, delta = saved.Apply(objects=patches)
    assert replayed == saved and not delta.created and not delta.updated, (
        "OpenAPI expectation failed: replayed == saved and (not "
        "delta.created) and (not delta.updated) "
    )
    assert saved.objects[0].attributes.get("existing") == "preserved", (
        "OpenAPI expectation failed: "
        "saved.objects[0].attributes.get('existing') == 'preserved' "
    )

    for value in saved.objects:
        templates = RequestsFromObject(value)
        assert templates, "Existing typed request consumer could not reopen API projection"
        assert all(template.endpoint.Identity() == value.identity for template in templates), (
            "OpenAPI expectation failed: all((template.endpoint.Identity() "
            "== value.identity for template in templates)) "
        )
        assert value.attributes["openapi_operations"], (
            "OpenAPI expectation failed: "
            "value.attributes['openapi_operations'] "
        )

    marker = b"synthetic-private-source-value"
    before = (root / "state/model/model.json").read_bytes()
    assert marker not in before and marker not in safe_bytes, "Private source values were persisted"
    operation = next(item for item in imported.operations if item.operation_id == "GetUser")
    assert CheckOpenApiTarget(operation, target, scope, at=datetime(
        2026, 10, 13, tzinfo=timezone.utc,
    )).Allowed(), (
        "OpenAPI expectation failed: CheckOpenApiTarget(operation, "
        "target, scope, at=datetime(2026, 10, 13, "
        "tzinfo=timezone.utc)).Allowed() "
    )

    with pytest.raises(PermissionError):
        CheckOpenApiTarget(operation, target, replace(scope, allow=()), at=datetime(
            2026, 10, 13, tzinfo=timezone.utc,
        ))

    assert (root / "state/scopes/api.json").read_bytes() == scope_before, (
        "OpenAPI expectation failed: (root / "
        "'state/scopes/api.json').read_bytes() == scope_before "
    )
    assert (root / "workspace.json").read_bytes() == workspace_before, (
        "OpenAPI expectation failed: (root / "
        "'workspace.json').read_bytes() == workspace_before "
    )
    moved = tmp_path / "relocated"
    root.rename(moved)
    assert LocalModelStore(moved).Open() == saved, (
        "OpenAPI expectation failed: LocalModelStore(moved).Open() == "
        "saved "
    )
    assert (moved / "state/model/model.json").read_bytes() == before, (
        "OpenAPI expectation failed: (moved / "
        "'state/model/model.json').read_bytes() == before "
    )
    assert LocalEvidenceStore(moved / "evidence").Read(evidence.reference) == safe_bytes, (
        "OpenAPI expectation failed: LocalEvidenceStore(moved / "
        "'evidence').Read(evidence.reference) == safe_bytes "
    )
