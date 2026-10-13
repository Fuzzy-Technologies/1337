# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise source/evidence replay, real typed model persistence and current exact GraphQL scope."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.graphql_import import (
    CheckGraphQlTarget,
    GenerateGraphQlRequest,
    ImportGraphQl,
    ProjectGraphQl,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.requests import BindingSource, RequestsFromObject
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURE = Path(__file__).resolve().parents[1] / "contract/fixtures/graphql_introspection.owned.json"
ENDPOINT = "http://127.0.0.1:8080/graphql"
AT = datetime(2026, 10, 13, tzinfo=timezone.utc)


@pytest.mark.parametrize("field_name", ["lookup", "updateOwned"])
def test_ActualSourcePreviewAndTypedRequestsSurviveModelEvidenceReplayAndRelocation(
    tmp_path, field_name,
):
    """Actual first-party owners persist structural metadata and exact original evidence bytes."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned GraphQL"), "graphql-model")
    model_store = LocalModelStore(root)
    initial = model_store.Create()
    source = FIXTURE.read_bytes()
    imported = ImportGraphQl(source, workspace_id=initial.workspace_id, endpoint_url=ENDPOINT)
    operation = next(item for item in imported.operations if item.field_name == field_name)
    preview = GenerateGraphQlRequest(source, operation.Reference(),
                                    workspace_id=initial.workspace_id, endpoint_url=ENDPOINT)
    evidence_store = LocalEvidenceStore(root / "evidence")
    evidence_provenance = EvidenceProvenance(initial.workspace_id, "scope:owned",
        "graphql-import", "1", None, "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z")
    source_record = evidence_store.Put(source, "graphql-introspection", "application/json",
                                       evidence_provenance)
    metadata = CanonicalModelJson(preview.Metadata())
    metadata_record = evidence_store.Put(metadata, "graphql-preview-metadata", "application/json",
                                         evidence_provenance)
    assert imported.source_digest == "sha256:" + source_record.reference.sha256, (
        "Actual source evidence does not bind the importer to its original description bytes"
    )
    provenance = ModelProvenance("graphql-import", "run:owned", "2026-10-13T00:00:01Z",
        "scope:owned", preview.target.Reference(), "1",
        (source_record.reference, metadata_record.reference))
    patch = ProjectGraphQl(imported, provenance=(provenance,))
    changed, _ = initial.Apply(objects=(patch,))
    saved = model_store.Save(changed, expected_revision=initial.revision)
    templates = [item for entity in saved.objects for item in RequestsFromObject(entity)]
    assert operation.template in templates, "Actual GraphQL template failed model round trip"
    assert len(templates) == 5, "Projection lost another typed query/mutation/subscription template"
    assert all(point.binding.source is BindingSource.INPUT for template in templates
               for point in template.injection_points), "Projection manufactured session authority"
    stored = (root / "state/model/model.json").read_bytes()
    assert preview.body not in stored + metadata, "Concrete synthetic request bytes were persisted"
    assert b"synthetic-private-default" not in stored + metadata, "Original default literal leaked"
    assert not Findings(saved), "Structural import manufactured security findings"
    assert evidence_store.Read(source_record.reference) == source, "Original bytes were rewritten"
    assert evidence_store.Read(metadata_record.reference) == metadata, "Reference evidence changed"
    persisted_metadata = next(entity for entity in saved.objects
                              if "graphql_import" in entity.attributes).attributes["graphql_import"]
    assert json.loads(CanonicalModelJson(persisted_metadata)) == imported.ToDict(), (
        "Typed input/operation source metadata changed in actual immutable model attributes"
    )
    before = model_store.Open()
    assert GenerateGraphQlRequest(
        evidence_store.Read(source_record.reference), operation.Reference(),
        workspace_id=initial.workspace_id, endpoint_url=ENDPOINT,
    ) == preview, (
        "Actual evidence replay changed deterministic synthetic encoding"
    )
    assert model_store.Open() == before, "Pure preview preparation mutated actual model state"
    moved = tmp_path / "relocated"
    root.rename(moved)
    reopened = LocalModelStore(moved).Open()
    replay_store = LocalEvidenceStore(moved / "evidence")
    replayed = ImportGraphQl(replay_store.Read(source_record.reference),
                             workspace_id=reopened.workspace_id, endpoint_url=ENDPOINT)
    assert reopened == saved, "Persistence depends on its previous physical workspace path"
    assert replayed == imported, "Raw evidence replay changed exact source-bound typed operations"
    assert replay_store.Read(metadata_record.reference) == metadata, (
        "Actual relocated reference evidence failed replay"
    )
    assert GenerateGraphQlRequest(
        replay_store.Read(source_record.reference), operation.Reference(),
        workspace_id=reopened.workspace_id, endpoint_url=ENDPOINT,
    ) == preview, (
        "Actual relocated source replay changed the synthetic preview"
    )


@pytest.mark.parametrize("field_name", ["lookup", "updateOwned"])
def test_PreviewStillRequiresCurrentExactEndpointWorkspaceAndConsent(tmp_path, field_name):
    """Neither modeled mutation nor generated query changes existing scope/workspace authority."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned GraphQL"), "graphql-scope")
    source = FIXTURE.read_bytes()
    imported = ImportGraphQl(source, workspace_id="graphql-scope", endpoint_url=ENDPOINT)
    operation = next(item for item in imported.operations if item.field_name == field_name)
    scope = ScopeSnapshot("owned", "graphql-scope", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned",
    ))
    scope_store = LocalScopeStore(root)
    scope_store.Create(scope)
    scope_before = (root / "state/scopes/owned.json").read_bytes()
    workspace_before = (root / "workspace.json").read_bytes()
    preview = GenerateGraphQlRequest(source, operation.Reference(),
                                    workspace_id="graphql-scope", endpoint_url=ENDPOINT)

    with pytest.raises(PermissionError):
        CheckGraphQlTarget(operation, preview.target, scope, at=AT)

    permitted = replace(scope, targets=(preview.target,), allow=(preview.target,))
    assert CheckGraphQlTarget(operation, preview.target, permitted, at=AT).Allowed(), (
        "Current explicit exact scope membership failed"
    )

    with pytest.raises(PermissionError):
        CheckGraphQlTarget(operation, preview.target, replace(permitted,
            deny=(Target(TargetKind.IP, "127.0.0.1"),)), at=AT)

    with pytest.raises(PermissionError):
        CheckGraphQlTarget(operation, preview.target, replace(permitted,
            authorization=replace(permitted.authorization, state=AuthorizationState.UNKNOWN)),
            at=AT)

    with pytest.raises(ValueError):
        CheckGraphQlTarget(operation, preview.target, replace(permitted, workspace_id="other"),
                          at=AT)

    with pytest.raises(ValueError):
        CheckGraphQlTarget(operation, Target(TargetKind.URL, ENDPOINT + "?actual=owned"),
                          permitted, at=AT)

    with pytest.raises(ValueError):
        CheckGraphQlTarget(operation, preview.target, permitted, at=datetime(2026, 10, 13))

    assert (root / "state/scopes/owned.json").read_bytes() == scope_before, "Preview changed scope"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Preview changed workspace"
