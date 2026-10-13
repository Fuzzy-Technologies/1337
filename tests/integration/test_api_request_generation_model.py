# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise exact generated targets and existing workspace, scope, evidence and model owners."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.api_request_generation import GenerateOpenApiRequest
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.openapi import CheckOpenApiTarget, ImportOpenApi, ProjectOpenApi
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

ROOT = Path(__file__).resolve().parents[2]
AT = datetime(2026, 10, 13, tzinfo=timezone.utc)


def Source(document_format: str = "json"):
    """Read the independent source fixture without generating an oracle from implementation data.

    Returns:
        Original bounded source text containing explicit synthetic ignored examples.
    """

    fixture = ROOT / f"tests/contract/fixtures/api_request_generation.oas.{document_format}"

    return fixture.read_text(encoding="utf-8")


@pytest.mark.parametrize("document_format", ["json", "yaml"])
def test_GeneratedValuesRemainEphemeralAcrossRealStructuralModelPersistence(tmp_path,
                                                                          document_format):
    """Existing symbolic request owners preserve source attribution after save and relocation."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned generation"), "generation-model")
    store = LocalModelStore(root)
    initial = store.Create()
    text = Source(document_format)
    imported = ImportOpenApi(text, workspace_id=initial.workspace_id,
                             document_format=document_format)
    operation = next(item for item in imported.operations if item.operation_id == "CreateOwned")
    generated = GenerateOpenApiRequest(
        text, operation.Reference(), workspace_id=initial.workspace_id,
        document_format=document_format,
    )
    metadata = CanonicalModelJson(generated.Metadata())
    evidence_store = LocalEvidenceStore(root / "evidence")
    source_evidence = evidence_store.Put(text.encode("utf-8"), "api-description",
        "application/yaml" if document_format == "yaml" else "application/json",
        EvidenceProvenance(initial.workspace_id, "scope:owned", "api-generation", "1", None,
                           "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z"))
    assert imported.source_digest == "sha256:" + source_evidence.reference.sha256, (
        "The original description evidence is not bound to the import's exact source bytes"
    )
    evidence = evidence_store.Put(metadata, "synthetic-request-metadata", "application/json",
        EvidenceProvenance(initial.workspace_id, "scope:owned", "api-generation", "1", None,
                           "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z"))
    provenance = ModelProvenance("api-generation", "run:owned", "2026-10-13T00:00:01Z",
        "scope:owned", generated.target.Reference(), "1",
        (source_evidence.reference, evidence.reference))
    patches = ProjectOpenApi(imported, provenance=(provenance,))
    changed, _ = initial.Apply(objects=patches)
    saved = store.Save(changed, expected_revision=initial.revision)
    actual = [template for entity in saved.objects for template in RequestsFromObject(entity)]
    assert operation.template in actual, "Original symbolic template did not survive projection"
    assert all(point.binding.source is BindingSource.INPUT for template in actual
               for point in template.injection_points), "Symbolic value ownership changed"
    stored_bytes = (root / "state/model/model.json").read_bytes()
    assert generated.body not in stored_bytes and generated.body not in metadata, (
        "Concrete generated body was persisted in structural state or reference metadata"
    )
    assert b"synthetic-private-source-value" not in stored_bytes + metadata, "Source example leaked"
    assert not Findings(saved), "Synthetic generation manufactured security findings"
    assert evidence_store.Read(evidence.reference) == metadata, "Evidence bytes were rewritten"
    assert evidence_store.Read(source_evidence.reference) == text.encode("utf-8"), (
        "The raw API description evidence was normalized or rewritten"
    )
    before = store.Open()
    assert GenerateOpenApiRequest(
        text, operation.Reference(), workspace_id=initial.workspace_id,
        document_format=document_format,
    ) == generated, (
        "Repeated preview changed its exact encoding"
    )
    assert store.Open() == before, "Generating a preview mutated the persisted model"
    moved = tmp_path / "relocated"
    root.rename(moved)
    assert LocalModelStore(moved).Open() == saved, "Structural persistence depends on original path"
    assert LocalEvidenceStore(moved / "evidence").Read(evidence.reference) == metadata, (
        "Attributed reference evidence could not be reopened after relocation"
    )
    assert LocalEvidenceStore(moved / "evidence").Read(source_evidence.reference) == text.encode(
        "utf-8"
    ), "Original source evidence could not be reopened after relocation"


@pytest.mark.parametrize("document_format", ["json", "yaml"])
def test_ActualGeneratedUrlAndQueryRequireCurrentExactScopeConsent(tmp_path, document_format):
    """Generation registers nothing; exact query, deny rules, owner and consent still decide."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned scope"), "generation-scope")
    text = Source(document_format)
    imported = ImportOpenApi(text, workspace_id="generation-scope", document_format=document_format)
    operation = next(item for item in imported.operations if item.operation_id == "CreateOwned")
    original_scope = ScopeSnapshot("owned", "generation-scope", ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:owned", "consent:owned",
    ))
    scope_store = LocalScopeStore(root)
    scope_store.Create(original_scope)
    scope_before = (root / "state/scopes/owned.json").read_bytes()
    workspace_before = (root / "workspace.json").read_bytes()
    generated = GenerateOpenApiRequest(text, operation.Reference(), workspace_id="generation-scope",
                                       document_format=document_format)

    with pytest.raises(PermissionError):
        CheckOpenApiTarget(operation, generated.target, original_scope, at=AT)

    permitted = replace(original_scope, targets=(generated.target,), allow=(generated.target,))
    decision = CheckOpenApiTarget(operation, generated.target, permitted, at=AT)
    assert decision.Allowed(), "Current explicitly permitted actual URL was rejected"
    assert generated.target.value.endswith("?tags=synthetic-0&tags=synthetic-1"), (
        "Scope consumed a structural URL instead of the actual query"
    )

    with pytest.raises(PermissionError):
        CheckOpenApiTarget(operation, Target(TargetKind.URL,
            generated.target.value.split("?")[0]), permitted, at=AT)

    with pytest.raises(PermissionError):
        CheckOpenApiTarget(operation, generated.target, replace(permitted,
            deny=(Target(TargetKind.IP, "127.0.0.1"),)), at=AT)

    with pytest.raises(PermissionError):
        CheckOpenApiTarget(operation, generated.target, replace(permitted,
            authorization=replace(permitted.authorization, state=AuthorizationState.UNKNOWN)),
            at=AT)

    with pytest.raises(ValueError):
        CheckOpenApiTarget(operation, generated.target,
            replace(permitted, workspace_id="other"), at=AT)

    with pytest.raises(ValueError):
        CheckOpenApiTarget(operation, generated.target, permitted, at=datetime(2026, 10, 13))

    assert (root / "state/scopes/owned.json").read_bytes() == scope_before, "Preview changed scope"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Preview changed workspace"
