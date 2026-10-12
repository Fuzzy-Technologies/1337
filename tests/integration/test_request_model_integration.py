# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real request projections through portable workspace, evidence, scope and model stores."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ModelProvenance, SecurityObject
from fuzzy1337.requests import (
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.scope import LocalScopeStore, ScopeDecisionReason, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def test_AttributableRequestProjectionPersistsAndMovesWithoutScopeConsent(tmp_path):
    """Real storage reopens structure and provenance while target registration grants nothing."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Request integration"), "demo")
    target = Target(TargetKind.URL, "http://127.0.0.1:8080/api")
    scope = LocalScopeStore(root).Create(ScopeSnapshot("local", "demo", targets=(target,)))
    scope_before = (root / "state/scopes/local.json").read_bytes()
    workspace_before = (root / "workspace.json").read_bytes()
    endpoint = Endpoint("demo", "http://127.0.0.1:8080", "/api")
    template = RequestTemplate(endpoint, (
        InjectionPoint(InjectionLocation.QUERY, "id", ValueBinding("user-id")),
    ))
    raw = template.ToJson().encode("utf-8")
    evidence_store = LocalEvidenceStore(root / "evidence")
    evidence = evidence_store.Put(raw, "structure", "application/json", EvidenceProvenance(
        "demo", scope.Reference(), "synthetic-request", "1", "structure-fixture",
        "2026-10-11T10:00:00Z", "2026-10-11T10:00:01Z",
    ))
    provenance = ModelProvenance(
        "synthetic-request", "structure-fixture", "2026-10-11T10:00:01Z",
        scope.Reference(), target.Reference(), "1", (evidence.reference,),
    )
    store = LocalModelStore(root)
    state = store.Create()
    baseline = SecurityObject(
        endpoint.Identity(), {"media_type": "application/json"}, (provenance,),
    )
    state, _ = state.Apply(objects=(baseline,))
    state = store.Save(state, expected_revision=0)
    patch = ProjectRequests((template,), provenance=(provenance,))
    state, delta = state.Apply(objects=(patch,))
    saved = store.Save(state, expected_revision=1)
    replayed, replay_delta = saved.Apply(objects=(patch,))
    assert delta.updated == (endpoint.Identity().Reference(),), "Request projection added objects"
    assert replayed == saved and replay_delta.updated == replay_delta.created == (), (
        "Replayed structural metadata unexpectedly advanced model revision"
    )
    assert RequestsFromObject(saved.objects[0]) == (template,), "Model consumer lost the template"
    assert saved.objects[0].attributes["media_type"] == "application/json", (
        "Request projection replaced another owner's Endpoint attribute"
    )
    assert saved.objects[0].provenance[0].execution is None, (
        "Offline structural metadata was represented as an executed request"
    )
    assert any(
        observation.attributes.get("request_templates") is not None
        and observation.provenance.evidence_references == (evidence.reference,)
        for observation in saved.observations
    ), "Request metadata did not retain attributed immutable evidence history"
    before = (root / "state/model/model.json").read_bytes()
    moved = tmp_path / "relocated"
    root.rename(moved)
    reopened = LocalModelStore(moved).Open()
    assert reopened == saved, "Workspace relocation changed canonical request/model identities"
    assert RequestsFromObject(reopened.objects[0]) == (template,), "Relocation lost request state"
    assert (moved / "state/model/model.json").read_bytes() == before, "Relocation rewrote model"
    assert (moved / "state/scopes/local.json").read_bytes() == scope_before, "Scope bytes changed"
    assert (moved / "workspace.json").read_bytes() == workspace_before, "Workspace bytes changed"
    assert LocalEvidenceStore(moved / "evidence").Read(evidence.reference) == raw, "Evidence drift"
    decision = LocalScopeStore(moved).Open("local").Check(
        target, at=datetime(2026, 10, 11, tzinfo=timezone.utc),
    )
    assert decision.reason is ScopeDecisionReason.AUTHORIZATION_UNKNOWN, (
        "A stored request projection granted unknown scope consent"
    )
    assert not decision.Allowed(), "Stored request metadata authorized a scope candidate"


def test_ProjectionFailureNeverWritesModelOrMutatesInput(tmp_path):
    """A foreign typed template fails before model persistence and leaves prior facts intact."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Request integration"), "demo")
    store = LocalModelStore(root)
    state = store.Create()
    provenance = ModelProvenance(
        "synthetic-request", "fixture", "2026-10-11T10:00:00Z", "scope:local", "target:local",
    )
    template = RequestTemplate(Endpoint("demo", "http://127.0.0.1", "/"))
    state, _ = state.Apply(objects=(ProjectRequests((template,), provenance=(provenance,)),))
    saved = store.Save(state, expected_revision=0)
    before = (root / "state/model/model.json").read_bytes()
    foreign = replace(template, endpoint=replace(template.endpoint, workspace_id="other"))

    with pytest.raises(ValueError, match="one endpoint"):
        ProjectRequests((template, foreign), provenance=(provenance,))

    tampered = template.ToDict()
    tampered["request_reference"] = "request:" + "f" * 64

    with pytest.raises(ValueError, match="canonical"):
        RequestTemplate.FromDict(tampered)

    assert store.Open() == saved, "Rejected template changed the actual persisted model"
    assert (root / "state/model/model.json").read_bytes() == before, "Rejected input wrote state"
    assert RequestsFromObject(saved.objects[0]) == (template,), "Snapshot was mutated on failure"
