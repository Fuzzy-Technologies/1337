# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real persisted scope owners consumed by offline journey preparation, without a browser."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.journeys import JourneyScenario, PrepareJourney
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


def test_ActualScopePersistenceFeedsPreparationWithoutWorkspaceOrModelMutation(tmp_path: Path):
    """Portable typed scope/target bindings are reused without a new identity or state schema."""

    scenario = JourneyScenario.FromJson(
        (ROOT / "tests/contract/fixtures/synthetic-journey.v1.json").read_text(encoding="utf-8")
    )
    workspace_root = tmp_path / "workspace"
    workspace_store = LocalWorkspaceStore(workspace_root)
    workspace = workspace_store.Create(
        WorkspaceConfiguration("Synthetic journey"), scenario.workspace_id
    )
    scope_store = LocalScopeStore(workspace_root)
    scope = scope_store.Create(ScopeSnapshot(
        scenario.scope_id, workspace.workspace_id,
        ScopeAuthorization(AuthorizationState.GRANTED, "operator:synthetic", "consent:synthetic"),
        targets=scenario.allowed_targets, allow=scenario.allowed_targets,
    ))
    workspace = workspace_store.Save(replace(workspace, scope_references=(scope.Reference(),)))
    before_workspace = (workspace_root / "workspace.json").read_bytes()
    scope_path = workspace_root / "state/scopes" / (scenario.scope_id + ".json")
    before_scope = scope_path.read_bytes()
    at = datetime(2026, 10, 11, tzinfo=timezone.utc)
    prepared = PrepareJourney(scenario, scope_store.Open(scenario.scope_id), at=at)

    assert prepared.scenario_digest == scenario.Digest(), "Persisted scope lost scenario binding"
    assert prepared.scope_revision == 0, "Preparation changed the scope revision"
    assert (workspace_root / "workspace.json").read_bytes() == before_workspace, (
        "Journey preparation mutated independently owned workspace metadata"
    )
    assert scope_path.read_bytes() == before_scope, "Journey preparation rewrote scope state"
    assert workspace_store.Open() == workspace, "Preparation created a new workspace identity"
    assert not (workspace_root / "state/journeys").exists(), (
        "Offline preparation silently created a competing persisted journey/model store"
    )
    assert scope.targets == scenario.allowed_targets, (
        "Preparation changed existing target identities"
    )

    denied = scope_store.Save(replace(scope, deny=(Target(TargetKind.IP, "127.0.0.1"),)))

    with pytest.raises(PermissionError, match="denied"):
        PrepareJourney(scenario, scope_store.Open(scenario.scope_id), at=at)

    assert denied.revision == prepared.scope_revision + 1, (
        "Later scope changes did not invalidate renewed preparation"
    )
    assert prepared.scope_revision == 0, (
        "Earlier preparation silently adopted a later scope revision"
    )

    relocated = tmp_path / "relocated"
    workspace_root.rename(relocated)

    with pytest.raises(PermissionError, match="denied"):
        PrepareJourney(scenario, LocalScopeStore(relocated).Open(scenario.scope_id), at=at)

    assert LocalWorkspaceStore(relocated).Open() == workspace, (
        "Relocation changed workspace identity"
    )
