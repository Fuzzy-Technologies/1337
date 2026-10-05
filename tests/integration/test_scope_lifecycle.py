# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real registered scope/workspace lifecycle, portable relocation, and ownership isolation."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def test_ScopeRegistrationWorkspaceRoundTripAndRelocation(tmp_path: Path):
    """Persist references through actual owners, relocate, and retain deterministic denied scope."""

    root = tmp_path / "original"
    workspace_store = LocalWorkspaceStore(root)
    workspace = workspace_store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    workspace_before = (root / "workspace.json").read_bytes()
    evidence_path = root / "evidence" / "independent-owner-fixture"
    evidence_path.write_bytes(b"independent immutable fixture")
    other_state = root / "state" / "other-owner-fixture"
    other_state.write_bytes(b"independent model fixture")
    network = Target(TargetKind.NETWORK, "192.0.2.0/24")
    candidate = Target(TargetKind.IP, "192.0.2.5")
    authorization = ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:fixture", "consent:fixture",
        "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z",
    )
    scope_store = LocalScopeStore(root)
    initial = scope_store.Create(ScopeSnapshot(
        "testing", workspace.workspace_id, authorization, allow=(network,), exclusions=(candidate,)
    ))
    registered = scope_store.Save(initial.Register(candidate))

    assert (root / "workspace.json").read_bytes() == workspace_before, (
        "Scope persistence mutated independently owned workspace metadata"
    )
    saved_workspace = workspace_store.Save(replace(
        workspace, scope_references=(registered.Reference(),)
    ))
    document_path = root / "state" / "scopes" / "testing.json"
    document = json.loads(document_path.read_text(encoding="utf-8"))

    assert document["targets"] == [{"kind": "ip", "value": "192.0.2.5"}], (
        "Independent consumer did not observe canonical registered targets"
    )
    assert document["revision"] == 1, "Typed registration was not committed as one revision"
    assert str(tmp_path) not in json.dumps(document), "Scope contains machine-local absolute paths"

    for partition in ("cache", "indexes"):
        (root / partition).rmdir()

    relocated = tmp_path / "relocated"
    root.rename(relocated)
    reopened_workspace = LocalWorkspaceStore(relocated).Open()
    reopened_scope = LocalScopeStore(relocated).Open("testing")
    decision = reopened_scope.Check(candidate, at=datetime(2026, 10, 5, tzinfo=timezone.utc))

    assert reopened_workspace == saved_workspace, "Workspace relocation lost the scope reference"
    assert reopened_scope == registered, "Relocation changed authoritative registered scope"
    assert decision.reason == ScopeDecisionReason.EXCLUDED, "Relocation lost an explicit exclusion"
    assert not decision.Allowed(), "Denied portable scope became allowed"
    assert (relocated / "evidence" / evidence_path.name).read_bytes() == (
        b"independent immutable fixture"
    ), "Scope/workspace lifecycle changed independently owned evidence"
    assert (relocated / "state" / other_state.name).read_bytes() == b"independent model fixture", (
        "Scope persistence modified another domain owner's state"
    )


def test_CopiedScopeCannotAuthorizeAnotherWorkspace(tmp_path: Path):
    """Moving retains identity; copying into a different workspace cannot carry its consent."""

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    LocalWorkspaceStore(first_root).Create(WorkspaceConfiguration("First"), "first")
    LocalWorkspaceStore(second_root).Create(WorkspaceConfiguration("Second"), "second")
    LocalScopeStore(first_root).Create(ScopeSnapshot("testing", "first"))
    target_namespace = second_root / "state" / "scopes"
    target_namespace.mkdir()
    (target_namespace / "testing.json").write_bytes(
        (first_root / "state" / "scopes" / "testing.json").read_bytes()
    )

    with pytest.raises(ValueError, match="identity"):
        LocalScopeStore(second_root).Open("testing")


def test_PrivateScopeCreationPermissionsOnPosix(tmp_path: Path):
    """Create owned scope directories and atomically written records with private permissions."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    LocalScopeStore(root).Create(ScopeSnapshot("testing", "synthetic"))
    namespace = root / "state" / "scopes"

    if os.name == "posix":
        for path in (namespace, namespace / "testing.json"):
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "Scope state is public"
