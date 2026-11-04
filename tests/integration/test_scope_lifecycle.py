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
    workspaceStore = LocalWorkspaceStore(root)
    workspace = workspaceStore.Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    workspaceBefore = (root / "workspace.json").read_bytes()
    evidencePath = root / "evidence" / "independent-owner-fixture"
    evidencePath.write_bytes(b"independent immutable fixture")
    otherState = root / "state" / "other-owner-fixture"
    otherState.write_bytes(b"independent model fixture")
    network = Target(TargetKind.NETWORK, "192.0.2.0/24")
    candidate = Target(TargetKind.IP, "192.0.2.5")
    authorization = ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:fixture", "consent:fixture",
        "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z",
    )
    scopeStore = LocalScopeStore(root)
    initial = scopeStore.Create(ScopeSnapshot(
        "testing", workspace.workspace_id, authorization, allow=(network,), exclusions=(candidate,)
    ))
    registered = scopeStore.Save(initial.Register(candidate))

    assert (root / "workspace.json").read_bytes() == workspaceBefore, (
        "Scope persistence mutated independently owned workspace metadata"
    )
    savedWorkspace = workspaceStore.Save(replace(
        workspace, scope_references=(registered.Reference(),)
    ))
    documentPath = root / "state" / "scopes" / "testing.json"
    document = json.loads(documentPath.read_text(encoding="utf-8"))

    assert document["targets"] == [{"kind": "ip", "value": "192.0.2.5"}], (
        "Independent consumer did not observe canonical registered targets"
    )
    assert document["revision"] == 1, "Typed registration was not committed as one revision"
    assert str(tmp_path) not in json.dumps(document), "Scope contains machine-local absolute paths"

    for partition in ("cache", "indexes"):
        (root / partition).rmdir()

    relocated = tmp_path / "relocated"
    root.rename(relocated)
    reopenedWorkspace = LocalWorkspaceStore(relocated).Open()
    reopenedScope = LocalScopeStore(relocated).Open("testing")
    decision = reopenedScope.Check(candidate, at=datetime(2026, 10, 5, tzinfo=timezone.utc))

    assert reopenedWorkspace == savedWorkspace, "Workspace relocation lost the scope reference"
    assert reopenedScope == registered, "Relocation changed authoritative registered scope"
    assert decision.reason == ScopeDecisionReason.EXCLUDED, "Relocation lost an explicit exclusion"
    assert not decision.Allowed(), "Denied portable scope became allowed"
    assert (relocated / "evidence" / evidencePath.name).read_bytes() == (
        b"independent immutable fixture"
    ), "Scope/workspace lifecycle changed independently owned evidence"
    assert (relocated / "state" / otherState.name).read_bytes() == b"independent model fixture", (
        "Scope persistence modified another domain owner's state"
    )


def test_CopiedScopeCannotAuthorizeAnotherWorkspace(tmp_path: Path):
    """Moving retains identity; copying into a different workspace cannot carry its consent."""

    firstRoot = tmp_path / "first"
    secondRoot = tmp_path / "second"
    LocalWorkspaceStore(firstRoot).Create(WorkspaceConfiguration("First"), "first")
    LocalWorkspaceStore(secondRoot).Create(WorkspaceConfiguration("Second"), "second")
    LocalScopeStore(firstRoot).Create(ScopeSnapshot("testing", "first"))
    targetNamespace = secondRoot / "state" / "scopes"
    targetNamespace.mkdir()
    (targetNamespace / "testing.json").write_bytes(
        (firstRoot / "state" / "scopes" / "testing.json").read_bytes()
    )

    with pytest.raises(ValueError, match="identity"):
        LocalScopeStore(secondRoot).Open("testing")


def test_PrivateScopeCreationPermissionsOnPosix(tmp_path: Path):
    """Create owned scope directories and atomically written records with private permissions."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    LocalScopeStore(root).Create(ScopeSnapshot("testing", "synthetic"))
    namespace = root / "state" / "scopes"

    if os.name == "posix":
        for path in (namespace, namespace / "testing.json"):
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "Scope state is public"
