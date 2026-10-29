# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Acquire handwritten owned inspect bytes through real canonical workspace/evidence owners."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURES = Path(__file__).parent / "contract" / "fixtures"
TIME = "2026-10-14T09:00:00Z"


def OwnedContext(root, workspace_id="docker-test"):
    """Create actual owned workspace/model stores with an explicit synthetic literal HOST.

    Args:
        root: Test-owned isolated physical directory.
        workspace_id: Explicit synthetic workspace identity.

    Returns:
        Root, persisted canonical snapshot, explicit host and evidence store.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned Docker input"), workspace_id)
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance("synthetic.host", "run:host", TIME, "scope:owned", "host:owned")
    host = SecurityObject(ObjectIdentity(initial.workspace_id, ObjectKind.HOST, "192.0.2.1"),
                          {"fixture_kind": "owned-explicit-host"}, (provenance,))
    state, _ = initial.Apply(objects=(host,))
    saved = store.Save(state, expected_revision=initial.revision)

    return root, saved, host, LocalEvidenceStore(root / "evidence")


def Payload():
    """Read the handwritten input fixture without deriving expectations from production code.

    Returns:
        Mutable isolated fixture document for each test.
    """

    return json.loads((FIXTURES / "docker-inspect.owned.v1.json").read_bytes())


def Acquire(context, payload=None, *, source_changes=None, role="docker-inspect",
            media_type="application/json"):
    """Publish the explicitly supplied original snapshot and exact independent attribution.

    Args:
        context: Existing synthetic workspace/model/host/evidence owners.
        payload: Explicit raw bytes or decoded JSON; None selects the handwritten fixture bytes.
        source_changes: Optional independent provenance substitutions for negative tests.
        role: Caller-declared original evidence role.
        media_type: Caller-declared original media type.

    Returns:
        Exact owning evidence record and corresponding explicit ModelProvenance.
    """

    _, state, host, store = context
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "inventory.docker-inspect",
        "owned-docker-container-inspect-v1", "owned-docker-version", TIME, TIME)

    if source_changes:
        source = replace(source, **source_changes)

    raw = (FIXTURES / "docker-inspect.owned.v1.json").read_bytes() if payload is None else (
        payload if isinstance(payload, bytes) else CanonicalModelJson(payload))
    record = store.Put(raw, role, media_type, source)
    provenance = ModelProvenance(source.source_id, "run:owned-inspect", source.finished_at,
        source.scope_reference, host.Reference(), source.tool_version, (record.reference,))

    return record, provenance
