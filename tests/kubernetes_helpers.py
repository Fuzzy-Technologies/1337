# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Acquire handwritten Kubernetes List bytes through unchanged workspace/evidence owners."""

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
TIME = "2026-10-14T12:00:00Z"


def OwnedKubernetesContext(root, workspace_id="kubernetes-test", cluster_id="owned-cluster"):
    """Create real test-owned storage with a caller-declared literal cluster anchor.

    Args:
        root: Isolated test-owned physical workspace.
        workspace_id: Explicit workspace identity.
        cluster_id: Explicit caller-owned cluster identity.

    Returns:
        Root, persisted model, cluster anchor and actual evidence owner.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned Kubernetes input"), workspace_id)
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance("synthetic.cluster", "run:cluster", TIME,
                                "scope:owned", "cluster:owned")
    cluster = SecurityObject(ObjectIdentity(initial.workspace_id, ObjectKind.ASSET,
        "kubernetes-cluster:" + cluster_id),
        {"asset_type": "kubernetes-cluster", "cluster_id": cluster_id}, (provenance,))
    state, _ = initial.Apply(objects=(cluster,))
    saved = store.Save(state, expected_revision=initial.revision)

    return root, saved, cluster, LocalEvidenceStore(root / "evidence")


def KubernetesPayload():
    """Read the independent handwritten input into one isolated mutable document.

    Returns:
        Mutable source fixture without deriving expectations from production code.
    """

    return json.loads((FIXTURES / "kubernetes-list.owned.v1.json").read_bytes())


def KubernetesResource(payload, kind, name, namespace=None):
    """Select one explicit fixture coordinate for independent source mutation.

    Args:
        payload: Mutable source document.
        kind: Source Kubernetes kind.
        name: Literal name.
        namespace: Literal namespace or cluster scope.

    Returns:
        Actual source entry at that coordinate.
    """

    return next(item for item in payload["items"] if item["kind"] == kind
        and item["metadata"]["name"] == name and item["metadata"].get("namespace") == namespace)


def AcquireKubernetes(context, payload=None, *, source_changes=None,
                      role="kubernetes-list", media_type="application/json"):
    """Publish exact independently supplied original bytes and matching explicit attribution.

    Args:
        context: Existing isolated workspace/model/cluster/evidence owners.
        payload: Raw bytes, decoded JSON or None to select original handwritten bytes.
        source_changes: Independent provenance substitutions for negative tests.
        role: Explicit original evidence role.
        media_type: Explicit original media type.

    Returns:
        Actual immutable evidence record and matching model attribution.
    """

    _, state, cluster, evidence = context
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "inventory.kubernetes-list",
        "owned-kubernetes-list-v1", "owned-kubernetes-version", TIME, TIME)

    if source_changes:
        source = replace(source, **source_changes)

    raw = (FIXTURES / "kubernetes-list.owned.v1.json").read_bytes() if payload is None else (
        payload if isinstance(payload, bytes) else CanonicalModelJson(payload))
    record = evidence.Put(raw, role, media_type, source)
    provenance = ModelProvenance(source.source_id, "run:owned-kubernetes", source.finished_at,
        source.scope_reference, cluster.Reference(), source.tool_version, (record.reference,))

    return record, provenance
