# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual Kubernetes evidence import, CAS storage, relocation, triage and reachability consumers."""

from __future__ import annotations

import socket
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.kubernetes_inventory import ApplyVerifiedKubernetesList
from fuzzy1337.model import LocalModelStore, SecurityObject
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
    SearchReachabilityPaths,
)
from tests.kubernetes_helpers import AcquireKubernetes, OwnedKubernetesContext


def ImportKubernetes(context):
    """Acquire original bytes and persist the production transition through canonical CAS.

    Args:
        context: Actual test-owned workspace/model/cluster/evidence stores.

    Returns:
        Saved model, immutable original manifest and explicit interpretation attribution.
    """

    root, basis, cluster, _ = context
    record, provenance = AcquireKubernetes(context)
    proposed, _ = ApplyVerifiedKubernetesList(basis, record, provenance,
        cluster_reference=cluster.Reference(), workspace_root=root)
    saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)

    return saved, record, provenance


def test_KubernetesOriginalEvidenceCasReopenRelocationAndExactReplay(tmp_path):
    """Portable original owner reads and canonical no-op replay leave every saved byte unchanged."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    root, _, cluster, evidence = context
    saved, record, provenance = ImportKubernetes(context)
    original = evidence.Read(record.reference)
    moved = tmp_path / "relocated"
    root.rename(moved)
    reopened = LocalModelStore(moved).Open()
    assert reopened == saved, "Relocation changed canonical resource identity or attribution"
    owner = LocalEvidenceStore(moved / "evidence")
    assert owner.Get(record.evidence_id) == record, "Relocation changed original owner manifest"
    assert owner.Read(record.reference) == original, "Relocation changed original export bytes"
    before = {path.relative_to(moved): path.read_bytes()
              for path in moved.rglob("*") if path.is_file()}
    replayed, delta = ApplyVerifiedKubernetesList(reopened, record, provenance,
        cluster_reference=cluster.Reference(), workspace_root=moved)
    assert replayed == saved and not delta.created and not delta.updated, "Replay changed facts"
    LocalModelStore(moved).Save(replayed, expected_revision=reopened.revision)
    after = {path.relative_to(moved): path.read_bytes()
             for path in moved.rglob("*") if path.is_file()}
    assert after == before, "Exact replay rewrote authoritative workspace or evidence state"


def test_KubernetesRefreshedAdvisoryPreservesExplicitOperatorTriage(tmp_path):
    """Refreshed actual source manifests add observations without reopening dismissed conditions."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    root, _, cluster, evidence = context
    imported, record, provenance = ImportKubernetes(context)
    finding = next(item for item in Findings(imported)
                   if item.check_id == "kubernetes.configured.privileged")
    decision = replace(provenance, source_id="owned.operator", run_reference="run:triage")
    triaged, _ = TransitionFinding(imported, finding.ToObject(imported.workspace_id).Reference(),
        FindingStatus.DISMISSED, decision, "Owned fixture disposition")
    saved = LocalModelStore(root).Save(triaged, expected_revision=imported.revision)
    refreshed_record = evidence.Put(evidence.Read(record.reference), record.reference.role,
        record.reference.media_type, replace(record.provenance,
            started_at="2026-10-14T12:00:01Z", finished_at="2026-10-14T12:00:01Z"))
    refreshed_provenance = replace(provenance, observed_at="2026-10-14T12:00:01Z",
                                  evidence_references=(refreshed_record.reference,))
    refreshed, delta = ApplyVerifiedKubernetesList(saved, refreshed_record, refreshed_provenance,
        cluster_reference=cluster.Reference(), workspace_root=root)
    LocalModelStore(root).Save(refreshed, expected_revision=saved.revision)
    current = next(item for item in Findings(LocalModelStore(root).Open())
                   if item.Fingerprint() == finding.Fingerprint())
    assert current.status is FindingStatus.DISMISSED, "Advisory refresh overwrote operator triage"
    assert current.status_reason == "Owned fixture disposition", "Triage reason was discarded"
    assert delta.revision == saved.revision + 1, "Refresh used more than one canonical transition"
    assert len(refreshed.observations) > len(saved.observations), "Fresh attribution was omitted"


def test_KubernetesRealReachabilityConsumerKeepsConfiguredSelectorAndRbacEdgesUnknown(tmp_path):
    """Actual selector and nominal RBAC edges cannot become confirmed access or physical paths."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    root = context[0]
    model, _, _ = ImportKubernetes(context)
    version = ReachabilityModelVersion.FromModel(model)
    claims = ReadReachabilityClaims(model, (), workspace_root=root,
        expected_model_version=version, context_reference="owned-kubernetes-configuration",
        scope_reference="scope:owned", at="2026-10-14T12:00:01Z")

    for association in ("configured-pod-selector-match", "nominal-role-reference"):
        edge = next(item for item in model.relations
                    if item.attributes["association"] == association)
        projected = ProjectReachability(model, (edge.Reference(),), claims,
                                        expected_model_version=version)
        paths = SearchReachabilityPaths(projected, model, edge.source_reference,
                                        edge.target_reference)
        assert not claims.claims and not projected.transitions[0].claims, "Importer invented claims"
        assert projected.transitions[0].state is ReachabilityState.UNKNOWN, (
            "Configured source relationship became confirmed network or authorization proof"
        )
        assert projected.transitions[0].reasons == ("unassessed",), "Unknown lost its exact reason"
        assert len(paths.paths) == 1 and paths.paths[0].state is ReachabilityState.UNKNOWN, (
            "Configured relationship became a confirmed physical path"
        )


def test_KubernetesOfflineImporterHasNoProcessOrClusterTransportAccess(tmp_path, monkeypatch):
    """Actual evidence-to-model functionality works with all live-access tripwires enabled."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    record, provenance = AcquireKubernetes(context)

    def Refuse(*args, **kwargs):
        """Fail attempted API/socket/native execution during the explicit offline import."""

        raise AssertionError("Offline importer attempted cluster or native process access")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        state, _ = ApplyVerifiedKubernetesList(context[1], record, provenance,
            cluster_reference=context[2].Reference(), workspace_root=context[0])

    assert len(Findings(state)) == 3, "Actual offline functionality failed under live-access guards"


def test_KubernetesForeignWorkspaceAndChangedClusterBasisRefuseBorrowedEvidence(tmp_path):
    """Original evidence cannot populate another workspace or changed/stale cluster model basis."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    record, provenance = AcquireKubernetes(context)
    foreign = OwnedKubernetesContext(tmp_path / "foreign", "foreign-workspace")

    with pytest.raises(ValueError):
        ApplyVerifiedKubernetesList(foreign[1], record,
            replace(provenance, target_reference=foreign[2].Reference()),
            cluster_reference=foreign[2].Reference(), workspace_root=foreign[0])

    with pytest.raises(ValueError):
        ApplyVerifiedKubernetesList(context[1], record, provenance,
            cluster_reference=context[2].Reference(), workspace_root=foreign[0])

    changed = SecurityObject(context[2].identity,
        {"asset_type": "kubernetes-cluster", "cluster_id": "changed-cluster"},
        context[2].provenance)
    state, _ = context[1].Apply(objects=(changed,))
    LocalModelStore(context[0]).Save(state, expected_revision=context[1].revision)

    with pytest.raises(ValueError):
        ApplyVerifiedKubernetesList(context[1], record, provenance,
            cluster_reference=context[2].Reference(), workspace_root=context[0])

    with pytest.raises(ValueError):
        ApplyVerifiedKubernetesList(state, record, provenance,
            cluster_reference=context[2].Reference(), workspace_root=context[0])


def test_KubernetesSameUidInDifferentDeclaredClustersDoesNotCorrelate(tmp_path):
    """Caller-owned cluster anchors domain-separate otherwise identical exported UID identities."""

    left = OwnedKubernetesContext(tmp_path / "left", cluster_id="left")
    right = OwnedKubernetesContext(tmp_path / "right", cluster_id="right")
    left_model, _, _ = ImportKubernetes(left)
    right_model, _, _ = ImportKubernetes(right)
    left_refs = {item.Reference() for item in left_model.objects
                 if item.attributes.get("resource_kind") == "Pod"}
    right_refs = {item.Reference() for item in right_model.objects
                  if item.attributes.get("resource_kind") == "Pod"}
    assert len(left_refs) == 4 and len(right_refs) == 4, "Identical fixture UID set changed"
    assert not left_refs & right_refs, "Cluster-separated UID identities were correlated"
