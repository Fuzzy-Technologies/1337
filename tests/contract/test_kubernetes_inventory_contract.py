# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten Kubernetes inventory, nominal RBAC and selector oracles through real owners."""

from __future__ import annotations

import json

from fuzzy1337.findings import Findings, FindingStatus
from fuzzy1337.kubernetes_inventory import ApplyVerifiedKubernetesList
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from tests.kubernetes_helpers import FIXTURES, AcquireKubernetes, OwnedKubernetesContext


def Coordinate(entity):
    """Render one selected resource coordinate for comparison with an independent oracle.

    Args:
        entity: Actual imported immutable model object.

    Returns:
        Kind, namespace and literal name coordinate.
    """

    return ":".join((entity.attributes["resource_kind"], entity.attributes["namespace"] or "",
                     entity.attributes["name"]))


def test_KubernetesHandwrittenInventoryRbacAndSelectorOracle(tmp_path):
    """Actual original import and CAS reopen agree with handwritten facts and absent conditions."""

    context = OwnedKubernetesContext(tmp_path / "workspace")
    root, basis, cluster, evidence = context
    record, provenance = AcquireKubernetes(context)
    original = (FIXTURES / "kubernetes-list.owned.v1.json").read_bytes()
    oracle = json.loads((FIXTURES / "kubernetes-list.oracle.v1.json").read_bytes())
    proposed, delta = ApplyVerifiedKubernetesList(basis, record, provenance,
        cluster_reference=cluster.Reference(), workspace_root=root)
    saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
    assert LocalModelStore(root).Open() == saved, "Kubernetes facts were lost on canonical reopen"
    resources = {item.Reference(): item for item in saved.objects
                 if item.attributes.get("asset_type") == "kubernetes-resource"}
    containers = [item for item in saved.objects
                  if item.attributes.get("asset_type") == "kubernetes-container-declaration"]
    assert len(resources) == oracle["resources"], "Exported resource count changed"
    assert len(containers) == oracle["container_declarations"], "Containers were synthesized"
    assert {"objects": len(saved.objects), "relations": len(saved.relations),
            "findings": len(Findings(saved))} == oracle["counts"], "Inventory graph oracle changed"
    assert delta.revision == basis.revision + 1, "Import did not use one atomic model transition"
    checks = {item.check_id for item in Findings(saved)}
    expected = set(oracle["expected_checks"])
    absent = set(oracle["absent_checks"])
    assert {"tp": len(checks & expected), "fn": len(expected - checks),
            "fp": len(checks & absent), "tn": len(absent - checks)} == {
                "tp": 3, "fn": 0, "fp": 0, "tn": 3}, "Configured-condition confusion oracle changed"
    assert checks == expected, "Undeclared effective privilege check was created"
    assert all(item.status is FindingStatus.OPEN for item in Findings(saved)), (
        "Configured conditions were promoted into confirmed triage"
    )
    selectors = {}
    roles = {}
    subjects = {}

    for edge in saved.relations:
        facts = edge.attributes.get("associations", (edge.attributes,))

        for fields in facts:
            association = fields["association"]

            if association == "configured-pod-selector-match":
                key = Coordinate(resources[edge.source_reference])
                target = resources[edge.target_reference]
                selectors.setdefault(key, []).append(target.attributes["namespace"] + ":" +
                                                       target.attributes["name"])

            if association == "nominal-role-reference":
                roles[Coordinate(resources[edge.source_reference])] = Coordinate(
                    resources[edge.target_reference])

            if association == "nominal-service-account-subject":
                key = Coordinate(resources[edge.source_reference])
                target = resources[edge.target_reference]
                subjects.setdefault(key, []).append(target.attributes["namespace"] + ":" +
                                                      target.attributes["name"])

    assert {key: sorted(items) for key, items in selectors.items()} == oracle["selector_matches"], (
        "Same-export selector matching differs from independent namespace/AND oracle"
    )
    assert roles == oracle["role_links"], "Nominal Role/ClusterRole resolution changed"
    assert {key: sorted(items) for key, items in subjects.items()} == oracle["subject_links"], (
        "Nominal ServiceAccount binding links lost explicit cross-namespace source facts"
    )
    reader = next(item for item in resources.values() if Coordinate(item) == "Role:blue:reader")
    assert CanonicalModelJson(reader.attributes["nominal_rules"][0]) == CanonicalModelJson(
        oracle["nominal_reader_rule"]), "Nominal RBAC rule facts changed"
    aggregate = next(item for item in resources.values()
                     if Coordinate(item) == "ClusterRole::aggregated")
    assert aggregate.attributes["aggregation_unresolved"] is True, "Aggregation became authority"
    assert all(item.attributes["effective_permissions"] is None for item in resources.values()), (
        "Nominal resource facts were interpreted as effective permission proof"
    )
    assert all(item.attributes["image_digest_kind"] is None for item in containers), (
        "Configured references or opaque CRI imageIDs acquired an unsupported digest domain"
    )
    assert "owned-operator" not in repr(saved) and "owned-group" not in repr(saved), (
        "Unselected User/Group names leaked into normalized metadata"
    )
    assert evidence.Get(record.evidence_id) == record, "Original owner manifest changed"
    assert evidence.Read(record.reference) == original, "Normalization replaced original bytes"
    observations = [item for item in saved.observations
                    if item.provenance.source_id == provenance.source_id]
    attributed = all(item.provenance.evidence_references == (record.reference,)
                     for item in observations)
    assert attributed, (
        "Imported observation lost original attribution"
    )


def test_KubernetesOfflineProfileExportsOnlyExplicitAdditiveInterface():
    """Experimental import does not introduce live discovery or canonical schema changes."""

    from fuzzy1337 import kubernetes_inventory
    from fuzzy1337.model import MODEL_SCHEMA_VERSION

    assert kubernetes_inventory.__all__ == [
        "KubernetesInventoryLimits", "ApplyVerifiedKubernetesList"], "Unexpected profile interface"
    assert MODEL_SCHEMA_VERSION == 1, "Provider subtype introduced a canonical model schema change"
