# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original runtime product acquisition and handwritten SDK oracle remain one canonical contract."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fuzzy1337.findings import Findings
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.docker_helpers import FIXTURES
from tests.runtime_helpers import Arguments, Context, KubernetesContext, Run


def test_ProductImportRetainsOriginalAcquisitionAndIndependentConfiguredConditionOracle(tmp_path):
    """Actual handler preserves original bytes, counts, identity and unknown source meanings."""

    context = Context(tmp_path)
    root, basis, _, evidence, source = context
    original = source.read_bytes()
    times = iter([datetime(2026, 10, 14, 10, 0, 0, tzinfo=timezone.utc),
                  datetime(2026, 10, 14, 10, 0, 1, tzinfo=timezone.utc)])
    status, outcome = Run(Arguments(context), clock=lambda: next(times))
    oracle = json.loads((FIXTURES / "docker-inspect.oracle.v1.json").read_bytes())
    assert status == 0 and outcome["status"] == "succeeded", "Owned product import failed"
    assert outcome["command"] == "runtime.import.docker-inspect" and (
        outcome["schema_version"] == 1
    ), (
        "Product command outcome changed its bounded namespace/version"
    )
    assert all(outcome[field] == "confirmed" for field in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "Successful product import lost one independently acknowledged owner boundary"
    record = evidence.Get(outcome["evidence_id"])
    assert evidence.Read(record.reference) == original, "Product import replaced original bytes"
    assert record.provenance.source_id == "inventory.docker-inspect" and (
        record.provenance.source_version == "owned-docker-container-inspect-v1"
        and record.provenance.tool_version is None
        and record.provenance.started_at == "2026-10-14T10:00:00.000000+00:00"
        and record.provenance.finished_at == "2026-10-14T10:00:01.000000+00:00"
        and record.provenance.execution is None
        and record.provenance.invocation_sha256 is None
    ), "Acquisition invented default provider/daemon execution or lost actual read observations"
    saved = LocalModelStore(root).Open()
    actual = {"objects": len(saved.objects), "relations": len(saved.relations),
              "observations": len(saved.observations), "findings": len(Findings(saved))}
    expected = {**oracle["counts"], "observations": 56}
    assert actual == expected, "Product import lost SDK facts or its one source observation"
    source_facts = [item for item in saved.observations if item.kind == "runtime-import-source"]
    assert len(source_facts) == 1 and (
        source_facts[0].attributes["evidence_id"] == record.evidence_id
    ), (
        "Product import lost its independently bound original manifest identity"
    )
    assert source_facts[0].attributes["read_actor_reference"] == "owner:owned" and (
        source_facts[0].attributes["read_consent_reference"] == "consent:owned-input"
    ), "Source fact replaced explicit current read references with inferred authority"
    checks = {item.check_id for item in Findings(saved)}
    confusion = {"tp": len(checks & set(oracle["expected_checks"])),
                 "fn": len(set(oracle["expected_checks"]) - checks),
                 "fp": len(checks & set(oracle["absent_checks"])),
                 "tn": len(set(oracle["absent_checks"]) - checks)}
    assert confusion == {"tp": 6, "fn": 0, "fp": 0, "tn": 3}, "Configured posture oracle regressed"
    unknown = next(item for item in saved.objects
                   if item.attributes.get("container_id") == oracle["unknown_container"])
    assert all(unknown.attributes[field] is None for field in oracle["unknown_fields"]), (
        "Product import invented a safe/default value for missing source facts"
    )
    workspace = LocalWorkspaceStore(root).Open()
    assert record.evidence_id in workspace.evidence_record_references and (
        record.reference in workspace.evidence_references
        and workspace.scope_references == ("scope:owned",)
        and set(workspace.object_references) == {item.Reference() for item in saved.objects}
        and not workspace.job_references
    ), "Product import lost source/context references or invented a scanner job"
    assert saved.revision == basis.revision + 1 and workspace.revision == 1, (
        "Product import did not use the exact independently selected owner revisions"
    )
    safe = CanonicalModelJson({"outcome": outcome, "model": saved.ToDict()})
    assert b"SYNTHETIC_PRIVATE_MARKER" not in safe and str(source).encode() not in safe, (
        "Original source or selected filename escaped the raw evidence boundary"
    )


def test_KubernetesProductImportRetainsOriginalClusterCustodyAndIndependentOracle(tmp_path):
    """Actual owned List composition preserves the handwritten graph and its unknown meanings."""

    context = KubernetesContext(tmp_path)
    root, basis, cluster, evidence, source = context
    original = source.read_bytes()
    status, outcome = Run(Arguments(context, profile="kubernetes-list"),
        clock=lambda: datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc))
    assert status == 0 and outcome["command"] == "runtime.import.kubernetes-list", (
        "Actual Kubernetes product selected a different profile or failed"
    )
    assert outcome["schema_version"] == 1 and all(outcome[name] == "confirmed" for name in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "Kubernetes product lost independent owner acknowledgements"
    record = evidence.Get(outcome["evidence_id"])
    assert evidence.Read(record.reference) == original and (
        record.provenance.source_id == "inventory.kubernetes-list"
        and record.provenance.source_version == "owned-kubernetes-list-v1"
        and record.provenance.tool_version is None
        and record.provenance.execution is None
        and record.provenance.invocation_sha256 is None
    ), "Product Kubernetes custody changed original bytes or invented provider execution"
    saved = LocalModelStore(root).Open()
    oracle = json.loads((FIXTURES / "kubernetes-list.oracle.v1.json").read_bytes())
    assert {"objects": len(saved.objects), "relations": len(saved.relations),
            "findings": len(Findings(saved))} == oracle["counts"], "Product graph oracle changed"
    checks = {item.check_id for item in Findings(saved)}
    assert {"tp": len(checks & set(oracle["expected_checks"])),
            "fp": len(checks - set(oracle["expected_checks"])),
            "fn": len(set(oracle["expected_checks"]) - checks),
            "tn": len(set(oracle["absent_checks"]) - checks)} == {
        "tp": 3, "fp": 0, "fn": 0, "tn": 3,
    }, "Kubernetes product configured-condition oracle regressed"
    facts = [item for item in saved.observations if item.kind == "runtime-import-source"]
    assert len(facts) == 1 and facts[0].subject_reference == cluster.Reference() and (
        dict(facts[0].attributes) == {
            "profile": "kubernetes-list", "evidence_id": record.evidence_id,
            "source_sha256": record.reference.sha256, "source_version": "owned-kubernetes-list-v1",
            "read_actor_reference": "owner:owned", "read_consent_reference": "consent:owned-input"}
    ), "Original Kubernetes manifest custody was collapsed or bound to a HOST"
    resources = [item for item in saved.objects
                 if item.attributes.get("asset_type") == "kubernetes-resource"]
    containers = [item for item in saved.objects
                  if item.attributes.get("asset_type") == "kubernetes-container-declaration"]
    assert len(resources) == oracle["resources"] and len(containers) == (
        oracle["container_declarations"]
    ), "Kubernetes product synthesized or omitted resources/containers"
    assert all(item.attributes["effective_permissions"] is None for item in resources) and all(
        item.attributes["image_digest_kind"] is None
        and item.attributes["effective_privileges"] is None for item in containers
    ), "Product import inferred effective authorization or image digest domains"
    resource_refs = {item.Reference(): item for item in resources}
    selectors = {}
    roles = {}
    subjects = {}

    def Coordinate(entity):
        """Render the independently authored resource coordinate without deriving expectations."""

        return ":".join((entity.attributes["resource_kind"], entity.attributes["namespace"] or "",
                         entity.attributes["name"]))

    for edge in saved.relations:
        for fields in edge.attributes.get("associations", (edge.attributes,)):
            association = fields["association"]

            if association == "configured-pod-selector-match":
                key = Coordinate(resource_refs[edge.source_reference])
                target = resource_refs[edge.target_reference]
                selectors.setdefault(key, []).append(target.attributes["namespace"] + ":" +
                                                       target.attributes["name"])

            if association == "nominal-role-reference":
                roles[Coordinate(resource_refs[edge.source_reference])] = Coordinate(
                    resource_refs[edge.target_reference])

            if association == "nominal-service-account-subject":
                key = Coordinate(resource_refs[edge.source_reference])
                target = resource_refs[edge.target_reference]
                subjects.setdefault(key, []).append(target.attributes["namespace"] + ":" +
                                                      target.attributes["name"])

    assert {key: sorted(items) for key, items in selectors.items()} == oracle["selector_matches"], (
        "Product selector associations differ from the handwritten namespace/AND oracle"
    )
    assert roles == oracle["role_links"] and {
        key: sorted(items) for key, items in subjects.items()
    } == oracle["subject_links"], "Product nominal RBAC associations differ from original oracle"
    workspace = LocalWorkspaceStore(root).Open()
    assert workspace.evidence_record_references == (record.evidence_id,) and (
        workspace.evidence_references == (record.reference,)
        and workspace.scope_references == ("scope:owned",)
        and not workspace.job_references
        and saved.revision == basis.revision + 1 and workspace.revision == 1
    ), "Kubernetes product changed owner revisions or created scanner execution state"
    rendered = CanonicalModelJson({"outcome": outcome, "model": saved.ToDict()})
    assert b"owned-operator" not in rendered and str(source).encode() not in rendered, (
        "Unselected raw Kubernetes values or filename escaped original custody"
    )
