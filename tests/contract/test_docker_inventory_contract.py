# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten owned Docker inspect oracle checked through the actual canonical importer."""

from __future__ import annotations

import json

from fuzzy1337.docker_inventory import ApplyVerifiedDockerInspect
from fuzzy1337.findings import Findings, FindingStatus
from fuzzy1337.model import LocalModelStore
from tests.docker_helpers import FIXTURES, Acquire, OwnedContext


def test_HandwrittenInventoryRelationshipAndConfiguredPostureOracle(tmp_path):
    """Original owned input yields exact declared positives/negatives and unknown missing facts."""

    context = OwnedContext(tmp_path / "workspace")
    root, basis, host, evidence = context
    record, provenance = Acquire(context)
    original = (FIXTURES / "docker-inspect.owned.v1.json").read_bytes()
    oracle = json.loads((FIXTURES / "docker-inspect.oracle.v1.json").read_bytes())
    state, delta = ApplyVerifiedDockerInspect(basis, record, provenance,
        host_reference=host.Reference(), workspace_root=root)
    saved = LocalModelStore(root).Save(state, expected_revision=basis.revision)
    assert LocalModelStore(root).Open() == saved, "Canonical model reopen lost imported facts"
    actual = {"objects": len(saved.objects), "relations": len(saved.relations),
              "observations": len(saved.observations), "findings": len(Findings(saved))}
    assert actual == oracle["counts"], "Inventory differs from the handwritten object/edge oracle"
    assert delta.revision == basis.revision + 1, "Atomic import created more than one revision"
    checks = {item.check_id for item in Findings(saved)}
    expected = set(oracle["expected_checks"])
    absent = set(oracle["absent_checks"])
    confusion = {"tp": len(checks & expected), "fn": len(expected - checks),
                 "fp": len(checks & absent), "tn": len(absent - checks)}
    assert confusion == {"tp": 6, "fn": 0, "fp": 0, "tn": 3}, (
        "Configured-condition known-answer positives/negatives regressed"
    )
    assert checks == expected, "Importer added an undeclared configured-condition check"
    assert all(item.status is FindingStatus.OPEN for item in Findings(saved)), (
        "Configured condition was promoted into confirmed triage"
    )
    unknown = next(item for item in saved.objects
        if item.attributes.get("container_id") == oracle["unknown_container"])
    assert all(unknown.attributes[name] is None for name in oracle["unknown_fields"]), (
        "Absent Docker facts were interpreted as safe/default values"
    )
    image = next(item for item in saved.objects if item.identity.key == oracle["image_key"])
    assert image.attributes["digest_kind"] == "config", "Runtime image domain changed"
    membership = next(item for item in saved.relations
        if item.attributes["association"] == "reported-network-membership")
    assert membership.attributes["ipv4_address"] == oracle["reported_address"], (
        "Reported assigned IPv4 address lost its exact source association"
    )
    assert membership.attributes["ipv6_address"] == oracle["reported_ipv6"], (
        "Reported assigned IPv6 address lost its exact source association"
    )
    service = next(item for item in saved.objects
        if item.attributes.get("container_port") == oracle["container_port"])
    assert service.attributes["transport"] == "tcp", "Declared protocol changed"
    assert {item["host_port"] for item in service.attributes["host_bindings"]} == {
        oracle["host_port"]}, "Published configuration port differs from original bytes"
    unpublished = next(item for item in saved.objects
        if item.attributes.get("container_port") == 443)
    assert unpublished.attributes["host_bindings"] is None, (
        "Null port binding was converted into observed listening or exposure"
    )
    assert evidence.Get(record.evidence_id) == record, "Original acquisition manifest changed"
    assert evidence.Read(record.reference) == original, "Normalized import replaced original bytes"
    assert all(item.provenance.evidence_references == (record.reference,)
               for item in saved.observations if item.subject_reference != host.Reference()), (
        "Canonical imported facts lost their raw attribution"
    )


def test_OfflineInputProfileExportsOnlyItsExplicitImporterAndLimits():
    """The additive interface retains model schemas and does not masquerade as a live discoverer."""

    from fuzzy1337 import docker_inventory
    from fuzzy1337.model import MODEL_SCHEMA_VERSION

    assert docker_inventory.__all__ == ["DockerInventoryLimits", "ApplyVerifiedDockerInspect"], (
        "Offline profile exported an undeclared acquisition/authority interface"
    )
    assert MODEL_SCHEMA_VERSION == 1, "Docker provider metadata changed canonical model schema"
