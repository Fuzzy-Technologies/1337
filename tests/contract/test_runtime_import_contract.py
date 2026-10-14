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
from tests.runtime_helpers import Arguments, Context, Run


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
