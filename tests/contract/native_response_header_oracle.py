# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent original-field and durable-state oracle for the closed native header check."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

from fuzzy1337.findings import Finding, Findings, FindingSeverity, FindingStatus
from fuzzy1337.model import LocalModelStore
from fuzzy1337.owned_response_custody import OwnedResponseEvidenceStore
from fuzzy1337.workspace import LocalWorkspaceStore

CATALOG = Path(__file__).resolve().parent / "fixtures/zap-passive.oracle.v1.json"
CATALOG_SHA256 = "fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7"
PROFILE = "owned-response-header-absence.v1"
PROVIDER = "native.response-passive"
CAPABILITY = "http.owned-response-header-check"
CHECK = "native.response-header-xcto-absent"
ASSESSMENT = "native.response-header-assessment"
ROLES = frozenset(("stdout", "stderr", "owned-response-request", "owned-response-headers",
    "owned-response-body", "owned-response-wire", "owned-response-receipt"))
ASSESSMENT_FIELDS = frozenset(("schema_version", "profile", "check_id", "analysis_reference",
    "original_receipt_id", "original_job_id", "source_observation_reference", "original_role_ids",
    "header_sha256", "condition_observed", "authority_basis"))
BASIS_FIELDS = frozenset(("workspace_id", "model_revision", "workspace_revision", "scope_reference",
    "scope_revision", "scope_sha256", "policy_reference", "policy_revision", "policy_sha256",
    "owner_reference", "owner_attribution", "analysis_reference", "original_receipt_id",
    "source_target_reference", "literal_ip_reference", "capability", "impact", "workflow_approved",
    "issued_at", "expires_at", "checked_at"))


def FrozenOriginals() -> dict[str, dict[str, bytes]]:
    """Decode only frozen original bytes, ignoring producer and ZAP expectation metadata."""

    raw = CATALOG.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CATALOG_SHA256, "Original catalog identity changed"
    result = {}

    for item in json.loads(raw)["cases"]:
        result[item["case_id"]] = {key: base64.b64decode(item[key]["base64"], validate=True)
            for key in ("header_section", "body", "response")}
        assert result[item["case_id"]]["response"] == (
            result[item["case_id"]]["header_section"] + result[item["case_id"]]["body"]), (
            'Frozen wire must equal its original complete header section and body.'
        )

    return result


def HeaderAbsent(raw: bytes) -> bool:
    """Score complete actual field names, never a body, case label, value or substring."""

    assert raw.startswith(b"HTTP/1.1 200 OK\r\n") and raw.endswith(b"\r\n\r\n"), (
        'Header-name oracle requires one exact complete admitted header section.'
    )
    lines = raw.split(b"\r\n")
    assert lines[-2:] == [b"", b""] and len(lines) <= 67, (
        'Header-name oracle requires one exact complete admitted header section.'
    )
    names = []

    for line in lines[1:-2]:
        name, separator, _value = line.partition(b":")
        assert separator and name and all(character in (
            b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ) for character in name), "Oracle input must be a complete admitted header section"
        names.append(name.lower())

    return b"x-content-type-options" not in names


def OriginalState(root: Path, receipt_id: str) -> dict:
    """Read actual retained IDs and bytes through their owner without creating source evidence."""

    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    store = OwnedResponseEvidenceStore(root / "evidence")
    receipt = store.Get(receipt_id)
    value = json.loads(store.Read(receipt.reference))
    ids = {"stdout": value["evidence_ids"]["stdout"],
        "stderr": value["evidence_ids"]["stderr"],
        "owned-response-request": value["evidence_ids"]["request"],
        "owned-response-headers": value["evidence_ids"]["headers"],
        "owned-response-body": value["evidence_ids"]["body"],
        "owned-response-wire": value["evidence_ids"]["response"],
        "owned-response-receipt": receipt_id}
    assert set(ids) == ROLES and None not in ids.values() and len(set(ids.values())) == 7, (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    assert set(ids.values()) <= set(workspace.evidence_record_references), (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    records = {role: store.Get(identity) for role, identity in ids.items()}
    content = {role: store.Read(record.reference) for role, record in records.items()}
    assert all(record.reference.role == role for role, record in records.items()), (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    assert value["custody"] == "complete" and value["termination"] == "process_exit", (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    assert value["execution"]["state"] == "succeeded" and value["execution"]["exit_code"] == 0, (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    facts = [item for item in model.observations if item.kind == "owned-response-source"
        and item.attributes.get("original_receipt_id") == receipt_id]
    assert len(facts) == 1, "Actual durable original source association is required"
    fact = facts[0]
    assert fact.provenance.run_reference in workspace.job_references, (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )
    assert fact.subject_reference in workspace.object_references, (
        'Actual original custody must retain all seven bound roles and its durable '
        'source/job association.'
    )

    return {"workspace": workspace, "model": model, "ids": ids, "records": records,
        "bytes": content, "source": fact, "receipt": value}


def AssertInterpretation(root: Path, original: dict, analysis: str, url: str):
    """Score actual persisted assessment and Findings against independently read original fields."""

    model = LocalModelStore(root).Open()
    workspace = LocalWorkspaceStore(root).Open()
    facts = [item for item in model.observations if item.kind == ASSESSMENT
        and item.attributes.get("analysis_reference") == analysis]
    assert len(facts) == 1, "One actual retained assessment must identify the explicit analysis"
    fact = facts[0]
    attrs = fact.attributes
    absent = HeaderAbsent(original["bytes"]["owned-response-headers"])
    assert set(attrs) == ASSESSMENT_FIELDS and attrs["schema_version"] == 1, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["profile"] == PROFILE and attrs["check_id"] == CHECK, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["condition_observed"] is absent, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["original_receipt_id"] == original["ids"]["owned-response-receipt"], (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert dict(attrs["original_role_ids"]) == original["ids"], (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["original_job_id"] == original["source"].provenance.run_reference, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["source_observation_reference"] == original["source"].Reference(), (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert attrs["header_sha256"] == hashlib.sha256(
        original["bytes"]["owned-response-headers"]).hexdigest(), (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert fact.subject_reference == original["source"].subject_reference, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    provenance = fact.provenance
    assert provenance.source_id == PROVIDER and provenance.provider_version == "1", (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert provenance.run_reference == analysis and provenance.execution is None, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert set(provenance.evidence_references) == {
        item.reference for item in original["records"].values()}, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    basis = attrs["authority_basis"]
    assert set(basis) == BASIS_FIELDS and basis["capability"] == CAPABILITY, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert basis["impact"] == "PASSIVE" and basis["workflow_approved"] is True, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert basis["owner_attribution"] in ("selected", "trusted-reader"), (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert basis["model_revision"] == original["model"].revision, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert basis["workspace_revision"] == original["workspace"].revision, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert basis["analysis_reference"] == analysis, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    issued, expires, checked = (datetime.fromisoformat(str(basis[key])) for key in
        ("issued_at", "expires_at", "checked_at"))
    assert all(value.tzinfo is not None and value.utcoffset() is not None
        for value in (issued, expires, checked)) and issued <= checked < expires, (
        "Retained authority times must lie in the original aware exclusive admission window"
    )
    assert basis["source_target_reference"] == original["source"].provenance.target_reference, (
        "Native authority must select the exact original URL Target"
    )
    assert provenance.scope_reference == original["source"].provenance.scope_reference, (
        "Native attribution must preserve the original owning scope"
    )
    selected = [item for item in Findings(model) if item.check_id == CHECK
        and any(source.run_reference == analysis for source in item.provenance)]
    assert len(selected) == int(absent), "Count actual saved native Findings, not producer counts"

    for finding in selected:
        assert finding.subject_reference == fact.subject_reference, (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )
        assert finding.location_key == url + "#response-header:x-content-type-options", (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )
        assert finding.severity is FindingSeverity.LOW and finding.confidence == 0.0, (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )
        assert finding.status is FindingStatus.OPEN, (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )
        assert finding.ToObject(model.workspace_id).Reference() in workspace.object_references, (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )
        assert all(source.execution is None for source in finding.provenance
            if source.source_id == PROVIDER), (
            'Saved native assessment and Findings must match original fields, provenance '
            'and retained owner identities.'
        )

    assert original["source"] in model.observations, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert workspace.evidence_record_references == (
        original["workspace"].evidence_record_references
    ), (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )
    assert workspace.job_references == original["workspace"].job_references, (
        'Saved native assessment and Findings must match original fields, provenance and '
        'retained owner identities.'
    )

    return fact, tuple(selected)


def AssertNoNewInterpretation(root: Path, model_before, workspace_before) -> None:
    """Require exact owner state on refusal before either canonical persistence attempt."""

    assert LocalModelStore(root).Open() == model_before, (
        'Refusal must preserve the exact pre-operation canonical model and workspace.'
    )
    assert LocalWorkspaceStore(root).Open() == workspace_before, (
        'Refusal must preserve the exact pre-operation canonical model and workspace.'
    )


def NativeFindingObjects(model) -> tuple:
    """Select actual normalized native objects without treating unrelated triage as detections."""

    return tuple(item for item in model.objects if item.identity.kind.value == "finding"
        and Finding.FromObject(item).check_id == CHECK)
