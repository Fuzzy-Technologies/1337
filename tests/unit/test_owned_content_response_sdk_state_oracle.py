# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic transition attacks; no actual SDK, Save callbacks or storage acceptance."""

from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

URL = "http://127.0.0.1:32123/research/content"


def Transition():
    """Construct explicitly synthetic linked owner documents, never original runtime evidence."""

    native = {"reference": "finding:native-unit-only", "status": "confirmed"}
    before = {"model": {"workspace_id": "unit", "revision": 1, "objects": [native],
        "relations": [], "observations": []}, "workspace": {"workspace_id": "unit",
        "revision": 1, "scope_references": [], "object_references": [native[
            "reference"]], "job_references": [], "evidence_record_references": [],
        "evidence_references": []}, "originals": {"native-unit-original": {"data_hex": "abcd"}}}
    after = deepcopy(before)
    roles = {role: "synthetic-manifest:" + role for role in ("stdout", "stderr",
        "owned-response-request", "owned-response-headers", "owned-response-body",
        "owned-response-wire", "owned-response-receipt")}
    refs = [{"role": role, "synthetic_only": True} for role in roles]
    after["originals"].update({identity: {"manifest": {"reference": reference,
        "provenance": {"workspace_id": "unit", "scope_reference": "scope:unit"}}}
        for identity, reference in zip(roles.values(), refs, strict=True)})
    receipt = roles["owned-response-receipt"]
    attrs = {"original_receipt_id": receipt, "original_job_id": "job:unit",
        "original_role_ids": roles}
    endpoint_identity = {"workspace_id": "unit", "kind": "endpoint", "key": URL}
    endpoint_reference = "object:" + hashlib.sha256(Canonical({"namespace": "object",
        "identity": endpoint_identity})).hexdigest()
    source = {"reference": "source:unit", "kind": "owned-content-response-source",
        "attributes": attrs, "subject_reference": endpoint_reference, "provenance": {
            "run_reference": "job:unit", "source_id": "native.loopback-content-response",
            "scope_reference": "scope:unit",
            "target_reference": "target:" + hashlib.sha256(Canonical({"kind": "url",
                "value": URL})).hexdigest(),
            "evidence_references": refs}}
    after["model"]["revision"] = after["workspace"]["revision"] = 2
    after["model"]["objects"].append({"reference": endpoint_reference,
        "identity": endpoint_identity})
    after["model"]["observations"].append(source)
    workspace = after["workspace"]
    workspace["scope_references"].append("scope:unit")
    workspace["object_references"].append(endpoint_reference)
    workspace["job_references"].append("job:unit")
    workspace["evidence_record_references"] = list(roles.values())
    workspace["evidence_references"] = refs
    summary = {"schema_version": 1, "workflow": "owned-content-response-capture",
        "source_id": "native.loopback-content-response", "state": "completed",
        "acquisition_outcome": "captured", "custody_status": "complete", "stage_retained": True,
        "original_job_id": "job:unit", "original_receipt_id": receipt, "original_role_ids": roles,
        "source_facts": attrs, "model_revision": 2, "workspace_revision": 2,
        "model_persistence_status": "acknowledged", "workspace_persistence_status": "acknowledged",
        "job": {"spec": {"job_id": "job:unit", "workspace_id": "unit",
            "scope_reference": "scope:unit"},
            "state": "completed", "failure": None,
            "cancellation_requested": False}}
    saves = [{"owner": owner, "expected_revision": 1, "proposal": deepcopy(after[owner]),
        "returned": deepcopy(after[owner]), "exception_type": None} for owner in (
            "model", "workspace")]
    saves[1]["proposal"]["revision"] = 1

    return before, after, summary, saves


def test_SyntheticAcknowledgementsRequireIndependentReturnedAndReopenedDocuments():
    """The positive is a pure structural fixture, not proof of real storage or execution."""

    AssertSdkSaveTransition(*Transition(), url=URL, workspace_id="unit",
        scope_reference="scope:unit")


@pytest.mark.parametrize("mutation", ["lost-return", "observed-commit", "foreign-proposal",
    "bool-cas", "double-save", "triage", "original-bytes", "unattached-role", "foreign-job",
    "cancelled", "bool-revision", "configuration", "finding", "workspace-proposal"])
def test_SummarySuccessCannotConcealUnacknowledgedChangedOrUnattachedOriginals(mutation):
    """Changing only one evidence boundary must invalidate the otherwise successful summary."""

    before, after, summary, saves = Transition()

    if mutation == "lost-return":
        saves[0]["returned"] = None

    elif mutation == "observed-commit":
        summary["workspace_persistence_status"] = "observed-committed"

    elif mutation == "foreign-proposal":
        saves[0]["proposal"]["revision"] = 3

    elif mutation == "bool-cas":
        saves[0]["expected_revision"] = True

    elif mutation == "double-save":
        saves.append(deepcopy(saves[0]))

    elif mutation == "triage":
        after["model"]["objects"][0]["status"] = "replaced"
        saves[0]["proposal"] = saves[0]["returned"] = deepcopy(after["model"])

    elif mutation == "original-bytes":
        after["originals"]["native-unit-original"]["data_hex"] = "00"

    elif mutation == "unattached-role":
        after["workspace"]["evidence_record_references"].pop()
        saves[1]["proposal"], saves[1]["returned"] = (deepcopy(after["workspace"]),
            deepcopy(after["workspace"]))
        saves[1]["proposal"]["revision"] = 1

    elif mutation == "foreign-job":
        summary["job"]["spec"]["job_id"] = "job:foreign"

    elif mutation == "cancelled":
        summary["job"]["cancellation_requested"] = True

    elif mutation == "bool-revision":
        summary["model_revision"] = True

    elif mutation == "configuration":
        after["workspace"]["unexpected_configuration"] = "foreign"
        saves[1]["proposal"], saves[1]["returned"] = (deepcopy(after["workspace"]),
            deepcopy(after["workspace"]))
        saves[1]["proposal"]["revision"] = 1

    elif mutation == "workspace-proposal":
        saves[1]["proposal"]["revision"] = 2

    else:
        after["model"]["objects"][1]["identity"]["kind"] = "finding"
        saves[0]["proposal"] = saves[0]["returned"] = deepcopy(after["model"])

    with pytest.raises(AssertionError):
        AssertSdkSaveTransition(before, after, summary, saves, url=URL, workspace_id="unit",
            scope_reference="scope:unit")


@pytest.mark.parametrize("mutation", ["endpoint", "manifest", "job-owner", "scope"])
def test_ConsistentForeignEndpointOrOwnerCannotReplaceIndependentlySelectedSource(mutation):
    """Re-signed owner documents cannot retarget otherwise coherent capture associations."""

    before, after, summary, saves = Transition()

    if mutation == "endpoint":
        endpoint = after["model"]["objects"][1]
        old_reference = endpoint["reference"]
        endpoint["identity"]["key"] = URL + "/foreign"
        endpoint["reference"] = "object:" + hashlib.sha256(Canonical({"namespace": "object",
            "identity": endpoint["identity"]})).hexdigest()
        after["workspace"]["object_references"].remove(old_reference)
        after["workspace"]["object_references"].append(endpoint["reference"])
        after["model"]["observations"][0]["subject_reference"] = endpoint["reference"]

    elif mutation == "manifest":
        identity = summary["original_role_ids"]["owned-response-body"]
        after["originals"][identity]["manifest"]["provenance"]["workspace_id"] = "foreign"

    elif mutation == "job-owner":
        summary["job"]["spec"]["workspace_id"] = "foreign"

    else:
        for identity in summary["original_role_ids"].values():
            after["originals"][identity]["manifest"]["provenance"]["scope_reference"] = (
                "scope:foreign")

    for row in saves:
        row["returned"] = deepcopy(after[row["owner"]])
        row["proposal"] = deepcopy(row["returned"])

        if row["owner"] == "workspace":
            row["proposal"]["revision"] = 1

    with pytest.raises(AssertionError):
        AssertSdkSaveTransition(before, after, summary, saves, url=URL, workspace_id="unit",
            scope_reference="scope:unit")
