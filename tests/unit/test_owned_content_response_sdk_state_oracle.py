# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic transition attacks; no actual SDK, Save callbacks or storage acceptance."""

from __future__ import annotations

from copy import deepcopy

import pytest

from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition


def Transition():
    """Construct explicitly synthetic linked owner documents, never original runtime evidence."""

    native = {"reference": "finding:native-unit-only", "status": "confirmed"}
    before = {"model": {"workspace_id": "unit", "revision": 1, "objects": [native],
        "relations": [], "observations": []}, "workspace": {"workspace_id": "unit",
        "revision": 1, "scope_references": ["scope:unit"], "object_references": [native[
            "reference"]], "job_references": [], "evidence_record_references": [],
        "evidence_references": []}, "originals": {"native-unit-original": {"data_hex": "abcd"}}}
    after = deepcopy(before)
    roles = {role: "synthetic-manifest:" + role for role in ("stdout", "stderr",
        "owned-response-request", "owned-response-headers", "owned-response-body",
        "owned-response-wire", "owned-response-receipt")}
    refs = [{"role": role, "synthetic_only": True} for role in roles]
    after["originals"].update({identity: {"manifest": {"reference": reference}}
        for identity, reference in zip(roles.values(), refs, strict=True)})
    receipt = roles["owned-response-receipt"]
    attrs = {"original_receipt_id": receipt, "original_job_id": "job:unit",
        "original_role_ids": roles}
    source = {"reference": "source:unit", "kind": "owned-content-response-source",
        "attributes": attrs, "subject_reference": "endpoint:unit", "provenance": {
            "run_reference": "job:unit", "source_id": "native.loopback-content-response",
            "evidence_references": refs}}
    after["model"]["revision"] = after["workspace"]["revision"] = 2
    after["model"]["objects"].append({"reference": "endpoint:unit", "identity": {
        "kind": "endpoint"}})
    after["model"]["observations"].append(source)
    workspace = after["workspace"]
    workspace["object_references"].append("endpoint:unit")
    workspace["job_references"].append("job:unit")
    workspace["evidence_record_references"] = list(roles.values())
    workspace["evidence_references"] = refs
    summary = {"schema_version": 1, "workflow": "owned-content-response-capture",
        "source_id": "native.loopback-content-response", "state": "completed",
        "acquisition_outcome": "captured", "custody_status": "complete", "stage_retained": True,
        "original_job_id": "job:unit", "original_receipt_id": receipt, "original_role_ids": roles,
        "source_facts": attrs, "model_revision": 2, "workspace_revision": 2,
        "model_persistence_status": "acknowledged", "workspace_persistence_status": "acknowledged",
        "job": {"spec": {"job_id": "job:unit"}, "state": "completed", "failure": None,
            "cancellation_requested": False}}
    saves = [{"owner": owner, "expected_revision": 1, "proposal": deepcopy(after[owner]),
        "returned": deepcopy(after[owner]), "exception_type": None} for owner in (
            "model", "workspace")]
    saves[1]["proposal"]["revision"] = 1

    return before, after, summary, saves


def test_SyntheticAcknowledgementsRequireIndependentReturnedAndReopenedDocuments():
    """The positive is a pure structural fixture, not proof of real storage or execution."""

    AssertSdkSaveTransition(*Transition())


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
        AssertSdkSaveTransition(before, after, summary, saves)
