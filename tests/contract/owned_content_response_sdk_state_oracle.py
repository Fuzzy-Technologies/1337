# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure joins of original SDK Save observations and reopened state, without runtime proof.

The caller must separately authenticate installed execution, seven original part manifests,
source authority and target settlement. Summary claims alone cannot satisfy this oracle.
"""

from __future__ import annotations

from tests.contract.owned_content_response_sdk_oracle import Canonical


def ByReference(rows: list[dict]) -> dict[str, dict]:
    """Index detached original model rows without silently dropping duplicate identities."""

    result = {row["reference"]: row for row in rows}
    assert len(result) == len(rows), "Original model identities cannot be duplicated"

    return result


def AssertSdkSaveTransition(before: dict, after: dict, summary: dict, saves: list[dict]) -> None:
    """Join one successful fresh acquisition's actual Save returns to reopened original state.

    Args:
        before: Original Setup/Inspect state before the acquisition attempt.
        after: Independently reopened Inspect state after the same attempt.
        summary: Original actual SDK summary, not a reconstructed expected result.
        saves: Original Save observations in call order: owner, expected_revision, proposal,
            returned and exception_type. The model basis is its original keyword argument;
            the workspace basis is its original proposal revision. Observers return unchanged
            original values; workspace Save itself increments the proposal revision.

    This predicate verifies transitions and associations only. It cannot prove that input
    documents came from a real SDK, durable storage, or actual Save calls by itself.
    """

    assert type(summary["schema_version"]) is int and summary["schema_version"] == 1
    assert summary["workflow"] == "owned-content-response-capture" and summary[
        "source_id"] == "native.loopback-content-response"
    assert summary["state"] == "completed" and summary["acquisition_outcome"] == "captured"
    assert summary["custody_status"] == "complete" and summary["stage_retained"] is True
    assert type(saves) is list and [row["owner"] for row in saves] == ["model", "workspace"], (
        "Exactly one original model Save and one original workspace Save are required")

    for row in saves:
        owner = row["owner"]
        prior, actual = before[owner], after[owner]
        assert type(prior["revision"]) is int and type(actual["revision"]) is int
        assert type(row["expected_revision"]) is int and row["expected_revision"] == (
            prior["revision"]), "Original Save must retain the exact original CAS basis"
        assert actual["revision"] == prior["revision"] + 1
        assert row["exception_type"] is None and row["returned"] is not None, (
            "Observed commits or missing Save returns cannot establish acknowledgement")
        expected_proposal = {**actual, "revision": prior["revision"]} if owner == (
            "workspace") else actual
        assert Canonical(row["proposal"]) == Canonical(expected_proposal) and Canonical(
            row["returned"]) == Canonical(actual), (
                "Original proposal and returned/reopened state must retain actual owner semantics")
        assert summary[owner + "_persistence_status"] == "acknowledged"
        assert type(summary[owner + "_revision"]) is int and summary[owner + "_revision"] == (
            actual["revision"])
        assert prior["workspace_id"] == actual["workspace_id"]

    for field in ("objects", "relations", "observations"):
        prior = ByReference(before["model"][field])
        actual = ByReference(after["model"][field])
        assert all(key in actual and Canonical(value) == Canonical(actual[key])
            for key, value in prior.items()), "Existing native model and triage must survive"

    for owner, mutable in (("workspace", {"revision", "object_references", "job_references",
        "evidence_record_references", "evidence_references"}), ("model", {
            "revision", "objects", "observations"})):
        assert Canonical({key: value for key, value in before[owner].items()
            if key not in mutable}) == Canonical({key: value for key, value in after[owner].items()
            if key not in mutable}), "Acquisition must preserve unrelated owner configuration"

    prior_objects = ByReference(before["model"]["objects"])
    added_objects = [row for row in after["model"]["objects"] if row["reference"] not in (
        prior_objects)]
    assert len(added_objects) == 1 and added_objects[0]["identity"]["kind"] == "endpoint", (
        "A fresh source acquisition adds one Endpoint and no Findings")

    for identity, original in before["originals"].items():
        assert identity in after["originals"] and Canonical(original) == Canonical(
            after["originals"][identity]), "Existing original native evidence cannot be replaced"

    workspace = after["workspace"]
    for field in ("scope_references", "object_references", "job_references",
        "evidence_record_references", "evidence_references"):
        prior = {Canonical(value) for value in before["workspace"][field]}
        actual = [Canonical(value) for value in workspace[field]]
        assert len(set(actual)) == len(actual) and prior <= set(actual), (
            "Original workspace associations cannot disappear or duplicate")

    job_id, receipt_id = summary["original_job_id"], summary["original_receipt_id"]
    assert type(job_id) is str and job_id and job_id in workspace["job_references"]
    job = summary["job"]
    assert job["spec"]["job_id"] == job_id and job["state"] == "completed" and (
        job["failure"] is None and job["cancellation_requested"] is False)
    roles = summary["original_role_ids"]
    assert len(roles) == len(set(roles.values())) == 7 and roles[
        "owned-response-receipt"] == receipt_id
    references = [after["originals"][identity]["manifest"]["reference"]
        for identity in roles.values()]
    assert set(roles.values()) <= set(workspace["evidence_record_references"])
    assert {Canonical(value) for value in references} <= {
        Canonical(value) for value in workspace["evidence_references"]}
    facts = [row for row in after["model"]["observations"] if row["kind"] == (
        "owned-content-response-source") and row["attributes"]["original_receipt_id"] == receipt_id]
    assert len(facts) == 1, "One durable original content source association is required"
    fact = facts[0]
    assert Canonical(fact["attributes"]) == Canonical(summary["source_facts"])
    assert Canonical(fact["attributes"]["original_role_ids"]) == Canonical(roles)
    assert fact["attributes"]["original_job_id"] == fact["provenance"]["run_reference"] == job_id
    assert fact["provenance"]["source_id"] == "native.loopback-content-response"
    assert {Canonical(value) for value in fact["provenance"]["evidence_references"]} == {
        Canonical(value) for value in references}
    assert fact["subject_reference"] in workspace["object_references"] and fact[
        "subject_reference"] in ByReference(after["model"]["objects"])
    assert fact["subject_reference"] == added_objects[0]["reference"]
