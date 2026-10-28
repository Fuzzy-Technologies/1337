# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure persisted content-header-v2 oracle; no production parser/check, store or runtime calls.

The caller independently retains installed identity, target cleanup and current authority.
Inputs here are original reopened documents and original Save returns, never summary claims.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from urllib.parse import urlsplit

from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_state_oracle import ByReference

PROFILE = "owned-response-header-absence.v2"
SOURCE_PROFILE = "owned-content-response-capture.v1"
CHECK = "native.response-header-xcto-absent"
PROVIDER = "native.response-passive"
CAPABILITY = "http.owned-response-header-check"
ASSESSMENT = "native.response-header-assessment"
FIELDS = {"schema_version", "profile", "source_profile", "check_id", "analysis_reference",
    "original_receipt_id", "original_job_id", "source_observation_reference", "original_role_ids",
    "header_sha256", "condition_observed", "authority_basis"}
BASIS = {"workspace_id", "model_revision", "workspace_revision", "scope_reference",
    "scope_revision", "scope_sha256", "policy_reference", "policy_revision", "policy_sha256",
    "owner_reference", "owner_attribution", "analysis_reference", "original_receipt_id",
    "source_target_reference", "literal_ip_reference", "capability", "impact", "workflow_approved",
    "issued_at", "expires_at", "checked_at", "source_profile"}


def Reference(namespace: str, value: dict) -> str:
    """Recompute declared model identities using only the published standard JSON grammar."""

    return namespace + ":" + hashlib.sha256(Canonical({"namespace": namespace,
        "identity": value})).hexdigest()


def HeaderAbsent(raw: bytes) -> bool:
    """Read only original complete header names; body text, values and case names are irrelevant."""

    assert type(raw) is bytes and 0 < len(raw) <= 16384 and raw.startswith(
        b"HTTP/1.1 200 OK\r\n") and raw.find(b"\r\n\r\n") == len(raw) - 4
    lines = raw[:-4].split(b"\r\n")
    assert 2 <= len(lines) <= 65 and all(len(line) + 2 <= 4096 for line in lines)
    names = []

    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        assert colon and name and all(byte in (
            b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ) for byte in name) and all(byte == 9 or 32 <= byte <= 126 for byte in value)
        names.append(name.lower())

    assert len(set(names)) == len(names), "Ambiguous original fields cannot establish header truth"

    return b"x-content-type-options" not in names


def ContractDigest(value: dict) -> str:
    """Recompute policy/scope contract hashes independently, including original Unicode escaping."""

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def AssertContentHeaderV2(before: dict, after: dict, summary: dict, saves: list[dict], *,
    case: str, url: str, receipt_id: str, analysis: str, authority: dict) -> dict:
    """Join originals, persisted v2 assessment/Finding, authority basis and Save acknowledgements.

    Args:
        before: Original post-capture Inspect state before this explicit analysis.
        after: Original reopened Inspect state after the same analysis.
        summary: Actual SDK summary, schema one despite persisted assessment schema two.
        saves: Actual model/workspace Save observations, returning original objects unchanged.
        case: Independently served admitted source variant, not a product-selected expectation.
        url: Independently selected original URL.
        receipt_id: Actual original acknowledged content receipt.
        analysis: Independently selected analysis identity, separate from acquisition job.
        authority: Independently retained scope/policy dictionaries and selected owner/attribution.

    Returns:
        Verified historical identities for later replay checks, without performing replay.
    """

    workspace_id = before["workspace"]["workspace_id"]
    assert before["model"]["workspace_id"] == after["model"]["workspace_id"] == (
        after["workspace"]["workspace_id"]) == workspace_id
    sources = [row for row in before["model"]["observations"] if row["kind"] == (
        "owned-content-response-source") and row["attributes"]["original_receipt_id"] == receipt_id]
    assert len(sources) == 1, "One original content source association is required"
    source = sources[0]
    job = source["attributes"]["original_job_id"]
    assert job != analysis and job == source["provenance"]["run_reference"] and job in (
        before["workspace"]["job_references"]), "Acquisition job is not analysis provenance"
    ids = AssertContentParts(case, url, receipt_id, before["originals"], source["attributes"],
        job_id=job)
    assert set(ids.values()) <= set(before["workspace"]["evidence_record_references"])
    assert source["reference"] == Reference("observation", {
        key: value for key, value in source.items() if key != "reference"}), (
            "The actual original source identity must remain content-addressed")
    endpoint = Reference("object", {"workspace_id": workspace_id, "kind": "endpoint", "key": url})
    assert source["subject_reference"] == endpoint and endpoint in before["workspace"][
        "object_references"], "Actual source must own the selected attached Endpoint"
    assessments = [row for row in after["model"]["observations"] if row["kind"] == ASSESSMENT
        and row["attributes"].get("analysis_reference") == analysis]
    assert len(assessments) == 1, "One independently selected persisted assessment is required"
    fact = assessments[0]
    attrs, provenance = fact["attributes"], fact["provenance"]
    headers = bytes.fromhex(before["originals"][ids["owned-response-headers"]]["data_hex"])
    absent = HeaderAbsent(headers)
    assert set(attrs) == FIELDS and type(attrs["schema_version"]) is int and attrs[
        "schema_version"] == 2 and attrs["profile"] == PROFILE and attrs["source_profile"] == (
        SOURCE_PROFILE), "Catalog v1 cannot substitute for content-family v2"
    assert attrs["check_id"] == CHECK and attrs["condition_observed"] is absent
    assert attrs["original_receipt_id"] == receipt_id and attrs["original_job_id"] == job and (
        attrs["source_observation_reference"] == source["reference"] and
        attrs["original_role_ids"] == ids and attrs["analysis_reference"] == analysis)
    assert attrs["header_sha256"] == hashlib.sha256(headers).hexdigest()
    assert fact["subject_reference"] == endpoint and fact["reference"] == Reference("observation",
        {key: value for key, value in fact.items() if key != "reference"})
    originals = [before["originals"][identity]["manifest"]["reference"]
        for identity in ids.values()]
    assert provenance["source_id"] == PROVIDER and provenance["provider_version"] == "1" and (
        provenance["run_reference"] == analysis and provenance["execution"] is None)
    assert sorted(map(Canonical, provenance["evidence_references"])) == sorted(
        map(Canonical, originals))
    scope, policy = authority["scope"], authority["policy"]
    scope_reference = "scope:" + scope["scope_id"]
    target = "target:" + hashlib.sha256(Canonical({"kind": "url", "value": url})).hexdigest()
    literal_ip = "target:" + hashlib.sha256(Canonical({"kind": "ip",
        "value": urlsplit(url).hostname})).hexdigest()
    assert provenance["scope_reference"] == source["provenance"]["scope_reference"] == (
        scope_reference)
    assert provenance["target_reference"] == source["provenance"]["target_reference"] == target
    basis = attrs["authority_basis"]
    assert set(basis) == BASIS and basis["source_profile"] == SOURCE_PROFILE
    expected = {"workspace_id": workspace_id, "analysis_reference": analysis,
        "original_receipt_id": receipt_id, "source_target_reference": target,
        "literal_ip_reference": literal_ip, "scope_reference": scope_reference,
        "scope_revision": scope["revision"], "scope_sha256": ContractDigest(scope),
        "policy_reference": "policy:" + policy["policy_id"], "policy_revision": policy["revision"],
        "policy_sha256": ContractDigest(policy), "owner_reference": authority["owner_reference"],
        "owner_attribution": authority["owner_attribution"], "capability": CAPABILITY,
        "impact": "PASSIVE", "workflow_approved": True}
    assert all(basis[key] == value for key, value in expected.items())
    assert basis["workflow_approved"] is True and authority["owner_attribution"] in (
        "selected", "trusted-reader")
    assert type(authority["owner_reference"]) is str and authority["owner_reference"]
    for owner in ("model", "workspace"):
        assert type(basis[owner + "_revision"]) is int and basis[owner + "_revision"] == (
            before[owner]["revision"]), "Immutable original CAS bases must be exact integers"
    assert all(type(basis[key]) is int for key in ("scope_revision", "policy_revision"))
    issued, expires, checked = [datetime.fromisoformat(basis[key]) for key in (
        "issued_at", "expires_at", "checked_at")]
    observed = datetime.fromisoformat(provenance["observed_at"])
    assert all(time.tzinfo is not None and time.utcoffset() is not None for time in (
        issued, expires, checked, observed)) and issued <= observed <= checked < expires
    impacts = {"PASSIVE", "SAFE", "STANDARD", "ACTIVE", "INTRUSIVE"}
    assert policy["maximum_impact"] in impacts and type(policy["max_authorization_seconds"]) is int
    assert 1 <= policy["max_authorization_seconds"] <= 3600
    permissions = [item for item in policy["permissions"] if item["capability_id"] == CAPABILITY
        and item["adapter_id"] == PROVIDER]
    assert len(permissions) == 1 and permissions[0]["maximum_impact"] in impacts and (
        permissions[0]["granted_privileges"] == []), "An explicit PASSIVE permission is required"
    assert (expires - issued).total_seconds() <= policy["max_authorization_seconds"]
    consent = scope["authorization"]
    assert scope["workspace_id"] == workspace_id and consent["state"] == "granted" and (
        type(consent["authority_reference"]) is str and consent["authority_reference"] and
        consent["authority_reference"] != authority["owner_reference"] and
        type(consent["record_reference"]) is str and consent["record_reference"])
    selected = [{"kind": "url", "value": url}, {"kind": "ip", "value": urlsplit(url).hostname}]
    for field in ("targets", "allow"):
        declarations = scope[field]
        assert type(declarations) is list and len(declarations) == len(
            set(map(Canonical, declarations)))
        assert all(Canonical(target) in set(map(Canonical, declarations)) for target in selected), (
            "The exact original URL and literal IP must both be registered and allowed")
    assert scope["deny"] == [] and scope["exclusions"] == [], (
        "This bounded positive oracle requires an explicit exclusion-free literal scope")
    for key, comparison in (("valid_from", lambda value: value <= checked),
        ("valid_until", lambda value: checked < value)):
        if consent[key] is not None:
            assert comparison(datetime.fromisoformat(consent[key]))
    finding_rows = [row for row in after["model"]["objects"] if row["identity"]["kind"] == "finding"
        and row["attributes"].get("check_id") == CHECK and any(item["source_id"] == PROVIDER and
            item["run_reference"] == analysis for item in row["provenance"])]
    assert len(finding_rows) == int(absent), "Count persisted Findings, never producer counts"
    finding_reference = None
    detection_reference = None
    update_reference = None
    detections = [row for row in after["model"]["observations"] if row["kind"] == (
        "finding-detection") and row["provenance"]["source_id"] == PROVIDER and row[
            "provenance"]["run_reference"] == analysis]
    assert len(detections) == int(absent), "Original detector fact count differs"
    updates = [row for row in after["model"]["observations"] if row["kind"] == (
        "object-update") and row["provenance"]["source_id"] == PROVIDER and row[
            "provenance"]["run_reference"] == analysis]
    assert len(updates) == int(absent), "One attributable Finding patch must accompany detection"

    if absent:
        finding = finding_rows[0]
        finding_attrs = finding["attributes"]
        fingerprint = hashlib.sha256(Canonical({"namespace": "finding",
            "subject_reference": endpoint, "check_id": CHECK,
            "location_key": url + "#response-header:x-content-type-options"})).hexdigest()
        assert finding["identity"] == {"workspace_id": workspace_id, "kind": "finding",
            "key": fingerprint}
        finding_reference = Reference("object", finding["identity"])
        assert finding["reference"] == finding_reference and finding_reference in after[
            "workspace"]["object_references"]
        assert finding_attrs["schema_version"] == 1 and type(finding_attrs["schema_version"]) is int
        assert set(finding_attrs) == {"schema_version", "fingerprint", "subject_reference",
            "check_id", "location_key", "summary", "severity", "confidence", "status",
            "status_reason", "remediation"}, "A persisted Finding has its complete closed schema"
        assert finding_attrs["fingerprint"] == fingerprint and finding_attrs[
            "subject_reference"] == endpoint
        assert finding_attrs["location_key"] == url + "#response-header:x-content-type-options"
        assert finding_attrs["summary"] == "Captured response omitted X-Content-Type-Options"
        assert finding_attrs["severity"] == "low" and type(
            finding_attrs["confidence"]) is float and finding_attrs["confidence"] == 0.0
        assert Canonical(provenance) in [Canonical(item) for item in finding["provenance"]]
        prior = ByReference(before["model"]["objects"]).get(finding_reference)
        if prior is None:
            assert finding_attrs["status"] == "open" and finding_attrs["status_reason"] is None
        else:
            assert all(finding_attrs[key] == prior["attributes"][key] for key in (
                "status", "status_reason", "remediation")), "Original operator triage must survive"

        detection = detections[0]
        assert set(detection) == {"reference", "kind", "subject_reference", "attributes",
            "provenance"}
        assert detection["subject_reference"] == finding_reference and Canonical(
            detection["provenance"]) == Canonical(provenance), "Detector attribution differs"
        assert Canonical(detection["attributes"]) == Canonical({**finding_attrs, "status": "open",
            "status_reason": None}), (
            "The original untriaged detection is distinct from preserved current Finding triage")
        detection_reference = Reference("observation", {
            key: value for key, value in detection.items() if key != "reference"})
        assert detection["reference"] == detection_reference, "Original detector fact hash differs"
        update = updates[0]
        assert set(update) == {"reference", "kind", "subject_reference", "attributes",
            "provenance"}, "The Finding patch must retain its complete observation schema"
        assert update["subject_reference"] == finding_reference and Canonical(
            update["attributes"]) == Canonical(finding_attrs) and Canonical(
            update["provenance"]) == Canonical(provenance), (
                "The original Finding patch must match the current attributed Finding")
        update_reference = Reference("observation", {
            key: value for key, value in update.items() if key != "reference"})
        assert update["reference"] == update_reference, "Original Finding patch hash differs"

    expected_owners = ["model"] + (["workspace"] if finding_reference is not None and (
        finding_reference not in before["workspace"]["object_references"]) else [])
    assert [row["owner"] for row in saves] == expected_owners, "Unexpected original Save attempt"
    for row in saves:
        owner = row["owner"]
        assert type(row["expected_revision"]) is int and row["expected_revision"] == (
            before[owner]["revision"])
        assert row["exception_type"] is None and Canonical(row["returned"]) == Canonical(
            after[owner])
        assert type(after[owner]["revision"]) is int and after[owner]["revision"] == (
            before[owner]["revision"] + 1)
        proposal = ({**after[owner], "revision": before[owner]["revision"]}
            if owner == "workspace" else after[owner])
        assert Canonical(row["proposal"]) == Canonical(proposal)
    for owner in ("model", "workspace"):
        assert summary[owner + "_commit"] == (
            "acknowledged" if owner in expected_owners else "not-attempted")
        assert type(summary[owner + "_revision"]) is int and summary[owner + "_revision"] == (
            after[owner]["revision"])
        if owner not in expected_owners:
            assert Canonical(before[owner]) == Canonical(after[owner])
    for field in ("job_references", "scope_references", "evidence_references",
        "evidence_record_references"):
        assert Canonical(before["workspace"][field]) == Canonical(after["workspace"][field])
    assert Canonical(before["originals"]) == Canonical(after["originals"]), (
        "Offline analysis cannot add or replace original evidence")
    attached = after["workspace"]["object_references"]
    assert len(attached) == len(set(attached)) and set(attached) == {
        *before["workspace"]["object_references"], *([] if finding_reference is None else [
            finding_reference])}, "Only the independently identified Finding may gain attachment"
    for field in ("objects", "relations", "observations"):
        old, new = ByReference(before["model"][field]), ByReference(after["model"][field])
        assert all(key in new and (key == finding_reference or Canonical(value) == (
            Canonical(new[key]))) for key, value in old.items()), (
                "Existing source, native state and triage cannot disappear")
        additions = ({fact["reference"], *(
            [] if detection_reference is None else [detection_reference, update_reference])}
            if field == "observations" else
            {finding_reference} if field == "objects" and finding_reference is not None else set())
        assert set(new) == set(old) | additions, "No unrelated model identities may appear"
    assert summary["schema_version"] == 1 and type(summary["schema_version"]) is int and (
        summary["state"] == "completed" and summary["profile"] == PROFILE and
        summary["source_profile"] == SOURCE_PROFILE and summary["condition_observed"] is absent)
    identities = {"original_receipt_id": receipt_id, "analysis_reference": analysis,
        "assessment_reference": fact["reference"], "finding_reference": finding_reference,
        "condition_observed": absent}
    assert all(summary[key] == value for key, value in identities.items())

    return identities


def AssertHistoricalContentHeaderReplay(before: dict, after: dict, replay: dict,
    identities: dict) -> None:
    """Require original v2 historical identities and unchanged detached state after relocation."""

    assert Canonical(before) == Canonical(after), "Historical verification cannot repair state"
    assert set(identities) == {"original_receipt_id", "analysis_reference", "assessment_reference",
        "finding_reference", "condition_observed"}, "Missing original historical identities"
    assert replay["state"] == "verified" and replay["profile"] == PROFILE and replay[
        "source_profile"] == SOURCE_PROFILE
    assert type(replay["condition_observed"]) is bool and all(replay[key] == value
        for key, value in identities.items()), "Replay preserves original assessment/Finding IDs"
