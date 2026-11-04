# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict original post-model-ACK expiry evidence and partial-state oracle; no runtime launch."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

from tests.contract.owned_content_response_ci_denial_evidence import ReadJson
from tests.contract.owned_content_response_header_v2_oracle import (
    ASSESSMENT,
    BASIS,
    CAPABILITY,
    CHECK,
    FIELDS,
    PROFILE,
    PROVIDER,
    SOURCE_PROFILE,
    ContractDigest,
    HeaderAbsent,
    Reference,
)
from tests.contract.owned_content_response_sdk_oracle import AssertContentParts, Canonical
from tests.contract.owned_content_response_sdk_pipeline import AssertOffline
from tests.contract.owned_content_response_sdk_state_oracle import ByReference

CASE_NAME = "test_InstalledFreshPostModelAckExpiryContentHeaderPipelinePreservesPartialState"
CASE_CLASS = "tests.functional.test_owned_content_response_sdk_pipeline"
SCENARIO = "post-model-ack-expiry"
OPERATION = "analyze-expiry-offline"
EXPIRY_HELPER = "owned_content_response_expiry_entrypoint.py"
PIPELINE = "owned_content_response_expiry_pipeline.py"
EXPIRY_HELPER_SHA256 = "8136b487f0ce5a169bb96036b8f44b0d065d34545c1bd32e1f838245e5c0a4a3"
PIPELINE_SHA256 = "231686ba3b560a52357314332b61b27834893b689da761789eea26b250971155"
OLD_PINS = {
    "owned_content_response_sdk_consumer.py":
        "853b7aed0c424a44eeb194ba962c44892f19020f0d19d11f2146a1e73814524e",
    "owned_content_response_sdk_controls.py":
        "5df829a54cfb564a86869ce5c2fc5a73107cbad868fa290660635d3bff7efd6a",
    "owned_content_response_sdk_entrypoint.py":
        "9f8bd64c8cd0cc3502ff20e5650eb1687bfa2b3296075bb7dee03a3a81076452",
    "owned_content_response_sdk_offline_guard.py":
        "578d17fc0a61af306b1ca4f650768a1023bac1df5853951cebe823c7fd4367ae",
    "owned_content_response_sdk_setup.py":
        "fb838dea871ce4351d9033330e9d02491b68295f46ce9058c32bda4ef8c7a526",
    "owned_response_product_runner.py":
        "7143b1b509fc81252fd3c78922ce71978d2b5502d357a3e04e0aef1336f59f55",
}


def AssertPartialExpiry(before: dict, after: dict, summary: dict, saves: list[dict], *,
    case: str, url: str, receipt_id: str, analysis: str, authority: dict) -> dict:
    """Verify original custody and the exact post-ACK expiry partial model delta.

    Args:
        before: Original post-capture Inspect state before this explicit analysis.
        after: Original reopened Inspect state after the same analysis.
        summary: Actual SDK summary, schema one despite persisted assessment schema two.
        saves: Actual model/workspace Save observations, returning original objects unchanged.
        case: Exactly the independently served missing-header source, never product-selected truth.
        url: Independently selected original URL.
        receipt_id: Actual original acknowledged content receipt.
        analysis: Independently selected analysis identity, separate from acquisition job.
        authority: Independently retained scope/policy dictionaries and selected owner/attribution.

    Returns:
        Actual partial persisted identities, without claiming complete workspace retention
        or replay.

    Raises:
        AssertionError: Custody, exact permitted model delta, authority basis or partial result
            differs.
    """

    assert case == "missing", "Expiry fixture admits only the independently served missing case"
    assert Canonical(before["workspace"]) == Canonical(after["workspace"]), (
        "No expired workspace Save or reference repair may occur")
    workspace_id = before["workspace"]["workspace_id"]
    assert before["model"]["workspace_id"] == after["model"]["workspace_id"] == (
        after["workspace"]["workspace_id"]) == workspace_id, (
        "Original expiry invariant differs: before['model']['workspace_id'] == "
        "after['model']['workspace_id'] == after['workspace']['workspace_id'] == workspace_id"
    )
    sources = [row for row in before["model"]["observations"] if row["kind"] == (
        "owned-content-response-source") and row["attributes"]["original_receipt_id"] == receipt_id]
    assert len(sources) == 1, "One original content source association is required"
    source = sources[0]
    job = source["attributes"]["original_job_id"]
    assert job != analysis and job == source["provenance"]["run_reference"] and job in (
        before["workspace"]["job_references"]), "Acquisition job is not analysis provenance"
    ids = AssertContentParts(case, url, receipt_id, before["originals"], source["attributes"],
        job_id=job)
    assert set(ids.values()) <= set(before["workspace"]["evidence_record_references"]), (
        'Original expiry invariant differs: set(ids.values()) <= '
        "set(before['workspace']['evidence_record_references'])"
    )
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
    assert set(fact) == {"reference", "kind", "subject_reference", "attributes", "provenance"}, (
        "Original expiry invariant differs: set(fact) == {'reference', 'kind', "
        "'subject_reference', 'attributes', 'provenance'}"
    )
    attrs, provenance = fact["attributes"], fact["provenance"]
    assert set(provenance) == {"source_id", "run_reference", "observed_at", "scope_reference",
        "target_reference", "provider_version", "evidence_references", "execution"}, (
            "Persisted interpretation provenance must have exactly the original model schema")
    headers = bytes.fromhex(before["originals"][ids["owned-response-headers"]]["data_hex"])
    absent = HeaderAbsent(headers)
    assert set(attrs) == FIELDS and type(attrs["schema_version"]) is int and attrs[
        "schema_version"] == 2 and attrs["profile"] == PROFILE and attrs["source_profile"] == (
        SOURCE_PROFILE), "Catalog v1 cannot substitute for content-family v2"
    assert attrs["check_id"] == CHECK and attrs["condition_observed"] is absent, (
        "Original expiry invariant differs: attrs['check_id'] == CHECK and "
        "attrs['condition_observed'] is absent"
    )
    assert attrs["original_receipt_id"] == receipt_id and attrs["original_job_id"] == job and (
        attrs["source_observation_reference"] == source["reference"] and
        attrs["original_role_ids"] == ids and attrs["analysis_reference"] == analysis), (
        "Original expiry invariant differs: attrs['original_receipt_id'] == receipt_id and "
        "attrs['original_job_id'] == job and (attrs['source_observation_referen..."
    )
    assert attrs["header_sha256"] == hashlib.sha256(headers).hexdigest(), (
        "Original expiry invariant differs: attrs['header_sha256'] == "
        'hashlib.sha256(headers).hexdigest()'
    )
    assert fact["subject_reference"] == endpoint and fact["reference"] == Reference("observation",
        {key: value for key, value in fact.items() if key != "reference"}), (
        "Original expiry invariant differs: fact['subject_reference'] == endpoint and "
        "fact['reference'] == Reference('observation', {key: value for key, value in..."
    )
    originals = [before["originals"][identity]["manifest"]["reference"]
        for identity in ids.values()]
    assert provenance["source_id"] == PROVIDER and provenance["provider_version"] == "1" and (
        provenance["run_reference"] == analysis and provenance["execution"] is None), (
        "Original expiry invariant differs: provenance['source_id'] == PROVIDER and "
        "provenance['provider_version'] == '1' and (provenance['run_reference'] == ana..."
    )
    assert sorted(map(Canonical, provenance["evidence_references"])) == sorted(
        map(Canonical, originals)), (
        'Original expiry invariant differs: sorted(map(Canonical, '
        "provenance['evidence_references'])) == sorted(map(Canonical, originals))"
    )
    scope, policy = authority["scope"], authority["policy"]
    scope_reference = "scope:" + scope["scope_id"]
    target = "target:" + hashlib.sha256(Canonical({"kind": "url", "value": url})).hexdigest()
    literal_ip = "target:" + hashlib.sha256(Canonical({"kind": "ip",
        "value": urlsplit(url).hostname})).hexdigest()
    assert provenance["scope_reference"] == source["provenance"]["scope_reference"] == (
        scope_reference), (
        "Original expiry invariant differs: provenance['scope_reference'] == "
        "source['provenance']['scope_reference'] == scope_reference"
    )
    assert provenance["target_reference"] == source["provenance"]["target_reference"] == target, (
        "Original expiry invariant differs: provenance['target_reference'] == "
        "source['provenance']['target_reference'] == target"
    )
    basis = attrs["authority_basis"]
    assert set(basis) == BASIS and basis["source_profile"] == SOURCE_PROFILE, (
        "Original expiry invariant differs: set(basis) == BASIS and basis['source_profile'] "
        '== SOURCE_PROFILE'
    )
    expected = {"workspace_id": workspace_id, "analysis_reference": analysis,
        "original_receipt_id": receipt_id, "source_target_reference": target,
        "literal_ip_reference": literal_ip, "scope_reference": scope_reference,
        "scope_revision": scope["revision"], "scope_sha256": ContractDigest(scope),
        "policy_reference": "policy:" + policy["policy_id"], "policy_revision": policy["revision"],
        "policy_sha256": ContractDigest(policy), "owner_reference": authority["owner_reference"],
        "owner_attribution": authority["owner_attribution"], "capability": CAPABILITY,
        "impact": "PASSIVE", "workflow_approved": True}
    assert all(basis[key] == value for key, value in expected.items()), (
        'Original expiry invariant differs: all((basis[key] == value for key, value in '
        'expected.items()))'
    )
    assert basis["workflow_approved"] is True and authority["owner_attribution"] in (
        "selected", "trusted-reader"), (
        "Original expiry invariant differs: basis['workflow_approved'] is True and "
        "authority['owner_attribution'] in ('selected', 'trusted-reader')"
    )
    assert type(authority["owner_reference"]) is str and authority["owner_reference"], (
        "Original expiry invariant differs: type(authority['owner_reference']) is str and "
        "authority['owner_reference']"
    )

    for owner in ("model", "workspace"):
        assert type(basis[owner + "_revision"]) is int and basis[owner + "_revision"] == (
            before[owner]["revision"]), "Immutable original CAS bases must be exact integers"

    assert all(type(basis[key]) is int for key in ("scope_revision", "policy_revision")), (
        'Original expiry invariant differs: all((type(basis[key]) is int for key in '
        "('scope_revision', 'policy_revision')))"
    )
    issued, expires, checked = [datetime.fromisoformat(basis[key]) for key in (
        "issued_at", "expires_at", "checked_at")]
    observed = datetime.fromisoformat(provenance["observed_at"])
    assert all(time.tzinfo is not None and time.utcoffset() is not None for time in (
        issued, expires, checked, observed)) and issued <= observed <= checked < expires, (
        'Original expiry invariant differs: all((time.tzinfo is not None and time.utcoffset() '
        'is not None for time in (issued, expires, checked, observed))) and ...'
    )
    impacts = {"PASSIVE", "SAFE", "STANDARD", "ACTIVE", "INTRUSIVE"}
    assert policy["maximum_impact"] in impacts and (
        type(policy["max_authorization_seconds"]) is int), (
        "Original expiry invariant differs: policy['maximum_impact'] in impacts and "
        "type(policy['max_authorization_seconds']) is int"
    )
    assert 1 <= policy["max_authorization_seconds"] <= 3600, (
        "Original expiry invariant differs: 1 <= policy['max_authorization_seconds'] <= 3600"
    )
    permissions = [item for item in policy["permissions"] if item["capability_id"] == CAPABILITY
        and item["adapter_id"] == PROVIDER]
    assert len(permissions) == 1 and permissions[0]["maximum_impact"] in impacts and (
        permissions[0]["granted_privileges"] == []), "An explicit PASSIVE permission is required"
    assert (expires - issued).total_seconds() <= policy["max_authorization_seconds"], (
        'Original expiry invariant differs: (expires - issued).total_seconds() <= '
        "policy['max_authorization_seconds']"
    )
    assert policy["maximum_impact"] == "PASSIVE" and policy["permissions"] == [{
        "capability_id": CAPABILITY, "adapter_id": PROVIDER, "maximum_impact": "PASSIVE",
        "granted_privileges": []}], (
            "The fixed fixture must use only its separate PASSIVE permission")
    consent = scope["authorization"]
    assert scope["workspace_id"] == workspace_id and consent["state"] == "granted" and (
        type(consent["authority_reference"]) is str and consent["authority_reference"] and
        consent["authority_reference"] != authority["owner_reference"] and
        type(consent["record_reference"]) is str and consent["record_reference"]), (
        "Original expiry invariant differs: scope['workspace_id'] == workspace_id and "
        "consent['state'] == 'granted' and (type(consent['authority_reference']) is ..."
    )
    selected = [{"kind": "url", "value": url}, {"kind": "ip", "value": urlsplit(url).hostname}]

    for field in ("targets", "allow"):
        declarations = scope[field]
        assert type(declarations) is list and len(declarations) == len(
            set(map(Canonical, declarations))), (
            'Original expiry invariant differs: type(declarations) is list and '
            'len(declarations) == len(set(map(Canonical, declarations)))'
        )
        assert all(Canonical(target) in set(map(Canonical, declarations)) for target in selected), (
            "The exact original URL and literal IP must both be registered and allowed")

    assert scope["deny"] == [] and scope["exclusions"] == [], (
        "This bounded positive oracle requires an explicit exclusion-free literal scope")

    for key, comparison in (("valid_from", lambda value: value <= checked),
        ("valid_until", lambda value: checked < value)):
        if consent[key] is not None:
            assert comparison(datetime.fromisoformat(consent[key])), (
                'Original expiry invariant differs: '
                'comparison(datetime.fromisoformat(consent[key]))'
            )

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
        assert set(finding) == {"reference", "identity", "attributes", "provenance"}, (
            "Original expiry invariant differs: set(finding) == {'reference', 'identity', "
            "'attributes', 'provenance'}"
        )
        finding_attrs = finding["attributes"]
        fingerprint = hashlib.sha256(Canonical({"namespace": "finding",
            "subject_reference": endpoint, "check_id": CHECK,
            "location_key": url + "#response-header:x-content-type-options"})).hexdigest()
        assert finding["identity"] == {"workspace_id": workspace_id, "kind": "finding",
            "key": fingerprint}, (
            "Original expiry invariant differs: finding['identity'] == {'workspace_id': "
            "workspace_id, 'kind': 'finding', 'key': fingerprint}"
        )
        finding_reference = Reference("object", finding["identity"])
        assert finding["reference"] == finding_reference and finding_reference not in after[
            "workspace"]["object_references"], (
            "Original expiry invariant differs: finding['reference'] == finding_reference and "
            "finding_reference not in after['workspace']['object_references']"
        )
        assert finding_attrs["schema_version"] == 1 and (
            type(finding_attrs["schema_version"]) is int), (
            "Original expiry invariant differs: finding_attrs['schema_version'] == 1 and "
            "type(finding_attrs['schema_version']) is int"
        )
        assert set(finding_attrs) == {"schema_version", "fingerprint", "subject_reference",
            "check_id", "location_key", "summary", "severity", "confidence", "status",
            "status_reason", "remediation"}, "A persisted Finding has its complete closed schema"
        assert finding_attrs["fingerprint"] == fingerprint and finding_attrs[
            "subject_reference"] == endpoint, (
            "Original expiry invariant differs: finding_attrs['fingerprint'] == fingerprint "
            "and finding_attrs['subject_reference'] == endpoint"
        )
        assert finding_attrs["location_key"] == url + "#response-header:x-content-type-options", (
            "Original expiry invariant differs: finding_attrs['location_key'] == url + "
            "'#response-header:x-content-type-options'"
        )
        assert finding_attrs["summary"] == "Captured response omitted X-Content-Type-Options", (
            "Original expiry invariant differs: finding_attrs['summary'] == 'Captured "
            "response omitted X-Content-Type-Options'"
        )
        assert finding_attrs["severity"] == "low" and type(
            finding_attrs["confidence"]) is float and finding_attrs["confidence"] == 0.0, (
            "Original expiry invariant differs: finding_attrs['severity'] == 'low' and "
            "type(finding_attrs['confidence']) is float and (finding_attrs['confidence'] "
            '==...'
        )
        assert Canonical(finding["provenance"]) == Canonical([provenance]), (
            "Original expiry invariant differs: Canonical(finding['provenance']) == "
            'Canonical([provenance])'
        )
        assert finding_attrs["remediation"] == {"summary": None, "steps": [], "references": []}, (
            "Original expiry invariant differs: finding_attrs['remediation'] == {'summary': "
            "None, 'steps': [], 'references': []}"
        )
        prior = ByReference(before["model"]["objects"]).get(finding_reference)
        assert prior is None, "This fresh fixture must add a Finding without changing old triage"
        assert finding_attrs["status"] == "open" and finding_attrs["status_reason"] is None, (
            "Original expiry invariant differs: finding_attrs['status'] == 'open' and "
            "finding_attrs['status_reason'] is None"
        )

        detection = detections[0]
        assert set(detection) == {"reference", "kind", "subject_reference", "attributes",
            "provenance"}, (
            "Original expiry invariant differs: set(detection) == {'reference', 'kind', "
            "'subject_reference', 'attributes', 'provenance'}"
        )
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

    expected_owners = ["model"]
    assert [row["owner"] for row in saves] == expected_owners, "Unexpected original Save attempt"

    for row in saves:
        owner = row["owner"]
        assert type(row["expected_revision"]) is int and row["expected_revision"] == (
            before[owner]["revision"]), (
            "Original expiry invariant differs: type(row['expected_revision']) is int and "
            "row['expected_revision'] == before[owner]['revision']"
        )
        assert row["exception_type"] is None and Canonical(row["returned"]) == Canonical(
            after[owner]), (
            "Original expiry invariant differs: row['exception_type'] is None and "
            "Canonical(row['returned']) == Canonical(after[owner])"
        )
        assert type(after[owner]["revision"]) is int and after[owner]["revision"] == (
            before[owner]["revision"] + 1), (
            "Original expiry invariant differs: type(after[owner]['revision']) is int and "
            "after[owner]['revision'] == before[owner]['revision'] + 1"
        )
        proposal = ({**after[owner], "revision": before[owner]["revision"]}
            if owner == "workspace" else after[owner])
        assert Canonical(row["proposal"]) == Canonical(proposal), (
            "Original expiry invariant differs: Canonical(row['proposal']) == "
            'Canonical(proposal)'
        )

    for owner in ("model", "workspace"):
        assert summary[owner + "_commit"] == (
            "acknowledged" if owner in expected_owners else "not-attempted"), (
            "Original expiry invariant differs: summary[owner + '_commit'] == ('acknowledged' "
            "if owner in expected_owners else 'not-attempted')"
        )
        assert type(summary[owner + "_revision"]) is int and summary[owner + "_revision"] == (
            after[owner]["revision"]), (
            "Original expiry invariant differs: type(summary[owner + '_revision']) is int and "
            "summary[owner + '_revision'] == after[owner]['revision']"
        )

        if owner not in expected_owners:
            assert Canonical(before[owner]) == Canonical(after[owner]), (
                'Original expiry invariant differs: Canonical(before[owner]) == '
                'Canonical(after[owner])'
            )

    for field in ("job_references", "scope_references", "evidence_references",
        "evidence_record_references"):
        assert Canonical(before["workspace"][field]) == Canonical(after["workspace"][field]), (
            "Original expiry invariant differs: Canonical(before['workspace'][field]) == "
            "Canonical(after['workspace'][field])"
        )

    assert Canonical(before["originals"]) == Canonical(after["originals"]), (
        "Offline analysis cannot add or replace original evidence")
    attached = after["workspace"]["object_references"]
    assert len(attached) == len(set(attached)) and set(attached) == set(
        before["workspace"]["object_references"]), "Expiry cannot attach a partial Finding"

    for field in ("objects", "relations", "observations"):
        old, new = ByReference(before["model"][field]), ByReference(after["model"][field])
        assert all(key in new and Canonical(value) == Canonical(new[key])
            for key, value in old.items()), (
                "Existing source, native state and triage cannot disappear")
        additions = ({fact["reference"], *(
            [] if detection_reference is None else [detection_reference, update_reference])}
            if field == "observations" else
            {finding_reference} if field == "objects" and finding_reference is not None else set())
        assert set(new) == set(old) | additions, "No unrelated model identities may appear"

    assert summary["schema_version"] == 1 and type(summary["schema_version"]) is int and (
        summary["state"] == "partial" and summary["failure"] == "admission-expired" and
        summary["profile"] == PROFILE and
        summary["source_profile"] == SOURCE_PROFILE and summary["condition_observed"] is absent), (
        "Original expiry invariant differs: summary['schema_version'] == 1 and "
        "type(summary['schema_version']) is int and (summary['state'] == 'partial' and "
        'summ...'
    )
    assert type(policy["max_authorization_seconds"]) is int and (
        policy["max_authorization_seconds"] == 30 and expires - issued == timedelta(seconds=30)
        and issued == checked == observed and
        datetime.fromisoformat(consent["valid_until"]) > expires
    ), "The controlled fixed thirty-second policy window, not earlier consent, must expire"
    assert authority["owner_attribution"] == "trusted-reader", (
        "Original expiry invariant differs: authority['owner_attribution'] == "
        "'trusted-reader'"
    )
    assert all(Canonical(before["model"][key]) == Canonical(after["model"][key])
        for key in before["model"]
        if key not in {"revision", "objects", "relations", "observations"}), (
        "Original expiry invariant differs: all((Canonical(before['model'][key]) == "
        "Canonical(after['model'][key]) for key in before['model'] if key not in {'rev..."
    )
    assert set(before["model"]) == set(after["model"]), "No unrelated model metadata may appear"
    assert set(summary) == {"schema_version", "workflow", "state", "source_id", "profile",
        "check_id", "impact", "original_receipt_id", "analysis_reference",
        "source_target_reference", "condition_observed", "assessment_reference",
        "finding_reference", "model_commit", "workspace_commit", "model_revision",
        "workspace_revision", "failure", "source_profile"}, (
        "Original expiry invariant differs: set(summary) == {'schema_version', 'workflow', "
        "'state', 'source_id', 'profile', 'check_id', 'impact', 'original_recei..."
    )
    assert summary["workflow"] == "owned-response-header-check" and (
        summary["source_id"] == PROVIDER and summary["check_id"] == CHECK and
        summary["impact"] == "PASSIVE" and summary["source_target_reference"] == target), (
        "Original expiry invariant differs: summary['workflow'] == "
        "'owned-response-header-check' and (summary['source_id'] == PROVIDER and "
        "summary['check_id'] ==..."
    )
    identities = {"original_receipt_id": receipt_id, "analysis_reference": analysis,
        "assessment_reference": fact["reference"], "finding_reference": finding_reference,
        "condition_observed": absent}
    assert all(summary[key] == value for key, value in identities.items()), (
        'Original expiry invariant differs: all((summary[key] == value for key, value in '
        'identities.items()))'
    )

    return identities


def AssertControls(control: dict, before: dict, after: dict, authority: dict) -> None:
    """Require the actual original model ACK to precede the exclusive controlled clock reading.

    Args:
        control: Original detached guard and reader/clock facts from the expiry-only child.
        before: Original acquired state with both exact caller CAS bases.
        after: Reopened original partial state after the single analysis.
        authority: Independently retained scope/policy and selected trusted actor.

    Raises:
        AssertionError: Original Save returns or the exact post-ACK clock/reader trace differs.
    """

    assert set(control) == {"guard", "clock", "owner_values", "policy_documents"}, (
        "Original expiry invariant differs: set(control) == {'guard', 'clock', "
        "'owner_values', 'policy_documents'}"
    )
    AssertOffline(control["guard"], historical=False)
    saves = control["guard"]["saves"]
    assert len(saves) == 1 and saves[0]["owner"] == "model", (
        "Original expiry invariant differs: len(saves) == 1 and saves[0]['owner'] == 'model'"
    )
    saved = saves[0]
    assert saved["exception_type"] is None and Canonical(saved["returned"]) == Canonical(
        saved["proposal"]) == Canonical(after["model"]), (
        "Original expiry invariant differs: saved['exception_type'] is None and "
        "Canonical(saved['returned']) == Canonical(saved['proposal']) == Canonical(after['..."
    )
    assert type(saved["expected_revision"]) is int and saved["expected_revision"] == (
        before["model"]["revision"]), (
        "Original expiry invariant differs: type(saved['expected_revision']) is int and "
        "saved['expected_revision'] == before['model']['revision']"
    )
    assert type(after["model"]["revision"]) is int and after["model"]["revision"] == (
        before["model"]["revision"] + 1), (
        "Original expiry invariant differs: type(after['model']['revision']) is int and "
        "after['model']['revision'] == before['model']['revision'] + 1"
    )
    clock = control["clock"]
    assert set(clock) == {"issued_at", "expires_at", "duration_seconds", "trigger",
        "elapsed_wall_clock_claimed", "readings"}, (
        "Original expiry invariant differs: set(clock) == {'issued_at', 'expires_at', "
        "'duration_seconds', 'trigger', 'elapsed_wall_clock_claimed', 'readings'}"
    )
    assert type(clock["duration_seconds"]) is int and clock["duration_seconds"] == 30, (
        "Original expiry invariant differs: type(clock['duration_seconds']) is int and "
        "clock['duration_seconds'] == 30"
    )
    assert clock["trigger"] == "original-model-save-return" and (
        clock["elapsed_wall_clock_claimed"] is False), (
        "Original expiry invariant differs: clock['trigger'] == 'original-model-save-return' "
        "and clock['elapsed_wall_clock_claimed'] is False"
    )
    start, end = (datetime.fromisoformat(clock[key]) for key in ("issued_at", "expires_at"))
    assert all(value.utcoffset() == timedelta(0) for value in (start, end)) and (
        end - start == timedelta(seconds=30)), (
        'Original expiry invariant differs: all((value.utcoffset() == timedelta(0) for value '
        'in (start, end))) and end - start == timedelta(seconds=30)'
    )
    readings = clock["readings"]
    assert type(readings) is list and 2 <= len(readings) <= 512, (
        'Original expiry invariant differs: type(readings) is list and 2 <= len(readings) <= '
        '512'
    )
    assert readings[-1] == {"value": end.isoformat(), "model_ack_observed": True,
        "returned_model_revision": after["model"]["revision"]}, (
        "Original expiry invariant differs: readings[-1] == {'value': end.isoformat(), "
        "'model_ack_observed': True, 'returned_model_revision': after['model']['rev..."
    )
    assert all(row == {"value": start.isoformat(), "model_ack_observed": False,
        "returned_model_revision": None} for row in readings[:-1]), (
            "Only the first actual post-model-ACK sample may reach exact exclusive expiry")
    facts = [row for row in after["model"]["observations"] if row["kind"] == ASSESSMENT and
        row["attributes"]["analysis_reference"] == authority["analysis_reference"]]
    assert len(facts) == 1, (
        'Original expiry invariant differs: len(facts) == 1'
    )
    basis = facts[0]["attributes"]["authority_basis"]
    assert (basis["issued_at"], basis["checked_at"], basis["expires_at"]) == (
        clock["issued_at"], clock["issued_at"], clock["expires_at"]), (
        "Original expiry invariant differs: (basis['issued_at'], basis['checked_at'], "
        "basis['expires_at']) == (clock['issued_at'], clock['issued_at'], clock['exp..."
    )
    assert type(control["owner_values"]) is list and 2 <= len(control["owner_values"]) <= 512, (
        "Original expiry invariant differs: type(control['owner_values']) is list and 2 <= "
        "len(control['owner_values']) <= 512"
    )
    assert all(owner == authority["owner_reference"] for owner in control["owner_values"]), (
        "Original expiry invariant differs: all((owner == authority['owner_reference'] for "
        "owner in control['owner_values']))"
    )
    assert type(control["policy_documents"]) is list and (
        len(control["policy_documents"]) == len(control["owner_values"])), (
        "Original expiry invariant differs: type(control['policy_documents']) is list and "
        "len(control['policy_documents']) == len(control['owner_values'])"
    )
    assert all(Canonical(policy) == Canonical(authority["policy"])
        for policy in control["policy_documents"]), "Actual fresh typed policy reads must reconcile"


def RequireJunit(path: Path) -> None:
    """Require exactly the new original expiry testcase, with no missing or skipped execution.

    Args:
        path: Explicit bounded original JUnit file supplied by the CI evidence owner.

    Raises:
        ValueError: The declared testcase, counts or original outcome is not exact.
    """

    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)

    if len(raw) > 1024 * 1024:
        raise ValueError("One expiry JUnit exceeds its fixed byte bound")

    document = ElementTree.fromstring(raw)
    suites, cases = list(document.iter("testsuite")), list(document.iter("testcase"))

    if len(suites) != 1 or len(cases) != 1 or any(suites[0].get(key) != value for key, value in (
        ("tests", "1"), ("failures", "0"), ("errors", "0"), ("skipped", "0"))) or (
            cases[0].get("name") != CASE_NAME or cases[0].get("classname") != CASE_CLASS
            or any(list(document.iter(kind)) for kind in ("failure", "error", "skipped"))):
        raise ValueError("One original expiry identity must pass without failure, error or skip")


def RequireChildren(case: Path, helpers: dict) -> list[dict]:
    """Reconcile the five original installed children, fixed helper sources and terminal streams.

    Args:
        case: Explicit single retained expiry case directory.
        helpers: Exact source-owned helper path/hash manifest from the original driver.

    Returns:
        Original child documents in fresh-setup/capture/inspect/expiry/inspect order.

    Raises:
        AssertionError: A source pin, installed identity or original child envelope differs.
        OSError: A required original child record is unavailable.
    """

    from tests.contract.owned_content_response_product_runner import (
        AssertContentInstallation,
        AssertOriginalTerminalProcess,
    )
    from tests.contract.owned_content_response_sdk_entrypoint import BoundedRead

    required_pins = {**OLD_PINS, EXPIRY_HELPER: EXPIRY_HELPER_SHA256, PIPELINE: PIPELINE_SHA256}
    checker = Path(__file__).name
    required_pins[checker] = hashlib.sha256(BoundedRead(Path(__file__), 1024 * 1024)).hexdigest()
    assert set(helpers) == set(required_pins) and all(
        helpers[name]["sha256"] == digest for name, digest in required_pins.items()), (
        'Original expiry invariant differs: set(helpers) == set(required_pins) and '
        "all((helpers[name]['sha256'] == digest for name, digest in required_pins.items..."
    )
    installation = ReadJson(case.parent / "installation/wheel-identity.json")
    checkpoint = ReadJson(case.parent / "installation/source-checkpoint.json")
    assert checkpoint == {key: installation[key] for key in (
        "schema_version", "source_commit", "source_tree", "source_modules_sha256")}, (
        'Original expiry invariant differs: checkpoint == {key: installation[key] for key in '
        "('schema_version', 'source_commit', 'source_tree', 'source_modules_s..."
    )
    operations = ("fresh-setup", "capture", "inspect", OPERATION, "inspect")
    children, selected_installation = [], None

    for index, operation in enumerate(operations, start=3):
        matches = list(case.glob(f"process-{index:03d}-sdk-{operation}"))
        assert len(matches) == 1, (
            'Original expiry invariant differs: len(matches) == 1'
        )
        root = matches[0]
        child = ReadJson(root / "stdout.bin")
        terminal = ReadJson(root / "process.json")
        invocation = ReadJson(root / "invocation.json")
        identity = child["installed_identity"]
        AssertContentInstallation(installation, identity,
            commit=installation["source_commit"], tree=installation["source_tree"])
        selected_helper = EXPIRY_HELPER if operation == OPERATION else (
            "owned_content_response_sdk_entrypoint.py")
        cwd = terminal["cwd"]
        argv = (identity["python"], "-I", "-B", helpers[selected_helper]["path"], operation,
            str(Path(cwd) / f"stage-{index - 2:02d}-input.json"), "--execute")
        AssertOriginalTerminalProcess(terminal, BoundedRead(root / "stdout.bin", 2 * 1024 * 1024),
            BoundedRead(root / "stderr.bin", 1024 * 1024), argv=argv)
        installed = terminal["installation"]
        manifest = json.dumps(installed["identity"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")
        assert installed["manifest_sha256"] == hashlib.sha256(manifest).hexdigest(), (
            "Original expiry invariant differs: installed['manifest_sha256'] == "
            'hashlib.sha256(manifest).hexdigest()'
        )
        assert selected_installation is None or installed == selected_installation, (
            'Original expiry invariant differs: selected_installation is None or installed == '
            'selected_installation'
        )
        selected_installation = installed
        assert terminal["returncode"] == 0 and (root / "stderr.bin").stat().st_size == 0, (
            "Original expiry invariant differs: terminal['returncode'] == 0 and (root / "
            "'stderr.bin').stat().st_size == 0"
        )
        assert terminal["timeout_seconds"] == 35 and invocation == {
            "schema_version": 1, "argv": list(argv), "cwd": cwd, "timeout_seconds": 35,
            "stdin": "closed-devnull", "state": "not-launched", "returncode": None,
            "terminal_return_observed": False, "installation": installed}, (
            "Original expiry invariant differs: terminal['timeout_seconds'] == 35 and "
            "invocation == {'schema_version': 1, 'argv': list(argv), 'cwd': cwd, "
            "'timeout_se..."
        )
        assert child["operation"] == operation, (
            "Original expiry invariant differs: child['operation'] == operation"
        )
        required = {"owned_content_response_sdk_entrypoint.py", EXPIRY_HELPER,
            "owned_content_response_sdk_offline_guard.py"} if operation == OPERATION else {
                "owned_content_response_sdk_entrypoint.py",
                "owned_content_response_sdk_consumer.py"}

        if operation in ("fresh-setup", "inspect"):
            required.update(("owned_content_response_sdk_controls.py",
                "owned_content_response_sdk_setup.py", "owned_response_product_runner.py"))

        assert child["consumer_sources"] == {name: helpers[name] for name in required}, (
            "Original expiry invariant differs: child['consumer_sources'] == {name: "
            'helpers[name] for name in required}'
        )
        assert all(installed["identity"][key] == value for key, value in installation.items()), (
            "Original expiry invariant differs: all((installed['identity'][key] == value for "
            'key, value in installation.items()))'
        )
        assert installed["identity"]["installed_sources"] == identity["installed_sources"], (
            "Original expiry invariant differs: installed['identity']['installed_sources'] == "
            "identity['installed_sources']"
        )
        children.append(child)

    assert len(list(case.glob("process-*-sdk-*"))) == 5, "No later SDK retry or repair is permitted"

    return children


def RequireOutcome(junit: Path, retained: Path) -> dict:
    """Verify one original installed post-ACK expiry and exact partial persistence/custody state.

    Args:
        junit: Original one-case JUnit selected by the independent CI owner.
        retained: Original installation/process/source evidence root, without replay or repair.

    Returns:
        Original finite partial-expiry result after strict independent original-state checks.

    Raises:
        AssertionError: Original state, custody, source or narrow partial-case association differs.
        ValueError: The one-case original JUnit is not exact.
    """

    from tests.contract.owned_content_response_product_runner import AssertContentSourceFacts
    from tests.contract.owned_content_response_sdk_state_oracle import AssertSdkSaveTransition

    RequireJunit(junit)
    matches = list(retained.glob("run-*/post-model-ack-expiry/pipeline-result.json"))
    assert len(matches) == 1, "Exactly one original expiry case is required"
    case = matches[0].parent
    result = ReadJson(matches[0])
    assert type(result["expected_findings"]) is int and result["expected_findings"] == 1, (
        "Original expiry invariant differs: type(result['expected_findings']) is int and "
        "result['expected_findings'] == 1"
    )
    plan = ReadJson(case / "pipeline-plan.json")
    helpers = ReadJson(case / "pipeline-helper-sources.json")
    setup_child, capture_child, acquired_child, expiry, after_child = RequireChildren(case, helpers)
    setup = setup_child["summary"]
    acquired = acquired_child["summary"]["original_inspection"]
    after = after_child["summary"]["original_inspection"]
    capture = ReadJson(case / "sdk-capture-original.json")
    assert capture["exception_type"] is None and Canonical(capture["summary"]) == Canonical(
        capture_child["summary"]), (
        "Original expiry invariant differs: capture['exception_type'] is None and "
        "Canonical(capture['summary']) == Canonical(capture_child['summary'])"
    )
    selected = ReadJson(case / "stage-04-input.json")["selection"]
    capture_selected = ReadJson(case / "stage-02-input.json")["selection"]
    assert capture_selected["approve_safe_content_response_capture"] is True and (
        capture_selected["retain_response"] is True), (
        'Original expiry invariant differs: '
        "capture_selected['approve_safe_content_response_capture'] is True and "
        "capture_selected['retain_response'] is True"
    )
    assert selected == {"workspace": plan["selection"]["workspace"],
        "url": plan["selection"]["url"], "scope_id": plan["scope_id"],
        "owner_reference": plan["owner_reference"], "policy": setup["policies"]["analysis"]["path"],
        "original_receipt_id": capture["summary"]["original_receipt_id"],
        "analysis_reference": plan["analysis_reference"],
        "expected_model_revision": acquired["model"]["revision"],
        "expected_workspace_revision": acquired["workspace"]["revision"],
        "approve_passive_header_check": True}, (
        "Original expiry invariant differs: selected == {'workspace': "
        "plan['selection']['workspace'], 'url': plan['selection']['url'], 'scope_id': "
        "plan['scope_id..."
    )
    assert selected["approve_passive_header_check"] is True and type(
        selected["expected_model_revision"]) is int and type(
            selected["expected_workspace_revision"]) is int, (
        "Original expiry invariant differs: selected['approve_passive_header_check'] is True "
        "and type(selected['expected_model_revision']) is int and (type(selec..."
    )
    assert plan["scenario"] == SCENARIO and plan["expected_state"] == "partial", (
        "Original expiry invariant differs: plan['scenario'] == SCENARIO and "
        "plan['expected_state'] == 'partial'"
    )
    assert type(plan["expected_findings"]) is int and plan["expected_findings"] == 1, (
        "Original expiry invariant differs: type(plan['expected_findings']) is int and "
        "plan['expected_findings'] == 1"
    )
    AssertSdkSaveTransition(setup["state"], acquired, capture["summary"], capture["store_saves"],
        url=selected["url"], workspace_id=plan["workspace_id"],
        scope_reference="scope:" + selected["scope_id"])
    original = ReadJson(case / "sdk-analyze-expiry-offline-original.json")
    assert original["exception_type"] is None and all(Canonical(original[key]) == Canonical(
        expiry[key]) for key in ("summary", "control", "exception_type")), (
        "Original expiry invariant differs: original['exception_type'] is None and "
        "all((Canonical(original[key]) == Canonical(expiry[key]) for key in ('summary',..."
    )
    authority = {"scope": setup["scope"], "policy": setup["policies"]["analysis"]["document"],
        "owner_reference": plan["owner_reference"], "owner_attribution": "trusted-reader",
        "analysis_reference": plan["analysis_reference"]}
    identities = AssertPartialExpiry(acquired, after, expiry["summary"],
        expiry["control"]["guard"]["saves"], case="missing", url=selected["url"],
        receipt_id=selected["original_receipt_id"], analysis=plan["analysis_reference"],
        authority=authority)
    AssertControls(expiry["control"], acquired, after, authority)
    main, sentinel = [ReadJson(case / (name + "-source-final.json")) for name in (
        "main", "sentinel")]
    delivery = AssertContentSourceFacts("missing", selected["url"], main, sentinel,
        sentinel_origin=sentinel["origin"])
    assert delivery == "normal-eof" and not (case / "physical-relocation.json").exists(), (
        "Original expiry invariant differs: delivery == 'normal-eof' and (not (case / "
        "'physical-relocation.json').exists())"
    )
    assert result == {"state": "checked-post-model-ack-expiry-partial", "expected_findings": 1,
        "identities": identities, "runtime_acceptance": "passed", "source_delivery": delivery}, (
        "Original expiry invariant differs: result == {'state': "
        "'checked-post-model-ack-expiry-partial', 'expected_findings': 1, 'identities': "
        "identities, 'runti..."
    )

    return result


def Main(arguments: list[str] | None = None) -> int:
    """Check only explicit original expiry evidence, without product or target execution.

    Args:
        arguments: Exactly the original JUnit and retained evidence root.

    Returns:
        Zero after this one original finite partial outcome passes every check.

    Raises:
        ValueError: The two explicit evidence paths were not supplied.
    """

    args = sys.argv[1:] if arguments is None else arguments

    if len(args) != 2:
        raise ValueError("Expected original expiry JUnit and evidence paths")

    RequireOutcome(Path(args[0]), Path(args[1]))
    print("Required genuine post-model-ACK expiry: 1 passed, 0 skipped; partial model only")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
