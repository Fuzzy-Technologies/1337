# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic persisted-header tampering only; no source, SDK, stores or replay execution."""

from __future__ import annotations

import copy
import hashlib

import pytest

from tests.contract import owned_content_response_header_v2_oracle as oracle
from tests.unit.test_owned_content_response_sdk_oracle import Bundle


def Fixture(case="missing", include_detection=True):
    """Build explicitly synthetic original/persisted documents, never actual runtime evidence."""

    url, receipt, originals, source_attrs = Bundle(case)
    refs = [item["manifest"]["reference"] for item in originals.values()]
    endpoint_id = {"workspace_id": "unit-only", "kind": "endpoint", "key": url}
    endpoint = oracle.Reference("object", endpoint_id)
    target = "target:" + hashlib.sha256(oracle.Canonical({"kind": "url", "value": url})).hexdigest()
    ip = "target:" + hashlib.sha256(oracle.Canonical({"kind": "ip",
        "value": "127.0.0.1"})).hexdigest()
    source_provenance = {"source_id": "native.loopback-content-response", "run_reference": (
        source_attrs["original_job_id"]), "observed_at": "2026-10-24T00:00:01+00:00",
        "scope_reference": "scope:unit-only", "target_reference": target, "provider_version": "1",
        "evidence_references": refs, "execution": {"state": "succeeded", "exit_code": 0}}
    source = {"kind": "owned-content-response-source", "subject_reference": endpoint,
        "attributes": source_attrs, "provenance": source_provenance}
    source["reference"] = oracle.Reference("observation", copy.deepcopy(source))
    native = {"reference": "object:synthetic-native-only", "identity": {"kind": "finding"},
        "attributes": {"check_id": "unrelated-native", "status": "confirmed"}, "provenance": []}
    before = {"model": {"workspace_id": "unit-only", "revision": 4,
        "objects": [{"reference": endpoint, "identity": endpoint_id, "attributes": {},
            "provenance": [source_provenance]}, native], "relations": [], "observations": [source]},
        "workspace": {"workspace_id": "unit-only", "revision": 2,
            "object_references": [endpoint, native["reference"]],
            "job_references": [source_attrs["original_job_id"]],
            "scope_references": ["scope:unit-only"],
            "evidence_record_references": list(originals), "evidence_references": refs},
        "originals": originals}
    scope = {"scope_id": "unit-only", "workspace_id": "unit-only", "revision": 0,
        "authorization": {"state": "granted", "authority_reference": "attester:independent",
            "record_reference": "consent:synthetic-only",
            "valid_from": "2026-10-24T00:00:00+00:00", "valid_until": "2026-10-24T00:01:00+00:00"},
        "targets": [{"kind": "url", "value": url}, {"kind": "ip", "value": "127.0.0.1"}],
        "allow": [{"kind": "url", "value": url}, {"kind": "ip", "value": "127.0.0.1"}],
        "deny": [], "exclusions": []}
    policy = {"policy_id": "unit-passive", "revision": 1, "max_authorization_seconds": 30,
        "maximum_impact": "PASSIVE", "permissions": [{"capability_id": oracle.CAPABILITY,
            "adapter_id": oracle.PROVIDER, "maximum_impact": "PASSIVE", "granted_privileges": []}]}
    authority = {"scope": scope, "policy": policy, "owner_reference": "actor:unit",
        "owner_attribution": "trusted-reader"}
    analysis = "analysis:synthetic-only"
    basis = {"workspace_id": "unit-only", "model_revision": 4, "workspace_revision": 2,
        "scope_reference": "scope:unit-only", "scope_revision": 0, "scope_sha256": (
            oracle.ContractDigest(scope)), "policy_reference": "policy:unit-passive",
        "policy_revision": 1, "policy_sha256": oracle.ContractDigest(policy),
        "owner_reference": "actor:unit", "owner_attribution": "trusted-reader",
        "analysis_reference": analysis, "original_receipt_id": receipt,
        "source_target_reference": target, "literal_ip_reference": ip,
        "capability": oracle.CAPABILITY, "impact": "PASSIVE", "workflow_approved": True,
        "issued_at": "2026-10-24T00:00:02+00:00", "checked_at": "2026-10-24T00:00:03+00:00",
        "expires_at": "2026-10-24T00:00:32+00:00", "source_profile": oracle.SOURCE_PROFILE}
    absent = case != "fixed"
    provenance = {**source_provenance, "source_id": oracle.PROVIDER, "run_reference": analysis,
        "observed_at": "2026-10-24T00:00:03+00:00", "execution": None}
    attrs = {"schema_version": 2, "profile": oracle.PROFILE,
        "source_profile": oracle.SOURCE_PROFILE,
        "check_id": oracle.CHECK, "analysis_reference": analysis, "original_receipt_id": receipt,
        "original_job_id": source_attrs["original_job_id"], "source_observation_reference": source[
            "reference"], "original_role_ids": source_attrs["original_role_ids"],
        "header_sha256": source_attrs and hashlib.sha256(bytes.fromhex(originals[
            source_attrs["original_role_ids"]["owned-response-headers"]]["data_hex"])).hexdigest(),
        "condition_observed": absent, "authority_basis": basis}
    fact = {"kind": oracle.ASSESSMENT, "subject_reference": endpoint, "attributes": attrs,
        "provenance": provenance}
    fact["reference"] = oracle.Reference("observation", copy.deepcopy(fact))
    after = copy.deepcopy(before)
    after["model"]["revision"] += 1
    after["model"]["observations"].append(fact)
    finding_reference = None

    if absent:
        location = url + "#response-header:x-content-type-options"
        fingerprint = hashlib.sha256(oracle.Canonical({"namespace": "finding",
            "subject_reference": endpoint, "check_id": oracle.CHECK,
            "location_key": location})).hexdigest()
        identity = {"workspace_id": "unit-only", "kind": "finding", "key": fingerprint}
        finding_reference = oracle.Reference("object", identity)
        after["model"]["objects"].append({"reference": finding_reference, "identity": identity,
            "attributes": {"schema_version": 1, "fingerprint": fingerprint,
                "subject_reference": endpoint, "check_id": oracle.CHECK, "location_key": location,
                "summary": "Captured response omitted X-Content-Type-Options",
                "severity": "low", "confidence": 0.0, "status": "open", "status_reason": None,
                "remediation": {"summary": None, "steps": [], "references": []}},
            "provenance": [provenance]})
        after["workspace"]["revision"] += 1
        after["workspace"]["object_references"].append(finding_reference)

        if include_detection:
            detection = {"kind": "finding-detection", "subject_reference": finding_reference,
                "attributes": copy.deepcopy(after["model"]["objects"][-1]["attributes"]),
                "provenance": provenance}
            detection["reference"] = oracle.Reference("observation", copy.deepcopy(detection))
            after["model"]["observations"].insert(-1, detection)

    summary = {"schema_version": 1, "state": "completed", "profile": oracle.PROFILE,
        "source_profile": oracle.SOURCE_PROFILE, "condition_observed": absent,
        "original_receipt_id": receipt, "analysis_reference": analysis,
        "assessment_reference": fact["reference"], "finding_reference": finding_reference,
        "model_revision": after["model"]["revision"],
        "workspace_revision": after["workspace"]["revision"],
        "model_commit": "acknowledged", "workspace_commit": (
            "acknowledged" if absent else "not-attempted")}
    options = {"case": case, "url": url, "receipt_id": receipt, "analysis": analysis,
        "authority": authority}

    return before, after, summary, Saves(before, after, absent), options


def Saves(before, after, workspace=True):
    """Create explicitly synthetic original Save records matching the selected owner transition."""

    rows = [{"owner": owner, "expected_revision": before[owner]["revision"],
        "proposal": copy.deepcopy(after[owner]), "returned": copy.deepcopy(after[owner]),
        "exception_type": None} for owner in (("model", "workspace") if workspace else ("model",))]

    if workspace:
        rows[1]["proposal"]["revision"] = before["workspace"]["revision"]

    return rows


@pytest.mark.parametrize("case", ["missing", "fixed", "body-decoy"])
def test_OriginalHeaderNamesDecidePersistedV2FindingWithActualOwnerJoins(case):
    """Synthetic positive checks exercise original-field truth, never an actual scanner verdict."""

    before, after, summary, saves, options = Fixture(case)
    oracle.AssertContentHeaderV2(before, after, summary, saves, **options)


@pytest.mark.parametrize("mutation", ["v1", "bool-schema", "wrong-truth", "job", "role",
    "owner", "bool-cas", "policy", "expired", "finding-severity", "native-triage", "lost-ack"])
def test_PersistedAssessmentTamperingCannotBecomeVerifiedV2Interpretation(mutation):
    """Even self-consistent new row hashes/Save returns cannot hide broken original associations."""

    before, after, summary, saves, options = Fixture()
    fact = after["model"]["observations"][-1]
    attrs = fact["attributes"]
    if mutation in ("v1", "bool-schema", "wrong-truth", "job", "role"):
        key, value = {"v1": ("profile", "owned-response-header-absence.v1"),
            "bool-schema": ("schema_version", True), "wrong-truth": ("condition_observed", False),
            "job": ("original_job_id", "job:foreign"), "role": ("original_role_ids", {})}[mutation]
        attrs[key] = value
    elif mutation in ("owner", "bool-cas", "policy", "expired"):
        key, value = {"owner": ("owner_reference", "actor:foreign"),
            "bool-cas": ("model_revision", True), "policy": ("policy_sha256", "0" * 64),
            "expired": ("checked_at", attrs["authority_basis"]["expires_at"])}[mutation]
        attrs["authority_basis"][key] = value
    elif mutation == "finding-severity":
        after["model"]["objects"][-1]["attributes"]["severity"] = "critical"
    elif mutation == "native-triage":
        after["model"]["objects"][1]["attributes"]["status"] = "dismissed"

    fact["reference"] = oracle.Reference("observation", {key: value for key, value in fact.items()
        if key != "reference"})
    summary["assessment_reference"] = fact["reference"]
    saves = Saves(before, after)

    if mutation == "lost-ack":
        saves[0]["returned"] = None

    with pytest.raises(AssertionError):
        oracle.AssertContentHeaderV2(before, after, summary, saves, **options)


@pytest.mark.parametrize("mutation", [None, "receipt", "v1", "state"])
def test_HistoricalReplayPreservesOriginalIdentitiesAndDoesNotRepairState(mutation):
    """Replay checks use retained historical IDs and unchanged snapshots, never current grants."""

    before, after, summary, saves, options = Fixture()
    identities = oracle.AssertContentHeaderV2(before, after, summary, saves, **options)
    replay = {**identities, "state": "verified", "profile": oracle.PROFILE,
        "source_profile": oracle.SOURCE_PROFILE}
    reopened = copy.deepcopy(after)

    if mutation == "receipt":
        replay["original_receipt_id"] = "foreign-receipt"
    elif mutation == "v1":
        replay["profile"] = "owned-response-header-absence.v1"
    elif mutation == "state":
        reopened["model"]["revision"] += 1

    if mutation is None:
        oracle.AssertHistoricalContentHeaderReplay(after, reopened, replay, identities)
    else:
        with pytest.raises(AssertionError):
            oracle.AssertHistoricalContentHeaderReplay(after, reopened, replay, identities)


def test_ReviewGuardActualPositiveRequiresFindingDetectionAlongsideAssessment():
    """The source schema includes both actual detector fact and the separately saved assessment."""

    before, after, summary, saves, options = Fixture(include_detection=True)
    oracle.AssertContentHeaderV2(before, after, summary, saves, **options)


@pytest.mark.parametrize("mutation", ["no-permission", "no-url-allow", "no-ip-allow",
    "no-url-registration", "no-ip-registration", "missing-attester", "early-observed",
    "late-observed", "naive-observed"])
def test_ReviewGuardPositiveAuthorityAndObservedTimeCannotBeHashOnly(mutation):
    """Self-consistent hashes cannot replace explicit permission, consent or original time joins."""

    before, after, summary, saves, options = Fixture()
    fact = after["model"]["observations"][-1]
    authority = options["authority"]

    if mutation == "no-permission":
        authority["policy"]["permissions"] = []
    elif mutation in ("no-url-allow", "no-ip-allow"):
        kind = "url" if mutation == "no-url-allow" else "ip"
        authority["scope"]["allow"] = [item for item in authority["scope"]["allow"]
            if item["kind"] != kind]
    elif mutation in ("no-url-registration", "no-ip-registration"):
        kind = "url" if mutation == "no-url-registration" else "ip"
        authority["scope"]["targets"] = [item for item in authority["scope"]["targets"]
            if item["kind"] != kind]
    elif mutation == "missing-attester":
        authority["scope"]["authorization"]["authority_reference"] = None
    else:
        fact["provenance"]["observed_at"] = {"early-observed": "2026-10-24T00:00:01+00:00",
            "late-observed": "2026-10-24T00:00:04+00:00",
            "naive-observed": "2026-10-24T00:00:03"}[mutation]

    basis = fact["attributes"]["authority_basis"]
    basis["scope_sha256"] = oracle.ContractDigest(authority["scope"])
    basis["policy_sha256"] = oracle.ContractDigest(authority["policy"])
    fact["reference"] = oracle.Reference("observation", {key: value for key, value in fact.items()
        if key != "reference"})
    summary["assessment_reference"] = fact["reference"]

    for row in after["model"]["observations"]:
        if row["kind"] == "finding-detection":
            row["reference"] = oracle.Reference("observation", {key: value for key, value in
                row.items() if key != "reference"})

    saves = Saves(before, after)

    with pytest.raises(AssertionError):
        oracle.AssertContentHeaderV2(before, after, summary, saves, **options)


@pytest.mark.parametrize("mutation", ["missing", "triaged-detection", "foreign-analysis",
    "bool-detector-schema", "bool-detector-confidence"])
def test_ReviewGuardDetectionMustRetainOriginalUntriagedAttributesAndAttribution(mutation):
    """Self-consistent detector hashes cannot replace the actual incoming detection association."""

    before, after, summary, saves, options = Fixture()
    detection = after["model"]["observations"][-2]

    if mutation == "missing":
        after["model"]["observations"].remove(detection)
    else:
        if mutation == "triaged-detection":
            detection["attributes"]["status"] = "confirmed"
        elif mutation == "bool-detector-schema":
            detection["attributes"]["schema_version"] = True
        elif mutation == "bool-detector-confidence":
            detection["attributes"]["confidence"] = False
        else:
            detection["provenance"] = {**detection["provenance"], "run_reference": "job:foreign"}
        detection["reference"] = oracle.Reference("observation", {key: value for key, value in
            detection.items() if key != "reference"})

    with pytest.raises(AssertionError):
        oracle.AssertContentHeaderV2(before, after, summary, Saves(before, after), **options)
