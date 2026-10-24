# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Synthetic original-document tamper controls, without actual capture or SDK acceptance."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from tests.contract import owned_content_response_sdk_oracle as oracle
from tests.contract.owned_content_response_oracle import RequestBytes


def Encode(value):
    """Encode only synthetic unit fixture documents using the manifest's specified JSON form."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def Bundle(name):
    """Build marked synthetic seven-role fixtures; no actual ACK or runtime is asserted."""

    case = oracle.CASES[name]
    url = "http://127.0.0.1:49123" + case.path
    originals = {}
    ids = {}
    provenance = {"source_id": "native.loopback-content-response", "workspace_id": "unit-only",
        "scope_reference": "scope:unit-only", "started_at": "2026-10-24T00:00:00+00:00",
        "finished_at": "2026-10-24T00:00:01+00:00", "execution": {
            "state": "succeeded", "exit_code": 0, "duration_seconds": 1.0}}

    def Add(role, raw):
        """Create only synthetic records with actual computed fixture hashes and role IDs."""

        digest = hashlib.sha256(raw).hexdigest()
        manifest = {"schema_version": 1, "reference": {"role": role,
            "locator": "blobs/sha256/" + digest, "sha256": digest, "size_bytes": len(raw),
            "media_type": "application/json" if role in ("stdout", oracle.RECEIPT_ROLE)
                else "application/octet-stream"}, "provenance": copy.deepcopy(provenance)}
        identity = "sha256:" + hashlib.sha256(Encode(manifest)).hexdigest()
        ids[role] = identity
        originals[identity] = {"manifest": manifest, "data_hex": raw.hex()}

    for role, raw in (("stdout", case.ExpectedStdout(url)), ("stderr", b""),
        ("owned-response-request", RequestBytes(url)), ("owned-response-headers", case.headers),
        ("owned-response-body", case.body), ("owned-response-wire", case.Wire())):
        Add(role, raw)

    receipt = {"schema_version": 1, "profile": "owned-content-response-receipt.v1",
        "owner_reference": "actor:synthetic-\u043e\u043f\u0435\u0440\u0430\u0442\u043e\u0440",
        "workspace_id": provenance["workspace_id"], "started_at": provenance["started_at"],
        "finished_at": provenance["finished_at"], "refusal": None, "events": [],
        "request": {"invocation": {"adapter_id": "native.loopback-content-response",
            "argv": ["/synthetic/bin/python", "-I", "-B", "-m",
                "fuzzy1337.owned_content_response_worker", url], "request": {
                    "capability": "http.owned-content-response-capture", "impact": "SAFE",
                    "target_reference": "target:" + hashlib.sha256(Encode({"kind": "url",
                        "value": url})).hexdigest(), "parameters": {"url": url,
                            "retain_response": True}, "credential_references": []}}},
        "custody": "complete", "termination": "process_exit", "execution": {
            "state": "succeeded", "exit_code": 0, "duration_seconds": 1.0}, "evidence_ids": {
                key: ids[role] for role, key in oracle.ROLE_KEYS.items()}}
    Add(oracle.RECEIPT_ROLE, json.dumps(receipt, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii"))
    attrs = {"schema_version": 1, "profile": "owned-content-response-capture.v1",
        "original_job_id": "job:synthetic-unit-only", "original_receipt_id": ids[
            oracle.RECEIPT_ROLE], "original_role_ids": ids,
        "request_sha256": hashlib.sha256(RequestBytes(url)).hexdigest(),
        "response_sha256": hashlib.sha256(case.Wire()).hexdigest(),
        "header_size_bytes": len(case.headers), "body_size_bytes": len(case.body),
        "media_type": case.media_type}

    return url, ids[oracle.RECEIPT_ROLE], originals, attrs


@pytest.mark.parametrize("name", ["missing", "fixed", "body-decoy", "empty-body"])
def test_IndependentOriginalPartsAllowEmptyBlobSharingButRequireDistinctRoleIds(name):
    """Independent bytes support admitted fixtures including equal empty stderr/body blobs."""

    url, receipt, originals, attrs = Bundle(name)
    assert oracle.AssertContentParts(name, url, receipt, originals, attrs,
        job_id="job:synthetic-unit-only") == attrs["original_role_ids"]


@pytest.mark.parametrize("mutation", ["bytes", "manifest", "role-alias", "receipt-selection",
    "source-family", "source-job", "source-schema-bool", "size-bool"])
def test_OriginalCustodyRejectsRebindingAndEqualValueBooleanClaims(mutation):
    """Substitution at byte, ID, family or original-association boundaries must be refused."""

    url, receipt, originals, attrs = copy.deepcopy(Bundle("empty-body"))
    identity = attrs["original_role_ids"]["owned-response-body"]

    if mutation == "bytes":
        originals[identity]["data_hex"] = b"substituted".hex()

    elif mutation == "manifest":
        originals[identity]["manifest"]["provenance"]["scope_reference"] = "scope:replaced"

    elif mutation == "role-alias":
        attrs["original_role_ids"]["owned-response-body"] = attrs["original_role_ids"]["stderr"]

    elif mutation == "receipt-selection":
        receipt = "sha256:" + "0" * 64

    elif mutation == "source-family":
        attrs["profile"] = "owned-response-capture.v1"

    elif mutation == "source-job":
        attrs["original_job_id"] = "job:foreign"

    elif mutation == "source-schema-bool":
        attrs["schema_version"] = True

    else:
        attrs["body_size_bytes"] = False

    with pytest.raises(AssertionError):
        oracle.AssertContentParts("empty-body", url, receipt, originals, attrs,
            job_id="job:synthetic-unit-only")


@pytest.mark.parametrize("mutation", ["exit-bool", "failed", "catalog", "role-rebind",
    "receipt-extra", "receipt-missing", "receipt-refusal", "foreign-url", "foreign-provider",
    "retain-integer"])
def test_ResignedReceiptStillCannotHideWrongFamilyFailureOrDifferentOriginalIds(mutation):
    """A self-consistent new manifest hash cannot validate false underlying custody facts."""

    url, receipt_id, originals, attrs = Bundle("missing")
    item = originals.pop(receipt_id)
    receipt = json.loads(bytes.fromhex(item["data_hex"]))

    if mutation == "exit-bool":
        receipt["execution"]["exit_code"] = False

    elif mutation == "failed":
        receipt["execution"]["state"] = "failed"

    elif mutation == "catalog":
        receipt["profile"] = "owned-response-capture-receipt.v1"

    elif mutation == "role-rebind":
        receipt["evidence_ids"]["body"] = receipt["evidence_ids"]["headers"]

    elif mutation == "receipt-extra":
        receipt["unexpected"] = "foreign contract"

    elif mutation == "receipt-missing":
        del receipt["events"]

    elif mutation == "receipt-refusal":
        receipt["refusal"] = "protocol"

    elif mutation == "foreign-url":
        receipt["request"]["invocation"]["request"]["parameters"]["url"] += "/foreign"

    elif mutation == "foreign-provider":
        receipt["request"]["invocation"]["adapter_id"] = "native.loopback-response"

    else:
        receipt["request"]["invocation"]["request"]["parameters"]["retain_response"] = 1

    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    item["data_hex"] = raw.hex()
    item["manifest"]["reference"].update(locator="blobs/sha256/" + digest, sha256=digest,
        size_bytes=len(raw))
    replacement_id = "sha256:" + hashlib.sha256(Encode(item["manifest"])).hexdigest()
    originals[replacement_id] = item
    attrs["original_receipt_id"] = replacement_id
    attrs["original_role_ids"][oracle.RECEIPT_ROLE] = replacement_id

    with pytest.raises(AssertionError):
        oracle.AssertContentParts("missing", url, replacement_id, originals, attrs,
            job_id="job:synthetic-unit-only")


@pytest.mark.parametrize("mutation", ["scope", "exit-bool"])
def test_ResignedPartCannotMixForeignScopeIntoOneOtherwiseConsistentCapture(mutation):
    """Equal bytes and freshly consistent IDs cannot replace original collection provenance."""

    url, receipt_id, originals, attrs = Bundle("missing")
    body_id = attrs["original_role_ids"]["owned-response-body"]
    body = originals.pop(body_id)
    if mutation == "scope":
        body["manifest"]["provenance"]["scope_reference"] = "scope:foreign"

    else:
        body["manifest"]["provenance"]["execution"]["exit_code"] = False
    new_body_id = "sha256:" + hashlib.sha256(Encode(body["manifest"])).hexdigest()
    originals[new_body_id] = body
    attrs["original_role_ids"]["owned-response-body"] = new_body_id
    receipt_item = originals.pop(receipt_id)
    receipt = json.loads(bytes.fromhex(receipt_item["data_hex"]))
    receipt["evidence_ids"]["body"] = new_body_id
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    receipt_item["data_hex"] = raw.hex()
    receipt_item["manifest"]["reference"].update(locator="blobs/sha256/" + digest,
        sha256=digest, size_bytes=len(raw))
    new_receipt_id = "sha256:" + hashlib.sha256(Encode(receipt_item["manifest"])).hexdigest()
    originals[new_receipt_id] = receipt_item
    attrs["original_receipt_id"] = new_receipt_id
    attrs["original_role_ids"][oracle.RECEIPT_ROLE] = new_receipt_id

    with pytest.raises(AssertionError, match="same actual collection provenance"):
        oracle.AssertContentParts("missing", url, new_receipt_id, originals, attrs,
            job_id="job:synthetic-unit-only")
