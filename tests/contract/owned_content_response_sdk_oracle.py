# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure independent seven-part content custody oracle, without SDK/runtime acceptance.

Inputs must be detached original manifests/bytes and the actual source attributes from a
separately retained consumer. These predicates do not prove acquisition authority, ACK,
durable workspace attachment, installed imports or a PASSIVE assessment by themselves.
"""

from __future__ import annotations

import hashlib
import json

from tests.contract.owned_content_response_oracle import CaseMatrix, RequestBytes

CASES = {case.name: case for case in CaseMatrix()}
ROLE_KEYS = {"stdout": "stdout", "stderr": "stderr", "owned-response-request": "request",
    "owned-response-headers": "headers", "owned-response-body": "body",
    "owned-response-wire": "response"}
RECEIPT_ROLE = "owned-response-receipt"


def Canonical(value: object) -> bytes:
    """Use standard JSON primitives, without invoking any production admission routine."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def AssertContentParts(name: str, url: str, receipt_id: str, originals: dict,
    source_attributes: dict, *, job_id: str) -> dict[str, str]:
    """Reconcile original seven-role IDs/bytes with one independent admitted source case.

    Args:
        name: Explicit frozen admitted case, never an outcome inferred from product output.
        url: Original caller-selected URL served for this case.
        receipt_id: Independently retained original acknowledged receipt ID.
        originals: Consumer-read original ID to manifest/data_hex records, possibly including
            unrelated existing evidence. No IDs or metadata are manufactured here.
        source_attributes: Detached actual content source Observation attributes.
        job_id: Independently retained actual acquisition job ID.

    Returns:
        Original selected role IDs after byte/manifest checks; no authority/ACK claim.
    """

    assert name in CASES and CASES[name].error is None, "An admitted frozen case is required"
    case = CASES[name]
    assert type(source_attributes.get("schema_version")) is int and (
        source_attributes["schema_version"] == 1), "Source schema requires an exact integer"
    assert all(type(source_attributes[key]) is int for key in (
        "header_size_bytes", "body_size_bytes")), "Source sizes require exact integers"
    ids = source_attributes["original_role_ids"]
    assert type(ids) is dict and set(ids) == {*ROLE_KEYS, RECEIPT_ROLE}, (
        "All seven distinct original role identities are required")
    assert all(type(value) is str for value in ids.values()) and len(set(ids.values())) == 7, (
        "Equal content is not a replacement for distinct original role identities")
    assert ids[RECEIPT_ROLE] == receipt_id, "Selected original receipt identity must remain exact"
    expected = {"stdout": case.ExpectedStdout(url), "stderr": b"",
        "owned-response-request": RequestBytes(url), "owned-response-headers": case.headers,
        "owned-response-body": case.body, "owned-response-wire": case.Wire()}
    selected = {}
    provenance = originals[receipt_id]["manifest"]["provenance"]

    for role, identity in ids.items():
        item = originals[identity]
        manifest = item["manifest"]
        assert set(manifest) == {"schema_version", "reference", "provenance"}, (
            "Original manifest schema must remain closed")
        assert type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, (
            "Manifest schema requires an exact integer")
        assert "sha256:" + hashlib.sha256(Canonical(manifest)).hexdigest() == identity, (
            "Original manifest bytes must derive the selected manifest identity")
        raw = bytes.fromhex(item["data_hex"])
        reference = manifest["reference"]
        digest = hashlib.sha256(raw).hexdigest()
        media = "application/json" if role in ("stdout", RECEIPT_ROLE) else (
            "application/octet-stream")
        assert type(reference["size_bytes"]) is int and reference == {
            "role": role, "locator": "blobs/sha256/" + digest, "sha256": digest,
            "size_bytes": len(raw), "media_type": media}, "Original role bytes/metadata differ"
        assert manifest["provenance"]["source_id"] == "native.loopback-content-response", (
            "A catalog or foreign source cannot establish content custody")
        assert manifest["provenance"] == provenance, (
            "All seven original roles must retain the same actual collection provenance")

        if role != RECEIPT_ROLE:
            assert raw == expected[role], "Retained original bytes differ from the served case"

        selected[role] = raw

    receipt = json.loads(selected[RECEIPT_ROLE])
    assert set(receipt) == {"schema_version", "profile", "custody", "workspace_id",
        "owner_reference", "started_at", "finished_at", "request", "execution", "termination",
        "events", "evidence_ids", "refusal"}, "Original receipt schema must remain closed"
    receipt_raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    assert receipt_raw == selected[RECEIPT_ROLE], (
        "Duplicate keys or substituted receipt serialization are not original canonical bytes")
    assert type(receipt["schema_version"]) is int and receipt["schema_version"] == 1, (
        "Receipt schema requires an exact integer")
    assert receipt["profile"] == "owned-content-response-receipt.v1" and (
        receipt["custody"] == "complete"), "Only complete original content custody is admitted"
    assert receipt["refusal"] is None, "An original refusal cannot establish captured parts"
    assert receipt["termination"] == "process_exit" and (
        receipt["execution"]["state"] == "succeeded") and type(
        receipt["execution"]["exit_code"]) is int and receipt["execution"]["exit_code"] == 0, (
            "Refused or incomplete original execution cannot establish complete content custody")
    assert receipt["execution"] == provenance["execution"] and all(
        receipt[key] == provenance[key] for key in ("workspace_id", "started_at", "finished_at")), (
            "Receipt execution and collection identity must match all original part manifests")
    invocation = receipt["request"]["invocation"]
    target_reference = "target:" + hashlib.sha256(Canonical({"kind": "url",
        "value": url})).hexdigest()
    assert invocation["adapter_id"] == "native.loopback-content-response" and invocation[
        "request"] == {"capability": "http.owned-content-response-capture",
            "target_reference": target_reference, "impact": "SAFE", "parameters": {
                "url": url, "retain_response": True}, "credential_references": []}, (
                    "Original receipt must select this exact content provider and URL")
    assert invocation["argv"][1:] == ["-I", "-B", "-m", (
        "fuzzy1337.owned_content_response_worker"), url], "Original source recipe must match"
    assert receipt["evidence_ids"] == {key: ids[role] for role, key in ROLE_KEYS.items()}, (
        "Receipt must preserve each original role ID, including equal-byte roles")
    assert source_attributes == {"schema_version": 1, "profile": (
        "owned-content-response-capture.v1"), "original_job_id": job_id,
        "original_receipt_id": receipt_id, "original_role_ids": ids,
        "request_sha256": hashlib.sha256(expected["owned-response-request"]).hexdigest(),
        "response_sha256": hashlib.sha256(case.Wire()).hexdigest(),
        "header_size_bytes": len(case.headers), "body_size_bytes": len(case.body),
        "media_type": case.media_type}, "Original source attributes must bind exact selected parts"

    return dict(ids)
