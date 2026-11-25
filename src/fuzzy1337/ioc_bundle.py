# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded transfer of one verified retained IOC acquisition without workspace export."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import fields
from io import BytesIO
from pathlib import Path
from typing import Any, TextIO

from fuzzy1337.artifact_inputs import ReadArtifactFile
from fuzzy1337.evidence import EVIDENCE_MANIFEST_MAX_BYTES, EvidenceError, ParseEvidenceManifest
from fuzzy1337.ioc_artifacts import (
    _ROLES,
    Header,
    Identity,
    IocEvidenceStore,
    IocLimits,
    IocSnapshot,
    IocSource,
    JsonBytes,
    LoadIocArtifact,
    Metadata,
    ObjectFields,
    OriginalRecord,
    ParseIocArtifact,
    RequestPin,
)
from fuzzy1337.ioc_commands import IocParser, SelectedPath
from fuzzy1337.report_commands import PublishReport, ReportFailure, ReportOutputPath
from fuzzy1337.workspace import LocalWorkspaceStore

FAMILY = "ioc-evidence-bundle-v1"
ROLES = ("ioc-source", "ioc-acquisition", "ioc-snapshot")
_EMPTY = {"schema_version": 1, "family": FAMILY, "snapshot_id": "sha256:" + "0" * 64,
          "receipt_id": "sha256:" + "0" * 64,
          "records": [{"manifest_base64": "", "payload_base64": ""} for _ in ROLES]}
# Base64 contains no JSON escapes. All other strings/keys have fixed profile lengths.
MAX_BUNDLE_BYTES = len(JsonBytes(_EMPTY)) + sum(
    4 * ((EVIDENCE_MANIFEST_MAX_BYTES + 2) // 3) + 4 * ((_ROLES[role][0] + 2) // 3)
    for role in ROLES
)


def DecodePart(value: object, maximum: int) -> bytes:
    """Bound canonical base64 before decoding any selected manifest or original payload.

    Args:
        value: One explicitly selected bundle field; arbitrary encodings are refused.
        maximum: Original owning consumer's maximum decoded byte count.

    Returns:
        Exact original bytes with canonical padding and no ignored characters.

    Raises:
        ValueError: Type, encoded/decoded length or canonical base64 differs.
    """

    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("IOC bundle part exceeds its encoded budget")

    decoded = base64.b64decode(value, validate=True)

    if len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("IOC bundle part differs from its canonical encoding")

    return decoded


def VerifyIocBundle(payload: bytes, receipt: str, digest: str) -> IocSnapshot:
    """Verify a detached selected bundle using independently retained transfer and receipt pins.

    Args:
        payload: Complete bounded canonical bundle bytes; no filesystem is consulted.
        receipt: Original acquisition manifest pin retained independently of this file.
        digest: Expected lowercase bundle SHA-256 retained from the exporter outcome.

    Returns:
        Independently reparsed original IOC occurrences with their unchanged attribution.

    Raises:
        ValueError: Transfer pin, original manifests, provenance, budgets or reparse disagree.
    """

    Identity(receipt)

    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest) or (
        type(payload) is not bytes or len(payload) > MAX_BUNDLE_BYTES
        or hashlib.sha256(payload).hexdigest() != digest
    ):
        raise ValueError("IOC bundle differs from the independently retained transfer pin")

    document = ObjectFields(Metadata(payload, MAX_BUNDLE_BYTES), {
        "schema_version", "family", "snapshot_id", "receipt_id", "records"})

    if type(document["schema_version"]) is not int or document["schema_version"] != 1 or (
        document["family"] != FAMILY or document["receipt_id"] != receipt
        or type(document["records"]) is not list or len(document["records"]) != len(ROLES)
    ):
        raise ValueError("IOC bundle differs from its selected closed profile")

    Identity(document["snapshot_id"])
    records = []
    originals = []

    for role, item in zip(ROLES, document["records"], strict=True):
        part = ObjectFields(item, {"manifest_base64", "payload_base64"})
        record = ParseEvidenceManifest(DecodePart(part["manifest_base64"],
                                                  EVIDENCE_MANIFEST_MAX_BYTES))
        maximum, media = _ROLES[role]
        attribution = record.provenance

        if record.reference.role != role or record.reference.media_type != media or (
            record.reference.size_bytes > maximum or attribution.source_id != "ioc-artifacts"
            or attribution.source_version != "1" or attribution.tool_version != "1"
            or attribution.execution is not None or attribution.invocation_sha256 is not None
        ):
            raise ValueError("IOC bundle record differs from original parser ownership")

        content = DecodePart(part["payload_base64"], maximum)

        if len(content) != record.reference.size_bytes or hashlib.sha256(content).hexdigest() != (
            record.reference.sha256
        ) or record.reference.locator != "blobs/sha256/" + record.reference.sha256:
            raise ValueError("IOC bundle original bytes differ from their manifest")

        records.append(record)
        originals.append(content)

    raw, acquired, derived = records

    if acquired.evidence_id != receipt or derived.evidence_id != document["snapshot_id"] or (
        raw.provenance != acquired.provenance or raw.provenance != derived.provenance
    ):
        raise ValueError("IOC bundle substitutes original manifest identities or provenance")

    data = Header(Metadata(originals[1], _ROLES["ioc-acquisition"][0]), {
        "state", "transport", "authentication", "raw_evidence_id", "source", "limits",
        "provenance", "request_sha256"})
    source = IocSource(**ObjectFields(data["source"], {item.name for item in fields(IocSource)}))
    limits = IocLimits(**ObjectFields(data["limits"], {item.name for item in fields(IocLimits)}))

    if data["state"] != "succeeded" or data["transport"] != "caller-supplied-bytes" or (
        data["authentication"] != "not-assessed" or data["raw_evidence_id"] != raw.evidence_id
        or data["provenance"] != acquired.provenance.ToDict()
        or data["request_sha256"] != RequestPin(source, limits)
    ):
        raise ValueError("IOC bundle differs from its original acquisition receipt")

    snapshot = IocSnapshot(raw.evidence_id, acquired.evidence_id, source, limits,
        ParseIocArtifact(originals[0], source, limits))

    if snapshot.Serialize() != originals[2]:
        raise ValueError("IOC bundle snapshot differs from original-byte replay")

    return snapshot


def ExportIocBundle(root: Path, snapshot: str, receipt: str) -> bytes:
    """Verify one original chain and serialize exactly its three records for an explicit handoff.

    Args:
        root: Existing physical owning workspace; no unrelated evidence is selected.
        snapshot: Exact original derived manifest ID selected by the operator.
        receipt: Independently retained original acquisition manifest anchor.

    Returns:
        Canonical deterministic JSON/base64 with original manifests and exact stored payloads.

    Raises:
        ValueError: Source chain, original provenance or detached verification differs.
        EvidenceError: An original manifest or payload is missing or corrupt.
        OSError: The owning workspace cannot be read.
    """

    verified = LoadIocArtifact(root, snapshot, receipt)
    workspace = LocalWorkspaceStore(root).Open()
    store = IocEvidenceStore(root / "evidence", verified.limits.max_bytes)
    parts = []

    for role, identity in zip(ROLES, (verified.raw_evidence_id, receipt, snapshot), strict=True):
        record = store.Get(identity)
        original = OriginalRecord(record, workspace.workspace_id, store, role)
        parts.append({"manifest_base64": base64.b64encode(record.Serialize()).decode("ascii"),
                      "payload_base64": base64.b64encode(original).decode("ascii")})

    payload = JsonBytes({"schema_version": 1, "family": FAMILY,
                        "snapshot_id": snapshot, "receipt_id": receipt, "records": parts})

    if VerifyIocBundle(payload, receipt, hashlib.sha256(payload).hexdigest()) != verified:
        raise ValueError("IOC export differs from its original independently verified chain")

    return payload


def RunIocBundleCommands(arguments: list[str], output: TextIO, *, machine: bool) -> int:
    """Export or independently verify one explicit original bundle without changing source state.

    Args:
        arguments: Exact trace/ioc bundle action and explicit selections.
        output: Caller-owned summary stream; explicit JSON candidate export also includes
            verified original tokens and declared source attribution.
        machine: Emit a version-one outcome with independently retainable transfer pins.

    Returns:
        Zero on success, two for invalid selections, four for integrity/publication refusal,
        or 130 for interruption. A post-link failure truthfully retains a complete publication.
    """

    from fuzzy1337.ioc_commands import IocFailure

    outcome: dict[str, Any] = {"schema_version": 1, "command": "trace.ioc.bundle",
        "status": "failed", "failure": None, "output_published": False,
        "bundle_sha256": None, "size_bytes": None, "raw_id": None,
        "receipt_id": None, "snapshot_id": None, "candidate_count": None,
        "evidence_commit": "not-attempted", "core_mutation": "none"}
    status = 4
    phase = "configuration"
    exported: dict[str, object] | None = None

    try:
        options = IocParser().parse_args(arguments)
        outcome["command"] = "trace.ioc." + options.action

        if options.action == "verify-bundle" and options.export_candidates and not machine:
            raise IocFailure("configuration", 2)

        Identity(options.receipt)

        if options.action == "export-bundle":
            root = SelectedPath(options.workspace)
            Identity(options.snapshot)
            destination = ReportOutputPath(options.output, root)
            phase = "integrity"
            payload = ExportIocBundle(root, options.snapshot, options.receipt)
            digest = hashlib.sha256(payload).hexdigest()
            snapshot = VerifyIocBundle(payload, options.receipt, digest)
            if ExportIocBundle(root, options.snapshot, options.receipt) != payload:
                raise ValueError("IOC original changed before bundle publication")

        else:
            if not re.fullmatch(r"[0-9a-f]{64}", options.expected_sha256):
                raise ValueError("IOC bundle requires an explicit transfer digest")

            selected = SelectedPath(options.file)
            phase = "integrity"
            stream = BytesIO()
            ReadArtifactFile(selected, "ioc-bundle.json", stream, max_bytes=MAX_BUNDLE_BYTES)
            payload = stream.getvalue()
            digest = options.expected_sha256
            snapshot = VerifyIocBundle(payload, options.receipt, digest)

        document = Metadata(payload, MAX_BUNDLE_BYTES)
        outcome.update({"bundle_sha256": digest,
            "size_bytes": len(payload), "raw_id": snapshot.raw_evidence_id,
            "receipt_id": snapshot.acquisition_evidence_id,
            "snapshot_id": document["snapshot_id"], "candidate_count": len(snapshot.candidates)})

        if options.action == "export-bundle":
            phase = "publication"
            PublishReport(destination, payload)
            outcome["output_published"] = True

        if options.action == "verify-bundle" and options.export_candidates:
            exported = json.loads(snapshot.Serialize())

        outcome["status"] = "completed"
        status = 0

    except IocFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except ReportFailure as error:
        outcome.update({"failure": error.kind, "output_published": error.published})
        status = error.status

    except (EvidenceError, OSError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    outcome["exit_code"] = status

    if machine:
        if status == 0 and exported is not None:
            outcome["candidate_export"] = exported

        output.write(json.dumps(outcome, sort_keys=True, allow_nan=False) + "\n")

    else:
        output.write(f"IOC bundle {outcome['status']} (exit {status}).\n")

        if status == 0:
            output.write(f"Bundle SHA-256 {outcome['bundle_sha256']}\n"
                         f"Original receipt {outcome['receipt_id']}\n"
                         f"Original snapshot {outcome['snapshot_id']}\n")

        else:
            output.write(f"Failure category: {outcome['failure']}.\n")

            if outcome["output_published"]:
                output.write("A complete bundle was published before acknowledgement failed.\n"
                             f"Bundle SHA-256 {outcome['bundle_sha256']}\n"
                             f"Original receipt {outcome['receipt_id']}\n")

    output.flush()

    return status
