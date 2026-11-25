# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Retain owned saved-syslog originals and reparse exact independently pinned receipts offline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import cast

from fuzzy1337.adapters.contracts import EvidenceReference, RequireIdentifier
from fuzzy1337.artifact_inputs import ArtifactPathInfo, ArtifactReadConsent, ReadArtifactFile
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    ParseEvidenceManifest,
    RejectManifestConstant,
    RequireManifestFields,
    UniqueManifestObject,
)
from fuzzy1337.syslog_records import (
    MAX_SYSLOG_DOCUMENT_BYTES,
    MAX_SYSLOG_SOURCE_BYTES,
    SYSLOG_PARSER,
    SYSLOG_PARSER_VERSION,
    SYSLOG_PROFILE,
    ParseSavedSyslog,
    RequireSyslogDigest,
    RequireSyslogFraming,
    SyslogDecodeError,
    SyslogJson,
    SyslogLimits,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = [
    "SyslogSource", "SyslogAcquisition", "ImportSavedSyslogFile", "LoadSavedSyslog",
]

RAW_ROLE = "syslog-rfc5424-original"
RECEIPT_ROLE = "syslog-rfc5424-receipt"
MAX_SYSLOG_RECEIPT_BYTES = 32 * 1024


def SyslogText(value: object) -> str:
    """Validate bounded descriptive metadata, independently from arbitrary RFC parameter values.

    Args:
        value: Explicit non-secret source, scope or read-declaration reference.

    Returns:
        Exact string, without inferring identity, authority or a retrievable location.
    """

    if type(value) is not str or not value or len(value.encode("utf-8")) > 512 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("Syslog metadata requires bounded non-control text")

    return value


@dataclass(frozen=True, slots=True)
class SyslogSource:
    """Describe a declared local source and byte pin, separately from parser identity."""

    sourceId: str
    sourceVersion: str
    sourceLocator: str
    expectedSha256: str
    framing: str
    sourceToolVersion: str | None = None

    def __post_init__(self) -> None:
        """Require closed immutable source fields without authenticating their declarations."""

        if type(self) is not SyslogSource:
            raise ValueError("Syslog source requires its exact first-party type")

        RequireIdentifier(self.sourceId, "source_id")
        SyslogText(self.sourceId)
        SyslogText(self.sourceVersion)
        SyslogText(self.sourceLocator)
        RequireSyslogDigest(self.expectedSha256)
        RequireSyslogFraming(self.framing)

        if self.sourceToolVersion is not None:
            SyslogText(self.sourceToolVersion)

    def ToDict(self) -> dict[str, object]:
        """Detach exact source declarations; no locator or producer is contacted.

        Returns:
            Closed source metadata, keeping an unknown original tool version unknown.
        """

        return {"source_id": self.sourceId, "source_version": self.sourceVersion,
            "source_locator": self.sourceLocator, "expected_sha256": self.expectedSha256,
            "framing": self.framing, "source_tool_version": self.sourceToolVersion}


@dataclass(frozen=True, slots=True)
class SyslogAcquisition:
    """Keep original storage acknowledgements separate from immutable normalized JSON bytes."""

    state: str
    source: SyslogSource
    sourceSha256: str
    raw: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None
    rawAck: str = "not-attempted"
    receiptAck: str = "not-attempted"
    ackBasis: str = "sdk-returned"
    document: bytes | None = None
    readConsent: ArtifactReadConsent | None = None

    def __post_init__(self) -> None:
        """Refuse mutable/subclass substitutions and inconsistent completion flags."""

        if type(self) is not SyslogAcquisition or type(self.source) is not SyslogSource:
            raise ValueError("Syslog result requires exact first-party records")

        object.__setattr__(self, "source", SourceFromDict(self.source.ToDict()))

        if self.readConsent is not None:
            if type(self.readConsent) is not ArtifactReadConsent:
                raise ValueError("Syslog read declaration requires its exact first-party type")

            object.__setattr__(self, "readConsent", ArtifactReadConsent(
                SyslogText(self.readConsent.actor_ref), SyslogText(self.readConsent.record_ref),
            ))
        RequireSyslogDigest(self.sourceSha256)

        if self.state not in {"succeeded", "parse-rejected", "digest-rejected", "storage-failed",
                              "interrupted"} or self.ackBasis not in {
            "sdk-returned", "verified-present",
        }:
            raise ValueError("Syslog outcome state is unsupported")

        for record, acknowledgement in ((self.raw, self.rawAck), (self.receipt, self.receiptAck)):
            if acknowledgement not in {"not-attempted", "unknown", "confirmed"} or (
                (record is not None) != (acknowledgement == "confirmed")
                or record is not None and (
                    type(record) is not EvidenceRecord
                    or type(record.reference) is not EvidenceReference
                    or type(record.provenance) is not EvidenceProvenance
                )
            ):
                raise ValueError("Syslog acknowledgement contradicts its returned record")

        complete = self.rawAck == self.receiptAck == "confirmed"

        if self.state in {"succeeded", "parse-rejected"} and not complete or (
            self.document is not None and (
                type(self.document) is not bytes
                or not 1 <= len(self.document) <= MAX_SYSLOG_DOCUMENT_BYTES
            )
        ) or (self.document is not None) != (self.state == "succeeded"):
            raise ValueError("Syslog result cannot expose incomplete normalized records")


class SyslogEvidenceStore(LocalEvidenceStore):
    """Preflight one profile-controlled role/media/byte domain before the owner's eager read."""

    def __init__(self, root: Path, role: str) -> None:
        """Select the original or receipt allocation budget before any stored source read.

        Args:
            root: Existing evidence owner within the explicit workspace.
            role: Implementation-owned exact original or receipt role.
        """

        super().__init__(root)

        if role not in {RAW_ROLE, RECEIPT_ROLE}:
            raise ValueError("Syslog evidence role is unsupported")

        self.role = role

    def Read(self, reference: EvidenceReference) -> bytes:
        """Bound even Get's implicit raw verification before reading the selected blob.

        Args:
            reference: Untrusted reference parsed from an immutable candidate manifest.

        Returns:
            Original hash-verified bytes only within the selected role's finite profile.
        """

        media = "application/octet-stream" if self.role == RAW_ROLE else "application/json"
        maximum = MAX_SYSLOG_SOURCE_BYTES if self.role == RAW_ROLE else MAX_SYSLOG_RECEIPT_BYTES

        if type(reference) is not EvidenceReference or reference.role != self.role or (
            reference.media_type != media or type(reference.size_bytes) is not int
            or not 1 <= reference.size_bytes <= maximum
        ):
            raise ValueError("Syslog role, media or size is outside its allocation profile")

        return super().Read(reference)


def SourceFromDict(value: object) -> SyslogSource:
    """Rebuild the closed declared source without accepting substituted optional fields.

    Args:
        value: Bounded receipt metadata from the exact selected original receipt.

    Returns:
        Validated immutable source declaration.
    """

    source = RequireManifestFields(value, {"source_id", "source_version", "source_locator",
        "expected_sha256", "framing", "source_tool_version"})

    return SyslogSource(cast(str, source["source_id"]), cast(str, source["source_version"]),
        cast(str, source["source_locator"]), cast(str, source["expected_sha256"]),
        cast(str, source["framing"]), cast(str | None, source["source_tool_version"]))


def SyslogReceipt(payload: bytes) -> dict[str, object]:
    """Decode finite canonical receipt metadata with no duplicate or non-JSON values.

    Args:
        payload: Exact selected receipt blob, already role/size/hash checked by its owner.

    Returns:
        Closed canonical profile metadata; malformed identity or structure raises ValueError.
    """

    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_SYSLOG_RECEIPT_BYTES:
        raise ValueError("Syslog receipt exceeds its profile")

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=UniqueManifestObject,
                           parse_constant=RejectManifestConstant)
        receipt = RequireManifestFields(value, {"schema_version", "profile", "parser_id",
            "parser_version", "source", "limits", "read", "raw_id", "raw", "state",
            "parse_error", "document_sha256", "method"})
        pending: list[tuple[object, int]] = [(receipt, 0)]
        nodes = 0

        while pending:
            item, depth = pending.pop()
            nodes += 1

            if nodes > 4096 or depth > 8:
                raise ValueError("Syslog receipt exceeds its metadata structure profile")

            if isinstance(item, dict):
                pending.extend((nested, depth + 1) for nested in item.values())

            elif isinstance(item, list):
                pending.extend((nested, depth + 1) for nested in item)

        if SyslogJson(receipt) != payload or type(receipt["schema_version"]) is not int or (
            receipt["schema_version"] != 1 or receipt["profile"] != SYSLOG_PROFILE
            or receipt["parser_id"] != SYSLOG_PARSER
            or receipt["parser_version"] != SYSLOG_PARSER_VERSION
            or receipt["limits"] != SyslogLimits()
            or receipt["method"] != "owned-offline-file"
        ):
            raise ValueError("Syslog receipt identity differs from its original profile")

        if receipt["state"] not in ("succeeded", "parse-rejected"):
            raise ValueError("Syslog receipt has no complete original publication")

        if receipt["state"] == "succeeded":
            RequireSyslogDigest(receipt["document_sha256"])

            if receipt["parse_error"] is not None:
                raise ValueError("Successful syslog receipt cannot contain a parser refusal")

        else:
            refusal = RequireManifestFields(receipt["parse_error"],
                                            {"code", "record_index", "byte_offset"})
            recordIndex = refusal["record_index"]
            byteOffset = refusal["byte_offset"]

            if type(refusal["code"]) is not str or type(recordIndex) is not int or (
                type(byteOffset) is not int or recordIndex < 0 or byteOffset < 0
                or receipt["document_sha256"] is not None
            ):
                raise ValueError("Syslog refusal coordinates are inconsistent")

        return receipt

    except (UnicodeError, RecursionError, ValueError) as error:
        raise ValueError("Syslog receipt metadata is invalid") from error


def OriginalSyslogPath(value: Path, *, directory: bool = False) -> Path:
    """Select an explicit physical path through the existing artifact owner.

    Args:
        value: Absolute operator-selected path, never a header or source-declared locator.
        directory: Require the owning workspace directory instead of an original file.

    Returns:
        Unchanged bounded path after non-following physical ownership checks.
    """

    if not isinstance(value, Path) or len(str(value).encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in str(value)
    ):
        raise ValueError("Syslog input requires an explicit bounded physical path")

    ArtifactPathInfo(value, directory=directory)

    return value


def ImportSavedSyslogFile(workspaceRoot: Path, sourcePath: Path, source: SyslogSource, *,
                          scopeReference: str, consent: ArtifactReadConsent) -> SyslogAcquisition:
    """Read one consented original, verify its pin and publish through existing evidence owners.

    Args:
        workspaceRoot: Existing physical workspace; no model is created or required.
        sourcePath: Explicit owned original file, never a remote locator or daemon.
        source: Declared source/version/tool/framing and independent original byte checksum.
        scopeReference: Existing collection attribution string, not a target or execution grant.
        consent: Descriptive selected-file actor/read references; identity is not authenticated.

    Returns:
        Independent truthful original/receipt acknowledgements. Parser refusal retains the
        complete verified original but exposes no normalized document; storage uncertainty
        never implies rollback. No Core or workspace state is saved.
    """

    if type(source) is not SyslogSource or type(consent) is not ArtifactReadConsent:
        raise ValueError("Syslog acquisition requires exact source and read declaration types")

    source = SourceFromDict(source.ToDict())
    scope = SyslogText(scopeReference)
    read = ArtifactReadConsent(SyslogText(consent.actor_ref), SyslogText(consent.record_ref))
    root = OriginalSyslogPath(workspaceRoot, directory=True)
    owner = LocalWorkspaceStore(root).Open()
    path = OriginalSyslogPath(sourcePath)
    buffer = BytesIO()
    started = datetime.now(UTC).isoformat()
    original = ReadArtifactFile(path, "saved-syslog", buffer, max_bytes=MAX_SYSLOG_SOURCE_BYTES)
    finished = datetime.now(UTC).isoformat()
    payload = buffer.getvalue()

    if not payload:
        raise ValueError("Syslog source requires at least one saved message")

    if original.sha256 != source.expectedSha256:
        return SyslogAcquisition("digest-rejected", source, original.sha256, readConsent=read)

    document = None
    parseError = None
    state = "succeeded"

    try:
        document = ParseSavedSyslog(payload, expectedSha256=source.expectedSha256,
                                    framing=source.framing)

    except SyslogDecodeError as error:
        state = "parse-rejected"
        parseError = {"code": error.code, "record_index": error.recordIndex,
                      "byte_offset": error.byteOffset}

    provenance = EvidenceProvenance(owner.workspace_id, scope, source.sourceId,
        source.sourceVersion, source.sourceToolVersion, started, finished)
    expected = EvidenceRecord(EvidenceReference(RAW_ROLE,
        "blobs/sha256/" + original.sha256, original.sha256, "application/octet-stream",
        original.size_bytes), provenance)
    receiptData = SyslogJson({"schema_version": 1, "profile": SYSLOG_PROFILE,
        "parser_id": SYSLOG_PARSER, "parser_version": SYSLOG_PARSER_VERSION,
        "source": source.ToDict(), "limits": SyslogLimits(),
        "read": {"actor_reference": read.actor_ref, "consent_reference": read.record_ref},
        "raw_id": expected.evidence_id, "raw": expected.ToDict(), "state": state,
        "parse_error": parseError, "document_sha256": (
            hashlib.sha256(document).hexdigest() if document is not None else None),
        "method": "owned-offline-file"})

    if len(receiptData) > MAX_SYSLOG_RECEIPT_BYTES:
        raise ValueError("Syslog receipt exceeds its byte profile")

    receiptSha256 = hashlib.sha256(receiptData).hexdigest()
    expectedReceipt = EvidenceRecord(EvidenceReference(RECEIPT_ROLE,
        "blobs/sha256/" + receiptSha256, receiptSha256, "application/json", len(receiptData)),
        provenance)
    raw = None
    receipt = None
    rawAck = "unknown"
    receiptAck = "not-attempted"

    try:
        originals = SyslogEvidenceStore(root / "evidence", RAW_ROLE)
        proposed = originals.Put(payload, RAW_ROLE, "application/octet-stream", provenance)

        if proposed != expected or originals.Get(proposed.evidence_id) != expected:
            raise ValueError("Syslog original publication differs from its exact manifest")

        raw = proposed
        rawAck = "confirmed"
        receiptAck = "unknown"
        receipts = SyslogEvidenceStore(root / "evidence", RECEIPT_ROLE)
        proposedReceipt = receipts.Put(receiptData, RECEIPT_ROLE, "application/json", provenance)

        if proposedReceipt != expectedReceipt or (
            receipts.Get(proposedReceipt.evidence_id) != expectedReceipt
            or receipts.Read(proposedReceipt.reference) != receiptData
        ):
            raise ValueError("Syslog receipt publication is unverified")

        receipt = proposedReceipt
        receiptAck = "confirmed"

    except KeyboardInterrupt:
        state = "interrupted"

    except (EvidenceError, OSError, ValueError):
        state = "storage-failed"

    if state not in {"succeeded", "parse-rejected"}:
        document = None

    return SyslogAcquisition(state, source, original.sha256, raw, receipt,
                              rawAck, receiptAck, document=document, readConsent=read)


def LoadSavedSyslog(workspaceRoot: Path, receiptId: str,
                     expectedSha256: str) -> SyslogAcquisition:
    """Verify an independent receipt and source pin before complete original-byte reparse.

    Args:
        workspaceRoot: Existing owning workspace, including a complete relocated or copied store.
        receiptId: Independently retained original receipt manifest ID, never a raw checksum.
        expectedSha256: Independently retained complete original-file SHA-256.

    Returns:
        Verified-present original source records without acquisition, clocks, Core or file writes.
        A correctly retained parser refusal remains refused and has no usable records.
    """

    RequireSyslogDigest(expectedSha256)

    if type(receiptId) is not str or not receiptId.startswith("sha256:"):
        raise ValueError("Syslog inspection requires an original receipt manifest")

    RequireSyslogDigest(receiptId[7:])
    root = OriginalSyslogPath(workspaceRoot, directory=True)
    owner = LocalWorkspaceStore(root).Open()
    receipts = SyslogEvidenceStore(root / "evidence", RECEIPT_ROLE)
    receipt = receipts.Get(receiptId)
    data = SyslogReceipt(receipts.Read(receipt.reference))
    source = SourceFromDict(data["source"])

    if source.expectedSha256 != expectedSha256:
        raise ValueError("Syslog receipt disagrees with the independent original pin")

    read = RequireManifestFields(data["read"], {"actor_reference", "consent_reference"})
    consent = ArtifactReadConsent(SyslogText(read["actor_reference"]),
                                  SyslogText(read["consent_reference"]))
    raw = ParseEvidenceManifest(SyslogJson(data["raw"]))

    if raw.evidence_id != data["raw_id"] or raw.provenance != receipt.provenance or (
        raw.provenance.workspace_id != owner.workspace_id
        or raw.reference.sha256 != expectedSha256
        or raw.provenance.source_id != source.sourceId
        or raw.provenance.source_version != source.sourceVersion
        or raw.provenance.tool_version != source.sourceToolVersion
        or raw.provenance.execution is not None or raw.provenance.invocation_sha256 is not None
    ):
        raise ValueError("Syslog original owner or provenance was substituted")

    SyslogText(raw.provenance.scope_reference)
    originals = SyslogEvidenceStore(root / "evidence", RAW_ROLE)

    if originals.Get(raw.evidence_id) != raw:
        raise ValueError("Syslog original acquisition manifest differs")

    document = None
    parseError = None
    state = "succeeded"

    try:
        document = ParseSavedSyslog(originals.Read(raw.reference), expectedSha256=expectedSha256,
                                    framing=source.framing)

    except SyslogDecodeError as error:
        state = "parse-rejected"
        parseError = {"code": error.code, "record_index": error.recordIndex,
                      "byte_offset": error.byteOffset}

    digest = hashlib.sha256(document).hexdigest() if document is not None else None

    if state != data["state"] or parseError != data["parse_error"] or digest != data[
        "document_sha256"
    ]:
        raise ValueError("Syslog original reparse differs from its original receipt")

    return SyslogAcquisition(state, source, expectedSha256, raw, receipt, "confirmed",
                              "confirmed", "verified-present", document, consent)
