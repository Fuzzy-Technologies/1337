# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental local CWE custody and exact selected replay; no network or model writes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
    ParseEvidenceManifest,
    RequireManifestFields,
)
from fuzzy1337.intel_references import (
    CanonicalReferenceJson,
    RequireReferenceDigest,
    RequireReferenceText,
)
from fuzzy1337.intelligence import BoundedJson, IntelligenceObject
from fuzzy1337.intelligence_cwe_notice import NOTICE_PROFILE, CweNoticeBundle
from fuzzy1337.intelligence_cwe_selection import (
    CweSelectedRecord,
    CweSelection,
    CweUnsupportedEntry,
    ParseCweSelection,
    RequestedIds,
)
from fuzzy1337.intelligence_cwe_zip import MAX_ZIP_BYTES
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("CweLocalSource", "CweLocalRequest", "CweAcquiredSelection", "CweAcquisitionState",
           "CweAcknowledgement", "CweAcquisitionOutcome", "AcquireLocalCweSelection",
           "LoadAcquiredCweSelection")

IMPORTER_ID = "cwe-local-selected-acquisition"
IMPORTER_VERSION = "1"
ENVELOPE_ROLE = "cwe-local-selected-envelope"
RECEIPT_ROLE = "cwe-local-selected-acquisition"
RAW_ROLE = "cwe-local-zip-source"
PARTIAL_ROLE = "cwe-local-zip-partial"
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024


class BoundedCweEvidenceStore(LocalEvidenceStore):
    """Enforce caller-expected role ceilings during owning Get's implicit content verification."""

    def __init__(self, root: Path, role: str, media_type: str, maximum: int) -> None:
        """Configure one internal exact artifact domain before any selected manifest is decoded.

        Args:
            root: Existing owning evidence directory.
            role: Profile-controlled expected role, never copied from an untrusted manifest.
            media_type: Expected original or normalized artifact media type.
            maximum: Profile-controlled role-specific byte ceiling.
        """

        super().__init__(root)
        self.expected_role = role
        self.expected_media_type = media_type
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Bound every owning read, including implicit original manifest verification.

        Args:
            reference: Untrusted artifact reference decoded by the existing owning store.

        Returns:
            Exact hash-verified content only for bounded artifacts in this acquisition family.
        """

        if (
            reference.role != self.expected_role or reference.media_type != self.expected_media_type
            or reference.size_bytes > self.maximum
        ):
            raise ValueError("CWE artifact exceeds its role-specific byte profile")

        return super().Read(reference)


class CweAcquisitionState(StrEnum):
    """Separate complete local custody from bounded import and publication failures."""

    SUCCEEDED = "succeeded"
    SIZE_EXCEEDED = "size-exceeded"
    DIGEST_MISMATCH = "digest-mismatch"
    PARSE_FAILED = "parse-failed"
    STORAGE_FAILED = "storage-failed"


class CweAcknowledgement(StrEnum):
    """Report storage acknowledgement without inferring rollback or unobserved publication."""

    NOT_ATTEMPTED = "not-attempted"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CweLocalSource:
    """Declare one finite release, mandatory original-byte pin and captured notice bundle."""

    catalog_version: str
    expected_sha256: str
    notice_profile: str = NOTICE_PROFILE

    def __post_init__(self) -> None:
        """Refuse unknown releases and notices before byte reads or publication."""

        if type(self.catalog_version) is not str or self.catalog_version not in ("5.0", "4.21"):
            raise ValueError("CWE source requires an exact supported catalog")

        if type(self.expected_sha256) is not str:
            raise ValueError("CWE source requires an exact digest string")

        RequireReferenceDigest(self.expected_sha256)

        if type(self.notice_profile) is not str or self.notice_profile != NOTICE_PROFILE:
            raise ValueError("CWE source requires the reviewed captured notice bundle")

    def ToDict(self) -> dict[str, object]:
        """Return exact source declaration and full notices without legal or authenticity claims.

        Returns:
            Complete versioned declaration bound into every custody identity.
        """

        return {"catalog_version": self.catalog_version,
                "expected_sha256": self.expected_sha256,
                "source_url": "https://cwe.mitre.org/data/xml/cwec_v" + self.catalog_version
                              + ".xml.zip",
                "publisher": "The MITRE Corporation", "notice_profile": self.notice_profile,
                "notice_bundle": CweNoticeBundle(), "legal_rights": "not-assessed",
                "publisher_authentication": "not-assessed", "notice_applicability": "not-assessed"}


@dataclass(frozen=True, slots=True)
class CweLocalRequest:
    """Select explicit local bytes and finite canonical CWE IDs without remote admission."""

    source: CweLocalSource
    payload: bytes
    requested_ids: tuple[str, ...]
    max_bytes: int = MAX_ZIP_BYTES

    def __post_init__(self) -> None:
        """Reject mutable or implicit selections and caller budget increases."""

        if type(self.source) is not CweLocalSource or type(self.payload) is not bytes:
            raise ValueError("CWE local acquisition requires typed source and explicit bytes")

        if type(self.requested_ids) is not tuple or self.requested_ids != RequestedIds(
            self.requested_ids,
        ):
            raise ValueError("CWE request requires canonical immutable requested IDs")

        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_ZIP_BYTES:
            raise ValueError("CWE compressed ceiling must be positive and at most four MiB")


@dataclass(frozen=True, slots=True)
class CweAcquiredSelection:
    """Bind original local custody to selected decoder output under a separate envelope family."""

    source: CweLocalSource
    raw: EvidenceRecord
    selection: CweSelection
    max_bytes: int

    def __post_init__(self) -> None:
        """Validate structural joins; original-byte proof belongs to the reopening boundary."""

        if type(self.source) is not CweLocalSource or type(self.raw) is not EvidenceRecord or (
            type(self.selection) is not CweSelection
        ):
            raise ValueError("CWE envelope requires exact typed source, raw and selection")

        RequireRecord(self.raw, RAW_ROLE, "application/zip")

        if (
            self.selection.raw_sha256 != self.raw.reference.sha256
            or self.selection.raw_size != self.raw.reference.size_bytes
            or self.selection.catalog_version != self.source.catalog_version
            or self.source.expected_sha256 != self.raw.reference.sha256
            or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_ZIP_BYTES
            or self.raw.reference.size_bytes > self.max_bytes
        ):
            raise ValueError("CWE envelope disagrees with original source selection")

    def ToDict(self) -> dict[str, object]:
        """Return detached envelope identity without legacy snapshot or authentication claims.

        Returns:
            Separate schema-one envelope containing unchanged schema-one decoder content.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "cwe-local-selected-acquisition", "source": self.source.ToDict(),
                "limits": {"max_zip_bytes": self.max_bytes}, "raw": self.raw.ToDict(),
                "raw_id": self.raw.evidence_id, "selection": self.selection.ToDict(),
                "selection_reference": self.selection.Reference()}

    def Reference(self) -> str:
        """Bind original manifest, terms and complete selected content into a distinct identity.

        Returns:
            Deterministic attributed reference that cannot impersonate a legacy snapshot.
        """

        return "cwe-local-selection:" + hashlib.sha256(
            BoundedEncode(self.ToDict(), MAX_ENVELOPE_BYTES),
        ).hexdigest()

    def Serialize(self) -> bytes:
        """Return bounded canonical envelope bytes including their separate content reference.

        Returns:
            JSON payload within the explicit selected-envelope ceiling.
        """

        payload = BoundedEncode(
            {**self.ToDict(), "reference": self.Reference()}, MAX_ENVELOPE_BYTES,
        )

        return payload


@dataclass(frozen=True, slots=True)
class CweAcquisitionOutcome:
    """Report actual local custody acknowledgements, including uncertain storage failure."""

    state: CweAcquisitionState
    source: CweLocalSource
    requested_ids: tuple[str, ...]
    started_at: str
    finished_at: str
    received_bytes: int
    body_complete: bool
    max_bytes: int
    raw: EvidenceRecord | None = None
    envelope: CweAcquiredSelection | None = None
    selection_record: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None
    raw_ack: CweAcknowledgement = CweAcknowledgement.NOT_ATTEMPTED
    selection_ack: CweAcknowledgement = CweAcknowledgement.NOT_ATTEMPTED
    receipt_ack: CweAcknowledgement = CweAcknowledgement.NOT_ATTEMPTED

    def __post_init__(self) -> None:
        """Keep returned execution facts immutable without granting replay authority."""

        CweLocalRequest(self.source, b"", self.requested_ids, self.max_bytes)

        if not isinstance(self.state, CweAcquisitionState) or any(
            not isinstance(value, CweAcknowledgement)
            for value in (self.raw_ack, self.selection_ack, self.receipt_ack)
        ):
            raise ValueError("CWE outcome requires typed state and acknowledgement facts")

        if type(self.body_complete) is not bool or type(self.received_bytes) is not int or not (
            0 <= self.received_bytes <= self.max_bytes
        ):
            raise ValueError("CWE outcome requires typed bounded byte completeness facts")

        if NormalizeEvidenceTime(self.started_at) != self.started_at or (
            NormalizeEvidenceTime(self.finished_at) != self.finished_at
            or self.finished_at < self.started_at
        ):
            raise ValueError("CWE outcome requires canonical observed acquisition chronology")

        for record in (self.raw, self.selection_record, self.receipt):
            if record is not None and type(record) is not EvidenceRecord:
                raise ValueError("CWE outcome requires immutable typed evidence handles")

        if self.envelope is not None and type(self.envelope) is not CweAcquiredSelection:
            raise ValueError("CWE outcome requires a typed selected envelope")

    def ReceiptContent(self) -> dict[str, object]:
        """Describe terminal pre-receipt facts without circular self-publication assertions.

        Returns:
            Distinct bounded receipt body; receipt acknowledgement is outcome-only.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "cwe-local-selected-acquisition", "state": self.state.value,
                "source": self.source.ToDict(), "requested_ids": list(self.requested_ids),
                "started_at": self.started_at, "finished_at": self.finished_at,
                "received_bytes": self.received_bytes, "body_complete": self.body_complete,
                "transport": "local-bytes", "http_status": None,
                "limits": {"max_zip_bytes": self.max_bytes},
                "raw": self.raw.ToDict() if self.raw is not None else None,
                "selection_record": (self.selection_record.ToDict()
                                     if self.selection_record is not None else None),
                "selection_reference": (self.envelope.Reference()
                                        if self.envelope is not None else None),
                "raw_ack": self.raw_ack.value, "selection_ack": self.selection_ack.value,
                "publisher_authentication": "not-assessed"}


def RequireRecord(record: EvidenceRecord, role: str, media_type: str) -> None:
    """Require this profile's artifact attribution before content reads or interpretation.

    Args:
        record: Exact selected immutable evidence manifest.
        role: Required artifact role in this distinct acquisition family.
        media_type: Required original or normalized content type.
    """

    if (
        record.reference.role != role or record.reference.media_type != media_type
        or record.provenance.source_id != IMPORTER_ID
        or record.provenance.source_version != IMPORTER_VERSION
        or record.provenance.tool_version is not None
        or record.provenance.invocation_sha256 is not None
        or record.provenance.execution is not None
    ):
        raise ValueError("CWE artifact has foreign role, media type or importer provenance")


def AcquireLocalCweSelection(
    workspace_root: Path, request: CweLocalRequest, *, scope_reference: str,
) -> CweAcquisitionOutcome:
    """Publish explicit local ZIP, attributed selection and terminal receipt in existing stores.

    Args:
        workspace_root: Explicit existing owning workspace.
        request: Typed local bytes, source facts, finite budget and selected IDs.
        scope_reference: Explicit collection attribution, never execution authority.

    Returns:
        Honest terminal state and independent acknowledgements; failed publication may leave
        immutable artifacts and is never reported as rollback or successful complete custody.
    """

    if type(request) is not CweLocalRequest:
        raise ValueError("CWE local acquisition requires a typed local request")

    RequireReferenceText(scope_reference, "scope_reference")
    owner = LocalWorkspaceStore(workspace_root).Open()
    store = LocalEvidenceStore(workspace_root / "evidence")
    startedAt = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    payload = request.payload[:request.max_bytes]
    complete = len(request.payload) <= request.max_bytes
    finishedAt = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    provenance = EvidenceProvenance(owner.workspace_id, scope_reference, IMPORTER_ID,
                                    IMPORTER_VERSION, None, startedAt, finishedAt)
    outcome = CweAcquisitionOutcome(
        CweAcquisitionState.SUCCEEDED if complete else CweAcquisitionState.SIZE_EXCEEDED,
        request.source, request.requested_ids, startedAt, finishedAt, len(payload),
        complete, request.max_bytes,
    )

    try:
        outcome = replace(outcome, raw_ack=CweAcknowledgement.UNKNOWN)
        raw = store.Put(payload, RAW_ROLE if complete else PARTIAL_ROLE,
                        "application/zip", provenance)
        outcome = replace(outcome, raw=raw, raw_ack=CweAcknowledgement.CONFIRMED)

        if complete:
            if request.source.expected_sha256 != raw.reference.sha256:
                outcome = replace(outcome, state=CweAcquisitionState.DIGEST_MISMATCH)

            else:
                try:
                    selected = ParseCweSelection(
                        payload, request.requested_ids,
                        catalog_version=request.source.catalog_version,
                    )
                    envelope = CweAcquiredSelection(
                        request.source, raw, selected, request.max_bytes,
                    )

                except ValueError:
                    outcome = replace(outcome, state=CweAcquisitionState.PARSE_FAILED)

                else:
                    serialized = envelope.Serialize()
                    outcome = replace(outcome, selection_ack=CweAcknowledgement.UNKNOWN)
                    record = store.Put(serialized, ENVELOPE_ROLE, "application/json", provenance)
                    outcome = replace(outcome, envelope=envelope, selection_record=record,
                                      selection_ack=CweAcknowledgement.CONFIRMED)

        serializedReceipt = BoundedEncode(outcome.ReceiptContent(), MAX_RECEIPT_BYTES)

        outcome = replace(outcome, receipt_ack=CweAcknowledgement.UNKNOWN)
        receipt = store.Put(serializedReceipt, RECEIPT_ROLE, "application/json", provenance)

        return replace(outcome, receipt=receipt, receipt_ack=CweAcknowledgement.CONFIRMED)

    except (EvidenceError, ValueError):
        return replace(outcome, state=CweAcquisitionState.STORAGE_FAILED, envelope=None)



def BoundedEncode(value: object, maximum: int) -> bytes:
    """Encode canonical JSON incrementally within one explicit publication budget.

    Args:
        value: Profile-controlled finite content with existing bounded source and selection fields.
        maximum: Envelope or receipt domain byte ceiling.

    Returns:
        Exact canonical bytes; over-budget content raises before any publication attempt.
    """

    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                               allow_nan=False)
    result = bytearray()

    for part in encoder.iterencode(value):
        encoded = part.encode("utf-8")

        if len(result) + len(encoded) > maximum:
            raise ValueError("CWE publication exceeds its role-specific byte profile")

        result.extend(encoded)

    return bytes(result)


def JsonObject(payload: bytes, maximum: int) -> dict[str, object]:
    """Decode bounded strict JSON without duplicate keys, constants or permissive coercion.

    Args:
        payload: Original selected JSON content bytes.
        maximum: Profile-specific byte ceiling enforced before decoding.

    Returns:
        Detached object; malformed input fails without source-byte interpretation.
    """

    if not isinstance(payload, bytes) or len(payload) > maximum:
        raise ValueError("CWE JSON exceeds its selected byte profile")

    return IntelligenceObject(BoundedJson(payload))


def DecodeSource(value: object) -> CweLocalSource:
    """Rebuild explicit source facts using the exact distinct source-declaration contract.

    Args:
        value: Untrusted decoded source declaration from an envelope or receipt.

    Returns:
        Validated typed declaration without fetching any source or license locator.
    """

    if type(value) is not dict:
        raise ValueError("CWE source requires an exact declaration object")

    source = CweLocalSource(cast(str, value.get("catalog_version")),
                            cast(str, value.get("expected_sha256")),
                            cast(str, value.get("notice_profile")))

    if CanonicalReferenceJson(source.ToDict()) != CanonicalReferenceJson(value):
        raise ValueError("CWE source declaration or complete notice bundle was changed")

    return source



def DecodeSelection(value: object) -> CweSelection:
    """Reconstruct exact bounded immutable selected facts before original artifact reads.

    Args:
        value: Untrusted nested selection with explicit original partitions.

    Returns:
        Structurally admitted DTO; original-byte verification remains mandatory afterward.
    """

    if type(value) is not dict:
        raise ValueError("CWE selected content requires an exact object")

    for key in ("requested_ids", "unmatched_ids", "records", "unsupported_entries"):
        if type(value.get(key)) is not list or len(value[key]) > 64:
            raise ValueError("CWE selected arrays exceed their exact finite profile")

    records = []

    for item in value["records"]:
        part = RequireManifestFields(item, {"identifier", "name", "status", "source_kind"})

        if part["source_kind"] != "Weakness":
            raise ValueError("CWE record requires exact Weakness kind")

        records.append(CweSelectedRecord(cast(str, part["identifier"]),
            cast(str, part["name"]), cast(str, part["status"])))

    unsupported = []

    for item in value["unsupported_entries"]:
        part = RequireManifestFields(item, {"identifier", "source_kind"})
        unsupported.append(CweUnsupportedEntry(cast(str, part["identifier"]),
                                               cast(str, part["source_kind"])))

    values = {field.name: value.get(field.name) for field in fields(CweSelection)}
    values.update(requested_ids=tuple(value["requested_ids"]), records=tuple(records),
                  unsupported_entries=tuple(unsupported),
                  unmatched_ids=tuple(value["unmatched_ids"]))
    result = CweSelection(**values)  # type: ignore[arg-type]

    if CanonicalReferenceJson(result.ToDict()) != CanonicalReferenceJson(value):
        raise ValueError("CWE selected content disagrees with its exact profile")

    return result


def ReadBounded(store: LocalEvidenceStore, record: EvidenceRecord, maximum: int) -> bytes:
    """Enforce role-specific byte limits before the owning evidence reader loads bytes.

    Args:
        store: Existing workspace-owned evidence store.
        record: Explicit selected immutable artifact manifest.
        maximum: Validated profile ceiling for its artifact role.

    Returns:
        Exact hash-verified original content within the selected role budget.
    """

    if record.reference.size_bytes > maximum:
        raise ValueError("CWE artifact exceeds its role-specific byte profile")

    return store.Read(record.reference)


def LoadAcquiredCweSelection(
    workspace_root: Path, selection_id: str, receipt_id: str,
) -> CweAcquiredSelection:
    """Reopen exact local custody roots and reparse complete original ZIP before returning.

    Args:
        workspace_root: Explicit existing owning workspace, including relocated original stores.
        selection_id: Exact attributed selected-envelope manifest identifier.
        receipt_id: Exact successful terminal receipt from the same acquisition.

    Returns:
        Verified original-byte selection; inspection writes nothing and never authenticates
        the publisher, assigns target applicability or enters legacy snapshot dispatch.
    """

    owner = LocalWorkspaceStore(workspace_root).Open()
    store = BoundedCweEvidenceStore(
        workspace_root / "evidence", ENVELOPE_ROLE, "application/json", MAX_ENVELOPE_BYTES,
    )
    receipts = BoundedCweEvidenceStore(
        workspace_root / "evidence", RECEIPT_ROLE, "application/json", MAX_RECEIPT_BYTES,
    )
    selectedRecord = store.Get(selection_id)
    receipt = receipts.Get(receipt_id)
    RequireRecord(selectedRecord, ENVELOPE_ROLE, "application/json")
    RequireRecord(receipt, RECEIPT_ROLE, "application/json")

    if selectedRecord.provenance != receipt.provenance or (
        receipt.provenance.workspace_id != owner.workspace_id
    ):
        raise ValueError("CWE selected custody requires identical owning acquisition provenance")

    document = JsonObject(
        ReadBounded(store, selectedRecord, MAX_ENVELOPE_BYTES), MAX_ENVELOPE_BYTES,
    )
    terminal = JsonObject(ReadBounded(receipts, receipt, MAX_RECEIPT_BYTES), MAX_RECEIPT_BYTES)
    source = DecodeSource(document.get("source"))
    limits = RequireManifestFields(document.get("limits"), {"max_zip_bytes"})
    selection = DecodeSelection(document.get("selection"))
    requestedIds = selection.requested_ids
    request = CweLocalRequest(source, b"", requestedIds,
                               cast(int, limits["max_zip_bytes"]))
    raw = ParseEvidenceManifest(CanonicalReferenceJson(document.get("raw")))

    if raw.provenance != selectedRecord.provenance or (
        raw.reference.size_bytes > request.max_bytes
    ):
        raise ValueError("CWE original raw facts disagree with selected receipt constraints")

    envelope = CweAcquiredSelection(source, raw, selection, request.max_bytes)
    expected = CweAcquisitionOutcome(
        CweAcquisitionState.SUCCEEDED, source, requestedIds,
        receipt.provenance.started_at, receipt.provenance.finished_at,
        raw.reference.size_bytes, True, request.max_bytes, raw=raw, envelope=envelope,
        selection_record=selectedRecord, raw_ack=CweAcknowledgement.CONFIRMED,
        selection_ack=CweAcknowledgement.CONFIRMED,
    )

    if envelope.Serialize() != CanonicalReferenceJson(document) or (
        CanonicalReferenceJson(expected.ReceiptContent()) != CanonicalReferenceJson(terminal)
    ):
        raise ValueError("CWE selected envelope or terminal receipt disagrees with exact custody")

    originals = BoundedCweEvidenceStore(
        workspace_root / "evidence", RAW_ROLE, "application/zip", request.max_bytes,
    )

    if originals.Get(raw.evidence_id) != raw:
        raise ValueError("CWE original acquisition manifest is missing or foreign")

    reparsed = ParseCweSelection(
        ReadBounded(originals, raw, request.max_bytes), requestedIds,
        catalog_version=source.catalog_version,
    )

    if reparsed != selection:
        raise ValueError("CWE selection disagrees with original ZIP")

    return envelope
