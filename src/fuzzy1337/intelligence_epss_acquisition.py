# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental local EPSS custody and exact selected replay; no network or model writes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
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
    RejectManifestConstant,
    RequireManifestFields,
    UniqueManifestObject,
)
from fuzzy1337.intel_references import (
    CanonicalReferenceJson,
    ReferenceSource,
    RequireReferenceDigest,
    RequireReferenceText,
    RequireReferenceUrl,
    SourceOrigin,
)
from fuzzy1337.intelligence import IntelligenceDate, IntelligenceText
from fuzzy1337.intelligence_epss_selection import (
    MAX_COMPRESSED_BYTES,
    EpssSelectedRecord,
    EpssSelection,
    ParseEpssSelection,
    RequestedIds,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("EpssLocalSource", "EpssLocalRequest", "EpssAcquiredSelection", "EpssAcquisitionState",
           "EpssAcknowledgement", "EpssAcquisitionOutcome", "AcquireLocalEpssSelection",
           "LoadAcquiredEpssSelection")

IMPORTER_ID = "epss-selection-acquisition"
IMPORTER_VERSION = "1"
ENVELOPE_ROLE = "epss-selected-snapshot"
RECEIPT_ROLE = "epss-selection-acquisition"
RAW_ROLE = "epss-gzip-source"
PARTIAL_ROLE = "epss-gzip-partial"
MAX_ENVELOPE_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 32 * 1024


class BoundedEpssEvidenceStore(LocalEvidenceStore):
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
            raise ValueError("EPSS artifact exceeds its role-specific byte profile")

        return super().Read(reference)


class EpssAcquisitionState(StrEnum):
    """Separate complete local custody from bounded import and publication failures."""

    SUCCEEDED = "succeeded"
    SIZE_EXCEEDED = "size-exceeded"
    DIGEST_MISMATCH = "digest-mismatch"
    PARSE_FAILED = "parse-failed"
    STORAGE_FAILED = "storage-failed"


class EpssAcknowledgement(StrEnum):
    """Report storage acknowledgement without inferring rollback or unobserved publication."""

    NOT_ATTEMPTED = "not-attempted"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EpssLocalSource:
    """Keep explicit caller attribution and source terms separate from acquisition facts."""

    origin: SourceOrigin
    publisher: str
    source_url: str
    license_name: str
    license_url: str
    terms_urls: tuple[str, ...]
    model_version: str
    score_date: str
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        """Require typed finite caller source facts without asserting license verification."""

        if not isinstance(self.origin, SourceOrigin):
            raise ValueError("EPSS source requires typed origin")

        RequireReferenceText(self.publisher, "publisher")
        RequireReferenceText(self.license_name, "license_name")
        RequireReferenceUrl(self.source_url)
        RequireReferenceUrl(self.license_url)
        IntelligenceText(self.model_version, "EPSS selected model version", 256)
        IntelligenceDate(self.score_date)

        if type(self.terms_urls) is not tuple or not 1 <= len(self.terms_urls) <= 4:
            raise ValueError("EPSS source requires one to four explicit immutable terms URLs")

        for url in self.terms_urls:
            RequireReferenceUrl(url)

        if self.terms_urls != tuple(sorted(set(self.terms_urls))):
            raise ValueError("EPSS terms URLs must be unique and canonical")

        if self.expected_sha256 is not None:
            RequireReferenceDigest(self.expected_sha256)

    def ToDict(self) -> dict[str, object]:
        """Return detached declared facts without authenticating the publisher or terms.

        Returns:
            Exact source declaration with explicit primary license and additional terms links.
        """

        return {"origin": self.origin.value, "publisher": self.publisher,
                "source_url": self.source_url, "license_name": self.license_name,
                "license_url": self.license_url, "terms_urls": list(self.terms_urls),
                "model_version": self.model_version, "score_date": self.score_date,
                "expected_sha256": self.expected_sha256}


@dataclass(frozen=True, slots=True)
class EpssLocalRequest:
    """Select explicit local bytes and finite canonical CVEs without remote admission."""

    source: EpssLocalSource
    payload: bytes
    requested_ids: tuple[str, ...]
    max_bytes: int = MAX_COMPRESSED_BYTES

    def __post_init__(self) -> None:
        """Reject mutable or implicit selections and caller budget increases."""

        if type(self.source) is not EpssLocalSource or not isinstance(self.payload, bytes):
            raise ValueError("EPSS local acquisition requires typed source and explicit bytes")

        if type(self.requested_ids) is not tuple or self.requested_ids != RequestedIds(
            self.requested_ids,
        ):
            raise ValueError("EPSS request requires canonical immutable requested IDs")

        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_COMPRESSED_BYTES:
            raise ValueError("EPSS compressed ceiling must be positive and at most four MiB")


@dataclass(frozen=True, slots=True)
class EpssAcquiredSelection:
    """Bind original local custody to selected decoder output under a separate envelope family."""

    source: EpssLocalSource
    raw: EvidenceRecord
    selection: EpssSelection

    def __post_init__(self) -> None:
        """Validate structural joins; original-byte proof belongs to the reopening boundary."""

        if type(self.source) is not EpssLocalSource or type(self.raw) is not EvidenceRecord or (
            type(self.selection) is not EpssSelection
        ):
            raise ValueError("EPSS envelope requires exact typed source, raw and selection")

        RequireRecord(self.raw, RAW_ROLE, "application/gzip")

        if (
            self.selection.raw_sha256 != self.raw.reference.sha256
            or self.selection.raw_size != self.raw.reference.size_bytes
            or self.selection.model_version != self.source.model_version
            or self.selection.score_date != self.source.score_date
            or self.source.expected_sha256 not in (None, self.raw.reference.sha256)
            or self.selection.effective_at > self.raw.provenance.finished_at
        ):
            raise ValueError("EPSS envelope disagrees with original source selection")

    def ToDict(self) -> dict[str, object]:
        """Return detached envelope identity without legacy snapshot or authentication claims.

        Returns:
            Separate schema-one envelope containing unchanged schema-two decoder content.
        """

        provenance = self.raw.provenance
        attributed = ReferenceSource(
            self.source.origin, self.source.publisher, self.source.source_url,
            self.raw.reference.sha256, self.source.license_name, self.source.license_url,
            provenance.finished_at, IMPORTER_ID, IMPORTER_VERSION,
        )

        return {"schema_version": 1, "profile_version": 1,
                "profile": "epss-local-selected-acquisition", "source": self.source.ToDict(),
                "attributed_source": attributed.ToDict(), "raw": self.raw.ToDict(),
                "raw_id": self.raw.evidence_id, "selection": self.selection.ToDict(),
                "selection_reference": self.selection.Reference()}

    def Reference(self) -> str:
        """Bind original manifest, terms and complete selected content into a distinct identity.

        Returns:
            Deterministic attributed reference that cannot impersonate a legacy snapshot.
        """

        return "epss-acquired-selection:" + hashlib.sha256(
            CanonicalReferenceJson(self.ToDict()),
        ).hexdigest()

    def Serialize(self) -> bytes:
        """Return bounded canonical envelope bytes including their separate content reference.

        Returns:
            JSON payload within the explicit selected-envelope ceiling.
        """

        payload = CanonicalReferenceJson({**self.ToDict(), "reference": self.Reference()})

        if len(payload) > MAX_ENVELOPE_BYTES:
            raise ValueError("EPSS envelope exceeds its byte profile")

        return payload


@dataclass(frozen=True, slots=True)
class EpssAcquisitionOutcome:
    """Report actual local custody acknowledgements, including uncertain storage failure."""

    state: EpssAcquisitionState
    source: EpssLocalSource
    requested_ids: tuple[str, ...]
    started_at: str
    finished_at: str
    received_bytes: int
    body_complete: bool
    max_bytes: int
    raw: EvidenceRecord | None = None
    envelope: EpssAcquiredSelection | None = None
    selection_record: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None
    raw_ack: EpssAcknowledgement = EpssAcknowledgement.NOT_ATTEMPTED
    selection_ack: EpssAcknowledgement = EpssAcknowledgement.NOT_ATTEMPTED
    receipt_ack: EpssAcknowledgement = EpssAcknowledgement.NOT_ATTEMPTED

    def __post_init__(self) -> None:
        """Keep returned execution facts immutable without granting replay authority."""

        EpssLocalRequest(self.source, b"", self.requested_ids, self.max_bytes)

        if not isinstance(self.state, EpssAcquisitionState) or any(
            not isinstance(value, EpssAcknowledgement)
            for value in (self.raw_ack, self.selection_ack, self.receipt_ack)
        ):
            raise ValueError("EPSS outcome requires typed state and acknowledgement facts")

        if type(self.body_complete) is not bool or type(self.received_bytes) is not int or not (
            0 <= self.received_bytes <= self.max_bytes
        ):
            raise ValueError("EPSS outcome requires typed bounded byte completeness facts")

        if NormalizeEvidenceTime(self.started_at) != self.started_at or (
            NormalizeEvidenceTime(self.finished_at) != self.finished_at
            or self.finished_at < self.started_at
        ):
            raise ValueError("EPSS outcome requires canonical observed acquisition chronology")

        for record in (self.raw, self.selection_record, self.receipt):
            if record is not None and type(record) is not EvidenceRecord:
                raise ValueError("EPSS outcome requires immutable typed evidence handles")

        if self.envelope is not None and type(self.envelope) is not EpssAcquiredSelection:
            raise ValueError("EPSS outcome requires a typed selected envelope")

    def ReceiptContent(self) -> dict[str, object]:
        """Describe terminal pre-receipt facts without circular self-publication assertions.

        Returns:
            Distinct bounded receipt body; receipt acknowledgement is outcome-only.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "epss-local-selected-acquisition", "state": self.state.value,
                "source": self.source.ToDict(), "requested_ids": list(self.requested_ids),
                "started_at": self.started_at, "finished_at": self.finished_at,
                "received_bytes": self.received_bytes, "body_complete": self.body_complete,
                "transport": "local-bytes", "http_status": None,
                "limits": {"max_compressed_bytes": self.max_bytes},
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
        raise ValueError("EPSS artifact has foreign role, media type or importer provenance")


def AcquireLocalEpssSelection(
    workspace_root: Path, request: EpssLocalRequest, *, scope_reference: str,
) -> EpssAcquisitionOutcome:
    """Publish explicit local gzip, attributed selection and terminal receipt in existing stores.

    Args:
        workspace_root: Explicit existing owning workspace.
        request: Typed local bytes, source facts, finite budget and selected IDs.
        scope_reference: Explicit collection attribution, never execution authority.

    Returns:
        Honest terminal state and independent acknowledgements; failed publication may leave
        immutable artifacts and is never reported as rollback or successful complete custody.
    """

    if type(request) is not EpssLocalRequest:
        raise ValueError("EPSS local acquisition requires a typed local request")

    RequireReferenceText(scope_reference, "scope_reference")
    owner = LocalWorkspaceStore(workspace_root).Open()
    store = LocalEvidenceStore(workspace_root / "evidence")
    started_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    payload = request.payload[:request.max_bytes]
    complete = len(request.payload) <= request.max_bytes
    finished_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    provenance = EvidenceProvenance(owner.workspace_id, scope_reference, IMPORTER_ID,
                                    IMPORTER_VERSION, None, started_at, finished_at)
    outcome = EpssAcquisitionOutcome(
        EpssAcquisitionState.SUCCEEDED if complete else EpssAcquisitionState.SIZE_EXCEEDED,
        request.source, request.requested_ids, started_at, finished_at, len(payload),
        complete, request.max_bytes,
    )

    try:
        outcome = replace(outcome, raw_ack=EpssAcknowledgement.UNKNOWN)
        raw = store.Put(payload, RAW_ROLE if complete else PARTIAL_ROLE,
                        "application/gzip", provenance)
        outcome = replace(outcome, raw=raw, raw_ack=EpssAcknowledgement.CONFIRMED)

        if complete:
            if request.source.expected_sha256 not in (None, raw.reference.sha256):
                outcome = replace(outcome, state=EpssAcquisitionState.DIGEST_MISMATCH)

            else:
                try:
                    selected = ParseEpssSelection(
                        payload, request.requested_ids, model_version=request.source.model_version,
                        score_date=request.source.score_date,
                    )
                    envelope = EpssAcquiredSelection(request.source, raw, selected)
                    serialized = envelope.Serialize()

                except ValueError:
                    outcome = replace(outcome, state=EpssAcquisitionState.PARSE_FAILED)

                else:
                    outcome = replace(outcome, selection_ack=EpssAcknowledgement.UNKNOWN)
                    record = store.Put(serialized, ENVELOPE_ROLE, "application/json", provenance)
                    outcome = replace(outcome, envelope=envelope, selection_record=record,
                                      selection_ack=EpssAcknowledgement.CONFIRMED)

        serialized_receipt = CanonicalReferenceJson(outcome.ReceiptContent())

        if len(serialized_receipt) > MAX_RECEIPT_BYTES:
            raise ValueError("EPSS receipt exceeds its byte profile")

        outcome = replace(outcome, receipt_ack=EpssAcknowledgement.UNKNOWN)
        receipt = store.Put(serialized_receipt, RECEIPT_ROLE, "application/json", provenance)

        return replace(outcome, receipt=receipt, receipt_ack=EpssAcknowledgement.CONFIRMED)

    except EvidenceError:
        return replace(outcome, state=EpssAcquisitionState.STORAGE_FAILED, envelope=None)


def JsonObject(payload: bytes, maximum: int) -> dict[str, object]:
    """Decode bounded strict JSON without duplicate keys, constants or permissive coercion.

    Args:
        payload: Original selected JSON content bytes.
        maximum: Profile-specific byte ceiling enforced before decoding.

    Returns:
        Detached object; malformed input fails without source-byte interpretation.
    """

    if not isinstance(payload, bytes) or len(payload) > maximum:
        raise ValueError("EPSS JSON exceeds its selected byte profile")

    value = json.loads(payload, object_pairs_hook=UniqueManifestObject,
                       parse_constant=RejectManifestConstant)

    if not isinstance(value, dict):
        raise ValueError("EPSS selected JSON requires an object")

    return value


def DecodeSource(value: object) -> EpssLocalSource:
    """Rebuild explicit source facts using the exact distinct source-declaration contract.

    Args:
        value: Untrusted decoded source declaration from an envelope or receipt.

    Returns:
        Validated typed declaration without fetching any source or license locator.
    """

    fields = RequireManifestFields(value, {"origin", "publisher", "source_url", "license_name",
        "license_url", "terms_urls", "model_version", "score_date", "expected_sha256"})
    terms = fields["terms_urls"]

    if type(terms) is not list:
        raise ValueError("EPSS source terms must be an explicit JSON array")

    return EpssLocalSource(
        SourceOrigin(cast(str, fields["origin"])), cast(str, fields["publisher"]),
        cast(str, fields["source_url"]), cast(str, fields["license_name"]),
        cast(str, fields["license_url"]), tuple(terms), cast(str, fields["model_version"]),
        cast(str, fields["score_date"]), cast(str | None, fields["expected_sha256"]),
    )


def DecodeSelection(value: object) -> EpssSelection:
    """Reconstruct strict decoder DTOs without trusting mutable or extra persisted fields.

    Args:
        value: Untrusted nested schema-two selected content.

    Returns:
        Structurally validated decoder output; raw-byte agreement is verified separately.
    """

    if not isinstance(value, dict):
        raise ValueError("EPSS decoder content must be an object")

    for key in ("requested_ids", "unmatched_ids", "records"):
        if type(value.get(key)) is not list:
            raise ValueError("EPSS decoder arrays must retain their explicit type")

    records = []

    for item in value["records"]:
        fields = RequireManifestFields(item, {"identifier", "probability", "percentile"})
        records.append(EpssSelectedRecord(cast(str, fields["identifier"]),
            cast(str, fields["probability"]), cast(str, fields["percentile"])))

    fields = {name: value.get(name) for name in (
        "model_version", "score_date", "effective_at", "original_metadata", "raw_sha256",
        "raw_size", "decoded_sha256", "decoded_size", "row_count",
    )}
    result = EpssSelection(
        tuple(value["requested_ids"]), tuple(records), tuple(value["unmatched_ids"]),
        **fields,  # type: ignore[arg-type]
    )

    if CanonicalReferenceJson(result.ToDict()) != CanonicalReferenceJson(value):
        raise ValueError("EPSS decoder content disagrees with its exact profile")

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
        raise ValueError("EPSS artifact exceeds its role-specific byte profile")

    return store.Read(record.reference)


def LoadAcquiredEpssSelection(
    workspace_root: Path, selection_id: str, receipt_id: str,
) -> EpssAcquiredSelection:
    """Reopen exact local custody roots and reparse complete original gzip before returning.

    Args:
        workspace_root: Explicit existing owning workspace, including relocated original stores.
        selection_id: Exact attributed selected-envelope manifest identifier.
        receipt_id: Exact successful terminal receipt from the same acquisition.

    Returns:
        Verified original-byte selection; inspection writes nothing and never authenticates
        the publisher, assigns target applicability or enters legacy snapshot dispatch.
    """

    owner = LocalWorkspaceStore(workspace_root).Open()
    store = BoundedEpssEvidenceStore(
        workspace_root / "evidence", ENVELOPE_ROLE, "application/json", MAX_ENVELOPE_BYTES,
    )
    receipts = BoundedEpssEvidenceStore(
        workspace_root / "evidence", RECEIPT_ROLE, "application/json", MAX_RECEIPT_BYTES,
    )
    selected_record = store.Get(selection_id)
    receipt = receipts.Get(receipt_id)
    RequireRecord(selected_record, ENVELOPE_ROLE, "application/json")
    RequireRecord(receipt, RECEIPT_ROLE, "application/json")

    if selected_record.provenance != receipt.provenance or (
        receipt.provenance.workspace_id != owner.workspace_id
    ):
        raise ValueError("EPSS selected custody requires identical owning acquisition provenance")

    document = JsonObject(
        ReadBounded(store, selected_record, MAX_ENVELOPE_BYTES), MAX_ENVELOPE_BYTES,
    )
    terminal = JsonObject(ReadBounded(receipts, receipt, MAX_RECEIPT_BYTES), MAX_RECEIPT_BYTES)
    source = DecodeSource(document.get("source"))
    selection = DecodeSelection(document.get("selection"))
    limits = RequireManifestFields(terminal.get("limits"), {"max_compressed_bytes"})
    request = EpssLocalRequest(source, b"", selection.requested_ids,
                               cast(int, limits["max_compressed_bytes"]))
    raw = ParseEvidenceManifest(CanonicalReferenceJson(document.get("raw")))
    envelope = EpssAcquiredSelection(source, raw, selection)

    if raw.provenance != selected_record.provenance or (
        raw.reference.size_bytes > request.max_bytes
    ):
        raise ValueError("EPSS original raw facts disagree with selected receipt constraints")

    expected = EpssAcquisitionOutcome(
        EpssAcquisitionState.SUCCEEDED, source, selection.requested_ids,
        receipt.provenance.started_at, receipt.provenance.finished_at,
        raw.reference.size_bytes, True, request.max_bytes, raw=raw, envelope=envelope,
        selection_record=selected_record, raw_ack=EpssAcknowledgement.CONFIRMED,
        selection_ack=EpssAcknowledgement.CONFIRMED,
    )

    if envelope.Serialize() != CanonicalReferenceJson(document) or (
        CanonicalReferenceJson(expected.ReceiptContent()) != CanonicalReferenceJson(terminal)
    ):
        raise ValueError("EPSS selected envelope or terminal receipt disagrees with exact custody")

    originals = BoundedEpssEvidenceStore(
        workspace_root / "evidence", RAW_ROLE, "application/gzip", request.max_bytes,
    )

    if originals.Get(raw.evidence_id) != raw:
        raise ValueError("EPSS original acquisition manifest is missing or foreign")

    reparsed = ParseEpssSelection(
        ReadBounded(originals, raw, request.max_bytes), selection.requested_ids,
        model_version=source.model_version, score_date=source.score_date,
    )

    if reparsed != selection:
        raise ValueError("EPSS selected content disagrees with original gzip bytes")

    return envelope
