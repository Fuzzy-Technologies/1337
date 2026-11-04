# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental pinned CWE HTTPS custody and exact read-only original-source replay."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import cast

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
from fuzzy1337.intelligence_cwe_acquisition import (
    BoundedCweEvidenceStore,
    BoundedEncode,
    DecodeSelection,
    JsonObject,
    ReadBounded,
)
from fuzzy1337.intelligence_cwe_notice import NOTICE_PROFILE, CweNoticeBundle
from fuzzy1337.intelligence_cwe_selection import (
    CweSelection,
    ParseCweSelection,
    RequestedIds,
)
from fuzzy1337.intelligence_cwe_zip import MAX_ZIP_BYTES
from fuzzy1337.intelligence_receiver import ReceiveIsolatedHttps
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("CweHttpsSource", "CweHttpsRequest", "CweHttpsSelection", "CweHttpsState",
           "CweHttpsAcknowledgement", "CweHttpsOutcome", "AcquireHttpsCweSelection",
           "LoadHttpsCweSelection")

IMPORTER_ID = "cwe-https-selected-acquisition"
IMPORTER_VERSION = "1"
ENVELOPE_ROLE = "cwe-https-selected-envelope"
RECEIPT_ROLE = "cwe-https-selected-acquisition"
RAW_ROLE = "cwe-https-zip-source"
PARTIAL_ROLE = "cwe-https-zip-partial"
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_NOTICE_BYTES = 16 * 1024
MAX_SOURCE_BYTES = 32 * 1024
TRANSPORT_PROFILE = "cwe-https-zip-identity-v1"
RECEIVE_STATES = frozenset({"succeeded", "redirect-rejected", "http-rejected", "format-rejected",
                            "size-exceeded", "transport-failed", "timed-out"})


class CweHttpsState(StrEnum):
    """Separate complete HTTPS custody from transport, decoding and publication failures."""

    SUCCEEDED = "succeeded"
    REDIRECT_REJECTED = "redirect-rejected"
    HTTP_REJECTED = "http-rejected"
    FORMAT_REJECTED = "format-rejected"
    TRANSPORT_FAILED = "transport-failed"
    TIMED_OUT = "timed-out"
    SIZE_EXCEEDED = "size-exceeded"
    DIGEST_MISMATCH = "digest-mismatch"
    PARSE_FAILED = "parse-failed"
    STORAGE_FAILED = "storage-failed"


class CweHttpsAcknowledgement(StrEnum):
    """Report storage acknowledgement without inferring rollback or unobserved publication."""

    NOT_ATTEMPTED = "not-attempted"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CweHttpsSource:
    """Declare one finite release, mandatory original-byte pin and captured notice bundle."""

    catalog_version: str
    expected_sha256: str
    notice_profile: str = NOTICE_PROFILE

    def __post_init__(self) -> None:
        """Refuse unknown releases, notices and declared subdocument bounds before resource work."""

        if type(self.catalog_version) is not str or self.catalog_version not in ("5.0", "4.21"):
            raise ValueError("CWE source requires an exact supported catalog")

        if type(self.expected_sha256) is not str:
            raise ValueError("CWE source requires an exact digest string")

        RequireReferenceDigest(self.expected_sha256)

        if type(self.notice_profile) is not str or self.notice_profile != NOTICE_PROFILE:
            raise ValueError("CWE source requires the reviewed captured notice bundle")

        BoundedEncode(CweNoticeBundle(), MAX_NOTICE_BYTES)
        BoundedEncode(self.ToDict(), MAX_SOURCE_BYTES)

    @property
    def SourceUrl(self) -> str:
        """Derive the sole fixed version locator without caller URL or query admission.

        Returns:
            Exact query-free HTTPS source URL for the finite selected catalog.
        """

        return "https://cwe.mitre.org/data/xml/cwec_v" + self.catalog_version + ".xml.zip"

    def ToDict(self) -> dict[str, object]:
        """Return exact source declaration and full notices without legal or authenticity claims.

        Returns:
            Complete versioned declaration bound into every custody identity.
        """

        return {"catalog_version": self.catalog_version,
                "expected_sha256": self.expected_sha256,
                "source_url": self.SourceUrl,
                "publisher": "The MITRE Corporation", "notice_profile": self.notice_profile,
                "notice_bundle": CweNoticeBundle(), "legal_rights": "not-assessed",
                "publisher_authentication": "not-assessed", "notice_applicability": "not-assessed"}


@dataclass(frozen=True, slots=True)
class CweHttpsRequest:
    """Select finite canonical CWE IDs and limits without caller URL or supplied byte admission."""

    source: CweHttpsSource
    requested_ids: tuple[str, ...]
    max_bytes: int = MAX_ZIP_BYTES
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        """Reject mutable or implicit selections and caller budget increases."""

        if type(self.source) is not CweHttpsSource:
            raise ValueError("CWE HTTPS acquisition requires an exact typed source")

        if type(self.requested_ids) is not tuple or self.requested_ids != RequestedIds(
            self.requested_ids,
        ):
            raise ValueError("CWE request requires canonical immutable requested IDs")

        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_ZIP_BYTES:
            raise ValueError("CWE compressed ceiling must be positive and at most four MiB")

        if type(self.timeout_seconds) not in (int, float) or not (
            0.05 <= self.timeout_seconds <= 60
        ) or not math.isfinite(self.timeout_seconds):
            raise ValueError("CWE HTTPS timeout must be finite and within 0.05..60 seconds")

        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))


@dataclass(frozen=True, slots=True)
class CweHttpsSelection:
    """Bind original HTTPS custody to selected decoder output under a separate envelope family."""

    source: CweHttpsSource
    raw: EvidenceRecord
    selection: CweSelection
    max_bytes: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        """Validate structural joins; original-byte proof belongs to the reopening boundary."""

        if type(self.source) is not CweHttpsSource or type(self.raw) is not EvidenceRecord or (
            type(self.selection) is not CweSelection
        ):
            raise ValueError("CWE envelope requires exact typed source, raw and selection")

        request = CweHttpsRequest(self.source, self.selection.requested_ids, self.max_bytes,
                                  self.timeout_seconds)
        object.__setattr__(self, "timeout_seconds", request.timeout_seconds)
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
                "profile": "cwe-https-selected-acquisition", "source": self.source.ToDict(),
                "limits": {"max_zip_bytes": self.max_bytes,
                           "timeout_seconds": self.timeout_seconds},
                "transport": "https", "transport_profile": TRANSPORT_PROFILE,
                "receive_state": "succeeded", "http_status": 200, "body_complete": True,
                "received_bytes": self.raw.reference.size_bytes, "raw": self.raw.ToDict(),
                "raw_id": self.raw.evidence_id, "selection": self.selection.ToDict(),
                "selection_reference": self.selection.Reference()}

    def Reference(self) -> str:
        """Bind original manifest, terms and complete selected content into a distinct identity.

        Returns:
            Deterministic attributed reference that cannot impersonate a legacy snapshot.
        """

        return "cwe-https-selection:" + hashlib.sha256(
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
class CweHttpsOutcome:
    """Report actual HTTPS custody acknowledgements, including uncertain storage failure."""

    state: CweHttpsState
    source: CweHttpsSource
    requested_ids: tuple[str, ...]
    started_at: str
    finished_at: str
    received_bytes: int
    body_complete: bool
    max_bytes: int
    timeout_seconds: float
    receive_state: str
    http_status: int | None
    raw: EvidenceRecord | None = None
    envelope: CweHttpsSelection | None = None
    selection_record: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None
    raw_ack: CweHttpsAcknowledgement = CweHttpsAcknowledgement.NOT_ATTEMPTED
    selection_ack: CweHttpsAcknowledgement = CweHttpsAcknowledgement.NOT_ATTEMPTED
    receipt_ack: CweHttpsAcknowledgement = CweHttpsAcknowledgement.NOT_ATTEMPTED

    def __post_init__(self) -> None:
        """Keep returned execution facts immutable without granting replay authority."""

        request = CweHttpsRequest(self.source, self.requested_ids, self.max_bytes,
                                  self.timeout_seconds)
        object.__setattr__(self, "timeout_seconds", request.timeout_seconds)

        if not isinstance(self.state, CweHttpsState) or any(
            not isinstance(value, CweHttpsAcknowledgement)
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

        if type(self.receive_state) is not str or self.receive_state not in RECEIVE_STATES:
            raise ValueError("CWE outcome requires an observed receiver state")

        if self.http_status is not None and (
            type(self.http_status) is not int or not 100 <= self.http_status <= 599
        ):
            raise ValueError("CWE outcome requires a typed HTTP status or unknown status")

        if self.body_complete != (self.receive_state == "succeeded") or (
            self.body_complete and self.http_status != 200
        ):
            raise ValueError("CWE outcome completeness disagrees with observed HTTPS facts")

        for record in (self.raw, self.selection_record, self.receipt):
            if record is not None and type(record) is not EvidenceRecord:
                raise ValueError("CWE outcome requires immutable typed evidence handles")

        if self.envelope is not None and type(self.envelope) is not CweHttpsSelection:
            raise ValueError("CWE outcome requires a typed selected envelope")

    def ReceiptContent(self) -> dict[str, object]:
        """Describe terminal pre-receipt facts without circular self-publication assertions.

        Returns:
            Distinct bounded receipt body; receipt acknowledgement is outcome-only.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "cwe-https-selected-acquisition", "state": self.state.value,
                "source": self.source.ToDict(), "requested_ids": list(self.requested_ids),
                "started_at": self.started_at, "finished_at": self.finished_at,
                "received_bytes": self.received_bytes, "body_complete": self.body_complete,
                "transport": "https", "transport_profile": TRANSPORT_PROFILE,
                "receive_state": self.receive_state, "http_status": self.http_status,
                "limits": {"max_zip_bytes": self.max_bytes,
                           "timeout_seconds": self.timeout_seconds},
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


def AcquireHttpsCweSelection(
    workspace_root: Path, request: CweHttpsRequest, *, scope_reference: str,
) -> CweHttpsOutcome:
    """Publish one fixed HTTPS ZIP, attributed selection and terminal receipt in existing stores.

    Args:
        workspace_root: Explicit existing owning workspace.
        request: Typed HTTPS source, source facts, finite budget and selected IDs.
        scope_reference: Explicit collection attribution, never execution authority.

    Returns:
        Honest terminal state and independent acknowledgements; failed publication may leave
        immutable artifacts and is never reported as rollback or successful complete custody.
    """

    if type(request) is not CweHttpsRequest:
        raise ValueError("CWE HTTPS acquisition requires a typed HTTPS request")

    RequireReferenceText(scope_reference, "scope_reference")
    owner = LocalWorkspaceStore(workspace_root).Open()
    store = LocalEvidenceStore(workspace_root / "evidence")
    started_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    payload, receive_state, http_status = ReceiveIsolatedHttps(
        request.source.SourceUrl, request.max_bytes, request.timeout_seconds, accept_kind="zip",
    )

    if type(payload) is not bytes or len(payload) > request.max_bytes or (
        type(receive_state) is not str or receive_state not in RECEIVE_STATES
    ):
        raise ValueError("CWE isolated receiver returned invalid bounded facts")

    complete = receive_state == "succeeded"
    finished_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    provenance = EvidenceProvenance(owner.workspace_id, scope_reference, IMPORTER_ID,
                                    IMPORTER_VERSION, None, started_at, finished_at)
    outcome = CweHttpsOutcome(
        CweHttpsState(receive_state),
        request.source, request.requested_ids, started_at, finished_at, len(payload),
        complete, request.max_bytes, request.timeout_seconds, receive_state, http_status,
    )

    try:
        outcome = replace(outcome, raw_ack=CweHttpsAcknowledgement.UNKNOWN)
        raw = store.Put(payload, RAW_ROLE if complete else PARTIAL_ROLE,
                        "application/zip", provenance)
        outcome = replace(outcome, raw=raw, raw_ack=CweHttpsAcknowledgement.CONFIRMED)

        if complete:
            if request.source.expected_sha256 != raw.reference.sha256:
                outcome = replace(outcome, state=CweHttpsState.DIGEST_MISMATCH)

            else:
                try:
                    selected = ParseCweSelection(
                        payload, request.requested_ids,
                        catalog_version=request.source.catalog_version,
                    )
                    envelope = CweHttpsSelection(
                        request.source, raw, selected, request.max_bytes, request.timeout_seconds,
                    )

                except ValueError:
                    outcome = replace(outcome, state=CweHttpsState.PARSE_FAILED)

                else:
                    serialized = envelope.Serialize()
                    outcome = replace(outcome, selection_ack=CweHttpsAcknowledgement.UNKNOWN)
                    record = store.Put(serialized, ENVELOPE_ROLE, "application/json", provenance)
                    outcome = replace(outcome, envelope=envelope, selection_record=record,
                                      selection_ack=CweHttpsAcknowledgement.CONFIRMED)

        serialized_receipt = BoundedEncode(outcome.ReceiptContent(), MAX_RECEIPT_BYTES)

        outcome = replace(outcome, receipt_ack=CweHttpsAcknowledgement.UNKNOWN)
        receipt = store.Put(serialized_receipt, RECEIPT_ROLE, "application/json", provenance)

        return replace(outcome, receipt=receipt, receipt_ack=CweHttpsAcknowledgement.CONFIRMED)

    except (EvidenceError, ValueError):
        return replace(outcome, state=CweHttpsState.STORAGE_FAILED, envelope=None)


def DecodeSource(value: object) -> CweHttpsSource:
    """Rebuild explicit source facts using the exact distinct source-declaration contract.

    Args:
        value: Untrusted decoded source declaration from an envelope or receipt.

    Returns:
        Validated typed declaration without fetching any source or license locator.
    """

    if type(value) is not dict:
        raise ValueError("CWE source requires an exact declaration object")

    BoundedEncode(value, MAX_SOURCE_BYTES)
    BoundedEncode(value.get("notice_bundle"), MAX_NOTICE_BYTES)
    source = CweHttpsSource(cast(str, value.get("catalog_version")),
                            cast(str, value.get("expected_sha256")),
                            cast(str, value.get("notice_profile")))

    if CanonicalReferenceJson(source.ToDict()) != CanonicalReferenceJson(value):
        raise ValueError("CWE source declaration or complete notice bundle was changed")

    return source


def LoadHttpsCweSelection(
    workspace_root: Path, selection_id: str, receipt_id: str,
) -> CweHttpsSelection:
    """Reopen exact HTTPS custody roots and reparse complete original ZIP before returning.

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
    selected_record = store.Get(selection_id)
    receipt = receipts.Get(receipt_id)
    RequireRecord(selected_record, ENVELOPE_ROLE, "application/json")
    RequireRecord(receipt, RECEIPT_ROLE, "application/json")

    if selected_record.provenance != receipt.provenance or (
        receipt.provenance.workspace_id != owner.workspace_id
    ):
        raise ValueError("CWE selected custody requires identical owning acquisition provenance")

    document = JsonObject(
        ReadBounded(store, selected_record, MAX_ENVELOPE_BYTES), MAX_ENVELOPE_BYTES,
    )
    terminal = JsonObject(ReadBounded(receipts, receipt, MAX_RECEIPT_BYTES), MAX_RECEIPT_BYTES)
    source = DecodeSource(document.get("source"))
    limits = RequireManifestFields(document.get("limits"),
                                   {"max_zip_bytes", "timeout_seconds"})
    selection = DecodeSelection(document.get("selection"))
    requested_ids = selection.requested_ids
    request = CweHttpsRequest(source, requested_ids, cast(int, limits["max_zip_bytes"]),
                             cast(float, limits["timeout_seconds"]))
    raw = ParseEvidenceManifest(CanonicalReferenceJson(document.get("raw")))

    if raw.provenance != selected_record.provenance or (
        raw.reference.size_bytes > request.max_bytes
    ):
        raise ValueError("CWE original raw facts disagree with selected receipt constraints")

    envelope = CweHttpsSelection(source, raw, selection, request.max_bytes,
                                request.timeout_seconds)
    expected = CweHttpsOutcome(
        CweHttpsState.SUCCEEDED, source, requested_ids,
        receipt.provenance.started_at, receipt.provenance.finished_at,
        raw.reference.size_bytes, True, request.max_bytes, request.timeout_seconds,
        "succeeded", 200, raw=raw, envelope=envelope,
        selection_record=selected_record, raw_ack=CweHttpsAcknowledgement.CONFIRMED,
        selection_ack=CweHttpsAcknowledgement.CONFIRMED,
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
        ReadBounded(originals, raw, request.max_bytes), requested_ids,
        catalog_version=source.catalog_version,
    )

    if reparsed != selection:
        raise ValueError("CWE selection disagrees with original ZIP")

    return envelope
