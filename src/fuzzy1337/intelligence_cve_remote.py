# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental pinned selected CVE HTTPS custody and offline replay; no model writes."""

from __future__ import annotations

import hashlib
import math
import re
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
    RequireManifestFields,
)
from fuzzy1337.intel_references import (
    CanonicalReferenceJson,
    ReferenceSource,
    RequireReferenceDigest,
    RequireReferenceText,
    SourceOrigin,
)
from fuzzy1337.intelligence import (
    BoundedJson,
    IntelligenceFeed,
    IntelligenceIdentifier,
    IntelligenceObject,
    IntelligenceSnapshot,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.intelligence_receiver import ReceiveIsolatedHttps
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("CveHttpsSource", "CveHttpsRequest", "CveHttpsSelection", "CveHttpsState",
           "CveHttpsAcknowledgement", "CveHttpsOutcome", "AcquireHttpsCveSelection",
           "LoadHttpsCveSelection")

IMPORTER_ID = "cve-https-selected-acquisition"
IMPORTER_VERSION = "1"
ENVELOPE_ROLE = "cve-https-selected-snapshot"
RECEIPT_ROLE = "cve-https-selected-acquisition"
RAW_ROLE = "cve-https-json-source"
PARTIAL_ROLE = "cve-https-json-partial"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
RECEIVE_STATES = frozenset({"succeeded", "redirect-rejected", "http-rejected", "format-rejected",
                            "size-exceeded", "transport-failed", "timed-out"})


CVE_NOTICE_SOURCE = ("https://github.com/CVEProject/cveproject.github.io/blob/"
                     "edf6d280a1a3a63af267a0f2ee043b6ed402196a/docs/terms.md")
CVE_NOTICE_BLOB = "9a1df8348853e654ed926d884047b6b9875b2f8d"
CVE_COPYRIGHT_NOTICE = "Copyright © 1999–2026, The MITRE Corporation."
CVE_TERMS_NOTICE = (
    '## LICENSE\n'
    '\n'
    'Submissions: For all materials you submit to the Common Vulnerabilities and \n'
    'Exposures (CVE®), you hereby grant to The MITRE Corporation (MITRE) and all \n'
    'CVE Numbering Authorities (CNAs) a perpetual, worldwide, non-exclusive, \n'
    'no-charge, royalty-free, irrevocable copyright license to reproduce, prepare \n'
    'derivative works of, publicly display, publicly perform, sublicense, and \n'
    'distribute such materials and derivative works. Unless required by applicable \n'
    'law or agreed to in writing, you provide such materials on an "AS IS" BASIS, \n'
    'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, \n'
    'including, without limitation, any warranties or conditions of TITLE, \n'
    'NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.\n'
    '\n'
    'CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, \n'
    'no-charge, royalty-free, irrevocable copyright license to reproduce, prepare \n'
    'derivative works of, publicly display, publicly perform, sublicense, and \n'
    'distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make for \n'
    "such purposes is authorized provided that you reproduce MITRE's copyright \n"
    'designation and this license in any such copy.\n'
    '\n'
    '## DISCLAIMERS\n'
    '\n'
    'ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE \n'
    'PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE \n'
    'REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF \n'
    'TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR \n'
    'IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE \n'
    'INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF \n'
    'MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.\n'
)


class CveHttpsState(StrEnum):
    """Separate complete HTTPS custody from bounded import and publication failures."""

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


class CveHttpsAcknowledgement(StrEnum):
    """Report storage acknowledgement without inferring rollback or unobserved publication."""

    NOT_ATTEMPTED = "not-attempted"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CveHttpsSource:
    """Select one original CVE record and its mandatory caller pin without URL admission."""

    commit: str
    identifier: str
    expected_sha256: str

    def __post_init__(self) -> None:
        """Require exact immutable commit, canonical single CVE and mandatory raw SHA-256."""

        if type(self.commit) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.commit):
            raise ValueError("CVE HTTPS source requires an exact lowercase 40-hex commit")

        if type(self.identifier) is not str or not IntelligenceIdentifier(
            self.identifier,
        ).startswith("CVE-"):
            raise ValueError("CVE HTTPS source requires one canonical CVE identifier")

        if type(self.expected_sha256) is not str:
            raise ValueError("CVE HTTPS source requires an exact string SHA-256 pin")

        RequireReferenceDigest(self.expected_sha256)

    @property
    def SourceUrl(self) -> str:
        """Derive the sole immutable official archive resource without caller path components.

        Returns:
            Exact raw GitHub locator derived only from validated commit and lexical CVE digits.
        """

        _, year, serial = self.identifier.split("-")

        return ("https://raw.githubusercontent.com/CVEProject/cvelistV5/"
                f"{self.commit}/cves/{year}/{serial[:-3]}xxx/{self.identifier}.json")

    def ToDict(self) -> dict[str, object]:
        """Bind declared source and fixed reviewed data notices without license entitlement claims.

        Returns:
            Detached source identity; schema licensing is not substituted for CVE data terms.
        """

        return {"commit": self.commit, "identifier": self.identifier,
                "expected_sha256": self.expected_sha256, "source_url": self.SourceUrl,
                "publisher": "CVE Program", "data_license_name": "CVE Program Terms of Use",
                "terms_url": "https://www.cve.org/Legal/TermsOfUse",
                "data_notice": {"copyright": CVE_COPYRIGHT_NOTICE, "text": CVE_TERMS_NOTICE,
                    "text_source_url": CVE_NOTICE_SOURCE, "text_git_blob": CVE_NOTICE_BLOB,
                    "copyright_source_url": "https://cveproject.github.io/docs/terms.html",
                    "observed_on": "2026-11-03"},
                "publisher_authentication": "not-assessed", "legal_rights": "not-assessed"}


@dataclass(frozen=True, slots=True)
class CveHttpsRequest:
    """Admit exactly one selected record and finite receive limits without supplied bytes."""

    source: CveHttpsSource
    max_bytes: int = MAX_SOURCE_BYTES
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        """Refuse untyped sources, boolean limits, unbounded time and raised source budgets."""

        if type(self.source) is not CveHttpsSource:
            raise ValueError("CVE HTTPS acquisition requires an exact typed source")

        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_SOURCE_BYTES:
            raise ValueError("CVE source ceiling must be positive and at most one MiB")

        if type(self.timeout_seconds) not in (int, float) or not (
            math.isfinite(self.timeout_seconds) and 0.05 <= self.timeout_seconds <= 60
        ):
            raise ValueError("CVE timeout must be finite and in 0.05..60 seconds")


class BoundedCveEvidenceStore(LocalEvidenceStore):
    """Bound caller-expected artifact domains before owning Get implicitly allocates content."""

    def __init__(self, root: Path, role: str, maximum: int) -> None:
        """Configure one expected profile role, JSON media type and byte ceiling.

        Args:
            root: Existing workspace-owned evidence directory.
            role: Caller-expected profile role, not copied from an untrusted manifest.
            maximum: Fixed or validated request ceiling for this artifact domain.
        """

        super().__init__(root)
        self.expected_role = role
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Refuse wrong roles, media or sizes before delegating actual blob allocation.

        Args:
            reference: Original reference being verified by the owning evidence store.

        Returns:
            Exact bounded hash-verified bytes in the expected artifact domain.
        """

        if reference.role != self.expected_role or reference.media_type != "application/json" or (
            reference.size_bytes > self.maximum
        ):
            raise ValueError("CVE artifact exceeds its role-specific byte profile")

        return super().Read(reference)


def SourceAttribution(source: CveHttpsSource, raw: EvidenceRecord) -> ReferenceSource:
    """Reconstruct full nested attribution from selected source and original receive provenance.

    Args:
        source: Exact immutable selected source and fixed data terms.
        raw: Original raw acquisition manifest carrying observed receive completion.

    Returns:
        Existing unchanged ReferenceSource with this profile's importer and data license link.
    """

    return ReferenceSource(SourceOrigin.EXTERNAL, "CVE Program", source.SourceUrl,
        raw.reference.sha256, "CVE Program Terms of Use", "https://www.cve.org/Legal/TermsOfUse",
        raw.provenance.finished_at, IMPORTER_ID, IMPORTER_VERSION)


@dataclass(frozen=True, slots=True)
class CveHttpsSelection:
    """Bind original HTTPS custody to unchanged snapshot output under a separate envelope family."""

    source: CveHttpsSource
    raw: EvidenceRecord
    snapshot: IntelligenceSnapshot
    max_bytes: int = MAX_SOURCE_BYTES
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        """Validate structural joins; original-byte proof belongs to the reopening boundary."""

        if type(self.source) is not CveHttpsSource or type(self.raw) is not EvidenceRecord or (
            type(self.snapshot) is not IntelligenceSnapshot
        ):
            raise ValueError("CVE envelope requires exact typed source, raw and snapshot")

        CveHttpsRequest(self.source, self.max_bytes, self.timeout_seconds)
        RequireRecord(self.raw, RAW_ROLE, "application/json")

        if (
            self.snapshot.feed is not IntelligenceFeed.CVE
            or self.snapshot.catalog_version != self.source.commit
            or self.snapshot.source != SourceAttribution(self.source, self.raw)
            or self.snapshot.evidence != self.raw.reference
            or self.raw.reference.size_bytes > self.max_bytes
            or self.source.expected_sha256 != self.raw.reference.sha256
            or len(self.snapshot.records) != 1
            or self.snapshot.records[0].identifier != self.source.identifier
            or self.snapshot.records[0].data["state"] != "PUBLISHED"
        ):
            raise ValueError("CVE envelope disagrees with original source snapshot")

    def ToDict(self) -> dict[str, object]:
        """Return detached envelope identity without legacy snapshot or authentication claims.

        Returns:
            Separate schema-one envelope containing unchanged schema-one snapshot content.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "cve-https-selected-acquisition", "source": self.source.ToDict(),
                "format_version": "5.2",
                "limits": {"max_source_bytes": self.max_bytes,
                           "timeout_seconds": self.timeout_seconds},
                "raw": self.raw.ToDict(),
                "raw_id": self.raw.evidence_id,
                "snapshot": {**self.snapshot.Content(), "reference": self.snapshot.Reference()},
                "snapshot_reference": self.snapshot.Reference()}

    def Reference(self) -> str:
        """Bind original manifest, terms and complete selected content into a distinct identity.

        Returns:
            Deterministic attributed reference that cannot impersonate a legacy snapshot.
        """

        return "cve-https-selection:" + hashlib.sha256(
            CanonicalReferenceJson(self.ToDict()),
        ).hexdigest()

    def Serialize(self) -> bytes:
        """Return bounded canonical envelope bytes including their separate content reference.

        Returns:
            JSON payload within the explicit selected-envelope ceiling.
        """

        payload = CanonicalReferenceJson({**self.ToDict(), "reference": self.Reference()})

        if len(payload) > MAX_ENVELOPE_BYTES:
            raise ValueError("CVE envelope exceeds its byte profile")

        return payload


@dataclass(frozen=True, slots=True)
class CveHttpsOutcome:
    """Report actual HTTPS custody acknowledgements, including uncertain storage failure."""

    state: CveHttpsState
    source: CveHttpsSource
    started_at: str
    finished_at: str
    received_bytes: int
    body_complete: bool
    max_bytes: int
    timeout_seconds: float
    receive_state: str
    http_status: int | None
    raw: EvidenceRecord | None = None
    envelope: CveHttpsSelection | None = None
    snapshot_record: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None
    raw_ack: CveHttpsAcknowledgement = CveHttpsAcknowledgement.NOT_ATTEMPTED
    snapshot_ack: CveHttpsAcknowledgement = CveHttpsAcknowledgement.NOT_ATTEMPTED
    receipt_ack: CveHttpsAcknowledgement = CveHttpsAcknowledgement.NOT_ATTEMPTED

    def __post_init__(self) -> None:
        """Keep returned execution facts immutable without granting replay authority."""

        CveHttpsRequest(self.source, self.max_bytes, self.timeout_seconds)

        if not isinstance(self.state, CveHttpsState) or any(
            not isinstance(value, CveHttpsAcknowledgement)
            for value in (self.raw_ack, self.snapshot_ack, self.receipt_ack)
        ):
            raise ValueError("CVE outcome requires typed state and acknowledgement facts")

        if type(self.body_complete) is not bool or type(self.received_bytes) is not int or not (
            0 <= self.received_bytes <= self.max_bytes
        ):
            raise ValueError("CVE outcome requires typed bounded byte completeness facts")

        if NormalizeEvidenceTime(self.started_at) != self.started_at or (
            NormalizeEvidenceTime(self.finished_at) != self.finished_at
            or self.finished_at < self.started_at
        ):
            raise ValueError("CVE outcome requires canonical observed acquisition chronology")

        if type(self.receive_state) is not str or self.receive_state not in RECEIVE_STATES:
            raise ValueError("CVE outcome requires an observed isolated-receiver state")

        if self.http_status is not None and (
            type(self.http_status) is not int or not 100 <= self.http_status <= 599
        ):
            raise ValueError("CVE outcome requires a typed HTTP status or unknown status")

        if self.body_complete != (self.receive_state == "succeeded") or (
            self.body_complete and self.http_status != 200
        ):
            raise ValueError("CVE outcome completeness disagrees with observed HTTPS facts")

        for record in (self.raw, self.snapshot_record, self.receipt):
            if record is not None and type(record) is not EvidenceRecord:
                raise ValueError("CVE outcome requires immutable typed evidence handles")

        if self.envelope is not None and type(self.envelope) is not CveHttpsSelection:
            raise ValueError("CVE outcome requires a typed selected envelope")

    def ReceiptContent(self) -> dict[str, object]:
        """Describe terminal pre-receipt facts without circular self-publication assertions.

        Returns:
            Distinct bounded receipt body; receipt acknowledgement is outcome-only.
        """

        return {"schema_version": 1, "profile_version": 1,
                "profile": "cve-https-selected-acquisition", "state": self.state.value,
                "source": self.source.ToDict(), "identifier": self.source.identifier,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "received_bytes": self.received_bytes, "body_complete": self.body_complete,
                "transport": "https", "http_status": self.http_status,
                "receive_state": self.receive_state,
                "limits": {"max_source_bytes": self.max_bytes,
                           "timeout_seconds": self.timeout_seconds},
                "raw": self.raw.ToDict() if self.raw is not None else None,
                "snapshot_record": (self.snapshot_record.ToDict()
                                     if self.snapshot_record is not None else None),
                "envelope_reference": (self.envelope.Reference()
                                        if self.envelope is not None else None),
                "raw_ack": self.raw_ack.value, "snapshot_ack": self.snapshot_ack.value,
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
        raise ValueError("CVE artifact has foreign role, media type or importer provenance")


def AcquireHttpsCveSelection(
    workspace_root: Path, request: CveHttpsRequest, *, scope_reference: str,
) -> CveHttpsOutcome:
    """Receive one pinned JSON and publish original custody, selection and receipt in owning stores.

    Args:
        workspace_root: Explicit existing owning workspace.
        request: Typed immutable selected CVE source, byte pin and finite receive limits.
        scope_reference: Explicit collection attribution, never execution authority.

    Returns:
        Honest terminal state and independent acknowledgements; failed publication may leave
        immutable artifacts and is never reported as rollback or successful complete custody.
    """

    if type(request) is not CveHttpsRequest:
        raise ValueError("CVE HTTPS acquisition requires a typed HTTPS request")

    RequireReferenceText(scope_reference, "scope_reference")
    owner = LocalWorkspaceStore(workspace_root).Open()
    store = LocalEvidenceStore(workspace_root / "evidence")
    startedAt = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    payload, receiveState, httpStatus = ReceiveIsolatedHttps(
        request.source.SourceUrl, request.max_bytes, request.timeout_seconds,
    )
    finishedAt = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    complete = receiveState == "succeeded"
    provenance = EvidenceProvenance(owner.workspace_id, scope_reference, IMPORTER_ID,
                                    IMPORTER_VERSION, None, startedAt, finishedAt)
    outcome = CveHttpsOutcome(
        CveHttpsState(receiveState),
        request.source, startedAt, finishedAt, len(payload),
        complete, request.max_bytes, request.timeout_seconds, receiveState, httpStatus,
    )

    try:
        outcome = replace(outcome, raw_ack=CveHttpsAcknowledgement.UNKNOWN)
        raw = store.Put(payload, RAW_ROLE if complete else PARTIAL_ROLE,
                        "application/json", provenance)
        outcome = replace(outcome, raw=raw, raw_ack=CveHttpsAcknowledgement.CONFIRMED)

        if complete:
            if request.source.expected_sha256 != raw.reference.sha256:
                outcome = replace(outcome, state=CveHttpsState.DIGEST_MISMATCH)

            else:
                try:
                    snapshot = ParseSelectedCve(payload, request.source, raw)
                    envelope = CveHttpsSelection(request.source, raw, snapshot,
                                                request.max_bytes, request.timeout_seconds)
                    serialized = envelope.Serialize()

                except ValueError:
                    outcome = replace(outcome, state=CveHttpsState.PARSE_FAILED)

                else:
                    outcome = replace(outcome, snapshot_ack=CveHttpsAcknowledgement.UNKNOWN)
                    record = store.Put(serialized, ENVELOPE_ROLE, "application/json", provenance)
                    outcome = replace(outcome, envelope=envelope, snapshot_record=record,
                                      snapshot_ack=CveHttpsAcknowledgement.CONFIRMED)

        serializedReceipt = CanonicalReferenceJson(outcome.ReceiptContent())

        if len(serializedReceipt) > MAX_RECEIPT_BYTES:
            return replace(outcome, state=CveHttpsState.STORAGE_FAILED, envelope=None)

        outcome = replace(outcome, receipt_ack=CveHttpsAcknowledgement.UNKNOWN)
        receipt = store.Put(serializedReceipt, RECEIPT_ROLE, "application/json", provenance)

        return replace(outcome, receipt=receipt, receipt_ack=CveHttpsAcknowledgement.CONFIRMED)

    except (EvidenceError, ValueError):
        # The owning publisher can refuse oversized generated manifests before a handle returns.
        return replace(outcome, state=CveHttpsState.STORAGE_FAILED, envelope=None)


def JsonObject(payload: bytes, maximum: int) -> dict[str, object]:
    """Require bounded strict JSON with the unchanged depth, duplicate and numeric protections.

    Args:
        payload: Original JSON bytes selected from an admitted bounded artifact domain.
        maximum: Fixed or request-derived role byte ceiling.

    Returns:
        Detached exact object without permissive scalar coercion.
    """

    if not isinstance(payload, bytes) or len(payload) > maximum:
        raise ValueError("CVE JSON exceeds its selected byte profile")

    return IntelligenceObject(BoundedJson(payload))


def DecodeHttpsSource(value: object) -> CveHttpsSource:
    """Reconstruct exact source and fixed data notices without network requests.

    Args:
        value: Untrusted nested source declaration decoded from bounded JSON.

    Returns:
        Strict immutable source whose full canonical declaration matches the supplied fields.
    """

    fields = RequireManifestFields(value, {"commit", "identifier", "expected_sha256", "source_url",
        "publisher", "data_license_name", "terms_url", "data_notice", "publisher_authentication",
        "legal_rights"})
    source = CveHttpsSource(cast(str, fields["commit"]), cast(str, fields["identifier"]),
                           cast(str, fields["expected_sha256"]))

    if CanonicalReferenceJson(source.ToDict()) != CanonicalReferenceJson(value):
        raise ValueError("CVE HTTPS source disagrees with its exact immutable identity")

    return source


def ParseSelectedCve(
    payload: bytes, source: CveHttpsSource, raw: EvidenceRecord,
) -> IntelligenceSnapshot:
    """Admit one exact wire-5.2 PUBLISHED record before producing unchanged nested content.

    Args:
        payload: Complete original JSON bytes within the one MiB source profile.
        source: Exact requested commit, canonical CVE and mandatory byte pin.
        raw: Original acquisition manifest whose observed clock binds parser attribution.

    Returns:
        Existing immutable schema-one snapshot without full-schema or authenticity claims.
    """

    document = JsonObject(payload, MAX_SOURCE_BYTES)
    metadata = IntelligenceObject(document.get("cveMetadata"))

    if document.get("dataType") != "CVE_RECORD" or document.get("dataVersion") != "5.2" or (
        metadata.get("state") != "PUBLISHED" or metadata.get("cveId") != source.identifier
    ):
        raise ValueError("CVE profile requires exact selected wire-5.2 PUBLISHED source")

    return ParseIntelligenceSnapshot(payload, IntelligenceFeed.CVE, source.commit,
                                     SourceAttribution(source, raw), raw.reference)


def LoadHttpsCveSelection(
    workspace_root: Path, selection_id: str, receipt_id: str,
) -> CveHttpsSelection:
    """Reopen exact HTTPS custody roots and reparse complete original JSON before returning.

    Args:
        workspace_root: Explicit existing owning workspace, including relocated original stores.
        selection_id: Exact attributed selected-envelope manifest identifier.
        receipt_id: Exact successful terminal receipt from the same acquisition.

    Returns:
        Verified original-byte selection; inspection writes nothing and never authenticates
        the publisher, assigns target applicability or enters legacy snapshot dispatch.
    """

    owner = LocalWorkspaceStore(workspace_root).Open()
    store = BoundedCveEvidenceStore(
        workspace_root / "evidence", ENVELOPE_ROLE, MAX_ENVELOPE_BYTES,
    )
    receipts = BoundedCveEvidenceStore(
        workspace_root / "evidence", RECEIPT_ROLE, MAX_RECEIPT_BYTES,
    )
    selectedRecord = store.Get(selection_id)
    receipt = receipts.Get(receipt_id)
    RequireRecord(selectedRecord, ENVELOPE_ROLE, "application/json")
    RequireRecord(receipt, RECEIPT_ROLE, "application/json")

    if selectedRecord.provenance != receipt.provenance or (
        receipt.provenance.workspace_id != owner.workspace_id
    ):
        raise ValueError("CVE selected custody requires identical owning acquisition provenance")

    document = JsonObject(
        store.Read(selectedRecord.reference), MAX_ENVELOPE_BYTES,
    )
    terminal = JsonObject(receipts.Read(receipt.reference), MAX_RECEIPT_BYTES)
    raw = ParseEvidenceManifest(CanonicalReferenceJson(document.get("raw")))
    RequireRecord(raw, RAW_ROLE, "application/json")

    if raw.provenance != selectedRecord.provenance:
        raise ValueError("CVE original raw facts disagree with selected receipt provenance")

    source = DecodeHttpsSource(document.get("source"))
    snapshot = IntelligenceSnapshot.Deserialize(CanonicalReferenceJson(document.get("snapshot")))
    limits = RequireManifestFields(document.get("limits"), {"max_source_bytes", "timeout_seconds"})
    request = CveHttpsRequest(source, cast(int, limits["max_source_bytes"]),
                             cast(float, limits["timeout_seconds"]))

    if raw.reference.size_bytes > request.max_bytes:
        raise ValueError("CVE original raw facts disagree with selected receipt constraints")

    envelope = CveHttpsSelection(source, raw, snapshot, request.max_bytes, request.timeout_seconds)
    expected = CveHttpsOutcome(
        CveHttpsState.SUCCEEDED, source,
        receipt.provenance.started_at, receipt.provenance.finished_at,
        raw.reference.size_bytes, True, request.max_bytes, request.timeout_seconds,
        "succeeded", 200, raw=raw, envelope=envelope,
        snapshot_record=selectedRecord, raw_ack=CveHttpsAcknowledgement.CONFIRMED,
        snapshot_ack=CveHttpsAcknowledgement.CONFIRMED,
    )

    if envelope.Serialize() != CanonicalReferenceJson(document) or (
        CanonicalReferenceJson(expected.ReceiptContent()) != CanonicalReferenceJson(terminal)
    ):
        raise ValueError("CVE selected envelope or terminal receipt disagrees with exact custody")

    originals = BoundedCveEvidenceStore(
        workspace_root / "evidence", RAW_ROLE, request.max_bytes,
    )

    if originals.Get(raw.evidence_id) != raw:
        raise ValueError("CVE original acquisition manifest is missing or foreign")

    reparsed = ParseSelectedCve(originals.Read(raw.reference), source, raw)

    if reparsed != snapshot:
        raise ValueError("CVE selected content disagrees with original JSON bytes")

    return envelope
