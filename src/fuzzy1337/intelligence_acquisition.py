# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental bounded intelligence acquisition with immutable terminal evidence receipts."""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.intel_references import (
    ReferenceSource,
    RequireReferenceDigest,
    RequireReferenceText,
    RequireReferenceUrl,
    SourceOrigin,
)
from fuzzy1337.intelligence import (
    MAX_SOURCE_BYTES,
    IntelligenceFeed,
    IntelligenceSnapshot,
    IntelligenceText,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.intelligence_transport import (
    FORMAT_EXIT,
    HTTP_EXIT,
    REDIRECT_EXIT,
    SIZE_EXIT,
    TIMEOUT_EXIT,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = (
    "SnapshotSource", "SnapshotRequest", "AcquisitionState", "AcquisitionOutcome",
    "SyncState", "SyncOutcome", "CisaKevSource", "AcquireIntelligenceSnapshot",
    "SyncIntelligenceSnapshots", "LoadAcquiredSnapshot",
)

ACQUISITION_SCHEMA_VERSION = 1
IMPORTER_ID = "intelligence-acquisition"
IMPORTER_VERSION = "1"
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_KEV_PREFIX = "https://raw.githubusercontent.com/cisagov/kev-data/"
_KEV_FILENAME = "/known_exploited_vulnerabilities.json"
_MEDIA_TYPES = {
    IntelligenceFeed.CVE: "application/json", IntelligenceFeed.CWE: "application/xml",
    IntelligenceFeed.KEV: "application/json", IntelligenceFeed.EPSS: "text/csv",
}


class AcquisitionState(StrEnum):
    """Distinguish complete publication from acquisition, parsing, or publication failures."""

    SUCCEEDED = "succeeded"
    REDIRECT_REJECTED = "redirect-rejected"
    HTTP_REJECTED = "http-rejected"
    FORMAT_REJECTED = "format-rejected"
    SIZE_EXCEEDED = "size-exceeded"
    TRANSPORT_FAILED = "transport-failed"
    TIMED_OUT = "timed-out"
    DIGEST_MISMATCH = "digest-mismatch"
    PARSE_FAILED = "parse-failed"
    STORAGE_FAILED = "storage-failed"


class SyncState(StrEnum):
    """Summarize explicit per-source outcomes without an all-or-nothing success claim."""

    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SnapshotSource:
    """Carry caller-declared source facts separately from receiver-observed acquisition time."""

    feed: IntelligenceFeed
    catalog_version: str
    origin: SourceOrigin
    publisher: str
    source_url: str
    license_name: str
    license_url: str
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        """Require bounded explicit attribution without fetching or authenticating it."""

        if not isinstance(self.feed, IntelligenceFeed) or not isinstance(self.origin, SourceOrigin):
            raise ValueError("snapshot source requires typed feed and origin")

        IntelligenceText(self.catalog_version, "catalog_version", 256)
        RequireReferenceText(self.publisher, "publisher")
        RequireReferenceText(self.license_name, "license_name")
        RequireReferenceUrl(self.source_url)
        RequireReferenceUrl(self.license_url)

        if self.expected_sha256 is not None:
            RequireReferenceDigest(self.expected_sha256)

    def ToDict(self) -> dict[str, object]:
        """Return declared source selection without claiming its license or publisher is verified.

        Returns:
            Feed, version, origin, attribution, locator, and optional expected byte digest.
        """

        return {
            "feed": self.feed.value, "catalog_version": self.catalog_version,
            "origin": self.origin.value, "publisher": self.publisher,
            "source_url": self.source_url, "license_name": self.license_name,
            "license_url": self.license_url, "expected_sha256": self.expected_sha256,
        }


def CisaKevSource(
    commit: str, catalog_version: str, *, expected_sha256: str | None = None,
) -> SnapshotSource:
    """Select one immutable official CISA mirror revision without discovering a latest version.

    Args:
        commit: Exact lowercase 40-hex repository commit chosen by the caller.
        catalog_version: Exact JSON catalogVersion expected by the existing parser.
        expected_sha256: Optional caller-owned byte pin; never a publisher signature.

    Returns:
        Explicit CISA KEV mirror JSON and same-revision license attribution.
    """

    if not isinstance(commit, str) or not _COMMIT_PATTERN.fullmatch(commit):
        raise ValueError("CISA KEV requires an exact lowercase repository commit")

    return SnapshotSource(
        IntelligenceFeed.KEV, catalog_version, SourceOrigin.EXTERNAL, "CISA",
        _KEV_PREFIX + commit + _KEV_FILENAME, "CC0-1.0",
        "https://github.com/cisagov/kev-data/blob/" + commit + "/LICENSE", expected_sha256,
    )


def RequireRemoteSelection(source: SnapshotSource) -> None:
    """Allow only the documented pinned mirror, never an arbitrary URL or moving ref.

    Args:
        source: Explicit selection proposed for HTTPS acquisition.
    """

    commit = source.source_url.removeprefix(_KEV_PREFIX).removesuffix(_KEV_FILENAME)

    if not _COMMIT_PATTERN.fullmatch(commit) or source != CisaKevSource(
        commit, source.catalog_version, expected_sha256=source.expected_sha256,
    ):
        raise ValueError("HTTPS acquisition requires the explicitly pinned official CISA selection")


@dataclass(frozen=True, slots=True)
class SnapshotRequest:
    """Choose explicit local bytes or one allowed HTTPS snapshot with finite receiver limits."""

    source: SnapshotSource
    payload: bytes | None = None
    max_bytes: int = MAX_SOURCE_BYTES
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject untyped selections, unbounded limits, and unsupported remote source choices."""

        if not isinstance(self.source, SnapshotSource):
            raise ValueError("snapshot request requires a typed source")

        if self.payload is not None and not isinstance(self.payload, bytes):
            raise ValueError("local snapshot payload must be explicitly supplied bytes")

        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_SOURCE_BYTES:
            raise ValueError("acquisition byte limit must be positive and at most 16 MiB")

        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds) or not 0.05 <= self.timeout_seconds <= 60
        ):
            raise ValueError("acquisition timeout must be finite and between 0.05 and 60 seconds")

        if self.payload is None:
            RequireRemoteSelection(self.source)


@dataclass(frozen=True, slots=True)
class AcquisitionOutcome:
    """Retain exact publication facts; failed acquisition supplies no usable snapshot."""

    state: AcquisitionState
    source: SnapshotSource
    started_at: str
    finished_at: str
    received_bytes: int
    body_complete: bool
    http_status: int | None
    raw: EvidenceRecord | None = None
    snapshot: IntelligenceSnapshot | None = None
    snapshot_record: EvidenceRecord | None = None
    receipt: EvidenceRecord | None = None

    def ToDict(self) -> dict[str, object]:
        """Describe terminal facts without raw bytes, local paths, secrets, or inferred approval.

        Returns:
            Controlled schema-v1 acquisition receipt content.
        """

        return {
            "schema_version": ACQUISITION_SCHEMA_VERSION, "state": self.state.value,
            "source": self.source.ToDict(), "started_at": self.started_at,
            "finished_at": self.finished_at, "received_bytes": self.received_bytes,
            "body_complete": self.body_complete, "http_status": self.http_status,
            "raw": JsonValue(self.raw) if self.raw is not None else None,
            "snapshot_reference": self.snapshot.Reference() if self.snapshot is not None else None,
            "snapshot_record": (
                JsonValue(self.snapshot_record) if self.snapshot_record is not None else None
            ),
            "publisher_authentication": "not-assessed",
        }


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """Return independent acquisitions in caller order, including actual partial success."""

    state: SyncState
    outcomes: tuple[AcquisitionOutcome, ...]


def AcquisitionTime() -> str:
    """Observe receiver UTC time without accepting a caller's acquisition timestamp.

    Returns:
        Offset-aware UTC timestamp with fixed microsecond precision.
    """

    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def FetchRemoteBytes(request: SnapshotRequest) -> tuple[bytes, AcquisitionState, int | None]:
    """Bound the whole isolated HTTPS receiver, retaining only actually delivered body bytes.

    Args:
        request: Prevalidated pinned official source and finite byte/deadline limits.

    Returns:
        Original bounded complete/partial bytes, terminal transport state, and observed HTTP status.
    """

    worker = Path(__file__).with_name("intelligence_transport.py")
    started = time.monotonic()

    try:
        process = subprocess.Popen(
            [sys.executable, "-I", str(worker), request.source.source_url,
             str(request.max_bytes), str(request.timeout_seconds)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={},
        )

    except OSError:
        return b"", AcquisitionState.TRANSPORT_FAILED, None

    timed_out = False

    try:
        remaining = max(0.0, request.timeout_seconds - (time.monotonic() - started))
        output, _ = process.communicate(timeout=remaining)

    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        output, _ = process.communicate()

    except BaseException:
        process.kill()
        process.communicate()

        raise

    line, separator, body = output.partition(b"\n")
    status = None

    if separator and len(line) <= 128:
        try:
            metadata = json.loads(line)

            if (
                isinstance(metadata, dict) and set(metadata) == {"status"}
                and type(metadata["status"]) is int and 100 <= metadata["status"] <= 599
            ):
                status = metadata["status"]

        except (ValueError, UnicodeError):
            pass

    if status is None or len(body) > request.max_bytes:
        return b"", (
            AcquisitionState.TIMED_OUT if timed_out else AcquisitionState.TRANSPORT_FAILED
        ), status

    state = {
        0: AcquisitionState.SUCCEEDED, REDIRECT_EXIT: AcquisitionState.REDIRECT_REJECTED,
        HTTP_EXIT: AcquisitionState.HTTP_REJECTED, FORMAT_EXIT: AcquisitionState.FORMAT_REJECTED,
        SIZE_EXIT: AcquisitionState.SIZE_EXCEEDED, TIMEOUT_EXIT: AcquisitionState.TIMED_OUT,
    }.get(process.returncode, AcquisitionState.TRANSPORT_FAILED)

    if timed_out:
        state = AcquisitionState.TIMED_OUT

    if state is AcquisitionState.SUCCEEDED and status != 200:
        state = AcquisitionState.TRANSPORT_FAILED

    return body, state, status


def AcquireIntelligenceSnapshot(
    workspace_root: Path, request: SnapshotRequest, *, scope_reference: str,
) -> AcquisitionOutcome:
    """Acquire one explicit source and publish immutable raw, parsed, and terminal evidence.

    Args:
        workspace_root: Existing owning workspace and evidence partition.
        request: Explicit local bytes or allowed pinned official HTTPS source.
        scope_reference: Explicit non-secret collection attribution, never scan authority.

    Returns:
        Exact terminal outcome. Parse/digest failure retains raw bytes; storage failure can leave
        immutable orphan bytes or a published snapshot and never claims successful acquisition.
    """

    if not isinstance(request, SnapshotRequest):
        raise ValueError("acquisition requires a typed request")

    RequireReferenceText(scope_reference, "scope_reference")
    workspace = LocalWorkspaceStore(workspace_root)
    owner = workspace.Open()
    store = LocalEvidenceStore(workspace.root / "evidence")
    started_at = AcquisitionTime()

    if request.payload is None:
        payload, state, status = FetchRemoteBytes(request)

    else:
        payload = request.payload[:request.max_bytes]
        state = (
            AcquisitionState.SUCCEEDED if len(request.payload) <= request.max_bytes
            else AcquisitionState.SIZE_EXCEEDED
        )
        status = None

    finished_at = AcquisitionTime()
    outcome = AcquisitionOutcome(
        state, request.source, started_at, finished_at, len(payload),
        state is AcquisitionState.SUCCEEDED, status,
    )
    provenance = EvidenceProvenance(
        owner.workspace_id, scope_reference, IMPORTER_ID, IMPORTER_VERSION, None,
        started_at, finished_at,
    )

    try:
        if payload or outcome.body_complete:
            raw = store.Put(
                payload, "intelligence-source" if outcome.body_complete else "intelligence-partial",
                _MEDIA_TYPES[request.source.feed], provenance,
            )
            outcome = replace(outcome, raw=raw)

        if outcome.body_complete:
            expected = request.source.expected_sha256

            if expected is not None and hashlib.sha256(payload).hexdigest() != expected:
                outcome = replace(outcome, state=AcquisitionState.DIGEST_MISMATCH)

            else:
                if outcome.raw is None:
                    raise ValueError("complete acquisition requires raw evidence publication")

                source = ReferenceSource(
                    request.source.origin, request.source.publisher, request.source.source_url,
                    outcome.raw.reference.sha256, request.source.license_name,
                    request.source.license_url, finished_at, IMPORTER_ID, IMPORTER_VERSION,
                )

                try:
                    snapshot = ParseIntelligenceSnapshot(
                        payload, request.source.feed, request.source.catalog_version,
                        source, outcome.raw.reference,
                    )
                    serialized = snapshot.Serialize()

                except ValueError:
                    outcome = replace(outcome, state=AcquisitionState.PARSE_FAILED)

                else:
                    snapshot_record = store.Put(
                        serialized, "intelligence-snapshot", "application/json", provenance,
                    )
                    outcome = replace(outcome, snapshot=snapshot, snapshot_record=snapshot_record)

        receipt = store.Put(
            CanonicalModelJson(outcome.ToDict()), "intelligence-acquisition", "application/json",
            provenance,
        )

        return replace(outcome, receipt=receipt)

    except EvidenceError:
        return replace(outcome, state=AcquisitionState.STORAGE_FAILED, snapshot=None)


def SyncIntelligenceSnapshots(
    workspace_root: Path, requests: tuple[SnapshotRequest, ...], *, scope_reference: str,
) -> SyncOutcome:
    """Acquire a bounded explicit batch without discovery, retries, rollback, or model mutation.

    Args:
        workspace_root: Existing owning workspace.
        requests: One to sixteen explicit independent selections in processing order.
        scope_reference: Explicit collection attribution reused for each source.

    Returns:
        All per-source terminal receipts and an honest complete, partial, or failed summary.
    """

    if (
        not isinstance(requests, tuple) or not 1 <= len(requests) <= 16
        or any(not isinstance(request, SnapshotRequest) for request in requests)
    ):
        raise ValueError("sync requires one to sixteen explicit typed requests")

    outcomes = tuple(
        AcquireIntelligenceSnapshot(workspace_root, request, scope_reference=scope_reference)
        for request in requests
    )
    successes = sum(outcome.state is AcquisitionState.SUCCEEDED for outcome in outcomes)
    state = (
        SyncState.SUCCEEDED if successes == len(outcomes)
        else SyncState.PARTIAL if successes else SyncState.FAILED
    )

    return SyncOutcome(state, outcomes)


def LoadAcquiredSnapshot(workspace_root: Path, evidence_id: str) -> IntelligenceSnapshot:
    """Verify a stored parsed snapshot and reparse its original source before returning it.

    Args:
        workspace_root: Existing owning workspace; foreign copied manifests are rejected.
        evidence_id: Immutable intelligence-snapshot evidence-manifest identity.

    Returns:
        Original verified snapshot ready for the existing verified enrichment consumer.
    """

    workspace = LocalWorkspaceStore(workspace_root)
    owner = workspace.Open()
    store = LocalEvidenceStore(workspace.root / "evidence")
    record = store.Get(evidence_id)

    if record.provenance.workspace_id != owner.workspace_id or (
        record.reference.role != "intelligence-snapshot"
        or record.reference.media_type != "application/json"
    ):
        raise ValueError("snapshot must be an intelligence artifact in the owning workspace")

    snapshot = IntelligenceSnapshot.Deserialize(store.Read(record.reference))

    if snapshot.evidence.role != "intelligence-source":
        raise ValueError("acquired snapshot must reference a complete original source artifact")

    reparsed = ParseIntelligenceSnapshot(
        store.Read(snapshot.evidence), snapshot.feed, snapshot.catalog_version,
        snapshot.source, snapshot.evidence,
    )

    if reparsed != snapshot:
        raise ValueError("stored snapshot disagrees with verified original source bytes")

    return snapshot
