# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed response custody, bounded private staging and offline original-ID verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from fuzzy1337.adapters import (
    AdapterExecution,
    EvidenceReference,
    ExecutionState,
    SerializeContract,
)
from fuzzy1337.adapters.owned_response_capture import (
    Destination,
    ParseOwnedResponseCapture,
    RequestBytes,
    ReviewedResponse,
    UniqueObject,
)
from fuzzy1337.artifact_inputs import (
    ArtifactHandleInfo,
    ArtifactPathInfo,
    PhysicalIdentity,
)
from fuzzy1337.evidence import (
    EvidenceNotFoundError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
)
from fuzzy1337.executors import LocalExecutionRequest, LocalExecutionResult
from fuzzy1337.executors.contracts import ExecutionEvent, ExecutionEventKind, ExecutionTermination
from fuzzy1337.jobs import JobContext, JobSnapshot
from fuzzy1337.scope import Target, TargetKind

PROVIDER_ID = "native.loopback-response"
CAPABILITY_ID = "http.synthetic-response-capture"
RECEIPT_PROFILE = "owned-response-capture-receipt.v1"
MAX_RECEIPT_BYTES = 2097152
MAX_PUBLICATION_BYTES = 3145728
MAX_LOG_BYTES = 131072
_MEDIA = {
    "stdout": "application/json",
    "stderr": "application/octet-stream",
    "owned-response-request": "application/octet-stream",
    "owned-response-headers": "application/octet-stream",
    "owned-response-body": "text/html; charset=utf-8",
    "owned-response-wire": "application/octet-stream",
    "owned-response-receipt": "application/json",
}
_MAXIMUM = {
    "stdout": 8192,
    "stderr": 0,
    "owned-response-request": 1024,
    "owned-response-headers": 16384,
    "owned-response-body": 65536,
    "owned-response-wire": 81920,
    "owned-response-receipt": MAX_RECEIPT_BYTES,
}
_KEYS = ("stdout", "stderr", "request", "headers", "body", "response")
_ROLES = (
    "stdout",
    "stderr",
    "owned-response-request",
    "owned-response-headers",
    "owned-response-body",
    "owned-response-wire",
)


def Canonical(value: object) -> bytes:
    """Encode finite canonical contract JSON without automatic secret collection.

    Args:
        value: Explicit admitted JSON-compatible value.

    Returns:
        Compact sorted UTF-8 JSON bytes.
    """

    return SerializeContract(value).encode("utf-8")


def ParseCanonical(raw: bytes, maximum: int) -> dict[str, object]:
    """Bound and strictly decode one canonical control or receipt document.

    Args:
        raw: Original selected bytes.
        maximum: Inclusive byte ceiling before parsing.

    Returns:
        Detached canonical object with finite values and unique keys.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise ValueError("owned response JSON bound differs")

    try:
        value = json.loads(raw, object_pairs_hook=UniqueObject)
        pending: list[tuple[object, int]] = [(value, 1)]
        nodes = 0

        while pending:
            item, depth = pending.pop()
            nodes += 1

            if nodes > 100000 or depth > 20:
                raise ValueError("owned response JSON tree bound differs")

            if isinstance(item, dict):
                for key, child in item.items():
                    key.encode("utf-8", errors="strict")
                    pending.append((child, depth + 1))

            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)

            elif isinstance(item, str):
                item.encode("utf-8", errors="strict")

        if type(value) is not dict or Canonical(value) != raw:
            raise ValueError("owned response JSON is noncanonical")

    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        raise ValueError("owned response JSON is unadmitted") from None

    return cast(dict[str, object], value)


def DirectoryIdentity(path: Path) -> tuple[int, int, int, int, int]:
    """Observe stable private directory facts without self-write timestamp false positives.

    Args:
        path: Explicit physical absolute directory.

    Returns:
        Device, inode, kind, owner and private mode.
    """

    info = ArtifactPathInfo(path, directory=True)

    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_ino == 0:
        raise ValueError("owned response directory is not private")

    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        stat.S_IMODE(info.st_mode),
    )


def NoFollowFlag() -> int:
    """Require the supported private-file platform before looking up its Linux-only flag.

    Returns:
        Original Linux no-follow open flag, without an unsafe portable fallback.
    """

    if sys.platform != "linux":
        raise ValueError("owned response private staging requires Linux")

    return cast(int, getattr(os, "O_NOFOLLOW"))


def ReadPrivate(path: Path, maximum: int) -> bytes:
    """Read only a bounded original singly linked private file with stable physical identity.

    Args:
        path: Explicit selected staging file.
        maximum: Inclusive size ceiling.

    Returns:
        Original bytes after before/open/after checks.
    """

    before = ArtifactPathInfo(path)

    if before.st_size > maximum or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("owned response staging file bound or mode differs")

    descriptor = os.open(path, os.O_RDONLY | NoFollowFlag())

    with os.fdopen(descriptor, "rb") as stream:
        opened = ArtifactHandleInfo(stream.fileno())
        raw = stream.read(maximum + 1)
        after = ArtifactHandleInfo(stream.fileno())

    if (
        len(raw) > maximum
        or PhysicalIdentity(before) != PhysicalIdentity(opened)
        or (
            PhysicalIdentity(opened) != PhysicalIdentity(after)
            or PhysicalIdentity(after) != PhysicalIdentity(ArtifactPathInfo(path))
        )
    ):
        raise ValueError("owned response staging changed during read")

    return raw


class OwnedResponseEvidenceStore(LocalEvidenceStore):
    """Apply closed role/media/byte admission before the inherited Get performs a blob read."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read exact permitted original evidence through the existing immutable owner.

        Args:
            reference: Original canonical reference to one closed acquisition role.

        Returns:
            Verified bounded bytes from the existing store.
        """

        if (
            type(reference) is not EvidenceReference
            or reference.role not in _MEDIA
            or (
                reference.media_type != _MEDIA[reference.role]
                or type(reference.size_bytes) is not int
                or not 0 <= reference.size_bytes <= _MAXIMUM[reference.role]
            )
        ):
            raise ValueError("owned response evidence role or bound differs")

        return super().Read(reference)


def ValidateRequest(value: dict[str, object], url: str) -> None:
    """Validate historical full fixed-request structure without consulting launch authority.

    Args:
        value: Canonical existing LocalExecutionRequest projection.
        url: Exact original selected URL.
    """

    Destination(url)
    invocation = cast(dict[str, object], value.get("invocation"))
    authorization = cast(dict[str, object], value.get("authorization"))
    workspace = value.get("workspace")
    environment = cast(dict[str, object], value.get("environment"))

    if (
        set(value)
        != {"invocation", "capability", "authorization", "workspace", "environment", "resources"}
        or type(invocation) is not dict
        or (
            type(authorization) is not dict
            or type(environment) is not dict
            or type(workspace) is not str
            or re.fullmatch(r"owned-response-[0-9a-f]{32}/work", workspace) is None
        )
    ):
        raise ValueError("owned response full request differs")

    argv = invocation.get("argv")

    if (
        type(argv) is not list
        or len(argv) != 6
        or type(argv[0]) is not str
        or (not PurePosixPath(argv[0]).is_absolute() or len(argv[0]) > 4096)
    ):
        raise ValueError("owned response installed recipe differs")

    expected_invocation = {
        "adapter_id": PROVIDER_ID,
        "request": {
            "capability": CAPABILITY_ID,
            "target_reference": Target(TargetKind.URL, url).Reference(),
            "impact": "SAFE",
            "parameters": {"url": url},
            "credential_references": [],
        },
        "argv": [argv[0], "-I", "-B", "-m", "fuzzy1337.owned_response_capture_worker", url],
        "timeout_seconds": 10,
        "provider_version": "1",
    }
    expected_capability = {
        "identifier": CAPABILITY_ID,
        "adapter_id": PROVIDER_ID,
        "maximum_impact": "SAFE",
        "required_privileges": [],
    }
    expected_resources = {
        "max_stdout_bytes": 8192,
        "max_stderr_bytes": 1,
        "terminate_grace_seconds": 0.5,
    }
    temp = environment.get("TEMP")

    if (
        type(temp) is not str
        or not PurePosixPath(temp).is_absolute()
        or (not temp.endswith("/" + workspace) or ".." in PurePosixPath(temp).parts)
    ):
        raise ValueError("owned response private environment differs")

    expected_environment = {
        key: "" for key in ("PATH", "COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR")
    }
    expected_environment.update(LANG="C", LC_ALL="C", TEMP=temp, TMP=temp)

    if Canonical(invocation) != Canonical(expected_invocation) or (
        Canonical(value["capability"]) != Canonical(expected_capability)
        or Canonical(value["resources"]) != Canonical(expected_resources)
        or Canonical(environment) != Canonical(expected_environment)
        or set(authorization)
        != {
            "authorization_id",
            "scope_reference",
            "policy_reference",
            "invocation_sha256",
            "granted_privileges",
        }
        or authorization["granted_privileges"] != []
        or authorization["invocation_sha256"] != hashlib.sha256(Canonical(invocation)).hexdigest()
    ):
        raise ValueError("owned response fixed request projection differs")

    for key in ("authorization_id", "scope_reference", "policy_reference"):
        text = authorization[key]

        if type(text) is not str or not 1 <= len(text) <= 512 or any(c in text for c in "\r\n\x00"):
            raise ValueError("owned response authorization attribution differs")


def ValidateControlResult(result: LocalExecutionResult) -> None:
    """Verify finite actual terminal controls without retaining unadmitted stream content.

    Args:
        result: Original executor return, never a reconstructed successful result.
    """

    if (
        type(result) is not LocalExecutionResult
        or type(result.execution) is not AdapterExecution
        or (
            type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or len(result.stdout) > 8192
            or len(result.stderr) > 1
            or type(result.events) is not tuple
            or not 1 <= len(result.events) <= 8195
            or type(result.termination) is not ExecutionTermination
        )
    ):
        raise ValueError("owned response actual control result differs")

    AdapterExecution(
        result.execution.state, result.execution.exit_code, result.execution.duration_seconds
    )
    allowed = {
        ExecutionTermination.PROCESS_EXIT: {ExecutionState.SUCCEEDED, ExecutionState.FAILED},
        ExecutionTermination.TIMEOUT: {ExecutionState.TIMED_OUT},
        ExecutionTermination.OUTPUT_LIMIT: {ExecutionState.CANCELLED},
        ExecutionTermination.CANCELLATION: {ExecutionState.CANCELLED},
    }

    if result.execution.state not in allowed[result.termination]:
        raise ValueError("owned response actual terminal state contradicts termination")

    joined: dict[ExecutionEventKind, list[bytes]] = {
        ExecutionEventKind.STDOUT: [],
        ExecutionEventKind.STDERR: [],
    }

    for sequence, event in enumerate(result.events):
        if (
            type(event) is not ExecutionEvent
            or type(event.sequence) is not int
            or (
                event.sequence != sequence
                or type(event.kind) is not ExecutionEventKind
                or type(event.data) is not bytes
            )
        ):
            raise ValueError("owned response actual control event differs")

        ExecutionEvent(event.sequence, event.kind, event.data, event.termination)

        if event.kind in joined:
            joined[event.kind].append(event.data)

        elif event.kind is ExecutionEventKind.STARTED and sequence != 0:
            raise ValueError("owned response actual start control differs")

        elif event.kind is ExecutionEventKind.COMPLETED and sequence != len(result.events) - 1:
            raise ValueError("owned response actual completion control differs")

    if result.events[-1].kind is not ExecutionEventKind.COMPLETED or (
        result.events[-1].termination is not result.termination
        or b"".join(joined[ExecutionEventKind.STDOUT]) != result.stdout
        or b"".join(joined[ExecutionEventKind.STDERR]) != result.stderr
    ):
        raise ValueError("owned response original control association differs")


def ValidateResult(result: LocalExecutionResult, url: str) -> dict[str, object]:
    """Admit actual original event fragments and terminal record before content publication.

    Args:
        result: Actual terminal executor return.
        url: Original selected URL.

    Returns:
        Fully admitted success or closed safe refusal record.
    """

    if (
        type(result) is not LocalExecutionResult
        or type(result.stdout) is not bytes
        or (
            type(result.stderr) is not bytes
            or result.stderr
            or len(result.stdout) > 8192
            or type(result.events) is not tuple
            or not 2 <= len(result.events) <= 8195
            or result.termination is not ExecutionTermination.PROCESS_EXIT
        )
    ):
        raise ValueError("owned response execution is unadmitted")

    streams: dict[ExecutionEventKind, list[bytes]] = {
        ExecutionEventKind.STDOUT: [],
        ExecutionEventKind.STDERR: [],
    }

    for sequence, event in enumerate(result.events):
        if (
            type(event) is not ExecutionEvent
            or type(event.sequence) is not int
            or (event.sequence != sequence or type(event.data) is not bytes)
        ):
            raise ValueError("owned response actual event shape differs")

        ExecutionEvent(event.sequence, event.kind, event.data, event.termination)

        if event.kind in streams:
            streams[event.kind].append(event.data)

        elif event.kind is ExecutionEventKind.STARTED:
            if sequence != 0:
                raise ValueError("owned response lifecycle differs")

        elif event.kind is ExecutionEventKind.COMPLETED and sequence != len(result.events) - 1:
            raise ValueError("owned response lifecycle differs")

    if result.events[0].kind is not ExecutionEventKind.STARTED or (
        result.events[-1].kind is not ExecutionEventKind.COMPLETED
        or result.events[-1].termination is not result.termination
        or b"".join(streams[ExecutionEventKind.STDOUT]) != result.stdout
        or b"".join(streams[ExecutionEventKind.STDERR]) != result.stderr
    ):
        raise ValueError("owned response actual stream association differs")

    record = ParseOwnedResponseCapture(result.stdout, url)
    refused = record["outcome"] == "refused"

    if result.execution.exit_code != (2 if refused else 0) or (
        result.execution.state
        is not (ExecutionState.FAILED if refused else ExecutionState.SUCCEEDED)
    ):
        raise ValueError("owned response original terminal status differs")

    return record


@dataclass(frozen=True, slots=True)
class OwnedResponseCapture:
    """Original acknowledged capture facts; retained stage never implies product persistence."""

    request: LocalExecutionRequest
    outcome: LocalExecutionResult | None
    stage: Path
    records: tuple[EvidenceRecord, ...]
    receipt_id: str | None
    refusal: str | None


@dataclass(frozen=True, slots=True)
class OwnedResponseReconciliation:
    """Storage observations and real original job acknowledgements remain distinct."""

    stored_ids: tuple[str, ...]
    acknowledged_ids: tuple[str, ...]
    unknown_ids: tuple[str, ...]
    absent_ids: tuple[str, ...] = ()
    unverifiable_ids: tuple[str, ...] = ()


class OwnedResponseStage:
    """Own two bounded private recovery files, never an authority or alternative evidence store."""

    def __init__(self, directory: Path, source: dict[str, object]) -> None:
        """Freeze admitted facts and complete intent plan before any canonical Put.

        Args:
            directory: Original private operation directory.
            source: Only fully admitted original bytes or safe control facts.
        """

        self.directory = directory
        self.identity = DirectoryIdentity(directory)
        self.frames = 0
        self._log_bytes = b""
        raw = Canonical(source)

        if len(raw) > MAX_PUBLICATION_BYTES:
            raise ValueError("owned response admitted staging exceeds its bound")

        self.WriteExclusive(directory / "admitted.json", raw)
        self.WriteExclusive(directory / "publication.log", b"")
        info = ArtifactPathInfo(directory / "publication.log")
        self._log_identity = (info.st_dev, info.st_ino)
        self._source_identity = PhysicalIdentity(ArtifactPathInfo(directory / "admitted.json"))
        self.Append(
            {
                "kind": "header",
                "directory_identity": self.identity,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "source_size_bytes": len(raw),
                "workspace_id": source["workspace_id"],
                "owner_reference": source["owner_reference"],
                "operation": directory.name,
            }
        )

    def Check(self) -> None:
        """Refuse private-directory replacement before any read or append."""

        if DirectoryIdentity(self.directory) != self.identity:
            raise ValueError("owned response stage directory changed")

    def WriteExclusive(self, path: Path, raw: bytes) -> None:
        """Write/fsync/read back one original exclusive private file.

        Args:
            path: One fixed child of the owning private operation directory.
            raw: Already bounded admitted content.
        """

        self.Check()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NoFollowFlag(), 0o600)

        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        if ReadPrivate(path, max(len(raw), 1)) != raw:
            raise ValueError("owned response stage readback differs")

    def Append(self, frame: dict[str, object]) -> None:
        """Append one finite durable frame without repair or retry.

        Args:
            frame: One fixed control header, intent, original ack or final status.
        """

        self.Check()
        path = self.directory / "publication.log"
        info = ArtifactPathInfo(path)

        if (info.st_dev, info.st_ino) != self._log_identity or (
            PhysicalIdentity(ArtifactPathInfo(self.directory / "admitted.json"))
            != self._source_identity
        ):
            raise ValueError("owned response original staging file changed")

        before = ReadPrivate(path, MAX_LOG_BYTES)

        if before != self._log_bytes:
            raise ValueError("owned response original log bytes changed")
        encoded = Canonical(frame)
        raw = len(encoded).to_bytes(4, "big") + encoded

        if self.frames >= 16 or len(raw) > 8192 or len(before) + len(raw) > MAX_LOG_BYTES:
            raise ValueError("owned response publication log bound differs")

        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | NoFollowFlag())

        with os.fdopen(descriptor, "wb") as stream:
            if PhysicalIdentity(ArtifactHandleInfo(stream.fileno())) != PhysicalIdentity(
                ArtifactPathInfo(path)
            ):
                raise ValueError("owned response publication log changed")

            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        if ReadPrivate(path, MAX_LOG_BYTES) != before + raw:
            raise ValueError("owned response publication log readback differs")

        self._log_bytes = before + raw
        self.frames += 1


def VerifyEvidence(
    store: OwnedResponseEvidenceStore,
    record: EvidenceRecord,
    expected: bytes,
    provenance: EvidenceProvenance,
    role: str,
) -> None:
    """Authenticate the exact original returned manifest, not an equal blob or candidate ID.

    Args:
        store: Existing bounded canonical owner.
        record: Actual original returned evidence record.
        expected: Already admitted bytes.
        provenance: Exact frozen collection attribution.
        role: Fixed permitted role.
    """

    if (
        type(record) is not EvidenceRecord
        or type(record.reference) is not EvidenceReference
        or type(record.provenance) is not EvidenceProvenance
        or type(record.schema_version) is not int
        or record.schema_version != 1
        or record.reference.role != role
        or (
            record.provenance != provenance
            or record.reference.media_type != _MEDIA[role]
            or record.reference.sha256 != hashlib.sha256(expected).hexdigest()
            or record.reference.size_bytes != len(expected)
            or EvidenceRecord(record.reference, record.provenance) != record
            or store.Get(record.evidence_id) != record
            or store.Read(record.reference) != expected
        )
    ):
        raise ValueError("owned response original evidence association differs")


def Receipt(
    request: LocalExecutionRequest,
    result: LocalExecutionResult,
    provenance: EvidenceProvenance,
    owner: str,
    ids: dict[str, str | None],
    refusal: str | None,
    *,
    complete: bool,
) -> dict[str, object]:
    """Project actual admitted bytes or safe control only, never rejected content hashes.

    Args:
        request: Original fixed request.
        result: Actual terminal result.
        provenance: Original frozen attribution.
        owner: Executing job owner.
        ids: Real original acknowledgements or all-null control association.
        refusal: Fixed owner or worker classification.
        complete: Full admitted record/result association, independent of product persistence.

    Returns:
        Closed canonical receipt projection.
    """

    events = []

    for event in result.events:
        row: dict[str, object] = {
            "sequence": event.sequence,
            "kind": event.kind,
            "termination": event.termination,
        }
        row["data_hex" if complete else "data_size_bytes"] = (
            event.data.hex() if complete else len(event.data)
        )
        events.append(row)

    return ParseCanonical(
        Canonical(
            {
                "schema_version": 1,
                "profile": RECEIPT_PROFILE,
                "custody": "complete" if complete else "control-only",
                "workspace_id": provenance.workspace_id,
                "owner_reference": owner,
                "started_at": provenance.started_at,
                "finished_at": provenance.finished_at,
                "request": request,
                "execution": result.execution,
                "termination": result.termination,
                "events": events,
                "evidence_ids": ids,
                "refusal": refusal,
            }
        ),
        MAX_RECEIPT_BYTES,
    )


def PublishCapture(
    context: JobContext,
    store: OwnedResponseEvidenceStore,
    directory: Path,
    request: LocalExecutionRequest,
    result: LocalExecutionResult,
    provenance: EvidenceProvenance,
    *,
    admitted: dict[str, object] | None,
    refusal: str | None,
) -> OwnedResponseCapture:
    """Stage before Put and publish a receipt only after all actual predecessor acknowledgements.

    Args:
        context: Original running job owner.
        store: Existing bounded canonical evidence store.
        directory: Original private operation directory, retained for future persistence ack.
        request: Exact fixed original request.
        result: Actual original terminal result.
        provenance: Frozen original collection metadata.
        admitted: Complete admitted record, absent for unsafe/incomplete output.
        refusal: Fixed safe refusal classification.

    Returns:
        Original acknowledged records and receipt, or truthful partial custody.
    """

    pieces: list[tuple[str, bytes]] = []
    ids: dict[str, str | None] = dict.fromkeys(_KEYS)

    if admitted is not None:
        pieces = [("stdout", result.stdout), ("stderr", result.stderr)]

        if admitted["outcome"] == "captured":
            url = cast(str, admitted["url"])
            headers, body = ReviewedResponse(Destination(url)[4])
            pieces += [
                ("owned-response-request", RequestBytes(url)),
                ("owned-response-headers", headers),
                ("owned-response-body", body),
                ("owned-response-wire", headers + body),
            ]

    candidates = []

    for role, raw in pieces:
        candidate = EvidenceRecord(
            EvidenceReference(
                role,
                "blobs/sha256/" + hashlib.sha256(raw).hexdigest(),
                hashlib.sha256(raw).hexdigest(),
                _MEDIA[role],
                len(raw),
            ),
            provenance,
        )
        candidates.append(
            {
                "manifest": candidate.ToDict(),
                "candidate_id": candidate.evidence_id,
                "base64": base64.b64encode(raw).decode("ascii"),
            }
        )
        ids[_KEYS[_ROLES.index(role)]] = candidate.evidence_id

    planned = Receipt(
        request,
        result,
        provenance,
        context.Spec.owner_reference,
        ids,
        refusal,
        complete=admitted is not None,
    )
    receipt_raw = Canonical(planned)
    total = sum(len(raw) for _, raw in pieces) + len(receipt_raw)

    if total > MAX_PUBLICATION_BYTES or len(pieces) + 1 > 8:
        raise ValueError("owned response aggregate publication bound differs")

    receipt_candidate = EvidenceRecord(
        EvidenceReference(
            "owned-response-receipt",
            "blobs/sha256/" + hashlib.sha256(receipt_raw).hexdigest(),
            hashlib.sha256(receipt_raw).hexdigest(),
            "application/json",
            len(receipt_raw),
        ),
        provenance,
    )
    candidates.append(
        {
            "manifest": receipt_candidate.ToDict(),
            "candidate_id": receipt_candidate.evidence_id,
            "base64": base64.b64encode(receipt_raw).decode("ascii"),
        }
    )
    stage = OwnedResponseStage(
        directory,
        {
            "schema_version": 1,
            "workspace_id": provenance.workspace_id,
            "owner_reference": context.Spec.owner_reference,
            "job_id": context.Spec.job_id,
            "plan": candidates,
        },
    )
    records: list[EvidenceRecord] = []

    try:
        for item in candidates:
            manifest = cast(dict[str, object], item["manifest"])
            reference = cast(dict[str, object], manifest["reference"])
            role = cast(str, reference["role"])
            raw = base64.b64decode(cast(str, item["base64"]), validate=True)
            stage.Append({"kind": "intent", "role": role, "candidate_id": item["candidate_id"]})
            original = context.CaptureEvidence(raw, role, _MEDIA[role], provenance).evidence
            VerifyEvidence(store, original, raw, provenance, role)

            if original.evidence_id != item["candidate_id"]:
                raise ValueError("owned response returned manifest differs from staged intent")

            records.append(original)
            stage.Append({"kind": "ack", "role": role, "original_id": original.evidence_id})

        stage.Append({"kind": "finished", "custody": "acknowledged"})

    except Exception:
        return OwnedResponseCapture(
            request,
            result if admitted is not None else None,
            directory,
            tuple(records),
            None,
            "custody-incomplete",
        )

    return OwnedResponseCapture(
        request,
        result if admitted is not None else None,
        directory,
        tuple(records),
        records[-1].evidence_id,
        refusal,
    )


def ReconcileOwnedResponse(
    directory: Path, store: OwnedResponseEvidenceStore, snapshot: JobSnapshot | None = None
) -> OwnedResponseReconciliation:
    """Verify known staged objects read-only without recovering an unreturned acknowledgement.

    Args:
        directory: Original private operation directory, never discovered by enumeration.
        store: Existing bounded canonical store.
        snapshot: Actual original coordinator snapshot, absent across unknown job restart.

    Returns:
        Storage and original attachment observations, kept independently truthful.
    """

    identity = DirectoryIdentity(directory)
    raw = ReadPrivate(directory / "admitted.json", MAX_PUBLICATION_BYTES)
    source = ParseCanonical(raw, MAX_PUBLICATION_BYTES)
    log = ReadPrivate(directory / "publication.log", MAX_LOG_BYTES)
    offset = 0
    frames: list[dict[str, object]] = []

    while offset < len(log):
        if offset + 4 > len(log):
            raise ValueError("owned response publication frame is partial")

        length = int.from_bytes(log[offset : offset + 4], "big")
        offset += 4

        if not 1 <= length <= 8188 or offset + length > len(log) or len(frames) >= 16:
            raise ValueError("owned response publication frame bound differs")

        frames.append(ParseCanonical(log[offset : offset + length], 8188))
        offset += length

    if not frames or frames[0] != {
        "kind": "header",
        "directory_identity": list(identity),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_size_bytes": len(raw),
        "workspace_id": source.get("workspace_id"),
        "owner_reference": source.get("owner_reference"),
        "operation": directory.name,
    }:
        raise ValueError("owned response stage header association differs")

    plan = source.get("plan")

    if type(plan) is not list or not 1 <= len(plan) <= 7:
        raise ValueError("owned response staged plan differs")

    expected_roles = (
        _ROLES + ("owned-response-receipt",)
        if len(plan) == 7
        else ("stdout", "stderr", "owned-response-receipt")
        if len(plan) == 3
        else ("owned-response-receipt",)
        if len(plan) == 1
        else ()
    )

    if not expected_roles or set(source) != {
        "schema_version",
        "workspace_id",
        "owner_reference",
        "job_id",
        "plan",
    }:
        raise ValueError("owned response closed stage plan differs")

    completed = 0
    stored = []
    acknowledged = []
    unknown = []
    absent = []
    unverifiable = []
    cursor = 1

    for index, item in enumerate(plan):
        if type(item) is not dict or set(item) != {"manifest", "candidate_id", "base64"}:
            raise ValueError("owned response stage item differs")

        from fuzzy1337.evidence import ParseEvidenceManifest

        expected = ParseEvidenceManifest(Canonical(item["manifest"]))
        if expected.reference.role != expected_roles[index]:
            raise ValueError("owned response staged role order differs")

        candidate_id = item["candidate_id"]
        if type(item["base64"]) is not str:
            raise ValueError("owned response staged byte encoding differs")

        original = base64.b64decode(item["base64"], validate=True)

        if base64.b64encode(original).decode("ascii") != item["base64"] or (
            expected.reference.size_bytes != len(original)
            or expected.reference.sha256 != hashlib.sha256(original).hexdigest()
        ):
            raise ValueError("owned response staged original bytes differ")

        if candidate_id != expected.evidence_id or len(original) > _MAXIMUM.get(
            expected.reference.role, -1
        ):
            raise ValueError("owned response staged original bound differs")

        if cursor < len(frames) and frames[cursor].get("kind") == "intent":
            if frames[cursor] != {
                "kind": "intent",
                "role": expected.reference.role,
                "candidate_id": candidate_id,
            }:
                raise ValueError("owned response publication intent differs")

            cursor += 1

            if cursor < len(frames) and frames[cursor].get("kind") == "ack":
                if frames[cursor] != {
                    "kind": "ack",
                    "role": expected.reference.role,
                    "original_id": candidate_id,
                }:
                    raise ValueError("owned response original ack differs")

                cursor += 1
                completed += 1

            elif cursor < len(frames):
                raise ValueError("owned response missing original ack before later frame")

        try:
            VerifyEvidence(store, expected, original, expected.provenance, expected.reference.role)

        except EvidenceNotFoundError:
            unknown.append(cast(str, candidate_id))
            absent.append(cast(str, candidate_id))

        except (OSError, ValueError, RuntimeError):
            unknown.append(cast(str, candidate_id))
            unverifiable.append(cast(str, candidate_id))

        else:
            stored.append(cast(str, candidate_id))

        if (
            snapshot is not None
            and snapshot.spec.owner_reference == source["owner_reference"]
            and (
                snapshot.spec.workspace_id == source["workspace_id"]
                and snapshot.spec.job_id == source["job_id"]
                and snapshot.spec.provider_id == PROVIDER_ID
                and any(artifact.evidence == expected for artifact in snapshot.artifacts)
            )
        ):
            acknowledged.append(cast(str, candidate_id))

    if cursor < len(frames) and frames[cursor] == {"kind": "finished", "custody": "acknowledged"}:
        if completed != len(plan):
            raise ValueError("owned response finished without every original ack")

        cursor += 1

    if cursor != len(frames) or DirectoryIdentity(directory) != identity:
        raise ValueError("owned response publication order or directory differs")

    return OwnedResponseReconciliation(
        tuple(stored), tuple(acknowledged), tuple(unknown), tuple(absent), tuple(unverifiable)
    )


@dataclass(frozen=True, slots=True)
class OwnedResponseReplay:
    """Verified historical acquisition facts, with no current authority or assessment claim."""

    record_json: bytes
    receipt_id: str
    original_ids: tuple[str, ...]


def ReplayOwnedResponseCapture(
    store: OwnedResponseEvidenceStore, receipt_id: str
) -> OwnedResponseReplay:
    """Reopen original acknowledged receipt/parts offline after an explicit workspace relocation.

    Args:
        store: Explicit relocated existing bounded canonical evidence owner.
        receipt_id: Original actually acknowledged receipt ID supplied by the owning caller.

    Returns:
        Verified original record and manifest IDs without network, Java, Save or re-Put.
    """

    # Storage integrity cannot establish a missing original Put/attachment acknowledgement.
    # Actual original IDs remain required; Reconcile.stored_ids cannot upgrade that precondition.
    from fuzzy1337.adapters import AdapterExecution

    receipt = store.Get(receipt_id)

    if receipt.reference.role != "owned-response-receipt":
        raise ValueError("owned response original receipt role differs")

    value = ParseCanonical(store.Read(receipt.reference), MAX_RECEIPT_BYTES)
    expected_keys = {
        "schema_version",
        "profile",
        "custody",
        "workspace_id",
        "owner_reference",
        "started_at",
        "finished_at",
        "request",
        "execution",
        "termination",
        "events",
        "evidence_ids",
        "refusal",
    }

    if (
        set(value) != expected_keys
        or type(value["schema_version"]) is not int
        or (
            value["schema_version"] != 1
            or value["profile"] != RECEIPT_PROFILE
            or value["custody"] != "complete"
            or type(value["request"]) is not dict
            or type(value["events"]) is not list
            or not 2 <= len(value["events"]) <= 8195
            or type(value["evidence_ids"]) is not dict
        )
    ):
        raise ValueError("owned response receipt is not complete original custody")

    request = cast(dict[str, object], value["request"])
    invocation = cast(dict[str, object], request.get("invocation", {}))
    if type(invocation) is not dict:
        raise ValueError("owned response historical invocation is not an object")

    args = cast(list[object], invocation.get("argv", []))
    url = cast(str, args[-1]) if args else ""
    ValidateRequest(request, url)
    ids = cast(dict[str, object], value["evidence_ids"])

    if set(ids) != set(_KEYS):
        raise ValueError("owned response receipt original ID fields differ")

    originals: dict[str, EvidenceRecord] = {}
    content: dict[str, bytes] = {}

    for key, role in zip(_KEYS, _ROLES, strict=True):
        if ids[key] is None and key not in {"stdout", "stderr"}:
            continue

        original = store.Get(cast(str, ids[key]))

        if original.reference.role != role or original.provenance != receipt.provenance:
            raise ValueError("owned response original manifest association differs")

        originals[key] = original
        content[key] = store.Read(original.reference)

    execution_data = cast(dict[str, object], value["execution"])

    if type(execution_data) is not dict or set(execution_data) != {
        "state",
        "exit_code",
        "duration_seconds",
    }:
        raise ValueError("owned response original execution differs")

    execution = AdapterExecution(
        ExecutionState(cast(str, execution_data["state"])),
        cast(int | None, execution_data["exit_code"]),
        cast(float, execution_data["duration_seconds"]),
    )
    events = []

    for row in cast(list[dict[str, object]], value["events"]):
        if (
            type(row) is not dict
            or set(row) != {"sequence", "kind", "data_hex", "termination"}
            or (type(row["data_hex"]) is not str)
        ):
            raise ValueError("owned response original receipt event differs")

        raw = bytes.fromhex(row["data_hex"])

        if raw.hex() != row["data_hex"]:
            raise ValueError("owned response original fragment encoding differs")

        termination = (
            None
            if row["termination"] is None
            else ExecutionTermination(cast(str, row["termination"]))
        )
        events.append(
            ExecutionEvent(
                cast(int, row["sequence"]),
                ExecutionEventKind(cast(str, row["kind"])),
                raw,
                termination,
            )
        )

    result = LocalExecutionResult(
        execution,
        ExecutionTermination(cast(str, value["termination"])),
        content["stdout"],
        content["stderr"],
        tuple(events),
    )
    record = ValidateResult(result, url)
    provenance = receipt.provenance
    expected_provenance = EvidenceProvenance(
        cast(str, value["workspace_id"]),
        cast(str, cast(dict[str, object], request["authorization"])["scope_reference"]),
        PROVIDER_ID,
        "1",
        "1",
        cast(str, value["started_at"]),
        cast(str, value["finished_at"]),
        hashlib.sha256(Canonical(invocation)).hexdigest(),
        execution,
    )

    if provenance != expected_provenance or value["refusal"] != record.get("error"):
        raise ValueError("owned response receipt attribution or refusal differs")

    if record["outcome"] == "captured":
        headers, body = ReviewedResponse(Destination(url)[4])
        expected_parts = {
            "request": RequestBytes(url),
            "headers": headers,
            "body": body,
            "response": headers + body,
        }

        if any(content.get(key) != expected for key, expected in expected_parts.items()):
            raise ValueError("owned response original wire evidence differs")

    elif any(ids[key] is not None for key in ("request", "headers", "body", "response")):
        raise ValueError("owned response refused record has response association")

    return OwnedResponseReplay(
        result.stdout, receipt_id, tuple(original.evidence_id for original in originals.values())
    )
