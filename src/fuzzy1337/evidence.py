# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Immutable, attributable raw evidence in an operator-owned local directory."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fuzzy1337.adapters import (
    AdapterExecution,
    EvidenceReference,
    ExecutionState,
)
from fuzzy1337.adapters.contracts import RequireIdentifier, RequireText

EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_MANIFEST_MAX_BYTES = 1024 * 1024
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    """Base failure for reading or publishing local evidence."""


class EvidenceIntegrityError(EvidenceError):
    """Stored bytes, canonical metadata, or filesystem boundaries are inconsistent."""


class EvidenceNotFoundError(EvidenceError):
    """An expected raw artifact or manifest is absent."""


class EvidenceStorageError(EvidenceError):
    """The filesystem could not complete an evidence operation."""


def RequireEvidenceDigest(value: str) -> None:
    """Internal helper: require a lowercase digest without accepting path syntax.

    Args:
        value: Candidate lowercase SHA-256 digest.

    Raises:
        ValueError: The digest is invalid.
    """

    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError("evidence digest must be a lowercase SHA-256 digest")


def NormalizeEvidenceTime(value: str) -> str:
    """Internal helper: normalize offset-aware collection times to UTC.

    Args:
        value: Single-line ISO 8601 datetime with an explicit UTC offset.

    Returns:
        UTC ISO 8601 text with fixed microsecond precision.

    Raises:
        ValueError: The timestamp is invalid or lacks an offset.
        OverflowError: UTC conversion exceeds the datetime range.
    """

    RequireText(value, "collection timestamp")

    try:
        timestamp = datetime.fromisoformat(value)

    except ValueError as error:
        raise ValueError("collection timestamp must be an ISO 8601 datetime") from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("collection timestamp must include a UTC offset")

    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    """Explicit non-secret collection context, independent from interpretation.

    Scope references attribute collection; they do not authorize any operation.
    Times require UTC offsets and are stored in UTC. No environment, arguments,
    or credential values are collected automatically.
    """

    workspace_id: str
    scope_reference: str
    source_id: str
    source_version: str
    tool_version: str | None
    started_at: str
    finished_at: str
    invocation_sha256: str | None = None
    execution: AdapterExecution | None = None

    def __post_init__(self) -> None:
        """Validate attribution and freeze canonical collection times."""

        RequireText(self.workspace_id, "workspace_id")
        RequireText(self.scope_reference, "scope_reference")
        RequireIdentifier(self.source_id, "source_id")
        RequireText(self.source_version, "source_version")

        if self.tool_version is not None:
            RequireText(self.tool_version, "tool_version")

        started_at = NormalizeEvidenceTime(self.started_at)
        finished_at = NormalizeEvidenceTime(self.finished_at)

        if finished_at < started_at:
            raise ValueError("finished_at must not precede started_at")

        if self.invocation_sha256 is not None:
            RequireEvidenceDigest(self.invocation_sha256)

        if self.execution is not None:
            if not isinstance(self.execution, AdapterExecution):
                raise ValueError("execution must be an AdapterExecution or None")

            duration = self.execution.duration_seconds

            if (
                isinstance(duration, bool)
                or not isinstance(duration, (int, float))
                or not math.isfinite(duration)
                or duration < 0
            ):
                raise ValueError("execution duration must be a finite non-negative number")

        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "finished_at", finished_at)

    def ToDict(self) -> dict[str, object]:
        """Return detached schema-v1 metadata with no automatic secret collection.

        Returns:
            JSON-compatible provenance, including explicit terminal failure state.
        """

        execution = None

        if self.execution is not None:
            execution = {
                "state": self.execution.state.value,
                "exit_code": self.execution.exit_code,
                "duration_seconds": self.execution.duration_seconds,
            }

        return {
            "workspace_id": self.workspace_id,
            "scope_reference": self.scope_reference,
            "source_id": self.source_id,
            "source_version": self.source_version,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "invocation_sha256": self.invocation_sha256,
            "execution": execution,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A versioned immutable raw-content reference and collection provenance."""

    reference: EvidenceReference
    provenance: EvidenceProvenance
    schema_version: int = EVIDENCE_SCHEMA_VERSION
    evidence_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Bind identity to the canonical manifest, independently from content."""

        if type(self.schema_version) is not int or self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema_version")

        if not isinstance(self.reference, EvidenceReference):
            raise ValueError("reference must be an EvidenceReference")

        if not isinstance(self.provenance, EvidenceProvenance):
            raise ValueError("provenance must be an EvidenceProvenance")

        expected_locator = f"blobs/sha256/{self.reference.sha256}"

        if self.reference.locator != expected_locator:
            raise ValueError("reference locator must match the canonical content address")

        digest = hashlib.sha256(self.Serialize()).hexdigest()
        object.__setattr__(self, "evidence_id", f"sha256:{digest}")

    def ToDict(self) -> dict[str, object]:
        """Return detached JSON-compatible schema fields without interpretation.

        Returns:
            Version, five-field adapter reference, and collection provenance.
        """

        return {
            "schema_version": self.schema_version,
            "reference": {
                "role": self.reference.role,
                "locator": self.reference.locator,
                "sha256": self.reference.sha256,
                "media_type": self.reference.media_type,
                "size_bytes": self.reference.size_bytes,
            },
            "provenance": self.provenance.ToDict(),
        }

    def Serialize(self) -> bytes:
        """Return deterministic UTF-8 JSON used to derive the evidence identifier.

        Returns:
            Sorted compact JSON with no non-finite numbers or embedded raw bytes.
        """

        return json.dumps(
            self.ToDict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


def UniqueManifestObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Internal parser hook: reject duplicate JSON keys at every nesting level.

    Args:
        pairs: Ordered fields decoded by the standard JSON parser.

    Returns:
        Detached mapping containing each field once.

    Raises:
        ValueError: A JSON field occurs more than once.
    """

    values: dict[str, object] = {}

    for key, value in pairs:
        if key in values:
            raise ValueError("evidence manifest contains duplicate JSON keys")

        values[key] = value

    return values


def RejectManifestConstant(value: str) -> None:
    """Internal parser hook: reject NaN and infinities before schema validation.

    Args:
        value: Nonstandard numeric constant encountered by the JSON parser.

    Raises:
        ValueError: Always, because these constants are not valid JSON numbers.
    """

    raise ValueError(f"evidence manifest contains a non-JSON number: {value}")


def RequireManifestFields(value: object, expected: set[str]) -> dict[str, object]:
    """Internal parser helper: require exact fields without ignoring unknown values.

    Args:
        value: Decoded candidate schema object.
        expected: Complete schema-v1 field-name set for that object.

    Returns:
        The validated decoded dictionary, without coercion or ignored fields.

    Raises:
        ValueError: The object type or field set does not match.
    """

    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("evidence manifest fields do not match schema version 1")

    return value


def ParseEvidenceManifest(data: bytes) -> EvidenceRecord:
    """Validate one schema-v1 manifest without accessing a filesystem.

    Args:
        data: Canonical UTF-8 JSON manifest bytes.

    Returns:
        Immutable record whose identifier derives from its canonical manifest.

    Raises:
        ValueError: JSON, schema, provenance, or canonical encoding is invalid.
    """

    if not isinstance(data, bytes):
        raise ValueError("evidence manifest must be bytes")

    if len(data) > EVIDENCE_MANIFEST_MAX_BYTES:
        raise ValueError("evidence manifest exceeds the 1 MiB schema limit")

    try:
        value = json.loads(
            data, object_pairs_hook=UniqueManifestObject, parse_constant=RejectManifestConstant,
        )
        manifest = RequireManifestFields(value, {"schema_version", "reference", "provenance"})
        reference = RequireManifestFields(manifest["reference"], {
            "role", "locator", "sha256", "media_type", "size_bytes",
        })
        provenance = RequireManifestFields(manifest["provenance"], {
            "workspace_id", "scope_reference", "source_id", "source_version", "tool_version",
            "started_at", "finished_at", "invocation_sha256", "execution",
        })
        execution = provenance["execution"]
        parsed_execution = None

        if execution is not None:
            execution_fields = RequireManifestFields(
                execution, {"state", "exit_code", "duration_seconds"},
            )
            parsed_execution = AdapterExecution(
                state=ExecutionState(execution_fields["state"]),  # type: ignore[arg-type]
                exit_code=execution_fields["exit_code"],  # type: ignore[arg-type]
                duration_seconds=execution_fields["duration_seconds"],  # type: ignore[arg-type]
            )

        parsed_provenance = EvidenceProvenance(
            workspace_id=provenance["workspace_id"],  # type: ignore[arg-type]
            scope_reference=provenance["scope_reference"],  # type: ignore[arg-type]
            source_id=provenance["source_id"],  # type: ignore[arg-type]
            source_version=provenance["source_version"],  # type: ignore[arg-type]
            tool_version=provenance["tool_version"],  # type: ignore[arg-type]
            started_at=provenance["started_at"],  # type: ignore[arg-type]
            finished_at=provenance["finished_at"],  # type: ignore[arg-type]
            invocation_sha256=provenance["invocation_sha256"],  # type: ignore[arg-type]
            execution=parsed_execution,
        )
        record = EvidenceRecord(
            reference=EvidenceReference(**reference),  # type: ignore[arg-type]
            provenance=parsed_provenance,
            schema_version=manifest["schema_version"],  # type: ignore[arg-type]
        )

        if record.Serialize() != data:
            raise ValueError("evidence manifest must use canonical UTF-8 JSON")

        return record

    except (TypeError, UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError("evidence manifest contains invalid schema values") from error


def CheckStorageEntry(path: Path, directory: bool) -> os.stat_result:
    """Internal filesystem check: reject links/reparse points and invalid kinds.

    Args:
        path: Explicit owned root component or artifact path to inspect.
        directory: Whether the entry must be a directory rather than regular file.

    Returns:
        Observed lstat metadata without following a link at this entry.

    Raises:
        EvidenceIntegrityError: A link, reparse point, or invalid kind is observed.
        OSError: The metadata could not be read.
    """

    metadata = path.lstat()
    reparse_point = getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT

    if stat.S_ISLNK(metadata.st_mode) or reparse_point:
        raise EvidenceIntegrityError("evidence paths must not contain links or reparse points")

    correct_kind = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)

    if not correct_kind:
        raise EvidenceIntegrityError("evidence path has an unexpected filesystem object kind")

    return metadata


class LocalEvidenceStore:
    """Content-addressed storage in an explicit operator-owned physical directory.

    The existing root and ancestors must not be symlinks/reparse points. Callers
    own the root; hostile concurrent directory replacement is outside this local
    pathname contract. Cooperative writers publish atomically without overwrite.
    Construction performs no filesystem access. No indexes, findings, or secret
    discovery are added; callers explicitly provide authorized non-secret bytes.
    """

    def __init__(self, root: Path) -> None:
        """Retain an explicit root without creating or inspecting local state.

        Args:
            root: Existing physical evidence directory, possibly relative.

        Raises:
            ValueError: The supplied root includes traversal or is a filesystem root.
        """

        root = Path(root)

        if ".." in root.parts:
            raise ValueError("evidence root must not contain parent traversal")

        self.root = root.absolute()

        if self.root == self.root.parent:
            raise ValueError("evidence root must not be a filesystem root")

    def StoragePath(self, parts: tuple[str, ...], create: bool = False) -> Path:
        """Internal helper: validate the root and optionally create owned directories.

        Args:
            parts: Fixed internal relative path components, never untrusted paths.
            create: Whether to create missing owned partition directories.

        Returns:
            Artifact path beneath checked physical directories.

        Raises:
            EvidenceIntegrityError: An observed component is unsafe.
            OSError: A directory is absent, inaccessible, or cannot be created.
        """

        for ancestor in (*reversed(self.root.parents), self.root):
            CheckStorageEntry(ancestor, directory=True)

        parent = self.root

        for part in parts[:-1]:
            parent = parent / part

            if create:
                parent.mkdir(exist_ok=True)

            CheckStorageEntry(parent, directory=True)

        return parent / parts[-1]

    def ReadStoredBytes(self, parts: tuple[str, ...], max_bytes: int) -> bytes:
        """Internal helper: read safe paths within a known size ceiling.

        Args:
            parts: Fixed internal artifact path components.
            max_bytes: Maximum permitted byte length from the reference/schema.

        Returns:
            Artifact bytes bounded by the declared size ceiling.

        Raises:
            EvidenceIntegrityError: A path is unsafe or the file exceeds its limit.
            OSError: The filesystem cannot read the artifact.
        """

        path = self.StoragePath(parts)
        metadata = CheckStorageEntry(path, directory=False)

        if metadata.st_size > max_bytes:
            raise EvidenceIntegrityError("evidence file exceeds the expected size bound")

        with path.open("rb") as stream:
            data = stream.read(min(metadata.st_size, max_bytes) + 1)

        if len(data) > max_bytes:
            raise EvidenceIntegrityError("evidence file exceeds the expected size bound")

        return data

    def PublishStoredBytes(self, parts: tuple[str, ...], data: bytes) -> None:
        """Internal helper: publish complete bytes and verify every existing identity.

        Args:
            parts: Fixed internal content-addressed path components.
            data: Complete immutable artifact bytes to publish without overwrite.

        Raises:
            EvidenceIntegrityError: Existing identity or filesystem kinds conflict.
            OSError: Creation, fsync, hard-link publication, or cleanup failed.
        """

        target = self.StoragePath(parts, create=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.pending")

        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())

            try:
                os.link(temporary, target)

            except FileExistsError:
                if self.ReadStoredBytes(parts, len(data)) != data:
                    raise EvidenceIntegrityError("existing evidence identity has different bytes")

        finally:
            temporary.unlink(missing_ok=True)

    def Put(
        self, data: bytes, role: str, media_type: str, provenance: EvidenceProvenance,
    ) -> EvidenceRecord:
        """Publish immutable raw bytes followed by their versioned manifest.

        Args:
            data: Authorized non-secret raw bytes; no parsing or normalization.
            role: Existing adapter role identifier, such as stdout or stderr.
            media_type: Explicit payload media type.
            provenance: Immutable collection attribution, never authorization.

        Returns:
            Verified record usable by the unchanged adapter EvidenceReference.

        Raises:
            ValueError: Caller-supplied contract values are invalid.
            EvidenceError: A path is unsafe, identity is corrupt, or publication
                failed. A valid orphan blob may remain after manifest failure.
        """

        if not isinstance(data, bytes):
            raise ValueError("raw evidence must be bytes")

        digest = hashlib.sha256(data).hexdigest()
        record = EvidenceRecord(
            EvidenceReference(role, f"blobs/sha256/{digest}", digest, media_type, len(data)),
            provenance,
        )

        manifest_data = record.Serialize()

        if len(manifest_data) > EVIDENCE_MANIFEST_MAX_BYTES:
            raise ValueError("evidence manifest exceeds the 1 MiB schema limit")

        try:
            self.PublishStoredBytes(("blobs", "sha256", digest), data)
            self.PublishStoredBytes(("records", f"{record.evidence_id[7:]}.json"), manifest_data)

        except OSError as error:
            raise EvidenceStorageError("filesystem could not publish immutable evidence") from error

        return record

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read an adapter reference and verify exact address, digest, and length.

        Args:
            reference: Existing adapter contract with canonical evidence locator.

        Returns:
            Original raw bytes only after integrity verification succeeds.

        Raises:
            ValueError: The reference is invalid or uses a noncanonical locator.
            EvidenceError: Evidence is missing, unsafe, unreadable, or corrupt.
        """

        if not isinstance(reference, EvidenceReference):
            raise ValueError("reference must be an EvidenceReference")

        if reference.locator != f"blobs/sha256/{reference.sha256}":
            raise ValueError("reference locator must match the canonical content address")

        try:
            data = self.ReadStoredBytes(("blobs", "sha256", reference.sha256), reference.size_bytes)

        except FileNotFoundError as error:
            raise EvidenceNotFoundError("raw evidence is missing") from error

        except OSError as error:
            raise EvidenceStorageError("filesystem could not read raw evidence") from error

        if (
            len(data) != reference.size_bytes
            or hashlib.sha256(data).hexdigest() != reference.sha256
        ):
            raise EvidenceIntegrityError("raw evidence digest or length differs from its reference")

        return data

    def Get(self, evidence_id: str) -> EvidenceRecord:
        """Load a canonical manifest and verify its identity and referenced bytes.

        Args:
            evidence_id: Manifest identity in sha256:<lowercase digest> form.

        Returns:
            Immutable verified record, including unchanged adapter reference.

        Raises:
            ValueError: The supplied identity is invalid.
            EvidenceError: A manifest or blob is missing, unsafe, corrupt, or
                unreadable; unsupported schema versions are integrity failures.
        """

        if not isinstance(evidence_id, str) or not evidence_id.startswith("sha256:"):
            raise ValueError("evidence_id must be a SHA-256 manifest identity")

        digest = evidence_id[7:]
        RequireEvidenceDigest(digest)

        try:
            data = self.ReadStoredBytes(("records", f"{digest}.json"), EVIDENCE_MANIFEST_MAX_BYTES)
            record = ParseEvidenceManifest(data)

        except FileNotFoundError as error:
            raise EvidenceNotFoundError("evidence manifest is missing") from error

        except OSError as error:
            raise EvidenceStorageError("filesystem could not read evidence manifest") from error

        except ValueError as error:
            raise EvidenceIntegrityError("stored evidence manifest violates its schema") from error

        if record.evidence_id != evidence_id:
            raise EvidenceIntegrityError("manifest digest does not match the evidence identity")

        self.Read(record.reference)

        return record
