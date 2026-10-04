# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable experimental workspace metadata with explicit local persistence ownership."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from fuzzy1337.adapters.contracts import EvidenceReference, RequireIdentifier, RequireText

WORKSPACE_SCHEMA_VERSION = 1
MAX_STATE_BYTES = 1024 * 1024
PARTITION_NAMES = ("state", "evidence", "cache", "indexes")
EVIDENCE_RECORD_REFERENCE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class WorkspaceLens(StrEnum):
    """Select one initial view without creating another authoritative model."""

    PENTEST = "pentest"
    DFIR = "dfir"
    DEVSECOPS = "devsecops"
    PURPLE = "purple"


class WorkspaceConflictError(RuntimeError):
    """Reject a stale revision or an attempted change of workspace identity."""


class WorkspaceBusyError(RuntimeError):
    """Report an active or abandoned writer lock without stealing ownership."""


def RequireWorkspaceText(value: object, field_name: str) -> str:
    """Require single-line non-secret reference text without coercing types.

    Args:
        value: Candidate string; callers must provide references rather than secret values.
        field_name: Metadata field named in validation failures.

    Returns:
        Validated text without interpreting or resolving it.

    Raises:
        ValueError: The value is not a nonempty single-line string.
    """

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    RequireText(value, field_name)

    return value


def RequireWorkspaceInteger(value: object, field_name: str) -> int:
    """Require a non-negative integer and reject booleans or numeric coercion.

    Args:
        value: Candidate revision, schema version, or byte count.
        field_name: Metadata field named in validation failures.

    Returns:
        Validated non-negative integer without coercion.

    Raises:
        ValueError: The value is negative, boolean, or not an integer.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")

    return value


def WorkspaceReferences(value: object, field_name: str) -> tuple[str, ...]:
    """Validate an ordered reference collection without interpreting authorization.

    Args:
        value: List or tuple of non-secret opaque single-line references.
        field_name: Collection named in validation failures.

    Returns:
        Immutable references retaining declaration order.

    Raises:
        ValueError: The collection, a reference, or uniqueness is invalid.
    """

    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{field_name} must be a reference sequence")

    references = tuple(RequireWorkspaceText(item, field_name) for item in value)

    if len(set(references)) != len(references):
        raise ValueError(f"{field_name} must contain unique references")

    return references


def WorkspaceFields(value: object, expected: set[str], field_name: str) -> dict[str, object]:
    """Reject absent or unknown fields at one serialized object boundary.

    Args:
        value: Decoded candidate object.
        expected: Complete supported field set, without extension fields.
        field_name: Object boundary named in validation failures.

    Returns:
        Exact-field object ready for typed field validation.

    Raises:
        ValueError: The candidate is not an object or its keys differ.
    """

    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{field_name} must contain exactly {sorted(expected)}")

    return value


def UniqueWorkspaceObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys before any document value can be overwritten.

    Args:
        pairs: Object members supplied by the JSON decoder in source order.

    Returns:
        Object whose keys are proven unique.

    Raises:
        ValueError: A key is repeated, even when both values are identical.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate workspace JSON key: {key}")

        result[key] = value

    return result


def RejectWorkspaceConstant(value: str) -> object:
    """Reject Python's non-standard JSON numeric constants at decode time.

    Args:
        value: Non-standard constant token supplied by the JSON decoder.

    Returns:
        No value; constants are always rejected.

    Raises:
        ValueError: Every non-standard constant is outside the workspace schema.
    """

    raise ValueError(f"workspace JSON must not contain {value}")


def DecodeEvidenceReference(value: object) -> EvidenceReference:
    """Validate the existing evidence schema and a canonical partition-relative locator.

    Args:
        value: Existing SDK evidence fields, with a locator relative to evidence/.

    Returns:
        Typed immutable reference without reading or verifying artifact bytes.

    Raises:
        ValueError: Fields, types, digest, size, or locator syntax are invalid.
    """

    record = WorkspaceFields(
        value, {"role", "locator", "sha256", "media_type", "size_bytes"}, "evidence reference"
    )
    reference = EvidenceReference(
        role=RequireWorkspaceText(record["role"], "role"),
        locator=RequireWorkspaceText(record["locator"], "locator"),
        sha256=RequireWorkspaceText(record["sha256"], "sha256"),
        media_type=RequireWorkspaceText(record["media_type"], "media_type"),
        size_bytes=RequireWorkspaceInteger(record["size_bytes"], "size_bytes"),
    )
    locator = PurePosixPath(reference.locator)

    if str(locator) != reference.locator or not locator.parts or ":" in reference.locator:
        raise ValueError("evidence locator must be a canonical relative evidence path")

    return reference


def StoragePathInfo(path: Path) -> os.stat_result | None:
    """Reject observed symlinks/reparse points and return non-following path metadata.

    Args:
        path: Workspace root, ancestor, partition, or authoritative metadata path.

    Returns:
        Non-following metadata, or None for an absent path.

    Raises:
        ValueError: The observed path is a link or reparse point.
        OSError: Metadata cannot be inspected for another filesystem reason.
    """

    try:
        metadata = path.lstat()

    except FileNotFoundError:
        return None

    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise ValueError("workspace paths must not contain symlinks or reparse points")

    return metadata


def SyncStorageDirectory(path: Path) -> None:
    """Synchronize a POSIX directory; other platforms retain atomic file replacement.

    Args:
        path: Owned workspace directory or its parent during initial creation.

    Raises:
        OSError: The POSIX directory flag is unavailable, or directory opening,
            synchronization, or descriptor cleanup fails.
    """

    if os.name != "posix":
        return

    directory_flag = getattr(os, "O_DIRECTORY", None)

    if (
        isinstance(directory_flag, bool)
        or not isinstance(directory_flag, int)
        or directory_flag <= 0
    ):
        raise OSError("POSIX directory synchronization requires a valid O_DIRECTORY flag")

    directory_fd = os.open(path, os.O_RDONLY | directory_flag)

    try:
        os.fsync(directory_fd)

    finally:
        os.close(directory_fd)


@dataclass(frozen=True, slots=True)
class WorkspaceConfiguration:
    """Immutable local view configuration containing non-secret context references."""

    display_name: str
    selected_lens: WorkspaceLens = WorkspaceLens.PENTEST
    view_reference: str | None = None
    report_context_reference: str | None = None

    def __post_init__(self) -> None:
        """Validate explicit configuration without resolving references or secrets."""

        RequireWorkspaceText(self.display_name, "display_name")

        if not isinstance(self.selected_lens, WorkspaceLens):
            raise ValueError("selected_lens must be a WorkspaceLens")

        for field_name in ("view_reference", "report_context_reference"):
            value = getattr(self, field_name)

            if value is not None:
                RequireWorkspaceText(value, field_name)

    def ToDict(self) -> dict[str, object]:
        """Render configuration fields without exposing resolved context or credentials.

        Returns:
            Deterministic configuration data for the versioned workspace document.
        """

        return {
            "display_name": self.display_name,
            "selected_lens": self.selected_lens.value,
            "view_reference": self.view_reference,
            "report_context_reference": self.report_context_reference,
        }

    @classmethod
    def FromDict(cls, value: object) -> WorkspaceConfiguration:
        """Decode exact configuration fields without silently defaulting unknown values.

        Args:
            value: JSON object from a supported workspace document.

        Returns:
            Validated immutable configuration.

        Raises:
            ValueError: Fields, types, references, or the lens are invalid.
        """

        record = WorkspaceFields(
            value,
            {"display_name", "selected_lens", "view_reference", "report_context_reference"},
            "configuration",
        )
        view_reference = record["view_reference"]
        report_reference = record["report_context_reference"]

        return cls(
            display_name=RequireWorkspaceText(record["display_name"], "display_name"),
            selected_lens=WorkspaceLens(
                RequireWorkspaceText(record["selected_lens"], "selected_lens")
            ),
            view_reference=(
                None if view_reference is None
                else RequireWorkspaceText(view_reference, "view_reference")
            ),
            report_context_reference=(
                None if report_reference is None
                else RequireWorkspaceText(report_reference, "report_context_reference")
            ),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceState:
    """Authoritative workspace identity and context references, without a parallel model."""

    workspace_id: str
    configuration: WorkspaceConfiguration
    revision: int = 0
    scope_references: tuple[str, ...] = ()
    object_references: tuple[str, ...] = ()
    job_references: tuple[str, ...] = ()
    evidence_references: tuple[EvidenceReference, ...] = ()
    evidence_record_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Freeze ordered metadata and reject ambiguous references before persistence."""

        RequireIdentifier(self.workspace_id, "workspace_id")
        RequireWorkspaceInteger(self.revision, "revision")

        if not isinstance(self.configuration, WorkspaceConfiguration):
            raise ValueError("configuration must be a WorkspaceConfiguration")

        for field_name in ("scope_references", "object_references", "job_references"):
            object.__setattr__(
                self, field_name, WorkspaceReferences(getattr(self, field_name), field_name)
            )

        record_references = WorkspaceReferences(
            self.evidence_record_references, "evidence_record_references"
        )

        for record_reference in record_references:
            if not EVIDENCE_RECORD_REFERENCE_PATTERN.fullmatch(record_reference):
                raise ValueError("evidence record references must be sha256:<lowercase hex digest>")

        object.__setattr__(self, "evidence_record_references", record_references)

        if not isinstance(self.evidence_references, (tuple, list)):
            raise ValueError("evidence_references must be an evidence sequence")

        references = tuple(self.evidence_references)
        identities: set[tuple[str, str]] = set()

        for reference in references:
            if not isinstance(reference, EvidenceReference):
                raise ValueError("evidence_references must contain EvidenceReference values")

            DecodeEvidenceReference({
                "role": reference.role,
                "locator": reference.locator,
                "sha256": reference.sha256,
                "media_type": reference.media_type, "size_bytes": reference.size_bytes,
            })
            identity = (reference.locator, reference.role)

            if identity in identities:
                raise ValueError("evidence references must be unique by locator and role")

            identities.add(identity)

        object.__setattr__(self, "evidence_references", references)

    def ToDict(self) -> dict[str, object]:
        """Render strict schema-versioned metadata, retaining evidence integrity fields.

        Returns:
            JSON-compatible fields without installation paths or raw evidence payloads.
        """

        return {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "workspace_id": self.workspace_id,
            "revision": self.revision,
            "configuration": self.configuration.ToDict(),
            "scope_references": list(self.scope_references),
            "object_references": list(self.object_references),
            "job_references": list(self.job_references),
            "evidence_record_references": list(self.evidence_record_references),
            "evidence_references": [
                {
                    "role": reference.role,
                    "locator": reference.locator,
                    "sha256": reference.sha256,
                    "media_type": reference.media_type,
                    "size_bytes": reference.size_bytes,
                }
                for reference in self.evidence_references
            ],
        }

    @classmethod
    def FromDict(cls, value: object) -> WorkspaceState:
        """Decode a supported document and fail closed on any unrecognized metadata.

        Args:
            value: Decoded JSON document; duplicate keys must already be rejected.

        Returns:
            Immutable validated workspace snapshot.

        Raises:
            ValueError: Schema version, fields, types, references, or configuration are invalid.
        """

        record = WorkspaceFields(
            value,
            {
                "schema_version", "workspace_id", "revision", "configuration", "scope_references",
                "object_references", "job_references", "evidence_references",
                "evidence_record_references",
            },
            "workspace state",
        )

        schema_version = RequireWorkspaceInteger(record["schema_version"], "schema_version")

        if schema_version != WORKSPACE_SCHEMA_VERSION:
            raise ValueError("unsupported workspace schema version")

        evidence = record["evidence_references"]

        if not isinstance(evidence, list):
            raise ValueError("evidence_references must be a JSON array")

        return cls(
            workspace_id=RequireWorkspaceText(record["workspace_id"], "workspace_id"),
            configuration=WorkspaceConfiguration.FromDict(record["configuration"]),
            revision=RequireWorkspaceInteger(record["revision"], "revision"),
            scope_references=WorkspaceReferences(record["scope_references"], "scope_references"),
            object_references=WorkspaceReferences(record["object_references"], "object_references"),
            job_references=WorkspaceReferences(record["job_references"], "job_references"),
            evidence_references=tuple(DecodeEvidenceReference(item) for item in evidence),
            evidence_record_references=WorkspaceReferences(
                record["evidence_record_references"], "evidence_record_references"
            ),
        )


@runtime_checkable
class WorkspaceStore(Protocol):
    """Separate workspace lifecycle consumers from a particular persistence backend."""

    def Create(self, configuration: WorkspaceConfiguration, workspace_id: str) -> WorkspaceState:
        """Create new authoritative state or fail without replacing an existing workspace.

        Args:
            configuration: Validated non-secret workspace configuration.
            workspace_id: Lowercase durable identity chosen by the caller.

        Returns:
            Initial snapshot at revision zero.

        Raises:
            ValueError: Metadata or the storage path is invalid.
            OSError: Creation or durable writing fails, including an existing root.
        """

        ...

    def Open(self) -> WorkspaceState:
        """Read validated authoritative state independently of cache or index availability.

        Returns:
            Latest complete validated snapshot.

        Raises:
            ValueError: Metadata is corrupt, unsupported, or the path is unsafe.
            OSError: Authoritative state cannot be read.
        """

        ...

    def Save(self, state: WorkspaceState) -> WorkspaceState:
        """Commit a matching revision and return its incremented immutable snapshot.

        Args:
            state: Proposed state retaining the last observed identity and revision.

        Returns:
            Committed snapshot with revision incremented exactly once.

        Raises:
            WorkspaceConflictError: Identity changed or another writer advanced the revision.
            WorkspaceBusyError: A writer owns the lock, including an abandoned lock.
            ValueError: Proposed metadata or the storage path is invalid.
            OSError: Writing fails; callers must reopen before retrying.
        """

        ...


@dataclass(frozen=True, slots=True)
class LocalWorkspaceStore:
    """Persist private portable metadata with atomic writes and cooperating-writer CAS.

    Construction does not perform I/O. The operator must own the workspace tree;
    hostile concurrent filesystem mutation is outside this implementation's contract.
    """

    root: Path

    def __post_init__(self) -> None:
        """Reject lexical traversal and filesystem roots without reading or creating paths."""

        if not isinstance(self.root, Path) or ".." in self.root.parts:
            raise ValueError("workspace root must be a Path without lexical traversal")

        root = self.root.absolute()

        if root == Path(root.anchor):
            raise ValueError("filesystem root cannot be a workspace")

        object.__setattr__(self, "root", root)

    def ValidateStoragePaths(self, *, require_root: bool = True) -> None:
        """Reject unsafe observed path types before local lifecycle operations.

        Args:
            require_root: Require an existing root; false only before initial creation.

        Raises:
            ValueError: Links, reparse points, or filesystem object types are unsafe.
            OSError: Storage path metadata cannot be inspected.
        """

        for path in (*reversed(self.root.parents), self.root):
            metadata = StoragePathInfo(path)

            if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("workspace root and ancestors must be directories")

        if require_root and not self.root.is_dir():
            raise ValueError("workspace root must be an existing directory")

        for name in PARTITION_NAMES:
            metadata = StoragePathInfo(self.root / name)

            if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"workspace partition must be a directory: {name}")

        metadata = StoragePathInfo(self.root / "workspace.json")

        if metadata is not None and not stat.S_ISREG(metadata.st_mode):
            raise ValueError("workspace state must be a regular file")

    def Create(self, configuration: WorkspaceConfiguration, workspace_id: str) -> WorkspaceState:
        """Create a private new workspace with explicit partition ownership.

        Args:
            configuration: Non-secret view configuration; no credentials are resolved.
            workspace_id: Durable lowercase identity retained by every later save.

        Returns:
            Initial snapshot at revision zero.

        Raises:
            ValueError: Metadata or paths are unsafe.
            OSError: The root exists or creation/writing fails; incomplete roots may remain.
        """

        state = WorkspaceState(workspace_id, configuration)
        self.ValidateStoragePaths(require_root=False)
        self.root.mkdir(mode=0o700)

        for name in PARTITION_NAMES:
            (self.root / name).mkdir(mode=0o700)

        self.WriteState(state)
        SyncStorageDirectory(self.root.parent)

        return state

    def Open(self) -> WorkspaceState:
        """Read authoritative metadata without loading evidence or rebuilding indexes.

        Returns:
            Latest complete snapshot even when derived directories are absent.

        Raises:
            ValueError: Paths, UTF-8/JSON, size, schema, or references are invalid.
            OSError: The authoritative state is missing or unreadable.
        """

        self.ValidateStoragePaths()

        with (self.root / "workspace.json").open("rb") as stream:
            payload = stream.read(MAX_STATE_BYTES + 1)

        if len(payload) > MAX_STATE_BYTES:
            raise ValueError("workspace state exceeds the metadata size limit")

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=UniqueWorkspaceObject,
                parse_constant=RejectWorkspaceConstant,
            )

        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("workspace state must be valid bounded UTF-8 JSON") from error

        return WorkspaceState.FromDict(value)

    def Save(self, state: WorkspaceState) -> WorkspaceState:
        """Atomically save a matching identity/revision under an exclusive writer lock.

        Args:
            state: Validated proposal with the identity/revision returned by Open or Save.

        Returns:
            New immutable snapshot with revision increased by one.

        Raises:
            WorkspaceConflictError: Another commit advanced the revision or identity changed.
            WorkspaceBusyError: A live or abandoned writer lock already exists.
            ValueError: State or storage paths fail validation.
            OSError: Commit/cleanup fails; replacement may already have occurred, so reopen.
        """

        if not isinstance(state, WorkspaceState):
            raise ValueError("state must be a WorkspaceState")

        self.ValidateStoragePaths()
        lock_path = self.root / ".write-lock"

        try:
            lock_path.mkdir(mode=0o700)

        except FileExistsError as error:
            raise WorkspaceBusyError(
                "workspace writer lock exists; never remove a live lock"
            ) from error

        try:
            current = self.Open()

            if state.workspace_id != current.workspace_id or state.revision != current.revision:
                raise WorkspaceConflictError(
                    "workspace identity or revision changed; reopen before saving"
                )

            committed = replace(state, revision=current.revision + 1)
            self.WriteState(committed)

            return committed

        finally:
            lock_path.rmdir()

    def WriteState(self, state: WorkspaceState) -> None:
        """Write internal state durably; lifecycle consumers must use Create or Save.

        This implementation helper does not acquire writer ownership or perform CAS.
        The supported lifecycle operations own those checks and resource cleanup.

        Args:
            state: Validated internal snapshot from the owning lifecycle operation.

        Raises:
            ValueError: Serialized metadata exceeds the explicit size limit.
            OSError: Writing, synchronization, replacement, or cleanup fails; replacement
                may already have happened, so a lifecycle caller must reopen before retrying.
        """

        payload = json.dumps(
            state.ToDict(), ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\n"

        if len(payload) > MAX_STATE_BYTES:
            raise ValueError("workspace state exceeds the metadata size limit")

        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.root, prefix=".workspace-", suffix=".json", delete=False
            ) as stream:
                temporary_path = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, self.root / "workspace.json")

            SyncStorageDirectory(self.root)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
