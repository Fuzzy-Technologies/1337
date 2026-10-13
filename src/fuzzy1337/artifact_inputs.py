# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit selected-file snapshots and bounded observed local artifact integrity."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.executors.contracts import RequireReference
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import StoragePathInfo

ARTIFACT_CONTRACT_VERSION = 1
MAX_ARTIFACT_FILES = 1024
MAX_ARTIFACT_FILE_BYTES = 512 * 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", re.IGNORECASE)

__all__ = [
    "ARTIFACT_CONTRACT_VERSION",
    "MAX_ARTIFACT_FILES",
    "MAX_ARTIFACT_FILE_BYTES",
    "MAX_ARTIFACT_TOTAL_BYTES",
    "ArtifactProfile",
    "ArtifactRole",
    "ArtifactReadConsent",
    "ArtifactSelection",
    "ArtifactFile",
    "ArtifactManifest",
    "ArtifactSnapshot",
    "ArtifactStage",
]


class ArtifactProfile(StrEnum):
    """Closed offline identities; native profiles are metadata-only until real acceptance."""

    IMAGE = "trivy.image-archive-offline.v1"
    DOCKERFILE = "trivy.dockerfile-offline.v1"
    KUBERNETES = "trivy.kubernetes-offline.v1"
    SYNTHETIC_IMAGE = "synthetic.image-archive-offline.v1"
    SYNTHETIC_DOCKERFILE = "synthetic.dockerfile-offline.v1"
    SYNTHETIC_KUBERNETES = "synthetic.kubernetes-offline.v1"


class ArtifactRole(StrEnum):
    """Domain-separate input bytes from trusted scanner and offline material bytes."""

    INPUT = "input"
    SCANNER = "scanner"
    MATERIAL = "material"


def ArtifactName(value: str) -> str:
    """Validate a finite portable relative name without filesystem inference.

    Args:
        value: ASCII portable relative name, at most 240 characters and 16 segments.

    Returns:
        The unchanged validated name; unsafe input raises ValueError.
    """

    if not isinstance(value, str) or len(value) > 240:
        raise ValueError("artifact name must be bounded portable relative text")

    parts = value.split("/")

    if not 1 <= len(parts) <= 16 or any(
        not _SEGMENT.fullmatch(part) or part.endswith(".") or _DEVICE.fullmatch(part)
        for part in parts
    ):
        raise ValueError("artifact name contains an unsafe or reserved path segment")

    return value


def ArtifactNames(values: Iterable[str], *, allow_directories: bool = False) -> tuple[str, ...]:
    """Reject duplicate, case-colliding and file-versus-directory portable names.

    Args:
        values: Explicit finite relative names, without inferred filesystem expansion.
        allow_directories: Inventory contains directory prefixes as separate entries.

    Returns:
        Sorted validated names, or ValueError for ambiguous portable identities.
    """

    names = tuple(sorted(ArtifactName(value) for value in values))
    folded = {name.casefold() for name in names}

    if len(names) != len(folded):
        raise ValueError("artifact names must be unique without case collisions")

    spellings: dict[str, str] = {}

    for name in names:
        parts = name.split("/")

        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            key = prefix.casefold()

            if key in spellings and spellings[key] != prefix:
                raise ValueError("artifact directory names must not case-collide")

            spellings[key] = prefix

            if not allow_directories and index < len(parts) and key in folded:
                raise ValueError("artifact file names must not also denote directories")

    return names


def PhysicalIdentity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Bind observed physical identity and mutation timestamps, without hostile-writer proof.

    Args:
        info: Non-following or opened-file metadata from an explicitly selected path.

    Returns:
        Device, inode, length and nanosecond modification/change timestamps.
    """

    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def ArtifactPathInfo(path: Path, *, directory: bool = False) -> os.stat_result:
    """Reject observed linked ancestors and require the selected owned physical type.

    Args:
        path: Explicit absolute physical selection, without traversal or linked ancestors.
        directory: Require an owned directory rather than a singly linked regular file.

    Returns:
        Non-following selected metadata; observed unsafe or missing paths raise ValueError.
    """

    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact physical paths must be absolute without traversal")

    for ancestor in reversed(path.parents):
        info = StoragePathInfo(ancestor)

        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ValueError("artifact ancestors must be existing physical directories")

    info = StoragePathInfo(path)

    if info is None:
        raise ValueError("selected artifact path does not exist")

    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("artifact partition must be a physical directory")

    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("selected artifact must be a singly linked regular file")

    return info


@dataclass(frozen=True, slots=True)
class ArtifactReadConsent:
    """Explicit non-secret selected-file read authority; not a signature or scan grant."""

    actor_ref: str
    record_ref: str

    def __post_init__(self) -> None:
        """Require explicit references without reading any path or consent record."""

        for value in (self.actor_ref, self.record_ref):
            RequireReference(value, "artifact read consent")

            if len(value) > 4096:
                raise ValueError("artifact read consent reference is oversized")


@dataclass(frozen=True, slots=True)
class ArtifactSelection:
    """One explicitly selected physical source and its portable snapshot name."""

    name: str
    source: Path

    def __post_init__(self) -> None:
        """Validate declaration syntax without filesystem reads or recursive selection."""

        ArtifactName(self.name)

        if not isinstance(self.source, Path) or not self.source.is_absolute():
            raise ValueError("artifact source selection must be an absolute Path")


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    """Exact selected-byte identity; an archive SHA is not an OCI digest."""

    name: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        """Validate finite canonical manifest file metadata."""

        ArtifactName(self.name)

        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 <= self.size_bytes <= MAX_ARTIFACT_FILE_BYTES
        ):
            raise ValueError("artifact file size exceeds the selected-file bound")

        if not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("artifact file digest must be canonical SHA-256")


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    """Versioned role/profile-separated content identity independent of absolute locations."""

    profile: ArtifactProfile
    role: ArtifactRole
    files: tuple[ArtifactFile, ...]

    def __post_init__(self) -> None:
        """Freeze canonical finite files and reject aggregate/collision ambiguity."""

        files = tuple(self.files)

        if not isinstance(self.profile, ArtifactProfile) or not isinstance(self.role, ArtifactRole):
            raise ValueError("artifact manifest requires a closed profile and role")

        if len(files) > MAX_ARTIFACT_FILES or any(
            not isinstance(item, ArtifactFile) for item in files
        ):
            raise ValueError("artifact manifest requires finite typed file records")

        if self.role != ArtifactRole.MATERIAL and not files:
            raise ValueError("input and scanner manifests must not be empty")

        if sum(item.size_bytes for item in files) > MAX_ARTIFACT_TOTAL_BYTES:
            raise ValueError("artifact manifest aggregate byte bound exceeded")

        ArtifactNames(item.name for item in files)
        object.__setattr__(self, "files", tuple(sorted(files, key=lambda item: item.name)))

    def ToDict(self) -> dict[str, object]:
        """Render the exact version-owned canonical manifest fields.

        Returns:
            Non-secret role/profile/name/length/hash metadata without source paths.
        """

        return {
            "schema_version": ARTIFACT_CONTRACT_VERSION,
            "profile": self.profile.value,
            "role": self.role.value,
            "files": [
                {"name": item.name, "size_bytes": item.size_bytes, "sha256": item.sha256}
                for item in self.files
            ],
        }

    @classmethod
    def FromDict(cls, value: object) -> ArtifactManifest:
        """Decode strict canonical metadata without reading artifact bytes.

        Args:
            value: Exactly versioned manifest JSON fields.

        Returns:
            Immutable manifest with canonical ordering and validated finite names.

        Raises:
            ValueError: Version, fields, types or canonical ordering are unsupported.
        """

        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "profile",
            "role",
            "files",
        }:
            raise ValueError("artifact manifest fields are invalid")

        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("artifact manifest version is unsupported")

        records = value["files"]

        if not isinstance(records, list) or len(records) > MAX_ARTIFACT_FILES:
            raise ValueError("artifact manifest file list is invalid")

        files = []

        for record in records:
            if not isinstance(record, dict) or set(record) != {"name", "size_bytes", "sha256"}:
                raise ValueError("artifact file fields are invalid")

            files.append(ArtifactFile(record["name"], record["size_bytes"], record["sha256"]))

        try:
            manifest = cls(
                ArtifactProfile(value["profile"]), ArtifactRole(value["role"]), tuple(files)
            )

        except (TypeError, ValueError) as error:
            raise ValueError("artifact manifest profile or role is invalid") from error

        if manifest.ToDict() != value:
            raise ValueError("persisted artifact manifest must already be canonical")

        return manifest

    def Digest(self) -> str:
        """Hash canonical version/profile/role/sorted-file JSON without a newline.

        Returns:
            Lowercase SHA-256 of the canonical UTF-8 manifest.
        """

        return hashlib.sha256(SerializeContract(self.ToDict()).encode("utf-8")).hexdigest()

    def Target(self) -> Target:
        """Return exact existing-store scope identity for input bytes only.

        Returns:
            ARTIFACT target whose value is distinct from each file or OCI hash.

        Raises:
            ValueError: Scanner/material bytes are substituted for selected input authority.
        """

        if self.role != ArtifactRole.INPUT:
            raise ValueError("only an input manifest can identify an artifact scope target")

        return Target(TargetKind.ARTIFACT, "manifest-sha256:" + self.Digest())


def ReadArtifactFile(
    path: Path,
    name: str,
    destination: BinaryIO | None = None,
    *,
    max_bytes: int = MAX_ARTIFACT_FILE_BYTES,
) -> ArtifactFile:
    """Bound and hash selected bytes while checking observed physical read stability.

    Args:
        path: Explicit read-authorized singly linked physical file.
        name: Portable manifest name for exactly those selected bytes.
        destination: Optional owned snapshot stream receiving only bounded bytes.
        max_bytes: Remaining aggregate budget, additionally limited to 512 MiB per file.

    Returns:
        Exact name/length/SHA record; changed or oversized input raises ValueError.
    """

    before = ArtifactPathInfo(path)

    limit = min(MAX_ARTIFACT_FILE_BYTES, max_bytes)

    if before.st_size > limit:
        raise ValueError("selected artifact file is oversized")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0

    with os.fdopen(os.open(path, flags), "rb") as stream:
        if PhysicalIdentity(os.fstat(stream.fileno())) != PhysicalIdentity(before):
            raise ValueError("selected artifact identity changed before reading")

        while chunk := stream.read(_CHUNK_BYTES):
            size += len(chunk)

            if size > limit:
                raise ValueError("selected artifact grew beyond its bound")

            digest.update(chunk)

            if destination is not None:
                destination.write(chunk)

        if PhysicalIdentity(os.fstat(stream.fileno())) != PhysicalIdentity(before):
            raise ValueError("selected artifact changed while reading")

    if (
        PhysicalIdentity(ArtifactPathInfo(path)) != PhysicalIdentity(before)
        or size != before.st_size
    ):
        raise ValueError("selected artifact changed after reading")

    return ArtifactFile(name, size, digest.hexdigest())


def ArtifactInventory(directory: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Enumerate only a bounded physical tree without following links or special files.

    Args:
        directory: Owned physical staging partition, never an arbitrary recursive selection.

    Returns:
        Sorted relative file and directory names, with bounded enumeration and no links.
    """

    ArtifactPathInfo(directory, directory=True)
    files: list[str] = []
    directories: list[str] = []
    pending = [directory]

    while pending:
        parent = pending.pop()

        for child in parent.iterdir():
            name = child.relative_to(directory).as_posix()
            ArtifactName(name)
            info = StoragePathInfo(child)

            if info is None:
                raise ValueError("artifact tree changed during enumeration")

            if stat.S_ISDIR(info.st_mode):
                directories.append(name)
                pending.append(child)

            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append(name)

            else:
                raise ValueError("artifact tree contains a linked or special file")

            if len(files) > MAX_ARTIFACT_FILES or len(directories) > MAX_ARTIFACT_FILES * 16:
                raise ValueError("artifact tree enumeration exceeds its finite bound")

    ArtifactNames((*files, *directories), allow_directories=True)

    return tuple(sorted(files)), tuple(sorted(directories))


@dataclass(frozen=True, slots=True)
class ArtifactSnapshot:
    """Captured read-authorized partition with immutable observed file identities."""

    manifest: ArtifactManifest
    directory: Path
    consent: ArtifactReadConsent
    identities: tuple[tuple[str, tuple[int, int, int, int, int]], ...]
    directory_identity: tuple[int, int]

    @classmethod
    def Capture(
        cls,
        directory: Path,
        profile: ArtifactProfile,
        role: ArtifactRole,
        selections: tuple[ArtifactSelection, ...],
        consent: ArtifactReadConsent,
        *,
        max_total_bytes: int = MAX_ARTIFACT_TOTAL_BYTES,
    ) -> ArtifactSnapshot:
        """Copy only explicit selected bytes into a new owned partition.

        Args:
            directory: Absent absolute partition under an exclusively owned physical parent.
            profile: Closed manifest profile; capture does not grant execution.
            role: Input/scanner/material domain separation.
            selections: Finite explicitly selected physical files, never recursive selection.
            consent: Required non-secret actor/read-authority references.
            max_total_bytes: Remaining combined stage budget, at most 2 GiB.

        Returns:
            Read-only file snapshot; partial failed capture remains caller-owned.

        Raises:
            ValueError: Selection, physical paths or byte bounds fail closed.
            OSError: Creating or copying owned snapshot files fails.
        """

        if not isinstance(consent, ArtifactReadConsent) or not isinstance(directory, Path):
            raise ValueError("snapshot capture requires explicit read consent and a Path")

        if not isinstance(profile, ArtifactProfile) or not isinstance(role, ArtifactRole):
            raise ValueError("snapshot capture requires a closed profile and role")

        if type(max_total_bytes) is not int or max_total_bytes < 0:
            raise ValueError("snapshot remaining byte budget must be non-negative")

        max_total_bytes = min(max_total_bytes, MAX_ARTIFACT_TOTAL_BYTES)
        selections = tuple(selections)

        if len(selections) > MAX_ARTIFACT_FILES or any(
            not isinstance(item, ArtifactSelection) for item in selections
        ):
            raise ValueError("snapshot capture requires finite typed selections")

        ArtifactNames(item.name for item in selections)

        if sum(ArtifactPathInfo(item.source).st_size for item in selections) > max_total_bytes:
            raise ValueError("snapshot selected bytes exceed the remaining stage budget")

        ArtifactPathInfo(directory.parent, directory=True)
        directory.mkdir(mode=0o700)
        files: list[ArtifactFile] = []
        identities = []
        total = 0

        for selection in sorted(selections, key=lambda item: item.name):
            destination = directory / selection.name
            destination.parent.mkdir(parents=True, exist_ok=True)

            with destination.open("xb") as output:
                record = ReadArtifactFile(
                    selection.source, selection.name, output, max_bytes=max_total_bytes - total
                )

            total += record.size_bytes

            if total > min(MAX_ARTIFACT_TOTAL_BYTES, max_total_bytes):
                raise ValueError("snapshot aggregate byte bound exceeded")

            destination.chmod(stat.S_IRUSR)
            files.append(record)
            identities.append((record.name, PhysicalIdentity(ArtifactPathInfo(destination))))

        manifest = ArtifactManifest(profile, role, tuple(files))
        info = ArtifactPathInfo(directory, directory=True)

        return cls(manifest, directory, consent, tuple(identities), (info.st_dev, info.st_ino))

    def Verify(self) -> None:
        """Rehash exact bytes and reject unlisted material or physical replacements.

        Raises:
            ValueError: Observed closed-world contents or snapshot identities have changed.
            OSError: The owned snapshot cannot be read.
        """

        info = ArtifactPathInfo(self.directory, directory=True)

        if (info.st_dev, info.st_ino) != self.directory_identity:
            raise ValueError("artifact partition physical identity changed")

        files, directories = ArtifactInventory(self.directory)
        expected_dirs: set[str] = set()

        for record in self.manifest.files:
            parts = record.name.split("/")
            expected_dirs.update("/".join(parts[:index]) for index in range(1, len(parts)))

        if (
            files != tuple(item.name for item in self.manifest.files)
            or set(directories) != expected_dirs
        ):
            raise ValueError("artifact snapshot contains missing or unlisted material")

        identities = dict(self.identities)

        for record in self.manifest.files:
            path = self.directory / record.name

            if (
                PhysicalIdentity(ArtifactPathInfo(path)) != identities.get(record.name)
                or ReadArtifactFile(path, record.name) != record
            ):
                raise ValueError("artifact snapshot observed bytes or identity changed")


@dataclass(frozen=True, slots=True)
class ArtifactStage:
    """Single-run owned input/scanner/material snapshots plus separate untrusted scratch."""

    root: Path
    lease_id: str
    input: ArtifactSnapshot
    scanner: ArtifactSnapshot
    material: ArtifactSnapshot
    executable: Path
    executable_identity: tuple[int, int, int, int, int]
    version: str
    root_identity: tuple[int, int]

    @classmethod
    def Create(
        cls,
        root: Path,
        profile: ArtifactProfile,
        consent: ArtifactReadConsent,
        inputs: tuple[ArtifactSelection, ...],
        executable: ArtifactSelection,
        version: str,
        *,
        material: tuple[ArtifactSelection, ...] = (),
        producer: ArtifactSelection | None = None,
    ) -> ArtifactStage:
        """Capture selected inputs and trusted material into an absent owned stage.

        Args:
            root: Absent absolute physical stage below an exclusively owned workspace.
            profile: Closed input/profile identity; native profiles capture metadata only.
            consent: Explicit selected-file read authority, not execution consent.
            inputs: Finite individually selected input bytes.
            executable: Explicit selected executable named exactly executable.
            version: Non-secret operator-attested tool version; not a compatibility proof.
            material: Explicit selected immutable database/check/fixture material.
            producer: Explicit synthetic producer named producer.py, checked by launch factory.

        Returns:
            Single-run stage; no process or scan authority is created.

        Raises:
            ValueError: Selected read authority, names, physical inputs or bounds are invalid.
            OSError: Capture or owned stage creation fails.
        """

        if not isinstance(consent, ArtifactReadConsent) or not isinstance(profile, ArtifactProfile):
            raise ValueError("artifact stage requires explicit consent and closed profile")

        if not isinstance(executable, ArtifactSelection) or executable.name != "executable":
            raise ValueError("artifact executable must be explicitly selected as executable")

        if producer is not None and (
            not isinstance(producer, ArtifactSelection) or producer.name != "producer.py"
        ):
            raise ValueError("synthetic producer must be explicitly selected as producer.py")

        if (
            not isinstance(version, str)
            or len(version) > 64
            or not re.fullmatch(r"0\.75\.\d+(?:-synthetic)?", version)
        ):
            raise ValueError("artifact profile requires a declared bounded Trivy 0.75 version")

        inputs = tuple(inputs)
        material = tuple(material)
        scanner_selections = (executable,) if producer is None else (executable, producer)
        selected = (*inputs, *scanner_selections, *material)

        if len(selected) > MAX_ARTIFACT_FILES or any(
            not isinstance(item, ArtifactSelection) for item in selected
        ):
            raise ValueError("combined stage selection exceeds its finite file bound")

        if (
            sum(ArtifactPathInfo(item.source).st_size for item in selected)
            > MAX_ARTIFACT_TOTAL_BYTES
        ):
            raise ValueError("combined selected stage byte bound exceeded")

        ArtifactPathInfo(root.parent, directory=True)
        root.mkdir(mode=0o700)
        input_snapshot = ArtifactSnapshot.Capture(
            root / "input", profile, ArtifactRole.INPUT, inputs, consent
        )
        remaining = MAX_ARTIFACT_TOTAL_BYTES - sum(
            item.size_bytes for item in input_snapshot.manifest.files
        )
        scanner = ArtifactSnapshot.Capture(
            root / "scanner",
            profile,
            ArtifactRole.SCANNER,
            scanner_selections,
            consent,
            max_total_bytes=remaining,
        )
        remaining -= sum(item.size_bytes for item in scanner.manifest.files)
        material_snapshot = ArtifactSnapshot.Capture(
            root / "material",
            profile,
            ArtifactRole.MATERIAL,
            material,
            consent,
            max_total_bytes=remaining,
        )
        (root / "scratch").mkdir(mode=0o700)
        info = ArtifactPathInfo(root, directory=True)

        return cls(
            root,
            uuid.uuid4().hex,
            input_snapshot,
            scanner,
            material_snapshot,
            executable.source,
            PhysicalIdentity(ArtifactPathInfo(executable.source)),
            version,
            (info.st_dev, info.st_ino),
        )

    def Verify(self, *, after_run: bool = False) -> None:
        """Verify closed immutable material and fresh or observed bounded scratch.

        Args:
            after_run: Permit bounded regular scratch output only after the single run.

        Raises:
            ValueError: Observed stage/executable/material integrity or bounds fail.
            OSError: Physical material cannot be inspected.
        """

        info = ArtifactPathInfo(self.root, directory=True)

        if (info.st_dev, info.st_ino) != self.root_identity:
            raise ValueError("artifact stage physical identity changed")

        partitions = set()

        for child in self.root.iterdir():
            partitions.add(child.name)

            if len(partitions) > 4:
                raise ValueError("artifact stage contains unlisted partitions")

        if partitions != {"input", "scanner", "material", "scratch"}:
            raise ValueError("artifact stage contains unlisted partitions")

        records = tuple(
            item
            for snapshot in (self.input, self.scanner, self.material)
            for item in snapshot.manifest.files
        )

        if (
            len(records) > MAX_ARTIFACT_FILES
            or sum(item.size_bytes for item in records) > MAX_ARTIFACT_TOTAL_BYTES
        ):
            raise ValueError("combined artifact stage manifest bound exceeded")

        for snapshot in (self.input, self.scanner, self.material):
            if snapshot.directory != self.root / snapshot.manifest.role.value:
                raise ValueError("artifact partition is not bound to this stage")

            if snapshot.manifest.profile != self.input.manifest.profile:
                raise ValueError("artifact partition profile mismatch")

            snapshot.Verify()

        executable = next(item for item in self.scanner.manifest.files if item.name == "executable")

        if (
            PhysicalIdentity(ArtifactPathInfo(self.executable)) != self.executable_identity
            or ReadArtifactFile(self.executable, "executable") != executable
        ):
            raise ValueError("selected executable identity or bytes changed")

        scratch = self.root / "scratch"
        files, directories = ArtifactInventory(scratch)

        if not after_run and (files or directories):
            raise ValueError("artifact scratch must start empty for a single run")

        if sum(ArtifactPathInfo(scratch / name).st_size for name in files) > MAX_ARTIFACT_TOTAL_BYTES:
            raise ValueError("observed artifact scratch aggregate byte bound exceeded")

        remaining = MAX_ARTIFACT_TOTAL_BYTES

        for name in files:
            record = ReadArtifactFile(scratch / name, name, max_bytes=remaining)
            remaining -= record.size_bytes
