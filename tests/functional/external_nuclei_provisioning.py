# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify offline Nuclei materials without acquiring assets or launching a process.

The host must acquire the pinned archive before starting any target and establish
the clean committed source revision. These helpers establish byte custody, not
root ownership, image immutability, successful initialization or Go validation.
"""

from __future__ import annotations

import hashlib
import io
import stat
import sys
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

from .external_native_runner import MAX_FILE_BYTES
from .external_nuclei_runner import (
    ARCHIVE_BYTES,
    EMPTY_CONFIG,
    MODULES,
    InstalledInventory,
    ProfileDocument,
    RegularIdentity,
    VerifyArchive,
)

MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_RELEASE_MEMBERS = 32
MAX_WHEEL_MEMBERS = 512
MAX_PACKAGE_ENTRIES = 1024
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100


def IdentityBytes(path: Path, identity: dict, *, maximum: int) -> bytes:
    """Read one finite byte snapshot and bind it to the already observed file identity."""

    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)

    if len(raw) > maximum or len(raw) != identity["size_bytes"] or (
        hashlib.sha256(raw).hexdigest() != identity["sha256"]
    ):
        raise ValueError("Nuclei material changed after its identity preflight")

    return raw


def RegularMembers(archive: ZipFile, *, maximum_members: int,
                   maximum_bytes: int, allow_directories: bool = False) -> dict[str, ZipInfo]:
    """Reject ambiguous, linked, encrypted or oversized ZIP member inventories.

    Relative regular files are returned. The wheel caller may explicitly admit
    safe empty directory records, which are validated and omitted from content.
    Member count includes directories; expanded byte limits apply per file and
    in aggregate. Nothing is extracted here; CRC verification occurs when a file
    is subsequently read through its end. Unread release documentation remains
    inventory only, without claiming its CRC was verified.
    """

    members = archive.infolist()

    if not 1 <= len(members) <= maximum_members:
        raise ValueError("Nuclei material ZIP exceeds its finite member budget")

    result = {}
    seen = set()
    total = 0

    for member in members:
        name = member.filename
        directory = member.is_dir()
        canonical = name[:-1] if directory else name
        parts = canonical.split("/")
        mode = stat.S_IFMT(member.external_attr >> 16)
        ordinary = mode in {0, stat.S_IFREG} and not member.external_attr & 0x10

        if directory:
            ordinary = allow_directories and mode in {0, stat.S_IFDIR} and member.file_size == 0

        if not canonical or len(name) > 256 or member.orig_filename != name or (
            PurePosixPath(name).is_absolute() or any(part in {"", ".", ".."} for part in parts)
            or any(character in "\\:" or ord(character) < 32 or ord(character) == 127
                   for character in name)
            or canonical in seen or not ordinary
            or member.flag_bits & 1 or member.compress_type not in {ZIP_STORED, ZIP_DEFLATED}
            or not 0 <= member.file_size <= maximum_bytes
            or not 0 <= member.compress_size <= maximum_bytes
            or member.file_size > MAX_COMPRESSION_RATIO * max(1, member.compress_size)
        ):
            raise ValueError("Nuclei ZIP requires unique bounded regular file members "
                             "or directories")

        total += member.file_size

        if total > maximum_bytes:
            raise ValueError("Nuclei material ZIP exceeds its aggregate expanded byte budget")

        seen.add(canonical)

        if not directory:
            result[name] = member

    return result


def PrepareMaterial(archive_path: Path, template: Path, configuration: Path,
                    destination: Path) -> dict:
    """Materialize verified offline inputs using explicit Linux file-mode semantics.

    The destination is a new private ordinary directory, never a claim of UID 0
    or immutable storage. Files are made read-only after success. The later image
    and host must enforce immutability and separately observe version 3.4.10 and
    genuine exact-template validation. No executable digest is guessed here.

    Raises:
        ValueError: The platform is unsupported, or pinned bytes/inventory/paths are invalid.
        OSError: Local custody cannot be established without replacing existing files.
        BadZipFile: The selected member fails ZIP integrity/CRC verification.

    Unsupported platforms refuse before any input read or output write. Cleanup
    failure annotates the original refusal; the destination remains unaccepted.
    """

    if sys.platform != "linux":
        raise ValueError("Nuclei executable materialization requires Linux file-mode semantics")

    archive_identity = VerifyArchive(archive_path)
    archive_bytes = IdentityBytes(archive_path, archive_identity, maximum=ARCHIVE_BYTES)
    original_profile = ProfileDocument(template, configuration)

    if not destination.is_absolute() or any(part == ".." for part in destination.parts):
        raise ValueError("Nuclei material requires a new absolute private directory")

    for component in reversed(destination.parents):
        if component.is_symlink():
            raise ValueError("Nuclei material directory cannot traverse symbolic links")

    with ZipFile(io.BytesIO(archive_bytes)) as archive:
        members = RegularMembers(archive, maximum_members=MAX_RELEASE_MEMBERS,
                                 maximum_bytes=MAX_EXECUTABLE_BYTES)

        if "nuclei" not in members or members["nuclei"].file_size == 0:
            raise ValueError("Nuclei release requires exactly one nonempty root executable")

        destination.mkdir(mode=0o700)
        executable = destination / "nuclei"
        written = 0

        try:
            with archive.open(members["nuclei"]) as source, executable.open("xb") as output:
                while chunk := source.read(min(1024 * 1024, MAX_EXECUTABLE_BYTES - written + 1)):
                    written += len(chunk)

                    if written > MAX_EXECUTABLE_BYTES or written > members["nuclei"].file_size:
                        raise ValueError("Nuclei executable exceeds its declared expanded budget")

                    output.write(chunk)

            if written != members["nuclei"].file_size:
                raise ValueError("Nuclei executable differs from its declared member size")

            executable.chmod(0o500)
            binary = RegularIdentity(executable, maximum=MAX_EXECUTABLE_BYTES, executable=True)
            copied_template = destination / "prometheus-exposition.yaml"
            copied_configuration = destination / "operator-config.yaml"

            for source, copied, maximum in (
                (template, copied_template, original_profile["templates"][0]["size_bytes"]),
                (configuration, copied_configuration, len(EMPTY_CONFIG)),
            ):
                with source.open("rb") as incoming, copied.open("xb") as outgoing:
                    raw = incoming.read(maximum + 1)

                    if len(raw) > maximum:
                        raise ValueError("Nuclei copied profile exceeds its fixed byte budget")

                    outgoing.write(raw)

                copied.chmod(0o400)

            profile = ProfileDocument(copied_template, copied_configuration)

        except BaseException as error:
            # Refuse partial material while retaining any cleanup failure on the original error.
            try:
                executable.unlink(missing_ok=True)

            except OSError as cleanup_error:
                error.add_note("Nuclei partial executable cleanup failed: "
                               + type(cleanup_error).__name__ + "; destination remains unaccepted")

            raise

    return {"archive": archive_identity, "executable": binary, "profile": profile,
            "release_inventory": [{"name": name, "size_bytes": member.file_size,
                "compressed_bytes": member.compress_size, "crc32": f"{member.CRC:08x}",
                "crc_verified": name == "nuclei"} for name, member in members.items()],
            "material_basis": "new-private-local-directory; image immutability unproven",
            "version_probe": "not-run", "go_template_validation": "not-run"}


def PackageFiles(package: Path) -> dict[str, dict]:
    """Inventory finite ordinary package files, excluding declared generated bytecode."""

    if not package.is_absolute() or package.name != "fuzzy1337" or (
        any(part == ".." for part in package.parts) or not package.is_dir()
    ):
        raise ValueError("Nuclei source inventory requires an absolute fuzzy1337 package directory")

    for component in (*reversed(package.parents), package):
        if component.is_symlink():
            raise ValueError("Nuclei package inventory cannot traverse symbolic links")

    files = {}
    total = 0
    entries = 0

    for path in package.rglob("*"):
        entries += 1

        if entries > MAX_PACKAGE_ENTRIES:
            raise ValueError("Nuclei package inventory exceeds its finite directory entry budget")

        metadata = path.lstat()

        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Nuclei package inventory refuses symbolic links")

        if stat.S_ISDIR(metadata.st_mode):
            continue

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Nuclei package inventory requires ordinary files")

        relative = path.relative_to(package)

        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue

        identity = RegularIdentity(path, maximum=MAX_FILE_BYTES)
        total += identity["size_bytes"]

        if len(files) >= MAX_WHEEL_MEMBERS or total > MAX_PACKAGE_BYTES:
            raise ValueError("Nuclei package inventory exceeds its finite file/byte budget")

        files[relative.as_posix()] = identity

    if "__init__.py" not in files:
        raise ValueError("Nuclei package inventory requires its ordinary package initializer")

    return dict(sorted(files.items()))


def InstalledSourceInventory(source_revision: str, wheel: Path, source_package: Path) -> dict:
    """Bind installed package bytes and selected actual imports to the supplied source/wheel.

    Reuses the real isolated installed-import preflight. All ordinary package
    files in the source, wheel and installed directory must match, including
    package data. Generated __pycache__/.pyc files are excluded; distribution
    metadata and dependencies are outside this declared content inventory.
    Source-revision cleanliness remains a separate host responsibility.
    """

    installed = InstalledInventory(source_revision, wheel)
    source = PackageFiles(source_package)
    package = PackageFiles(Path(installed["package_path"]))

    if set(source) != set(package):
        raise ValueError("Nuclei installed package file inventory differs from supplied source")

    wheel_bytes = IdentityBytes(wheel, installed["wheel"], maximum=MAX_FILE_BYTES)

    with ZipFile(io.BytesIO(wheel_bytes)) as archive:
        members = RegularMembers(archive, maximum_members=MAX_WHEEL_MEMBERS,
                                 maximum_bytes=MAX_PACKAGE_BYTES, allow_directories=True)
        selected = {name.removeprefix("fuzzy1337/"): member for name, member in members.items()
                    if name.startswith("fuzzy1337/")}

        if set(selected) != set(source):
            raise ValueError("Nuclei wheel package file inventory differs from supplied source")

        for name, identity in source.items():
            with archive.open(selected[name]) as stream:
                raw = stream.read(MAX_FILE_BYTES + 1)

            if len(raw) != selected[name].file_size or len(raw) > MAX_FILE_BYTES or (
                raw != IdentityBytes(Path(identity["path"]), identity, maximum=MAX_FILE_BYTES)
                or raw != IdentityBytes(Path(package[name]["path"]), package[name],
                                        maximum=MAX_FILE_BYTES)
            ):
                raise ValueError("Nuclei wheel/source/installed package bytes differ")

    for name in MODULES:
        relative = name.replace(".", "/") + ".py"

        if relative not in package:
            relative = name.replace(".", "/") + "/__init__.py"

        if relative not in package or installed["module_sha256"][name] != (
            package[relative]["sha256"]
        ):
            raise ValueError("Nuclei actual imported module differs from the wheel inventory")

    return {"installed": installed, "package_files": {name: {
                "sha256": identity["sha256"], "size_bytes": identity["size_bytes"],
            } for name, identity in source.items()},
            "coverage": {"package_content": "all ordinary fuzzy1337 files",
                "actual_import_modules": list(MODULES),
                "excluded_generated": ["__pycache__/**", "*.pyc"],
                "excluded_content": ["distribution metadata", "dependencies"]},
            "source_revision_basis": "caller-supplied; host clean-commit check required"}
