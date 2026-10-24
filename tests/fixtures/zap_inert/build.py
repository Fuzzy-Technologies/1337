# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit CI-only pinned source build; no download or build occurs on import."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from urllib.request import urlopen

ARCHIVE_URL = (
    "https://github.com/containers/bubblewrap/releases/download/v0.13.0/"
    "bubblewrap-0.13.0.tar.xz"
)
ARCHIVE_SHA256 = "4734237473c0e5d695e4e9034a34e43b2dbf5164655bd13fa59ae376b2b7a765"
ARCHIVE_SIZE = 129260
INVENTORY_REPORT_NAME = "source-archive-inventory.json"
FIXTURE_FLAGS = ("-static", "-std=c11", "-O2", "-D_GNU_SOURCE")


def ValidateElf(raw: bytes) -> None:
    """Require a fixed static ELF64 x86_64 executable without interpreter/dynamic segments.

    Args:
        raw: Complete bounded freshly compiled fixture bytes.

    Raises:
        ValueError: Header or program segment facts differ from the closed profile.
    """

    if not 64 <= len(raw) <= 2 * 1024 * 1024 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("inert fixture is not bounded ELF64 little-endian")

    elf_type, machine, version = struct.unpack_from("<HHI", raw, 16)
    program_offset = struct.unpack_from("<Q", raw, 32)[0]
    program_size, program_count = struct.unpack_from("<HH", raw, 54)

    if (elf_type, machine, version) != (2, 62, 1) or program_size != 56 or not (
        1 <= program_count <= 32 and program_offset >= 64
        and program_offset + program_size * program_count <= len(raw)
    ):
        raise ValueError("inert fixture ELF program header differs")

    for index in range(program_count):
        kind = struct.unpack_from("<I", raw, program_offset + index * program_size)[0]

        if kind in {2, 3}:
            raise ValueError("inert fixture has dynamic or interpreter material")


def OrdinaryFile(member: tarfile.TarInfo) -> bool:
    """Identify ordinary source bytes rather than sparse, linked or special archive entries.

    Args:
        member: Original selected archive metadata.

    Returns:
        True only for ordinary regular-file types without sparse metadata.
    """

    return member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and member.sparse is None


def ValidateMembers(members: list[tarfile.TarInfo]) -> None:
    """Admit only canonical pinned source members and two exact ordinary-target license links.

    Args:
        members: Original archive member inventory, before any extraction.

    Raises:
        ValueError: Counts, sizes, paths, duplicates, types or exact license targets differ.
    """

    if not 1 <= len(members) <= 256 or any(
        type(item.size) is not int or item.size < 0 for item in members
    ) or sum(item.size for item in members) > 8 * 1024 * 1024:
        raise ValueError("bubblewrap source inventory exceeds its fixed cap")

    prefix = "bubblewrap-0.13.0"
    license_names = {prefix + "/COPYING.LIB", prefix + "/LICENSE"}
    inventory = {}

    for index, member in enumerate(members):
        if type(member.name) is not str:
            raise ValueError(f"bubblewrap source name refused at member {index}")

        name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
        path = PurePosixPath(name)

        if path.is_absolute() or ".." in path.parts or not path.parts or (
            path.parts[0] != prefix or path.as_posix() != name or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
        ):
            raise ValueError(f"bubblewrap source noncanonical path at member {index}")

        if name in inventory:
            raise ValueError(f"bubblewrap source duplicate name at member {index}")

        if name == prefix and not member.isdir():
            raise ValueError(f"bubblewrap source root type refused at member {index}")

        if member.issym():
            if name not in license_names or member.linkname != "COPYING" or member.size != 0:
                raise ValueError(f"bubblewrap source license link refused at member {index}")

        elif member.isdir():
            if member.size != 0:
                raise ValueError(f"bubblewrap source directory size refused at member {index}")

        elif not OrdinaryFile(member):
            raise ValueError(f"bubblewrap source member type refused at member {index}")

        inventory[name] = member

    for index, (name, member) in enumerate(inventory.items()):
        if member.issym():
            target = inventory.get(prefix + "/COPYING")

            if target is None or not OrdinaryFile(target):
                raise ValueError(f"bubblewrap ordinary COPYING target absent at member {index}")

        for parent in PurePosixPath(name).parents:
            ancestor = inventory.get(parent.as_posix())

            if ancestor is not None and not ancestor.isdir():
                raise ValueError(f"bubblewrap source parent alias refused at member {index}")


def InventoryText(value: object) -> dict[str, object]:
    """Bound one public dependency metadata preview without leaking arbitrary source contents.

    Args:
        value: Original archive name or literal link target.

    Returns:
        At most 128 original UTF-8 bytes rendered as ASCII plus length/truncation facts.
    """

    if type(value) is not str:
        return {"value": "<invalid-string>", "bytes": None, "truncated": False}

    raw = value.encode("utf-8", errors="backslashreplace")

    return {"value": raw[:128].decode("ascii", errors="backslashreplace"),
        "bytes": len(raw), "truncated": len(raw) > 128}


def AdmitMembers(members: list[tarfile.TarInfo], report_path: Path) -> None:
    """Retain bounded actual inventory before validating the already checksum-pinned archive.

    Args:
        members: Original metadata from the exact verified public dependency archive.
        report_path: Fixed private CI provisioning JSON path selected by Main.

    Raises:
        ValueError: Admission refuses or the bounded diagnostic contract is exceeded.
    """

    inventory = []

    for index, member in enumerate(members[:256]):
        valid_size = type(member.size) is int and -(2 ** 63) <= member.size < 2 ** 64
        size = member.size if valid_size else "invalid-size"
        inventory.append({"index": index, "name": InventoryText(member.name),
            "type_hex": member.type.hex() if type(member.type) is bytes and len(member.type) == 1
            else "invalid-type", "size": size, "linkname": InventoryText(member.linkname)})

    report = {"schema_version": 1, "archive_pin_sha256": ARCHIVE_SHA256,
        "archive_pin_bytes": ARCHIVE_SIZE, "member_count": len(members),
        "inventory_truncated": len(members) > 256, "members": inventory,
        "admission": "pending", "first_rejection": None}

    def Save() -> None:
        """Write only bounded public dependency metadata, before extraction or helper execution."""

        raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

        if len(raw) > 512 * 1024:
            raise ValueError("bubblewrap inventory diagnostic exceeds its fixed cap")

        report_path.write_bytes(raw)

    Save()

    try:
        ValidateMembers(members)

    except ValueError as error:
        report["admission"] = "refused"
        report["first_rejection"] = str(error)[:256]
        Save()

        raise

    report["admission"] = "admitted"
    Save()


def Command(argv: tuple[str, ...], *, timeout: int = 60) -> bytes:
    """Execute only a source-selected build/provenance command without shell expansion.

    Args:
        argv: Exact source-selected tool arguments.
        timeout: Fixed bounded build/provenance ceiling.

    Returns:
        Bounded stdout for provenance.

    Raises:
        ValueError: Command output exceeds its provenance cap.
    """

    result = subprocess.run(argv, check=True, capture_output=True, timeout=timeout)

    if len(result.stdout) > 16384 or len(result.stderr) > 65536:
        raise ValueError("build command output exceeds its fixed cap")

    return result.stdout


def Main() -> int:
    """Build the two fixed helpers only in the explicitly enabled reviewed CI lane.

    Returns:
        Zero after writing actual provenance; no helper/payload executes here.
    """

    if len(sys.argv) != 2 or os.environ.get("FUZZY1337_RUN_ZAP_INERT_ACCEPTANCE") != "1" or (
        os.getuid() == 0 or sys.platform != "linux" or platform.machine() != "x86_64"
    ):
        raise ValueError("pinned inert build requires the explicit nonroot CI lane")

    root = Path(sys.argv[1]).resolve()
    root.mkdir(mode=0o700)
    archive_path = root / "bubblewrap-0.13.0.tar.xz"

    with urlopen(ARCHIVE_URL, timeout=20) as source:
        raw = source.read(ARCHIVE_SIZE + 1)

    if len(raw) != ARCHIVE_SIZE or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("bubblewrap archive differs from its exact source pin")

    archive_path.write_bytes(raw)

    with tarfile.open(archive_path, "r:xz") as archive:
        AdmitMembers(archive.getmembers(), root / INVENTORY_REPORT_NAME)
        archive.extractall(root, filter="data")

    source_root = root / "bubblewrap-0.13.0"
    build_root, prefix = root / "build", root / "runtime"
    meson = shutil.which("meson")
    ninja = shutil.which("ninja")
    compiler = shutil.which("gcc")
    assert meson and ninja and compiler, ("Closed inert source material loading invariant failed")
    options = ("--prefix=" + str(prefix), "--bindir=bin", "--buildtype=release",
        "--wrap-mode=nodownload", "-Dselinux=disabled", "-Dman=disabled",
        "-Dbash_completion=disabled", "-Dzsh_completion=disabled", "-Dtests=false",
        "-Ddebug_logging=false", "-Dassume_kernel=", "-Dpython=" + sys.executable)
    Command((meson, "setup", str(build_root), str(source_root), *options))
    Command((ninja, "-C", str(build_root), "-j2"))
    Command((meson, "install", "-C", str(build_root)))
    fixture_source = Path(__file__).with_name("inert.c")
    fixture = prefix / "inert"
    Command((compiler, *FIXTURE_FLAGS, str(fixture_source), "-o", str(fixture)))
    fixture.chmod(0o700)
    ValidateElf(fixture.read_bytes())
    bwrap = prefix / "bin/bwrap"

    for path in (fixture, bwrap):
        info = path.lstat()

        if not path.is_file() or path.is_symlink() or info.st_uid != os.getuid() or (
            info.st_mode & 0o7022 or "security.capability" in os.listxattr(path)
        ):
            raise ValueError("built helper has unsafe ownership, mode or capabilities")

    provenance = {"source_archive_sha256": ARCHIVE_SHA256, "source_archive_bytes": ARCHIVE_SIZE,
        "source_commit": "719a4fd474d44b26906bcf2b1b0fb6eddd8d56d0",
        "fixture_source_sha256": hashlib.sha256(fixture_source.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "bwrap_sha256": hashlib.sha256(bwrap.read_bytes()).hexdigest(),
        "fixture_flags": FIXTURE_FLAGS, "meson_options": options,
        "compiler": Command((compiler, "--version")).decode(),
        "meson": Command((meson, "--version")).decode(),
        "ninja": Command((ninja, "--version")).decode(),
        "libcap": Command(("/usr/bin/pkg-config", "--modversion", "libcap")).decode(),
        "libcap_packages": Command(("/usr/bin/dpkg-query", "-W", "libcap2", "libcap-dev")).decode(),
        "image_version": os.environ.get("ImageVersion"), "kernel": platform.release(),
        "host_uid": os.getuid(), "python": sys.version}
    (prefix / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
