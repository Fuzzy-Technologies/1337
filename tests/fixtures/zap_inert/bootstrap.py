# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Standalone test-only quota bootstrap; importing this file performs no system operation."""

from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import stat
import sys
from pathlib import Path

CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_NODEV = 4
MS_NOSUID = 2
MS_NOEXEC = 8


def Identity(info: os.stat_result) -> list[int]:
    """Return full original file identity for fixed material validation.

    Args:
        info: Original nofollow stat result.

    Returns:
        Device, inode, mode, owner, link count, length and timestamps.
    """

    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def ReadFixed(path: Path, expected: list[int], maximum: int) -> bytes:
    """Read unchanged regular material without following a final symlink.

    Args:
        path: One owner-generated fixed material path.
        expected: Original full physical identity.
        maximum: Closed per-role read cap.

    Returns:
        Original bounded bytes.

    Raises:
        ValueError: Ownership, identity, type or size differs.
    """

    before = path.lstat()

    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or (
        before.st_uid not in (0, os.getuid()) or before.st_mode & 0o7022
        or before.st_size > maximum or Identity(before) != expected
    ):
        raise ValueError("inert material admission refused")

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)

    try:
        if Identity(os.fstat(descriptor)) != expected:
            raise ValueError("inert material changed at open")

        raw = os.read(descriptor, maximum + 1)

        if len(raw) != before.st_size or Identity(os.fstat(descriptor)) != expected or (
            Identity(path.lstat()) != expected
        ):
            raise ValueError("inert material changed during read")

        return raw

    finally:
        os.close(descriptor)


def Call(name: str, *args: object) -> None:
    """Invoke a required libc setup operation without a weaker fallback.

    Args:
        name: Fixed source-selected libc operation name.
        args: Fixed operation arguments built by this module.

    Raises:
        OSError: The required operation is unavailable or denied.
    """

    libc = ctypes.CDLL(None, use_errno=True)

    if getattr(libc, name)(*args) != 0:
        error = ctypes.get_errno()

        raise OSError(error, "required inert namespace operation refused")


def Main() -> int:
    """Enter the fixed quota/bootstrap boundary and replace self with verified bubblewrap.

    Returns:
        Only the refusal exit code; successful setup replaces the current process.
    """

    if len(sys.argv) != 2 or sys.platform != "linux" or platform.machine() != "x86_64":
        raise ValueError("unsupported closed inert bootstrap")

    if os.getuid() == 0 or os.geteuid() != os.getuid() or os.getegid() != os.getgid():
        raise ValueError("inert bootstrap requires the original unprivileged owner")

    status = Path("/proc/self/status").read_text(encoding="ascii")

    for key in ("CapEff", "CapPrm", "CapAmb"):
        if int(next(line.split()[1] for line in status.splitlines()
            if line.startswith(key + ":")), 16):
            raise ValueError("host capabilities are forbidden")

    request_path = Path(sys.argv[1])
    request_info = request_path.lstat()
    raw = ReadFixed(request_path, Identity(request_info), 4096)
    request = json.loads(raw)
    keys = {"operation", "request_sha256", "materials"}

    if set(request) != keys or json.dumps(request, sort_keys=True,
        separators=(",", ":")).encode() != raw:
        raise ValueError("noncanonical inert bootstrap request")

    operation = Path(request["operation"])

    if request_path != operation / "bootstrap.json" or operation.resolve() != operation or (
        operation.stat().st_uid != os.getuid() or stat.S_IMODE(operation.stat().st_mode) != 0o700
    ):
        raise ValueError("inert operation identity refused")

    materials = request["materials"]

    if set(materials) != {"fixture", "bwrap", "contract", "bootstrap", "request"}:
        raise ValueError("invalid closed inert material set")

    paths = {}

    for role, material in materials.items():
        if set(material) != {"path", "identity", "sha256"}:
            raise ValueError("invalid inert material record")

        path = Path(material["path"])
        data = ReadFixed(path, material["identity"], 16 * 1024 * 1024)

        if hashlib.sha256(data).hexdigest() != material["sha256"]:
            raise ValueError("inert material digest mismatch")

        if role in {"fixture", "bwrap"} and os.listxattr(path) and (
            "security.capability" in os.listxattr(path)
        ):
            raise ValueError("file capabilities are forbidden")

        paths[role] = path

    if paths["bootstrap"] != Path(__file__).resolve() or (
        paths["contract"] != Path(__file__).with_name("contract.py")
        or paths["request"] != operation / "request.bin"
        or hashlib.sha256(paths["request"].read_bytes()).hexdigest() != request["request_sha256"]
    ):
        raise ValueError("inert fixed recipe differs")

    spec = importlib.util.spec_from_file_location("inert_closed_contract", paths["contract"])
    assert spec is not None and spec.loader is not None, (
        "Closed inert source material loading invariant failed"
    )
    contract = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = contract
    spec.loader.exec_module(contract)
    contract.Decode(paths["request"].read_bytes())
    original_uid, original_gid = os.getuid(), os.getgid()
    Call("unshare", CLONE_NEWUSER)
    Path("/proc/self/setgroups").write_text("deny", encoding="ascii")
    Path("/proc/self/uid_map").write_text(f"0 {original_uid} 1\n", encoding="ascii")
    Path("/proc/self/gid_map").write_text(f"0 {original_gid} 1\n", encoding="ascii")
    Call("unshare", CLONE_NEWNS)
    Call("mount", None, b"/", None, ctypes.c_ulong(MS_REC | MS_PRIVATE), None)
    work = operation / "work"
    work.mkdir(mode=0o700)
    Call("mount", b"tmpfs", os.fsencode(work), b"tmpfs",
        ctypes.c_ulong(MS_NODEV | MS_NOSUID | MS_NOEXEC),
        b"size=67108864,nr_inodes=1024,mode=0700")

    for name in ("home", "tmp", "session", "report", "shm", "run"):
        (work / name).mkdir(mode=0o700)

    handles = []

    try:
        for path in (work, paths["fixture"], paths["request"], operation / "control.sock"):
            descriptor = os.open(path, os.O_PATH | os.O_NOFOLLOW)
            os.set_inheritable(descriptor, True)
            handles.append(descriptor)

        null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(null, 0)
        os.close(null)
        Call("prctl", 38, 1, 0, 0, 0)
        args = contract.BwrapArguments(str(paths["bwrap"]), tuple(handles))
        os.execve(args[0], args, {"LANG": "C", "LC_ALL": "C", "PATH": ""})

    finally:
        for descriptor in handles:
            os.close(descriptor)

    return 4


if __name__ == "__main__":
    try:
        raise SystemExit(Main())

    except (OSError, ValueError, KeyError, TypeError):
        print("closed inert bootstrap refused", file=sys.stderr)
        raise SystemExit(4) from None
