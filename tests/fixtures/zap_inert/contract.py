# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure closed wire and argument templates for the experimental inert proof only."""

from __future__ import annotations

import struct
from dataclasses import dataclass

REQUEST = struct.Struct("!8sB3xHH16s32s")
READY = struct.Struct("!8s16s32sQQQQQ")
ACK = struct.Struct("!8s16s32s")
REQUEST_MAGIC = b"1337ZIP1"
READY_MAGIC = b"1337ZRD1"
ACK_MAGIC = b"1337ZAK1"
MODES = ("normal", "byte-limit", "inode-limit", "wait", "before-report")
QUOTA_BYTES = 67108864
QUOTA_INODES = 1024
SETUP_BYTES = b"1337 ZAP inert setup v1\n"
REPORT_BYTES = b"1337 ZAP inert late-report v1\n"
BWRAP_SHA256 = "4734237473c0e5d695e4e9034a34e43b2dbf5164655bd13fa59ae376b2b7a765"
BWRAP_SIZE = 129260


@dataclass(frozen=True, slots=True)
class Envelope:
    """The only inert request, without an executable, path or caller-selected limits."""

    mode: str
    sink_port: int
    private_port: int
    nonce: bytes
    digest: bytes

    def Encode(self) -> bytes:
        """Validate and encode the one fixed 64-byte request.

        Returns:
            Exact closed binary request.

        Raises:
            ValueError: A mode, port or binding is outside the closed contract.
        """

        if self.mode not in MODES or any(
            type(port) is not int or not 1024 <= port <= 65535
            for port in (self.sink_port, self.private_port)
        ) or self.sink_port == self.private_port:
            raise ValueError("invalid closed inert mode or owned ports")

        if type(self.nonce) is not bytes or len(self.nonce) != 16 or (
            type(self.digest) is not bytes or len(self.digest) != 32
        ):
            raise ValueError("invalid inert request binding")

        return REQUEST.pack(REQUEST_MAGIC, MODES.index(self.mode), self.sink_port,
            self.private_port, self.nonce, self.digest)

    def Ack(self) -> bytes:
        """Bind the single ACK to this exact original request.

        Returns:
            Exact closed 56-byte ACK.
        """

        self.Encode()

        return ACK.pack(ACK_MAGIC, self.nonce, self.digest)


def Decode(raw: bytes) -> Envelope:
    """Reject alternate encodings and return one exact request.

    Args:
        raw: Original fixed request bytes.

    Returns:
        Validated closed envelope.

    Raises:
        ValueError: Length, magic, reserved bytes or fields differ.
    """

    if len(raw) != REQUEST.size or raw[9:12] != b"\0\0\0":
        raise ValueError("invalid inert request length or reserved bytes")

    magic, mode, sink_port, private_port, nonce, digest = REQUEST.unpack(raw)

    if magic != REQUEST_MAGIC or mode >= len(MODES):
        raise ValueError("invalid inert request version or mode")

    envelope = Envelope(MODES[mode], sink_port, private_port, nonce, digest)

    if envelope.Encode() != raw:
        raise ValueError("noncanonical inert request")

    return envelope


def ParseReady(raw: bytes, envelope: Envelope) -> tuple[int, int, int, int, int]:
    """Bind one READY and declared quota facts to the original request.

    Args:
        raw: Exactly one original READY frame.
        envelope: Original request selected by the owner.

    Returns:
        Quota device, inode, block size, block count and inode count.

    Raises:
        ValueError: The message or bounds are not the fixed profile.
    """

    if len(raw) != READY.size:
        raise ValueError("invalid inert READY length")

    magic, nonce, digest, device, inode, block_size, blocks, files = READY.unpack(raw)

    if (magic, nonce, digest) != (READY_MAGIC, envelope.nonce, envelope.digest) or (
        device < 1 or inode < 1 or block_size < 1 or block_size * blocks != QUOTA_BYTES
        or files != QUOTA_INODES
    ):
        raise ValueError("inert READY binding or quota mismatch")

    return device, inode, block_size, blocks, files


def BwrapArguments(binary: str, own_handles: tuple[int, int, int, int]) -> tuple[str, ...]:
    """Substitute only the bootstrap's four typed handles into the fixed template.

    Args:
        binary: Already verified private helper path, never a workload selection.
        own_handles: Bootstrap-created quota, fixture, request and socket O_PATH handles.

    Returns:
        Fixed helper argument vector.

    Raises:
        ValueError: The closed handle slots are invalid or reused.
    """

    if len(own_handles) != 4 or len(set(own_handles)) != 4 or any(
        type(value) is not int or value < 3 for value in own_handles
    ):
        raise ValueError("four distinct bootstrap-owned handles are required")

    quota, fixture, request, control = map(str, own_handles)
    args = [binary, "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--disable-userns", "--cap-drop", "ALL", "--new-session",
        "--die-with-parent", "--uid", "0", "--gid", "0", "--hostname", "1337-inert",
        "--clearenv"]

    for name, value in (("PWD", "/work"), ("HOME", "/work/home"), ("PATH", ""),
        ("LANG", "C"), ("LC_ALL", "C"), ("TMP", "/work/tmp"), ("TEMP", "/work/tmp"),
        ("TMPDIR", "/work/tmp"), ("XDG_CACHE_HOME", "/work/home/cache"),
        ("XDG_CONFIG_HOME", "/work/home/config"), ("XDG_DATA_HOME", "/work/home/data"),
        ("XDG_RUNTIME_DIR", "/work/run")):
        args.extend(("--setenv", name, value))

    args.extend(("--bind-fd", quota, "/work", "--ro-bind-fd", fixture, "/inert",
        "--ro-bind-fd", request, "/request.bin", "--ro-bind-fd", control, "/control.sock",
        "--dir", "/dev", "--dir", "/var"))

    for source, target in (("/work/home", "/home"), ("/work/tmp", "/tmp"),
        ("/work/tmp", "/var/tmp"), ("/work/session", "/session"),
        ("/work/report", "/report"), ("/work/shm", "/dev/shm")):
        args.extend(("--symlink", source, target))

    args.extend(("--chdir", "/work", "--remount-ro", "/", "--", "/inert", "/request.bin"))

    return tuple(args)
