# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal exact CWE ZIP framing and complete bounded DEFLATE consumption without extraction."""

from __future__ import annotations

import hashlib
import stat
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

__all__: tuple[str, ...] = ()

MAX_ZIP_BYTES = 4 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024
MAX_EXTRA_BYTES = 256
MAX_EXTRA_FIELDS = 8
CHUNK_BYTES = 64 * 1024
_MEMBER_NAMES = frozenset({"cwec_v5.0.xml", "cwec_v4.21.xml"})
_END = struct.Struct("<4s4H2IH")
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_LOCAL = struct.Struct("<4s5H3I2H")
_EXTRA = struct.Struct("<HH")


@dataclass(frozen=True, slots=True)
class CweZipFacts:
    """Carry actual complete member facts, without XML interpretation or source authentication."""

    raw_sha256: str
    raw_size: int
    member_name: str
    member_compressed_size: int
    member_declared_size: int
    member_declared_crc32: str
    decoded_sha256: str
    decoded_size: int
    decoded_crc32: str


def ValidateExtras(extra: bytes) -> None:
    """Require bounded unique opaque TLVs that cannot redirect a member or its interpretation.

    Args:
        extra: One already bounded original local or central header extra region.

    Raises:
        ValueError: Metadata exceeds its byte/count ceiling or contains duplicate, truncated
            or ZIP64 fields. Unknown IDs remain opaque, never alternate paths or directives.
    """

    if len(extra) > MAX_EXTRA_BYTES:
        raise ValueError("CWE ZIP extra metadata exceeds its profile")

    seen: set[int] = set()
    offset = 0

    while offset < len(extra):
        if len(extra) - offset < _EXTRA.size or len(seen) >= MAX_EXTRA_FIELDS:
            raise ValueError("CWE ZIP extra framing exceeds its profile")

        identifier, size = _EXTRA.unpack_from(extra, offset)
        offset += _EXTRA.size

        if identifier == 1 or identifier in seen or size > len(extra) - offset:
            raise ValueError("CWE ZIP extra metadata is refused")

        seen.add(identifier)
        offset += size


def MemberFrame(payload: bytes, member_name: bytes) -> tuple[int, int, int, int]:
    """Verify the sole exact local/central/EOCD chain before any member reaches a sink.

    Args:
        payload: Exact immutable original ZIP bytes admitted within the four-MiB ceiling.
        member_name: One fixed ASCII basename selected by the owning closed CWE mode.

    Returns:
        Compressed start, compressed size, declared expanded size and declared CRC32.

    Raises:
        ValueError: A header, range, identity, source type or unsupported ZIP feature is present.
    """

    if len(payload) < _LOCAL.size + _CENTRAL.size + _END.size:
        raise ValueError("CWE ZIP framing is incomplete")

    end_offset = len(payload) - _END.size
    (signature, disk, central_disk, disk_count, total_count, central_size, central_offset,
     comment) = _END.unpack_from(payload, end_offset)

    if signature != b"PK\x05\x06" or disk != 0 or central_disk != 0 or disk_count != 1 or (
        total_count != 1 or comment != 0 or not _CENTRAL.size <= central_size
        <= MAX_CENTRAL_DIRECTORY_BYTES or central_offset < _LOCAL.size
        or central_offset + central_size != end_offset
    ):
        raise ValueError("CWE ZIP end record is outside its profile")

    (signature, creator, extraction, flags, method, _time, _day, crc32, compressed_size,
     declared_size, name_size, extra_size, member_comment, member_disk, attributes,
     external, local_offset) = _CENTRAL.unpack_from(payload, central_offset)

    if signature != b"PK\x01\x02" or creator >> 8 != 3 or extraction != 20 or flags != 0 or (
        method != 8 or member_disk != 0 or attributes not in (0, 1) or external & 0x18
        or stat.S_IFMT(external >> 16) != stat.S_IFREG or local_offset != 0
        or member_comment != 0 or name_size != len(member_name) or extra_size > MAX_EXTRA_BYTES
        or central_size != _CENTRAL.size + name_size + extra_size
        or not 1 <= compressed_size <= MAX_ZIP_BYTES or declared_size > MAX_XML_BYTES
    ):
        raise ValueError("CWE ZIP member header is outside its profile")

    name_offset = central_offset + _CENTRAL.size

    if payload[name_offset:name_offset + name_size] != member_name:
        raise ValueError("CWE ZIP requires its exact fixed member basename")

    ValidateExtras(payload[name_offset + name_size:central_offset + central_size])
    (signature, local_extraction, local_flags, local_method, _local_time, _local_day,
     local_crc32, local_compressed, local_declared, local_name_size, local_extra_size) = (
        _LOCAL.unpack_from(payload)
    )

    if signature != b"PK\x03\x04" or local_extraction != 20 or local_flags != 0 or (
        local_method != 8 or (local_crc32, local_compressed, local_declared)
        != (crc32, compressed_size, declared_size) or local_name_size != len(member_name)
        or local_extra_size > MAX_EXTRA_BYTES
    ):
        raise ValueError("CWE ZIP local header does not match its member")

    compressed_start = _LOCAL.size + local_name_size + local_extra_size

    if compressed_start + compressed_size != central_offset or payload[
        _LOCAL.size:_LOCAL.size + local_name_size
    ] != member_name:
        raise ValueError("CWE ZIP member ranges or basenames do not match")

    ValidateExtras(payload[_LOCAL.size + local_name_size:compressed_start])

    return compressed_start, compressed_size, declared_size, crc32


def ConsumeCweZip(
    payload: bytes, member_name: str, sink: Callable[[bytes], None],
) -> CweZipFacts:
    """Consume one complete bounded exact member before returning any verified ZIP facts.

    Args:
        payload: Exact immutable original ZIP bytes, at most four MiB; no paths or streams.
        member_name: Exact fixed basename for either supported CWE catalog mode.
        sink: Internal XML owner's consumer of original decoded chunks at most 64 KiB each.
            A sink failure propagates and cannot publish successful completion facts.

    Returns:
        Original and actual expanded digests, sizes and CRC after full EOF/frame verification.
        This proves neither XML validity, publisher identity, a license grant nor acquisition.

    Raises:
        ValueError: Admission, framing, bounded expansion, actual size/CRC or complete EOF fails.
    """

    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_ZIP_BYTES or (
        type(member_name) is not str or member_name not in _MEMBER_NAMES or not callable(sink)
    ):
        raise ValueError("CWE ZIP input is outside its closed profile")

    start, compressed_size, declared_size, declared_crc32 = MemberFrame(
        payload, member_name.encode("ascii"),
    )
    end = start + compressed_size
    offset = start
    pending = b""
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    digest = hashlib.sha256()
    decoded_size = 0
    crc32 = 0

    while True:
        if not pending and offset < end:
            pending = payload[offset:min(offset + CHUNK_BYTES, end)]
            offset += len(pending)

        previous_size = len(pending)

        try:
            decoded = decoder.decompress(pending, CHUNK_BYTES)

        except zlib.error as error:
            raise ValueError("CWE ZIP DEFLATE stream is refused") from error

        pending = decoder.unconsumed_tail

        if decoded:
            following_size = decoded_size + len(decoded)

            if following_size > MAX_XML_BYTES or following_size > declared_size:
                raise ValueError("CWE ZIP actual expansion exceeds its profile")

            decoded_size = following_size
            digest.update(decoded)
            crc32 = zlib.crc32(decoded, crc32)
            sink(decoded)

        if decoder.eof:
            if decoder.unused_data or pending or offset != end:
                raise ValueError("CWE ZIP has unused or trailing member data")

            if decoded_size != declared_size or crc32 != declared_crc32:
                raise ValueError("CWE ZIP actual decoded size or CRC does not match")

            break

        if not decoded and previous_size <= len(pending):
            raise ValueError("CWE ZIP DEFLATE is incomplete or made no progress")

    return CweZipFacts(hashlib.sha256(payload).hexdigest(), len(payload), member_name,
        compressed_size, declared_size, f"{declared_crc32:08x}", digest.hexdigest(),
        decoded_size, f"{crc32:08x}")
