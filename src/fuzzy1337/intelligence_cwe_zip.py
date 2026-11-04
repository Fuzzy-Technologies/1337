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

    endOffset = len(payload) - _END.size
    (signature, disk, centralDisk, diskCount, totalCount, centralSize, centralOffset,
     comment) = _END.unpack_from(payload, endOffset)

    if signature != b"PK\x05\x06" or disk != 0 or centralDisk != 0 or diskCount != 1 or (
        totalCount != 1 or comment != 0 or not _CENTRAL.size <= centralSize
        <= MAX_CENTRAL_DIRECTORY_BYTES or centralOffset < _LOCAL.size
        or centralOffset + centralSize != endOffset
    ):
        raise ValueError("CWE ZIP end record is outside its profile")

    (signature, creator, extraction, flags, method, _time, _day, crc32, compressedSize,
     declaredSize, nameSize, extraSize, memberComment, memberDisk, attributes,
     external, localOffset) = _CENTRAL.unpack_from(payload, centralOffset)

    if signature != b"PK\x01\x02" or creator >> 8 != 3 or extraction != 20 or flags != 0 or (
        method != 8 or memberDisk != 0 or attributes not in (0, 1) or external & 0x18
        or stat.S_IFMT(external >> 16) != stat.S_IFREG or localOffset != 0
        or memberComment != 0 or nameSize != len(member_name) or extraSize > MAX_EXTRA_BYTES
        or centralSize != _CENTRAL.size + nameSize + extraSize
        or not 1 <= compressedSize <= MAX_ZIP_BYTES or declaredSize > MAX_XML_BYTES
    ):
        raise ValueError("CWE ZIP member header is outside its profile")

    nameOffset = centralOffset + _CENTRAL.size

    if payload[nameOffset:nameOffset + nameSize] != member_name:
        raise ValueError("CWE ZIP requires its exact fixed member basename")

    ValidateExtras(payload[nameOffset + nameSize:centralOffset + centralSize])
    (signature, localExtraction, localFlags, localMethod, _localTime, _localDay,
     localCrc32, localCompressed, localDeclared, localNameSize, localExtraSize) = (
        _LOCAL.unpack_from(payload)
    )

    if signature != b"PK\x03\x04" or localExtraction != 20 or localFlags != 0 or (
        localMethod != 8 or (localCrc32, localCompressed, localDeclared)
        != (crc32, compressedSize, declaredSize) or localNameSize != len(member_name)
        or localExtraSize > MAX_EXTRA_BYTES
    ):
        raise ValueError("CWE ZIP local header does not match its member")

    compressedStart = _LOCAL.size + localNameSize + localExtraSize

    if compressedStart + compressedSize != centralOffset or payload[
        _LOCAL.size:_LOCAL.size + localNameSize
    ] != member_name:
        raise ValueError("CWE ZIP member ranges or basenames do not match")

    ValidateExtras(payload[_LOCAL.size + localNameSize:compressedStart])

    return compressedStart, compressedSize, declaredSize, crc32


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

    start, compressedSize, declaredSize, declaredCrc32 = MemberFrame(
        payload, member_name.encode("ascii"),
    )
    end = start + compressedSize
    offset = start
    pending = b""
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    digest = hashlib.sha256()
    decodedSize = 0
    crc32 = 0

    while True:
        if not pending and offset < end:
            pending = payload[offset:min(offset + CHUNK_BYTES, end)]
            offset += len(pending)

        previousSize = len(pending)

        try:
            decoded = decoder.decompress(pending, CHUNK_BYTES)

        except zlib.error as error:
            raise ValueError("CWE ZIP DEFLATE stream is refused") from error

        pending = decoder.unconsumed_tail

        if decoded:
            followingSize = decodedSize + len(decoded)

            if followingSize > MAX_XML_BYTES or followingSize > declaredSize:
                raise ValueError("CWE ZIP actual expansion exceeds its profile")

            decodedSize = followingSize
            digest.update(decoded)
            crc32 = zlib.crc32(decoded, crc32)
            sink(decoded)

        if decoder.eof:
            if decoder.unused_data or pending or offset != end:
                raise ValueError("CWE ZIP has unused or trailing member data")

            if decodedSize != declaredSize or crc32 != declaredCrc32:
                raise ValueError("CWE ZIP actual decoded size or CRC does not match")

            break

        if not decoded and previousSize <= len(pending):
            raise ValueError("CWE ZIP DEFLATE is incomplete or made no progress")

    return CweZipFacts(hashlib.sha256(payload).hexdigest(), len(payload), member_name,
        compressedSize, declaredSize, f"{declaredCrc32:08x}", digest.hexdigest(),
        decodedSize, f"{crc32:08x}")
