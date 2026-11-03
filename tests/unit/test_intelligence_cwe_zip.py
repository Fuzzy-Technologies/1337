# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise exact CWE ZIP framing, bounded actual decode and complete-tail failure barriers."""

from __future__ import annotations

import builtins
import hashlib
import stat
import struct
import zlib
from dataclasses import FrozenInstanceError, fields

import pytest

from fuzzy1337 import intelligence_cwe_zip as owner

MEMBER = "cwec_v5.0.xml"
BODY = b"<owned>selected original source</owned>"


def Deflate(body: bytes) -> bytes:
    """Encode one owned raw DEFLATE member using the independent stdlib producer."""

    encoder = zlib.compressobj(wbits=-zlib.MAX_WBITS)

    return encoder.compress(body) + encoder.flush()


def Extra(identifier: int, body: bytes = b"") -> bytes:
    """Construct an original opaque ZIP extra field without assigning metadata authority."""

    return struct.pack("<HH", identifier, len(body)) + body


def Archive(body=BODY, *, member=MEMBER, local_extra=b"", central_extra=b"",
            compressed=None, declared_size=None, crc32=None):
    """Produce independently framed one-member ZIP bytes with explicit original header facts."""

    name = member.encode("utf-8")
    compressed = Deflate(body) if compressed is None else compressed
    size = len(body) if declared_size is None else declared_size
    crc = zlib.crc32(body) if crc32 is None else crc32
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 8, 0, 0, crc,
                        len(compressed), size, len(name), len(local_extra)) + name + local_extra
    central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 3 << 8 | 30, 20, 0, 8, 0, 0,
        crc, len(compressed), size, len(name), len(central_extra), 0, 0, 1,
        (stat.S_IFREG | 0o640) << 16, 0) + name + central_extra
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central),
                      len(local) + len(compressed), 0)

    return local + compressed + central + end


def Rewrite(payload, header, offset, grammar, value):
    """Change one independent binary header field without repairing linked original facts."""

    starts = {"local": 0, "central": struct.unpack_from("<I", payload, len(payload) - 6)[0],
              "end": len(payload) - 22}
    changed = bytearray(payload)
    struct.pack_into(grammar, changed, starts[header] + offset, value)

    return bytes(changed)


def StoredStream(body: bytes) -> bytes:
    """Encode exact uncompressed DEFLATE blocks for meaningful original-byte boundary cases."""

    parts = []

    for offset in range(0, len(body), 65535):
        selected = body[offset:offset + 65535]
        final = offset + len(selected) == len(body)
        parts.append(bytes((int(final),)) + struct.pack("<HH", len(selected),
                                                       65535 - len(selected)) + selected)

    return b"".join(parts)


@pytest.mark.parametrize("member", ["cwec_v5.0.xml", "cwec_v4.21.xml"])
def test_ExactCompleteMemberRetainsOriginalFactsWithoutIo(member, monkeypatch):
    """Different bounded local/central extras remain metadata while complete original bytes bind."""

    local = Extra(0x5455, b"\x03" + b"x" * 8) + Extra(0x7875, b"owned-user")
    central = Extra(0x5455, b"\x03" + b"y" * 4) + Extra(0x7875, b"other")
    payload = Archive(member=member, local_extra=local, central_extra=central)
    retained = []

    def NoIo(*args, **kwargs):
        """Expose any path extraction or unadvertised file operation."""

        raise AssertionError("Pure CWE ZIP consumption attempted file I/O")

    monkeypatch.setattr(builtins, "open", NoIo)
    result = owner.ConsumeCweZip(payload, member, retained.append)
    assert b"".join(retained) == BODY, "Decoded original bytes were changed"
    assert result.raw_sha256 == hashlib.sha256(payload).hexdigest() and result.raw_size == len(
        payload,
    ), "Original complete ZIP identity was lost"
    assert result.member_name == member and result.member_compressed_size == len(Deflate(BODY)), (
        "The selected fixed basename or original compressed range changed"
    )
    assert result.member_declared_size == result.decoded_size == len(BODY) and (
        result.member_declared_crc32 == result.decoded_crc32 == f"{zlib.crc32(BODY):08x}"
        and result.decoded_sha256 == hashlib.sha256(BODY).hexdigest()
    ), "Declared promises replaced actual complete decode facts"
    assert owner.__all__ == () and len(fields(result)) == 9, "An Internal fact contract changed"

    with pytest.raises(FrozenInstanceError):
        result.decoded_size = 1


def test_OpaqueExtrasCannotSupplyAnotherPathOrExtractionDirective():
    """Unknown and Unicode-path metadata never override the sole exact ASCII header basename."""

    metadata = Extra(0x7075, b"\x01\x00\x00\x00\x00../../untrusted.xml") + Extra(0x1234, b"\0" * 7)
    payload = Archive(local_extra=metadata, central_extra=Extra(0xCAFE, b"opaque"))
    result = owner.ConsumeCweZip(payload, MEMBER, lambda value: None)
    assert result.member_name == MEMBER, "Opaque extra metadata became an alternate source path"

    with pytest.raises(ValueError):
        owner.ConsumeCweZip(Archive(member="../" + MEMBER, local_extra=metadata), MEMBER,
                            lambda value: None)


@pytest.mark.parametrize("extra", [b"x", b"xyz", struct.pack("<HH", 2, 5) + b"x",
    Extra(1), Extra(2) + Extra(2), b"".join(Extra(index) for index in range(2, 11)),
    Extra(2, b"x" * 253)])
@pytest.mark.parametrize("location", ["local", "central"])
def test_InvalidExtraMetadataRefusesBeforeAnySink(extra, location):
    """Truncated, duplicate, ZIP64, ninth-field and 257-byte regions never reach decoded input."""

    payload = Archive(**{location + "_extra": extra})

    def NoSink(value):
        """Expose decoding before all original extra metadata is admitted."""

        raise AssertionError("Invalid ZIP metadata reached its sink")

    with pytest.raises(ValueError):
        owner.ConsumeCweZip(payload, MEMBER, NoSink)


@pytest.mark.parametrize("extra", [Extra(2, b"x" * 252),
    b"".join(Extra(index) for index in range(2, 10))])
def test_Inclusive256BytesAndEightOpaqueFieldsRemainSupported(extra):
    """The real metadata ceilings admit their inclusive values without relaxed constants."""

    result = owner.ConsumeCweZip(Archive(local_extra=extra, central_extra=extra), MEMBER,
                                  lambda value: None)
    assert result.decoded_size == len(BODY), "Inclusive opaque metadata limits were reduced"


@pytest.mark.parametrize("header,offset,grammar,value", [
    ("end", 0, "<I", 0), ("end", 4, "<H", 1), ("end", 6, "<H", 1),
    ("end", 8, "<H", 2), ("end", 10, "<H", 2), ("end", 12, "<I", 0),
    ("end", 12, "<I", 16385), ("end", 16, "<I", 0), ("end", 20, "<H", 1),
    ("central", 0, "<I", 0), ("central", 4, "<H", 30), ("central", 6, "<H", 21),
    ("central", 8, "<H", 1), ("central", 10, "<H", 0), ("central", 16, "<I", 0),
    ("central", 20, "<I", 0), ("central", 24, "<I", 33554433),
    ("central", 28, "<H", 0), ("central", 30, "<H", 257), ("central", 32, "<H", 1),
    ("central", 34, "<H", 1), ("central", 36, "<H", 2),
    ("central", 38, "<I", (stat.S_IFLNK | 0o777) << 16),
    ("central", 38, "<I", (stat.S_IFDIR | 0o755) << 16),
    ("central", 38, "<I", (stat.S_IFREG << 16) | 0x08),
    ("central", 38, "<I", (stat.S_IFREG << 16) | 0x10),
    ("central", 42, "<I", 1), ("local", 0, "<I", 0), ("local", 4, "<H", 21),
    ("local", 6, "<H", 8), ("local", 8, "<H", 0), ("local", 14, "<I", 0),
    ("local", 18, "<I", 0), ("local", 22, "<I", 0), ("local", 26, "<H", 0),
    ("local", 28, "<H", 257),
])
def test_UnsupportedOrInconsistentHeadersRefuseBeforeSink(header, offset, grammar, value):
    """No alternate type, disk, method, descriptor, offset, name or declaration gains admission."""

    payload = Rewrite(Archive(), header, offset, grammar, value)

    def NoSink(decoded):
        """Expose member consumption before every header and original source range agrees."""

        raise AssertionError("Refused ZIP framing reached its sink")

    with pytest.raises(ValueError):
        owner.ConsumeCweZip(payload, MEMBER, NoSink)


@pytest.mark.parametrize("header", ["local", "central"])
def test_EachHeaderMustHaveTheExactOriginalBasename(header):
    """Matching filename lengths never substitute a different local or central source name."""

    payload = bytearray(Archive())
    start = 30 if header == "local" else struct.unpack_from("<I", payload, len(payload) - 6)[0] + 46
    payload[start] = ord("q")

    with pytest.raises(ValueError, match="basename"):
        owner.ConsumeCweZip(bytes(payload), MEMBER, lambda value: None)


@pytest.mark.parametrize("case", ["stub", "gap", "directory-gap", "zip64-locator", "trailer",
                                  "concatenated", "short"])
def test_NoHiddenRangeOrExtraArchiveMaySurviveTheCompleteFrame(case):
    """The fixed local/central/EOCD chain rejects prepended, intervening and following bytes."""

    payload = Archive()
    central = struct.unpack_from("<I", payload, len(payload) - 6)[0]

    if case in ("gap", "stub"):
        position = central if case == "gap" else 0
        payload = payload[:position] + b"owned gap" + payload[position:]
        payload = Rewrite(payload, "end", 16, "<I", central + 9)

    elif case in ("directory-gap", "zip64-locator"):
        gap = b"x" if case == "directory-gap" else b"PK\x06\x07" + b"\0" * 16
        payload = payload[:-22] + gap + payload[-22:]

    elif case == "trailer":
        payload += b"x"

    elif case == "concatenated":
        payload += Archive()

    else:
        payload = b"PK\x03\x04"

    with pytest.raises(ValueError):
        owner.ConsumeCweZip(payload, MEMBER, lambda value: None)


@pytest.mark.parametrize("case", ["bad-stream", "truncated", "second-deflate", "padding",
                                  "declared-short", "declared-long", "wrong-crc"])
def test_ActualDeflateEofSizeCrcAndNoUnusedBytesAreMandatory(case):
    """A complete header promise or already observed selected content cannot replace EOF/CRC."""

    body = b"<selected/>" + b"owned tail" * 10000
    compressed = Deflate(body)
    options = {}

    if case == "bad-stream":
        compressed = b"\xff"

    elif case == "truncated":
        compressed = compressed[:-1]

    elif case in ("second-deflate", "padding"):
        compressed += Deflate(b"") if case == "second-deflate" else b"\0"

    elif case == "declared-short":
        options["declared_size"] = len(body) - 1

    elif case == "declared-long":
        options["declared_size"] = len(body) + 1

    else:
        options["crc32"] = zlib.crc32(body) ^ 1

    retained = []

    with pytest.raises(ValueError):
        owner.ConsumeCweZip(Archive(body, compressed=compressed, **options), MEMBER,
                            retained.append)

    if case in ("wrong-crc", "declared-long"):
        assert b"".join(retained) == body, "The fixture did not reach its complete-tail barrier"


def test_EofAtInputBoundaryCannotHideAnotherUnloadedCompressedRange():
    """EOF with no same-chunk unused_data still refuses bytes remaining in the declared range."""

    body = b"x" * 65531
    compressed = StoredStream(body)
    assert len(compressed) == 65536, "Owned raw-block fixture missed the real input boundary"

    with pytest.raises(ValueError, match="trailing"):
        owner.ConsumeCweZip(Archive(body, compressed=compressed + b"tail"), MEMBER,
                            lambda value: None)


def test_EmptyCompleteMemberReportsOnlyZipFactsForSeparateXmlOwner():
    """An empty DEFLATE member is complete ZIP data, without claiming a valid XML root."""

    retained = []
    result = owner.ConsumeCweZip(Archive(b""), MEMBER, retained.append)
    assert result.decoded_size == 0 and result.decoded_crc32 == "00000000" and not retained, (
        "The ZIP owner invented XML content or conflated its separate completion barrier"
    )


def test_InclusiveOriginalFourMiBLimitConsumesActualStoredDeflate():
    """An original ZIP exactly at its real fixed ceiling is decoded rather than approximated."""

    overhead = len(Archive(b"", compressed=b""))
    body = b"x" * (4194304 - overhead - 64 * 5)
    payload = Archive(body, compressed=StoredStream(body))
    assert len(payload) == 4194304, "Owned stored-block fixture missed the actual source ceiling"
    result = owner.ConsumeCweZip(payload, MEMBER, lambda value: None)
    assert result.raw_size == 4194304 and result.decoded_sha256 == hashlib.sha256(
        body,
    ).hexdigest(), (
        "Inclusive original-byte admission failed to verify actual complete content"
    )


@pytest.mark.parametrize("actual_extra", [0, 1])
def test_ActualExpandedCeilingNeverUsesDeclaredSizeAsProof(actual_extra):
    """Exactly 32 MiB succeeds; one additional expanded byte refuses before sink publication."""

    body = b"x" * (33554432 + actual_extra)
    payload = Archive(body, declared_size=33554432)
    received = 0

    def Count(value):
        """Count actual retained callback bytes without accumulating the expanded member."""

        nonlocal received
        assert 1 <= len(value) <= 65536, "A sink received an unbounded decompression chunk"
        received += len(value)

    if actual_extra:
        with pytest.raises(ValueError, match="expansion"):
            owner.ConsumeCweZip(payload, MEMBER, Count)

        assert received <= 33554432, "An over-limit expanded byte reached the sink"

    else:
        result = owner.ConsumeCweZip(payload, MEMBER, Count)
        assert result.decoded_size == received == 33554432, "Inclusive expanded ceiling changed"


def test_ActualCompressedInputAndOutputCallsAreIndependentlyChunkBounded(monkeypatch):
    """Observe the real stdlib decoder without replacing its EOF, tail or progress semantics."""

    body = b"bounded original bytes" * 20000
    payload = Archive(body, compressed=StoredStream(body))
    original = zlib.decompressobj
    calls = []

    class CheckedDecoder:
        """Observe actual decoder calls while preserving all C-library-owned stream state."""

        def __init__(self, decoder):
            """Retain the real raw decoder for this one observed member."""

            self.decoder = decoder

        def Decompress(self, data, max_length):
            """Check exact caller bounds before delegating to real zlib decoding."""

            assert len(data) <= 65536 and max_length == 65536, "A decode call escaped chunk bounds"
            decoded = self.decoder.decompress(data, max_length)
            assert len(decoded) <= 65536, "Actual decoder output exceeded its requested maximum"
            calls.append((len(data), len(decoded)))

            return decoded

        decompress = Decompress

        def __getattr__(self, name):
            """Read exact external decoder state rather than simulating its completion."""

            return getattr(self.decoder, name)

    def Decode(bits):
        """Wrap the actual raw-DEFLATE factory with a passive bound-observation adapter."""

        assert bits == -zlib.MAX_WBITS, "The owner changed the exact raw-DEFLATE format"

        return CheckedDecoder(original(bits))

    monkeypatch.setattr(owner.zlib, "decompressobj", Decode)
    result = owner.ConsumeCweZip(payload, MEMBER, lambda value: None)
    assert len(calls) > 1 and max(row[0] for row in calls) == 65536 and (
        result.decoded_sha256 == hashlib.sha256(body).hexdigest()
    ), "The owned stream did not exercise bounded multi-chunk real decoding"


def test_SinkFailurePropagatesWithoutAnySuccessfulCompletionFact():
    """XML refusal or another sink error cannot be caught and recast as successful ZIP facts."""

    error = RuntimeError("owned sink refusal")
    calls = []

    def Refuse(value):
        """Refuse the first actual decoded chunk before further input is consumed."""

        calls.append(len(value))

        raise error

    with pytest.raises(RuntimeError) as raised:
        owner.ConsumeCweZip(Archive(), MEMBER, Refuse)

    assert raised.value is error and len(calls) == 1, "The sink error or completion meaning changed"


@pytest.mark.parametrize("payload", [None, bytearray(b"x"), memoryview(b"x"), b"", b"x" * 4194305])
def test_OriginalAdmissionRequiresExactBytesWithinItsOwnCeiling(payload):
    """A path, mutable buffer or one-over original source cannot enter framing or decoding."""

    with pytest.raises(ValueError, match="closed profile"):
        owner.ConsumeCweZip(payload, MEMBER, lambda value: None)


@pytest.mark.parametrize("member", [None, b"cwec_v5.0.xml", "cwec_latest.xml", "../cwec_v5.0.xml"])
def test_MemberAdmissionIsOnlyTheTwoExactBasenames(member):
    """No caller-selected release path or moving catalog enters the Internal closed mode."""

    with pytest.raises(ValueError, match="closed profile"):
        owner.ConsumeCweZip(Archive(), member, lambda value: None)


def test_ExactTypeAdmissionPrecedesOverriddenOperationsAndInvalidSink():
    """Bytes/str subclasses cannot execute altered admission operations before refusal."""

    class HostileBytes(bytes):
        """Expose subclass length dispatch that exact-byte admission must never invoke."""

        def __len__(self):
            """Trip an altered source operation."""

            raise AssertionError("Bytes subclass length executed")

    class HostileName(str):
        """Expose subclass hash dispatch that exact-name admission must never invoke."""

        def __hash__(self):
            """Trip an altered member-name operation."""

            raise AssertionError("String subclass hash executed")

    for payload, member, sink in ((HostileBytes(b"x"), MEMBER, lambda value: None),
        (Archive(), HostileName(MEMBER), lambda value: None), (Archive(), MEMBER, None)):
        with pytest.raises(ValueError, match="closed profile"):
            owner.ConsumeCweZip(payload, member, sink)


def test_CreatorVersionTimeAndPermissionsRemainNonAuthorityMetadata():
    """Admitted regular-file metadata does not become a clock, user or extraction instruction."""

    payload = Rewrite(Archive(), "central", 4, "<H", 3 << 8)
    payload = Rewrite(payload, "central", 36, "<H", 0)
    payload = Rewrite(payload, "central", 38, "<I", (stat.S_IFREG | 0o7777) << 16)
    payload = Rewrite(payload, "local", 10, "<H", 65535)
    result = owner.ConsumeCweZip(payload, MEMBER, lambda value: None)
    assert result.decoded_size == len(BODY), "Opaque creator/time/permission metadata became policy"
