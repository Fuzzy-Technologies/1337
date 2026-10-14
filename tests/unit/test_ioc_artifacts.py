# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Hand-written IOC token, coordinate, time and closed grammar failure oracles without I/O."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.ioc_artifacts import (
    IocCandidate,
    IocLimits,
    IocRequest,
    IocSnapshot,
    IocSource,
    Metadata,
    ParseIocArtifact,
)


@pytest.fixture
def ioc_source():
    """Return an explicit owned fixture selection with its exact source-byte pin."""

    def Source(payload):
        """Pin only the supplied synthetic bytes, without reading any source locator."""

        return IocSource("owned.synthetic", "fixture-1", "owned:case.tsv", "Apache-2.0",
                         "owned:LICENSE", hashlib.sha256(payload).hexdigest())

    return Source


def test_UnitHandWrittenNormalizationAndOriginalCoordinates(ioc_source):
    """Literal normalization retains each original byte range and repeated supplied occurrence."""

    raw = (b"ipv4\t192.0.2.7\r\ndns\tEXAMPLE.Invalid.\nipv6\t2001:0DB8::1\nsha256\t"
           + b"A" * 64 + b"\ndns\texample.invalid\t2026-10-12T12:34:56+05:30\t+05:30\n")
    candidates = ParseIocArtifact(raw, ioc_source(raw))
    oracle = [
        ("ipv4", "192.0.2.7", "192.0.2.7", 1, 5, 9),
        ("dns", "EXAMPLE.Invalid.", "example.invalid", 2, 20, 16),
        ("ipv6", "2001:0DB8::1", "2001:db8::1", 3, 42, 12),
        ("sha256", "A" * 64, "a" * 64, 4, 62, 64),
        ("dns", "example.invalid", "example.invalid", 5, 131, 15),
    ]

    assert [(item.kind, item.raw_token, item.normalized_token, item.line_number,
             item.byte_offset, item.byte_length) for item in candidates] == oracle, (
        "IOC normalization or original token coordinates differ from the hand-written oracle"
    )
    assert len(candidates) == 5 and candidates[1].normalized_token == (
        candidates[4].normalized_token
    ), "Repeated source occurrences were silently deduplicated"
    assert all(item.source_locator == "owned:case.tsv" for item in candidates), (
        "Logical source locator was interpreted or replaced by a local filesystem path"
    )
    last = candidates[-1]

    assert (last.observed_at, last.observation_timezone, last.observed_at_utc) == (
        "2026-10-12T12:34:56+05:30", "+05:30", "2026-10-12T07:04:56.000000+00:00"
    ), "Original source timestamp/timezone or separately derived UTC value changed"
    assert candidates[0].observed_at is None and candidates[0].observed_at_utc is None, (
        "Parser fabricated an observation timestamp for an untimed source occurrence"
    )


@pytest.mark.parametrize("kind,token,normalized", [
    ("ipv4", "0.0.0.0", "0.0.0.0"),
    ("ipv4", "255.255.255.255", "255.255.255.255"),
    ("ipv6", "::", "::"),
    ("ipv6", "::ffff:192.0.2.1", "::ffff:c000:201"),
    ("dns", "A-B.EXAMPLE.INVALID", "a-b.example.invalid"),
    ("dns", "xn--owned.example", "xn--owned.example"),
    ("sha256", "aB" * 32, "ab" * 32),
])
def test_UnitExplicitSupportedTokenFamilies(ioc_source, kind, token, normalized):
    """Explicit supported token families receive deterministic normalization."""

    raw = f"{kind}\t{token}".encode("ascii")
    candidates = ParseIocArtifact(raw, ioc_source(raw))

    assert candidates[0].normalized_token == normalized, (
        "Explicit supported token normalization differs from its known-answer oracle"
    )


@pytest.mark.parametrize("raw", [
    b"", b"\n", b"dns\texample.invalid\n\n", b"dns\texample.invalid\r",
    b"dns\texample.\rinvalid\n", b"dns\texample.invalid\textra\n",
    b"dns\texample.invalid\t\t\n", b"dns\texample.invalid\t2026-10-12T12:00:00\tZ\n",
    b"dns\texample.invalid\t2026-10-12T12:00:00Z\t+00:00\n",
    b"dns\texample.invalid\t2026-10-12T12:00:00-00:00\t-00:00\n",
    b"dns\texample.invalid\t2026-02-30T12:00:00Z\tZ\n",
    b"dns\texample.invalid\t2026-10-12T12:00:00+24:00\t+24:00\n",
    b"\xef\xbb\xbfdns\texample.invalid\n", b"dns\texample.\xff\n",
    b"kind\ttoken\n", b"# comment\n", b"url\thttps://example.invalid/\n",
    b"md5\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", b"sha256\tabcd\n",
    b"ipv4\t0192.0.2.1\n", b"ipv4\t2001:db8::1\n", b"ipv6\t192.0.2.1\n",
    b"ipv6\tfe80::1%eth0\n", b"ipv6\t[2001:db8::1]\n", b"ipv4\t192.0.2.999\n",
    b"dns\tlocalhost\n", b"dns\t192.0.2.1\n", b"dns\tbad_.invalid\n",
    b"dns\t-bad.invalid\n", b"dns\tbad-.invalid\n", b"dns\tbad..invalid\n",
    b"dns\t example.invalid\n", b"dns\texample.invalid \n", b"dns\t\"example.invalid\"\n",
    b"dns\t" + b"a" * 64 + b".invalid\n",
    b"dns\t" + b"a." * 126 + b"invalid\n",
    b"dns\texample.invalid\x00\n", b"dns\texample.invalid\x1b\n",
])
def test_UnitMalformedOrUnsupportedBytesFailClosed(ioc_source, raw):
    """Malformed, inferred, ambiguous, control-bearing and unsupported source bytes are rejected."""

    with pytest.raises(ValueError):
        ParseIocArtifact(raw, ioc_source(raw))


@pytest.mark.parametrize("limits", [
    IocLimits(max_bytes=5), IocLimits(max_lines=1), IocLimits(max_items=1),
    IocLimits(max_line_bytes=10), IocLimits(max_token_bytes=3),
])
def test_UnitEveryCallerParserBudgetIsEnforced(ioc_source, limits):
    """Every independent caller budget constrains the parser beneath its global ceiling."""

    raw = b"dns\texample.invalid\ndns\tsecond.invalid\n"

    with pytest.raises(ValueError, match="budget"):
        ParseIocArtifact(raw, ioc_source(raw), limits)


@pytest.mark.parametrize("name,ceiling", [
    ("max_bytes", 65536), ("max_lines", 256), ("max_items", 256),
    ("max_line_bytes", 512), ("max_token_bytes", 512),
])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", None, "over"])
def test_UnitUnboundedOrUntypedLimitsAreRejected(name, ceiling, value):
    """Limits accept exact positive integers only and cannot expand hard ceilings."""

    with pytest.raises(ValueError):
        IocLimits(**{name: ceiling + 1 if value == "over" else value})


@pytest.mark.parametrize("name", [
    "source_id", "source_version", "source_locator", "license_name", "license_locator",
    "expected_sha256",
])
@pytest.mark.parametrize("value", ["", "a\tb", " x", "a" * 257, "unicode-\u00e9", 1])
def test_UnitSourceAttributionIsExplicitBoundedAscii(ioc_source, name, value):
    """No source/version/license/locator field accepts missing, hidden or unbounded attribution."""

    with pytest.raises(ValueError):
        replace(ioc_source(b"dns\texample.invalid"), **{name: value})


def test_UnitExactDigestAndAcquisitionByteBoundary(ioc_source):
    """Pins are exact lowercase digests and acquisition never silently truncates oversized bytes."""

    raw = b"dns\texample.invalid\n"

    with pytest.raises(ValueError):
        replace(ioc_source(raw), expected_sha256="G" * 64)

    with pytest.raises(ValueError, match="pin"):
        ParseIocArtifact(raw, ioc_source(raw + b"x"))

    with pytest.raises(ValueError, match="budget"):
        IocRequest(raw, ioc_source(raw), IocLimits(max_bytes=1))

    with pytest.raises(ValueError):
        IocRequest(bytearray(raw), ioc_source(raw))


@pytest.mark.parametrize("zone", ["Z", "+00:00", "-03:30"])
def test_UnitOriginalObservationTimezoneIsNeverAcquisitionTime(ioc_source, zone):
    """Future declared observations remain source assertions and retain their original suffix."""

    raw = f"dns\texample.invalid\t2099-01-01T00:00:00.12{zone}\t{zone}\n".encode()
    candidate = ParseIocArtifact(raw, ioc_source(raw))[0]

    assert candidate.observed_at == f"2099-01-01T00:00:00.12{zone}" and (
        candidate.observation_timezone == zone
    ), "A source-declared observation was normalized away or substituted for an acquisition clock"


@pytest.mark.parametrize("payload", [
    b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x": 1}',
    b"{", b'{"x":"\xff"}', b'{"x":' + b"[" * 9 + b"0" + b"]" * 9 + b"}",
])
def test_UnitMetadataRejectsNoncanonicalDuplicateNonfiniteAndDeepJson(payload):
    """Snapshot/receipt interchange cannot hide fields or allocate unbounded nested JSON."""

    with pytest.raises(ValueError):
        Metadata(payload, 512)


def test_UnitMetadataQuotesDoNotCreateFalseDepthAndSizeIsCheckedFirst():
    """Quoted brackets/escaped quotes remain text while size and byte type limits fail closed."""

    assert Metadata(b'{"x":"[[[[[[[[[\\\""}', 512) == {"x": '[[[[[[[[["'}, (
        "Metadata depth scanning treated quoted brackets as structural nesting"
    )

    for payload, maximum in ((b'{"x":0}', 2), ("{}", 10)):
        with pytest.raises(ValueError):
            Metadata(payload, maximum)


@pytest.mark.parametrize("changes", [
    {"normalized_token": "else.invalid"}, {"observed_at_utc": "2099"},
    {"line_number": True}, {"byte_offset": -1}, {"byte_length": 2},
])
def test_UnitCandidateFactsMustAgreeWithTheirDeclaredGrammar(ioc_source, changes):
    """A candidate cannot claim a different normalization, offset type or token length."""

    raw = b"dns\texample.invalid"
    original = ParseIocArtifact(raw, ioc_source(raw))[0]

    with pytest.raises(ValueError):
        replace(original, **changes)


@pytest.mark.parametrize("candidates", [(), [], (object(),)])
def test_UnitSnapshotRequiresExactBoundedCandidateTypes(ioc_source, candidates):
    """Snapshot serialization cannot accept foreign or empty normalized candidate collections."""

    snapshot = IocSnapshot("sha256:" + "a" * 64, "sha256:" + "b" * 64,
                           ioc_source(b"dns\texample.invalid"), IocLimits(), candidates)

    with pytest.raises(ValueError):
        snapshot.Serialize()


def test_UnitInvalidCandidateAndManifestIdentityAreRejected(ioc_source):
    """Foreign token kind and manifest identity cannot be serialized as a verified IOC snapshot."""

    with pytest.raises(ValueError):
        IocCandidate("sha1", "abc", "abc", "owned:x", 1, 5, 3, None, None, None)

    raw = b"dns\texample.invalid"
    snapshot = IocSnapshot("sha256:wrong", "sha256:" + "a" * 64, ioc_source(raw), IocLimits(),
                           ParseIocArtifact(raw, ioc_source(raw)))

    with pytest.raises(ValueError):
        snapshot.Serialize()
