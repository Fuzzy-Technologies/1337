# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental pure EPSS gzip selection; no acquisition, storage or legacy snapshot dispatch."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal

from fuzzy1337.intel_references import CanonicalReferenceJson, RequireReferenceDigest
from fuzzy1337.intelligence import (
    EpssScoreTime,
    IntelligenceDate,
    IntelligenceIdentifier,
    IntelligenceText,
)

__all__ = ("EpssSelectedRecord", "EpssSelection", "ParseEpssSelection")

SELECTION_SCHEMA_VERSION = 2
SELECTION_PROFILE_VERSION = 1
MAX_COMPRESSED_BYTES = 4 * 1024 * 1024
MAX_DECODED_BYTES = 16 * 1024 * 1024
MAX_CSV_ROWS = 500_000
MAX_REQUESTED_IDS = 64
MAX_ABSOLUTE_EXPONENT = 32
_PROBABILITY_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,3})?\Z",
)


def DecimalToken(value: str) -> str:
    """Require an exact finite source decimal with bounded spelling and exponent.

    Args:
        value: Original unsigned ordinary or scientific decimal token.

    Returns:
        Unmodified token in 0..1; Decimal arithmetic does not round or underflow it.
    """

    if not isinstance(value, str) or len(value) > 32 or not _PROBABILITY_PATTERN.fullmatch(value):
        raise ValueError("EPSS assertions require bounded finite decimal tokens")

    exponent = value.lower().partition("e")[2]

    if exponent and abs(int(exponent)) > MAX_ABSOLUTE_EXPONENT:
        raise ValueError("EPSS decimal exponent exceeds its profile")

    if not 0 <= Decimal(value) <= 1:
        raise ValueError("EPSS decimal assertions must remain in 0..1")

    return value


@dataclass(frozen=True, slots=True)
class EpssSelectedRecord:
    """Retain one original decimal assertion without a binary-float or risk conversion."""

    identifier: str
    probability: str
    percentile: str

    def __post_init__(self) -> None:
        """Reject malformed direct construction as well as invalid original CSV assertions."""

        if not IntelligenceIdentifier(self.identifier).startswith("CVE-"):
            raise ValueError("EPSS record requires a canonical CVE identifier")

        DecimalToken(self.probability)
        DecimalToken(self.percentile)

    def ToDict(self) -> dict[str, str]:
        """Return detached exact source tokens for the distinct selection profile.

        Returns:
            CVE identifier, probability and percentile original decimal strings.
        """

        return {"identifier": self.identifier, "probability": self.probability,
                "percentile": self.percentile}


@dataclass(frozen=True, slots=True)
class EpssSelection:
    """Hold immutable parser output, distinct from a stored or authenticated Intel snapshot."""

    requested_ids: tuple[str, ...]
    records: tuple[EpssSelectedRecord, ...]
    unmatched_ids: tuple[str, ...]
    model_version: str
    score_date: str
    effective_at: str
    original_metadata: str
    raw_sha256: str
    raw_size: int
    decoded_sha256: str
    decoded_size: int
    row_count: int

    def __post_init__(self) -> None:
        """Require immutable structural facts without claiming to reverify unavailable raw bytes."""

        if type(self.requested_ids) is not tuple or self.requested_ids != RequestedIds(
            self.requested_ids,
        ):
            raise ValueError("EPSS DTO requires an immutable canonical requested sequence")

        if type(self.records) is not tuple or any(
            type(record) is not EpssSelectedRecord for record in self.records
        ):
            raise ValueError("EPSS DTO requires immutable typed records")

        matched = tuple(record.identifier for record in self.records)

        if matched != tuple(sorted(set(matched))) or not set(matched) <= set(self.requested_ids):
            raise ValueError("EPSS DTO matched IDs must be canonical selected unique records")

        if type(self.unmatched_ids) is not tuple or self.unmatched_ids != tuple(
            identifier for identifier in self.requested_ids if identifier not in matched
        ):
            raise ValueError("EPSS DTO requires the exact immutable unmatched partition")

        IntelligenceText(self.model_version, "EPSS selected model version", 256)
        IntelligenceDate(self.score_date)

        if not isinstance(self.original_metadata, str):
            raise ValueError("EPSS DTO requires original metadata text")

        line, effective = Metadata(
            io.StringIO(self.original_metadata), self.model_version, self.score_date,
        )

        if line != self.original_metadata or effective != self.effective_at:
            raise ValueError("EPSS DTO metadata or source clock does not match original facts")

        RequireReferenceDigest(self.raw_sha256)
        RequireReferenceDigest(self.decoded_sha256)

        for value, maximum in ((self.raw_size, MAX_COMPRESSED_BYTES),
                               (self.decoded_size, MAX_DECODED_BYTES)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("EPSS DTO byte facts exceed their profile")

        if type(self.row_count) is not int or not (
            len(self.records) <= self.row_count <= MAX_CSV_ROWS
        ):
            raise ValueError("EPSS DTO row count does not match its selected record budget")

    def ToDict(self) -> dict[str, object]:
        """Describe selected assertions and exact custody facts without claiming SDK acceptance.

        Returns:
            Detached schema-two/profile-one content; absent IDs remain explicitly unmatched.
        """

        return {
            "schema_version": SELECTION_SCHEMA_VERSION,
            "profile_version": SELECTION_PROFILE_VERSION,
            "profile": "epss-dated-gzip-selected",
            "requested_ids": list(self.requested_ids),
            "matched_ids": [record.identifier for record in self.records],
            "unmatched_ids": list(self.unmatched_ids),
            "records": [record.ToDict() for record in self.records],
            "model_version": self.model_version, "score_date": self.score_date,
            "effective_at": self.effective_at, "original_metadata": self.original_metadata,
            "raw_sha256": self.raw_sha256, "raw_size": self.raw_size,
            "decoded_sha256": self.decoded_sha256, "decoded_size": self.decoded_size,
            "row_count": self.row_count, "gzip_members": 1,
            "limits": {"compressed_bytes": MAX_COMPRESSED_BYTES,
                       "decoded_bytes": MAX_DECODED_BYTES, "csv_rows": MAX_CSV_ROWS,
                       "requested_ids": MAX_REQUESTED_IDS,
                       "absolute_decimal_exponent": MAX_ABSOLUTE_EXPONENT},
        }

    def Reference(self) -> str:
        """Bind source identity, requested scope, source assertions and decode profile.

        Returns:
            Separate deterministic reference; never a legacy intelligence snapshot reference.
        """

        return "epss-selection:" + hashlib.sha256(CanonicalReferenceJson(self.ToDict())).hexdigest()


def DecodeGzip(payload: bytes) -> bytes:
    """Bound expansion while requiring one complete gzip member with checked CRC and EOF.

    Args:
        payload: Original complete gzip bytes, never an HTTP content-encoding promise.

    Returns:
        At most the fixed decoded byte budget; trailing and concatenated members refuse.
    """

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_COMPRESSED_BYTES:
        raise ValueError("EPSS gzip exceeds its compressed byte profile")

    decoder = zlib.decompressobj(31)

    try:
        decoded = decoder.decompress(payload, MAX_DECODED_BYTES + 1)

        if len(decoded) > MAX_DECODED_BYTES or decoder.unconsumed_tail:
            raise ValueError("EPSS gzip exceeds its decoded byte profile")

        if not decoder.eof or decoder.unused_data:
            raise ValueError("EPSS requires one complete gzip member without trailing bytes")

        return decoded

    except zlib.error as error:
        raise ValueError("EPSS gzip header, stream or CRC is invalid") from error


def RequestedIds(requested_ids: Sequence[str]) -> tuple[str, ...]:
    """Require a finite explicit unique CVE selection before decoding any corpus.

    Args:
        requested_ids: Caller-selected sequence, not an unbounded iterator or one string.

    Returns:
        Lexically sorted canonical CVE identifiers without silently removing duplicates.
    """

    if (
        not isinstance(requested_ids, (tuple, list))
        or not 1 <= len(requested_ids) <= MAX_REQUESTED_IDS
    ):
        raise ValueError("EPSS requires one to 64 explicit requested CVE identifiers")

    identifiers = tuple(IntelligenceIdentifier(value) for value in requested_ids)

    if any(not value.startswith("CVE-") for value in identifiers) or (
        len(set(identifiers)) != len(identifiers)
    ):
        raise ValueError("EPSS requested CVE identifiers must be unique and canonical")

    return tuple(sorted(identifiers))


def Metadata(stream: io.StringIO, model_version: str, score_date: str) -> tuple[str, str]:
    """Validate original explicit model and full score clock against caller-selected facts.

    Args:
        stream: Decoded original UTF-8 CSV, positioned at its first character.
        model_version: Exact expected model revision, never the API version.
        score_date: Exact expected archive calendar day without an invented time.

    Returns:
        Unchanged original metadata line and normalized explicit score timestamp.
    """

    line = stream.readline(514)

    if len(line.encode("utf-8")) > 512 or not line.startswith("#"):
        raise ValueError("EPSS requires bounded original model and score-date metadata")

    metadata = {}

    for component in line.rstrip("\r\n")[1:].split(","):
        key, separator, value = component.partition(":")

        if not separator or key in metadata:
            raise ValueError("EPSS metadata fields must be explicit and unique")

        metadata[key] = value

    if set(metadata) != {"model_version", "score_date"} or (
        metadata["model_version"] != model_version
    ):
        raise ValueError("EPSS source model does not match its explicit selection")

    effective_at = EpssScoreTime(metadata["score_date"])

    if metadata["score_date"][:10] != score_date:
        raise ValueError("EPSS source calendar day does not match its dated selection")

    return line, effective_at


def ParseEpssSelection(
    payload: bytes, requested_ids: Sequence[str], *, model_version: str, score_date: str,
) -> EpssSelection:
    """Validate every original row while retaining normalized assertions only for selected IDs.

    Args:
        payload: Original single-member gzip bytes with actual publisher metadata.
        requested_ids: One to 64 unique canonical CVEs; missing IDs remain unmatched.
        model_version: Explicit expected model revision; no model value is synthesized.
        score_date: Explicit expected YYYY-MM-DD archive day, checked against the source clock.

    Returns:
        Immutable pure decode/selection result with original hashes and bounded decode facts.
        This foundation does not perform acquisition, receipt replay or product inspection.
    """

    requested = RequestedIds(requested_ids)
    IntelligenceText(model_version, "EPSS selected model version", 256)
    IntelligenceDate(score_date)
    decoded = DecodeGzip(payload)

    try:
        stream = io.StringIO(decoded.decode("utf-8"), newline="")
        metadata, effective_at = Metadata(stream, model_version, score_date)
        reader = csv.reader(stream, strict=True)

        if next(reader, None) != ["cve", "epss", "percentile"]:
            raise ValueError("EPSS requires exact cve,epss,percentile columns")

        seen: set[str] = set()
        selected = {}
        wanted = frozenset(requested)

        for row in reader:
            if len(row) != 3 or len(seen) >= MAX_CSV_ROWS:
                raise ValueError("EPSS rows exceed their shape or count profile")

            identifier = IntelligenceIdentifier(row[0])

            if not identifier.startswith("CVE-") or identifier in seen:
                raise ValueError("EPSS corpus CVE identifiers must be unique and canonical")

            for value in row[1:]:
                DecimalToken(value)

            seen.add(identifier)

            if identifier in wanted:
                selected[identifier] = EpssSelectedRecord(identifier, row[1], row[2])

        records = tuple(selected[identifier] for identifier in requested if identifier in selected)
        unmatched = tuple(identifier for identifier in requested if identifier not in selected)

        return EpssSelection(
            requested, records, unmatched, model_version, score_date, effective_at, metadata,
            hashlib.sha256(payload).hexdigest(), len(payload),
            hashlib.sha256(decoded).hexdigest(), len(decoded), len(seen),
        )

    except (UnicodeError, csv.Error) as error:
        raise ValueError("EPSS source must be valid bounded UTF-8 CSV") from error
