# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise bounded EPSS gzip selection with independent synthetic source mutations."""

from __future__ import annotations

import gzip
import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337 import intelligence_epss_selection as selection

MODEL = "synthetic-model-1"
DAY = "2026-11-02"
FIRST = "CVE-1900-0001"
SECOND = "CVE-1900-0002"
MISSING = "CVE-1900-9999"
HEADER = f"#model_version:{MODEL},score_date:{DAY}T12:00:30Z\n"
CSV_HEADER = "cve,epss,percentile\n"


def Body(rows: str = f"{FIRST},0.047530,0.91883\n") -> bytes:
    """Create original deterministic synthetic UTF-8 CSV without official-source claims."""

    return (HEADER + CSV_HEADER + rows).encode()


def Parse(raw: bytes | None = None, ids=(FIRST,)) -> selection.EpssSelection:
    """Use the actual pure profile parser over original synthetic gzip bytes."""

    payload = gzip.compress(Body() if raw is None else raw, mtime=0)

    return selection.ParseEpssSelection(payload, ids, model_version=MODEL, score_date=DAY)


def test_SelectionRetainsExactAssertionsClockHashesAndUnknownWithoutZero():
    """A requested absent CVE is unmatched while original decimal tokens remain distinct."""

    raw = Body(f"{FIRST},0.047530,0.91883\n{SECOND},0,1.000\n")
    payload = gzip.compress(raw, mtime=0)
    result = selection.ParseEpssSelection(
        payload, [MISSING, SECOND, FIRST], model_version=MODEL, score_date=DAY,
    )
    assert result.requested_ids == (FIRST, SECOND, MISSING), "Requested IDs lost canonical order"
    assert result.unmatched_ids == (MISSING,) and len(result.records) == 2, "Unknown became a score"
    assert result.records[0].probability == "0.047530", "Original decimal spelling changed"
    assert result.records[1].percentile == "1.000", "Probability and percentile were conflated"
    assert result.effective_at == "2026-11-02T12:00:30.000000+00:00", "Source clock changed"
    assert result.original_metadata == HEADER and result.row_count == 2, "Original facts changed"
    assert (result.raw_sha256, result.raw_size) == (
        hashlib.sha256(payload).hexdigest(), len(payload),
    ), "Original compressed identity changed"
    assert (result.decoded_sha256, result.decoded_size) == (
        hashlib.sha256(raw).hexdigest(), len(raw),
    ), "Decoded source identity changed"
    assert result.Reference() == selection.ParseEpssSelection(
        payload, [FIRST, MISSING, SECOND], model_version=MODEL, score_date=DAY,
    ).Reference(), "Selection order changed deterministic identity"


def test_ImmutableOutputAndDetachedPresentationCannotChangeSelectedFacts():
    """Frozen DTOs and detached dictionaries preserve parser-produced source facts."""

    result = Parse()
    original = result.Reference()
    document = result.ToDict()
    document["records"][0]["probability"] = "1"
    document["requested_ids"].append(MISSING)
    assert result.Reference() == original, "Detached presentation changed immutable parser facts"

    with pytest.raises(FrozenInstanceError):
        result.model_version = "changed"

    with pytest.raises(FrozenInstanceError):
        result.records[0].probability = "1"


@pytest.mark.parametrize("ids", [[], (), FIRST, None, {FIRST}, iter([FIRST]),
    [FIRST, FIRST], [True], ["cve-1900-0001"], ["CWE-79"], ["CVE-1900-001"],
    [f"CVE-1900-{index:04}" for index in range(65)]])
def test_InvalidSelectionsRefuseBeforeSourceDecode(ids):
    """Explicit finite unique canonical CVE selections cannot become full-corpus requests."""

    with pytest.raises(ValueError):
        selection.ParseEpssSelection(b"invalid gzip", ids, model_version=MODEL, score_date=DAY)


def test_Inclusive64IdsCanAllRemainUnknown():
    """The inclusive finite selection ceiling does not require fabricated score records."""

    ids = [f"CVE-2000-{index:04}" for index in range(64)]
    result = Parse(ids=ids)
    assert result.unmatched_ids == tuple(ids) and result.records == (), (
        "Missing IDs acquired scores"
    )


@pytest.mark.parametrize("mutation", ["empty", "plain", "zlib", "header", "crc", "size",
    "truncated", "trailer", "concatenated", "empty-member", "junk"])
def test_InvalidGzipMembersNeverProduceSelectedAssertions(mutation):
    """CRC, trailer, single-member and stream invariants are checked beyond declared ISIZE."""

    payload = gzip.compress(Body(), mtime=0)

    if mutation == "empty":
        payload = b""

    elif mutation == "plain":
        payload = Body()

    elif mutation == "zlib":
        import zlib

        payload = zlib.compress(Body())

    elif mutation == "header":
        payload = b"\x00" + payload[1:]

    elif mutation == "crc":
        payload = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]

    elif mutation == "size":
        payload = payload[:-1] + bytes([payload[-1] ^ 1])

    elif mutation == "truncated":
        payload = payload[:15]

    elif mutation == "trailer":
        payload = payload[:-1]

    elif mutation == "concatenated":
        payload += gzip.compress(Body(), mtime=0)

    elif mutation == "empty-member":
        payload += gzip.compress(b"", mtime=0)

    else:
        payload += b"trailing bytes"

    with pytest.raises(ValueError):
        selection.ParseEpssSelection(payload, [FIRST], model_version=MODEL, score_date=DAY)


@pytest.mark.parametrize("field", ["MAX_COMPRESSED_BYTES", "MAX_DECODED_BYTES", "MAX_CSV_ROWS"])
def test_ResourceBoundariesAreInclusiveAndFailAboveOriginalMeasuredSize(monkeypatch, field):
    """Compressed, expanded and row budgets refuse at the first exceeded boundary."""

    raw = Body()
    payload = gzip.compress(raw, mtime=0)
    limit = {"MAX_COMPRESSED_BYTES": len(payload), "MAX_DECODED_BYTES": len(raw),
             "MAX_CSV_ROWS": 1}[field]
    monkeypatch.setattr(selection, field, limit)
    assert Parse().row_count == 1, "An inclusive resource ceiling was rejected"
    monkeypatch.setattr(selection, field, limit - 1)

    with pytest.raises(ValueError):
        Parse()


def test_ActualProfileExpansionBombIsRejectedWithoutTrustingTrailer():
    """A tiny compressed body cannot allocate beyond the actual fixed expanded ceiling."""

    payload = gzip.compress(b"a" * (selection.MAX_DECODED_BYTES + 1), mtime=0)
    assert len(payload) < selection.MAX_COMPRESSED_BYTES, "Bomb fixture exceeds compressed budget"

    with pytest.raises(ValueError, match="decoded"):
        selection.ParseEpssSelection(payload, [FIRST], model_version=MODEL, score_date=DAY)


@pytest.mark.parametrize("replacement", [
    b"", b"#model_version:other,score_date:2026-11-02T12:00:30Z\n",
    b"#model_version:synthetic-model-1,score_date:2026-11-03T12:00:30Z\n",
    b"#model_version:synthetic-model-1,score_date:2026-11-02\n",
    b"#model_version:synthetic-model-1,score_date:2026-11-02T12:00:30\n",
    b"#model_version:synthetic-model-1,score_date:2026-02-30T12:00:30Z\n",
    b"#model_version:synthetic-model-1,score_date:2026-11-02T12:00:30Z,extra:x\n",
    b"#model_version:synthetic-model-1,score_date:2026-11-02T12:00:30Z,model_version:x\n",
    b"#model_version:synthetic-model-1,score_date\n", b"#" + b"x" * 513 + b"\n",
])
def test_ModelClockAndOriginalMetadataCannotBeInventedOrBorrowed(replacement):
    """Absent clocks, mismatched models/days and malformed headers fail explicitly."""

    with pytest.raises(ValueError):
        Parse(replacement + CSV_HEADER.encode() + f"{FIRST},0.1,0.2\n".encode())


@pytest.mark.parametrize("model,day", [("", DAY), (MODEL + " ", DAY), (True, DAY),
    (MODEL, "2026-11"), (MODEL, "2026-02-30"), (MODEL, True)])
def test_CallerMetadataSelectionIsStrict(model, day):
    """Invalid caller metadata cannot substitute for an explicit model and calendar day."""

    with pytest.raises(ValueError):
        selection.ParseEpssSelection(
            gzip.compress(Body(), mtime=0), [FIRST], model_version=model, score_date=day,
        )


@pytest.mark.parametrize("value", ["nan", "NaN", "Infinity", "-0.1", "-0", "1.1", "1e2",
    "1e-9999", "1e-33", "0e33", "0E-999", "1e+9999999",
    ".1", "0.", " 0.1", "+0.1", "0.1 ", "0." + "0" * 31])
@pytest.mark.parametrize("column", [1, 2])
def test_UnselectedRowNumericValidationCannotBeSkipped(value, column):
    """Even an unrequested invalid row poisons the corpus, including percentile failures."""

    row = [SECOND, "0.1", "0.2"]
    row[column] = value

    with pytest.raises(ValueError):
        Parse(Body(f"{FIRST},0.1,0.2\n" + ",".join(row) + "\n"))


@pytest.mark.parametrize("row", [f"{SECOND},0.1\n", f"{SECOND},0.1,0.2,extra\n",
    "cve-1900-0002,0.1,0.2\n", "CWE-79,0.1,0.2\n", "\n",
    f"{SECOND},0.1,0.2\n{SECOND},0.2,0.3\n", '"unterminated,0.1,0.2\n'])
def test_UnselectedShapesIdentifiersAndDuplicatesRemainStrict(row):
    """Selection never hides malformed rows, duplicate identities or non-CVE taxonomies."""

    with pytest.raises(ValueError):
        Parse(Body(f"{FIRST},0.1,0.2\n" + row))


@pytest.mark.parametrize("raw", [
    b"\xff", Body().replace(b"cve,epss,percentile", b"cve,percentile,epss"),
])
def test_EncodingAndColumnOrderAreNotGuessed(raw):
    """Only the documented UTF-8 CSV and exact original column order are supported."""

    with pytest.raises(ValueError):
        Parse(raw)


def test_ExplicitHistoricalOffsetRetainsOriginalClockWhileNormalizingUtc():
    """A source-provided basic numeric zone is accepted without inventing a score time."""

    raw = Body().replace(b"12:00:30Z", b"01:00:30+0200")
    result = Parse(raw)
    assert result.effective_at == "2026-11-01T23:00:30.000000+00:00", "Explicit zone was lost"
    assert result.score_date == DAY and "01:00:30+0200" in result.original_metadata, (
        "Source calendar day or original clock changed"
    )


def test_PublisherScientificDecimalTokensRemainExactAndContextIndependent():
    """FIRST's bounded scientific percentile spelling is a decimal assertion, not invalid JSON."""

    from decimal import Inexact, localcontext

    with localcontext() as context:
        context.prec = 1
        context.traps[Inexact] = True
        result = Parse(Body(f"{FIRST},0.0006,6e-05\n{SECOND},1e-2,1E+0\n"), (FIRST, SECOND))

    assert result.records[0].percentile == "6e-05", "Scientific source assertion was rounded"
    assert result.records[1].probability == "1e-2", "Decimal exponent source token changed"


@pytest.mark.parametrize("field,value", [("identifier", "CWE-79"), ("identifier", "bad"),
    ("probability", "NaN"), ("probability", 0.1), ("percentile", "1.1"),
    ("percentile", "1e-999")])
def test_DirectRecordConstructionCannotBypassSourceScalarContracts(field, value):
    """Exported DTO replacement is validated without trusting construction through the parser."""

    with pytest.raises(ValueError):
        replace(Parse().records[0], **{field: value})


@pytest.mark.parametrize("field,value", [
    ("requested_ids", [FIRST]), ("requested_ids", (SECOND, FIRST)),
    ("requested_ids", ()), ("records", []), ("records", ("untyped",)),
    ("unmatched_ids", []), ("unmatched_ids", (MISSING,)),
    ("model_version", "other"), ("score_date", "2026-11-03"),
    ("effective_at", "2026-11-02T00:00:00Z"), ("original_metadata", None),
    ("original_metadata", HEADER + "extra"), ("raw_sha256", "bad"),
    ("decoded_sha256", "F" * 64), ("raw_size", True), ("raw_size", 0),
    ("raw_size", selection.MAX_COMPRESSED_BYTES + 1), ("decoded_size", -1),
    ("decoded_size", selection.MAX_DECODED_BYTES + 1),
    ("row_count", True), ("row_count", -1), ("row_count", 0),
    ("row_count", selection.MAX_CSV_ROWS + 1),
])
def test_DirectSelectionConstructionRejectsAliasesAndInconsistentFacts(field, value):
    """Profile identity requires typed budgets, exact metadata and a canonical partition."""

    with pytest.raises(ValueError):
        replace(Parse(), **{field: value})


@pytest.mark.parametrize("mutation", ["duplicate", "outside", "unordered"])
def test_DirectMatchedPartitionCannotForgeDuplicateForeignOrUnorderedRecords(mutation):
    """Matched record identities must be a canonical unique subset of the explicit request."""

    first = Parse().records[0]
    second = replace(first, identifier=SECOND)
    valid = Parse(Body(f"{FIRST},0.1,0.2\n{SECOND},0.2,0.3\n"), (FIRST, SECOND))
    records = {"duplicate": (first, first), "outside": (replace(first, identifier=MISSING),),
               "unordered": (second, first)}[mutation]

    with pytest.raises(ValueError):
        replace(valid, records=records)


def test_SmallestSupportedScientificTokenDoesNotBecomeZero():
    """Exact decimal tokens preserve positive tiny assertions at the documented exponent bound."""

    result = Parse(Body(f"{FIRST},1e-32,0e+32\n"))
    assert result.records[0].probability == "1e-32", "Positive tiny assertion became zero"
