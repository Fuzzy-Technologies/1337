# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure independent source/record expectation checks; no producer, transport or installed work."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.contract.owned_content_response_oracle import (
    CaseMatrix,
    InputRejections,
    MatrixManifest,
    RequestBytes,
)

MATRIX = CaseMatrix()
MANIFEST = Path(__file__).resolve().parents[1] / "fixtures/owned_content_response/oracle.v1.json"


def FieldNames(headers: bytes) -> tuple[bytes, ...]:
    """Read complete actual original field names without a production parser or result metadata."""

    assert headers.startswith(b"HTTP/1.1 200 OK\r\n") and headers.endswith(b"\r\n\r\n"), (
        "Admitted source requires complete exact original status and CRLF framing")
    fields = headers.split(b"\r\n")[1:-2]
    names = tuple(line.split(b":", 1)[0].lower() for line in fields)
    assert len(names) == len(set(names)) <= 64, "Admitted source field names remain unique"

    return names


@pytest.mark.parametrize("case", MATRIX, ids=lambda case: case.name)
def test_FrozenIndependentCaseShapeBytesAndHeaderTruth(case) -> None:
    """Every finite expectation is internally bounded and independent of a producer report."""

    assert len(case.Wire()) <= 81921, "Even deliberate source overflows have a fixed finite bound"
    record = case.ExpectedRecord("http://127.0.0.1:15432" + case.path)
    stdout = case.ExpectedStdout("http://127.0.0.1:15432" + case.path)
    assert stdout.isascii() and not stdout.endswith(b"\n") and json.loads(stdout) == record, (
        "Expected worker stdout is one canonical ASCII record without BOM or terminal newline")

    if case.error is not None:
        assert record == {"schema_version": 1, "profile": "owned-content-response-capture.v1",
            "outcome": "refused", "error": case.error}, "Refusal retains only the fixed safe code"
        encoded = json.dumps(record)
        assert hashlib.sha256(case.Wire()).hexdigest() not in encoded, (
            "Expected refusal cannot claim a digest of rejected source bytes")

    else:
        names = FieldNames(case.headers)
        assert (b"x-content-type-options" not in names) is case.header_absent, (
            "Handwritten header truth must agree with complete source field names")
        assert len(case.headers) <= 16384 and len(case.body) <= 65536 and (
            len(case.Wire()) <= 81920), "Admitted source keeps all inclusive byte bounds"
        assert all(len(line) + 2 <= 4096 for line in case.headers.split(b"\r\n")[:-2]), (
            "Admitted status and field lines each keep their exact CRLF-inclusive ceiling")
        assert case.body.decode("utf-8").encode("utf-8") == case.body, (
            "Original UTF8 bytes are never normalized or replaced")
        assert record["response_body"]["size_bytes"] == len(case.body), (
            "Expected original-byte metadata must include admitted zero-byte bodies")


def test_ManifestFreezesSameUrlBodyChangesAndExactInclusiveBoundaries() -> None:
    """Stable hashes expose unintended source drift; the manifest is never production admission."""

    assert json.loads(MANIFEST.read_bytes()) == MatrixManifest(), (
        "Immutable independent source hashes and manually chosen outcomes must remain exact")
    cases = {case.name: case for case in MATRIX}
    assert cases["missing"].body == cases["fixed"].body and (
        cases["missing"].path == cases["fixed"].path == cases["body-decoy"].path), (
            "Missing/fixed/decoy mutate actual headers/body at the identical selected source URL")
    assert cases["body-alpha"].headers == cases["body-bravo"].headers and (
        cases["body-alpha"].body != cases["body-bravo"].body), (
            "Identical original headers can carry different valid bodies without catalog dispatch")
    assert len(cases["wire-limit"].headers) == 16384 and len(cases["wire-limit"].body) == (
        65536), "The admitted maximum wire reaches both inclusive source bounds"
    assert len(cases["extra-byte-at-maximum"].body) == 65536 and (
        len(cases["extra-byte-at-maximum"].extra) == 1), "A one-byte probe is required at max body"
    assert cases["empty-body"].ExpectedRecord("http://127.0.0.1:15432/research/content")[
        "response_body"]["base64"] == "", "Admitted zero-byte body needs canonical empty base64"


@pytest.mark.parametrize("authority", ["127.0.0.1:15432", "[::1]:15432"])
def test_ExactAnonymousRequestRetainsLiteralIpv4Ipv6Authority(authority) -> None:
    """The independent expected GET preserves IPv6 brackets and never resolves a hostname."""

    request = RequestBytes("http://" + authority + "/research/content")
    assert request == (b"GET /research/content HTTP/1.1\r\nHost: " + authority.encode() +
        b"\r\nConnection: close\r\nAccept: text/html, text/plain\r\nAccept-Encoding: identity\r\n"
        b"User-Agent: 1337-owned-content-response/1\r\n\r\n"), "Exact original GET grammar changed"
    assert len(InputRejections()) == 20, "All unsupported URL cases require zero original contact"
