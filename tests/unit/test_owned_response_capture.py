# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent original-wire and strict pure owned-response record admission checks."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters import owned_response_capture as capture

CATALOG = Path(__file__).parents[1] / "contract/fixtures/zap-passive.oracle.v1.json"
ORACLE = json.loads(CATALOG.read_bytes())


def Record(case_id="missing", address="127.0.0.1"):
    """Build an independent record from handwritten original fixtures and request grammar."""

    case = next(case for case in ORACLE["cases"] if case["case_id"] == case_id)
    authority = "[::1]:19008" if address == "::1" else "127.0.0.1:19008"
    url = "http://" + authority + case["path"]
    request = (f"GET {case['path']} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
        "Accept: text/html\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-response/1\r\n\r\n").encode("ascii")
    return {"schema_version": 1, "profile": "owned-response-capture.v1", "outcome": "captured",
        "catalog_sha256": "fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7",
        "case_id": case_id, "url": url, "address": address, "port": 19008,
        "request": {"base64": base64.b64encode(request).decode(), "size_bytes": len(request),
                    "sha256": hashlib.sha256(request).hexdigest()},
        "response_headers": {key: case["header_section"][key] for key in
                             ("base64", "size_bytes", "sha256")},
        "response_body": {key: case["body"][key] for key in ("base64", "size_bytes", "sha256")},
        "response": {key: case["response"][key] for key in ("size_bytes", "sha256")}}


@pytest.mark.parametrize("case_id", ["missing", "fixed", "body-decoy"])
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_IndependentOriginalRecordsAndFrozenCatalogMatchExactly(case_id, address):
    """Original wire admission uses actual byte facts without selected-rule expected outcomes."""

    record = Record(case_id, address)
    raw = SerializeContract(record).encode()
    assert capture.ParseOwnedResponseCapture(raw, record["url"]) == record, (
        "Both canonical literal families must retain the independent exact original record."
    )
    assert hashlib.sha256(CATALOG.read_bytes()).hexdigest() == (
        capture.OWNED_RESPONSE_CATALOG_SHA256
    ), "The versioned original catalog must retain its independently reviewed file digest."
    headers, body = capture.ReviewedResponse(case_id)
    assert headers == base64.b64decode(record["response_headers"]["base64"]) and body == (
        base64.b64decode(record["response_body"]["base64"])
    ), "Runtime admission must freeze exactly the independently authored header/body bytes."
    assert capture.RequestBytes(record["url"]) == base64.b64decode(record["request"]["base64"]), (
        "Request order, case, spacing and final CRLF must match the independent template."
    )


@pytest.mark.parametrize("error", ["input", "connection", "timeout", "protocol",
                                  "response-policy", "body-policy"])
def test_SixClosedRefusalsContainNoResponseAssociation(error):
    """A safe refusal remains a refusal without a response body, selected URL or content hash."""

    record = {"schema_version": 1, "profile": "owned-response-capture.v1",
              "outcome": "refused", "error": error}
    parsed = capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), Record()["url"])
    assert parsed == record, "Every closed refusal must retain only the exact four safe fields."


@pytest.mark.parametrize("url", [None, "", "http://localhost:19008/zap-passive/missing",
    "http://127.0.0.2:19008/zap-passive/missing", "http://[0:0:0:0:0:0:0:1]:19008/zap-passive/missing",
    "HTTP://127.0.0.1:19008/zap-passive/missing", "https://127.0.0.1:19008/zap-passive/missing",
    "http://127.0.0.1:019008/zap-passive/missing", "http://127.0.0.1:1023/zap-passive/missing",
    "http://127.0.0.1:65536/zap-passive/missing", "http://127.0.0.1/zap-passive/missing",
    "http://127.0.0.1:19008/zap-passive/missing?", "http://127.0.0.1:19008/zap-passive/missing#",
    "http://127.0.0.1:19008/zap-passive/%6dissing", "http://127.0.0.1:19008/zap-passive/missing/",
    "http://127.0.0.1:19008/zap-passive/missing\n", "http://u@127.0.0.1:19008/zap-passive/missing"])
def test_OriginalDestinationSpellingNeverNormalizesOrResolves(url):
    """Alternate authority, path or delimiters fail before network or output interpretation."""

    with pytest.raises(ValueError):
        capture.Destination(url)
    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(SerializeContract(Record()).encode(), url)


@pytest.mark.parametrize("port", [1024, 65535])
def test_CanonicalPortEndpointsRemainAdmitted(port):
    """The explicit reviewed listener port interval includes both declared endpoints."""

    assert capture.Destination(f"http://127.0.0.1:{port}/zap-passive/fixed")[1] == port, (
        "Only the exact canonical bounded port selection may reach a socket."
    )
    with pytest.raises(ValueError):
        capture.ReviewedResponse("unknown")


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 1.0),
    ("schema_version", 2), ("profile", "unknown"), ("outcome", "refused"),
    ("catalog_sha256", "0" * 64), ("case_id", "fixed"), ("address", "::1"),
    ("port", True), ("port", 19008.0), ("port", 19009),
    ("url", "http://127.0.0.1:19009/zap-passive/missing"), ("extra", "PRIVATE_MARKER")])
def test_UnsupportedTypesFieldsAndCrossAssociationsRefuse(field, value):
    """A valid source byte digest cannot substitute another case, selection or primitive type."""

    record = Record()
    record[field] = value
    with pytest.raises(capture.OwnedResponseRecordError) as caught:
        capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), Record()["url"])
    assert "PRIVATE_MARKER" not in str(caught.value), "Rejection must not echo unadmitted fields."


@pytest.mark.parametrize("part", ["request", "response_headers", "response_body"])
@pytest.mark.parametrize("field,value", [("size_bytes", True), ("size_bytes", 1.0),
    ("size_bytes", 1), ("sha256", "A" * 64), ("sha256", "0" * 64),
    ("base64", "AA==\n"), ("base64", "-_=="), ("base64", "PRIVATE_MARKER"),
    ("extra", "PRIVATE_MARKER")])
def test_EveryOriginalBytePartMustMatchEncodingHashLengthAndClosedShape(part, field, value):
    """Part decoding verifies actual independent originals instead of trusting declared hashes."""

    record = Record()
    record[part][field] = value
    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), record["url"])


def test_NonzeroBase64PaddingBitsAreRejectedEvenWithIdenticalDecodedBody():
    """Strict decoder acceptance alone cannot admit alternate encodings of the same bytes."""

    record = Record()
    original = record["response_body"]["base64"]
    changed = original[:-2] + "p="
    assert base64.b64decode(changed, validate=True) == base64.b64decode(original), (
        "This regression must isolate noncanonical padding rather than different source bytes."
    )
    record["response_body"]["base64"] = changed
    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), record["url"])


@pytest.mark.parametrize("change", [{"size_bytes": True}, {"size_bytes": 269.0},
    {"size_bytes": 270}, {"sha256": "0" * 64}, {"base64": "AA=="}])
def test_ConcatenatedOriginalResponseDigestAndLengthAreIndependent(change):
    """Header and body admission still requires their exact joined response descriptor."""

    record = Record()
    record["response"].update(change)
    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), record["url"])


@pytest.mark.parametrize("raw", [b"", b"x" * 8193, b"[]", b"{}\n", b"\xef\xbb\xbf{}",
    b'{"schema_version":1,"schema_version":1}', b'{"nested":{"a":1,"a":1}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":"\\ud800"}', b"\xff",
    b'{"nested":' * 7 + b"0" + b"}" * 7, b'{"nodes":[' + b"0," * 127 + b"0]}"])
def test_StrictOriginalFramingUnicodeDepthAndNodesRefuse(raw):
    """No malformed, duplicate, nonfinite, oversized or overnested record reaches byte admission."""

    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(raw, Record()["url"])


@pytest.mark.parametrize("change", [{"error": "other"}, {"error": []}, {"url": "PRIVATE_MARKER"},
    {"request": {}}, {"schema_version": False}])
def test_RefusalCannotCarrySelectedOrRejectedData(change):
    """A safe refusal object cannot become a channel for rejected response or request material."""

    record = {"schema_version": 1, "profile": "owned-response-capture.v1",
              "outcome": "refused", "error": "protocol", **change}
    with pytest.raises(capture.OwnedResponseRecordError):
        capture.ParseOwnedResponseCapture(SerializeContract(record).encode(), Record()["url"])
