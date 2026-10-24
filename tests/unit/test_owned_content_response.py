# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten original-response truth and independent strict record counterexamples."""

from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters import owned_content_response as capture

URL = "http://127.0.0.1:19008/arbitrary-new-path"
PROFILE = "owned-content-response-capture.v1"


def Headers(body=b"new body", *, media=b"text/plain", extra=b""):
    """Construct independent wire truth without production request/header helpers."""

    return (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nContent-Type: " + media + b"\r\nConnection: close\r\n" + extra + b"\r\n")


def Part(raw):
    """Describe independent original bytes without calling the producer's BytePart."""

    return {"base64": base64.b64encode(raw).decode(), "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest()}


def Record(body=b"new body", headers=None, url=URL, media="text/plain"):
    """Write the eleven-field expected record independently from the worker implementation."""

    authority, _, path = url.removeprefix("http://").partition("/")
    address = "::1" if authority.startswith("[") else "127.0.0.1"
    request = (f"GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
        "Accept: text/html, text/plain\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-content-response/1\r\n\r\n").encode()
    original_headers = Headers(body) if headers is None else headers
    wire = original_headers + body

    return {"schema_version": 1, "profile": PROFILE, "outcome": "captured", "url": url,
        "address": address, "port": int(authority.rsplit(":", 1)[1]), "media_type": media,
        "request": Part(request), "response_headers": Part(original_headers),
        "response_body": Part(body),
        "response": {"size_bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()}}


@pytest.mark.parametrize("url", [URL, "http://[::1]:65535/second/path/",
    "http://127.0.0.1:1024/", "http://127.0.0.1:19008/" + "x/" * 63,
    "http://127.0.0.1:19008/" + "x" * 1023])
@pytest.mark.parametrize("body", [b"", b"completely changed", "\ufeffnew UTF-8 é".encode()])
def test_ContentAndPathsAreNotComparedWithAnyCatalog(url, body):
    """Any selected admitted path and UTF-8 body preserve their exact original bytes."""

    record = Record(body, url=url)
    assert capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), url) == (
        record
    ), (
        "Actual originals, including an empty body, must not depend on catalog membership."
    )
    assert capture.RequestBytes(url) == base64.b64decode(record["request"]["base64"]), (
        "The independently handwritten request must equal the actual fixed request recipe."
    )


@pytest.mark.parametrize("url", [None, 1, "", "http://localhost:19008/a",
    "http://127.0.0.2:19008/a", "http://[0:0:0:0:0:0:0:1]:19008/a",
    "HTTP://127.0.0.1:19008/a", "https://127.0.0.1:19008/a", "http://u@127.0.0.1:19008/a",
    "http://127.0.0.1:19008", "http://127.0.0.1:019008/a", "http://127.0.0.1:1023/a",
    "http://127.0.0.1:65536/a", "http://127.0.0.1:19008/a?", "http://127.0.0.1:19008/a#",
    "http://127.0.0.1:19008/%61", "http://127.0.0.1:19008/../a",
    "http://127.0.0.1:19008/./a", "http://127.0.0.1:19008/a//b", "http://127.0.0.1:19008/{id}",
    "http://127.0.0.1:19008/é", "http://127.0.0.1:19008/a\n",
    "http://127.0.0.1:19008/" + "x/" * 64, "http://127.0.0.1:19008/" + "x" * 1024,
    "http://127.0.0.1:19008/" + "x" * 2048])
def test_OriginalUrlSpellingRefusesBeforeNormalization(url):
    """No normalization, alternate literal, delimiter or excessive path can expand admission."""

    with pytest.raises(ValueError):
        capture.Destination(url)


@pytest.mark.parametrize("media", [b"TEXT/HTML", b"text/plain ;\tcharset=UTF-8\t",
                                  b"text/html; charset=utf-8"])
def test_ChangingHeaderValuesAndOrderingPreserveOriginals(media):
    """Header order/case/OWS and actual XCTO values have no capture-time detector meaning."""

    headers = Headers(extra=b"DaTe: changing\r\nX-Custom: value\r\nx-content-type-options:\t\r\n",
        media=media)
    record = Record(headers=headers, media=media.split(b";")[0].strip().decode().lower())
    assert capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), URL) == (
        record
    ), (
        "Admitted dynamic headers must retain original spelling and empty field values."
    )


@pytest.mark.parametrize("replacement", [b"-1", b"01", b"+1", b"1,1", b"65537", b"9" * 100])
def test_AmbiguousOrExcessiveLengthsCannotBeOriginalFraming(replacement):
    """Canonical decimal length is independently established before body/hash admission."""

    with pytest.raises(capture.ContentResponsePolicyError):
        capture.AdmitHeaders(Headers().replace(b"Length: 8", b"Length: " + replacement))


@pytest.mark.parametrize("extra", [b"content-length: 8\r\n", b"X: a\r\nx: b\r\n",
    b"Transfer-Encoding: chunked\r\n", b"Content-Encoding: identity\r\n", b"Trailer: X\r\n",
    b"TE: trailers\r\n", b"Upgrade: h2c\r\n", b"Location: /elsewhere\r\n",
    b"Set-Cookie: hidden\r\n", b"Set-Cookie2: hidden\r\n", b"Cookie: hidden\r\n",
    b"Authorization: hidden\r\n", b"Proxy-Authorization: hidden\r\n",
    b"WWW-Authenticate: hidden\r\n", b"Proxy-Authenticate: hidden\r\n",
    b" Bad: value\r\n", b"X : value\r\n", b"NoColon\r\n", b"X: a\nb\r\n",
    b"X: a\rb\r\n", b"X: \xff\r\n", b"X: a\x00\r\n",
    pytest.param(b"X: " + b"a" * 4092 + b"\r\n", id="line-cap"),
    b"".join(f"X-{n}: a\r\n".encode() for n in range(62))])
def test_UnsupportedHeaderPolicyNeverBecomesCapturedSource(extra):
    """Duplicate, active, private, malformed and excessive fields remain unassessed."""

    record = Record(headers=Headers(extra=extra))
    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), URL)


@pytest.mark.parametrize("headers", [b"", b"HTTP/1.1 200 OK\r\n\r\n",
    Headers().replace(b"200 OK", b"302 Found"), Headers().replace(b"200 OK", b"100 Continue"),
    Headers().replace(b"Connection: close", b"Connection: keep-alive"),
    Headers().replace(b"Content-Type: text/plain", b"Content-Type: application/json"),
    Headers().replace(b"text/plain", b'text/plain; charset="utf-8"'),
    Headers().replace(b"text/plain", b"text/plain; charset=utf-8; extra=value"),
    Headers() + b"extra", Headers()[:-1], b"x" * 16385])
def test_FullHeaderFramingAndExactMediaAreRechecked(headers):
    """Valid hashes of unsupported response bytes do not establish policy admission."""

    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(
            SerializeContract(Record(headers=headers)).encode(), URL)


def test_MaximumHeaderBodyAndWireRemainWithinStdoutCap():
    """Inclusive caps support an actual full body while preserving the original wire exactly."""

    body = b"x" * 65536
    headers = Headers(body)[:-2]
    index = 0

    while len(headers) < 16382:
        prefix = f"Padding-{index}: ".encode()
        count = min(4096, 16382 - len(headers))
        headers += prefix + b"x" * (count - len(prefix) - 2) + b"\r\n"
        index += 1

    headers += b"\r\n"
    record = Record(body, headers=headers)
    raw = SerializeContract(record).encode()
    assert len(headers) == 16384 and len(raw) < 131072, "Boundary originals must fit stdout."
    assert capture.ParseOwnedContentResponseRecord(raw, URL) == record, (
        "Exact maximum response bytes must remain admissible with canonical records."
    )


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 1.0),
    ("schema_version", 2), ("profile", "owned-response-capture.v1"), ("outcome", "unknown"),
    ("address", "::1"), ("port", True), ("port", 1.0), ("port", 19009), ("url", URL + "x"),
    ("media_type", "text/html"), ("extra", "PRIVATE_MARKER")])
def test_RecordTypesShapesAndPeerBindingAreExact(field, value):
    """Neither valid byte parts nor plausible metadata can replace the owning source selection."""

    record = Record()
    record[field] = value
    with pytest.raises(capture.OwnedContentResponseRecordError) as caught:
        capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), URL)
    assert "PRIVATE_MARKER" not in str(caught.value), "Refusal cannot echo untrusted fields."


@pytest.mark.parametrize("part", ["request", "response_headers", "response_body"])
@pytest.mark.parametrize("field,value", [("size_bytes", True), ("size_bytes", 1.0),
    ("size_bytes", -1), ("size_bytes", 65537), ("sha256", "A" * 64), ("sha256", "0" * 64),
    ("base64", "AA==\n"), ("base64", "-_=="), ("base64", "AB=="), ("extra", "private")])
def test_AllPartEncodingsSizesAndDigestsAreVerified(part, field, value):
    """Every independently retained part must have canonical base64 and actual byte integrity."""

    record = Record()
    record[part][field] = value
    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), URL)


@pytest.mark.parametrize("kind", ["request", "length", "utf8", "wire-size", "wire-hash"])
def test_RehashedTamperedOriginalsStillRequireCompleteWireAndRequestAssociation(kind):
    """Recomputing an attacker-controlled digest cannot bypass semantic original validation."""

    record = Record()

    if kind == "request":
        record["request"] = Part(b"GET /different HTTP/1.1\r\n\r\n")

    elif kind == "length":
        record = Record(b"short", headers=Headers())

    elif kind == "utf8":
        record = Record(b"\xff")

    else:
        record["response"]["size_bytes" if kind == "wire-size" else "sha256"] = (
            True if kind == "wire-size" else "0" * 64)

    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(SerializeContract(record).encode(), URL)


@pytest.mark.parametrize("raw", [b"", b"x" * 131073, b"\xff", b"\xef\xbb\xbf{}", b"{}\n",
    b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1.5}',
    b"[" * 10 + b"0" + b"]" * 10, json.dumps(list(range(129))).encode(), b'"\\ud800"'])
def test_NoncanonicalOrExcessiveJsonIsNeverRenderedAsAnOriginal(raw):
    """Byte bounds, unique keys, finite primitives and tree bounds precede canonical output."""

    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(raw, URL)


@pytest.mark.parametrize("error", ["input", "connection", "timeout", "protocol",
                                  "response-policy", "body-policy", "unknown", []])
def test_RefusalRecordHasOnlyItsSafeClosedCategory(error):
    """Refusals retain no source URL, content, hashes or catalog association."""

    record = {"schema_version": 1, "profile": PROFILE, "outcome": "refused", "error": error}
    raw = SerializeContract(record).encode()

    if isinstance(error, str) and error in capture.ERROR_CODES:
        assert capture.ParseOwnedContentResponseRecord(raw, URL) == record, (
            "Each fixed refusal must preserve only its exact safe four-field record."
        )

    else:
        with pytest.raises(capture.OwnedContentResponseRecordError):
            capture.ParseOwnedContentResponseRecord(raw, URL)


def test_DescriptorHasNoPrivilegesAndNoOldProfileAuthority():
    """Static declaration cannot manufacture a grant or inherit old acquisition permission."""

    descriptor = capture.OWNED_CONTENT_RESPONSE_DESCRIPTOR
    assert descriptor.adapter_id == "native.loopback-content-response" and (
        descriptor.capabilities == ("http.owned-content-response-capture",)
        and descriptor.maximum_impact is ImpactLevel.SAFE and descriptor.required_privileges == ()
    ), "The new provider must declare only its independently permitted SAFE capability."
    altered = copy.deepcopy(Record())
    altered["response_body"]["base64"] = "A" * 87389
    with pytest.raises(capture.OwnedContentResponseRecordError):
        capture.ParseOwnedContentResponseRecord(SerializeContract(altered).encode(), URL)
