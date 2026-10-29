# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure bounded original-content response admission; no contact, catalog or authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import cast

from fuzzy1337.adapters import AdapterDescriptor, ImpactLevel, SerializeContract
from fuzzy1337.requests import Endpoint
from fuzzy1337.scope import Target, TargetKind

PROVIDER_ID = "native.loopback-content-response"
CAPABILITY_ID = "http.owned-content-response-capture"
OWNED_CONTENT_RESPONSE_PROFILE = "owned-content-response-capture.v1"
OWNED_CONTENT_RESPONSE_DESCRIPTOR = AdapterDescriptor(PROVIDER_ID,
    "Owned content-response capture", "1", (CAPABILITY_ID,), ImpactLevel.SAFE)
MAX_RECORD_BYTES = 131072
MAX_REQUEST_BYTES = 2048
MAX_HEADER_BYTES = 16384
MAX_BODY_BYTES = 65536
MAX_WIRE_BYTES = 81920
MAX_HEADER_FIELDS = 64
MAX_LINE_BYTES = 4096
ERROR_CODES = frozenset({"input", "connection", "timeout", "protocol", "response-policy",
                         "body-policy"})
_URL = re.compile(r"http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{3,4})(/[A-Za-z0-9._~/-]*)",
                  re.ASCII)
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(rb"0|[1-9][0-9]*")
_MEDIA = re.compile(rb"(text/html|text/plain)(?:[ \t]*;[ \t]*charset=utf-8)?", re.IGNORECASE)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_FORBIDDEN = frozenset({b"transfer-encoding", b"content-encoding", b"trailer", b"te",
    b"upgrade", b"location", b"set-cookie", b"set-cookie2", b"cookie", b"authorization",
    b"proxy-authorization", b"www-authenticate", b"proxy-authenticate"})
_COMMON = {"schema_version", "profile", "outcome"}
_SUCCESS = _COMMON | {"url", "address", "port", "media_type", "request", "response_headers",
                      "response_body", "response"}


class OwnedContentResponseRecordError(ValueError):
    """Untrusted output cannot establish original content-response custody."""


class ContentResponsePolicyError(ValueError):
    """Carry only a fixed safe transient response refusal category."""

    def __init__(self, error: str) -> None:
        """Bind an internal fixed category without rejected values.

        Args:
            error: Fixed protocol, response-policy or body-policy category.
        """

        self.error = error
        super().__init__(error)


def Destination(url: object) -> tuple[str, int, str, str]:
    """Require original canonical anonymous HTTP loopback selection before normalization.

    Args:
        url: Exact selected URL, including explicit owned port and concrete path.

    Returns:
        Literal address, port, original path and exact Host authority.
    """

    if type(url) is not str or not 1 <= len(url) <= 2048 or not url.isascii():
        raise ValueError("content response requires an exact selected loopback URL")

    match = _URL.fullmatch(url)

    if match is None or not 1024 <= int(match[2]) <= 65535:
        raise ValueError("content response requires an exact selected loopback URL")

    path = match[3]
    authority = match[1] + ":" + match[2]

    if len(path) > 1024 or "//" in path or any(part in {".", ".."} for part in path.split("/")):
        raise ValueError("content response requires an exact selected loopback URL")

    if Target(TargetKind.URL, url).value != url:
        raise ValueError("content response requires an exact selected loopback URL")

    Endpoint("content-response", "http://" + authority, path)

    return "::1" if match[1] == "[::1]" else "127.0.0.1", int(match[2]), path, authority


def RequestBytes(url: str) -> bytes:
    """Build the exact one-request template without implicit HTTP-client headers.

    Args:
        url: Original admitted canonical URL.

    Returns:
        Complete ASCII request, with no body, credentials or session values.
    """

    _, _, path, authority = Destination(url)
    raw = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
        "Accept: text/html, text/plain\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-content-response/1\r\n\r\n").encode("ascii")

    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("content response request exceeds its fixed bound")

    return raw


def AdmitHeaders(raw: bytes) -> tuple[int, str]:
    """Recheck complete original framing, unique fields and the narrow response policy.

    Args:
        raw: Complete original header section through its final CRLFCRLF.

    Returns:
        Exact declared body length and normalized admitted media type.
    """

    if len(raw) > MAX_HEADER_BYTES:
        raise ContentResponsePolicyError("response-policy")

    if not raw or raw.find(b"\r\n\r\n") != len(raw) - 4:
        raise ContentResponsePolicyError("protocol")

    lines = raw[:-4].split(b"\r\n")

    if not 2 <= len(lines) <= MAX_HEADER_FIELDS + 1 or lines[0] != b"HTTP/1.1 200 OK" or any(
        len(line) + 2 > MAX_LINE_BYTES for line in lines
    ):
        raise ContentResponsePolicyError("response-policy")

    fields: dict[bytes, bytes] = {}

    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        key = name.lower()

        if key == b"content-length" and key in fields:
            raise ContentResponsePolicyError("protocol")

        if not colon or _TOKEN.fullmatch(name) is None or key in fields or key in _FORBIDDEN or (
            any(byte != 9 and not 32 <= byte <= 126 for byte in value)
        ):
            raise ContentResponsePolicyError("response-policy")

        fields[key] = value.strip(b" \t")

    length = fields.get(b"content-length", b"")
    media = _MEDIA.fullmatch(fields.get(b"content-type", b""))

    if _LENGTH.fullmatch(length) is None:
        raise ContentResponsePolicyError("protocol")

    if len(length) > 5 or len(length) == 5 and length > b"65536":
        raise ContentResponsePolicyError("body-policy")

    if fields.get(b"connection", b"").lower() != b"close" or media is None:
        raise ContentResponsePolicyError("response-policy")

    return int(length), media[1].decode("ascii").lower()


def AdmitBody(raw: bytes, length: int) -> None:
    """Require complete bounded UTF-8 originals without normalizing their bytes.

    Args:
        raw: Original body bytes after complete framing and EOF.
        length: Independently admitted Content-Length.
    """

    if len(raw) != length or len(raw) > MAX_BODY_BYTES:
        raise ContentResponsePolicyError("protocol")

    try:
        raw.decode("utf-8", errors="strict")

    except UnicodeError:
        raise ContentResponsePolicyError("body-policy") from None


def BytePart(raw: bytes) -> dict[str, object]:
    """Describe already admitted original bytes, including an empty body.

    Args:
        raw: Complete admitted request, headers or body.

    Returns:
        Exact canonical base64, byte count and SHA-256.
    """

    return {"base64": base64.b64encode(raw).decode("ascii"), "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys before dictionary conversion.

    Args:
        pairs: Original object members at any JSON depth.

    Returns:
        Original unique members without last-key-wins behavior.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise OwnedContentResponseRecordError("content response record is unadmitted")

        result[key] = value

    return result


def BoundJson(value: object) -> None:
    """Bound strict JSON nodes and depth before canonical rendering.

    Args:
        value: Already byte-bounded decoded JSON with unique object keys.
    """

    pending = [(value, 1)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 128 or depth > 8 or type(item) not in (dict, list, str, int, bool, type(None)):
            raise OwnedContentResponseRecordError("content response record is unadmitted")

        if isinstance(item, dict):
            for key, child in item.items():
                key.encode("utf-8", errors="strict")
                pending.append((child, depth + 1))

        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)

        elif isinstance(item, str):
            item.encode("utf-8", errors="strict")


def Fields(value: object, expected: set[str]) -> dict[str, object]:
    """Require an exact object member set before field access.

    Args:
        value: Untrusted decoded JSON object.
        expected: Entire required and permitted key set.

    Returns:
        Original dictionary with its exact shape established.
    """

    if type(value) is not dict or value.keys() != expected:
        raise OwnedContentResponseRecordError("content response record is unadmitted")

    return cast(dict[str, object], value)


def VerifyPart(value: object, maximum: int, minimum: int = 0) -> bytes:
    """Recompute original lengths, canonical encoding and digest independently.

    Args:
        value: Untrusted byte-part object.
        maximum: Inclusive decoded byte ceiling checked before decoding.
        minimum: Minimum original part length; zero permits an empty body.

    Returns:
        Exact verified original bytes, never reconstructed from a digest.
    """

    part = Fields(value, {"base64", "size_bytes", "sha256"})
    encoded, size, digest = part["base64"], part["size_bytes"], part["sha256"]

    if type(encoded) is not str or len(encoded) > 4 * ((maximum + 2) // 3) or (
        type(size) is not int or not minimum <= size <= maximum or type(digest) is not str
        or _SHA256.fullmatch(digest) is None
    ):
        raise OwnedContentResponseRecordError("content response record is unadmitted")

    raw = base64.b64decode(encoded, validate=True)

    if base64.b64encode(raw).decode("ascii") != encoded or len(raw) != size or (
        hashlib.sha256(raw).hexdigest() != digest
    ):
        raise OwnedContentResponseRecordError("content response record is unadmitted")

    return raw


def ParseOwnedContentResponseRecord(raw: bytes, expected_url: str) -> dict[str, object]:
    """Independently admit original worker output against the selected URL and full wire rules.

    Args:
        raw: Exact original stdout within its 131072-byte ceiling.
        expected_url: Owning immutable request URL, never selected by worker output.

    Returns:
        Detached verified eleven-field success or four-field safe refusal.

    Raises:
        OwnedContentResponseRecordError: Original JSON, bytes or association are unverified.
    """

    try:
        address, port, _, _ = Destination(expected_url)

        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RECORD_BYTES:
            raise ValueError

        value = json.loads(raw.decode("ascii"), object_pairs_hook=UniqueObject)
        BoundJson(value)

        if SerializeContract(value).encode("ascii") != raw or type(value) is not dict or (
            type(value.get("schema_version")) is not int or value.get("schema_version") != 1
            or value.get("profile") != OWNED_CONTENT_RESPONSE_PROFILE
        ):
            raise ValueError

        if value.get("outcome") == "refused":
            record = Fields(value, _COMMON | {"error"})

            if type(record["error"]) is not str or record["error"] not in ERROR_CODES:
                raise ValueError

            return record

        record = Fields(value, _SUCCESS)

        if record["outcome"] != "captured" or record["url"] != expected_url or (
            record["address"] != address or type(record["port"]) is not int
            or record["port"] != port
        ):
            raise ValueError

        request = VerifyPart(record["request"], MAX_REQUEST_BYTES, 1)
        headers = VerifyPart(record["response_headers"], MAX_HEADER_BYTES, 1)
        body = VerifyPart(record["response_body"], MAX_BODY_BYTES)
        length, media = AdmitHeaders(headers)
        AdmitBody(body, length)
        response = Fields(record["response"], {"size_bytes", "sha256"})
        wire = headers + body

        if request != RequestBytes(expected_url) or record["media_type"] != media or (
            len(wire) > MAX_WIRE_BYTES or type(response["size_bytes"]) is not int
            or response["size_bytes"] != len(wire) or type(response["sha256"]) is not str
            or response["sha256"] != hashlib.sha256(wire).hexdigest()
        ):
            raise ValueError

        return record

    except (ValueError, TypeError, UnicodeError, RecursionError, binascii.Error):
        raise OwnedContentResponseRecordError("content response record is unadmitted") from None
