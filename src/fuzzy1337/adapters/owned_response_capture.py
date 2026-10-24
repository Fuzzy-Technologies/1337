# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure admission of the versioned closed original-response wire; no execution authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from types import MappingProxyType
from typing import cast

from fuzzy1337.adapters import SerializeContract

OWNED_RESPONSE_PROFILE = "owned-response-capture.v1"
OWNED_RESPONSE_CATALOG_SHA256 = "fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7"
MAX_RECORD_BYTES = 8192
MAX_REQUEST_BYTES = 1024
MAX_HEADER_BYTES = 16384
MAX_BODY_BYTES = 65536
ERROR_CODES = frozenset({"input", "connection", "timeout", "protocol", "response-policy",
                         "body-policy"})
_URL = re.compile(r"http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{3,4})/zap-passive/"
                  r"(missing|fixed|body-decoy)", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_BODY = (b'<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8">'
    b'<title>Owned passive header fixture</title></head>\n<body><p>Reviewed non-secret '
    b'response.</p></body>\n</html>\n')
_DECOY_BODY = (b'<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8">'
    b'<title>Owned passive header fixture</title></head>\n<body><p>Reviewed non-secret '
    b'response.</p><pre>X-Content-Type-Options: nosniff</pre></body>\n</html>\n')
_HEADERS = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: 170\r\nConnection: close\r\n\r\n")
_REVIEWED = MappingProxyType({
    "missing": (_HEADERS, _BODY),
    "fixed": (_HEADERS[:-2] + b"X-Content-Type-Options: nosniff\r\n\r\n", _BODY),
    "body-decoy": (_HEADERS.replace(b"Length: 170", b"Length: 212"), _DECOY_BODY),
})
_COMMON_FIELDS = {"schema_version", "profile", "outcome"}
_SUCCESS_FIELDS = _COMMON_FIELDS | {"catalog_sha256", "case_id", "url", "address", "port",
                                    "request", "response_headers", "response_body", "response"}


class OwnedResponseRecordError(ValueError):
    """Untrusted output cannot establish the closed original-response association."""


def Destination(url: object) -> tuple[str, int, str, str, str]:
    """Validate only exact selected literal loopback URLs without normalization or resolution.

    Args:
        url: Original canonical URL, including an explicit owned port and one catalog path.

    Returns:
        Literal address, port, path, exact authority and selected case identifier.

    Raises:
        ValueError: Any original spelling, port or path is outside the closed profile.
    """

    if type(url) is not str or len(url) > 128:
        raise ValueError("owned response requires a canonical selected URL")

    match = _URL.fullmatch(url)

    if match is None or not 1024 <= int(match[2]) <= 65535:
        raise ValueError("owned response requires a canonical selected URL")

    address = "::1" if match[1] == "[::1]" else "127.0.0.1"

    return address, int(match[2]), "/zap-passive/" + match[3], match[1] + ":" + match[2], match[3]


def RequestBytes(url: str) -> bytes:
    """Build the sole exact version-one request without HTTP-client or environment additions.

    Args:
        url: Original accepted literal URL.

    Returns:
        Complete ASCII request, including its final blank line and no body.
    """

    _, _, path, authority, _ = Destination(url)

    return (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
        "Accept: text/html\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-response/1\r\n\r\n").encode("ascii")


def ReviewedResponse(case_id: str) -> tuple[bytes, bytes]:
    """Return only the frozen original header/body bytes, never passive-rule expectations.

    Args:
        case_id: One of the three exact version-one case identifiers.

    Returns:
        Immutable original header section and body for acquisition admission.
    """

    if case_id not in _REVIEWED:
        raise ValueError("owned response case is outside the closed catalog")

    return _REVIEWED[case_id]


def BytePart(raw: bytes) -> dict[str, object]:
    """Describe already admitted original bytes for a closed worker record.

    Args:
        raw: Complete admitted request, headers or body, never rejected response fragments.

    Returns:
        Canonical standard-base64, actual byte length and lowercase SHA256.
    """

    return {"base64": base64.b64encode(raw).decode("ascii"), "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object members at every decoded JSON level.

    Args:
        pairs: Original JSON decoder object members, before dictionary conversion.

    Returns:
        The original unique members without last-key-wins interpretation.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise OwnedResponseRecordError("owned response record is unadmitted")

        result[key] = value

    return result


def BoundJson(value: object) -> None:
    """Bound the parsed finite JSON tree before canonical serialization or byte admission.

    Args:
        value: Already byte-bounded strict JSON value, with no duplicate members.
    """

    pending = [(value, 1)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 128 or depth > 4:
            raise OwnedResponseRecordError("owned response record is unadmitted")

        if isinstance(item, dict):
            for key, child in item.items():
                key.encode("utf-8", errors="strict")
                pending.append((child, depth + 1))

        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)

        elif isinstance(item, str):
            item.encode("utf-8", errors="strict")


def Fields(value: object, expected: set[str]) -> dict[str, object]:
    """Require one exact finite object shape before typed field access.

    Args:
        value: Decoded original object.
        expected: Complete closed member set for this profile branch.

    Returns:
        Original object only when its fields match exactly.
    """

    if type(value) is not dict or value.keys() != expected:
        raise OwnedResponseRecordError("owned response record is unadmitted")

    return cast(dict[str, object], value)


def VerifyPart(value: object, expected: bytes, maximum: int) -> bytes:
    """Independently verify canonical base64, length, digest and exact admitted originals.

    Args:
        value: Untrusted worker byte-part object.
        expected: Independent versioned original bytes for this selected association.
        maximum: Inclusive byte ceiling before base64 decoding.

    Returns:
        Exact original decoded bytes, without accepting alternate encodings or padding bits.
    """

    part = Fields(value, {"base64", "size_bytes", "sha256"})
    encoded, size, digest = part["base64"], part["size_bytes"], part["sha256"]

    if type(encoded) is not str or len(encoded) > 4 * ((maximum + 2) // 3) or (
        type(size) is not int or not 1 <= size <= maximum or type(digest) is not str
        or _SHA256.fullmatch(digest) is None
    ):
        raise OwnedResponseRecordError("owned response record is unadmitted")

    raw = base64.b64decode(encoded, validate=True)

    if base64.b64encode(raw).decode("ascii") != encoded or raw != expected or (
        len(raw) != size or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise OwnedResponseRecordError("owned response record is unadmitted")

    return raw


def ParseOwnedResponseCapture(raw: bytes, expected_url: str) -> dict[str, object]:
    """Admit one original closed worker record against its independently selected URL.

    Args:
        raw: Exact original stdout, at most 8192 bytes, without BOM/newline/whitespace.
        expected_url: Owning request's canonical literal URL, never an output-selected target.

    Returns:
        Detached original captured or closed-refusal object; neither grants execution authority.

    Raises:
        OwnedResponseRecordError: Canonical, typed, byte or association verification fails.
    """

    try:
        address, port, _, _, case_id = Destination(expected_url)

        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RECORD_BYTES:
            raise OwnedResponseRecordError("owned response record is unadmitted")

        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=UniqueObject)
        BoundJson(value)

        if SerializeContract(value).encode("utf-8") != raw or type(value) is not dict or (
            type(value.get("schema_version")) is not int or value.get("schema_version") != 1
            or value.get("profile") != OWNED_RESPONSE_PROFILE
        ):
            raise OwnedResponseRecordError("owned response record is unadmitted")

        if value.get("outcome") == "refused":
            record = Fields(value, _COMMON_FIELDS | {"error"})

            if type(record["error"]) is not str or record["error"] not in ERROR_CODES:
                raise OwnedResponseRecordError("owned response record is unadmitted")

            return record

        record = Fields(value, _SUCCESS_FIELDS)

        if record["outcome"] != "captured" or record["catalog_sha256"] != (
            OWNED_RESPONSE_CATALOG_SHA256
        ) or record["url"] != expected_url or record["address"] != address or (
            type(record["port"]) is not int or record["port"] != port
            or record["case_id"] != case_id
        ):
            raise OwnedResponseRecordError("owned response record is unadmitted")

        headers, body = ReviewedResponse(case_id)
        VerifyPart(record["request"], RequestBytes(expected_url), MAX_REQUEST_BYTES)
        verified_headers = VerifyPart(record["response_headers"], headers, MAX_HEADER_BYTES)
        verified_body = VerifyPart(record["response_body"], body, MAX_BODY_BYTES)
        response = Fields(record["response"], {"size_bytes", "sha256"})
        joined = verified_headers + verified_body

        if type(response["size_bytes"]) is not int or response["size_bytes"] != len(joined) or (
            type(response["sha256"]) is not str
            or response["sha256"] != hashlib.sha256(joined).hexdigest()
        ):
            raise OwnedResponseRecordError("owned response record is unadmitted")

        return record

    except (ValueError, TypeError, UnicodeError, RecursionError, binascii.Error):
        raise OwnedResponseRecordError("owned response record is unadmitted") from None
