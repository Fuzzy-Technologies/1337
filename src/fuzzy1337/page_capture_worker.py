# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal one-connection worker retaining only an exact reviewed non-secret HTML body."""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import sys
import time
from collections.abc import Sequence

from fuzzy1337.adapters.page_capture import (
    ERROR_EXITS,
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    MAX_HEADER_FIELDS,
    MAX_LINE_BYTES,
    CanonicalRecord,
    Destination,
    Integer,
    KnownSyntheticHtmlBody,
    Seconds,
)

_STATUS = re.compile(rb"(HTTP/1\.[01]) ([0-9]{3}) ([\x20-\x7e]*)\r\n\Z")
_FIELD = re.compile(rb"([A-Za-z0-9!#$%&'*+\-.^_`|~]+):([\t\x20-\x7e]*)\r\n\Z")
_LENGTH = re.compile(rb"(?:0|[1-9][0-9]{0,4})\Z")
_TYPE = re.compile(rb"text/html(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*utf-8)?\Z", re.IGNORECASE)


class PageProtocolError(ValueError):
    """Framing cannot prove one complete bounded response."""


class PageResponsePolicyError(ValueError):
    """Status, media or encoding is outside the closed acquisition profile."""


class PageBodyPolicyError(ValueError):
    """Declared or received body differs from the closed reviewed catalog."""


def Remaining(deadline: float) -> float:
    """Return the positive monotonic budget without renewing it after partial progress.

    Args:
        deadline: Shared monotonic end time covering connect/send/headers/body/final EOF.

    Returns:
        Remaining positive seconds for the next socket phase.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError("page capture deadline exceeded")

    return remaining


def ParseHeaders(raw: bytes, expected_size: int, max_body_bytes: int) -> dict[str, object]:
    """Validate CRLF/token framing then retain only measured normalized allowlisted metadata.

    Unknown header values and status reason stay transient and are never returned or hashed.

    Args:
        raw: Complete header section including final CRLFCRLF, at most 16384 bytes.
        expected_size: Exact body size from the closed reviewed catalog.
        max_body_bytes: Selected already-validated integer allocation ceiling.

    Returns:
        Only measured counts and normalized version/status/media/charset/length metadata.

    Raises:
        PageProtocolError: Header grammar or bounded section/count/line rules fail.
        PageResponsePolicyError: Status/media/encoding is unsupported.
        PageBodyPolicyError: Declared body size differs from the reviewed body or limit.
    """

    if type(raw) is not bytes or not raw.endswith(b"\r\n\r\n") or (
        len(raw) > MAX_HEADER_BYTES
    ):
        raise PageProtocolError("invalid bounded header section")

    lines = raw[:-2].split(b"\r\n")

    if len(lines) < 4 or lines[-1] != b"" or any(
        len(line) + 2 > MAX_LINE_BYTES for line in lines[:-1]
    ):
        raise PageProtocolError("invalid bounded header lines")

    status = _STATUS.fullmatch(lines[0] + b"\r\n")

    if status is None:
        raise PageProtocolError("unsupported status grammar")

    headers: dict[bytes, bytes] = {}

    for line in lines[1:-1]:
        field = _FIELD.fullmatch(line + b"\r\n")

        if field is None:
            raise PageProtocolError("unsupported field grammar")

        name = field[1].lower()

        if name in headers or len(headers) >= MAX_HEADER_FIELDS:
            raise PageProtocolError("ambiguous or excessive field count")

        headers[name] = field[2].strip(b" \t")

    if status[2] != b"200" or b"content-encoding" in headers or b"transfer-encoding" in headers:
        raise PageResponsePolicyError("unsupported response policy")

    length = headers.get(b"content-length")
    media = headers.get(b"content-type")

    if length is None or not _LENGTH.fullmatch(length):
        raise PageProtocolError("unsupported body framing")

    if media is None or not _TYPE.fullmatch(media):
        raise PageResponsePolicyError("unsupported media policy")

    size = int(length)

    if size != expected_size or size > max_body_bytes:
        raise PageBodyPolicyError("declared body differs from the reviewed bound")

    return {"http_version": status[1].decode("ascii"), "status": 200,
        "content_type": "text/html", "declared_charset": "utf-8" if b";" in media else None,
        "content_length": size, "header_size_bytes": len(raw), "header_count": len(headers)}


def Probe(url: str, timeout_seconds: float, fixture_id: str,
          max_body_bytes: int) -> dict[str, object]:
    """Perform one exact GET and EOF-bounded closed-body acquisition without DNS or retry.

    Calling this internal worker directly establishes no consent or authorization.

    Args:
        url: Exact anonymous canonical literal-loopback plain-HTTP endpoint.
        timeout_seconds: Whole request seconds in 0.05..5, excluding bool/nonfinite values.
        fixture_id: Explicit closed reviewed fixture identifier, never a file path.
        max_body_bytes: Exact integer body quota in 1..65536; selected body must fit.

    Returns:
        Flat success fields containing only known non-secret admitted body bytes.

    Raises:
        ValueError: Destination, catalog or numeric inputs are outside the accepted profile.
        PageProtocolError: Framing/peer/complete-body/EOF rules fail.
        PageResponsePolicyError: Response status/media/encoding is refused.
        PageBodyPolicyError: Body declaration or exact hash differs.
        TimeoutError: The single request budget expires.
        OSError: The one literal socket connection fails.
    """

    target, address, port, path, authority = Destination(url)
    timeout = Seconds(timeout_seconds, 5)
    expected = KnownSyntheticHtmlBody(fixture_id)
    Integer(max_body_bytes, 1, MAX_BODY_BYTES)

    if expected.size_bytes > max_body_bytes:
        raise ValueError("reviewed body does not fit the selected limit")

    deadline = time.monotonic() + timeout
    family = socket.AF_INET6 if address == "::1" else socket.AF_INET
    request = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
               "Accept: text/html\r\nAccept-Encoding: identity\r\n\r\n").encode("ascii")

    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))

        if connection.getpeername()[0] != address:
            raise PageProtocolError("peer differs from the exact approved literal")

        connection.settimeout(Remaining(deadline))
        connection.sendall(request)
        buffer = bytearray()
        boundary = -1

        while boundary < 0:
            if len(buffer) >= MAX_HEADER_BYTES:
                raise PageProtocolError("response headers exceed the byte budget")

            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, MAX_HEADER_BYTES - len(buffer)))

            if not chunk:
                raise PageProtocolError("response headers are incomplete")

            buffer.extend(chunk)
            boundary = buffer.find(b"\r\n\r\n")

        metadata = ParseHeaders(bytes(buffer[:boundary + 4]), expected.size_bytes, max_body_bytes)

        if len(buffer) - boundary - 4 > expected.size_bytes:
            raise PageProtocolError("response contains excess body bytes")

        body = bytearray(buffer[boundary + 4:])

        while len(body) < expected.size_bytes:
            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, expected.size_bytes - len(body)))

            if not chunk:
                raise PageProtocolError("response body is incomplete")

            body.extend(chunk)

        connection.settimeout(Remaining(deadline))

        if connection.recv(1):
            raise PageProtocolError("response contains bytes beyond its declared body")

    observed = bytes(body)

    if hashlib.sha256(observed).hexdigest() != expected.sha256:
        raise PageBodyPolicyError("response body differs from the reviewed catalog")

    try:
        observed.decode("utf-8", errors="strict")

        if observed.startswith(b"\xef\xbb\xbf"):
            raise UnicodeError("unsupported body prefix")

    except UnicodeError:
        raise PageBodyPolicyError("response body violates the closed UTF-8 profile") from None

    return {"schema_version": 1, "fixture_id": expected.fixture_id, "url": target.value,
        "address": address, "port": port, "scheme": "http", **metadata,
        "body_sha256": expected.sha256,
        "body_base64": base64.b64encode(observed).decode("ascii")}


def WorkerInputs(arguments: Sequence[str]) -> tuple[str, float, str, int]:
    """Bound canonical argv tokens before any numeric conversion or network operation.

    Args:
        arguments: Exact tuple/list of four text URL/timeout/fixture/body-limit tokens.

    Returns:
        Independently validated canonical destination, timeout, fixture selection and quota.
    """

    if type(arguments) not in (tuple, list) or len(arguments) != 4 or (
        any(type(argument) is not str for argument in arguments)
    ):
        raise ValueError("page capture worker requires four text arguments")

    url, timeout_text, fixture_id, maximum_text = arguments

    if len(timeout_text) > 24 or not re.fullmatch(r"[0-9]+\.[0-9]+", timeout_text) or (
        len(maximum_text) > 5 or not re.fullmatch(r"[1-9][0-9]*", maximum_text)
    ):
        raise ValueError("page capture worker requires bounded canonical numeric tokens")

    timeout = Seconds(float(timeout_text), 5)
    maximum = Integer(int(maximum_text), 1, MAX_BODY_BYTES)
    Destination(url)
    expected = KnownSyntheticHtmlBody(fixture_id)

    if timeout_text != str(timeout) or maximum_text != str(maximum) or (
        expected.size_bytes > maximum
    ):
        raise ValueError("page capture worker input binding differs")

    return url, timeout, fixture_id, maximum


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit only one canonical known-body or fixed failure record with truthful exit status.

    No raw header, reason, unexpected body, exception text or stderr is emitted.

    Args:
        argv: Exact tuple/list of prepared tokens, or process arguments when omitted.

    Returns:
        Zero for admitted page, 64 for input, 124 for timeout, one for other fixed failures.
    """

    error_code = "input"

    try:
        if argv is None:
            if len(sys.argv) != 5:
                raise ValueError("page capture worker requires exactly four process arguments")

            arguments: Sequence[str] = (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

        else:
            arguments = argv

        result = Probe(*WorkerInputs(arguments))

    except (TimeoutError, socket.timeout):
        error_code = "timeout"

    except PageProtocolError:
        error_code = "protocol"

    except PageResponsePolicyError:
        error_code = "response-policy"

    except PageBodyPolicyError:
        error_code = "body-policy"

    except OSError:
        error_code = "connection"

    except (ValueError, TypeError, UnicodeError, OverflowError):
        pass

    else:
        sys.stdout.buffer.write(CanonicalRecord(result))

        return 0

    sys.stdout.buffer.write(CanonicalRecord({"schema_version": 1, "error": error_code}))

    return ERROR_EXITS[error_code]


if __name__ == "__main__":
    raise SystemExit(Main())
