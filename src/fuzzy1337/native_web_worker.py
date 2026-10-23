# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded literal-IP response check retaining no HTTP bodies or header values."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
import sys
import time
from collections.abc import Sequence
from urllib.parse import urlsplit

from fuzzy1337.adapters.native_http import RequestTimeout
from fuzzy1337.adapters.native_web import (
    MAX_NATIVE_WEB_BODY_BYTES,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_ERROR_EXITS,
    NATIVE_WEB_VERSION,
    CanonicalRecord,
    MatchesGitHead,
    NativeWebEndpoint,
)
from fuzzy1337.native_http_worker import Remaining

MAX_HEADER_BYTES = 16384
MAX_HEADER_FIELDS = 64
MAX_LINE_BYTES = 4096
_STATUS = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2}) [\x20-\x7e]*")
_FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(rb"(?:0|[1-9][0-9]{0,3})")


class NativeWebProtocolError(ValueError):
    """Response framing cannot establish a complete bounded native observation."""


class NativeWebResponseError(ValueError):
    """Response status or encoding is explicitly unassessed rather than clean."""


def Headers(raw: bytes) -> tuple[int, str, int]:
    """Parse bounded strict response framing and discard all unneeded header values.

    Args:
        raw: Complete header section including its final CRLFCRLF.

    Returns:
        Actual status, fixed normalized media category and bounded content length.

    Raises:
        NativeWebProtocolError: Header syntax, duplication, count or length is unsupported.
        NativeWebResponseError: HTTP5xx or encoded/chunked responses remain unassessed.
    """

    lines = raw[:-4].split(b"\r\n")

    if not raw.endswith(b"\r\n\r\n") or len(raw) > MAX_HEADER_BYTES or (
        not 1 <= len(lines) <= MAX_HEADER_FIELDS + 1
        or any(len(line) + 2 > MAX_LINE_BYTES for line in lines)
    ):
        raise NativeWebProtocolError

    status_match = _STATUS.fullmatch(lines[0])

    if status_match is None:
        raise NativeWebProtocolError

    status = int(status_match[1])
    values: dict[bytes, bytes] = {}

    for line in lines[1:]:
        name, separator, value = line.partition(b":")

        if not separator or _FIELD.fullmatch(name) is None or any(
            byte != 9 and not 32 <= byte <= 126 for byte in value
        ) or name.lower() in values:
            raise NativeWebProtocolError

        values[name.lower()] = value.strip(b" \t")

    if status >= 500 or b"content-encoding" in values or b"transfer-encoding" in values:
        raise NativeWebResponseError

    length_text = values.get(b"content-length", b"")

    if _LENGTH.fullmatch(length_text) is None:
        raise NativeWebProtocolError

    size = int(length_text)

    if size > MAX_NATIVE_WEB_BODY_BYTES:
        raise NativeWebProtocolError

    media = values.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
    category = media.decode("ascii") if media in {b"text/plain", b"application/octet-stream"} \
        else "other"

    return status, category, size


def Probe(url: str, timeout_seconds: float) -> dict[str, object]:
    """Issue one exact governed-input GET and retain only the complete predicate metadata.

    Args:
        url: Explicit query-free unicast literal-IP HTTP(S) URL validated inside the worker.
        timeout_seconds: One monotonic budget across connect, TLS, send, body and final EOF.

    Returns:
        Fixed schema-one metadata with body digest and match result, never body or header text.

    Raises:
        ValueError: Inputs or response framing/status violate the fixed profile.
        OSError: Connection, TLS or complete-request deadline fails.
    """

    target, address, port, scheme = NativeWebEndpoint(url)
    deadline = time.monotonic() + RequestTimeout(timeout_seconds)
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)

    try:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))

        if scheme == "https":
            connection.settimeout(Remaining(deadline))
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = context.wrap_socket(connection, server_hostname=address)

        peer = str(ipaddress.ip_address(connection.getpeername()[0]))

        if peer != address:
            raise NativeWebProtocolError

        parsed = urlsplit(target.value)
        request = (f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
                   "Connection: close\r\nAccept: text/plain, application/octet-stream\r\n"
                   "Accept-Encoding: identity\r\n\r\n")
        connection.settimeout(Remaining(deadline))
        connection.sendall(request.encode("ascii"))
        incoming = bytearray()

        while b"\r\n\r\n" not in incoming:
            if len(incoming) >= MAX_HEADER_BYTES:
                raise NativeWebProtocolError

            connection.settimeout(Remaining(deadline))
            part = connection.recv(min(1024, MAX_HEADER_BYTES - len(incoming)))

            if not part:
                raise NativeWebProtocolError

            incoming.extend(part)

        boundary = incoming.index(b"\r\n\r\n") + 4
        status, media_type, length = Headers(bytes(incoming[:boundary]))
        body = incoming[boundary:]

        if len(body) > length:
            raise NativeWebProtocolError

        while len(body) < length:
            connection.settimeout(Remaining(deadline))
            part = connection.recv(min(1024, length - len(body)))

            if not part:
                raise NativeWebProtocolError

            body.extend(part)

        connection.settimeout(Remaining(deadline))

        if connection.recv(1):
            raise NativeWebProtocolError

        raw_body = bytes(body)

        return {
            "schema_version": 1, "check_id": NATIVE_WEB_CHECK_ID,
            "profile_version": NATIVE_WEB_VERSION, "url": target.value, "address": peer,
            "port": port, "scheme": scheme, "status": status, "media_type": media_type,
            "body_bytes": len(raw_body), "body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "matched": MatchesGitHead(status, media_type, raw_body),
        }

    finally:
        connection.close()


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit canonical safe metadata and truthful fixed-code failures without exception text.

    Args:
        argv: Exact URL and request deadline, or process arguments when omitted.

    Returns:
        Zero for assessed response, 64 for input, 124 for timeout and one for other failures.
    """

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    error = "input"

    try:
        if len(arguments) != 2:
            raise ValueError

        record = Probe(arguments[0], float(arguments[1]))

    except TimeoutError:
        error = "timeout"

    except ssl.SSLError:
        error = "tls"

    except NativeWebResponseError:
        error = "response-policy"

    except NativeWebProtocolError:
        error = "protocol"

    except OSError:
        error = "connection"

    except (ValueError, UnicodeError, OverflowError):
        pass

    else:
        sys.stdout.buffer.write(CanonicalRecord(record))

        return 0

    sys.stdout.buffer.write(CanonicalRecord({"schema_version": 1, "error": error}))

    return NATIVE_WEB_ERROR_EXITS[error]


if __name__ == "__main__":
    raise SystemExit(Main())
