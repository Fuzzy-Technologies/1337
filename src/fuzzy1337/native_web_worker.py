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
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_FILE_CANARY_PROFILE,
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_CHECK_ID,
    NATIVE_WEB_ERROR_EXITS,
    NATIVE_WEB_VERSION,
    CanonicalRecord,
    NativeFileCanaryTemplate,
    NativeWebCheckFor,
    NativeWebEndpoint,
)
from fuzzy1337.native_http_worker import Remaining

MAX_HEADER_BYTES = 16384
MAX_HEADER_FIELDS = 64
MAX_LINE_BYTES = 4096
MAX_PROMETHEUS_WIRE_BYTES = 512 * 1024
MAX_PROMETHEUS_CHUNKS = 4096
MAX_CHUNK_LINE_BYTES = 32
_STATUS = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2}) [\x20-\x7e]*")
_FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(rb"(?:0|[1-9][0-9]{0,3})")


class NativeWebProtocolError(ValueError):
    """Response framing cannot establish a complete bounded native observation."""


class NativeWebResponseError(ValueError):
    """Response status or encoding is explicitly unassessed rather than clean."""


def Headers(
    raw: bytes, *, check_id: str = NATIVE_WEB_CHECK_ID,
) -> tuple[int, str, int | str]:
    """Parse bounded strict response framing and discard all unneeded header values.

    Args:
        raw: Complete header section including its final CRLFCRLF.
        check_id: Explicit predicate; only metrics admits bounded streaming framing.

    Returns:
        Actual status, fixed media category and bounded length or explicit streaming mode.

    Raises:
        NativeWebProtocolError: Header syntax, duplication, count or length is unsupported.
        NativeWebResponseError: HTTP5xx, encoded or old-profile streaming remains unassessed.
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

    streaming = check_id == NATIVE_PROMETHEUS_CHECK_ID

    if status >= 500 or b"content-encoding" in values or (
        not streaming and b"transfer-encoding" in values
    ):
        raise NativeWebResponseError

    length_text = values.get(b"content-length", b"")

    if streaming and b"transfer-encoding" in values:
        if b"content-length" in values or values[b"transfer-encoding"].lower() != b"chunked":
            raise NativeWebProtocolError

        size: int | str = "chunked"

    elif streaming and b"content-length" not in values:
        size = "eof"

    else:
        length_pattern = rb"(?:0|[1-9][0-9]{0,5})" if streaming else _LENGTH

        if re.fullmatch(length_pattern, length_text) is None:
            raise NativeWebProtocolError

        size = int(length_text)

        if size > NativeWebCheckFor(check_id).max_body_bytes:
            raise NativeWebProtocolError

    media = values.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
    category = media.decode("ascii") if media in {b"text/plain", b"application/octet-stream"} \
        else "other"

    return status, category, size


class PrometheusBodyReader:
    """Own one finite metrics wire buffer and shared deadline, including terminal EOF."""

    def __init__(
        self, connection: socket.socket, deadline: float, initial: bytes, header_bytes: int,
    ) -> None:
        """Bind already received bytes without resetting the original request budget.

        Args:
            connection: Existing exact-peer socket; Probe retains cleanup ownership.
            deadline: Original shared monotonic request deadline, never renewed here.
            initial: Prefetched response bytes following the validated bounded headers.
            header_bytes: Already consumed header bytes charged to the wire budget.
        """

        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray(initial)
        self.wire_bytes = header_bytes + len(initial)

    def Receive(self, maximum: int) -> bytes:
        """Check the original deadline before and after every actual bounded receive.

        Args:
            maximum: Maximum remaining fragment bytes; each actual read is at most 1024.

        Returns:
            Actual bounded bytes, including empty bytes only for observed connection EOF.

        Raises:
            TimeoutError: The original deadline expired before or after receive.
            NativeWebProtocolError: The independent total wire-byte budget was exhausted.
        """

        self.connection.settimeout(Remaining(self.deadline))
        part = self.connection.recv(min(maximum, 1024))
        Remaining(self.deadline)
        self.wire_bytes += len(part)

        if self.wire_bytes > MAX_PROMETHEUS_WIRE_BYTES:
            raise NativeWebProtocolError

        return part

    def Take(self, size: int) -> bytes:
        """Read exactly one independently bounded wire fragment or refuse truncation.

        Args:
            size: Exact admitted fragment length, bounded by its framing/body owner.

        Returns:
            Exactly the selected number of bytes from prefetched and actual receives.

        Raises:
            NativeWebProtocolError: Connection EOF truncates the required fragment.
            TimeoutError: The original request deadline expires.
        """

        Remaining(self.deadline)

        while len(self.buffer) < size:
            part = self.Receive(size - len(self.buffer))

            if not part:
                raise NativeWebProtocolError

            self.buffer.extend(part)

        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        Remaining(self.deadline)

        return result

    def Line(self) -> bytes:
        """Read a finite CRLF chunk-size line with no extension or trailer expansion.

        Returns:
            Complete bounded size-line bytes without CRLF, for lexical validation.

        Raises:
            NativeWebProtocolError: The size line exceeds its independent byte limit.
            TimeoutError: The original request deadline expires.
        """

        line = bytearray()

        while len(line) < MAX_CHUNK_LINE_BYTES:
            line.extend(self.Take(1))

            if line.endswith(b"\r\n"):
                return bytes(line[:-2])

        raise NativeWebProtocolError

    def Body(self, framing: int | str) -> bytes:
        """Decode only the admitted identity framing within body/chunk/wire/time budgets.

        Args:
            framing: Validated bounded integer length or the exact chunked/eof mode.

        Returns:
            Complete transient decoded body after actual final connection EOF.

        Raises:
            NativeWebProtocolError: Framing, completeness or any independent bound fails.
            TimeoutError: The original request deadline expires, including at final EOF.
        """

        maximum = NativeWebCheckFor(NATIVE_PROMETHEUS_CHECK_ID).max_body_bytes
        body = bytearray()

        if type(framing) is int:
            if len(self.buffer) > framing:
                raise NativeWebProtocolError

            body.extend(self.Take(framing))

        elif framing == "chunked":
            for _ in range(MAX_PROMETHEUS_CHUNKS + 1):
                line = self.Line()

                if re.fullmatch(rb"[0-9A-Fa-f]{1,8}", line) is None:
                    raise NativeWebProtocolError

                size = int(line, 16)

                if not size:
                    if self.Take(2) != b"\r\n":
                        raise NativeWebProtocolError

                    break

                if _ == MAX_PROMETHEUS_CHUNKS or len(body) + size > maximum:
                    raise NativeWebProtocolError

                body.extend(self.Take(size))

                if self.Take(2) != b"\r\n":
                    raise NativeWebProtocolError

            else:
                raise NativeWebProtocolError

        elif framing == "eof":
            body.extend(self.buffer)
            self.buffer.clear()

            while len(body) <= maximum:
                part = self.Receive(min(1024, maximum + 1 - len(body)))

                if not part:
                    return bytes(body)

                body.extend(part)

            raise NativeWebProtocolError

        else:
            raise NativeWebProtocolError

        if self.buffer or self.Receive(1):
            raise NativeWebProtocolError

        Remaining(self.deadline)

        return bytes(body)


def Probe(
    url: str, timeout_seconds: float, *, check_id: str = NATIVE_WEB_CHECK_ID,
    workspace_id: str | None = None,
) -> dict[str, object]:
    """Issue one exact governed-input GET and retain only the complete predicate metadata.

    Args:
        url: Exact Git URL or closed owned-loopback canary-pack URL.
        timeout_seconds: One monotonic budget across connect, TLS, send, body and final EOF.
        check_id: Exact registered native predicate; Git remains the compatible default.
        workspace_id: Owning structural-request partition for the canary profile only.

    Returns:
        Fixed schema-one metadata with body digest and match result, never body or header text.

    Raises:
        ValueError: Inputs or response framing/status violate the fixed profile.
        OSError: Connection, TLS or complete-request deadline fails.
    """

    check = NativeWebCheckFor(check_id)
    target, address, port, scheme = NativeWebEndpoint(url, check_id=check_id)
    template = None

    if check_id == NATIVE_FILE_CANARY_CHECK_ID:
        if type(workspace_id) is not str:
            raise ValueError("owned canary worker requires its workspace")

        template = NativeFileCanaryTemplate(workspace_id, url)

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
        request_target = parsed.path + ("?" + parsed.query if template is not None else "")
        request = (f"GET {request_target} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
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

            if check_id == NATIVE_PROMETHEUS_CHECK_ID:
                Remaining(deadline)

            if not part:
                raise NativeWebProtocolError

            incoming.extend(part)

        boundary = incoming.index(b"\r\n\r\n") + 4
        status, media_type, length = Headers(bytes(incoming[:boundary]), check_id=check_id)
        body = incoming[boundary:]

        if check_id == NATIVE_PROMETHEUS_CHECK_ID:
            Remaining(deadline)
            reader = PrometheusBodyReader(connection, deadline, bytes(body), boundary)
            raw_body = reader.Body(length)
            Remaining(deadline)

        else:
            if type(length) is not int or len(body) > length:
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

        matched = check.predicate(status, media_type, raw_body)

        if check_id == NATIVE_PROMETHEUS_CHECK_ID:
            Remaining(deadline)

        record: dict[str, object] = {
            "schema_version": 1, "check_id": check.check_id,
            "profile_version": NATIVE_WEB_VERSION, "url": target.value, "address": peer,
            "port": port, "scheme": scheme, "status": status, "media_type": media_type,
            "body_bytes": len(raw_body), "body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "matched": matched,
        }

        if template is not None:
            record.update({"request_profile": NATIVE_FILE_CANARY_PROFILE,
                "request_reference": template.Reference(),
                "injection_reference": template.injection_points[0].Reference(
                    template.Reference())})

        if check_id == NATIVE_PROMETHEUS_CHECK_ID:
            Remaining(deadline)

        return record

    finally:
        connection.close()


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit canonical safe metadata and truthful fixed-code failures without exception text.

    Args:
        argv: Exact URL/deadline, plus explicit canary check/workspace only for that profile.

    Returns:
        Zero for assessed response, 64 for input, 124 for timeout and one for other failures.
    """

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    error = "input"

    try:
        if len(arguments) == 2:
            record = Probe(arguments[0], float(arguments[1]))

        elif len(arguments) == 3 and arguments[2] == NATIVE_PROMETHEUS_CHECK_ID:
            record = Probe(arguments[0], float(arguments[1]), check_id=arguments[2])

        elif len(arguments) == 4 and arguments[2] == NATIVE_FILE_CANARY_CHECK_ID:
            record = Probe(arguments[0], float(arguments[1]), check_id=arguments[2],
                           workspace_id=arguments[3])

        else:
            raise ValueError

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
