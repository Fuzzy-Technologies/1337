# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal first-party literal-IP worker emitting only non-sensitive discovery records."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from collections.abc import Sequence
from urllib.parse import urlsplit

from fuzzy1337.adapters.native_http import Endpoint, RequestTimeout

MAX_HTTP_HEADER_BYTES = 16 * 1024
_STATUS = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2})(?: [^\r\n]*)?\r\n")


class HttpProtocolError(ValueError):
    """The response cannot prove a complete bounded HTTP/1 status observation."""


def Remaining(deadline: float) -> float:
    """Compute a strictly positive monotonic budget for the next socket operation.

    Args:
        deadline: Shared connection, TLS, send and response deadline.

    Returns:
        Remaining seconds; slow intermediate progress never renews the deadline.

    Raises:
        TimeoutError: The complete probe budget is exhausted.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError("native request deadline exceeded")

    return remaining


def Probe(url: str, timeout_seconds: float) -> dict[str, object]:
    """Observe one approved literal endpoint without DNS, redirects or body retention.

    This internal worker receives already governed inputs; calling it directly
    does not establish consent. HTTPS certificate verification remains enabled.
    Response bytes are transient bounded header-parser input, never stdout data.

    Args:
        url: Explicit literal-IP HTTP(S) endpoint validated again inside the worker.
        timeout_seconds: Shared finite deadline for all socket phases.

    Returns:
        Strict schema-v1 URL/peer/port/scheme/integer-status record only.

    Raises:
        ValueError: Caller inputs violate the finite endpoint contract.
        HttpProtocolError: Header completeness, size or HTTP status is invalid.
        TimeoutError: A network phase exceeds the complete request deadline.
        OSError: Connection, TLS verification or socket operations fail.
    """

    target, address, port, scheme = Endpoint(url)
    timeout = RequestTimeout(timeout_seconds)
    deadline = time.monotonic() + timeout
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)

    try:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))

        if scheme == "https":
            connection.settimeout(Remaining(deadline))
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = context.wrap_socket(
                connection, server_hostname=address,
            )

        peer = str(ipaddress.ip_address(connection.getpeername()[0]))

        if peer != address:
            raise HttpProtocolError("socket peer differs from the literal approved destination")

        parsed = urlsplit(target.value)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        request = f"GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n"
        connection.settimeout(Remaining(deadline))
        connection.sendall(request.encode("ascii"))
        headers = bytearray()

        while b"\r\n\r\n" not in headers:
            if len(headers) >= MAX_HTTP_HEADER_BYTES:
                raise HttpProtocolError("HTTP headers exceed the byte budget")

            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(1024, MAX_HTTP_HEADER_BYTES - len(headers)))

            if not chunk:
                raise HttpProtocolError("HTTP response headers are incomplete")

            headers.extend(chunk)

        status = _STATUS.match(headers)

        if status is None:
            raise HttpProtocolError("HTTP response status is unsupported")

        return {
            "schema_version": 1, "url": target.value, "address": peer, "port": port,
            "scheme": scheme, "status": int(status[1]),
        }

    finally:
        connection.close()


def Main(argv: Sequence[str] | None = None) -> int:
    """Write one bounded safe record and truthful exit status, never exception text.

    Args:
        argv: Exact URL and timeout tokens, or process arguments when omitted.

    Returns:
        Zero for observation, 124 for timeout, 64 for invalid inputs, one for
        connection, TLS or protocol failure. No response headers/bodies are printed.
    """

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    error_code = "input"
    exit_code = 64

    try:
        if len(arguments) != 2:
            raise ValueError("the native worker requires exactly two arguments")

        result = Probe(arguments[0], float(arguments[1]))

    except (TimeoutError, socket.timeout):
        error_code, exit_code = "timeout", 124

    except ssl.SSLError:
        error_code, exit_code = "tls", 1

    except HttpProtocolError:
        error_code, exit_code = "protocol", 1

    except OSError:
        error_code, exit_code = "connection", 1

    except (ValueError, UnicodeError):
        pass

    else:
        sys.stdout.write(json.dumps(result, sort_keys=True, allow_nan=False) + "\n")

        return 0

    sys.stdout.write(json.dumps({"schema_version": 1, "error": error_code}, sort_keys=True) + "\n")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(Main())
