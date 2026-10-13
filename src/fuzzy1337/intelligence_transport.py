# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal isolated HTTPS byte receiver; a parent deadline owns worker termination."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import sys
from typing import BinaryIO
from urllib.parse import urlsplit

REDIRECT_EXIT = 2
HTTP_EXIT = 3
FORMAT_EXIT = 4
SIZE_EXIT = 5
TRANSPORT_EXIT = 6
TIMEOUT_EXIT = 7


def Receive(url: str, max_bytes: int, timeout_seconds: float, output: BinaryIO) -> int:
    """Stream only bounded original response bytes without redirects or decompression.

    Args:
        url: Parent-validated non-secret absolute HTTPS locator.
        max_bytes: Maximum retained response-body bytes.
        timeout_seconds: Socket inactivity ceiling beneath the parent's total deadline.
        output: Parent-owned binary pipe; first line contains controlled framing metadata.

    Returns:
        Explicit terminal status; nonzero status never means a complete source body.
    """

    parsed = urlsplit(url)

    if parsed.scheme != "https" or parsed.hostname is None:
        return FORMAT_EXIT

    connection = http.client.HTTPSConnection(
        parsed.hostname, port=parsed.port, timeout=timeout_seconds,
        context=ssl.create_default_context(),
    )

    try:
        connection.request("GET", parsed.path, headers={
            "Accept": "application/json", "Accept-Encoding": "identity",
            "Connection": "close", "User-Agent": "1337-intelligence-acquisition/1",
        })
        response = connection.getresponse()
        output.write(json.dumps({"status": response.status}).encode("ascii") + b"\n")
        output.flush()

        if 300 <= response.status < 400:
            return REDIRECT_EXIT

        if response.status != 200:
            return HTTP_EXIT

        encoding = response.getheader("Content-Encoding")
        transfer = response.getheader("Transfer-Encoding")
        declared = response.getheader("Content-Length")

        if encoding not in (None, "identity") or transfer not in (None, "chunked"):
            return FORMAT_EXIT

        if declared is not None and (
            len(declared) > 20 or not declared.isascii() or not declared.isdecimal()
        ):
            return FORMAT_EXIT

        length = int(declared) if declared is not None else None

        if transfer is not None and length is not None:
            return FORMAT_EXIT

        if length is not None and length > max_bytes:
            return SIZE_EXIT

        received = 0

        while True:
            chunk = response.read1(min(65536, max_bytes - received + 1))

            if not chunk:
                break

            retained = chunk[:max_bytes - received]
            output.write(retained)
            output.flush()
            received += len(retained)

            if len(retained) != len(chunk):
                return SIZE_EXIT

        if length is not None and received != length:
            return TRANSPORT_EXIT

        return 0

    except (TimeoutError, socket.timeout):
        return TIMEOUT_EXIT

    except (OSError, http.client.HTTPException, ValueError):
        return TRANSPORT_EXIT

    finally:
        connection.close()


def Main() -> int:
    """Receive the parent-selected artifact using only explicit process arguments.

    Returns:
        Terminal receiver status; no exception details or environment are exported.
    """

    if len(sys.argv) != 4:
        return FORMAT_EXIT

    return Receive(sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(Main())
