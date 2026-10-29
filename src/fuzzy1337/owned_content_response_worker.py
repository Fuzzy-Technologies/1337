# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""One exact anonymous loopback GET, complete content admission and no rejected output."""

from __future__ import annotations

import hashlib
import socket
import sys
import time
from collections.abc import Sequence

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.owned_content_response import (
    MAX_HEADER_BYTES,
    MAX_RECORD_BYTES,
    OWNED_CONTENT_RESPONSE_PROFILE,
    AdmitBody,
    AdmitHeaders,
    BytePart,
    ContentResponsePolicyError,
    Destination,
    RequestBytes,
)


def Remaining(deadline: float) -> float:
    """Consume the original connect/send/read/EOF clock without renewal on progress.

    Args:
        deadline: One absolute five-second monotonic boundary.

    Returns:
        Positive remaining allowance; expiry raises TimeoutError without response values.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError

    return remaining


def Probe(url: str) -> dict[str, object]:
    """Admit one actual complete original response before producing any byte descriptors.

    Args:
        url: Exact canonical anonymous loopback URL, without a path/body catalog.

    Returns:
        Captured record after complete framing, actual timely EOF and UTF-8 admission.
    """

    address, port, _, _ = Destination(url)
    request = RequestBytes(url)
    deadline = time.monotonic() + 5.0
    family = socket.AF_INET6 if address == "::1" else socket.AF_INET

    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))
        Remaining(deadline)
        peer = connection.getpeername()

        if peer[0] != address or peer[1] != port:
            raise ContentResponsePolicyError("protocol")

        connection.settimeout(Remaining(deadline))
        connection.sendall(request)
        Remaining(deadline)
        buffer = bytearray()
        boundary = -1

        while boundary < 0:
            if len(buffer) >= MAX_HEADER_BYTES:
                raise ContentResponsePolicyError("response-policy")

            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, MAX_HEADER_BYTES - len(buffer)))
            Remaining(deadline)

            if not chunk:
                raise ContentResponsePolicyError("protocol")

            buffer.extend(chunk)
            boundary = buffer.find(b"\r\n\r\n")

        headers = bytes(buffer[:boundary + 4])
        length, media = AdmitHeaders(headers)
        body = bytearray(buffer[boundary + 4:])

        if len(body) > length:
            raise ContentResponsePolicyError("protocol")

        while len(body) < length:
            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, length - len(body)))
            Remaining(deadline)

            if not chunk:
                raise ContentResponsePolicyError("protocol")

            body.extend(chunk)

        connection.settimeout(Remaining(deadline))
        extra = connection.recv(1)
        Remaining(deadline)

        if extra:
            raise ContentResponsePolicyError("protocol")

    original_body = bytes(body)
    AdmitBody(original_body, length)
    response = headers + original_body

    return {"schema_version": 1, "profile": OWNED_CONTENT_RESPONSE_PROFILE, "outcome": "captured",
        "url": url, "address": address, "port": port, "media_type": media,
        "request": BytePart(request), "response_headers": BytePart(headers),
        "response_body": BytePart(original_body),
        "response": {"size_bytes": len(response), "sha256": hashlib.sha256(response).hexdigest()}}


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit only an admitted canonical record or safe refusal, without stderr diagnostics.

    Args:
        argv: Exactly one canonical URL; no flags or timeout configuration.

    Returns:
        Zero for captured original bytes, two for a fixed four-field refusal.
    """

    arguments = sys.argv[1:] if argv is None else argv
    error: str | None = None

    try:
        if len(arguments) != 1:
            raise ValueError

        record = Probe(arguments[0])

    except ContentResponsePolicyError as refusal:
        error = refusal.error

    except TimeoutError:
        error = "timeout"

    except OSError:
        error = "connection"

    except (ValueError, TypeError):
        error = "input"

    if error is not None:
        record = {"schema_version": 1, "profile": OWNED_CONTENT_RESPONSE_PROFILE,
                  "outcome": "refused", "error": error}

    output = SerializeContract(record).encode("ascii")

    if len(output) > MAX_RECORD_BYTES:
        raise ValueError("content response record exceeds its fixed bound")

    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()

    return 0 if error is None else 2


if __name__ == "__main__":
    raise SystemExit(Main())
