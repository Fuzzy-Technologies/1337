# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""One fixed loopback GET admitting the complete reviewed original response before output."""

from __future__ import annotations

import hashlib
import socket
import sys
import time
from collections.abc import Sequence

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.owned_response_capture import (
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    OWNED_RESPONSE_CATALOG_SHA256,
    OWNED_RESPONSE_PROFILE,
    BytePart,
    Destination,
    RequestBytes,
    ReviewedResponse,
)


class CaptureRefusal(Exception):
    """Keep only the fixed safe refusal classification, without rejected response material."""

    def __init__(self, error: str) -> None:
        """Bind a fixed internal error classification without byte-bearing diagnostic text.

        Args:
            error: Internal protocol, response-policy or body-policy refusal classification.
        """

        self.error = error
        super().__init__(error)


def Remaining(deadline: float) -> float:
    """Return the remaining shared monotonic budget without renewing it on progress.

    Args:
        deadline: One fixed five-second deadline shared by connection, send, reads and EOF.

    Returns:
        Positive remaining seconds; expiration raises the fixed timeout classification.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError

    return remaining


def Probe(url: str) -> dict[str, object]:
    """Acquire exactly one selected original response through a direct literal socket.

    Args:
        url: One exact admitted loopback URL, with fixed catalog path and explicit owned port.

    Returns:
        Complete success record only after exact header/body admission and actual timely EOF.

    Raises:
        ValueError: The original URL is outside the closed selection grammar.
        CaptureRefusal: Peer, finite framing or reviewed response admission fails.
        TimeoutError: The shared five-second request deadline expires.
        OSError: The single direct connection or send/receive operation fails.
    """

    address, port, _, _, case_id = Destination(url)
    expected_headers, expected_body = ReviewedResponse(case_id)
    request = RequestBytes(url)
    deadline = time.monotonic() + 5.0
    family = socket.AF_INET6 if address == "::1" else socket.AF_INET

    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))
        Remaining(deadline)
        peer = connection.getpeername()

        if peer[0] != address or peer[1] != port:
            raise CaptureRefusal("protocol")

        connection.settimeout(Remaining(deadline))
        connection.sendall(request)
        Remaining(deadline)
        buffer = bytearray()
        boundary = -1

        while boundary < 0:
            if len(buffer) >= MAX_HEADER_BYTES:
                raise CaptureRefusal("protocol")

            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, MAX_HEADER_BYTES - len(buffer)))
            Remaining(deadline)

            if not chunk:
                raise CaptureRefusal("protocol")

            buffer.extend(chunk)
            boundary = buffer.find(b"\r\n\r\n")

            if (boundary < 0 and len(buffer) > MAX_HEADER_BYTES) or (
                boundary >= 0 and boundary + 4 > MAX_HEADER_BYTES
            ):
                raise CaptureRefusal("protocol")

        headers = bytes(buffer[:boundary + 4])

        if headers != expected_headers:
            raise CaptureRefusal("response-policy")

        body = bytearray(buffer[boundary + 4:])

        while True:
            if len(body) > MAX_BODY_BYTES or len(body) > len(expected_body):
                raise CaptureRefusal("protocol")

            connection.settimeout(Remaining(deadline))
            chunk = connection.recv(min(4096, MAX_BODY_BYTES - len(body),
                                        len(expected_body) + 1 - len(body)))
            Remaining(deadline)

            if not chunk:
                break

            body.extend(chunk)

    observed_body = bytes(body)

    if len(observed_body) != len(expected_body):
        raise CaptureRefusal("protocol")

    if observed_body != expected_body:
        raise CaptureRefusal("body-policy")

    response = headers + observed_body

    return {"schema_version": 1, "profile": OWNED_RESPONSE_PROFILE, "outcome": "captured",
        "catalog_sha256": OWNED_RESPONSE_CATALOG_SHA256, "case_id": case_id, "url": url,
        "address": address, "port": port, "request": BytePart(request),
        "response_headers": BytePart(headers), "response_body": BytePart(observed_body),
        "response": {"size_bytes": len(response), "sha256": hashlib.sha256(response).hexdigest()}}


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit exactly one canonical closed record without diagnostics or retained rejected bytes.

    Args:
        argv: Exactly one selected canonical URL; no caller flags or timeout options exist.

    Returns:
        Zero for captured originals or two for one closed refusal; stderr remains untouched.
    """

    arguments = sys.argv[1:] if argv is None else argv
    error: str | None = None

    try:
        if len(arguments) != 1:
            raise ValueError("fixed worker requires one URL")

        record = Probe(arguments[0])

    except CaptureRefusal as refusal:
        error = refusal.error

    except TimeoutError:
        error = "timeout"

    except OSError:
        error = "connection"

    except (ValueError, TypeError):
        error = "input"

    if error is not None:
        record = {"schema_version": 1, "profile": OWNED_RESPONSE_PROFILE,
                  "outcome": "refused", "error": error}

    sys.stdout.buffer.write(SerializeContract(record).encode("utf-8"))
    sys.stdout.buffer.flush()

    return 0 if error is None else 2


if __name__ == "__main__":
    raise SystemExit(Main())
