# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Read one fixed-loopback HTTP response under the parent process timeout."""

from __future__ import annotations

import http.client
import json
import sys
from collections.abc import Sequence

MAX_HTTP_BODY_BYTES = 65536


def ReadResponse(port: int, path: str) -> dict[str, object]:
    """Bound response size without redirects, proxies, or an arbitrary destination."""

    if not 1 <= port <= 65535 or not path.startswith("/") or path.startswith("//"):
        raise ValueError("HTTP probe requires a loopback port and an origin-relative path")

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)

    try:
        connection.request("GET", path)
        response = connection.getresponse()
        payload = response.read(MAX_HTTP_BODY_BYTES + 1)

        return {
            "status": response.status,
            "headers": response.getheaders(),
            "body": payload.decode("utf-8", errors="replace"),
            "error": (
                "HTTP response exceeded the bounded body budget"
                if len(payload) > MAX_HTTP_BODY_BYTES else ""
            ),
        }

    finally:
        connection.close()


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit one raw JSON response; the fixture owns the subprocess wall-clock budget."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)

    if len(arguments) != 2:
        raise ValueError("HTTP probe requires exactly a port and origin-relative path")

    print(json.dumps(ReadResponse(int(arguments[0]), arguments[1]), sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
