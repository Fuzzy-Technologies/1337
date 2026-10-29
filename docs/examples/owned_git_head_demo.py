# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Serve two fixed nonsecret loopback responses; never read files or contact another service."""

from __future__ import annotations

import argparse
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast


class OwnedServer(HTTPServer):
    """Own one bounded local listener and a two-request synthetic receipt."""

    def __init__(self, port: int) -> None:
        """Bind only IPv4 loopback, using zero for an operating-system-selected test port."""

        super().__init__(("127.0.0.1", port), OwnedHandler)
        self.timeout = 0.25
        self.requests: list[str] = []

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        """Bound an accepted client's headers so partial requests cannot hold the fixture open."""

        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


class OwnedHandler(BaseHTTPRequestHandler):
    """Return only one inert Git HEAD canary and one fixed denial."""

    def do_GET(self) -> None:
        """Respond from constants, with no disk access, redirects, authentication or cookies."""

        exposed = self.path == "/.git/HEAD"
        label = "exposed" if exposed else "fixed" if self.path == "/fixed/.git/HEAD" else "other"
        cast(OwnedServer, self.server).requests.append(label)
        body = b"ref: refs/heads/main\n" if exposed else b"Not Found\n"
        self.send_response(200 if exposed else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        """Keep arbitrary request values out of logs; only fixed receipt labels are reported."""


def Main() -> int:
    """Stop after two requests, ten minutes or Ctrl+C and report the actual owned teardown."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--seconds", type=int, default=600)
    options = parser.parse_args()

    if options.port != 0 and not 1024 <= options.port <= 65535 or not 1 <= options.seconds <= 600:
        parser.error("select port 0 or 1024..65535, and seconds 1..600")

    server = OwnedServer(options.port)
    host, port = server.server_address
    print(json.dumps({"schema_version": 1, "state": "serving", "host": host, "port": port,
        "exposed_url": f"http://{host}:{port}/.git/HEAD",
        "fixed_url": f"http://{host}:{port}/fixed/.git/HEAD", "max_requests": 2}), flush=True)
    deadline = time.monotonic() + options.seconds

    try:
        while len(server.requests) < 2 and time.monotonic() < deadline:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    print(json.dumps({"schema_version": 1, "state": "stopped", "requests": server.requests,
                      "listener_closed": True}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
