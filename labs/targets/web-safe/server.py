"""Safe deterministic HTTP target for the M0 synthetic security lab."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

HOST: Final = "0.0.0.0"
PORT: Final = 8080


class SafeLabRequestHandler(BaseHTTPRequestHandler):
    """Serve the intentionally small public contract of the safe lab target."""

    server_version = "1337SyntheticLab/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        """Respond only to deterministic safe target routes."""
        if self.path == "/health":
            self._send_json({"status": "ok", "target": "web-safe"})
            return

        if self.path == "/":
            self._send_json(
                {
                    "name": "1337 synthetic web-safe target",
                    "purpose": "local development health target",
                }
            )
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Synthetic route not found")

    def log_message(self, format: str, *arguments: object) -> None:
        """Keep routine synthetic target requests out of test logs."""

    def _send_json(self, payload: dict[str, str]) -> None:
        """Write one deterministic JSON response."""
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    """Run the safe target until its isolated container is stopped."""
    with ThreadingHTTPServer((HOST, PORT), SafeLabRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
