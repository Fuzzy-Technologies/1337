"""Bounded HTTP helpers shared by the attack-path-mini lab services."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Final

MAX_REQUEST_BYTES: Final = 4096
AUTHORIZATION_HEADER: Final = "X-1337-Authorization"
AUTHORIZATION_VALUE: Final = "synthetic-fixture-only"


class LabRequestHandler(BaseHTTPRequestHandler):
    """Provide deterministic JSON I/O without accepting unbounded input."""

    server_version = "1337AttackPathMini/0.1"
    sys_version = ""

    def log_message(self, format: str, *arguments: object) -> None:
        """Keep expected synthetic requests out of routine test logs."""

    def IsAuthorized(self) -> bool:
        """Accept only the fixed synthetic-fixture authorization boundary."""

        return self.headers.get(AUTHORIZATION_HEADER) == AUTHORIZATION_VALUE

    def ReadJson(self) -> dict[str, object] | None:
        """Read one bounded JSON object or emit a deterministic client error."""

        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)

        except ValueError:
            self.SendJson({"error": "invalid-content-length"}, HTTPStatus.BAD_REQUEST)
            return None

        if length < 0 or length > MAX_REQUEST_BYTES:
            self.SendJson({"error": "request-too-large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None

        try:
            payload = json.loads(self.rfile.read(length) or b"{}")

        except json.JSONDecodeError:
            self.SendJson({"error": "invalid-json"}, HTTPStatus.BAD_REQUEST)
            return None

        if not isinstance(payload, dict):
            self.SendJson({"error": "json-object-required"}, HTTPStatus.BAD_REQUEST)
            return None

        return payload

    def SendJson(
        self,
        payload: dict[str, object],
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        """Write one stable JSON response."""

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
