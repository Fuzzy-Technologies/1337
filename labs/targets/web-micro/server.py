"""Deterministic first-party HTTP micro-target for safe functional scanner tests."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final
from urllib.parse import parse_qs, urlsplit

HOST: Final = "0.0.0.0"
PORT: Final = 8080
MAX_REQUEST_BYTES: Final = 4096
DISCOVERY_LINKS: Final = ("/catalog", "/form", "/headers", "/cookie")
CANARY_SIMULATIONS: Final = {
    "/canary/command-execution": "command-execution",
    "/canary/file-inclusion": "file-inclusion",
    "/canary/ssrf": "ssrf",
    "/canary/upload": "upload-validation",
}
STATUS_ROUTES: Final = frozenset((400, 401, 403, 404, 500))


class MicroTargetRequestHandler(BaseHTTPRequestHandler):
    """Serve known-answer routes without executing user-controlled behavior."""

    server_version = "1337WebMicro/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        """Serve deterministic discovery, input, status, and canary contracts."""

        request = urlsplit(self.path)
        path = request.path

        if path == "/health":
            self.SendJson({"status": "ok", "target": "web-micro"})
            return

        if path == "/":
            self.SendJson({"links": list(DISCOVERY_LINKS), "target": "web-micro"})
            return

        if path == "/catalog":
            self.SendJson({"items": ["alpha", "beta"], "target": "web-micro"})
            return

        if path == "/redirect":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/catalog")
            self.end_headers()
            return

        if path == "/headers":
            self.SendJson(
                {"target": "web-micro"},
                headers=(
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("X-1337-Lab", "web-micro"),
                ),
            )
            return

        if path == "/cookie":
            self.SendJson(
                {"target": "web-micro"},
                headers=(("Set-Cookie", "lab_session=deterministic; HttpOnly; SameSite=Strict"),),
            )
            return

        if path == "/form":
            self.SendHtml(
                "<!doctype html><html><body><form action=\"/submit\" method=\"post\">"
                "<input name=\"query\"><button>Submit</button></form></body></html>"
            )
            return

        if path == "/query":
            query = parse_qs(request.query, keep_blank_values=True)
            self.SendJson({"item": query.get("item", ["default"])[0]})
            return

        if path in CANARY_SIMULATIONS:
            simulation = CANARY_SIMULATIONS[path]
            payload: dict[str, int | str] = {"simulation": simulation}
            if simulation == "ssrf":
                payload["outbound_requests"] = 0

            self.SendJson(payload)
            return

        if path.startswith("/status/"):
            self.SendStatusRoute(path)
            return

        self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        """Model bounded input handling without persisting files or executing input."""

        path = urlsplit(self.path).path
        body = self.ReadRequestBody()
        if body is None:
            return

        if path == "/submit":
            self.SendJson({"accepted": True, "simulation": "form"})
            return

        if path == "/json":
            self.SendJsonRequestResult(body)
            return

        if path == "/upload":
            self.SendJson({"accepted": False, "simulation": "upload-validation"})
            return

        self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *arguments: object) -> None:
        """Keep expected synthetic requests out of functional-test logs."""

    def ReadRequestBody(self) -> bytes | None:
        """Read only a bounded local fixture body and reject invalid lengths."""

        content_length = self.headers.get("Content-Length", "0")
        try:
            size = int(content_length)

        except ValueError:
            self.SendJson({"error": "invalid-content-length"}, status=HTTPStatus.BAD_REQUEST)
            return None

        if size < 0 or size > MAX_REQUEST_BYTES:
            self.SendJson(
                {"error": "request-too-large"},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return None

        return self.rfile.read(size)

    def SendJsonRequestResult(self, body: bytes) -> None:
        """Parse a JSON object only to expose deterministic input-route behavior."""

        try:
            payload = json.loads(body)

        except json.JSONDecodeError:
            self.SendJson({"error": "invalid-json"}, status=HTTPStatus.BAD_REQUEST)
            return

        if not isinstance(payload, dict):
            self.SendJson({"error": "json-object-required"}, status=HTTPStatus.BAD_REQUEST)
            return

        self.SendJson({"accepted": True, "keys": sorted(payload)})

    def SendStatusRoute(self, path: str) -> None:
        """Serve a small finite error-status matrix for deterministic assertions."""

        try:
            status_code = int(path.removeprefix("/status/"))

        except ValueError:
            self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)
            return

        if status_code not in STATUS_ROUTES:
            self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)
            return

        self.SendJson({"status": status_code}, status=HTTPStatus(status_code))

    def SendHtml(self, body: str) -> None:
        """Write a compact static HTML contract for form discovery."""

        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def SendJson(
        self,
        payload: dict[str, object],
        status: HTTPStatus = HTTPStatus.OK,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Write one stable JSON response with optional fixed response headers."""

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)

        self.end_headers()
        self.wfile.write(body)


def Main() -> None:
    """Run the isolated synthetic target until its container is stopped."""

    with ThreadingHTTPServer((HOST, PORT), MicroTargetRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    Main()
