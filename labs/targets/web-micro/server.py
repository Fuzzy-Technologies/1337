"""Детерминированная HTTP-микроцель для безопасных функциональных тестов."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final
from urllib.parse import parse_qs, urlsplit

HOST: Final = "0.0.0.0"
PORT: Final = 8080
MAXREQUESTBYTES: Final = 4096
DISCOVERYLINKS: Final = ("/catalog", "/form", "/headers", "/cookie")
CANARYSIMULATIONS: Final = {
    "/canary/command-execution": "command-execution",
    "/canary/file-inclusion": "file-inclusion",
    "/canary/ssrf": "ssrf",
    "/canary/upload": "upload-validation",
}
STATUSROUTES: Final = frozenset((400, 401, 403, 404, 500))


class MicroTargetRequestHandler(BaseHTTPRequestHandler):
    """Обслуживает известные маршруты без выполнения пользовательского ввода."""

    serverVersion = "1337WebMicro/0.1"
    sysVersion = ""

    def do_GET(self) -> None:  # noqa: N802
        """Обслуживает контракты обнаружения, ввода, статусов и маркеров."""

        request = urlsplit(self.path)
        path = request.path

        if path == "/health":
            self.SendJson({"status": "ok", "target": "web-micro"})
            return

        if path == "/":
            self.SendJson({"links": list(DISCOVERYLINKS), "target": "web-micro"})
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

        if path in CANARYSIMULATIONS:
            # Маркер подтверждает маршрут, но не выполняет опасное действие.
            simulation = CANARYSIMULATIONS[path]
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
        """Моделирует ограниченный ввод без сохранения и выполнения данных."""

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
        """Исключает ожидаемые запросы из журналов функциональных тестов."""

    def ReadRequestBody(self) -> bytes | None:
        """Читает ограниченное тело фикстуры и отклоняет неверную длину."""

        contentLength = self.headers.get("Content-Length", "0")
        try:
            size = int(contentLength)

        except ValueError:
            self.SendJson({"error": "invalid-content-length"}, status=HTTPStatus.BAD_REQUEST)
            return None

        if size < 0 or size > MAXREQUESTBYTES:
            self.SendJson(
                {"error": "request-too-large"},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return None

        return self.rfile.read(size)

    def SendJsonRequestResult(self, body: bytes) -> None:
        """Разбирает JSON-объект только для проверки поведения маршрута."""

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
        """Обслуживает конечную матрицу ошибочных статусов для проверок."""

        try:
            statusCode = int(path.removeprefix("/status/"))

        except ValueError:
            self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)
            return

        if statusCode not in STATUSROUTES:
            self.SendJson({"error": "not-found"}, status=HTTPStatus.NOT_FOUND)
            return

        self.SendJson({"status": statusCode}, status=HTTPStatus(statusCode))

    def SendHtml(self, body: str) -> None:
        """Возвращает статический HTML-контракт для обнаружения формы."""

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
        """Возвращает стабильный JSON с необязательными заголовками."""

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)

        self.end_headers()
        self.wfile.write(body)


def Main() -> None:
    """Запускает синтетическую цель до остановки контейнера."""

    with ThreadingHTTPServer((HOST, PORT), MicroTargetRequestHandler) as server:
        server.serve_forever()

if __name__ == "__main__":
    Main()
