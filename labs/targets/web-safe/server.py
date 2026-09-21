"""Безопасная детерминированная HTTP-цель для синтетической лаборатории M0."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

HOST: Final = "0.0.0.0"
PORT: Final = 8080


class SafeLabRequestHandler(BaseHTTPRequestHandler):
    """Обслуживает намеренно ограниченный контракт безопасной лабораторной цели."""

    serverVersion = "1337SyntheticLab/0.1"
    sysVersion = ""

    def do_GET(self) -> None:  # noqa: N802
        """Отвечает только на детерминированные маршруты безопасной цели."""

        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "web-safe"})
            return

        if self.path == "/":
            self.SendJson(
                {
                    "name": "1337 synthetic web-safe target",
                    "purpose": "local development health target",
                }
            )
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Synthetic route not found")

    def log_message(self, format: str, *arguments: object) -> None:
        """Исключает штатные запросы к синтетической цели из журналов тестов."""

    def SendJson(self, payload: dict[str, str]) -> None:
        """Возвращает один детерминированный JSON-ответ."""

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def Main() -> None:
    """Запускает безопасную цель до остановки изолированного контейнера."""

    with ThreadingHTTPServer((HOST, PORT), SafeLabRequestHandler) as server:
        server.serve_forever()

if __name__ == "__main__":
    Main()
