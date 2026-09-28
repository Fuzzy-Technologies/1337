"""Synthetic Business Event store for the canonical attack-path-mini lab."""

from __future__ import annotations

from http import HTTPStatus
from http.server import ThreadingHTTPServer
from threading import Lock
from typing import Final, cast

from http_common import LabRequestHandler

HOST: Final = "0.0.0.0"
PORT: Final = 8080
SERVICE_TOKEN: Final = "billing-service-v1"


class EventServer(ThreadingHTTPServer):
    """Keep deterministic in-memory event state that container restart also resets."""

    events: list[str]
    event_lock: Lock

    def __init__(self, server_address: tuple[str, int]) -> None:
        """Initialize an empty, process-local synthetic event store."""

        super().__init__(server_address, EventRequestHandler)
        self.events = []
        self.event_lock = Lock()


class EventRequestHandler(LabRequestHandler):
    """Accept only the fixed event and service identity used by the fixture."""

    def do_GET(self) -> None:  # noqa: N802
        """Serve health and the current deterministic event list."""

        server = cast(EventServer, self.server)
        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "attack-path-events"})
            return

        if self.path == "/events":
            with server.event_lock:
                events = list(server.events)

            self.SendJson({"asset_id": "asset.business-event", "events": events})
            return

        self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        """Create or reset only the known synthetic business event."""

        server = cast(EventServer, self.server)
        if self.path == "/reset":
            if not self.IsAuthorized():
                self.SendJson({"error": "authorization-required"}, HTTPStatus.FORBIDDEN)
                return

            with server.event_lock:
                server.events.clear()

            self.SendJson({"reset": True})
            return

        if self.path != "/events":
            self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)
            return

        if self.headers.get("X-1337-Service") != SERVICE_TOKEN:
            self.SendJson({"error": "invalid-service-token"}, HTTPStatus.FORBIDDEN)
            return

        payload = self.ReadJson()
        if payload is None:
            return

        if payload != {"event": "invoice-settlement-demo"}:
            self.SendJson({"error": "synthetic-event-required"}, HTTPStatus.BAD_REQUEST)
            return

        with server.event_lock:
            if "invoice-settlement-demo" not in server.events:
                server.events.append("invoice-settlement-demo")

        self.SendJson(
            {
                "asset_id": "asset.business-event",
                "created": True,
                "event": "invoice-settlement-demo",
            },
            HTTPStatus.CREATED,
        )


def Main() -> None:
    """Run the isolated Business Event fixture until its container is stopped."""

    with EventServer((HOST, PORT)) as server:
        server.serve_forever()


if __name__ == "__main__":
    Main()
