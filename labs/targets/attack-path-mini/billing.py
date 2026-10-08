"""Synthetic Billing API for the canonical attack-path-mini lab."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Final
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from http_common import LabRequestHandler

HOST: Final = "0.0.0.0"
PORT: Final = 8080
BILLING_TOKEN: Final = "billing-event-token-v1"
EVENT_STORE_URL: Final = "http://lab-attack-events:8080/events"
SERVICE_TOKEN: Final = "billing-service-v1"


class BillingRequestHandler(LabRequestHandler):
    """Create one known event while keeping signing-key access blocked."""

    def do_GET(self) -> None:  # noqa: N802
        """Serve health and the policy-blocked signing-key route."""

        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "attack-path-billing"})
            return

        if self.path == "/signing-key":
            self.SendJson(
                {
                    "blocked_by": "control.billing-key-policy",
                    "relation_id": "relation.billing-api-signing-key",
                    "state": "BLOCKED",
                },
                HTTPStatus.FORBIDDEN,
            )
            return

        self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        """Forward one authorized synthetic event to the isolated event store."""

        if self.path != "/events":
            self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)
            return

        if not self.IsAuthorized():
            self.SendJson({"error": "authorization-required"}, HTTPStatus.FORBIDDEN)
            return

        if self.headers.get("Authorization") != f"Bearer {BILLING_TOKEN}":
            self.SendJson({"error": "invalid-billing-token"}, HTTPStatus.UNAUTHORIZED)
            return

        payload = self.ReadJson()
        if payload is None:
            return

        if payload != {"event": "invoice-settlement-demo"}:
            self.SendJson({"error": "synthetic-event-required"}, HTTPStatus.BAD_REQUEST)
            return

        request = Request(
            EVENT_STORE_URL,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-1337-Service": SERVICE_TOKEN},
            method="POST",
        )
        try:
            with urlopen(request, timeout=2) as response:
                event_result = json.load(response)

        except (HTTPError, URLError, TimeoutError):
            self.SendJson({"error": "event-store-unavailable"}, HTTPStatus.BAD_GATEWAY)
            return

        self.SendJson(
            {
                "business_event": event_result,
                "evidence_id": "evidence.authorized-validation",
                "relation_id": "relation.billing-api-business-event",
                "state": "CONFIRMED",
            },
            HTTPStatus.CREATED,
        )


def Main() -> None:
    """Run the isolated Billing API fixture until its container is stopped."""

    with ThreadingHTTPServer((HOST, PORT), BillingRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    Main()
