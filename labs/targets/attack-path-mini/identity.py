"""Synthetic Identity service for the canonical attack-path-mini lab."""

from __future__ import annotations

from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Final

from http_common import LabRequestHandler

HOST: Final = "0.0.0.0"
PORT: Final = 8080
PORTAL_TOKEN: Final = "portal-runtime-token-v1"
BILLING_TOKEN: Final = "billing-event-token-v1"


class IdentityRequestHandler(LabRequestHandler):
    """Exchange only the fixed Portal fixture token for a bounded Billing token."""

    def do_GET(self) -> None:  # noqa: N802
        """Serve the deterministic health route."""

        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "attack-path-identity"})
            return

        self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        """Exchange one exact synthetic identity token."""

        if self.path != "/exchange":
            self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)
            return

        if not self.IsAuthorized():
            self.SendJson({"error": "authorization-required"}, HTTPStatus.FORBIDDEN)
            return

        if self.headers.get("Authorization") != f"Bearer {PORTAL_TOKEN}":
            self.SendJson({"error": "invalid-portal-token"}, HTTPStatus.UNAUTHORIZED)
            return

        self.SendJson(
            {
                "evidence_id": "evidence.discovery",
                "relation_id": "relation.identity-billing-api",
                "token": BILLING_TOKEN,
            }
        )


def Main() -> None:
    """Run the isolated Identity fixture until its container is stopped."""

    with ThreadingHTTPServer((HOST, PORT), IdentityRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    Main()
