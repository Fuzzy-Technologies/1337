"""Synthetic Portal service for the canonical attack-path-mini lab."""

from __future__ import annotations

from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Final, cast

from http_common import LabRequestHandler

HOST: Final = "0.0.0.0"
PORT: Final = 8080
PORTAL_TOKEN: Final = "portal-runtime-token-v1"


class PortalServer(ThreadingHTTPServer):
    """Hold the resettable remediation state for the Portal fixture."""

    hardened: bool = False


class PortalRequestHandler(LabRequestHandler):
    """Expose only health, session validation, remediation, and reset routes."""

    def do_GET(self) -> None:  # noqa: N802
        """Serve health and bounded discovery metadata."""

        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "attack-path-portal"})
            return

        if self.path == "/":
            self.SendJson({"routes": ["POST /session"], "service_id": "service.portal"})
            return

        self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        """Model the session weakness and its deterministic remediation."""

        if not self.IsAuthorized():
            self.SendJson({"error": "authorization-required"}, HTTPStatus.FORBIDDEN)
            return

        server = cast(PortalServer, self.server)
        if self.path == "/controls/harden":
            server.hardened = True
            self.SendJson(
                {
                    "control_id": "control.portal-identity-hardening",
                    "relation_id": "relation.portal-identity",
                    "state": "BLOCKED",
                }
            )
            return

        if self.path == "/controls/reset":
            server.hardened = False
            self.SendJson({"reset": True, "state": "LIKELY"})
            return

        if self.path != "/session":
            self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)
            return

        payload = self.ReadJson()
        if payload is None:
            return

        if payload != {"subject": "synthetic-user"}:
            self.SendJson({"error": "synthetic-subject-required"}, HTTPStatus.BAD_REQUEST)
            return

        if server.hardened:
            self.SendJson(
                {
                    "blocked_by": "control.portal-identity-hardening",
                    "relation_id": "relation.portal-identity",
                    "state": "BLOCKED",
                },
                HTTPStatus.FORBIDDEN,
            )
            return

        self.SendJson(
            {
                "evidence_id": "evidence.finding-confirmation",
                "identity_id": "identity.portal-runtime",
                "relation_id": "relation.portal-identity",
                "token": PORTAL_TOKEN,
            }
        )


def Main() -> None:
    """Run the isolated Portal fixture until its container is stopped."""

    with PortalServer((HOST, PORT), PortalRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    Main()
