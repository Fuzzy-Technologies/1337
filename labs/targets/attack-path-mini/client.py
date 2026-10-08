"""Controlled client for exercising the attack-path-mini lab."""

from __future__ import annotations

import json
import sys
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Final
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from http_common import AUTHORIZATION_HEADER, AUTHORIZATION_VALUE, LabRequestHandler

HOST: Final = "0.0.0.0"
PORT: Final = 8080
PORTAL_URL: Final = "http://lab-attack-portal:8080"
IDENTITY_URL: Final = "http://lab-attack-identity:8080"
BILLING_URL: Final = "http://lab-attack-billing:8080"
EVENTS_URL: Final = "http://lab-attack-events:8080"
CANONICAL_NODES: Final = (
    "zone.internet",
    "service.portal",
    "identity.portal-runtime",
    "service.billing-api",
    "asset.business-event",
)
CANONICAL_RELATIONS: Final = (
    "relation.internet-portal",
    "relation.portal-identity",
    "relation.identity-billing-api",
    "relation.billing-api-business-event",
)


class ClientRequestHandler(LabRequestHandler):
    """Expose health only; active flows run as explicit bounded commands."""

    def do_GET(self) -> None:  # noqa: N802
        """Serve the controlled client health route."""

        if self.path == "/health":
            self.SendJson({"status": "ok", "target": "attack-path-client"})
            return

        self.SendJson({"error": "not-found"}, HTTPStatus.NOT_FOUND)


def RequestJson(
    url: str,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    """Execute one bounded internal-lab request and preserve error payloads."""

    request_headers = {AUTHORIZATION_HEADER: AUTHORIZATION_VALUE, **(headers or {})}
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, json.load(response)

    except HTTPError as error:
        return error.code, json.load(error)


def Validate() -> dict[str, object]:
    """Exercise the complete authorized canonical path and return evidence."""

    status, portal = RequestJson(
        f"{PORTAL_URL}/session",
        method="POST",
        payload={"subject": "synthetic-user"},
    )
    if status != HTTPStatus.OK:
        return {"phase_id": "phase.authorized-validation", "result": portal, "state": "BLOCKED"}

    status, identity = RequestJson(
        f"{IDENTITY_URL}/exchange",
        method="POST",
        headers={"Authorization": f"Bearer {portal['token']}"},
    )
    if status != HTTPStatus.OK:
        raise RuntimeError(f"Identity exchange failed: {identity}")

    status, billing = RequestJson(
        f"{BILLING_URL}/events",
        method="POST",
        payload={"event": "invoice-settlement-demo"},
        headers={"Authorization": f"Bearer {identity['token']}"},
    )
    if status != HTTPStatus.CREATED:
        raise RuntimeError(f"Billing event creation failed: {billing}")

    return {
        "evidence_ids": [
            portal["evidence_id"],
            identity["evidence_id"],
            billing["evidence_id"],
            "evidence.validation-authorization",
        ],
        "node_ids": list(CANONICAL_NODES),
        "path_id": "path.internet-to-business-event",
        "phase_id": "phase.authorized-validation",
        "relation_ids": list(CANONICAL_RELATIONS),
        "state": billing["state"],
    }


def Negative() -> dict[str, object]:
    """Prove the signing-key path remains blocked by the exact policy."""

    status, result = RequestJson(f"{BILLING_URL}/signing-key")
    if status != HTTPStatus.FORBIDDEN:
        raise RuntimeError("Signing-key path unexpectedly became reachable")

    return {"path_id": "path.internet-to-signing-key", **result}


def Remediate() -> dict[str, object]:
    """Apply identity hardening and prove the canonical path is blocked."""

    status, control = RequestJson(f"{PORTAL_URL}/controls/harden", method="POST", payload={})
    if status != HTTPStatus.OK:
        raise RuntimeError(f"Portal hardening failed: {control}")

    status, result = RequestJson(
        f"{PORTAL_URL}/session",
        method="POST",
        payload={"subject": "synthetic-user"},
    )
    if status != HTTPStatus.FORBIDDEN:
        raise RuntimeError("Remediated Portal unexpectedly issued a runtime token")

    return {
        "path_id": "path.internet-to-business-event",
        "phase_id": "phase.remediation",
        **result,
    }


def Reset() -> dict[str, object]:
    """Restore the deterministic initial executable-lab state."""

    results = []
    for url in (f"{PORTAL_URL}/controls/reset", f"{EVENTS_URL}/reset"):
        status, result = RequestJson(url, method="POST", payload={})
        if status != HTTPStatus.OK:
            raise RuntimeError(f"Lab reset failed for {url}: {result}")
        results.append(result)

    return {"reset": True, "results": results}


def Health() -> dict[str, object]:
    """Verify every service through the controlled internal network."""

    targets = {}
    for name, base_url in (
        ("portal", PORTAL_URL),
        ("identity", IDENTITY_URL),
        ("billing", BILLING_URL),
        ("events", EVENTS_URL),
    ):
        status, result = RequestJson(f"{base_url}/health")
        if status != HTTPStatus.OK:
            raise RuntimeError(f"Health check failed for {name}: {result}")
        targets[name] = result["target"]

    return {"status": "ok", "targets": targets}


def Events() -> dict[str, object]:
    """Return the current Business Event state for reset verification."""

    status, result = RequestJson(f"{EVENTS_URL}/events")
    if status != HTTPStatus.OK:
        raise RuntimeError(f"Business Event state query failed: {result}")
    return result


def Serve() -> None:
    """Run the controlled entry-zone client until its container is stopped."""

    with ThreadingHTTPServer((HOST, PORT), ClientRequestHandler) as server:
        server.serve_forever()


def Main(arguments: list[str] | None = None) -> None:
    """Run one explicit lab operation or the client health service."""

    values = arguments if arguments is not None else sys.argv[1:]
    operation = values[0] if values else "serve"
    operations = {
        "events": Events,
        "health": Health,
        "negative": Negative,
        "remediate": Remediate,
        "reset": Reset,
        "validate": Validate,
    }
    if operation == "serve":
        Serve()
        return

    if operation not in operations:
        raise SystemExit(f"Unsupported attack-path-mini operation: {operation}")

    print(json.dumps(operations[operation](), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    Main()
