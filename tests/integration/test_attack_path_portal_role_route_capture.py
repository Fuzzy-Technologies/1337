# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify the owned Portal descriptor through original capture and offline replay."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.evidence import EvidenceIntegrityError, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.owned_response_workflow import (
    OwnedResponseAuthorityDeniedError,
    OwnedResponseCaptureSummary,
    OwnedResponseReplaySummary,
    ReplayOwnedContentResponse,
    RunOwnedContentResponseCapture,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.integration.test_attack_path_native_discovery import LoadFixtureModule, TrackRequests

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Capture owns a Linux worker")

DESCRIPTOR_PATH = "/.well-known/attack-path-mini"
DESCRIPTOR_BODY = b"service_id=service.portal\nroute=POST /session\n"
DESCRIPTOR_WIRE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Length: 46\r\n"
    b"Connection: close\r\n\r\n"
    + DESCRIPTOR_BODY
)
WORKSPACE_ID = "attack-path-portal-capture"
SCOPE_ID = "owned-portal"
OWNER = "operator:attack-path-portal"


@contextmanager
def Listen(server: ThreadingHTTPServer, path: str) -> Iterator[str]:
    """Own one already bound test listener and stop it before offline replay."""

    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})

    with server:
        thread.start()

        try:
            yield f"http://127.0.0.1:{server.server_port}{path}"

        finally:
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive(), "The test-owned Portal listener must stop"


def CreateWorkspace(
    root: Path, url: str, *, admitUrl: bool = True, admitIp: bool = True, expired: bool = False,
) -> None:
    """Register and allow only the selected literal loopback source and its address."""

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned Portal capture"), WORKSPACE_ID)
    LocalModelStore(root).Create()
    members = (Target(TargetKind.URL, url), Target(TargetKind.IP, "127.0.0.1"))
    allow = tuple(target for target, allowed in zip(members, (admitUrl, admitIp), strict=True)
                  if allowed)
    now = datetime.now(UTC)

    if expired:
        now -= timedelta(minutes=5)

    LocalScopeStore(root).Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
        AuthorizationState.GRANTED, "attester:owned-portal", "consent:owned-portal",
        (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=2)).isoformat(),
    ), targets=members, allow=allow))


def Capture(
    root: Path, url: str, *, approve: bool = True, retainResponse: bool = True,
    permit: bool = True,
) -> OwnedResponseCaptureSummary:
    """Use the existing governed SDK with the explicit capability and separate retention choice."""

    permission = CapabilityPermission(
        "http.owned-content-response-capture", "native.loopback-content-response", ImpactLevel.SAFE,
    )
    policy = ImpactPolicy("portal-capture", permissions=(permission,) if permit else ())
    return asyncio.run(RunOwnedContentResponseCapture(root, SCOPE_ID, url, OWNER, lambda: policy,
        approve_safe_content_response_capture=approve, retain_response=retainResponse))


def AdvertisedPortal(
    root: Path, replay: OwnedResponseReplaySummary, url: str,
) -> tuple[str, str, str, str, str] | None:
    """Read the advertised role and route with the original custody IDs for this exact source."""

    model = LocalModelStore(root).Open()
    endpoint, = model.objects
    source, = (item for item in model.observations if item.kind == "owned-content-response-source")

    if (
        endpoint.identity.kind is not ObjectKind.ENDPOINT or endpoint.identity.key != url
        or source.subject_reference != endpoint.Reference()
        or source.provenance.target_reference != Target(TargetKind.URL, url).Reference()
        or source.provenance.run_reference != replay.original_job_id
        or source.provenance.scope_reference != f"scope:{SCOPE_ID}"
    ):
        return None

    body, = (item for item in replay.records if item.reference.role == "owned-response-body")
    originalBody = LocalEvidenceStore(root / "evidence").Read(body.reference)
    if (
        body.reference not in source.provenance.evidence_references
        or originalBody != DESCRIPTOR_BODY
    ):
        return None

    service, route = originalBody.decode("ascii").splitlines()

    return (service.removeprefix("service_id="), route.removeprefix("route="),
            replay.original_receipt_id, replay.original_job_id, body.evidence_id)


def test_AttackPathPortalJsonDoesNotBecomeAnOriginalContentSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise one governed GET against the legacy JSON route and preserve a typed refusal."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    requests: list[tuple[str, str, str, bool]] = []
    TrackRequests(portal.PortalRequestHandler, requests, "actual-portal", monkeypatch)
    root = tmp_path / "workspace"
    server = portal.PortalServer(("127.0.0.1", 0), portal.PortalRequestHandler)

    with Listen(server, "/") as url:
        CreateWorkspace(root, url)
        refused = Capture(root, url)

    assert requests == [("actual-portal", "GET", "/", False)], (
        "The legacy route must receive one anonymous GET."
    )
    assert refused.ExitCode() == 4 and refused.acquisition_outcome == "refused", (
        "Legacy JSON must return a typed capture refusal."
    )
    assert refused.source_facts is None, "Refused legacy content must provide no source facts."
    originals = {item.reference.role: item for item in refused.records}
    assert set(originals) == {"stdout", "stderr", "owned-response-receipt"}, (
        "Legacy refusal must retain diagnostics and the receipt only."
    )
    store = LocalEvidenceStore(root / "evidence")
    assert json.loads(store.Read(originals["stdout"].reference)) == {
        "schema_version": 1, "profile": "owned-content-response-capture.v1",
        "outcome": "refused", "error": "response-policy",
    }, "Legacy JSON must report the response-policy diagnostic."
    model = LocalModelStore(root).Open()
    assert not model.objects and not model.observations and not model.relations, (
        "Legacy refusal must leave the model empty."
    )


@pytest.mark.parametrize("advertisedRoute", ("POST /session", "GET /session"))
def test_AttackPathPortalDescriptorReplaysOriginalBodyAfterListenerTeardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advertisedRoute: str,
) -> None:
    """Replay original Portal bytes and derive the fact only from the admitted role and route."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    expectedBody = f"service_id=service.portal\nroute={advertisedRoute}\n".encode("ascii")

    if advertisedRoute != "POST /session":
        monkeypatch.setattr(portal, "DESCRIPTOR_BODY", expectedBody)

    requests: list[tuple[str, str, str, bool]] = []
    TrackRequests(portal.PortalRequestHandler, requests, "actual-portal", monkeypatch)
    root = tmp_path / "workspace"
    server = portal.PortalServer(("127.0.0.1", 0), portal.PortalRequestHandler)

    with Listen(server, DESCRIPTOR_PATH) as url:
        CreateWorkspace(root, url)

        captured = Capture(root, url)

    assert requests == [("actual-portal", "GET", DESCRIPTOR_PATH, False)], (
        "The descriptor must receive one anonymous GET."
    )
    assert captured.ExitCode() == 0 and captured.acquisition_outcome == "captured", (
        "The descriptor must complete the governed capture."
    )
    assert captured.original_receipt_id is not None, "Capture must issue an original receipt."
    moved = root.rename(tmp_path / "moved")
    replay = ReplayOwnedContentResponse(moved, captured.original_receipt_id)
    assert replay.original_job_id == captured.snapshot.spec.job_id, (
        "Replay must identify the original capture job."
    )
    assert replay.original_receipt_id == captured.original_receipt_id, (
        "Replay must preserve the original receipt."
    )
    assert replay.records == captured.records and replay.source_facts == captured.source_facts, (
        "Replay must preserve every captured record and source fact."
    )
    roles = {item.reference.role: item for item in replay.records}
    assert set(roles) == {"stdout", "stderr", "owned-response-request", "owned-response-headers",
                          "owned-response-body", "owned-response-wire", "owned-response-receipt"}, (
        "Replay must contain all seven original evidence roles."
    )
    store = LocalEvidenceStore(moved / "evidence")
    body = store.Get(roles["owned-response-body"].evidence_id)
    assert store.Read(body.reference) == expectedBody, (
        "Replay must preserve the exact advertised body."
    )
    assert replay.source_facts["original_role_ids"] == {
        role: record.evidence_id for role, record in roles.items()
    }, "Source facts must identify each original evidence role."
    model = LocalModelStore(moved).Open()
    assert not model.relations, "Original GET custody must not create a POST or a pivot"
    assert tuple(item.identity.kind for item in model.objects) == (ObjectKind.ENDPOINT,), (
        "Capture must record only the selected GET endpoint."
    )

    if advertisedRoute != "POST /session":
        assert AdvertisedPortal(moved, replay, url) is None, (
            "An altered advertised method must produce no Portal fact."
        )
        return

    assert store.Read(roles["owned-response-wire"].reference) == DESCRIPTOR_WIRE, (
        "Replay must preserve the original HTTP/1.1 response wire."
    )
    assert AdvertisedPortal(moved, replay, url) == (
        "service.portal", "POST /session", captured.original_receipt_id,
        captured.snapshot.spec.job_id, body.evidence_id,
    ), "The Portal fact must retain the original receipt, job and body IDs."
    assert AdvertisedPortal(moved, replay, url.removesuffix(DESCRIPTOR_PATH) + "/other") is None, (
        "A different source URL must produce no Portal fact."
    )

    foreign = tmp_path / "foreign"
    CreateWorkspace(foreign, url)

    with pytest.raises(ValueError, match="receipt association is unknown"):
        ReplayOwnedContentResponse(foreign, captured.original_receipt_id)

    (moved / "evidence" / body.reference.locator).write_bytes(b"!" + expectedBody[1:])

    with pytest.raises(EvidenceIntegrityError):
        ReplayOwnedContentResponse(moved, captured.original_receipt_id)


@pytest.mark.parametrize("denial", ("approval", "retention", "capability", "url", "ip", "consent"))
def test_AttackPathPortalDescriptorAuthorityDenialHasZeroContact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, denial: str,
) -> None:
    """Refuse each missing authority input before any request or original source exists."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    requests: list[tuple[str, str, str, bool]] = []
    TrackRequests(portal.PortalRequestHandler, requests, "actual-portal", monkeypatch)
    root = tmp_path / "workspace"
    server = portal.PortalServer(("127.0.0.1", 0), portal.PortalRequestHandler)

    with Listen(server, DESCRIPTOR_PATH) as url:
        CreateWorkspace(root, url, admitUrl=denial != "url", admitIp=denial != "ip",
                        expired=denial == "consent")

        if denial in {"approval", "retention"}:
            with pytest.raises(OwnedResponseAuthorityDeniedError):
                Capture(
                    root, url, approve=denial != "approval", retainResponse=denial != "retention",
                )

            assert not LocalWorkspaceStore(root).Open().job_references, (
                "Missing approval or retention must leave no job."
            )

        else:
            refused = Capture(root, url, permit=denial != "capability")
            assert refused.ExitCode() == 3, "Authority refusal must return the denial exit code."
            assert refused.original_receipt_id is None and refused.source_facts is None, (
                "Authority refusal must provide no original receipt or source facts."
            )
            assert not refused.records, "Authority refusal must retain no original records."

    assert not requests, "Authority denial must stop before contacting the Portal."
    model = LocalModelStore(root).Open()
    assert not model.objects and not model.observations and not model.relations, (
        "Authority denial must leave the model empty."
    )


def test_AttackPathPortalDescriptorPreservesLegacyRoutes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the Portal's existing route behavior and expose only one exact descriptor path."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    server = portal.PortalServer(("127.0.0.1", 0), portal.PortalRequestHandler)
    cases = (
        ("GET", "/", 200, b'{"routes":["POST /session"],"service_id":"service.portal"}'),
        ("GET", "/health", 200, b'{"status":"ok","target":"attack-path-portal"}'),
        ("GET", f"{DESCRIPTOR_PATH}?other", 404, b'{"error":"not-found"}'),
        ("POST", DESCRIPTOR_PATH, 403, b'{"error":"authorization-required"}'),
        ("POST", "/session", 403, b'{"error":"authorization-required"}'),
    )

    with Listen(server, "/"):
        for method, path, status, body in cases:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)

            try:
                connection.request(method, path)
                response = connection.getresponse()
                assert response.version == 10 and response.status == status, (
                    "Legacy HTTP version or status changed for the requested route."
                )
                assert response.getheader("Content-Type") == "application/json", (
                    "Legacy routes must continue to declare JSON."
                )
                assert response.getheader("Content-Length") == str(len(body)), (
                    "Legacy routes must declare the exact response length."
                )
                assert response.read() == body, "Legacy route response bytes changed."

            finally:
                connection.close()
