# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify the existing capture boundary for the proposed attack-path Portal descriptor."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.owned_response_workflow import (
    OwnedResponseAuthorityDeniedError,
    OwnedResponseCaptureSummary,
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
WORKSPACE_ID = "attack-path-portal-capture"
SCOPE_ID = "owned-portal"
OWNER = "operator:attack-path-portal"


class DescriptorWireControl(BaseHTTPRequestHandler):
    """Serve the proposed wire in a test-only listener, separate from the real Portal."""

    protocol_version = "HTTP/1.1"

    def Get(self) -> None:
        """Send only the fixed non-secret descriptor and close the connection."""

        self.close_connection = True

        if self.path != DESCRIPTOR_PATH:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        self.send_response_only(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(DESCRIPTOR_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(DESCRIPTOR_BODY)


# BaseHTTPRequestHandler dispatches with an externally imposed name.
setattr(DescriptorWireControl, "do_GET", DescriptorWireControl.Get)


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


def CreateWorkspace(root: Path, url: str) -> None:
    """Register and allow only the selected literal loopback source and its address."""

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned Portal capture"), WORKSPACE_ID)
    LocalModelStore(root).Create()
    members = (Target(TargetKind.URL, url), Target(TargetKind.IP, "127.0.0.1"))
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
        AuthorizationState.GRANTED, "attester:owned-portal", "consent:owned-portal",
        (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=2)).isoformat(),
    ), targets=members, allow=members))


def Capture(root: Path, url: str, *, retainResponse: bool = True) -> OwnedResponseCaptureSummary:
    """Use the existing governed SDK with the explicit capability and separate retention choice."""

    policy = ImpactPolicy("portal-capture", permissions=(CapabilityPermission(
        "http.owned-content-response-capture", "native.loopback-content-response", ImpactLevel.SAFE,
    ),))
    return asyncio.run(RunOwnedContentResponseCapture(root, SCOPE_ID, url, OWNER, lambda: policy,
        approve_safe_content_response_capture=True, retain_response=retainResponse))


def test_AttackPathPortalJsonDoesNotBecomeAnOriginalContentSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise one governed GET against the unmodified Portal and preserve a typed refusal."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    requests: list[tuple[str, str, str, bool]] = []
    TrackRequests(portal.PortalRequestHandler, requests, "actual-portal", monkeypatch)
    root = tmp_path / "workspace"
    server = portal.PortalServer(("127.0.0.1", 0), portal.PortalRequestHandler)

    with Listen(server, "/") as url:
        CreateWorkspace(root, url)
        refused = Capture(root, url)

    assert requests == [("actual-portal", "GET", "/", False)]
    assert refused.ExitCode() == 4 and refused.acquisition_outcome == "refused"
    assert refused.source_facts is None
    originals = {item.reference.role: item for item in refused.records}
    assert set(originals) == {"stdout", "stderr", "owned-response-receipt"}
    store = LocalEvidenceStore(root / "evidence")
    assert json.loads(store.Read(originals["stdout"].reference)) == {
        "schema_version": 1, "profile": "owned-content-response-capture.v1",
        "outcome": "refused", "error": "response-policy",
    }
    model = LocalModelStore(root).Open()
    assert not model.objects and not model.observations and not model.relations


def test_AttackPathDescriptorControlReplaysOriginalBodyAfterListenerTeardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove original custody for the candidate wire only, without adding a Portal feature."""

    requests: list[tuple[str, str, str, bool]] = []
    TrackRequests(DescriptorWireControl, requests, "test-wire", monkeypatch)
    root = tmp_path / "workspace"
    server = ThreadingHTTPServer(("127.0.0.1", 0), DescriptorWireControl)

    with Listen(server, DESCRIPTOR_PATH) as url:
        CreateWorkspace(root, url)

        with pytest.raises(OwnedResponseAuthorityDeniedError):
            Capture(root, url, retainResponse=False)

        assert not requests and not LocalWorkspaceStore(root).Open().job_references
        captured = Capture(root, url)

    assert requests == [("test-wire", "GET", DESCRIPTOR_PATH, False)]
    assert captured.ExitCode() == 0 and captured.acquisition_outcome == "captured"
    assert captured.original_receipt_id is not None
    moved = root.rename(tmp_path / "moved")
    replay = ReplayOwnedContentResponse(moved, captured.original_receipt_id)
    assert replay.original_job_id == captured.snapshot.spec.job_id
    assert replay.original_receipt_id == captured.original_receipt_id
    assert replay.records == captured.records and replay.source_facts == captured.source_facts
    roles = {item.reference.role: item for item in replay.records}
    assert set(roles) == {"stdout", "stderr", "owned-response-request", "owned-response-headers",
                          "owned-response-body", "owned-response-wire", "owned-response-receipt"}
    store = LocalEvidenceStore(moved / "evidence")
    body = store.Get(roles["owned-response-body"].evidence_id)
    assert store.Read(body.reference) == DESCRIPTOR_BODY
    model = LocalModelStore(moved).Open()
    endpoint, = model.objects
    assert endpoint.identity.kind is ObjectKind.ENDPOINT and endpoint.identity.key == url
    source, = (item for item in model.observations if item.kind == "owned-content-response-source")
    assert source.subject_reference == endpoint.Reference()
    assert source.provenance.target_reference == Target(TargetKind.URL, url).Reference()
    assert source.provenance.run_reference == replay.original_job_id
    assert source.provenance.scope_reference == f"scope:{SCOPE_ID}"
    assert body.reference in source.provenance.evidence_references
    assert not model.relations, "Original GET custody must not create a POST or a pivot"
