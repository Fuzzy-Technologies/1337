# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify the governed MCP wire interface against an inert owned loopback catalog."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from traceback import walk_tb
from typing import Any, cast

import pytest

from fuzzy1337 import mcp_metadata_http
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.mcp_drift import ApproveMcpBaseline, ReviewMcpDrift
from fuzzy1337.mcp_inventory import (
    CollectAndImportMcpMetadata,
    ImportMcpInventory,
    ParseMcpInventory,
)
from fuzzy1337.mcp_metadata import (
    MCP_PROTOCOL_VERSION,
    McpMetadataDenied,
    McpMetadataIssue,
    McpMetadataLimits,
)
from fuzzy1337.mcp_metadata_http import (
    MCP_METADATA_CAPABILITY,
    CollectMcpMetadataHttp,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
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

_SNAPSHOT = Path(__file__).parents[1] / "contract" / "fixtures" / "mcp.inventory.v1.json"
_TOKEN = "fixture-bearer-auth-113358"
_SESSION = "owned-fixture-session-71828"
_EXPECTED = (
    "initialize", "notifications/initialized", "tools/list", "tools/list",
    "resources/list", "resources/templates/list", "prompts/list",
)


@dataclass(slots=True)
class CatalogProgram:
    """Inert catalog replies and a method-only request log."""

    sample: dict[str, Any]
    mode: str
    requiresToken: bool
    onAcceptedPost: Callable[[], None] | None
    methods: list[str] = field(default_factory=list)
    shutdown: Event = field(default_factory=Event)


class CatalogServer(ThreadingHTTPServer):
    """Owned single-loopback listener carrying fixture state in memory."""

    program: CatalogProgram


class CatalogHandler(BaseHTTPRequestHandler):
    """Serve the fixed catalog with synthetic HTTP framing and no content handlers."""

    protocol_version = "HTTP/1.1"

    def SuppressAccessLog(self, format: str, *arguments: object) -> None:
        """Suppress HTTP logs so the fixture's only log is the method sequence.

        Args:
            format: External HTTP server logging format.
            arguments: Interpolation arguments deliberately ignored by the fixture.
        """

    def ReceivePost(self) -> None:
        """Record a method and serve its fixed declaration or the selected failure fixture."""

        program = cast(CatalogServer, self.server).program
        self.close_connection = True

        if self.path != "/catalog/mcp":
            program.methods.append("unexpected-endpoint")
            self.send_response_only(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

            return

        if program.requiresToken and self.headers.get("Authorization") != "Bearer " + _TOKEN:
            self.send_response_only(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

            return

        request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        method = request["method"]
        program.methods.append(method)

        if program.onAcceptedPost is not None:
            program.onAcceptedPost()

        try:
            self.Reply(program, request)

        except (ConnectionError, OSError):
            # The client closes intentionally after a decisive SSE frame or a deadline.
            return

    # BaseHTTPRequestHandler owns these callback names.
    do_POST = ReceivePost
    log_message = SuppressAccessLog

    def Reply(self, program: CatalogProgram, request: dict[str, Any]) -> None:
        """Emit only the finite synthetic declarations and chosen passive failure.

        Args:
            program: Fixture catalog, mode and owned synchronization.
            request: Parsed request from the collector's loopback connection.
        """

        method = request["method"]
        sample = program.sample

        if method == "initialize":
            if self.headers.get("MCP-Session-Id") is not None or (
                self.headers.get("MCP-Protocol-Version") is not None
            ) or request["params"]["capabilities"] != {}:
                self.SendFixed(400, b"")

                return

            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION, "serverInfo": sample["server"],
                "instructions": sample["instructions"],
                "capabilities": {item["name"]: item["declaration"]
                                 for item in sample["capabilities"]["items"]},
            }
            self.ReplyInitialize(program, request, result)

            return

        if self.headers.get("MCP-Session-Id") != _SESSION or (
            self.headers.get("MCP-Protocol-Version") != MCP_PROTOCOL_VERSION
        ):
            self.SendFixed(400, b"")

            return

        if method == "notifications/initialized":
            self.SendFixed(202, b"")

            return

        if method == "tools/list":
            tools = sample["tools"]["items"]

            if "params" not in request:
                body = self.Rpc(request, {"tools": tools[:1], "nextCursor": "known-cursor"})
                self.SendFixed(200, body)

                return

            body = self.Rpc(request, {"tools": tools[1:]})
            self.SendEventStream(body, program)

            return

        lists = {
            "resources/list": {"resources": sample["resources"]["items"]},
            "resources/templates/list": {
                "resourceTemplates": sample["resource_templates"]["items"],
            },
            "prompts/list": {"prompts": sample["prompts"]["items"]},
        }

        if method in lists:
            self.SendFixed(200, self.Rpc(request, lists[method]))

            return

        self.SendFixed(405, b"")

    def ReplyInitialize(self, program: CatalogProgram, request: dict[str, Any],
                        result: dict[str, Any]) -> None:
        """Send one initialization result or a selected scoped failure response.

        Args:
            program: Scripted loopback fault mode and synthetic credentials.
            request: Original parsed initialize request.
            result: Inert initialization declarations.
        """

        session = _SESSION
        extra: tuple[tuple[str, str], ...] = ()

        if program.mode == "redirect":
            self.SendFixed(307, b"", (("Location", "/outside"),))

            return

        if program.mode == "header-drip":
            self.Drip(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")

            return

        if program.mode == "session-echo":
            session = _TOKEN

        if program.mode == "body-echo":
            result["serverInfo"]["name"] = _TOKEN

        if program.mode == "duplicate":
            extra = (("Content-Type", "application/json"),)

        if program.mode == "oversized-header":
            extra = (("X-Bound", "x" * (17 * 1024)),)

        if program.mode == "encoding":
            extra = (("Content-Encoding", "gzip"),)

        if program.mode == "ambiguous":
            extra = (("Transfer-Encoding", "chunked"),)

        body = self.Rpc(request, result)

        if program.mode == "body-echo":
            escaped = b"\\u%04x" % ord(_TOKEN[0]) + _TOKEN[1:].encode("ascii")
            body = body.replace(_TOKEN.encode("ascii"), escaped)

        if program.mode == "body-drip":
            self.send_response_only(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.Drip(body)

            return

        if program.mode == "close-delimited":
            self.send_response_only(200)
            self.send_header("MCP-Session-Id", session)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

            return

        self.SendFixed(200, body, (("MCP-Session-Id", session), *extra))

    def Rpc(self, request: dict[str, Any], result: object) -> bytes:
        """Build a JSON-RPC fixture response from its exact request ID.

        Args:
            request: The original fixture request.
            result: Synthetic initialization or descriptor declarations.

        Returns:
            Exact UTF-8 JSON response body for that parsed request.
        """

        return CanonicalModelJson({"jsonrpc": "2.0", "id": request["id"], "result": result})

    def SendFixed(self, status: int, body: bytes,
                  extra: tuple[tuple[str, str], ...] = ()) -> None:
        """Send one known-length HTTP fixture response.

        Args:
            status: Constant scripted HTTP status.
            body: Synthetic response body.
            extra: Approved test framing variations.
        """

        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))

        for key, value in extra:
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def Drip(self, body: bytes) -> None:
        """Keep making progress below an inactivity timeout but exceed the total deadline.

        Args:
            body: Fixed benign HTTP header or body bytes to send separately.
        """

        for value in body[:12]:
            self.wfile.write(bytes((value,)))
            sleep(0.035)

    def SendEventStream(self, body: bytes, program: CatalogProgram) -> None:
        """Send an SSE result split across transfer chunks on an optionally still-open stream.

        Args:
            body: Complete matching JSON-RPC result.
            program: Fixture mode and shutdown synchronization.
        """

        self.send_response_only(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        data = (
            b"data:\r\n\r\n"
            b'data: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'
            b"data: " + body + b"\r\n\r\n"
        )

        if program.mode == "incomplete-sse":
            data = data[:-2]

        fragments = (data[:7], data[7:-3], data[-3:])

        for index, fragment in enumerate(fragments):
            boundary = b"XX" if program.mode == "bad-chunk" and index == 2 else b"\r\n"
            self.wfile.write(b"%x\r\n" % len(fragment) + fragment + boundary)

        if program.mode == "hold-open":
            program.shutdown.wait(timeout=4)

        self.wfile.write(b"0\r\n\r\n")


@contextmanager
def OwnedCatalog(*, mode: str = "normal", tls: ssl.SSLContext | None = None,
                 onAcceptedPost: Callable[[], None] | None = None,
                 ) -> Iterator[tuple[str, list[str]]]:
    """Run an owned literal loopback fixture bound to an OS-assigned port.

    Args:
        mode: Finite inert reply selection.
        tls: Optional synthetic TLS server context.
        onAcceptedPost: Optional in-process scope update invoked during a fixture request.

    Yields:
        Exact selected MCP endpoint and a method-only event log.
    """

    sample = cast(dict[str, Any], json.loads(_SNAPSHOT.read_bytes()))
    program = CatalogProgram(sample, mode, tls is not None, onAcceptedPost)

    with CatalogServer(("127.0.0.1", 0), CatalogHandler) as server:
        server.program = program

        if tls is not None:
            server.socket = tls.wrap_socket(server.socket, server_side=True)

        serving = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        serving.start()

        try:
            scheme = "https" if tls is not None else "http"

            yield f"{scheme}://127.0.0.1:{server.server_port}/catalog/mcp", program.methods

        finally:
            program.shutdown.set()
            server.shutdown()
            serving.join(timeout=2)


def ScopeFor(root: Path, endpoint: str, *, allowAddress: bool = True) -> ScopeSnapshot:
    """Write current synthetic scope consent for this exact URL and literal IP.

    Args:
        root: Isolated workspace root.
        endpoint: Exact chosen owned fixture URL.
        allowAddress: Include the distinct destination scope approval.

    Returns:
        Saved canonical scope state.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("MCP catalog"), "catalog")
    source = Target(TargetKind.URL, endpoint)
    destination = Target(TargetKind.IP, "127.0.0.1")
    targets = (source, destination) if allowAddress else (source,)

    return LocalScopeStore(root).Create(ScopeSnapshot(
        "catalog", "catalog",
        ScopeAuthorization(AuthorizationState.GRANTED, "actor:operator", "consent:catalog"),
        targets=targets, allow=targets,
    ))


def CatalogPolicy() -> ImpactPolicy:
    """Return an exact SAFE permit for the native MCP metadata capability.

    Returns:
        Minimal Workbench impact policy admitting the trusted adapter/capability pair.
    """

    return ImpactPolicy("catalog", permissions=(CapabilityPermission(
        MCP_METADATA_CAPABILITY.identifier, MCP_METADATA_CAPABILITY.adapter_id, ImpactLevel.SAFE,
    ),))


def RequireNoLookup(*arguments: object, **options: object) -> None:
    """Tripwire the collector's use of host discovery and ambient DNS.

    Args:
        arguments: Positional arguments of an unexpected lookup.
        options: Named arguments of an unexpected lookup.
    """

    pytest.fail("The literal MCP path attempted a hostname lookup")


@pytest.mark.parametrize("mode", ["hold-open", "close-delimited"])
def test_ApprovedOwnedCatalogMatchesTheOfflineSnapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Collect real qualified metadata over HTTP/1.1 and chunked/close-delimited framing.

    Args:
        tmp_path: Isolated workspace parent.
        monkeypatch: Owned DNS and proxy tripwire controls.
        mode: Keeper-open chunked SSE or bounded close-delimited JSON case.
    """

    with OwnedCatalog(mode=mode) as (endpoint, methods):
        root = tmp_path / "work"
        scope = ScopeFor(root, endpoint)
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setattr(socket, "getaddrinfo", RequireNoLookup)
        result = CollectMcpMetadataHttp(root, "catalog", endpoint, approved=True,
                                        policyProvider=CatalogPolicy)

    assert result.inventory == ParseMcpInventory(_SNAPSHOT.read_bytes()), (
        "Real wire collection differs from the independent checked-in catalog"
    )
    assert tuple(methods) == _EXPECTED, "Only exact initialization and list methods are allowed"
    assert result.protocolVersion == MCP_PROTOCOL_VERSION and not result.issues, (
        "The qualifying catalog should have completed its negotiated collection"
    )
    assert result.sourceReference == Target(TargetKind.URL, endpoint).Reference(), (
        "The collection lost the exact explicitly selected endpoint reference"
    )
    assert result.scopeRevision == scope.revision and result.scopeReference == scope.Reference(), (
        "The collection was not tied to its exact approved scope revision"
    )
    assert _SESSION not in repr(result), "Session material escaped in returned metadata"
    assert not any(path.is_file() for path in (root / "evidence").rglob("*")), (
        "The wire-only SDK unexpectedly retained evidence"
    )


@pytest.mark.parametrize(("mode", "stage", "reason"), [
    ("redirect", "initialize", "redirect"),
    ("duplicate", "initialize", "transport-failure"),
    ("oversized-header", "initialize", "transport-failure"),
    ("encoding", "initialize", "transport-failure"),
    ("ambiguous", "initialize", "transport-failure"),
    ("bad-chunk", "tools", "transport-failure"),
    ("incomplete-sse", "tools", "event-stream-ended"),
])
def test_MalformedAndRedirectResponsesStopTheWireCollection(
    tmp_path: Path, mode: str, stage: str, reason: str,
) -> None:
    """Refuse response framing and keep earlier pages when the failure is during pagination.

    Args:
        tmp_path: Isolated workspace parent.
        mode: Finite illustrative wire fault.
        stage: The failed MCP stage.
        reason: The fixed report classification.
    """

    with OwnedCatalog(mode=mode) as (endpoint, methods):
        root = tmp_path / "work"
        ScopeFor(root, endpoint)
        result = CollectMcpMetadataHttp(root, "catalog", endpoint, approved=True,
                                        policyProvider=CatalogPolicy)

    assert result.issues == (McpMetadataIssue(stage, reason),), (
        "The wire fault lost its fixed stage and classification"
    )
    expectedCount = 1 if stage == "initialize" else 4
    assert methods == list(_EXPECTED[:expectedCount]), (
        "The request sequence continued after failure"
    )

    if stage == "tools":
        assert result.inventory is not None, "A late fault discarded the accepted inventory"
        sections = cast(dict[str, Any], result.inventory["sections"])
        assert sections["tools"]["status"] == "incomplete", "Truncated tools were marked complete"
        assert len(sections["tools"]["items"]) == 1, "The first accepted page did not survive"


@pytest.mark.parametrize("mode", ["header-drip", "body-drip"])
def test_SlowProgressCannotRenewTheAbsoluteDeadline(tmp_path: Path, mode: str) -> None:
    """Enforce one hard monotonic deadline over actively trickling headers and payload.

    Args:
        tmp_path: Isolated workspace parent.
        mode: Fixture drips the header or the response body.
    """

    with OwnedCatalog(mode=mode) as (endpoint, methods):
        root = tmp_path / "work"
        ScopeFor(root, endpoint)
        start = monotonic()
        result = CollectMcpMetadataHttp(
            root, "catalog", endpoint, approved=True, policyProvider=CatalogPolicy,
            limits=McpMetadataLimits(requestTimeoutSeconds=0.2),
        )
        elapsed = monotonic() - start

    assert result.issues == (McpMetadataIssue("initialize", "timeout"),), (
        "Ongoing progress renewed the wire deadline"
    )
    assert elapsed < 1.5, "The owned slow-peer request did not return within its finite allowance"
    assert methods == ["initialize"], "The collector retried the timed-out POST"


def test_DeclaredBodyBoundIsAppliedBeforeAdmission(tmp_path: Path) -> None:
    """Refuse a declared body that exceeds the exact per-reply allowance.

    Args:
        tmp_path: Isolated workspace parent.
    """

    with OwnedCatalog() as (endpoint, methods):
        root = tmp_path / "work"
        ScopeFor(root, endpoint)
        result = CollectMcpMetadataHttp(
            root, "catalog", endpoint, approved=True, policyProvider=CatalogPolicy,
            limits=McpMetadataLimits(maxReplyBytes=32),
        )

    assert result.issues == (McpMetadataIssue("initialize", "size-limit"),), (
        "Declared oversized input reached metadata decoding"
    )
    assert methods == ["initialize"], "The client retried after an oversized response"


@pytest.mark.parametrize("case", ["approval", "policy", "scope", "impact", "bearer-http", "race"])
def test_EachMissingOrChangedAuthorityPreventsAPost(tmp_path: Path, case: str) -> None:
    """Deny unticked approval, wrong scope, policy and insecure credentials before transmission.

    Args:
        tmp_path: Isolated workspace parent.
        case: The one authority boundary to invalidate.
    """

    with OwnedCatalog() as (endpoint, methods):
        root = tmp_path / "work"
        ScopeFor(root, endpoint, allowAddress=case != "scope")
        policy = CatalogPolicy()
        calls: list[None] = []

        def ReadCurrentPolicy() -> ImpactPolicy:
            """Return a synthetic exact policy, optionally changed at the final send check.

            Returns:
                The current bounded policy variant for the selected case.
            """

            calls.append(None)

            if case == "policy":
                return replace(policy, permissions=(replace(
                    policy.permissions[0], adapter_id="fixture.other-provider",
                ),))

            if case == "impact":
                return replace(policy, maximum_impact=ImpactLevel.PASSIVE)

            if case == "race" and len(calls) >= 4:
                return replace(policy, revision=policy.revision + 1)

            return policy

        with pytest.raises(McpMetadataDenied) as error:
            CollectMcpMetadataHttp(
                root, "catalog", endpoint, approved=case != "approval",
                policyProvider=ReadCurrentPolicy,
                credentialProvider=(lambda: _TOKEN) if case == "bearer-http" else None,
            )

    assert not methods, "The failed or changed authority allowed a JSON-RPC POST"
    assert error.value.__cause__ is None and error.value.__context__ is None, (
        "The public denial retained an internal credential-sensitive cause"
    )
    frames = [frame for frame, _line in walk_tb(error.value.__traceback__)
              if frame.f_globals.get("__name__") == mcp_metadata_http.__name__]
    assert [frame.f_code.co_name for frame in frames] == ["CollectMcpMetadataHttp"], (
        "The denial escaped with session-owning transport frames"
    )
    assert "credentialProvider" not in frames[0].f_locals, (
        "The outward error retained the trusted resolver"
    )


def test_ScopeRevocationPreventsTheSecondRequest(tmp_path: Path) -> None:
    """Read current scope before each send instead of reusing the initial permission.

    Args:
        tmp_path: Isolated workspace parent.
    """

    root = tmp_path / "work"

    def Revoke() -> None:
        """Revoke the fixture's explicit scope after the first observed POST."""

        store = LocalScopeStore(root)
        scope = store.Open("catalog")
        store.Save(replace(scope, authorization=ScopeAuthorization(AuthorizationState.REVOKED)))

    with OwnedCatalog(onAcceptedPost=Revoke) as (endpoint, methods):
        ScopeFor(root, endpoint)

        with pytest.raises(McpMetadataDenied):
            CollectMcpMetadataHttp(
                root, "catalog", endpoint, approved=True, policyProvider=CatalogPolicy,
            )

    assert methods == ["initialize"], "The collector ignored a newer revoked scope"


def BuildTls(tmpPath: Path) -> tuple[ssl.SSLContext, Path]:
    """Create one short-lived synthetic IP certificate for the owned TLS fixture.

    Args:
        tmpPath: Isolated directory owned by this test.

    Returns:
        Loopback-only server context and the fixture certificate for explicit test trust.
    """

    openssl = shutil.which("openssl")

    if openssl is None:
        pytest.skip("Owned TLS fixtures require the platform OpenSSL executable")

    cert = tmpPath / "fixture-cert.pem"
    key = tmpPath / "fixture-key.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=15,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    return context, cert


@pytest.mark.parametrize("mode", ["normal", "untrusted", "body-echo", "session-echo"])
def test_TlsBearerIsVerifiedMemoryOnlyAndNeverRetained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Exercise real TLS trust, authorization, escaped body echoes and session-header echoes.

    Args:
        tmp_path: Isolated certificate and workspace parent.
        monkeypatch: Process-local fixture CA and TLS diagnostic environment.
        mode: Trusted TLS and fixture authentication, trust refusal or secret echo.
    """

    tls, cert = BuildTls(tmp_path)
    keyLog = tmp_path / "unwanted-ssl-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keyLog))

    if mode != "untrusted":
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))

    with OwnedCatalog(mode=mode, tls=tls) as (endpoint, methods):
        root = tmp_path / "work"
        ScopeFor(root, endpoint)
        result = CollectMcpMetadataHttp(
            root, "catalog", endpoint, approved=True, policyProvider=CatalogPolicy,
            credentialProvider=lambda: _TOKEN,
        )

    if mode == "normal":
        assert tuple(methods) == _EXPECTED and not result.issues, (
            "The qualified TLS catalog did not complete with the expected bearer"
        )
        assert result.inventory == ParseMcpInventory(_SNAPSHOT.read_bytes()), (
            "Verified HTTPS changed otherwise identical declaration metadata"
        )

    else:
        assert result.issues == (McpMetadataIssue("initialize", "transport-failure"),), (
            "TLS trust failure or authorization echo was not refused"
        )
        assert result.inventory is None, "A failed TLS or bearer admission returned metadata"
        expected = [] if mode == "untrusted" else ["initialize"]
        assert methods == expected, "The client sent application data after a TLS or echo failure"

    assert not keyLog.exists(), "An ambient TLS settings variable captured session keys"
    assert _TOKEN not in repr(result) and _SESSION not in repr(result), (
        "The collected result exposed bearer or session material"
    )
    assert not any(path.is_file() for path in (root / "evidence").rglob("*")), (
        "The wire exchange persisted original response or session material"
    )


def test_TlsCatalogEntersTheSharedModelAndReviewsAgainstAnOfflineBaseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve one catalog identity across an approved offline baseline and a real TLS import.

    Args:
        tmp_path: Isolated certificate and workspace parent.
        monkeypatch: Install the process-local trust anchor for the owned TLS catalog.
    """

    tls, cert = BuildTls(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    root = tmp_path / "work"

    with OwnedCatalog(tls=tls) as (endpoint, methods):
        scope = ScopeFor(root, endpoint)
        model = LocalModelStore(root)
        initial = model.Create()
        offline = ImportMcpInventory(
            model, _SNAPSHOT, serverKey="catalog", scopeId=scope.scope_id,
            consent=ArtifactReadConsent("actor:operator", "consent:owned-file"),
            observedAt="2026-11-26T12:30:00+00:00", expectedRevision=initial.revision,
        )
        baseline = ApproveMcpBaseline(
            model, serverReference=offline.serverReference,
            snapshotReference=offline.snapshotReference,
            actorReference="actor:operator", approvalReference="approval:catalog",
            approvedAt="2026-11-26T13:30:00+00:00", expectedRevision=offline.state.revision,
        )
        result, imported = CollectAndImportMcpMetadata(
            model, endpoint, serverKey="catalog", scopeId=scope.scope_id, approved=True,
            expectedRevision=baseline.state.revision, policyProvider=CatalogPolicy,
            credentialProvider=lambda: _TOKEN,
        )

    assert tuple(methods) == _EXPECTED, "The real catalog returned an unexpected request sequence"
    assert imported is not None and not result.issues, "The approved TLS catalog was not imported"
    assert imported.serverReference == offline.serverReference, "MCP server identity changed"
    assert imported.snapshotReference != offline.snapshotReference, "Source attribution collapsed"
    assert model.Open() == imported.state, "The imported model revision was not committed"

    store = LocalEvidenceStore(root / "evidence")
    receipt = store.Read(store.Get(imported.evidence.evidence_id).reference)
    payload = json.loads(receipt)
    assert payload["inventory"] == ParseMcpInventory(_SNAPSHOT.read_bytes()), (
        "The stored declarations differ from the approved offline catalog"
    )
    assert payload["acquisition"] == {
        "source_reference": result.sourceReference, "scope_reference": scope.Reference(),
        "scope_revision": scope.revision, "protocol_version": MCP_PROTOCOL_VERSION, "issues": [],
        "actor_ref": "actor:operator", "operator_receipt_reference": "consent:catalog",
    }, "The receipt lost its exact authorized acquisition"
    observation = next(
        item for item in imported.state.observations
        if item.Reference() == imported.snapshotReference
    )
    acquisition = json.loads(CanonicalModelJson(observation.attributes["acquisition"]))
    assert payload["acquisition"] == acquisition, (
        "Evidence and the shared model recorded different attribution"
    )
    retained = receipt + CanonicalModelJson(observation.attributes)
    assert all(value.encode() not in retained for value in (endpoint, _TOKEN, _SESSION)), (
        "Endpoint, bearer, or session material escaped into retained MCP evidence"
    )
    review = ReviewMcpDrift(
        model, serverReference=imported.serverReference,
        snapshotReference=imported.snapshotReference, expectedRevision=imported.state.revision,
    )
    assert review.status == "unchanged" and not review.changes, (
        "Equal declarations from the independently retained sources produced drift"
    )
