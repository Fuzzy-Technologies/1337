# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise wire and Workbench admission with bounded scripted sockets and no connections."""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from time import monotonic
from typing import cast
from unittest.mock import Mock

import pytest

from fuzzy1337 import mcp_metadata_http
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.executors import CapabilityDescriptor
from fuzzy1337.mcp_metadata import (
    MCP_PROTOCOL_VERSION,
    McpMetadataDenied,
    McpMetadataFailure,
    McpMetadataIssue,
    McpMetadataLimits,
    McpMetadataPost,
    McpMetadataReply,
    McpMetadataSizeLimit,
    ParseReply,
)
from fuzzy1337.mcp_metadata_http import (
    MCP_METADATA_CAPABILITY,
    CheckPost,
    CollectMcpMetadataHttp,
    McpHttpWireError,
    ReadReply,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.policy import (
    CapabilityPermission,
    ImpactPolicy,
    PolicyContext,
    PolicyDenialReason,
    PolicyDeniedError,
    PolicyEngine,
    UtcNow,
)
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

_BEARER = "synthetic-credential-2236"
_PORT = 8391
_HOST = "::1"
_ENDPOINT = "https://[::1]:8391/mcp"
_INIT = {
    "protocolVersion": MCP_PROTOCOL_VERSION, "serverInfo": {"name": "Catalog", "version": "1"},
    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
}
_HEADERS = (
    ("Content-Type", "application/json"), ("Accept-Encoding", "identity"),
    ("Accept", "application/json, text/event-stream"),
    ("MCP-Protocol-Version", MCP_PROTOCOL_VERSION),
)


def MemorySocket(*pieces: bytes, peer: str = _HOST) -> Mock:
    """Create a socket-shaped mock that enforces each finite receive allowance.

    Args:
        pieces: Ordered synthetic TCP fragments to return under each receive bound.
        peer: Claimed literal kernel peer coordinate for this scripted socket.

    Returns:
        A mock with deterministic receive and no actual socket capability.
    """

    incoming = list(pieces)

    def Receive(maximum: int) -> bytes:
        """Return no more than requested from the next finite scripted segment.

        Args:
            maximum: The caller's immediate positive receive ceiling.

        Returns:
            A bounded scripted fragment or EOF when the script is exhausted.
        """

        assert maximum > 0, "The collector attempted an empty or negative receive reservation"

        if not incoming:
            return b""

        piece = incoming[0]
        result = piece[:maximum]

        if len(result) == len(piece):
            incoming.pop(0)

        else:
            incoming[0] = piece[maximum:]

        return result

    connection = Mock(spec=socket.socket)
    connection.getpeername.return_value = (peer, _PORT, 0, 0)
    connection.recv.side_effect = Receive

    return connection


def Wire(body: bytes, *fields: bytes, status: bytes = b"200 OK", fixed: bool = True) -> bytes:
    """Frame a synthetic response without relying on the production HTTP decoder.

    Args:
        body: Exact payload or preframed chunk stream.
        fields: Explicit response headers including CRLF termination only as joined here.
        status: Wire status text.
        fixed: Whether to append a canonical declared length.

    Returns:
        Synthetic HTTP/1.1 header and body bytes.
    """

    if fixed:
        fields = (*fields, b"Content-Length: %d" % len(body))

    return b"HTTP/1.1 " + status + b"\r\n" + b"\r\n".join((*fields, b"", body))


def JsonReply(requestId: int, result: object) -> bytes:
    """Encode one synthetic JSON-RPC response body.

    Args:
        requestId: Exact mocked response identifier.
        result: Declared synthetic metadata.

    Returns:
        Canonical UTF-8 response bytes.
    """

    return CanonicalModelJson({"jsonrpc": "2.0", "id": requestId, "result": result})


def Authority(root: Path) -> ImpactPolicy:
    """Provision one synthetic workspace and exact scoped HTTPS URL and peer.

    Args:
        root: Temporary workspace directory.

    Returns:
        Exact typed operator policy for that single metadata capability.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("catalog"), "catalog")
    targets = (Target(TargetKind.URL, _ENDPOINT), Target(TargetKind.IP, _HOST))
    LocalScopeStore(root).Create(ScopeSnapshot(
        "catalog", "catalog",
        ScopeAuthorization(AuthorizationState.GRANTED, "actor:fixture", "consent:fixture"),
        targets=targets, allow=targets,
    ))

    return ImpactPolicy("catalog", permissions=(CapabilityPermission(
        MCP_METADATA_CAPABILITY.identifier, MCP_METADATA_CAPABILITY.adapter_id, ImpactLevel.SAFE,
    ),))


@pytest.mark.parametrize("message", [
    {"method": "tools/call", "id": 2},
    {"method": "resources/read", "id": 2},
    {"method": "prompts/get", "id": 2},
    {"method": "ping", "id": 2},
    {"method": "tools/list", "id": 2, "params": {"uri": "file:///unread"}},
    {"method": "tools/list", "id": 2, "params": {"cursor": False}},
    {"method": "tools/list", "id": True},
    {"method": "initialize", "id": 1, "params": {"capabilities": {"sampling": {}}}},
    {"method": "notifications/initialized", "id": 2},
])
def test_PostAdmissionRejectsEverythingOutsideTheMetadataProfile(
    message: dict[str, object],
) -> None:
    """Refuse unapproved procedures, client capabilities, IDs, and method parameters.

    Args:
        message: Synthetic request shape outside the fixed read-only profile.
    """

    body = CanonicalModelJson({"jsonrpc": "2.0", **message})

    with pytest.raises(McpHttpWireError):
        CheckPost(McpMetadataPost(_HEADERS, body))


@pytest.mark.parametrize("response", [
    b"",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nx-obsolete-fold: hello\r\n injected\r\n\r\n",
    Wire(b"x", b"Content-Length: nope", fixed=False),
    Wire(b"x", b"Content-Length: 2", fixed=False),
    Wire(b"x", b"Content-Type: text/plain", b"Content-Type: application/json"),
    Wire(b"x", b"Content-Encoding: br"),
    Wire(b"x", b"Transfer-Encoding: chunked"),
    Wire(b"1;charset=utf-8\r\nx\r\n", b"Transfer-Encoding: chunked", fixed=False),
    Wire(b"1\r\nxXX", b"Transfer-Encoding: chunked", fixed=False),
    Wire(b"0\r\nX-Extra: forbidden\r\n\r\n", b"Transfer-Encoding: chunked", fixed=False),
    Wire(b"ignored", status=b"202 Accepted"),
])
def test_WireReaderRejectsIncompleteAmbiguousAndUnsupportedFraming(response: bytes) -> None:
    """Verify malformed HTTP framing cannot become a complete reply.

    Args:
        response: Finite inert bytes representing one unsupported framing.
    """

    peer = cast(socket.socket, MemorySocket(response))

    with pytest.raises((McpHttpWireError, McpMetadataSizeLimit)):
        ReadReply(peer, monotonic() + 1, 16384, 1, None)


@pytest.mark.parametrize("response", [
    Wire(b"over limit"),
    Wire(b"over limit", b"Content-Type: application/json", fixed=False),
    Wire(b"10\r\n", b"Transfer-Encoding: chunked", fixed=False),
])
def test_WireReaderStopsAtEachLengthOverrun(response: bytes) -> None:
    """Bound body allocation for declared, unframed and chunked lengths.

    Args:
        response: Synthetic oversized length or payload.
    """

    peer = cast(socket.socket, MemorySocket(response))

    with pytest.raises(McpMetadataSizeLimit):
        ReadReply(peer, monotonic() + 1, 3, 1, None)


def TestSocketFactory(
    monkeypatch: pytest.MonkeyPatch, *scripts: Mock,
) -> tuple[list[Mock], Mock]:
    """Inject scripted kernel peers and record requested socket family and TLS identity.

    Args:
        monkeypatch: Scoped module substitution with no actual socket access.
        scripts: Ordered mock connections for the expected POST sequence.

    Returns:
        Remaining scripted connections and a TLS identity-verifying mock context.
    """

    remaining = list(scripts)
    context = Mock()
    context.wrap_socket.side_effect = lambda connection, **_options: connection

    def OpenSocket(family: int, kind: int) -> Mock:
        """Provide exactly the next IPv6 stream socket from the unit script.

        Args:
            family: Required address family for the selected literal URL.
            kind: Required stream socket type.

        Returns:
            Next socket-shaped mock in sequence, never a kernel socket.
        """

        assert (family, kind) == (socket.AF_INET6, socket.SOCK_STREAM), (
            "The provider selected a different literal family or transport"
        )
        assert remaining, "The provider attempted a connection beyond the allowed sequence"

        return remaining.pop(0)

    monkeypatch.setattr(socket, "socket", OpenSocket)
    monkeypatch.setattr(mcp_metadata_http, "VerifiedTls", lambda: context)

    return remaining, context


def test_PreviouslyReadSseTailConsumesTheNextPostBudget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Charge the containing chunk after a terminal SSE event against later POSTs.

    Args:
        tmp_path: Isolated current Workbench authority.
        monkeypatch: Scoped mocks for sockets and TLS.
    """

    root = tmp_path / "work"
    policy = Authority(root)
    initial = JsonReply(1, _INIT)
    payload = (
        b"data: " + JsonReply(2, {"tools": []}) + b"\r\n\r\n" + b":padding " * 120 + b"\xc3"
    )
    session = b"MCP-Session-Id: synthetic-session"
    first = MemorySocket(Wire(initial, b"Content-Type: application/json", session))
    ack = MemorySocket(Wire(b"", session, status=b"202 Accepted"))
    other = JsonReply(3, {"resources": []})
    stream = MemorySocket(Wire(
        b"%x\r\n" % len(payload) + payload + b"\r\n",
        b"Transfer-Encoding: chunked", b"Content-Type: text/event-stream", fixed=False,
    ))
    resource = MemorySocket(Wire(other, b"Content-Type: application/json"))
    remaining, tls = TestSocketFactory(monkeypatch, first, ack, stream, resource)
    bounds = McpMetadataLimits(
        maxReplyBytes=len(payload), maxTotalReplyBytes=len(initial) + len(payload) + 5,
    )
    result = CollectMcpMetadataHttp(
        root, "catalog", _ENDPOINT, approved=True, policyProvider=lambda: policy,
        credentialProvider=lambda: _BEARER, limits=bounds,
    )

    assert result.issues == (McpMetadataIssue("resources", "size-limit"),), (
        "Discarded tail bytes became an extra budget for the next POST"
    )
    assert not remaining and result.inventory is not None, (
        "The scripted POST sequence or earlier accepted inventory was lost"
    )
    assert tls.wrap_socket.call_count == 4, "Every scoped request must use its own verified TLS"
    assert tls.wrap_socket.call_args.kwargs["server_hostname"] == _HOST, (
        "TLS did not verify the selected literal certificate identity"
    )
    firstRequest = first.sendall.call_args.args[0]
    assert firstRequest.startswith(b"POST /mcp HTTP/1.1\r\nHost: [::1]:8391\r\n"), (
        "The provider rewrote the selected HTTP authority"
    )
    assert b"Authorization: Bearer " + _BEARER.encode("ascii") in firstRequest, (
        "The scoped HTTPS provider lost its explicitly supplied authorization header"
    )
    assert _BEARER not in repr(result), "Returned metadata exposed the known credential"


@pytest.mark.parametrize(("session", "reason"), [
    (b"MCP-Session-Id: changed", "malformed-session"),
    (b"MCP-Session-Id: ", "malformed-session"),
    (b"MCP-Session-Id: " + _BEARER.encode("ascii"), "transport-failure"),
])
def test_InitializedAcknowledgementChecksItsSessionMaterial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: bytes, reason: str,
) -> None:
    """Reject malformed, changed, or credential-echoing headers on the 202 acknowledgement.

    Args:
        tmp_path: Isolated current Workbench authority.
        monkeypatch: Scoped mocks for actual sockets and TLS.
        session: Header supplied on the acknowledgement.
        reason: Expected fixed redacted classification.
    """

    root = tmp_path / "work"
    policy = Authority(root)
    initial = MemorySocket(Wire(
        JsonReply(1, _INIT), b"Content-Type: application/json", b"MCP-Session-Id: initial",
    ))
    ack = MemorySocket(Wire(b"", session, status=b"202 Accepted"))
    TestSocketFactory(monkeypatch, initial, ack)
    result = CollectMcpMetadataHttp(
        root, "catalog", _ENDPOINT, approved=True, policyProvider=lambda: policy,
        credentialProvider=lambda: _BEARER,
    )
    assert result.issues == (McpMetadataIssue("initialized", reason),), (
        "The collector bypassed session inspection on the acknowledgement"
    )
    assert result.inventory is not None and _BEARER not in repr(result), (
        "The failed acknowledgement discarded the already accepted redacted identity"
    )


@pytest.mark.parametrize("case", ["peer", "resolver", "permission", "policy-change"])
def test_UnapprovedCurrentPeerPolicyOrCredentialsCannotSend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str,
) -> None:
    """Require exact policy, pinned peer and approved credential before a POST.

    Args:
        tmp_path: Isolated current Workbench authority.
        monkeypatch: Scoped socket and TLS mock substitutions.
        case: Selected failed authorization condition.
    """

    root = tmp_path / "work"
    policy = Authority(root)
    peer = MemorySocket(peer="::2" if case == "peer" else _HOST)
    TestSocketFactory(monkeypatch, peer)
    reads: list[None] = []

    def CurrentPolicy() -> ImpactPolicy:
        """Return the current policy snapshot for the selected authority trial.

        Returns:
            Disallowed/changed policy, or exact current approved capability.
        """

        reads.append(None)

        if case == "permission":
            return replace(policy, permissions=())

        if case == "policy-change" and len(reads) >= 4:
            return replace(policy, revision=policy.revision + 1)

        return policy

    def UnavailableCredential() -> str:
        """Raise a synthetic secret-bearing failure from the trusted resolver.

        Returns:
            No value; a resolver failure aborts authorization.
        """

        raise RuntimeError(_BEARER)

    resolver: Callable[[], str | None] | None = (
        UnavailableCredential if case == "resolver" else None
    )

    with pytest.raises(McpMetadataDenied) as error:
        CollectMcpMetadataHttp(
            root, "catalog", _ENDPOINT, approved=True,
            policyProvider=CurrentPolicy, credentialProvider=resolver,
        )

    peer.sendall.assert_not_called()
    assert _BEARER not in str(error.value) and error.value.__context__ is None, (
        "An underlying provider failure escaped in the public denial"
    )


@pytest.mark.parametrize(("observed", "reason"), [(0, "malformed"), (91, "size-limit")])
def test_TheReplyCannotUnderreportOrExceedObservedPayload(observed: int, reason: str) -> None:
    """Reject invented or excessive observed byte counts before the parser uses reply data.

    Args:
        observed: Incorrect or excessive payload count supplied by the exchange.
        reason: Expected fixed protocol classification.
    """

    reply = McpMetadataReply(200, "application/json", b"{}", observedBodyBytes=observed)

    with pytest.raises(McpMetadataFailure, match=reason):
        ParseReply(reply, 1, 90)


@pytest.mark.parametrize(("capability", "reason"), [
    (replace(MCP_METADATA_CAPABILITY, maximum_impact=ImpactLevel.STANDARD),
     PolicyDenialReason.IMPACT_DENIED),
    (replace(MCP_METADATA_CAPABILITY, required_privileges=("fixture.ungranted",)),
     PolicyDenialReason.PRIVILEGE_DENIED),
])
def test_InProcessPolicyCannotRaiseImpactOrAddPrivilege(
    tmp_path: Path, capability: CapabilityDescriptor, reason: PolicyDenialReason,
) -> None:
    """Retain the existing impact and privilege checks at an in-process authority boundary.

    Args:
        tmp_path: Isolated current Workbench authority.
        capability: Descriptor with a disallowed impact or privilege requirement.
        reason: Shared policy denial reason expected for that descriptor.
    """

    root = tmp_path / "work"
    policy = Authority(root)
    scope = LocalScopeStore(root).Open("catalog")
    context = PolicyContext(
        scope, policy, Target(TargetKind.URL, _ENDPOINT), (Target(TargetKind.IP, _HOST),),
    )
    with pytest.raises(PolicyDeniedError) as error:
        PolicyEngine().CheckSafeCapability(capability, context, at=UtcNow())

    assert error.value.reason == reason, "Shared authority admitted an unapproved capability"
