# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the scoped MCP metadata contract against inert Streamable HTTP transcripts."""

from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from traceback import walk_tb
from typing import Any, cast

import pytest

from fuzzy1337 import mcp_metadata
from fuzzy1337.mcp_inventory import ParseMcpInventory
from fuzzy1337.mcp_metadata import (
    MCP_PROTOCOL_VERSION,
    CollectMcpMetadata,
    McpMetadataDenied,
    McpMetadataIssue,
    McpMetadataLimits,
    McpMetadataPost,
    McpMetadataReply,
    McpMetadataResult,
    McpMetadataSizeLimit,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    TargetKind,
)
from fuzzy1337.scope import Target as ScopeTarget
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

_FIXTURE = Path(__file__).parent / "fixtures" / "mcp.inventory.v1.json"
_SOURCE = ScopeTarget(TargetKind.URL, "http://127.0.0.1:8731/catalog/mcp")
_ADDRESS = ScopeTarget(TargetKind.IP, "127.0.0.1")
_SESSION = "synthetic-session-19951230"
_SECRET = "synthetic-auth-material-19421231"
_CURSOR = "synthetic-opaque-cursor-17520914"


@dataclass(slots=True)
class ScriptedExchange:
    """Act as the peer, verify full requests and log only method names and budget facts."""

    steps: list[tuple[dict[str, object], McpMetadataReply | Exception]]
    session: str | None = field(default=None, repr=False)
    afterPost: Callable[[], None] | None = None
    methods: list[str] = field(default_factory=list)
    budgets: list[tuple[float, int]] = field(default_factory=list)

    def Post(self, target: ScopeTarget, post: McpMetadataPost, *, timeoutSeconds: float,
             maxReplyBytes: int) -> McpMetadataReply:
        """Verify exact destination/framing and consume the next scripted peer reply.

        Args:
            target: The exact scoped URL.
            post: The collector-produced headers and body, held only during this call.
            timeoutSeconds: Supplied remaining per-POST and collection deadline.
            maxReplyBytes: Supplied remaining per-POST and cumulative response-body allowance.

        Returns:
            In-memory fixture reply with status, selected headers and body.
        """

        assert target == _SOURCE, "The peer received a request for a different endpoint"
        assert self.steps, "The collector exceeded the scripted request sequence"
        expected, reply = self.steps.pop(0)
        method = str(expected["method"])
        assert json.loads(post.body) == {"jsonrpc": "2.0", **expected}, (
            "The peer received an unexpected method, ID, or parameter"
        )
        headers = {
            "Accept": "application/json, text/event-stream", "Accept-Encoding": "identity",
            "Content-Type": "application/json",
        }

        if method != "initialize":
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION

            if self.session is not None:
                headers["MCP-Session-Id"] = self.session

        assert dict(post.headers) == headers, (
            "The peer received wrong media, session, or revision headers"
        )
        assert _SESSION not in repr(post) and _CURSOR not in repr(post), (
            "Transient POST material appeared in its diagnostic representation"
        )
        self.methods.append(method)
        self.budgets.append((timeoutSeconds, maxReplyBytes))

        if self.afterPost is not None:
            self.afterPost()

        if isinstance(reply, Exception):
            raise reply

        return reply


def CreateScope(path: Path, *, registerAddress: bool = True) -> ScopeSnapshot:
    """Create one workspace with current granted membership at the fixture endpoint.

    Args:
        path: Physical test workspace directory.
        registerAddress: Whether the fixture's literal destination is independently admitted.

    Returns:
        The created scope with exact URL and, when requested, literal IP membership.
    """

    LocalWorkspaceStore(path).Create(WorkspaceConfiguration("MCP contract"), "catalog")
    targets = (_SOURCE, _ADDRESS) if registerAddress else (_SOURCE,)

    return LocalScopeStore(path).Create(ScopeSnapshot(
        "fixture", "catalog",
        ScopeAuthorization(AuthorizationState.GRANTED, "actor:operator", "consent:owned-loopback"),
        targets=targets, allow=targets,
    ))


def InitializeRequest() -> dict[str, object]:
    """Return the exact request proving the collector offers no client execution capabilities.

    Returns:
        The first expected request, excluding the common JSON-RPC version field.
    """

    return {"id": 1, "method": "initialize", "params": {
        "protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "1337-metadata", "version": "1"},
    }}


def ReadFixture() -> dict[str, Any]:
    """Load the offline catalog declaration that serves as the differential oracle.

    Returns:
        A fresh decoded catalog fixture, which tests may intentionally modify in memory.
    """

    return cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))


def Initialization(sample: dict[str, Any], *, capabilities: dict[str, object] | None = None,
                   version: str = MCP_PROTOCOL_VERSION) -> dict[str, object]:
    """Build an InitializeResult independently of the collector's projection.

    Args:
        sample: Checked-in offline declaration with server, instructions and capabilities.
        capabilities: Optional source declaration map overriding the checked-in fixture.
        version: Advertised protocol revision for negotiation tests.

    Returns:
        A wire InitializeResult including a service link that must never be followed.
    """

    return {
        "protocolVersion": version,
        "serverInfo": {
            "name": sample["server"]["name"], "version": sample["server"]["version"],
            "websiteUrl": "https://example.invalid/never-fetched",
        },
        "instructions": sample["instructions"],
        "capabilities": {
            item["name"]: item["declaration"] for item in sample["capabilities"]["items"]
        } if capabilities is None else capabilities,
    }


def RpcReply(requestId: int, result: object, *, session: str | None = None) -> McpMetadataReply:
    """Frame one fixture result as Streamable HTTP JSON.

    Args:
        requestId: Peer response ID, normally matched to the pending request.
        result: The untrusted synthetic result payload.
        session: Optional transient fixture session header.

    Returns:
        An HTTP JSON response over the scripted exchange.
    """

    body = CanonicalModelJson({"jsonrpc": "2.0", "id": requestId, "result": result})

    return McpMetadataReply(200, "application/json", body, session)


def CatalogExchange(sample: dict[str, Any], *, cursor: str = _CURSOR) -> ScriptedExchange:
    """Build the checked-in catalog as a complete six-method scripted MCP session.

    Args:
        sample: The checked-in offline catalog fixture.
        cursor: Opaque server pagination token returned and replayed as-is.

    Returns:
        A fresh peer logging only request methods and supplied budgets.
    """

    tools = sample["tools"]["items"]
    secondPage = RpcReply(3, {"tools": tools[1:]})
    notification = b'{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}'
    peerRequest = b'{"jsonrpc":"2.0","id":"peer-1","method":"sampling/createMessage"}'
    stream = (
        b"\xef\xbb\xbf: stream comment\r\nid: first-event\r\ndata:\r\n\r\n"
        b"event: message\rdata: " + notification + b"\r\r"
        b"data: " + peerRequest + b"\n\n"
        b"data: " + secondPage.body.replace(b',"jsonrpc"', b',\ndata: "jsonrpc"') + b"\n\n"
    )

    return ScriptedExchange([
        (InitializeRequest(), RpcReply(1, Initialization(sample), session=_SESSION)),
        ({"method": "notifications/initialized"}, McpMetadataReply(202)),
        ({"id": 2, "method": "tools/list"},
         RpcReply(2, {"tools": tools[:1], "nextCursor": cursor})),
        ({"id": 3, "method": "tools/list", "params": {"cursor": cursor}},
         McpMetadataReply(200, "Text/Event-Stream; charset=UTF-8", stream)),
        ({"id": 4, "method": "resources/list"},
         RpcReply(4, {"resources": sample["resources"]["items"]})),
        ({"id": 5, "method": "resources/templates/list"},
         RpcReply(5, {"resourceTemplates": sample["resource_templates"]["items"]})),
        ({"id": 6, "method": "prompts/list"},
         RpcReply(6, {"prompts": sample["prompts"]["items"]})),
    ], session=_SESSION)


def Collect(path: Path, exchange: ScriptedExchange | None = None,
            limits: McpMetadataLimits = McpMetadataLimits()) -> McpMetadataResult:
    """Call the real SDK with the fixture's explicit workspace, scope and endpoint.

    Args:
        path: Existing synthetic Workbench workspace.
        exchange: Scripted peer, or no exchange to exercise fail-closed behavior.
        limits: Explicit bounded collection limits.

    Returns:
        Redacted SDK result with source and completeness state.
    """

    return CollectMcpMetadata(
        path, "fixture", _SOURCE.value, approved=True, exchange=exchange, limits=limits,
    )


def RefuseExternalWork(*arguments: object, **options: object) -> None:
    """Tripwire network or process I/O during the scripted protocol test.

    Args:
        arguments: Positional arguments of the forbidden operation.
        options: Named arguments of the forbidden operation.
    """

    pytest.fail("MCP declaration protocol attempted network or process I/O")


def Section(result: McpMetadataResult, name: str) -> dict[str, Any]:
    """Select one normalized section from an established result for assertions.

    Args:
        result: Collection result expected to have accepted initialization.
        name: Canonical offline profile section identifier.

    Returns:
        Section status and redacted declaration items.
    """

    assert result.inventory is not None, (
        "This fixture must negotiate an inventory before reading a section"
    )

    return cast(dict[str, dict[str, Any]], result.inventory["sections"])[name]


@pytest.mark.parametrize("cursor", [_CURSOR, ""])
def test_ScriptedCatalogMatchesOfflineInventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cursor: str,
) -> None:
    """Prove fixture parity, source binding, bounded calls and metadata-only method usage.

    Args:
        tmp_path: Isolated local workspace.
        monkeypatch: Process and network tripwire controls.
        cursor: Opaque cursor chosen by the peer, including the empty string.
    """

    scope = CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture(), cursor=cursor)
    monkeypatch.setattr(socket, "socket", RefuseExternalWork)
    monkeypatch.setattr(socket, "getaddrinfo", RefuseExternalWork)
    monkeypatch.setattr(subprocess, "Popen", RefuseExternalWork)
    result = Collect(tmp_path / "work", peer)
    assert result.inventory == ParseMcpInventory(_FIXTURE.read_bytes()), (
        "The wire collection and independent offline snapshot differ"
    )
    assert result.sourceReference == _SOURCE.Reference(), (
        "The result lost the exact endpoint identity"
    )
    assert result.scopeReference == scope.Reference() and result.scopeRevision == scope.revision, (
        "The result lost the specific scope authority snapshot"
    )
    assert result.protocolVersion == MCP_PROTOCOL_VERSION and not result.issues, (
        "A complete catalog should have the agreed revision and no diagnostics"
    )
    assert peer.methods == [
        "initialize", "notifications/initialized", "tools/list", "tools/list", "resources/list",
        "resources/templates/list", "prompts/list",
    ], "Observed methods must be limited to the expected declaration workflow"
    assert not peer.steps, "The peer did not receive all expected declaration requests"
    assert all(0 < timeout <= 3 and size == 65536 for timeout, size in peer.budgets), (
        "An exchange did not receive the expected request budget"
    )
    assert not any(path.is_file() for path in (tmp_path / "work" / "evidence").rglob("*")), (
        "Collection persisted response material as evidence"
    )
    assert not any(token in repr(result) for token in (_SESSION, _CURSOR)), (
        "Session or cursor material appeared in the result"
    )


@pytest.mark.parametrize(("reply", "reason"), [
    (McpMetadataReply(302, body=b"https://example.invalid/sensitive-redirect"), "redirect"),
    (McpMetadataReply(401, body=b"Sensitive error"), "http-status"),
    (McpMetadataReply(200, "text/html", b"Sensitive error"), "unsupported-transport"),
    (McpMetadataReply(200, "application/json\r\n; charset=utf-8"), "unsupported-transport"),
    (McpMetadataReply(200), "unsupported-transport"),
    (McpMetadataReply(200, "text/event-stream", b"event: endpoint\ndata: /other\n\n"),
     "unsupported-transport"),
    (McpMetadataReply(200, "text/event-stream", b"data: \xff\n\n"), "malformed"),
    (McpMetadataReply(200, "text/event-stream", b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n'),
     "event-stream-ended"),
    (McpMetadataReply(200, "text/event-stream",
                      b'data: {"jsonrpc":"2.0","method":"sample","extra":true}\n\n'), "malformed"),
    (McpMetadataReply(200, "application/json", b'{"jsonrpc":"2.0","id":1,"result":{}, "id":1}'),
     "malformed"),
    (McpMetadataReply(200, "application/json", b'{"jsonrpc":"2.0","id":1,"result":[]}'),
     "malformed"),
    (McpMetadataReply(200, "application/json",
                      b'{"jsonrpc":"2.0","id":1,"error":{"message":"sensitive"}}'), "rpc-error"),
    (RpcReply(27, {}), "malformed"),
    (RpcReply(1, {"protocolVersion": MCP_PROTOCOL_VERSION}), "malformed"),
    (RpcReply(1, Initialization(ReadFixture(), version="2025-06-18")), "unsupported-version"),
    (RpcReply(1, Initialization(ReadFixture()), session="synthetic\r\ninjected-header"),
     "malformed-session"),
    (RpcReply(1, {**Initialization(ReadFixture()), "instructions": _SESSION}, session=_SESSION),
     "session-material"),
    (RpcReply(1, Initialization(ReadFixture(), capabilities={"tools": False})),
     "invalid-declaration"),
    (ConnectionError(_SECRET), "transport-failure"),
])
def test_InvalidInitializeStopsWithoutInventingAnInventory(
    tmp_path: Path, reply: McpMetadataReply | Exception, reason: str,
) -> None:
    """Reject initialization failures with fixed diagnostics and no additional requests.

    Args:
        tmp_path: Isolated local workspace.
        reply: Untrusted reply or failure from the first POST.
        reason: Expected fixed incompleteness classification.
    """

    CreateScope(tmp_path / "work")
    peer = ScriptedExchange([(InitializeRequest(), reply)])
    result = Collect(tmp_path / "work", peer)
    assert result.inventory is None, "Failed initialization invented an inventory"
    assert result.issues == (McpMetadataIssue("initialize", reason),), (
        "Initialization diagnosis lost its stage or fixed reason"
    )
    assert peer.methods == ["initialize"] and not peer.steps, (
        "Failed initialization made an unexpected follow-up request"
    )
    assert _SECRET not in repr(result) and _SESSION not in repr(result), (
        "Diagnostic output exposed transient peer material"
    )


@pytest.mark.parametrize(("replacement", "reason"), [
    (TimeoutError(_SECRET), "timeout"),
    (RpcReply(3, {"tools": [], "nextCursor": _CURSOR}), "invalid-cursor"),
    (McpMetadataSizeLimit(_SECRET), "size-limit"),
    (RpcReply(3, {"tools": [], "nextCursor": None}), "malformed-page"),
    (RpcReply(3, {"tools": [], "instructions": "unexpected field"}), "malformed-page"),
    (RpcReply(3, {"tools": [{"name": "catalog_list", "inputSchema": {"type": "object"}}]}),
     "invalid-declaration"),
    (RpcReply(3, {"tools": []}, session="changed-session"), "malformed-session"),
    (RpcReply(3, {"tools": [{"name": _SESSION, "inputSchema": {"type": "object"}}]}),
     "session-material"),
    (McpMetadataReply(200, "application/json", b"x" * (65536 + 1)), "size-limit"),
])
def test_InvalidSecondPagePreservesPreviouslyAcceptedDeclarations(
    tmp_path: Path, replacement: McpMetadataReply | Exception, reason: str,
) -> None:
    """A bad second page leaves first-page membership and downstream scope undecided.

    Args:
        tmp_path: Isolated local workspace.
        replacement: Untrusted reply or failure replacing the second page.
        reason: Expected fixed incompleteness classification.
    """

    CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())
    expectedRequest, _ = peer.steps[3]
    peer.steps[3] = (expectedRequest, replacement)
    result = Collect(tmp_path / "work", peer)
    assert result.protocolVersion == MCP_PROTOCOL_VERSION, (
        "A second-page failure discarded the negotiated revision"
    )
    assert result.issues == (McpMetadataIssue("tools", reason),), (
        "The second-page failure was not attributed to the tool list"
    )
    assert Section(result, "tools")["status"] == "incomplete", "A partial list was marked complete"
    assert [tool["name"] for tool in Section(result, "tools")["items"]] == ["catalog_list"], (
        "The first valid page was lost or the second page was accepted"
    )
    assert Section(result, "resources") == {"status": "incomplete", "items": []}, (
        "An unvisited section asserted membership"
    )
    assert len(peer.methods) == 4, "Collection continued after the invalid page"
    assert _SECRET not in repr(result) and _SESSION not in repr(result), (
        "An incomplete result exposed secret or session material"
    )
    assert _CURSOR not in repr(result), "An incomplete result exposed an opaque cursor"


def test_UnadvertisedCapabilitiesStayIncompleteWhileAnEmptyListIsComplete(tmp_path: Path) -> None:
    """Distinguish unknown membership in absent families from an explicit empty declaration.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    sample = ReadFixture()
    peer = ScriptedExchange([
        (InitializeRequest(), RpcReply(1, Initialization(sample, capabilities={"prompts": {}}))),
        ({"method": "notifications/initialized"}, McpMetadataReply(202)),
        ({"id": 2, "method": "prompts/list"}, RpcReply(2, {"prompts": []})),
    ])
    result = Collect(tmp_path / "work", peer)
    assert result.issues == tuple(
        McpMetadataIssue(name, "capability-not-advertised")
        for name in ("tools", "resources", "resource_templates")
    ), "Missing capabilities were not reported individually"
    assert Section(result, "tools") == {"status": "incomplete", "items": []}, (
        "An absent tool capability asserted membership"
    )
    assert Section(result, "prompts") == {"status": "complete", "items": []}, (
        "An explicit empty prompt list was classified as partial"
    )
    assert not peer.steps, "The collector did not enumerate the sole advertised capability"


def test_TransientAuthAndSessionMaterialCannotEnterReturnedInventory(tmp_path: Path) -> None:
    """Return redacted declaration data and never retain exchange authorization details.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    sample = ReadFixture()
    sample["instructions"] = "Authorization: Bearer " + _SECRET
    sample["resources"]["items"][0]["uri"] += "?access_token=" + _SECRET
    sample["tools"]["items"][0]["inputSchema"]["properties"]["category"]["default"] = _SECRET
    peer = CatalogExchange(sample)
    result = Collect(tmp_path / "work", peer)
    assert result.inventory == ParseMcpInventory(CanonicalModelJson(sample)), (
        "The same source data must pass through the offline profile's redactor"
    )
    assert _SECRET not in repr(result) and _SESSION not in repr(result), (
        "Exchange authorization material escaped redaction"
    )
    assert not any(path.is_file() for path in (tmp_path / "work" / "evidence").rglob("*")), (
        "The SDK stored material from a secret-bearing reply"
    )


def test_ExchangeDenialRedactsProviderDiagnostic(tmp_path: Path) -> None:
    """Preserve provider-side authority denial without retaining its exception message.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())
    expectedRequest, _ = peer.steps[3]
    peer.steps[3] = (expectedRequest, McpMetadataDenied(_SECRET))

    with pytest.raises(McpMetadataDenied, match="exchange denied") as error:
        Collect(tmp_path / "work", peer)

    assert _SECRET not in str(error.value), "The exchange's denial exposed provider material"
    assert len(peer.methods) == 4, "Exchange denial enabled an additional request"
    assert error.value.__cause__ is None and error.value.__context__ is None, (
        "The outward denial chained the original provider exception"
    )
    tracebackFrames = [
        frame for frame, _line in walk_tb(error.value.__traceback__)
        if frame.f_globals.get("__name__") == mcp_metadata.__name__
    ]
    assert [frame.f_code.co_name for frame in tracebackFrames] == ["CollectMcpMetadata"], (
        "The outward denial exposes frames that own session material"
    )
    frameLocals = tracebackFrames[0].f_locals
    assert "exchange" not in frameLocals and "endpoint" not in frameLocals, (
        "The outward denial retains the potentially secret-bearing inputs"
    )


def test_AdvertisedTemplateMethodErrorPreservesEarlierCompleteLists(tmp_path: Path) -> None:
    """Keep positive resource membership when the peer says template enumeration is unsupported.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())
    expectedRequest, _ = peer.steps[5]
    peer.steps[5] = (expectedRequest, McpMetadataReply(
        200, "application/json", b'{"jsonrpc":"2.0","id":5,"error":{"code":-32601}}',
    ))
    result = Collect(tmp_path / "work", peer)
    assert Section(result, "resources")["status"] == "complete", (
        "A later template error discarded the complete resource list"
    )
    assert Section(result, "resource_templates") == {"status": "incomplete", "items": []}, (
        "An unsupported template list asserted membership"
    )
    assert result.issues == (McpMetadataIssue("resource_templates", "rpc-error"),), (
        "The template error was not attributed to its list"
    )
    assert "prompts/list" not in peer.methods, (
        "The collector sent another request after the template error"
    )


def test_InvalidInitializationAckStopsBeforeLists(tmp_path: Path) -> None:
    """A successful initialization with malformed acknowledgement opens no list workflow.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())
    peer.steps[1] = ({"method": "notifications/initialized"}, McpMetadataReply(202, body=b"oops"))
    result = Collect(tmp_path / "work", peer)
    assert result.inventory is not None, "A bad acknowledgement erased valid negotiated metadata"
    assert result.issues == (McpMetadataIssue("initialized", "invalid-notification-ack"),), (
        "The acknowledgement failure lost its fixed diagnostic"
    )
    assert peer.methods == ["initialize", "notifications/initialized"], (
        "A rejected notification acknowledgement enabled list requests"
    )


def test_PageAndAggregateResponseBudgetsStopNewRequests(tmp_path: Path) -> None:
    """Stop before another page after reaching either the page cap or total reply budget.

    Args:
        tmp_path: Isolated local workspace.
    """

    CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())
    result = Collect(tmp_path / "work", peer, McpMetadataLimits(maxPagesPerSection=1))
    assert result.issues == (McpMetadataIssue("tools", "page-limit"),), (
        "Page exhaustion was not attributed to the tool list"
    )
    assert Section(result, "tools")["status"] == "incomplete", (
        "Exhausted pagination was declared complete"
    )
    assert len(peer.methods) == 3, "The peer received a request beyond the page ceiling"
    peer = CatalogExchange(ReadFixture())
    initialReply = peer.steps[0][1]
    firstPage = peer.steps[2][1]
    assert isinstance(initialReply, McpMetadataReply) and isinstance(firstPage, McpMetadataReply), (
        "The cumulative budget scenario requires two fixture bodies"
    )
    total = len(initialReply.body) + len(firstPage.body)
    limits = McpMetadataLimits(maxReplyBytes=total, maxTotalReplyBytes=total)
    result = Collect(tmp_path / "work", peer, limits)
    assert result.issues == (McpMetadataIssue("tools", "size-limit"),), (
        "Cumulative response exhaustion was not reported"
    )
    assert peer.budgets[-1][1] == len(firstPage.body), (
        "The last request did not receive the remaining total byte allowance"
    )
    assert len(peer.methods) == 3, "The peer received a request after the total byte budget expired"


def test_LateReplyAndTotalDeadlineRemainIncomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a late reply even if the scripted transport returns structurally valid bytes.

    Args:
        tmp_path: Isolated local workspace.
        monkeypatch: Deterministic collection-time clock.
    """

    CreateScope(tmp_path / "work")
    clock = [0.0]
    monkeypatch.setattr(mcp_metadata, "monotonic", lambda: clock[0])

    def Advance() -> None:
        """Consume a deterministic fraction of the collection deadline per POST."""

        clock[0] += 0.125

    peer = CatalogExchange(ReadFixture())
    peer.afterPost = Advance
    result = Collect(tmp_path / "work", peer, McpMetadataLimits(totalTimeoutSeconds=0.375))
    assert result.issues == (McpMetadataIssue("tools", "timeout"),), (
        "A late reply was accepted instead of recording a timeout"
    )
    assert [timeout for timeout, _ in peer.budgets] == [0.375, 0.25, 0.125], (
        "The collector did not reduce later timeouts to the total deadline"
    )
    assert Section(result, "tools") == {"status": "incomplete", "items": []}, (
        "The tool reply arrived at the deadline and must remain unaccepted"
    )


def test_ExplicitScopeAndMissingWireTransportFailClosed(tmp_path: Path) -> None:
    """Approval, exact URL, literal IP and injected wire boundary are independent requirements.

    Args:
        tmp_path: Isolated local workspace.
    """

    incompleteScope = tmp_path / "incomplete"
    completeScope = tmp_path / "complete"
    CreateScope(incompleteScope, registerAddress=False)
    CreateScope(completeScope)
    peer = CatalogExchange(ReadFixture())

    with pytest.raises(McpMetadataDenied, match="scope denied"):
        Collect(incompleteScope, peer)

    assert not peer.methods, "A scope without the literal destination reached the transport"

    with pytest.raises(McpMetadataDenied, match="scope unavailable"):
        CollectMcpMetadata(completeScope, "unknown", _SOURCE.value, approved=True, exchange=peer)

    with pytest.raises(McpMetadataDenied, match="scope denied"):
        CollectMcpMetadata(
            completeScope, "fixture", _SOURCE.value + "/other", approved=True, exchange=peer,
        )

    with pytest.raises(McpMetadataDenied, match="requires explicit approval"):
        CollectMcpMetadata(completeScope, "fixture", _SOURCE.value, approved=False, exchange=peer)

    result = Collect(completeScope)
    assert result.inventory is None and result.protocolVersion is None, (
        "A missing transport fabricated a negotiation result"
    )
    assert result.issues == (McpMetadataIssue("initialize", "transport-unavailable"),), (
        "The unavailable transport was not explicitly classified"
    )
    assert not peer.methods, "An unapproved endpoint reached the transport"


def test_RevokedOrChangedScopeStopsBeforeTheNextPost(tmp_path: Path) -> None:
    """Reread scope before every request and deny even an otherwise equivalent new revision.

    Args:
        tmp_path: Isolated local workspace.
    """

    scope = CreateScope(tmp_path / "work")
    peer = CatalogExchange(ReadFixture())

    def ChangeScope() -> None:
        """Update consent after the initialize POST in the real local state owner."""

        LocalScopeStore(tmp_path / "work").Save(replace(
            scope,
            authorization=replace(scope.authorization, record_reference="consent:replacement"),
        ))

    peer.afterPost = ChangeScope

    with pytest.raises(McpMetadataDenied, match="scope changed"):
        Collect(tmp_path / "work", peer)

    assert peer.methods == ["initialize"], (
        "The collector sent another POST after scope authority changed"
    )


@pytest.mark.parametrize("endpoint", [
    "https://example.invalid/mcp",
    "http://192.0.2.1/mcp",
    "https://127.0.0.1/mcp?token=never-send",
    "https://user:secret@127.0.0.1/mcp",
    "https://127.0.0.1/mcp#alternate",
])
def test_AmbiguousOrUnencryptedNonLoopbackEndpointIsRejected(
    tmp_path: Path, endpoint: str,
) -> None:
    """Reject unsafe address forms before opening any exchange.

    Args:
        tmp_path: Isolated directory without an initialized workspace.
        endpoint: Unadmitted address spelling, potentially containing an inline credential.
    """

    with pytest.raises(ValueError) as error:
        CollectMcpMetadata(tmp_path, "fixture", endpoint, approved=True)

    assert endpoint not in str(error.value), (
        "The endpoint text appeared in its rejection diagnostic"
    )
    assert error.value.__cause__ is None and error.value.__context__ is None, (
        "The endpoint validation error retained its underlying parse failure"
    )


@pytest.mark.parametrize("limits", [
    {"requestTimeoutSeconds": True}, {"totalTimeoutSeconds": float("inf")},
    {"maxReplyBytes": 0}, {"maxReplyBytes": 200, "maxTotalReplyBytes": 100},
    {"maxPagesPerSection": 17},
])
def test_BudgetLimitsRejectCoercionsAndUnboundedValues(limits: dict[str, Any]) -> None:
    """Explicit limits remain finite and aligned with offline profile/resource ceilings.

    Args:
        limits: Candidate field overrides outside the bounded contract.
    """

    with pytest.raises(ValueError):
        McpMetadataLimits(**limits)


def test_ReplyDiagnosticRepresentationOmitsAllPeerMaterial() -> None:
    """Represent wire input by type and status without body, media or session material."""

    reply = McpMetadataReply(200, _SECRET, _SECRET.encode(), _SESSION)
    assert repr(reply) == "McpMetadataReply(status=200)", (
        "Wire material escaped through the response diagnostic representation"
    )
