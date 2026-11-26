# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Collect bounded MCP declarations through a supplied, already governed exchange."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Protocol, cast

from fuzzy1337.adapters.native_http import Endpoint, RequestTimeout
from fuzzy1337.adapters.page_capture import Seconds
from fuzzy1337.captured_web import WebInteger
from fuzzy1337.mcp_inventory import DecodeInventory, ParseMcpInventory
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.policy import UtcNow
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = (
    "CollectMcpMetadata", "McpMetadataDenied", "McpMetadataExchange", "McpMetadataIssue",
    "McpMetadataLimits", "McpMetadataPost", "McpMetadataReply", "McpMetadataResult",
    "McpMetadataSizeLimit",
)

MCP_PROTOCOL_VERSION = "2025-11-25"
_MAX_BYTES = 256 * 1024
_MAX_PAGES = 16
_MAX_SESSION_BYTES = 512
_MEDIA_TYPES = re.compile(r"(application/json|text/event-stream)(?:[ \t]*;[ \t]*charset=utf-8)?",
                          re.ASCII | re.IGNORECASE)
_SECTIONS = (
    ("tools", "tools", "tools/list", "tools"),
    ("resources", "resources", "resources/list", "resources"),
    ("resource_templates", "resources", "resources/templates/list", "resourceTemplates"),
    ("prompts", "prompts", "prompts/list", "prompts"),
)


class McpMetadataDenied(PermissionError):
    """The selected endpoint and literal destination lack current collection approval."""


class McpMetadataFailure(Exception):
    """An exchange or declaration failed with only a fixed diagnostic code."""


class McpMetadataSizeLimit(ValueError):
    """The exchange stopped reading before buffering a reply beyond its byte limit."""


@dataclass(frozen=True, slots=True)
class McpMetadataLimits:
    """Bound per-POST elapsed time, collection time, cumulative bytes and pagination."""

    requestTimeoutSeconds: float = 3.0
    totalTimeoutSeconds: float = 30.0
    maxReplyBytes: int = 64 * 1024
    maxTotalReplyBytes: int = _MAX_BYTES
    maxPagesPerSection: int = 8

    def __post_init__(self) -> None:
        """Reject limits outside the existing finite time and MCP profile byte ceilings."""

        RequestTimeout(self.requestTimeoutSeconds)
        Seconds(self.totalTimeoutSeconds, 60)
        WebInteger(self.maxReplyBytes, 1, _MAX_BYTES)
        WebInteger(self.maxTotalReplyBytes, self.maxReplyBytes, _MAX_BYTES)
        WebInteger(self.maxPagesPerSection, 1, _MAX_PAGES)


@dataclass(frozen=True, slots=True)
class McpMetadataPost:
    """One generated POST; the body and headers may contain transient opaque tokens."""

    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class McpMetadataReply:
    """Bounded response bytes and selected single-value headers from the same POST."""

    status: int
    contentType: str | None = field(default=None, repr=False)
    body: bytes = field(default=b"", repr=False)
    sessionId: str | None = field(default=None, repr=False)
    observedBodyBytes: int | None = field(default=None, repr=False)


class McpMetadataExchange(Protocol):
    """Trusted transport boundary for one exact endpoint and a metadata-only POST."""

    def Post(self, target: Target, post: McpMetadataPost, *, timeoutSeconds: float,
             maxReplyBytes: int) -> McpMetadataReply:
        """Send the exact POST under separately verified execution authority and hard bounds.

        It owns transport security and verifies authority at the final send boundary.
        It never redirects, resolves service links or exposes authorization material in
        returned response data, logs or diagnostics.

        Args:
            target: The only authorized canonical literal URL.
            post: Method-specific JSON-RPC body and headers. Keep all material transient.
            timeoutSeconds: Total exchange deadline in seconds, including connect and body.
            maxReplyBytes: Inclusive payload ceiling. Report any bytes read past an SSE result.

        Returns:
            Status, bounded JSON or SSE bytes, and only the selected response headers.

        Raises:
            McpMetadataDenied: Current execution authority cannot be verified.
            TimeoutError: The request did not finish within the given deadline.
            McpMetadataSizeLimit: The response exceeds the given byte limit.
            OSError: The authorized exchange could not be completed.
        """

        ...


@dataclass(frozen=True, slots=True)
class McpMetadataIssue:
    """Redacted incompleteness coordinate and fixed classification."""

    stage: str
    reason: str


@dataclass(frozen=True, slots=True)
class McpMetadataResult:
    """Attribute a detached redacted snapshot or an incomplete negotiation to its source."""

    sourceReference: str
    scopeReference: str
    scopeRevision: int
    protocolVersion: str | None
    inventory: dict[str, object] | None
    issues: tuple[McpMetadataIssue, ...]


def ReadScope(workspaceRoot: Path, scopeId: str, source: Target,
              destination: Target) -> ScopeSnapshot:
    """Read current Workbench membership for the exact URL and connected literal address.

    Args:
        workspaceRoot: Existing physical Workbench workspace.
        scopeId: Explicit existing scope in the workspace.
        source: Exact canonical URL, including path.
        destination: Exact literal address with no DNS expansion.

    Returns:
        The current admitted scope for comparison at each exchange boundary.

    Raises:
        McpMetadataDenied: Current local consent, membership or workspace binding is unavailable.
    """

    try:
        scope = LocalScopeStore(workspaceRoot).Open(scopeId)
        workspace = LocalWorkspaceStore(workspaceRoot).Open()
        at = UtcNow()

    except (ValueError, OSError, RuntimeError):
        raise McpMetadataDenied("MCP metadata scope unavailable") from None

    if scope.workspace_id != workspace.workspace_id or (
        not scope.Check(source, at=at).Allowed() or not scope.Check(destination, at=at).Allowed()
    ):
        raise McpMetadataDenied("MCP metadata scope denied")

    return scope


def RpcObject(body: bytes) -> dict[str, object]:
    """Decode a bounded JSON-RPC object without exposing received values in errors.

    Args:
        body: One complete bounded JSON frame, already separated from HTTP/SSE framing.

    Returns:
        The decoded JSON-RPC 2.0 object.
    """

    try:
        message = DecodeInventory(body)

    except ValueError:
        raise McpMetadataFailure("malformed") from None

    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise McpMetadataFailure("malformed")

    return cast(dict[str, object], message)


def RpcResult(message: dict[str, object], requestId: int) -> dict[str, object]:
    """Accept only the exact matching JSON-RPC response and an object result.

    Args:
        message: The decoded candidate response frame.
        requestId: The exact integer ID generated for this POST.

    Returns:
        The response result containing declaration data.
    """

    if type(message.get("id")) is not int or message["id"] != requestId:
        raise McpMetadataFailure("malformed")

    if message.keys() == {"jsonrpc", "id", "error"}:
        raise McpMetadataFailure("rpc-error")

    result = message.get("result")

    if message.keys() != {"jsonrpc", "id", "result"} or not isinstance(result, dict):
        raise McpMetadataFailure("malformed")

    return cast(dict[str, object], result)


def EventStreamResult(body: bytes, requestId: int) -> dict[str, object]:
    """Read a matching response from completed SSE events, ignoring valid peer requests.

    Args:
        body: Bounded UTF-8 SSE bytes ending at a complete event or transport termination.
        requestId: The exact integer ID generated for this POST.

    Returns:
        The response result when present in a complete SSE event.
    """

    try:
        data = body.decode("utf-8-sig")

    except UnicodeError:
        raise McpMetadataFailure("malformed") from None

    eventType = "message"
    lines: list[str] = []

    # The unterminated last line cannot complete an event. An empty line dispatches it.
    for line in re.split(r"\r\n|\r|\n", data)[:-1]:
        if line:
            name, _, value = line.partition(":")

            if name == "event":
                eventType = value.removeprefix(" ")

            elif name == "data":
                lines.append(value.removeprefix(" "))

            continue

        if eventType not in ("", "message"):
            raise McpMetadataFailure("unsupported-transport")

        if lines and any(lines):
            message = RpcObject("\n".join(lines).encode("utf-8"))

            method = message.get("method")

            if not isinstance(method, str):
                return RpcResult(message, requestId)

            if not method or not message.keys() <= {"jsonrpc", "id", "method", "params"} or (
                "id" in message and type(message["id"]) not in (str, int)
            ) or (
                "params" in message and not isinstance(message["params"], dict)
            ):
                raise McpMetadataFailure("malformed")

        eventType = "message"
        lines.clear()

    raise McpMetadataFailure("event-stream-ended")


def ParseReply(reply: McpMetadataReply, requestId: int | None,
               maximum: int) -> dict[str, object]:
    """Apply fixed HTTP response framing for a collection request or initialization notice.

    Args:
        reply: One trusted transport response; all field data are still untrusted input.
        requestId: Non-null generated request ID, or None for the initialized notification.
        maximum: Inclusive response body byte ceiling for this request.

    Returns:
        The matching RPC result or an empty acknowledgement.
    """

    if type(reply) is not McpMetadataReply or type(reply.status) is not int or (
        type(reply.body) is not bytes
    ):
        raise McpMetadataFailure("malformed")

    observed = len(reply.body) if reply.observedBodyBytes is None else reply.observedBodyBytes

    if type(observed) is not int or observed < len(reply.body):
        raise McpMetadataFailure("malformed")

    if observed > maximum:
        raise McpMetadataFailure("size-limit")

    if 300 <= reply.status < 400:
        raise McpMetadataFailure("redirect")

    if requestId is None:
        if reply.status == 202 and observed == 0:
            return {}

        raise McpMetadataFailure("invalid-notification-ack")

    if reply.status != 200:
        raise McpMetadataFailure("http-status")

    media = reply.contentType

    if type(media) is not str or len(media) > 128:
        raise McpMetadataFailure("unsupported-transport")

    match = _MEDIA_TYPES.fullmatch(media.strip(" \t"))

    if match is None:
        raise McpMetadataFailure("unsupported-transport")

    if match[1].lower() == "application/json":
        return RpcResult(RpcObject(reply.body), requestId)

    return EventStreamResult(reply.body, requestId)


def InitialInventory(result: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    """Project negotiated initialization data into the existing v1 inventory structure.

    Args:
        result: JSON-RPC InitializeResult with advertised capabilities.

    Returns:
        The initial inventory document and its capability names for list selection.
    """

    if result.get("protocolVersion") != MCP_PROTOCOL_VERSION:
        raise McpMetadataFailure("unsupported-version")

    server = result.get("serverInfo")
    capabilities = result.get("capabilities")

    if not isinstance(server, dict) or not isinstance(capabilities, dict):
        raise McpMetadataFailure("malformed")

    capabilityMap = cast(dict[str, object], capabilities)
    document: dict[str, object] = {
        "schema_version": 1,
        "server": {**{name: server[name] for name in ("name", "version", "title", "description")
                      if name in server}, "protocolVersion": MCP_PROTOCOL_VERSION},
        "capabilities": {"status": "complete", "items": [
            {"name": name, "declaration": declaration}
            for name, declaration in capabilityMap.items()
        ]},
        **{section: {"status": "incomplete", "items": []} for section, _, _, _ in _SECTIONS},
    }

    if "instructions" in result:
        document["instructions"] = result["instructions"]

    return document, capabilityMap


def NormalizeDeclaration(document: dict[str, object], deadline: float) -> dict[str, object]:
    """Validate a candidate document atomically with the offline snapshot profile.

    Args:
        document: Initial snapshot or candidate revision including one newly received page.
        deadline: The inclusive collection's monotonic deadline.

    Returns:
        The same redacted normalized projection as the checked-in offline profile.
    """

    try:
        inventory = ParseMcpInventory(CanonicalModelJson(document))

    except ValueError:
        raise McpMetadataFailure("invalid-declaration") from None

    if monotonic() >= deadline:
        raise McpMetadataFailure("timeout")

    return inventory


def CollectMcpMetadata(
    workspaceRoot: Path, scopeId: str, endpoint: str, *, approved: bool,
    exchange: McpMetadataExchange | None = None, limits: McpMetadataLimits = McpMetadataLimits(),
) -> McpMetadataResult:
    """Collect a single 2025-11-25 declaration snapshot using a separately governed exchange.

    Args:
        workspaceRoot: Workspace owning the selected scope.
        scopeId: Current granted scope registering the exact URL and literal destination.
        endpoint: Explicit literal HTTP(S) URL without credentials, query or fragment.
        approved: Explicit operator opt-in for this one collection.
        exchange: Trusted preauthorized exchange. There is no default wire transport.
        limits: Per-exchange and cumulative time, reply bytes and page ceilings.

    Returns:
        A redacted inventory, exact source and revision, and fixed incomplete diagnostics.
        Failed initialization yields no inventory because no server identity is established.

    Raises:
        McpMetadataDenied: Approval or current endpoint/destination membership is missing.
        ValueError: The endpoint or limits are outside the admitted contract.
    """

    try:
        return CollectScopedMetadata(workspaceRoot, scopeId, endpoint, approved, exchange, limits)

    except McpMetadataDenied as denied:
        failure: ValueError | McpMetadataDenied = McpMetadataDenied(str(denied))

    except ValueError:
        failure = ValueError("MCP metadata selection is invalid")

    # Keep a rejected endpoint or exchange object out of the outward traceback.
    del endpoint, exchange

    raise failure


def CollectScopedMetadata(
    workspaceRoot: Path, scopeId: str, endpoint: str, approved: bool,
    exchange: McpMetadataExchange | None, limits: McpMetadataLimits,
) -> McpMetadataResult:
    """Run the bounded collection inside the boundary that owns session material.

    Args:
        workspaceRoot: Workspace owning the selected scope.
        scopeId: Current granted scope registering the exact URL and literal destination.
        endpoint: Explicit literal HTTP(S) URL for the single selected server.
        approved: Explicit operator opt-in for this one collection.
        exchange: Trusted preauthorized exchange, or no transport.
        limits: Typed per-exchange and total time, bytes and pagination limits.

    Returns:
        The redacted snapshot or classified incomplete result.
    """

    if approved is not True:
        raise McpMetadataDenied("MCP metadata collection requires explicit approval")

    if type(limits) is not McpMetadataLimits:
        raise ValueError("MCP metadata collection requires typed limits")

    source, address, _, scheme = Endpoint(endpoint)

    if scheme != "https" and address not in {"127.0.0.1", "::1"}:
        raise ValueError("MCP metadata requires HTTPS or a literal loopback endpoint")

    destination = Target(TargetKind.IP, address)
    scope = ReadScope(workspaceRoot, scopeId, source, destination)
    protocol: str | None = None
    sessionId: str | None = None
    inventory: dict[str, object] | None = None
    issues: list[McpMetadataIssue] = []
    stage = "initialize"
    requestId = 0
    remainingBytes = limits.maxTotalReplyBytes
    deadline = monotonic() + limits.totalTimeoutSeconds

    def Send(method: str, params: dict[str, object] | None = None, *,
             notification: bool = False) -> dict[str, object]:
        """Send one collector-selected POST and account for its response before parsing.

        Args:
            method: One of initialize, initialized notification or the four list methods.
            params: Static initialize fields or an opaque cursor from the same list operation.
            notification: Whether JSON-RPC acknowledgement framing is required.

        Returns:
            The negotiated result, list page or empty notification acknowledgement.
        """

        nonlocal requestId, sessionId, remainingBytes

        if exchange is None:
            raise McpMetadataFailure("transport-unavailable")

        if ReadScope(workspaceRoot, scopeId, source, destination) != scope:
            raise McpMetadataDenied("MCP metadata scope changed")

        headers = [
            ("Accept", "application/json, text/event-stream"), ("Accept-Encoding", "identity"),
            ("Content-Type", "application/json"),
        ]
        message: dict[str, object] = {"jsonrpc": "2.0", "method": method}

        if protocol is not None:
            headers.append(("MCP-Protocol-Version", protocol))

        if sessionId is not None:
            headers.append(("MCP-Session-Id", sessionId))

        if not notification:
            requestId += 1
            message["id"] = requestId

        if params is not None:
            message["params"] = params

        maximum = min(remainingBytes, limits.maxReplyBytes)
        replyDeadline = min(deadline, monotonic() + limits.requestTimeoutSeconds)
        timeout = replyDeadline - monotonic()

        if maximum == 0:
            raise McpMetadataFailure("size-limit")

        if timeout <= 0:
            raise McpMetadataFailure("timeout")

        post = McpMetadataPost(tuple(headers), CanonicalModelJson(message))

        try:
            reply = exchange.Post(source, post, timeoutSeconds=timeout, maxReplyBytes=maximum)

        except McpMetadataDenied:
            raise McpMetadataDenied("MCP metadata exchange denied") from None

        except TimeoutError:
            raise McpMetadataFailure("timeout") from None

        except McpMetadataSizeLimit:
            raise McpMetadataFailure("size-limit") from None

        except Exception:
            raise McpMetadataFailure("transport-failure") from None

        if monotonic() >= replyDeadline:
            raise McpMetadataFailure("timeout")

        result = ParseReply(reply, None if notification else requestId, maximum)
        remainingBytes -= (
            len(reply.body) if reply.observedBodyBytes is None else reply.observedBodyBytes
        )

        if reply.sessionId is not None:
            token = reply.sessionId

            if type(token) is not str or not 1 <= len(token) <= _MAX_SESSION_BYTES or (
                not all(0x21 <= ord(char) <= 0x7E for char in token)
            ):
                raise McpMetadataFailure("malformed-session")

            if method == "initialize":
                sessionId = token

            elif token != sessionId:
                raise McpMetadataFailure("malformed-session")

        if sessionId is not None and CanonicalModelJson(sessionId)[1:-1] in CanonicalModelJson(
            result
        ):
            raise McpMetadataFailure("session-material")

        return result

    try:
        initial = Send("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "1337-metadata", "version": "1"},
        })
        document, capabilities = InitialInventory(initial)
        protocol = MCP_PROTOCOL_VERSION
        inventory = NormalizeDeclaration(document, deadline)
        stage = "initialized"
        Send("notifications/initialized", notification=True)

        for stage, capability, method, listKey in _SECTIONS:
            if capability not in capabilities:
                issues.append(McpMetadataIssue(stage, "capability-not-advertised"))

                continue

            cursor: str | None = None
            seen: set[str] = set()
            accepted: list[object] = []

            for _page in range(limits.maxPagesPerSection):
                page = Send(method, {"cursor": cursor} if cursor is not None else None)
                items = page.get(listKey)
                nextCursor = page.get("nextCursor")

                if not isinstance(items, list) or not page.keys() <= {
                    listKey, "nextCursor", "_meta",
                }:
                    raise McpMetadataFailure("malformed-page")

                if "nextCursor" in page:
                    if not isinstance(nextCursor, str):
                        raise McpMetadataFailure("malformed-page")

                    if nextCursor in seen:
                        raise McpMetadataFailure("invalid-cursor")

                accepted = [*accepted, *items]
                document[stage] = {
                    "status": "complete" if nextCursor is None else "incomplete",
                    "items": accepted,
                }
                inventory = NormalizeDeclaration(document, deadline)

                if not isinstance(nextCursor, str):
                    break

                seen.add(nextCursor)
                cursor = nextCursor

            else:
                raise McpMetadataFailure("page-limit")

    except McpMetadataFailure as error:
        issues.append(McpMetadataIssue(stage, str(error)))

    return McpMetadataResult(
        source.Reference(), scope.Reference(), scope.revision, protocol, inventory, tuple(issues),
    )
