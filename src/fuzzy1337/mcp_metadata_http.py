# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Governed first-party HTTP exchange for one explicit MCP metadata collection."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.adapters.native_http import Endpoint
from fuzzy1337.executors import CapabilityDescriptor
from fuzzy1337.mcp_inventory import DecodeInventory
from fuzzy1337.mcp_metadata import (
    MCP_PROTOCOL_VERSION,
    CollectMcpMetadata,
    EventStreamResult,
    McpMetadataDenied,
    McpMetadataFailure,
    McpMetadataLimits,
    McpMetadataPost,
    McpMetadataReply,
    McpMetadataResult,
    McpMetadataSizeLimit,
    ParseReply,
    ReadScope,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.native_http_worker import MAX_HTTP_HEADER_BYTES, Remaining
from fuzzy1337.policy import ImpactPolicy, PolicyContext, PolicyEngine, UtcNow
from fuzzy1337.scope import Target, TargetKind

__all__ = ("CollectMcpMetadataHttp", "MCP_METADATA_CAPABILITY")

MCP_METADATA_CAPABILITY = CapabilityDescriptor(
    "mcp.metadata-collection", "native.mcp-metadata", ImpactLevel.SAFE,
)
_LIST_METHODS = frozenset((
    "tools/list", "resources/list", "resources/templates/list", "prompts/list",
))
_INIT_PARAMS = {
    "protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
    "clientInfo": {"name": "1337-metadata", "version": "1"},
}
_HEADERS = {
    "Accept": "application/json, text/event-stream", "Accept-Encoding": "identity",
    "Content-Type": "application/json",
}
_RESPONSE_FIELDS = frozenset((
    b"content-type", b"content-length", b"content-encoding", b"transfer-encoding",
    b"mcp-session-id",
))
_STATUS = re.compile(rb"HTTP/1\.[01] ([2-5][0-9]{2})(?: [\t\x20-\x7e]*)?")
_FIELD = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):([\t\x20-\x7e]*)")
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,2}", re.ASCII)
_SESSION = re.compile(r"[!-~]{1,512}", re.ASCII)
_CHUNK = re.compile(rb"[0-9A-Fa-f]{1,8}")
_EVENT_END = re.compile(rb"(?:\r\n|\r(?!\n)|(?<!\r)\n){2}")
_MAX_REQUEST_BYTES = 52 * 1024
_MAX_CHUNKS = 4096
_READ_BLOCK = 4096


class McpHttpWireError(OSError):
    """Reject unsupported or malformed exchange framing without exposing wire content."""


def CheckPost(post: McpMetadataPost) -> tuple[dict[str, str], int | None]:
    """Admit only the collector's fixed metadata methods and request envelope.

    Args:
        post: One generated request with no caller-selected HTTP headers or methods.

    Returns:
        Validated headers and exact outstanding ID, or None for the initialized notification.
    """

    if type(post) is not McpMetadataPost or type(post.body) is not bytes or (
        len(post.body) > _MAX_REQUEST_BYTES
    ):
        raise McpHttpWireError("invalid MCP POST")

    try:
        value = DecodeInventory(post.body)
        headers = dict(post.headers)

    except (ValueError, TypeError):
        raise McpHttpWireError("invalid MCP POST") from None

    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0" or (
        len(headers) != len(post.headers) or any(headers.get(key) != item
                                               for key, item in _HEADERS.items())
    ):
        raise McpHttpWireError("invalid MCP POST")

    method = value.get("method")
    requestId = value.get("id")

    if method == "initialize":
        if (
            value.keys() != {"jsonrpc", "id", "method", "params"}
            or type(requestId) is not int or requestId != 1 or value["params"] != _INIT_PARAMS
            or headers != _HEADERS
        ):
            raise McpHttpWireError("invalid MCP initialize POST")

        return headers, requestId

    session = headers.get("MCP-Session-Id")

    if (
        headers.get("MCP-Protocol-Version") != MCP_PROTOCOL_VERSION
        or not headers.keys() <= {*_HEADERS, "MCP-Protocol-Version", "MCP-Session-Id"}
        or (session is not None and (type(session) is not str or not _SESSION.fullmatch(session)))
    ):
        raise McpHttpWireError("invalid MCP session POST")

    if method == "notifications/initialized" and value.keys() == {"jsonrpc", "method"}:
        return headers, None

    if (
        not isinstance(method, str) or method not in _LIST_METHODS or type(requestId) is not int
        or not 2 <= requestId <= 65 or not value.keys() <= {"jsonrpc", "id", "method", "params"}
    ):
        raise McpHttpWireError("invalid MCP method")

    if "params" in value:
        params = value["params"]

        if not isinstance(params, dict) or params.keys() != {"cursor"} or (
            not isinstance(params["cursor"], str)
        ):
            raise McpHttpWireError("invalid MCP list cursor")

    return headers, requestId


@dataclass(slots=True)
class McpHttpReader:
    """Transient bounded socket reader whose remaining deadline never renews."""

    connection: socket.socket = field(repr=False)
    deadline: float
    pending: bytearray = field(default_factory=bytearray, repr=False)

    def Receive(self, maximum: int) -> bytes:
        """Receive once under the shared deadline.

        Args:
            maximum: Maximum bytes accepted into this read.

        Returns:
            Original socket bytes, or empty bytes at EOF.
        """

        self.connection.settimeout(Remaining(self.deadline))
        return self.connection.recv(maximum)

    def ReadUntil(self, delimiter: bytes, maximum: int) -> bytes:
        """Consume a complete header block or chunk line inside its own byte ceiling.

        Args:
            delimiter: Exact required framing delimiter.
            maximum: Inclusive byte ceiling including framing bytes.

        Returns:
            Bytes up to and including the delimiter.
        """

        while True:
            end = self.pending.find(delimiter)

            if end >= 0 and end + len(delimiter) <= maximum:
                count = end + len(delimiter)
                prefix = bytes(self.pending[:count])
                del self.pending[:count]

                return prefix

            if len(self.pending) >= maximum:
                raise McpHttpWireError("HTTP framing exceeds its bound")

            incoming = self.Receive(min(_READ_BLOCK, maximum - len(self.pending)))

            if not incoming:
                raise McpHttpWireError("HTTP framing is incomplete")

            self.pending.extend(incoming)

    def ReadData(self, maximum: int) -> bytes:
        """Consume pending bytes first, falling back to one bounded socket read.

        Args:
            maximum: Maximum bytes returned during this call.

        Returns:
            Pending or new original bytes, or empty bytes at EOF.
        """

        if self.pending:
            data = bytes(self.pending[:maximum])
            del self.pending[:maximum]

            return data

        return self.Receive(maximum)

    def ReadFixed(self, length: int) -> Iterator[bytes]:
        """Read exactly a declared payload or framing length.

        Args:
            length: Bounded declared byte count.

        Yields:
            Original blocks bounded by the remaining length.
        """

        while length:
            data = self.ReadData(min(_READ_BLOCK, length))

            if not data:
                raise McpHttpWireError("HTTP payload is incomplete")

            length -= len(data)

            yield data

    def ReadBody(self, fields: dict[bytes, bytes], maximum: int) -> Iterator[bytes]:
        """Read a bounded fixed-length, chunked or close-delimited HTTP body.

        Args:
            fields: Selected single-value response framing fields.
            maximum: Inclusive application response byte ceiling.

        Yields:
            Original de-framed bytes without interpreting or decompressing them.
        """

        length = fields.get(b"content-length")
        transfer = fields.get(b"transfer-encoding")
        encoding = fields.get(b"content-encoding")

        if encoding is not None and encoding.lower() != b"identity":
            raise McpHttpWireError("unsupported HTTP content encoding")

        if transfer is not None:
            if length is not None or transfer.lower() != b"chunked":
                raise McpHttpWireError("unsupported HTTP transfer framing")

            yield from self.ReadChunks(maximum)

            return

        if length is not None:
            if not 1 <= len(length) <= 12 or not length.isdigit():
                raise McpHttpWireError("invalid HTTP body length")

            count = int(length)

            if count > maximum:
                raise McpMetadataSizeLimit("HTTP body exceeds its bound")

            yield from self.ReadFixed(count)

            return

        total = 0

        while True:
            data = self.ReadData(min(_READ_BLOCK, maximum - total + 1))

            if not data:
                return

            total += len(data)

            if total > maximum:
                raise McpMetadataSizeLimit("HTTP body exceeds its bound")

            yield data

    def ReadChunks(self, maximum: int) -> Iterator[bytes]:
        """Read simple HTTP chunks under both payload and finite framing bounds.

        Args:
            maximum: Inclusive cumulative decoded payload allowance.

        Yields:
            Original transfer-decoded byte blocks.
        """

        for _index in range(_MAX_CHUNKS):
            line = self.ReadUntil(b"\r\n", 10)[:-2]

            if not _CHUNK.fullmatch(line):
                raise McpHttpWireError("invalid or unsupported HTTP chunk")

            length = int(line, 16)

            if length == 0:
                self.ReadUntil(b"\r\n", 2)

                return

            if length > maximum:
                raise McpMetadataSizeLimit("HTTP body exceeds its bound")

            maximum -= length
            chunk = b"".join(self.ReadFixed(length))

            if b"".join(self.ReadFixed(2)) != b"\r\n":
                raise McpHttpWireError("invalid HTTP chunk boundary")

            yield chunk

        raise McpMetadataSizeLimit("HTTP chunk count exceeds its bound")


def ReadHeaders(reader: McpHttpReader) -> tuple[int, dict[bytes, bytes]]:
    """Read one final HTTP status and selected unambiguous framing headers.

    Args:
        reader: Socket reader under the shared request deadline.

    Returns:
        Final HTTP status and only the selected protocol fields.
    """

    lines = reader.ReadUntil(b"\r\n\r\n", MAX_HTTP_HEADER_BYTES)[:-4].split(b"\r\n")
    status = _STATUS.fullmatch(lines[0])

    if status is None:
        raise McpHttpWireError("invalid HTTP response status")

    fields: dict[bytes, bytes] = {}

    for line in lines[1:]:
        match = _FIELD.fullmatch(line)

        if match is None:
            raise McpHttpWireError("invalid HTTP response header")

        name = match[1].lower()

        if name in _RESPONSE_FIELDS:
            if name in fields:
                raise McpHttpWireError("duplicate HTTP protocol header")

            fields[name] = match[2].strip(b" \t")

    return int(status[1]), fields


def ReadEventPayload(blocks: Iterator[bytes], requestId: int) -> tuple[bytes, int]:
    """Stop at the first decisive bounded event on the originating POST stream.

    Args:
        blocks: Bounded transfer-decoded response blocks.
        requestId: Outstanding JSON-RPC response ID.

    Returns:
        The decisive event prefix and the whole already-read payload byte count.
    """

    data = bytearray()
    start = 0

    for block in blocks:
        offset = max(start, len(data) - 3)
        data.extend(block)

        for match in _EVENT_END.finditer(data, offset):
            end = match.end()

            try:
                EventStreamResult(bytes(data[start:end]), requestId)

            except McpMetadataFailure as error:
                if str(error) != "event-stream-ended":
                    return bytes(data[:end]), len(data)

            else:
                # The collector charges every payload byte already read from this POST.
                return bytes(data[:end]), len(data)

            start = end

    return bytes(data), len(data)


def ReadReply(connection: socket.socket, deadline: float, maximum: int, requestId: int | None,
              token: str | None) -> McpMetadataReply:
    """Read only the selected reply, guarding known authorization material before handoff.

    Args:
        connection: Checked socket pinned to the selected literal address.
        deadline: Shared connection, send and response monotonic deadline.
        maximum: Inclusive body bytes allowed for the current POST.
        requestId: Exact outstanding ID, or None for a notification.
        token: Known memory-only bearer token, when enabled.

    Returns:
        Minimal MCP response framing and bounded body data.
    """

    reader = McpHttpReader(connection, deadline)
    status, fields = ReadHeaders(reader)

    if status not in (200, 202):
        return McpMetadataReply(status)

    session = fields.get(b"mcp-session-id")
    sessionHeader = session.decode("ascii") if session is not None else None
    secret = token.encode("ascii") if token is not None else None

    if secret is not None and session is not None and secret in session:
        raise McpHttpWireError("response contains authorization material")

    if status == 202:
        # A notification acknowledgement is only acceptable when it contains no body.
        body = b"".join(reader.ReadBody(fields, 0))

        if reader.pending:
            raise McpHttpWireError("invalid MCP acknowledgement body")

        return McpMetadataReply(status, body=body, sessionId=sessionHeader)

    media = fields.get(b"content-type", b"")
    blocks = reader.ReadBody(fields, maximum)
    stream = media.split(b";", 1)[0].strip(b" \t").lower() == b"text/event-stream"
    observed: int | None = None

    if stream and requestId is not None and b"content-length" not in fields:
        body, observed = ReadEventPayload(blocks, requestId)

    else:
        body = b"".join(blocks)

        if reader.pending:
            raise McpHttpWireError("unexpected HTTP bytes after reply")

    reply = McpMetadataReply(status, media.decode("ascii"), body, sessionHeader, observed)

    if secret is not None:
        if secret in body:
            raise McpHttpWireError("response contains authorization material")

        # JSON escapes can conceal a credential until after decoding. Only accepted results
        # can enter the inventory, so test their decoded canonical representation as well.
        try:
            result = ParseReply(reply, requestId, maximum)

        except McpMetadataFailure:
            return reply

        if secret in CanonicalModelJson(result):
            raise McpHttpWireError("response contains authorization material")

    return reply


def VerifiedTls() -> ssl.SSLContext:
    """Use platform trust and IP identity validation without ambient TLS key logging.

    Returns:
        TLS 1.2-or-newer client context requiring a valid peer certificate.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs()

    return context


def CurrentAuthority(workspaceRoot: Path, scopeId: str, target: Target, destination: Target,
                     policyProvider: Callable[[], ImpactPolicy]) -> PolicyContext:
    """Get and validate the current Workbench authority for this exact capability.

    Args:
        workspaceRoot: Existing workspace owning the selected scope.
        scopeId: Caller-selected scope identifier.
        target: Approved literal endpoint URL.
        destination: Independently approved literal IP destination.
        policyProvider: Trusted bounded local reader of the current typed policy.

    Returns:
        Current scope, policy and exact destination after their shared policy check.
    """

    try:
        scope = ReadScope(workspaceRoot, scopeId, target, destination)
        policy = policyProvider()

        if type(policy) is not ImpactPolicy:
            raise ValueError("typed MCP policy required")

        context = PolicyContext(scope, policy, target, (destination,))
        PolicyEngine().CheckSafeCapability(MCP_METADATA_CAPABILITY, context, at=UtcNow())

        return context

    except Exception:
        raise McpMetadataDenied("MCP HTTP authority denied") from None


@dataclass(slots=True)
class McpHttpExchange:
    """One collection's pinned endpoint, authority and ephemeral bearer state."""

    workspaceRoot: Path
    scopeId: str
    policyProvider: Callable[[], ImpactPolicy] = field(repr=False)
    credentialProvider: Callable[[], str | None] | None = field(repr=False)
    authority: PolicyContext
    port: int
    scheme: str
    token: str | None = field(default=None, init=False, repr=False)
    credentialRead: bool = field(default=False, init=False)

    def CheckAuthority(self) -> None:
        """Fail closed if the current scope or exact policy changes during this collection."""

        current = CurrentAuthority(
            self.workspaceRoot, self.scopeId, self.authority.target,
            self.authority.destinations[0], self.policyProvider,
        )

        if current != self.authority:
            raise McpMetadataDenied("MCP HTTP authority changed")

    def ReadCredential(self) -> None:
        """Resolve only one optional separately approved TLS bearer into ephemeral state."""

        if self.credentialRead:
            return

        try:
            token = self.credentialProvider() if self.credentialProvider is not None else None

        except Exception:
            raise McpMetadataDenied("MCP HTTP credential unavailable") from None

        if token is not None and (
            self.scheme != "https" or type(token) is not str or not 1 <= len(token) <= 4096
            or not _TOKEN.fullmatch(token)
        ):
            raise McpMetadataDenied("MCP HTTP credential denied")

        self.token = token
        self.credentialRead = True

    def Post(self, target: Target, post: McpMetadataPost, *, timeoutSeconds: float,
             maxReplyBytes: int) -> McpMetadataReply:
        """Send one exact metadata POST to the policy-approved literal peer.

        Args:
            target: Exact URL supplied by the scoped metadata collector.
            post: Collector-generated method, fixed headers and JSON-RPC body.
            timeoutSeconds: Remaining hard per-POST and collection duration.
            maxReplyBytes: Remaining hard response payload allowance.

        Returns:
            Bounded reply of the same POST, without following service instructions.
        """

        deadline = monotonic() + timeoutSeconds

        if target != self.authority.target:
            raise McpMetadataDenied("MCP HTTP endpoint changed")

        headers, requestId = CheckPost(post)
        self.CheckAuthority()
        self.ReadCredential()
        address = self.authority.destinations[0].value
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        Remaining(deadline)
        self.CheckAuthority()
        connection = socket.socket(family, socket.SOCK_STREAM)

        try:
            connection.settimeout(Remaining(deadline))
            connection.connect((address, self.port))
            peerAddress, peerPort = connection.getpeername()[:2]

            if str(ipaddress.ip_address(peerAddress)) != address or peerPort != self.port:
                raise McpMetadataDenied("MCP HTTP literal peer changed")

            if self.scheme == "https":
                context = VerifiedTls()
                connection.settimeout(Remaining(deadline))
                connection = context.wrap_socket(connection, server_hostname=address)

            if self.token is not None:
                headers["Authorization"] = "Bearer " + self.token

            url = urlsplit(target.value)
            request = (
                f"POST {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\nConnection: close\r\n"
                f"Content-Length: {len(post.body)}\r\n"
                + "".join(f"{key}: {value}\r\n" for key, value in headers.items())
                + "\r\n"
            ).encode("ascii") + post.body
            self.CheckAuthority()
            connection.settimeout(Remaining(deadline))
            connection.sendall(request)

            return ReadReply(connection, deadline, maxReplyBytes, requestId, self.token)

        finally:
            connection.close()


def CollectOwnedHttpMetadata(
    workspaceRoot: Path, scopeId: str, endpoint: str, approved: bool,
    policyProvider: Callable[[], ImpactPolicy], credentialProvider: Callable[[], str | None] | None,
    limits: McpMetadataLimits,
) -> McpMetadataResult:
    """Bind one explicitly approved operation to its exact Workbench authority.

    Args:
        workspaceRoot: Existing scope-owning workspace.
        scopeId: Exact caller-selected scope.
        endpoint: Exact literal MCP URL.
        approved: Explicit independent opt-in for this collection.
        policyProvider: Trusted local reader supplying the current impact policy.
        credentialProvider: Optional trusted local TLS bearer resolver.
        limits: Typed whole-collection and per-request bounds.

    Returns:
        Detached redacted declarations or reported incomplete state.
    """

    if approved is not True:
        raise McpMetadataDenied("MCP HTTP collection requires explicit approval")

    target, address, port, scheme = Endpoint(endpoint)

    if scheme != "https" and address not in {"127.0.0.1", "::1"}:
        raise ValueError("MCP HTTP requires HTTPS or exact loopback")

    destination = Target(TargetKind.IP, address)
    authority = CurrentAuthority(workspaceRoot, scopeId, target, destination, policyProvider)
    exchange = McpHttpExchange(
        workspaceRoot, scopeId, policyProvider, credentialProvider, authority, port, scheme,
    )

    return CollectMcpMetadata(
        workspaceRoot, scopeId, target.value, approved=approved, exchange=exchange, limits=limits,
    )


def CollectMcpMetadataHttp(
    workspaceRoot: Path, scopeId: str, endpoint: str, *, approved: bool,
    policyProvider: Callable[[], ImpactPolicy],
    credentialProvider: Callable[[], str | None] | None = None,
    limits: McpMetadataLimits = McpMetadataLimits(),
) -> McpMetadataResult:
    """Collect MCP declarations using Workbench-governed first-party Streamable HTTP.

    Args:
        workspaceRoot: Existing Workbench owning the selected scope.
        scopeId: Scope that registers and allows the exact URL and its literal IP.
        endpoint: Single explicit literal-IP HTTPS endpoint, or unauthenticated loopback HTTP.
        approved: Explicit operator opt-in independent of scope and policy.
        policyProvider: Trusted bounded local reader of the exact permitted capability policy.
        credentialProvider: Optional trusted bounded local resolver of one HTTPS bearer token.
        limits: Explicit finite collection time, byte and pagination bounds.

    Returns:
        The shared redacted inventory, source metadata and incomplete diagnostics.

    Raises:
        McpMetadataDenied: Authorization or optional credential cannot be verified.
        ValueError: The endpoint or bounds violate the admitted profile.
    """

    try:
        return CollectOwnedHttpMetadata(
            workspaceRoot, scopeId, endpoint, approved, policyProvider, credentialProvider, limits,
        )

    except McpMetadataDenied:
        failure: McpMetadataDenied | ValueError = McpMetadataDenied("MCP HTTP collection denied")

    except ValueError:
        failure = ValueError("MCP HTTP selection is invalid")

    del endpoint, policyProvider, credentialProvider

    raise failure
