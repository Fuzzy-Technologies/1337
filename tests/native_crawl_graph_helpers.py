# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own a finite mutable HTML target independently of crawl parsers and scanner truth."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from socketserver import BaseRequestHandler, TCPServer
from threading import BoundedSemaphore, Event, Lock, Thread
from time import monotonic
from typing import Any, cast
from urllib.parse import urlsplit

GRAPH_PATHS = (
    "/branch-a", "/branch-b", "/comment-decoy", "/entry", "/fixed/.git/HEAD",
    "/html/.git/HEAD", "/leaf/.git/HEAD", "/redirect", "/redirect-destination",
    "/script-decoy", "/selected-unreachable", "/shared", "/style-decoy",
)
VARIANTS = ("positive", "fixed", "decoy", "redirect")
MAX_REQUESTS = 64
MAX_CONCURRENT_REQUESTS = 4
MAX_REQUEST_BYTES = 8192
SOCKET_TIMEOUT_SECONDS = 2
GATE_TIMEOUT_SECONDS = 2
CLEANUP_TIMEOUT_SECONDS = 3
MAX_ERRORS = 64


@dataclass(frozen=True, slots=True)
class GraphResponse:
    """Contain exact independently authored response bytes, with finite complete framing."""

    status: int
    content_type: str
    body: bytes
    location: str | None = None

    def Wire(self) -> bytes:
        """Render complete HTTP/1.1 bytes without a generic response override interface."""

        reasons = {200: "OK", 302: "Found", 403: "Forbidden", 404: "Not Found"}
        headers = [f"HTTP/1.1 {self.status} {reasons[self.status]}",
                   f"Content-Length: {len(self.body)}", f"Content-Type: {self.content_type}",
                   "Connection: close"]

        if self.location is not None:
            headers.append("Location: " + self.location)

        return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + self.body


class MutableCrawlGraph:
    """Render finite target-owned bytes; changing a variant preserves the identical seed URL."""

    def __init__(self, origin: str, *, sentinel_origin: str | None = None) -> None:
        """Accept only a literal IPv4 loopback origin, without starting any listener."""

        parsed = urlsplit(origin)

        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or (
            parsed.username is not None or parsed.password is not None or parsed.path or
            parsed.query or parsed.fragment or parsed.port is None or
            origin != f"http://127.0.0.1:{parsed.port}"
        ):
            raise ValueError("Owned graph requires its exact ephemeral loopback origin")

        self.origin = origin
        self.variant = "positive"
        self.owner: CrawlGraphState | None = None
        self.sentinel_origin: str | None = None

        if sentinel_origin is not None:
            self.AttachSentinel(sentinel_origin)

    def AttachSentinel(self, origin: str) -> None:
        """Bind a distinct canonical literal loopback origin owned by this fixture."""

        parsed = urlsplit(origin)

        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or (
            parsed.username is not None or parsed.password is not None or parsed.path or
            parsed.query or parsed.fragment or parsed.port is None or
            origin != f"http://127.0.0.1:{parsed.port}" or origin == self.origin
        ):
            raise ValueError("Owned sentinel requires a distinct exact loopback origin")

        if self.owner is not None:
            self.owner.AttachSentinel(origin)

        else:
            self.sentinel_origin = origin

    def SetVariant(self, variant: str) -> None:
        """Change only fixture-owned source bytes through a local Python control API."""

        if variant not in VARIANTS:
            raise ValueError("Unknown owned graph variant")

        if self.owner is not None:
            self.owner.SetVariant(variant)

        else:
            self.variant = variant

    def Url(self, path: str) -> str:
        """Return only an explicitly declared URL; callers cannot add routes or origins."""

        if path not in GRAPH_PATHS:
            raise ValueError("Owned graph URL must be explicitly declared")

        return self.origin + path

    def SelectedUrls(self) -> tuple[str, ...]:
        """Select a finite same-origin set including unreachable and lexical-decoy controls."""

        return tuple(self.Url(path) for path in GRAPH_PATHS)

    def Response(self, path: str) -> GraphResponse:
        """Return one complete response without consulting the handwritten oracle or production."""

        if path == "/entry":
            return GraphResponse(200, "text/html; charset=utf-8", self.SeedBody())

        if path == "/branch-a":
            return GraphResponse(200, "text/html", (
                '<html><body><a href="/shared">shared</a>'
                '<a href="/leaf/.git/HEAD">leaf</a><a href="/fixed/.git/HEAD">fixed</a>'
                '<a href="/html/.git/HEAD">HTML</a><a href="/branch-b">cycle</a>'
                '</body></html>').encode("ascii"))

        if path == "/branch-b":
            return GraphResponse(200, "text/html", (
                '<html><body><a href="/shared">shared</a>'
                '<a href="/leaf/.git/HEAD">leaf</a><a href="/entry">cycle</a>'
                '</body></html>').encode("ascii"))

        if path == "/shared":
            return GraphResponse(200, "text/html", (
                '<html><body><a href="/branch-a">cycle</a>'
                '<a href="/leaf/.git/HEAD">shared leaf</a></body></html>').encode("ascii"))

        if path == "/leaf/.git/HEAD":
            return GraphResponse(200, "text/plain", b"ref: refs/heads/independent-crawl-fixture\n")

        if path == "/fixed/.git/HEAD":
            return GraphResponse(403, "text/plain", b"owned-dotfile-denied")

        if path == "/html/.git/HEAD":
            return GraphResponse(200, "text/html; charset=utf-8", (
                b"<html><body><code>ref: refs/heads/independent-crawl-fixture\n"
                b"</code></body></html>"))

        if path == "/redirect":
            return GraphResponse(302, "text/plain", b"owned-crawl-redirect",
                                 "/redirect-destination")

        if path == "/redirect-destination":
            return GraphResponse(200, "text/plain", b"redirect follow-up must never occur")

        if path in GRAPH_PATHS:
            return GraphResponse(200, "text/html", b"<html><body>unreachable control</body></html>")

        return GraphResponse(404, "text/plain", b"undeclared route must never be requested")

    def SeedBody(self) -> bytes:
        """Author four byte-distinct pages at one URL, with no catalog IDs or digest dispatch."""

        decoys = (
            '<!-- <a href="/comment-decoy">comment</a> -->'
            '<script>var marker = \'<a href="/script-decoy">script</a>\';</script>'
            '<style>.marker { content: \'<a href="/style-decoy">style</a>\'; }</style>'
        )

        if self.variant == "fixed":
            markup = '<html><body><p>The linked graph was removed.</p></body></html>'

        elif self.variant == "decoy":
            markup = '<html><body>' + decoys + '</body></html>'

        elif self.variant == "redirect":
            markup = '<html><body><a href="/redirect">explicit redirect control</a></body></html>'

        else:
            if self.sentinel_origin is None:
                raise ValueError("Positive graph requires its owned off-origin sentinel")

            markup = (
                '<html><body><a href="/branch-b">B</a><a href="/branch-a">A</a>'
                '<a href="/branch-a">duplicate A</a><a href="/unselected">unselected</a>'
                '<a href="/unregistered">unregistered</a>'
                f'<a href="{self.sentinel_origin}/off-origin-marker">other origin</a>'
                f'<a href="http://credential-marker@{self.origin[7:]}/credential-marker">user</a>'
                '<a href="/query-marker?private-marker=1">query</a>'
                '<a href="#fragment-marker">fragment only</a><a>missing href</a>'
                '<a href="mailto:non-http-marker@example.invalid">scheme</a>'
                '<a href="/entry">self</a><a href="/bad%20path">unsupported</a>' +
                decoys + '</body></html>'
            )

        return markup.encode("ascii")


class OffOriginCrawlSentinel(MutableCrawlGraph):
    """Serve finite terminal bytes; every original accepted contact violates exclusion."""

    def Response(self, path: str) -> GraphResponse:
        """Return complete terminal bytes without links, forwarding or remote controls."""

        return GraphResponse(404, "text/plain", b"owned-off-origin-contact-must-be-zero")


@dataclass(frozen=True, slots=True)
class GraphRequestObservation:
    """Retain each bounded original accepted contact, including partial and refused requests."""

    sequence: int
    variant: str
    accepted_at: float
    deadline_at: float
    target: str | None = None
    request_bytes: bytes = b""
    received_bytes: int = 0
    request_truncated: bool = False
    active_at_start: int = 0
    response_bytes: bytes = b""
    sent_bytes: int = 0
    completion_sequence: int | None = None
    admission_state: str = "accepted"
    failure: str | None = None
    socket_closed: bool = False

    def ToDict(self) -> dict[str, Any]:
        """Preserve bounded original binary prefixes and distinguish completion from settlement."""

        return {"sequence": self.sequence, "target": self.target,
                "request_hex": self.request_bytes.hex(), "received_bytes": self.received_bytes,
                "request_truncated": self.request_truncated, "variant": self.variant,
                "accepted_at": self.accepted_at, "deadline_at": self.deadline_at,
                "active_at_start": self.active_at_start,
                "response_hex": self.response_bytes.hex(), "sent_bytes": self.sent_bytes,
                "completion_sequence": self.completion_sequence,
                "admission_state": self.admission_state, "failure": self.failure,
                "socket_closed": self.socket_closed}


@dataclass(slots=True)
class GraphSocketOwner:
    """Own an original accepted socket before any handler can be created."""

    index: int | None
    deadline_at: float
    closing: bool = False


class CrawlGraphState:
    """Own bounded accept-time evidence, absolute request deadlines and fixed sibling gates."""

    def __init__(self, graph: MutableCrawlGraph, *, clock: Callable[[], float] = monotonic) -> None:
        """Create pure state; the clock seam supports fake-socket tests without real execution."""

        self.graph = graph
        self.graph.owner = self
        self.clock = clock
        self.lock = Lock()
        self.requests: list[GraphRequestObservation] = []
        self.errors: list[str] = []
        self.error_count = 0
        self.error_overflow = 0
        self.contact_count = 0
        self.contact_overflow = 0
        self.active = 0
        self.maximum_active = 0
        self.completed = 0
        self.invert_siblings = False
        self.branch_a_entered = Event()
        self.branch_b_completed = Event()
        self.closing = Event()
        self.connections: dict[socket.socket, GraphSocketOwner] = {}
        self.running_handlers: set[socket.socket] = set()
        self.settled_handler_owners: dict[socket.socket, GraphSocketOwner] = {}
        self.dispatch_owners: set[socket.socket] = set()
        self.idle = Event()
        self.idle.set()

    def RecordErrorLocked(self, error: str) -> None:
        """Keep fixed mechanism failures through teardown, with explicit bounded-detail overflow."""

        self.error_count += 1

        if len(self.errors) < MAX_ERRORS:
            self.errors.append(error)

        else:
            self.error_overflow += 1

    def RecordError(self, error: str) -> None:
        """Record one fixed fixture failure without suppressing it after admission closes."""

        with self.lock:
            self.RecordErrorLocked(error)

    def Accept(self, connection: socket.socket) -> None:
        """Atomically own/count every accepted socket before dispatch, even after close or quota."""

        with self.lock:
            self.contact_count += 1
            accepted_at = self.clock()
            deadline_at = accepted_at + SOCKET_TIMEOUT_SECONDS
            index = None

            if len(self.requests) < MAX_REQUESTS:
                index = len(self.requests)
                self.requests.append(GraphRequestObservation(self.contact_count, self.graph.variant,
                                                              accepted_at, deadline_at))

            else:
                self.contact_overflow += 1
                self.RecordErrorLocked("owned-contact-limit")

            self.connections[connection] = GraphSocketOwner(index, deadline_at)
            self.UpdateIdleLocked()

            if self.closing.is_set():
                self.FailLocked(connection, "owned-admission-closed", "refused")

    def FailLocked(self, connection: socket.socket, failure: str, state: str = "failed") -> None:
        """Preserve the first contact failure and count every fixed mechanism failure."""

        self.RecordErrorLocked(failure)
        owner = self.connections.get(connection) or self.settled_handler_owners.get(connection)

        if owner is not None and owner.index is not None:
            record = self.requests[owner.index]
            self.requests[owner.index] = replace(record, admission_state=state,
                                                 failure=record.failure or failure)

    def Fail(self, connection: socket.socket, failure: str) -> None:
        """Retain original interrupted/invalid request facts, including during teardown."""

        with self.lock:
            self.FailLocked(connection, failure)

    def SetVariant(self, variant: str) -> None:
        """Require every original accepted socket to settle before changing seed bytes."""

        with self.lock:
            if self.connections or self.running_handlers or self.dispatch_owners or (
                self.closing.is_set()
            ):
                raise RuntimeError("Owned graph mutation requires open admission and no sockets")

            if variant not in VARIANTS:
                raise ValueError("Unknown owned graph variant")

            self.graph.variant = variant

    def AttachSentinel(self, origin: str) -> None:
        """Require complete original idleness before binding the fixture-owned second origin."""

        with self.lock:
            if self.connections or self.running_handlers or self.dispatch_owners or (
                self.closing.is_set()
            ):
                raise RuntimeError("Owned sentinel binding requires every original owner idle")

            self.graph.sentinel_origin = origin

    def InvertSiblingCompletion(self) -> None:
        """Require idle original socket ownership before enabling the two-way sibling handshake."""

        with self.lock:
            if self.connections or self.running_handlers or self.dispatch_owners or (
                self.closing.is_set()
            ):
                raise RuntimeError("Owned graph gates require open admission and no sockets")

            self.invert_siblings = True
            self.branch_a_entered.clear()
            self.branch_b_completed.clear()

    def Observe(self) -> tuple[GraphRequestObservation, ...]:
        """Return all retained accepted contacts, including original partial/refused prefixes."""

        with self.lock:
            return tuple(self.requests)

    def Counters(self) -> dict[str, int]:
        """Distinguish exact total accepts, bounded records, overflow and actual handler overlap."""

        with self.lock:
            return {"contacts": self.contact_count, "retained_contacts": len(self.requests),
                    "contact_overflow": self.contact_overflow,
                    "active_connections": len(self.connections), "active_handlers": self.active,
                    "active_dispatches": len(self.dispatch_owners),
                    "maximum_active_handlers": self.maximum_active,
                    "completed_responses": self.completed, "errors": self.error_count,
                    "error_overflow": self.error_overflow}

    def Errors(self) -> tuple[str, ...]:
        """Return bounded fixed failure details; Counters exposes any omitted detail count."""

        with self.lock:
            return tuple(self.errors)

    def UpdateIdleLocked(self) -> None:
        """Expose idleness only after original sockets, handlers and dispatch slots settle."""

        if self.connections or self.running_handlers or self.dispatch_owners:
            self.idle.clear()

        else:
            self.idle.set()

    def WaitIdle(self, timeout: float = CLEANUP_TIMEOUT_SECONDS) -> bool:
        """Wait once on the settlement event, then atomically verify every ownership set."""

        if not 0 <= timeout <= CLEANUP_TIMEOUT_SECONDS:
            raise ValueError("Owned graph idle wait must remain bounded")

        if not self.idle.wait(timeout):
            return False

        with self.lock:
            return not (self.connections or self.running_handlers or self.dispatch_owners)

    def Remaining(self, connection: socket.socket) -> float:
        """Use one original accept-time deadline across headers, gates, sends and EOF."""

        with self.lock:
            owner = self.connections[connection]
            remaining = owner.deadline_at - self.clock()

            if self.closing.is_set():
                raise OSError("owned-admission-closed")

            if remaining <= 0:
                raise TimeoutError("owned-request-deadline")

            return remaining

    def BeginHandler(self, connection: socket.socket) -> None:
        """Measure actual handler entry using an already registered original socket owner."""

        with self.lock:
            owner = self.connections[connection]

            if self.closing.is_set():
                raise OSError("owned-admission-closed")

            self.running_handlers.add(connection)
            self.active += 1
            self.UpdateIdleLocked()
            self.maximum_active = max(self.maximum_active, self.active)

            if owner.index is not None:
                self.requests[owner.index] = replace(self.requests[owner.index],
                    active_at_start=self.active, admission_state="receiving")

    def EndHandler(self, connection: socket.socket) -> None:
        """Keep actual running-handler ownership independent of earlier socket settlement."""

        with self.lock:
            if connection in self.running_handlers:
                self.running_handlers.remove(connection)
                self.active -= 1

            self.settled_handler_owners.pop(connection, None)
            self.UpdateIdleLocked()

    def ContactOwnerLocked(self, connection: socket.socket) -> GraphSocketOwner:
        """Retain original read/send facts when teardown closes their socket first."""

        owner = self.connections.get(connection) or self.settled_handler_owners.get(connection)

        if owner is None:
            raise KeyError("owned-original-contact-missing")

        return owner

    def RecordRequest(self, connection: socket.socket, block: bytes) -> None:
        """Keep a bounded original request prefix before parsing, with explicit truncation facts."""

        with self.lock:
            index = self.ContactOwnerLocked(connection).index

            if index is not None:
                record = self.requests[index]
                received = record.received_bytes + len(block)
                self.requests[index] = replace(record,
                    request_bytes=(record.request_bytes + block)[:MAX_REQUEST_BYTES],
                    received_bytes=received, request_truncated=received > MAX_REQUEST_BYTES)

    def BeginResponse(self, connection: socket.socket, target: str) -> tuple[bytes, bool]:
        """Render only target-owned source bytes after retaining the complete original request."""

        with self.lock:
            index = self.ContactOwnerLocked(connection).index
            response = self.graph.Response(target).Wire()

            if index is not None:
                self.requests[index] = replace(self.requests[index], target=target,
                    response_bytes=response, admission_state="serving")

            return response, self.invert_siblings

    def WaitForSibling(self, connection: socket.socket, target: str) -> None:
        """B waits for actual A entry; A waits for actual B complete send and SHUT_WR."""

        if target == "/branch-a":
            self.branch_a_entered.set()
            gate = self.branch_b_completed

        elif target == "/branch-b":
            gate = self.branch_a_entered

        else:
            return

        if not gate.wait(min(GATE_TIMEOUT_SECONDS, self.Remaining(connection))):
            raise TimeoutError("owned-response-gate")

        self.Remaining(connection)

    def RecordSent(self, connection: socket.socket, count: int) -> None:
        """Count only bytes returned by actual sends; intended bytes remain a separate field."""

        with self.lock:
            index = self.ContactOwnerLocked(connection).index

            if index is not None:
                record = self.requests[index]
                self.requests[index] = replace(record, sent_bytes=record.sent_bytes + count)

    def CompleteResponse(self, connection: socket.socket, target: str) -> None:
        """Publish completion only after the original complete response has been half-closed."""

        with self.lock:
            self.completed += 1
            index = self.ContactOwnerLocked(connection).index

            if index is not None:
                self.requests[index] = replace(self.requests[index],
                    completion_sequence=self.completed, admission_state="completed")

        if target == "/branch-b":
            self.branch_b_completed.set()

    def CloseAdmission(self) -> None:
        """Atomically deny all later dispatch and release both fixed gates for original cleanup."""

        with self.lock:
            self.closing.set()
            self.branch_a_entered.set()
            self.branch_b_completed.set()

    def CloseConnection(self, connection: socket.socket) -> None:
        """Actively close an original socket before releasing its ownership or evidence facts."""

        with self.lock:
            owner = self.connections.get(connection)

            if owner is None or owner.closing:
                return

            owner.closing = True

            if owner.index is not None:
                record = self.requests[owner.index]

                if record.completion_sequence is None and record.failure is None:
                    self.FailLocked(connection, "owned-contact-interrupted")

        try:
            connection.shutdown(socket.SHUT_RDWR)

        except OSError:
            self.RecordError("owned-socket-shutdown-failure")

        try:
            connection.close()

        except OSError:
            self.RecordError("owned-socket-close-failure")

            with self.lock:
                owner.closing = False

            return

        with self.lock:
            owner = self.connections.pop(connection, None)

            if owner is not None:
                if connection in self.running_handlers:
                    self.settled_handler_owners[connection] = owner

                if owner.index is not None:
                    self.requests[owner.index] = replace(self.requests[owner.index],
                                                        socket_closed=True)

            self.UpdateIdleLocked()

    def CloseConnections(self) -> None:
        """After listener admission joins, settle every remaining original accepted socket."""

        with self.lock:
            connections = tuple(self.connections)

        for connection in connections:
            self.CloseConnection(connection)


class CrawlGraphHandler(BaseRequestHandler):
    """Serve only finite anonymous GET responses, retaining original partial contact evidence."""

    def Handle(self) -> None:
        """Use the original absolute deadline; never renew it on a partial read or gate progress."""

        state: CrawlGraphState = self.server.state
        connection: socket.socket = self.request

        try:
            state.BeginHandler(connection)
            raw = bytearray()

            while b"\r\n\r\n" not in raw:
                connection.settimeout(state.Remaining(connection))
                block = connection.recv(min(1024, MAX_REQUEST_BYTES + 1 - len(raw)))
                state.RecordRequest(connection, block)
                state.Remaining(connection)

                if not block or len(raw) >= MAX_REQUEST_BYTES:
                    raise ValueError("invalid-owned-request")

                raw.extend(block)

            first_line = bytes(raw).split(b"\r\n", 1)[0].decode("ascii")
            method, target, version = first_line.split(" ")

            if method != "GET" or version not in ("HTTP/1.0", "HTTP/1.1") or (
                not target.startswith("/") or len(target) > 1024 or
                len(raw) > MAX_REQUEST_BYTES or not bytes(raw).endswith(b"\r\n\r\n")
            ):
                raise ValueError("invalid-owned-request")

            response, invert_siblings = state.BeginResponse(connection, target)

            if invert_siblings:
                state.WaitForSibling(connection, target)

            sent = 0

            while sent < len(response):
                connection.settimeout(state.Remaining(connection))
                count = connection.send(response[sent:])

                if count <= 0:
                    raise OSError("owned-response-short-send")

                sent += count
                state.RecordSent(connection, count)
                state.Remaining(connection)

            connection.shutdown(socket.SHUT_WR)
            state.Remaining(connection)
            state.CompleteResponse(connection, target)

        except (OSError, ValueError, KeyError):
            state.Fail(connection, "owned-request-failure")

        finally:
            state.EndHandler(connection)

    # Socketserver owns the external callback name; implementation follows house naming.
    handle = Handle


class CrawlGraphServer(TCPServer):
    """Own accepted sockets before explicitly starting bounded non-daemon handler threads."""

    allow_reuse_address = False

    def __init__(self, *, sentinel_only: bool = False) -> None:
        """Bind one owned ephemeral origin with a fixed main or terminal-sentinel graph."""

        self.slots = BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self.handlers: list[Thread] = []
        super().__init__(("127.0.0.1", 0), CrawlGraphHandler)
        self.timeout = 0.05
        graph_type = OffOriginCrawlSentinel if sentinel_only else MutableCrawlGraph
        self.state = CrawlGraphState(graph_type(f"http://127.0.0.1:{self.server_address[1]}"))

    def GetRequest(self) -> tuple[socket.socket, tuple[str, int]]:
        """Register every accepted socket atomically before any dispatch can start a handler."""

        request, client_address = self.socket.accept()
        self.state.Accept(request)

        return request, client_address

    def ProcessRequest(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        """Close admission and thread creation through the same original state ownership lock."""

        with self.state.lock:
            owner = self.state.connections[request]
            allowed = not self.state.closing.is_set() and owner.index is not None
            acquired = allowed and self.slots.acquire(blocking=False)

            if not acquired:
                self.state.FailLocked(request, "owned-dispatch-refused", "refused")

            else:
                self.state.dispatch_owners.add(request)
                self.state.UpdateIdleLocked()
                thread = Thread(target=self.ProcessRequestThread, args=(request, client_address),
                                name="owned-native-crawl-response", daemon=False)
                self.handlers.append(thread)

                try:
                    thread.start()

                except BaseException:
                    self.slots.release()
                    self.state.dispatch_owners.remove(request)
                    self.state.UpdateIdleLocked()
                    self.state.FailLocked(request, "owned-handler-start-failure")
                    acquired = False

        if not acquired:
            self.state.CloseConnection(request)

    def ProcessRequestThread(self, request: socket.socket,
                             client_address: tuple[str, int]) -> None:
        """Close the original accepted socket and release its bounded slot after actual work."""

        try:
            self.finish_request(request, client_address)

        except Exception:
            self.state.Fail(request, "owned-handler-failure")

        finally:
            try:
                self.state.CloseConnection(request)

            finally:
                self.ReleaseDispatch(request)

    def ReleaseDispatch(self, request: socket.socket) -> None:
        """Release the actual original slot before exposing settled dispatch ownership."""

        with self.state.lock:
            self.slots.release()
            self.state.dispatch_owners.remove(request)
            self.state.UpdateIdleLocked()

    def Settle(self, listener: Thread) -> None:
        """Stop/join admission first, then close sockets and join original handlers once bounded."""

        deadline = monotonic() + CLEANUP_TIMEOUT_SECONDS
        self.state.CloseAdmission()

        if listener.ident is not None:
            listener.join(timeout=max(0, deadline - monotonic()))

        self.server_close()

        if listener.is_alive():
            listener.join(timeout=max(0, deadline - monotonic()))

        if listener.is_alive():
            self.state.RecordError("owned-listener-cleanup-limit")

        self.state.CloseConnections()

        for handler in self.handlers:
            if handler.ident is not None:
                handler.join(timeout=max(0, deadline - monotonic()))

        if listener.is_alive() or any(handler.is_alive() for handler in self.handlers) or (
            self.state.Counters()["active_connections"] != 0 or
            self.state.Counters()["active_handlers"] != 0 or
            self.state.Counters()["active_dispatches"] != 0
        ):
            self.state.RecordError("owned-handler-cleanup-limit")

            raise RuntimeError("Owned graph original cleanup did not settle")

    # Socketserver owns these exact dispatch attributes, not the implementation function names.
    get_request = GetRequest
    process_request = ProcessRequest


@dataclass(frozen=True, slots=True)
class OwnedCrawlGraph:
    """Expose local fixture controls and exact accept-time facts to acceptance consumers."""

    state: CrawlGraphState
    thread: Thread
    graph: MutableCrawlGraph
    sentinel_state: CrawlGraphState
    sentinel_thread: Thread
    sentinel_origin: str


@contextmanager
def OwnedNativeCrawlGraph() -> Iterator[OwnedCrawlGraph]:
    """Start only an explicit loopback target; settle admission before bounded original handlers."""

    server = CrawlGraphServer()

    try:
        sentinel = CrawlGraphServer(sentinel_only=True)

    except BaseException:
        server.server_close()

        raise

    server.state.graph.AttachSentinel(sentinel.state.graph.origin)
    ready, sentinel_ready = Event(), Event()

    def Serve(owner: CrawlGraphServer, readiness: Event) -> None:
        """Signal one bound original origin and preserve all mechanism errors through cleanup."""

        readiness.set()

        try:
            while not owner.state.closing.is_set():
                owner.handle_request()

        except (OSError, ValueError):
            owner.state.RecordError("owned-listener-failure")

    thread = Thread(target=Serve, args=(server, ready),
                    name="owned-native-crawl-graph", daemon=False)
    sentinel_thread = Thread(target=Serve, args=(sentinel, sentinel_ready),
                             name="owned-native-crawl-sentinel", daemon=False)

    try:
        thread.start()
        sentinel_thread.start()

        if not ready.wait(2) or not sentinel_ready.wait(2) or (
            not thread.is_alive() or not sentinel_thread.is_alive()
        ):
            raise RuntimeError("Both owned crawl origins must become ready")

        yield OwnedCrawlGraph(server.state, thread, server.state.graph, sentinel.state,
                              sentinel_thread, sentinel.state.graph.origin)

    finally:
        try:
            server.Settle(thread)

        finally:
            sentinel.Settle(sentinel_thread)


def CrawlGraphOracle() -> dict[str, Any]:
    """Read handwritten truth without importing any scanner, parser, schema examples or target."""

    path = Path(__file__).parent / "fixtures/native_crawl_graph/oracle.v1.json"

    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
