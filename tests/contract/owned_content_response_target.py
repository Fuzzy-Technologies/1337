# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite mutable IPv4/IPv6 source; reviewed dispatch/socket owners, no remote controls or proxy."""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from socketserver import BaseRequestHandler, TCPServer
from threading import BoundedSemaphore, Event, Thread
from time import monotonic
from urllib.parse import urlsplit

from tests.contract.owned_content_response_oracle import (
    LONG_PATH,
    PRIMARY_PATH,
    SECOND_PATH,
    SEED_BODY,
    SEED_PATH,
    SEGMENT_PATH,
    SOURCE_PATHS,
    CaseMatrix,
    ContentCase,
    Headers,
)
from tests.integration.test_owned_response_product import HeldPeerSignal
from tests.native_crawl_acceptance_helpers import NativeCaseEvidence
from tests.native_crawl_graph_helpers import (
    MAX_CONCURRENT_REQUESTS,
    MAX_REQUESTS,
    CrawlGraphServer,
    CrawlGraphState,
    GraphRequestObservation,
    GraphResponse,
    GraphSocketOwner,
    MutableCrawlGraph,
)

SOURCE_REQUEST_SECONDS = 7
SOURCE_REQUEST_BYTES = 2048
CASES = {case.name: case for case in CaseMatrix()}


@dataclass(frozen=True, slots=True)
class ContentWire(GraphResponse):
    """Return exact independently authored wire and its explicit EOF behavior."""

    original_wire: bytes = b""
    eof_mode: str = "close"

    def Wire(self) -> bytes:
        """Keep original order/case/values/body/trailing bytes, without normalization."""

        return self.original_wire


class MutableContentSource(MutableCrawlGraph):
    """Select fixed test-owned source variants locally; the selected URL remains identical."""

    def __init__(self, origin: str, case: str = "missing") -> None:
        """Construct only pure state for one exact anonymous literal ephemeral origin."""

        parsed = urlsplit(origin)
        authority = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"

        if parsed.hostname not in ("127.0.0.1", "::1") or parsed.port is None or not (
            1024 <= parsed.port <= 65535) or origin != f"http://{authority}:{parsed.port}" or (
            case not in CASES
        ):
            raise ValueError("Independent source needs its literal owned origin and fixed case")

        self.origin, self.variant = origin, case
        self.owner = None
        self.sentinel_origin = None

    def Url(self, path: str = PRIMARY_PATH) -> str:
        """Return only one of five explicit concrete test-owned paths."""

        if path not in SOURCE_PATHS:
            raise ValueError("Unknown independent source path")

        return self.origin + path

    def SelectedUrls(self) -> tuple[str, ...]:
        """Describe only the later three-URL native pipeline, without enrolling any scope."""

        return tuple(sorted(self.Url(path) for path in (SEED_PATH, PRIMARY_PATH, SECOND_PATH)))

    def SetCase(self, case: str) -> None:
        """Change source bytes only through local fixture API, after all original owners settle."""

        if case not in CASES:
            raise ValueError("Unknown independent content case")

        if self.owner is None:
            self.variant = case

        else:
            if not isinstance(self.owner, ContentResponseState):
                raise RuntimeError("Content source must retain its original state owner")

            self.owner.SelectCase(case)

    def SetVariant(self, variant: str) -> None:
        """Keep inherited local fixture spelling within this source's explicit case set."""

        self.SetCase(variant)

    def SeedBody(self) -> bytes:
        """Return only the new handwritten two-link seed, independent of the older graph."""

        return SEED_BODY

    def Response(self, path: str) -> ContentWire:
        """Serve finite handwritten source bytes without consulting any expected detector truth."""

        if path == PRIMARY_PATH:
            case = CASES[self.variant]

        elif path == SECOND_PATH:
            case = CASES["second-concrete-path"]

        elif path == LONG_PATH:
            case = CASES["path-limit"]

        elif path == SEGMENT_PATH:
            case = CASES["segments-limit"]

        elif path == SEED_PATH:
            case = ContentCase("source-link-seed", Headers(SEED_BODY), SEED_BODY)

        else:
            case = ContentCase("unknown-source-path",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", b"")

        return ContentWire(200, "application/octet-stream", case.body,
            original_wire=case.Wire(), eof_mode=case.eof_mode)


class ContentResponseState(CrawlGraphState):
    """Reuse original socket/dispatch ownership with one seven-second source request deadline."""

    def __init__(self, source: MutableContentSource,
        *, clock: Callable[[], float] = monotonic) -> None:
        """Create pure locks/events and bounded additional actual peer/EOF facts only."""

        super().__init__(source, clock=clock)
        self.endpoint_facts: dict[int, dict[str, object]] = {}
        self.original_deadlines: dict[socket.socket, float] = {}
        self.request_ready = Event()
        self.body_sent = Event()

    def Accept(self, connection: socket.socket) -> None:
        """Register/count accepted sockets before dispatch, using one nonrenewing source bound."""

        with self.lock:
            self.contact_count += 1
            accepted_at = self.clock()
            deadline_at = accepted_at + SOURCE_REQUEST_SECONDS
            index = None

            if len(self.requests) < MAX_REQUESTS:
                index = len(self.requests)
                self.requests.append(GraphRequestObservation(self.contact_count,
                    self.graph.variant, accepted_at, deadline_at))
                self.original_deadlines[connection] = deadline_at

            else:
                self.contact_overflow += 1
                self.RecordErrorLocked("owned-contact-limit")

            self.connections[connection] = GraphSocketOwner(index, deadline_at)
            self.UpdateIdleLocked()

            if self.closing.is_set():
                self.FailLocked(connection, "owned-admission-closed", "refused")

    def SelectCase(self, case: str) -> None:
        """Require accepted sockets, running handlers and original dispatch slots all idle."""

        with self.lock:
            if case not in CASES:
                raise ValueError("Unknown independent content case")

            if self.connections or self.running_handlers or self.dispatch_owners or (
                self.closing.is_set()
            ):
                raise RuntimeError("Content mutation requires all original owners idle")

            self.graph.variant = case
            self.request_ready.clear()
            self.body_sent.clear()

    def RecordEndpoints(self, connection: socket.socket, peer: tuple, local: tuple) -> None:
        """Retain actual accepted local/peer address+port before any request handler can start."""

        with self.lock:
            owner = self.connections[connection]

            if owner.index is not None:
                self.endpoint_facts[owner.index] = {"peer_address": peer[0], "peer_port": peer[1],
                    "local_address": local[0], "local_port": local[1], "peer_terminal": None}

    def RecordHeldTerminal(self, connection: socket.socket, data: bytes | None = None,
        error: OSError | None = None) -> bool:
        """Preserve actual EOF/reset separately from local-close artifacts and unknown failures."""

        with self.lock:
            owner = self.ContactOwnerLocked(connection)
            signal = HeldPeerSignal("peer-receive", not owner.closing and not self.closing.is_set(),
                data, error, within_hold=self.clock() < owner.deadline_at)

            if owner.index is not None:
                self.endpoint_facts[owner.index]["peer_terminal"] = signal

            return signal["before_local_close"] is True and signal["within_hold"] is True and (
                signal["kind"] in ("eof", "peer-reset"))

    def CompleteHeldResponse(self, connection: socket.socket) -> None:
        """Record full sends plus actual peer termination without claiming a local EOF was sent."""

        with self.lock:
            self.completed += 1
            owner = self.ContactOwnerLocked(connection)

            if owner.index is not None:
                self.requests[owner.index] = replace(self.requests[owner.index],
                    completion_sequence=self.completed, admission_state="sent-peer-ended")

    def EndpointFacts(self) -> dict[int, dict[str, object]]:
        """Return bounded detached actual endpoint/terminal facts after cleanup."""

        with self.lock:
            return {index: {**facts, "peer_terminal": None if facts["peer_terminal"] is None else
                dict(facts["peer_terminal"])} for index, facts in self.endpoint_facts.items()}

    def WaitOriginalIdle(self) -> bool:
        """Wait once within original contact deadlines before any local-close-induced EOF exists."""

        with self.lock:
            active = set(self.connections) | self.running_handlers | self.dispatch_owners
            now = self.clock()
            deadline = min((self.original_deadlines.get(owner, now) for owner in active),
                default=now)

        return self.WaitIdle(min(3, max(0, deadline - now)))


class ContentResponseHandler(BaseRequestHandler):
    """Serve one finite original response, with optional held EOF until the actual peer exits."""

    def Handle(self) -> None:
        """Retain original partial GET/sends under one deadline; never renew on progress."""

        state: ContentResponseState = self.server.state
        connection: socket.socket = self.request

        try:
            state.BeginHandler(connection)
            raw = bytearray()

            while b"\r\n\r\n" not in raw:
                connection.settimeout(state.Remaining(connection))
                block = connection.recv(min(1024, SOURCE_REQUEST_BYTES + 1 - len(raw)))
                state.RecordRequest(connection, block)
                state.Remaining(connection)

                if not block or len(raw) + len(block) > SOURCE_REQUEST_BYTES:
                    raise ValueError("invalid-owned-content-request")

                raw.extend(block)

            method, path, version = bytes(raw).split(b"\r\n", 1)[0].decode("ascii").split(" ")

            if method != "GET" or version != "HTTP/1.1" or not path.startswith("/") or (
                len(raw) > SOURCE_REQUEST_BYTES or not bytes(raw).endswith(b"\r\n\r\n")
            ):
                raise ValueError("invalid-owned-content-request")

            response, _unused = state.BeginResponse(connection, path)
            state.request_ready.set()
            sent = 0

            while sent < len(response):
                connection.settimeout(state.Remaining(connection))
                count = connection.send(response[sent:])

                if count <= 0:
                    raise OSError("owned-content-short-send")

                sent += count
                state.RecordSent(connection, count)
                state.Remaining(connection)

            state.body_sent.set()

            if state.graph.Response(path).eof_mode == "hold-until-peer-eof":
                connection.settimeout(state.Remaining(connection))

                try:
                    remote = state.RecordHeldTerminal(connection, data=connection.recv(1))

                except OSError as error:
                    remote = state.RecordHeldTerminal(connection, error=error)

                if not remote:
                    raise ValueError("owned-content-peer-not-observed")

                state.Remaining(connection)
                state.CompleteHeldResponse(connection)

            else:
                connection.shutdown(socket.SHUT_WR)
                connection.settimeout(state.Remaining(connection))

                try:
                    tail = connection.recv(SOURCE_REQUEST_BYTES + 1 - len(raw))

                except OSError as error:
                    state.RecordHeldTerminal(connection, error=error)

                    raise

                state.RecordRequest(connection, tail)
                remote = state.RecordHeldTerminal(connection, data=tail)
                state.Remaining(connection)

                if tail or not remote:
                    raise ValueError("owned-content-normal-request-not-complete")

                state.CompleteResponse(connection, path)

        except (OSError, ValueError, KeyError):
            state.Fail(connection, "owned-content-request-failure")

        finally:
            state.EndHandler(connection)

    handle = Handle


class ContentResponseServer(CrawlGraphServer):
    """Use reviewed slot/thread/close owners for one IPv4 or IPv6 anonymous owned listener."""

    def __init__(self, address: str, case: str) -> None:
        """Bind only an explicitly named literal loopback family; launch no thread here."""

        if address not in ("127.0.0.1", "::1") or case not in CASES:
            raise ValueError("Independent source accepts only its fixed loopback family and case")

        self.address_family = socket.AF_INET6 if address == "::1" else socket.AF_INET
        self.slots = BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self.handlers = []
        TCPServer.__init__(self, (address, 0), ContentResponseHandler)

        try:
            self.timeout = 0.05
            authority = f"[{address}]" if address == "::1" else address
            source = MutableContentSource(f"http://{authority}:{self.server_address[1]}", case)
            self.state = ContentResponseState(source)

        except BaseException:
            self.server_close()

            raise

    def GetRequest(self) -> tuple[socket.socket, tuple]:
        """Own every accepted socket before endpoint inspection and original handler creation."""

        connection, peer = self.socket.accept()
        self.state.Accept(connection)

        try:
            self.state.RecordEndpoints(connection, peer, connection.getsockname())

        except OSError:
            self.state.Fail(connection, "owned-content-endpoint-failure")
            self.state.CloseConnection(connection)

            raise

        return connection, peer

    get_request = GetRequest


def FinalSourceFacts(server: ContentResponseServer | None, thread: Thread | None,
    yielded: bool) -> dict[str, object]:
    """Expose original post-cleanup counts/errors/bytes, never infer zero from absent records."""

    if server is None:
        return {"schema_version": 1, "target_yielded": yielded, "owner_state": "unobserved"}

    counters = server.state.Counters()
    alive = thread is not None and thread.is_alive()
    settled = not alive and server.socket.fileno() == -1 and all(counters[name] == 0 for name in (
        "active_connections", "active_handlers", "active_dispatches"))

    return {"schema_version": 1, "target_yielded": yielded,
        "owner_state": "settled" if settled else "unsettled", "listener_alive": alive,
        "listener_closed": server.socket.fileno() == -1, "origin": server.state.graph.origin,
        "counters": counters, "errors": list(server.state.Errors()),
        "contacts": [contact.ToDict() for contact in server.state.Observe()],
        "accepted_endpoints": server.state.EndpointFacts()}


@contextmanager
def OwnedContentResponseTarget(evidence: NativeCaseEvidence, *, address: str = "127.0.0.1",
    case: str = "missing") -> Iterator[ContentResponseState]:
    """Own one finite family/source listener and always retain actual final facts before asserts."""

    server = thread = None
    yielded = False
    cleanup_returned = False
    cleanup_failure = None
    idle_before_close = None

    def Serve(owner: ContentResponseServer, ready: Event) -> None:
        """Signal already-bound readiness and keep listener mechanism failures through teardown."""

        ready.set()

        try:
            while not owner.state.closing.is_set():
                owner.handle_request()

        except (OSError, ValueError):
            owner.state.RecordError("owned-content-listener-failure")

    try:
        server = ContentResponseServer(address, case)
        ready = Event()
        thread = Thread(target=Serve, args=(server, ready), daemon=False)
        thread.start()

        if not ready.wait(2) or not thread.is_alive():
            raise RuntimeError("Owned content listener did not become ready")

        yielded = True

        yield server.state

    finally:
        try:
            if server is not None:
                try:
                    idle_before_close = server.state.WaitOriginalIdle()

                finally:
                    if thread is None:
                        server.server_close()

                    else:
                        server.Settle(thread)

                cleanup_returned = True

        except BaseException as error:
            cleanup_failure = type(error).__name__ if type(error) in (
                OSError, RuntimeError, AssertionError) else "other"

            raise

        finally:
            final = FinalSourceFacts(server, thread, yielded)
            final.update(cleanup_returned=cleanup_returned, cleanup_failure=cleanup_failure,
                idle_before_local_close=idle_before_close)
            evidence.Json("content-source-final.json", final)
