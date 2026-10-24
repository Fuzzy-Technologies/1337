# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Four-route owned pipeline target reusing reviewed original socket ownership and cleanup."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Thread

from tests.contract.native_response_header_oracle import FrozenOriginals
from tests.native_crawl_acceptance_helpers import FinalNativeTargetFacts, NativeCaseEvidence
from tests.native_crawl_graph_helpers import (
    CrawlGraphServer,
    CrawlGraphState,
    GraphResponse,
    MutableCrawlGraph,
    OwnedCrawlGraph,
)

SEED = "/native-header-seed"
CASES = ("missing", "fixed", "body-decoy")
PATHS = (SEED, "/zap-passive/body-decoy", "/zap-passive/fixed", "/zap-passive/missing")
SEED_BODY = (b'<!doctype html><html><body><a href="/zap-passive/missing">one</a>'
    b'<a href="/zap-passive/fixed">two</a><a href="/zap-passive/body-decoy">three</a>'
    b'</body></html>')


@dataclass(frozen=True, slots=True)
class OriginalPipelineResponse(GraphResponse):
    """Serve the independently frozen original wire without a production response template."""

    original_wire: bytes = b""

    def Wire(self) -> bytes:
        """Return complete frozen original bytes, including their exact header ordering."""

        return self.original_wire


class HeaderPipelineGraph(MutableCrawlGraph):
    """Expose exactly one handwritten link page and three unchanged admitted capture routes."""

    def Url(self, path: str) -> str:
        """Require one of four explicit anonymous paths on this owned origin."""

        if path not in PATHS:
            raise ValueError("Header pipeline URL is outside the four-route fixture")

        return self.origin + path

    def SelectedUrls(self) -> tuple[str, ...]:
        """Select four canonical lexical URLs; selection alone never schedules a request."""

        return tuple(self.Url(path) for path in PATHS)

    def Response(self, path: str) -> GraphResponse:
        """Render only fixed source bytes; never consult a detector or descriptive alert count."""

        if path == SEED:
            return GraphResponse(200, "text/html; charset=utf-8", SEED_BODY)

        if path in PATHS[1:]:
            source = FrozenOriginals()[path.rsplit("/", 1)[1]]

            return OriginalPipelineResponse(200, "text/html; charset=utf-8", source["body"],
                original_wire=source["response"])

        return GraphResponse(404, "text/plain", b"unselected pipeline route")


class HeaderPipelineServer(CrawlGraphServer):
    """Replace the inert graph before any admission thread exists, preserving socket owners."""

    def __init__(self) -> None:
        """Bind one owned ephemeral IPv4 origin using the reviewed server lifecycle."""

        super().__init__()
        self.state = CrawlGraphState(HeaderPipelineGraph(self.state.graph.origin))


@contextmanager
def HeaderPipelineTarget(evidence: NativeCaseEvidence) -> Iterator[OwnedCrawlGraph]:
    """Always settle and retain both held origins, including consumer or cleanup failures."""

    target = server = sentinel = thread = sentinel_thread = None
    yielded = False

    def Serve(owner: CrawlGraphServer, gate: Event) -> None:
        """Signal already-bound readiness, retaining mechanism failures without target probes."""

        gate.set()

        try:
            while not owner.state.closing.is_set():
                owner.handle_request()

        except (OSError, ValueError):
            owner.state.RecordError("owned-pipeline-listener-failure")

    try:
        server = HeaderPipelineServer()
        sentinel = CrawlGraphServer(sentinel_only=True)
        ready, sentinel_ready = Event(), Event()
        thread = Thread(target=Serve, args=(server, ready), daemon=False)
        sentinel_thread = Thread(target=Serve, args=(sentinel, sentinel_ready), daemon=False)
        target = OwnedCrawlGraph(server.state, thread, server.state.graph, sentinel.state,
            sentinel_thread, sentinel.state.graph.origin)
        thread.start()
        sentinel_thread.start()

        if not ready.wait(2) or not sentinel_ready.wait(2) or (
            not thread.is_alive() or not sentinel_thread.is_alive()
        ):
            raise RuntimeError("Both pipeline-owned origins must become ready")

        yielded = True

        yield target

    finally:
        try:
            if server is not None:
                if thread is None:
                    server.server_close()

                else:
                    server.Settle(thread)

        finally:
            try:
                if sentinel is not None:
                    if sentinel_thread is None:
                        sentinel.server_close()

                    else:
                        sentinel.Settle(sentinel_thread)

            finally:
                final = FinalNativeTargetFacts(target)
                final["target_yielded"] = yielded

                if target is None:
                    final["partial_owners"] = {
                        name: None if owner is None else {"counters": owner.state.Counters(),
                            "errors": list(owner.state.Errors()),
                            "listener_closed": owner.socket.fileno() == -1}
                        for name, owner in (("main", server), ("sentinel", sentinel))}

                evidence.Json("target-final.json", final)
