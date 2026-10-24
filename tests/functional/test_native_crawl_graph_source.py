# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check owned graph source/rendering without claiming runtime success."""

from __future__ import annotations

import ast
import errno
import json
import socket
from collections.abc import Callable
from pathlib import Path
from threading import BoundedSemaphore
from types import SimpleNamespace

import pytest

import tests.native_crawl_graph_helpers as graph_helpers
from tests.native_crawl_graph_helpers import (
    MAX_ERRORS,
    MAX_REQUEST_BYTES,
    MAX_REQUESTS,
    CrawlGraphHandler,
    CrawlGraphOracle,
    CrawlGraphServer,
    CrawlGraphState,
    MutableCrawlGraph,
    OffOriginCrawlSentinel,
)


def test_SourceVariantsChangeOnlyBytesAtTheIdenticalSelectedSeed() -> None:
    """Keep selection/URL fixed while target-owned source removes or hides the complete graph."""

    graph = MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153")
    selected = graph.SelectedUrls()
    seed = graph.Url("/entry")
    variants = {}

    for variant in ("positive", "fixed", "decoy", "redirect"):
        graph.SetVariant(variant)
        variants[variant] = graph.Response("/entry").body
        assert graph.Url("/entry") == seed, "A content mutation must preserve the identical seed."
        assert graph.SelectedUrls() == selected, "Changing content must not reselect graph URLs."

    assert len(set(variants.values())) == 4, "Each fixture control must actually change seed bytes."
    assert b'<a href="/branch-a">A</a>' in variants["positive"], (
        "The positive seed must contain a live explicit edge into the linked graph."
    )
    assert b"<a " not in variants["fixed"], "The fixed source must remove every seed edge."
    assert b"<!-- <a " in variants["decoy"] and b"<script>" in variants["decoy"] and (
        b"<style>" in variants["decoy"]
    ), "The lexical-decoy source must contain comment, script and style controls."
    assert selected == tuple(sorted(set(selected))) and 1 <= len(selected) <= 16, (
        "The selected graph must remain a sorted bounded exact URL set."
    )


def test_HandwrittenGraphOracleAccountsForEveryExplicitSlot() -> None:
    """Validate the oracle's own finite arithmetic without asking production to define truth."""

    oracle = CrawlGraphOracle()
    selected = oracle["selected_paths"]
    positive = oracle["variants"]["positive"]
    flattened = [path for wave in positive["expected_waves"] for path in wave]
    assert selected == sorted(set(selected)) and len(selected) == 13, (
        "The independently declared selected set must retain all thirteen controls."
    )
    assert flattened == positive["expected_commit_order"] and len(flattened) == 7, (
        "The positive oracle must explicitly declare seven breadth/lexical model transitions."
    )

    for path, frontier in positive["expected_frontiers"].items():
        entries = frontier["entries"]
        ordinals = [ordinal for entry in entries for ordinal in entry["ordinals"]]
        assert path in selected and all(entry["path"] in selected for entry in entries), (
            "Every positive expected source and candidate must belong to the selected set."
        )
        assert len(ordinals) == len(set(ordinals)), "Expected slot ownership must be disjoint."
        assert len(ordinals) + sum(frontier["exclusion_counts"].values()) == (
            frontier["anchor_count"]
        ), "Handwritten exclusion counts and ordinals must account for the full anchor count."
        assert [entry["path"] for entry in entries] == sorted(entry["path"] for entry in entries), (
            "Expected candidate output must be lexical even when source anchors are reversed."
        )

    assert set(oracle["zero_contact_paths"]).isdisjoint(flattened), (
        "Selected lexical decoys and rejected destinations must receive zero positive contact."
    )
    assert all(oracle["variants"][name]["expected_commit_order"] == ["/entry"]
               for name in ("fixed", "decoy")), (
        "Removed/hidden live edges must leave only the same seed reachable."
    )


def test_OwnedResponsesHaveExactCompleteFiniteFramingAndIndependentLeafBytes() -> None:
    """Inspect in-memory wire bytes only; no socket, worker, scanner or helper process runs."""

    graph = MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153")
    oracle = CrawlGraphOracle()

    for path in oracle["selected_paths"]:
        response = graph.Response(path)
        wire = response.Wire()
        header, body = wire.split(b"\r\n\r\n", 1)
        assert body == response.body, "Complete response framing must preserve exact served bytes."
        assert f"Content-Length: {len(body)}".encode("ascii") in header.split(b"\r\n"), (
            "Each response must explicitly frame its entire finite body."
        )
        assert b"Connection: close" in header and len(wire) < 4096, (
            "The finite target must close responses and remain well below worker body ceilings."
        )

    for path, expected in oracle["leaf_responses"].items():
        response = graph.Response(path)
        assert (response.status, response.content_type.split(";", 1)[0], response.body) == (
            expected["status"], expected["media_type"], expected["body"].encode("ascii")
        ), "Target response bytes must match separately handwritten leaf truth."
        assert response.location == expected.get("location"), (
            "Only the explicit redirect control may carry its declared local Location."
        )


def test_ExplicitGitHandoffRetainsIndependentTruthAndFailedWorkUnassessed() -> None:
    """Freeze positive/fixed/HTML/redirect expectations before any actual checker consumption."""

    oracle = CrawlGraphOracle()
    handoff = oracle["git_handoff"]
    assert [(case["id"], case["expected_match"]) for case in handoff["cases"]] == [
        ("crawl-git-positive", True), ("crawl-git-fixed", False),
        ("crawl-git-html-decoy", False), ("crawl-git-redirect", False),
    ], "The independent native Git matrix must remain exactly one positive and three controls."
    assert handoff["policy"] == {"impact": "STANDARD", "capability": "web.git-head-check",
        "requires_separate_permission": True, "requires_exact_plan_confirmation": True}, (
        "SAFE crawl approval must grant no automatic STANDARD Git check authority."
    )
    assert handoff["endpoint_identity"] == {"crawl": "structural-json-key",
        "git": "legacy-exact-url", "automatic_join": False}, (
        "The existing checker cannot silently join its legacy Endpoint to a structural key."
    )
    assert handoff["failed_or_unexecuted_work_counts_as_negative"] is False and (
        oracle["source_checkpoint_runtime_acceptance"] == "not-run"
    ), "Source shape checks cannot claim successful scanner/product acceptance."


def test_TargetImplementationImportsNoProductionParserOrOracleCatalog() -> None:
    """Keep owned payload generation independent and listener startup out of module import."""

    path = Path(__file__).parents[1] / "native_crawl_graph_helpers.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name is not None and name.startswith("fuzzy1337") for name in imports), (
        "Target/oracle source must never consult production parser or body catalog modules."
    )
    assert not any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                   for node in tree.body), "Importing fixture definitions must start no target."


class FakeGraphClock:
    """Advance only when a pure test requests it; never consult or wait for wall time."""

    def __init__(self) -> None:
        """Create a deterministic absolute clock shared by state and fake socket reads."""

        self.now = 10.0

    def __call__(self) -> float:
        """Return the current test-owned instant without any real timing operation."""

        return self.now


class FakeGraphSocket:
    """Model original receive/send/close facts without creating an OS socket or descriptor."""

    def __init__(self, *, blocks: tuple[bytes, ...] = (), clock: FakeGraphClock | None = None,
                 advances: tuple[float, ...] = (), events: list[str] | None = None) -> None:
        """Keep fixed original inputs and deterministic per-read fake-clock advancement."""

        self.blocks = list(blocks)
        self.clock = clock
        self.advances = list(advances)
        self.events = [] if events is None else events
        self.timeouts: list[float] = []
        self.sent = bytearray()
        self.closed = False
        self.shutdowns: list[int] = []
        self.on_recv: Callable[[], None] | None = None
        self.on_send: Callable[[], None] | None = None

    def SetTimeout(self, value: float) -> None:
        """Record the original remaining budget supplied to each independent I/O operation."""

        self.timeouts.append(value)

    def Recv(self, limit: int) -> bytes:
        """Return one bounded predetermined prefix and advance only the explicit fake clock."""

        if self.clock is not None and self.advances:
            self.clock.now += self.advances.pop(0)

        block = self.blocks.pop(0) if self.blocks else b""

        if self.on_recv is not None:
            self.on_recv()

        assert len(block) <= limit, "The fake must preserve the fixture's real recv byte ceiling."

        return block

    def Send(self, block: bytes) -> int:
        """Record the bytes actually accepted by the fake send contract."""

        self.sent.extend(block)

        if self.on_send is not None:
            self.on_send()

        return len(block)

    def Shutdown(self, mode: int) -> None:
        """Record half-close/full-close ordering without touching a kernel connection."""

        self.shutdowns.append(mode)
        self.events.append("socket-shutdown")

    def Close(self) -> None:
        """Record actual modeled closure independently of response completion."""

        self.closed = True
        self.events.append("socket-close")

    settimeout = SetTimeout
    recv = Recv
    send = Send
    shutdown = Shutdown
    close = Close


class FakeGraphGate:
    """Model fixed sibling handshakes without starting or waiting for threads."""

    def __init__(self, *, on_wait: Callable[[], None] | None = None) -> None:
        """Create a closed gate and retain each bounded wait attempt."""

        self.ready = False
        self.waits: list[float] = []
        self.on_wait = on_wait

    def Set(self) -> None:
        """Release this modeled gate explicitly."""

        self.ready = True

    def Wait(self, timeout: float) -> bool:
        """Invoke a deterministic interleaving callback and report the actual modeled gate state."""

        self.waits.append(timeout)

        if self.on_wait is not None:
            self.on_wait()

        return self.ready

    set = Set
    wait = Wait


class FakeGraphThread:
    """Retain a joinable original thread identity without creating any real thread."""

    def __init__(self, name: str, events: list[str],
                 on_join: Callable[[], None] | None = None) -> None:
        """Record one original cleanup owner and optional deterministic admission race."""

        self.name = name
        self.events = events
        self.on_join = on_join
        self.ident = 1
        self.alive = True

    def Join(self, timeout: float) -> None:
        """Run one modeled cleanup transition under the provided absolute remaining ceiling."""

        assert 0 <= timeout <= 3, "Every join must share one finite original cleanup budget."
        self.events.append(self.name + "-join")

        if self.on_join is not None:
            self.on_join()

        self.alive = False

    def IsAlive(self) -> bool:
        """Return the actual modeled original-owner settlement state."""

        return self.alive

    join = Join
    is_alive = IsAlive


def PureGraphServer(state: CrawlGraphState) -> CrawlGraphServer:
    """Create dispatch state without running TCPServer initialization or opening a listener."""

    server = object.__new__(CrawlGraphServer)
    server.state = state
    server.slots = BoundedSemaphore(4)
    server.handlers = []

    return server


def test_BothSiblingEntriesPrecedeBThenACompletionWithoutRealThreads() -> None:
    """B cannot send first while A is absent; the two-way gate measures actual handler overlap."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))
    state.InvertSiblingCompletion()
    a_socket = FakeGraphSocket()
    b_socket = FakeGraphSocket()
    a_gate = FakeGraphGate()
    b_gate = FakeGraphGate()
    state.branch_a_entered = a_gate
    state.branch_b_completed = b_gate
    state.Accept(b_socket)
    state.BeginHandler(b_socket)

    with pytest.raises(TimeoutError):
        state.WaitForSibling(b_socket, "/branch-b")

    assert a_gate.waits and not b_socket.sent and not b_gate.ready, (
        "B must wait for actual A entry before it can send or publish completion."
    )
    state.Accept(a_socket)
    state.BeginHandler(a_socket)

    def CompleteB() -> None:
        """Interleave actual modeled B completion only after A has entered its fixed gate."""

        assert a_gate.ready, "A must signal its actual entry before B's wait can succeed."
        state.WaitForSibling(b_socket, "/branch-b")
        response, _ = state.BeginResponse(b_socket, "/branch-b")
        state.RecordSent(b_socket, b_socket.send(response))
        b_socket.shutdown(socket.SHUT_WR)
        state.CompleteResponse(b_socket, "/branch-b")

    b_gate.on_wait = CompleteB
    state.WaitForSibling(a_socket, "/branch-a")
    response, _ = state.BeginResponse(a_socket, "/branch-a")
    state.RecordSent(a_socket, a_socket.send(response))
    a_socket.shutdown(socket.SHUT_WR)
    state.CompleteResponse(a_socket, "/branch-a")
    observations = state.Observe()
    assert [(item.target, item.completion_sequence) for item in observations] == [
        ("/branch-b", 1), ("/branch-a", 2),
    ], "Only B complete-send/SHUT_WR may release A's eventual completion."
    assert state.Counters()["maximum_active_handlers"] == 2, (
        "Gate configuration alone must not substitute for measured two-handler overlap."
    )
    state.EndHandler(a_socket)
    state.EndHandler(b_socket)
    state.CloseConnections()


def test_AcceptedPartialAndInvalidRequestsRemainVisibleThroughTeardown() -> None:
    """A partial or invalid GET cannot become an empty zero-contact observation."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))
    partial = FakeGraphSocket(blocks=(b"GET /entry HTTP/1.1\r\n", b""))
    invalid = FakeGraphSocket(blocks=(b"POST /entry HTTP/1.1\r\n\r\n",))

    for connection in (partial, invalid):
        state.Accept(connection)
        CrawlGraphHandler(connection, ("127.0.0.1", 12345), SimpleNamespace(state=state))

    state.CloseAdmission()
    state.CloseConnections()
    observations = state.Observe()
    assert [item.request_bytes for item in observations] == [
        b"GET /entry HTTP/1.1\r\n", b"POST /entry HTTP/1.1\r\n\r\n",
    ], "Each original prefix must survive parser refusal and socket cleanup."
    assert all(item.failure is not None and item.socket_closed and item.sent_bytes == 0
               and item.completion_sequence is None for item in observations), (
        "Partial/refused work must retain actual failed/closed facts without fabricated completion."
    )
    assert state.Counters()["contacts"] == 2 and state.Errors(), (
        "Accept-time counts and errors must remain exposed after admission closes."
    )


def test_OriginalSocketOwnershipBlocksMutationBeforeAnyValidRequestExists() -> None:
    """A pre-parse accepted socket owns the original graph even with zero running handlers."""

    graph = MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153")
    state = CrawlGraphState(graph)
    connection = FakeGraphSocket()
    state.Accept(connection)
    assert state.Counters()["active_handlers"] == 0, "The test must precede handler entry."

    with pytest.raises(RuntimeError):
        state.SetVariant("fixed")

    with pytest.raises(RuntimeError):
        graph.SetVariant("fixed")

    with pytest.raises(RuntimeError):
        state.InvertSiblingCompletion()

    state.CloseConnection(connection)
    state.SetVariant("fixed")
    assert graph.variant == "fixed", "Content mutation may proceed only after original settlement."


def test_PartialProgressNeverRenewsOriginalAcceptTimeRequestDeadline() -> None:
    """Slow partial headers exhaust one original deadline despite fresh receive operations."""

    clock = FakeGraphClock()
    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"), clock=clock)
    connection = FakeGraphSocket(blocks=(b"GET /entry ", b"HTTP/1.1\r\n"),
                                 clock=clock, advances=(1.5, 0.6))
    state.Accept(connection)
    CrawlGraphHandler(connection, ("127.0.0.1", 12345), SimpleNamespace(state=state))
    state.CloseConnection(connection)
    record = state.Observe()[0]
    assert connection.timeouts == [2.0, 0.5], (
        "Each operation must receive only the same original request's remaining time."
    )
    assert record.deadline_at == 12 and record.request_bytes == b"GET /entry HTTP/1.1\r\n", (
        "Late original bytes remain contact evidence without extending the original deadline."
    )
    assert record.failure is not None and record.completion_sequence is None, (
        "An original expired partial request must remain failed rather than completed."
    )


def test_LateAcceptIsOwnedAndRefusedBeforeAnyThreadDispatch(monkeypatch) -> None:
    """Close-before-dispatch cannot create an unregistered late handler or invisible contact."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))
    server = PureGraphServer(state)
    connection = FakeGraphSocket()
    server.socket = SimpleNamespace(accept=lambda: (connection, ("127.0.0.1", 12345)))
    state.CloseAdmission()

    def ForbiddenThread(*args, **kwargs) -> None:
        """Fail if closed admission attempts any real or modeled handler creation."""

        pytest.fail("Closed admission must refuse before constructing a handler thread")

    monkeypatch.setattr(graph_helpers, "Thread", ForbiddenThread)
    accepted, address = server.GetRequest()
    assert accepted in state.connections and state.Counters()["contacts"] == 1, (
        "The original accept must be owned and counted before ProcessRequest can run."
    )
    server.ProcessRequest(accepted, address)
    record = state.Observe()[0]
    assert connection.closed and record.socket_closed and record.admission_state == "refused", (
        "Every late accepted original socket must be closed without dispatch and remain visible."
    )
    assert state.Errors() and state.Counters()["active_connections"] == 0, (
        "Late teardown contact must never become an empty contact/error result."
    )


def test_AdmissionJoinPrecedesFinalOriginalSocketAndHandlerSettlement(monkeypatch) -> None:
    """A modeled already-entered accept settles before the final snapshot and handler joins."""

    clock = FakeGraphClock()
    events: list[str] = []
    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"), clock=clock)
    server = PureGraphServer(state)
    original = FakeGraphSocket(events=events)
    late = FakeGraphSocket(events=events)
    state.Accept(original)
    state.BeginHandler(original)
    server.socket = SimpleNamespace(accept=lambda: (late, ("127.0.0.1", 12346)))

    def FinishOriginalAdmission() -> None:
        """Model an accept already entered when teardown atomically closes admission."""

        assert state.branch_a_entered.is_set() and state.branch_b_completed.is_set(), (
            "Both original sibling waits must be released before listener settlement."
        )
        accepted, address = server.GetRequest()
        server.ProcessRequest(accepted, address)

    listener = FakeGraphThread("listener", events, FinishOriginalAdmission)
    handler = FakeGraphThread("handler", events, lambda: state.EndHandler(original))
    server.handlers.append(handler)
    monkeypatch.setattr(server, "server_close", lambda: events.append("listener-close"))
    monkeypatch.setattr(graph_helpers, "monotonic", clock)
    server.Settle(listener)
    assert events.index("listener-join") < events.index("listener-close") < (
        len(events) - 1
    ) and events[-1] == "handler-join", (
        "Admission must stop/join before final original-socket cleanup and original-handler joins."
    )
    assert state.Counters()["contacts"] == 2 and all(item.socket_closed
        for item in state.Observe()) and state.Counters()["active_connections"] == 0, (
        "The already-entered late accept must be counted, retained and settled through teardown."
    )
    assert not listener.is_alive() and not handler.is_alive() and state.Errors(), (
        "Interrupted originals must retain failures after their modeled cleanup owners settle."
    )


def test_ContactAndErrorOverflowRemainExplicitWithBoundedOriginalDetails() -> None:
    """Retained-record limits cannot hide exact original accept totals or suppressed failures."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))

    for _ in range(MAX_REQUESTS + 7):
        connection = FakeGraphSocket()
        state.Accept(connection)
        state.CloseConnection(connection)

    counters = state.Counters()
    assert counters["contacts"] == MAX_REQUESTS + 7 and len(state.Observe()) == MAX_REQUESTS, (
        "Every original accept must count even when bounded detailed contact retention fills."
    )
    assert counters["contact_overflow"] == 7 and len(state.Errors()) == MAX_ERRORS and (
        counters["error_overflow"] == counters["errors"] - MAX_ERRORS
    ), "Every omitted detail must have an explicit overflow count and failure evidence."
    assert counters["active_connections"] == 0 and all(record.socket_closed
        for record in state.Observe()), "Bounded retention must preserve actual original closure."


def test_BoundedOriginalPrefixMarksTruncationRatherThanSilentlyDroppingBytes() -> None:
    """A bounded retained prefix remains distinguishable from exact original received length."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))
    connection = FakeGraphSocket()
    state.Accept(connection)
    state.RecordRequest(connection, b"G" * (MAX_REQUEST_BYTES + 1))
    state.CloseConnection(connection)
    record = state.Observe()[0]
    assert len(record.request_bytes) == MAX_REQUEST_BYTES and record.received_bytes == (
        MAX_REQUEST_BYTES + 1
    ) and record.request_truncated, "Truncated prefix custody must expose its exact original count."


@pytest.mark.parametrize("operation", ["recv", "send"])
def test_OriginalInFlightByteFactsSurviveSocketClosureBeforeRecording(operation: str) -> None:
    """Preserve original received/sent bytes if teardown precedes their ledger update."""

    state = CrawlGraphState(MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153"))
    raw = b"GET /entry HTTP/1.1\r\n\r\n"
    connection = FakeGraphSocket(blocks=(raw,))
    state.Accept(connection)

    def CloseDuringOriginalOperation() -> None:
        """Close the original socket after modeled I/O succeeds but before its caller records it."""

        state.CloseAdmission()
        state.CloseConnection(connection)

    if operation == "recv":
        connection.on_recv = CloseDuringOriginalOperation

    else:
        connection.on_send = CloseDuringOriginalOperation

    CrawlGraphHandler(connection, ("127.0.0.1", 12345), SimpleNamespace(state=state))
    record = state.Observe()[0]
    assert record.request_bytes == raw and record.received_bytes == len(raw), (
        "Original received bytes must survive teardown before the post-recv recording step."
    )
    assert record.sent_bytes == len(connection.sent) and record.socket_closed and (
        record.completion_sequence is None and record.failure is not None
    ), "Original successful send counts must survive close without inventing response completion."
    assert state.Counters()["active_handlers"] == 0 and not state.settled_handler_owners, (
        "Original in-flight contact associations must settle only after their handler exits."
    )


def test_OriginalDispatchSlotPreventsFalseIdleAfterHandlerAndSocketClose() -> None:
    """Keep mutation blocked until the original dispatch slot actually releases."""

    graph = MutableCrawlGraph(
        "http://127.0.0.1:49152", sentinel_origin="http://127.0.0.1:49153")
    state = CrawlGraphState(graph)
    server = PureGraphServer(state)
    connection = FakeGraphSocket()
    state.Accept(connection)
    assert server.slots.acquire(blocking=False), "The modeled original dispatch must own one slot."

    with state.lock:
        state.dispatch_owners.add(connection)
        state.UpdateIdleLocked()

    state.BeginHandler(connection)
    state.EndHandler(connection)
    state.CloseConnection(connection)
    assert state.Counters()["active_connections"] == state.Counters()["active_handlers"] == 0, (
        "The counterexample must reach the old false-idle interval after handler/socket settlement."
    )
    assert state.Counters()["active_dispatches"] == 1 and not state.WaitIdle(0), (
        "The original outstanding dispatch slot must keep the deterministic idle event closed."
    )

    with pytest.raises(RuntimeError):
        state.SetVariant("fixed")

    with pytest.raises(RuntimeError):
        state.InvertSiblingCompletion()

    server.ReleaseDispatch(connection)
    assert state.WaitIdle(0) and state.Counters()["active_dispatches"] == 0, (
        "Only actual original slot release may clear dispatch ownership and signal idleness."
    )
    state.SetVariant("fixed")
    state.InvertSiblingCompletion()

    with pytest.raises(ValueError):
        state.WaitIdle(4)


def test_OffOriginLinkRequiresADeclaredDifferentOwnedSentinelOrigin() -> None:
    """Pure rendering cannot invent an unmeasured arbitrary-port exclusion destination."""

    graph = MutableCrawlGraph("http://127.0.0.1:49152")

    with pytest.raises(ValueError):
        graph.SeedBody()

    graph.AttachSentinel("http://127.0.0.1:49153")
    assert b'http://127.0.0.1:49153/off-origin-marker' in graph.SeedBody() and (
        b'http://127.0.0.1:1/' not in graph.SeedBody()
    ), "Positive bytes must bind the held second origin rather than arbitrary port1."
    assert all(url.startswith(graph.origin + "/") for url in graph.SelectedUrls()) and (
        not any(url.startswith(graph.sentinel_origin + "/") for url in graph.SelectedUrls())
    ), "The second origin must never enter the main thirteen-URL admitted selection."

    with pytest.raises(ValueError):
        graph.AttachSentinel(graph.origin)

    with pytest.raises(ValueError):
        graph.AttachSentinel("http://example.invalid")


def test_SentinelOriginalPartialContactsRemainDistinctFromMainZeroContact() -> None:
    """A sentinel contact cannot be hidden by the main origin's empty contact ledger."""

    main = CrawlGraphState(MutableCrawlGraph("http://127.0.0.1:49152"))
    sentinel = CrawlGraphState(OffOriginCrawlSentinel("http://127.0.0.1:49153"))
    main.graph.AttachSentinel(sentinel.graph.origin)
    connection = FakeGraphSocket()
    sentinel.Accept(connection)
    sentinel.RecordRequest(connection, b"GET /off-origin-marker ")
    sentinel.CloseAdmission()
    sentinel.CloseConnection(connection)
    assert main.Counters()["contacts"] == 0 and main.Observe() == (), (
        "The counterexample deliberately leaves the main origin completely uncontacted."
    )
    assert sentinel.Counters()["contacts"] == 1 and sentinel.Observe()[0].request_bytes == (
        b"GET /off-origin-marker "
    ) and sentinel.Observe()[0].socket_closed and sentinel.Errors(), (
        "Sentinel accept-time evidence must retain partial forbidden contact after cleanup."
    )
    response = sentinel.graph.Response("/off-origin-marker")
    assert response.status == 404 and b"href" not in response.body and len(response.Wire()) < 256, (
        "The owned sentinel must serve only finite terminal bytes without traversal or forwarding."
    )


def test_CompletedOriginalResponseClosesWithoutRedundantFullShutdown() -> None:
    """A completed original send/SHUT_WR needs physical close without a second full shutdown."""

    state = CrawlGraphState(MutableCrawlGraph("http://127.0.0.1:49152"))
    server = PureGraphServer(state)
    connection = FakeGraphSocket()
    original_shutdown = connection.shutdown

    def Shutdown(mode: int) -> None:
        """Model a completed connection refusing only the redundant full-shutdown operation."""

        original_shutdown(mode)

        if mode == socket.SHUT_RDWR:
            raise OSError(errno.ENOTCONN, "private simulated shutdown diagnostic")

    connection.shutdown = Shutdown
    state.Accept(connection)
    assert server.slots.acquire(blocking=False), "The original modeled dispatch must own one slot."

    with state.lock:
        state.dispatch_owners.add(connection)
        state.UpdateIdleLocked()

    state.BeginHandler(connection)
    response, _ = state.BeginResponse(connection, "/leaf/.git/HEAD")
    state.RecordSent(connection, connection.send(response))
    connection.shutdown(socket.SHUT_WR)
    state.CompleteResponse(connection, "/leaf/.git/HEAD")
    state.EndHandler(connection)
    state.CloseConnection(connection)
    assert state.Errors() == (), "Completed response cleanup must not repeat full shutdown."
    assert connection.closed and state.Observe()[0].socket_closed and connection.shutdowns == [
        socket.SHUT_WR], "Physical closure must preserve actual complete-send and half-close facts."
    assert state.Counters()["active_dispatches"] == 1 and not state.WaitIdle(0), (
        "Physical closure must not release the original dispatch slot or expose false idleness."
    )
    server.ReleaseDispatch(connection)
    assert state.WaitIdle(0), "Only original slot release may complete cleanup idleness."


@pytest.mark.parametrize("shutdown_fails", [False, True])
def test_IncompleteOriginalSocketStillRequiresFullShutdownAndPhysicalClose(
    shutdown_fails: bool,
) -> None:
    """Incomplete teardown must unblock the original socket and retain actual errno."""

    state = CrawlGraphState(MutableCrawlGraph("http://127.0.0.1:49152"))
    server = PureGraphServer(state)
    connection = FakeGraphSocket()
    original_shutdown = connection.shutdown

    def Shutdown(mode: int) -> None:
        """Observe required full shutdown and optionally model its actual failure."""

        original_shutdown(mode)

        if shutdown_fails:
            raise OSError(errno.EIO, "private mock shutdown detail must not survive")

    connection.shutdown = Shutdown
    state.Accept(connection)
    assert server.slots.acquire(blocking=False), "Original dispatch must acquire its slot."

    with state.lock:
        state.dispatch_owners.add(connection)
        state.UpdateIdleLocked()

    state.BeginHandler(connection)
    state.RecordRequest(connection, b"GET /leaf/.git/HEAD ")
    state.CloseAdmission()
    state.CloseConnection(connection)
    record = state.Observe()[0]
    assert connection.shutdowns == [socket.SHUT_RDWR] and (
        connection.closed and record.socket_closed
    ), (
        "Incomplete original work must attempt full shutdown and still physically close its socket."
    )
    assert record.completion_sequence is None and record.failure == "owned-contact-interrupted", (
        "Interrupted original work must preserve its real incomplete response state."
    )
    assert record.shutdown_error is shutdown_fails and record.shutdown_errno == (
        errno.EIO if shutdown_fails else None), "Only observed required-shutdown errno survives."
    assert ("owned-socket-shutdown-failure" in state.Errors()) is shutdown_fails and (
        "private mock shutdown" not in json.dumps(record.ToDict())
    ), "Required shutdown failures must remain errors without retaining exception text or paths."
    assert not state.WaitIdle(0), "Physical close must retain running/dispatch owners."
    state.EndHandler(connection)
    assert not state.WaitIdle(0), "Dispatch keeps its semaphore after handler exit."
    server.ReleaseDispatch(connection)
    assert state.WaitIdle(0), "Only original dispatch-slot release exposes idle cleanup."


@pytest.mark.parametrize("actual_errno,retained_errno", [
    (errno.EBADF, errno.EBADF), (None, None), (True, None), (999999, None),
])
def test_PhysicalCloseFailureRetainsOriginalOwnerAndBoundedFirstErrno(
    actual_errno: int | None, retained_errno: int | None,
) -> None:
    """A failed physical close keeps original ownership and first bounded errno."""

    state = CrawlGraphState(MutableCrawlGraph("http://127.0.0.1:49152"))
    connection = FakeGraphSocket()
    original_close = connection.close

    def Close() -> None:
        """Model only one original close failure without opening or reading any real descriptor."""

        raise OSError(actual_errno, "private mock close path and diagnostic must not survive")

    connection.close = Close
    state.Accept(connection)
    state.BeginHandler(connection)
    response, _ = state.BeginResponse(connection, "/leaf/.git/HEAD")
    state.RecordSent(connection, connection.send(response))
    connection.shutdown(socket.SHUT_WR)
    state.CompleteResponse(connection, "/leaf/.git/HEAD")
    state.EndHandler(connection)
    state.CloseConnection(connection)
    record = state.Observe()[0]
    assert state.Errors() == ("owned-socket-close-failure",) and not record.socket_closed and (
        connection in state.connections and not state.WaitIdle(0)
    ), "A failed actual close must remain an error with unsettled original socket ownership."
    assert record.close_error is True and record.close_errno == retained_errno and (
        "private mock close" not in json.dumps(record.ToDict())
    ), "Only known original integer errno survives; unsupported values stay unknown."
    connection.close = original_close
    state.CloseConnection(connection)
    retried = state.Observe()[0]
    assert connection.closed and retried.socket_closed and state.WaitIdle(0), (
        "Only a successful actual physical retry may release the original socket owner."
    )
    assert connection.shutdowns == [socket.SHUT_WR] and retried.close_error and (
        retried.close_errno == retained_errno and state.Errors() == ("owned-socket-close-failure",)
    ), "Actual close success must preserve first-failure errno without adding redundant shutdown."
