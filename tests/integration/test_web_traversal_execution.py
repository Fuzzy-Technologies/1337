# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual bounded async owned-page traversal, authority, persistence and lifecycle acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import threading
import time
from dataclasses import replace
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import pytest

from fuzzy1337.captured_web import CapturedWebLimits
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobContext, JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.page_capture import LocalPageCaptureProvider, PageCaptureLimits
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.web_traversal import LocalWebTraversalProvider, WebTraversalLimits
from fuzzy1337.workspace import WorkspaceConflictError
from tests.contract.web_traversal_fixture import NOW, Body, Fixture, Run
from tests.integration.test_page_capture_execution import OwnedWireServer

ORACLE = json.loads((Path(__file__).parents[1] / "contract" / "fixtures" /
                     "web-traversal.oracle.v1.json").read_text())


class JoinedOwnedHTTPServer(ThreadingHTTPServer):
    """Keep request workers non-daemon so native server_close joins every owned response."""

    daemon_threads = False
    block_on_close = True


class OwnedPages:
    """Own an actual finite loopback HTTP service and measure requests/concurrent transport."""

    def __init__(self, *, delays=None, failures=None, holds=None, barriers=None):
        """Start only a literal ephemeral loopback listener with fixed non-secret page responses."""

        self.delays = {} if delays is None else delays
        self.failures = {} if failures is None else failures
        self.holds = {} if holds is None else holds
        self.barriers = {} if barriers is None else barriers
        self.requests = []
        self.starts = []
        self.lock = threading.Lock()
        self.active = 0
        self.maximum_active = 0
        self.received = threading.Event()
        self.wave_received = threading.Event()
        self.stop = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            """Serve exact selected synthetic markup or explicit fixed refusal scenarios."""

            def log_message(self, format, *args):
                """Suppress framework request/header logging at the owned test boundary."""

            def do_GET(self):
                """Record only approved structural paths, then emit one complete owned response."""

                with owner.lock:
                    owner.requests.append(self.path)
                    owner.starts.append(time.monotonic())
                    owner.active += 1
                    owner.maximum_active = max(owner.maximum_active, owner.active)
                    owner.received.set()

                    if {"/alpha", "/beta"}.issubset(owner.requests):
                        owner.wave_received.set()

                try:
                    if self.path in owner.barriers:
                        owner.barriers[self.path].wait(5)

                    if self.path in owner.holds and not owner.holds[self.path].wait(5):
                        return

                    owner.stop.wait(owner.delays.get(self.path, 0))
                    failure = owner.failures.get(self.path)

                    if failure == "redirect":
                        body = b""
                        self.send_response(302)
                        self.send_header("Location", owner.origin + "/shared")

                    else:
                        body = (b"UNEXPECTED-PRIVATE-MARKER" if failure == "body"
                                else Body(self.path))
                        self.send_response(200)

                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True

                except (BrokenPipeError, ConnectionResetError, threading.BrokenBarrierError):
                    pass

                finally:
                    with owner.lock:
                        owner.active -= 1

        self.server = JoinedOwnedHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def Close(self):
        """Stop responses and join every owned listener/response thread even after cancellation."""

        self.stop.set()

        for hold in self.holds.values():
            hold.set()

        for barrier in self.barriers.values():
            barrier.abort()

        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        assert not self.thread.is_alive(), "Owned target listener survived fixture teardown"
        assert self.active == 0, "Owned target response thread survived fixture teardown"


@pytest.fixture
def owned_pages():
    """Keep actual owned target cleanup guaranteed for every successful and failed test."""

    servers = []

    def Start(**kwargs):
        """Create one current-test owned target without remote access or readiness probes."""

        server = OwnedPages(**kwargs)
        servers.append(server)

        return server

    try:
        yield Start

    finally:
        for server in reversed(servers):
            server.Close()


def SourceObservations(root):
    """Reopen actual canonical saved page facts independently from controller counters."""

    return tuple(item for item in LocalModelStore(root).Open().observations
                 if item.kind == "http.synthetic-page")


def test_ActualAsyncTraversalPreservesOrderedCommitsAndIndependentOracle(
    tmp_path, owned_pages, monkeypatch,
):
    """Inverted worker completion cannot alter deterministic frontier, CAS or source attribution."""

    beta_captured = threading.Event()
    dispatch_starts = []
    response_barrier = threading.Barrier(2)
    server = owned_pages(holds={"/alpha": beta_captured},
        barriers={"/alpha": response_barrier, "/beta": response_barrier})
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(page_limits=PageCaptureLimits(request_timeout_seconds=5))
    original = LocalPageCaptureProvider.Acquire

    async def ReleaseAfterBetaCapture(self, context, *, before_commit=None, publish_progress=True):
        """Release alpha's actual response only after beta is fully captured and interpreted."""

        dispatch_starts.append(time.monotonic())

        async def Gate():
            """Signal actual inverted completion, then wait at the unchanged ordered commit gate."""

            if self._target.value.endswith("/beta"):
                beta_captured.set()

            await before_commit()

        return await original(self, context, before_commit=Gate,
                              publish_progress=publish_progress)

    monkeypatch.setattr(LocalPageCaptureProvider, "Acquire", ReleaseAfterBetaCapture)
    job = fixture.Job(provider)
    snapshot = Run(job)
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    assert sorted(server.requests) == ORACLE["request_paths"], "Traversal acquired wrong routes"
    assert server.maximum_active == 2, "Actual page acquisition failed to overlap asynchronously"
    assert min(later - earlier for earlier, later in
               zip(dispatch_starts, dispatch_starts[1:], strict=False)) >= 0.049, (
        "Controller page dispatch ignored its configured monotonic start interval"
    )
    assert [urlsplit(url).path for url in provider.CompletedUrls] == ORACLE["commit_paths"], (
        "Worker completion order leaked into canonical model commit order"
    )
    assert provider.UnselectedCandidates == ORACLE["unselected_candidates"], (
        "Allowed unselected candidate was lost or acquired"
    )
    state = LocalModelStore(fixture.root).Open()
    assert state.revision == ORACLE["model_revision"], "Canonical per-page Save count differs"
    pages = sorted(SourceObservations(fixture.root),
                   key=lambda item: item.attributes["prior_model_revision"])
    assert [urlsplit(item.attributes["url"]).path for item in pages] == ORACLE["commit_paths"], (
        "Saved page history differs from independent breadth/URL order"
    )
    assert len(snapshot.artifacts) == ORACLE["manifest_count"], "Original acquisition count differs"
    store = LocalEvidenceStore(fixture.root / "evidence")
    body_bytes = 0
    schema = json.loads((Path(__file__).parents[2] / "contracts" /
                         "page-capture-record.schema.json").read_bytes())

    for artifact in snapshot.artifacts:
        record = store.Get(artifact.evidence.evidence_id)
        assert record == artifact.evidence, "Original complete acquisition manifest changed"
        raw = store.Read(record.reference)
        assert hashlib.sha256(raw).hexdigest() == record.reference.sha256, (
            "Actual immutable raw evidence failed independent digest verification"
        )

        if record.reference.role == "response-body":
            body_bytes += len(raw)

        else:
            jsonschema.validate(json.loads(raw), schema)

    assert body_bytes == ORACLE["body_bytes"], "Measured admitted body bytes differ from oracle"
    assert snapshot.progress.completed == snapshot.progress.total == 4, (
        "Traversal final progress did not use actual completed work"
    )
    progress = [event.data for event in job.EventsSince() if event.kind is JobEventKind.PROGRESS]
    assert [item.completed for item in progress] == [0, 1, 2, 3, 4, 4], (
        "Page-local progress leaked into aggregate traversal counters"
    )
    assert all(item.total is None for item in progress[:-1]), "Unknown total was invented early"
    assert sum(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince()) == 4, (
        "Every acknowledged page commit must publish exactly one owning delta"
    )


@pytest.mark.parametrize("limit,expected", [
    ({"max_pages": 1}, ["/index"]), ({"max_depth": 0}, ["/index"]),
    ({"max_total_body_bytes": 220}, ["/index"]),
    ({"max_total_body_bytes": 219}, []),
])
def test_ActualBudgetFailurePreservesOnlyAcknowledgedPriorPages(tmp_path, owned_pages,
                                                               limit, expected):
    """Whole-wave quotas stop before any omitted wave launches and preserve earlier evidence."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(limits=WebTraversalLimits(**limit))
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Truncated selected traversal falsely succeeded"
    assert snapshot.failure.code is JobFailureCode.OUTPUT_LIMIT, "Budget refusal was hidden"
    assert server.requests == expected, "Quota refusal launched extra owned requests"
    assert LocalModelStore(fixture.root).Open().revision == len(expected), (
        "Prior acknowledged canonical pages were lost on later budget refusal"
    )
    assert len(snapshot.artifacts) == 2 * len(expected), "Prior actual acquisitions were lost"


@pytest.mark.parametrize("failure", ["redirect", "body"])
def test_ActualRedirectAndUnexpectedBodyRefuseWithoutDestinationAcquisition(
    tmp_path, owned_pages, failure,
):
    """A response cannot forward consent or publish unexpected page/header content."""

    server = owned_pages(failures={"/alpha": failure})
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(limits=WebTraversalLimits(concurrency=1))
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Refused acquisition incorrectly completed"
    assert snapshot.failure.code is JobFailureCode.PROVIDER, "Worker refusal was hidden"
    assert server.requests == ["/index", "/alpha"], "Refusal followed a redirect or another wave"
    assert "/shared" not in server.requests, "Redirect destination received transferred consent"
    assert LocalModelStore(fixture.root).Open().revision == 1, (
        "Refused page entered canonical state"
    )
    store = LocalEvidenceStore(fixture.root / "evidence")
    failure_record = snapshot.artifacts[-1].evidence
    raw = store.Read(store.Get(failure_record.evidence_id).reference)
    error = "response-policy" if failure == "redirect" else "body-policy"
    assert json.loads(raw) == {"error": error, "schema_version": 1}, (
        "Original truthful fixed worker refusal was not retained"
    )
    assert failure_record.provenance.execution.state.value == "failed", (
        "Failed acquisition was changed into a successful collection"
    )
    retained = b"\n".join(path.read_bytes() for path in fixture.root.rglob("*") if path.is_file())
    assert b"UNEXPECTED-PRIVATE-MARKER" not in retained, "Unexpected body leaked into evidence"


def test_CurrentRevocationAfterSeedStopsEveryDiscoveredLaunch(tmp_path, owned_pages, monkeypatch):
    """A successfully captured link is discovery metadata and never a reusable invocation grant."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    original = JobContext.ModelChanged

    def RevokeAfterSeed(self, delta):
        """Persist actual revoked current owner consent after the acknowledged seed Save."""

        original(self, delta)
        scopes = LocalScopeStore(fixture.root)
        scope = scopes.Open("local")
        scopes.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

    monkeypatch.setattr(JobContext, "ModelChanged", RevokeAfterSeed)
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Stale seed consent authorized another page"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Current revocation was hidden"
    assert server.requests == ["/index"], "Revocation allowed discovered worker launch"
    assert LocalModelStore(fixture.root).Open().revision == 1, "Prior page facts were erased"


def test_ActualCancellationDrainsConcurrentWorkersAndCommitWaiter(
    tmp_path, owned_pages, monkeypatch,
):
    """Cancel after the later page reaches its gate; earlier slow worker and waiter both drain."""

    alpha_hold = threading.Event()
    response_barrier = threading.Barrier(2)
    server = owned_pages(holds={"/alpha": alpha_hold},
        barriers={"/alpha": response_barrier, "/beta": response_barrier})
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(page_limits=PageCaptureLimits(request_timeout_seconds=5))
    job = fixture.Job(provider)
    gate_waiting = threading.Event()
    original = LocalPageCaptureProvider.Acquire

    async def TrackGate(self, context, *, before_commit=None, publish_progress=True):
        """Observe a genuine captured later page just before it waits for ordered Save admission."""

        async def Gate():
            """Signal the blocked beta commit then invoke the real condition gate."""

            if self._target.value.endswith("/beta"):
                gate_waiting.set()

            await before_commit()

        return await original(self, context, before_commit=Gate,
                              publish_progress=publish_progress)

    monkeypatch.setattr(LocalPageCaptureProvider, "Acquire", TrackGate)

    async def CancelAfterGate():
        """Cancel the real owning job only after actual beta capture has reached its gate."""

        job.Start()
        seen = await asyncio.to_thread(gate_waiting.wait, 3)
        assert seen, "Actual beta acquisition never reached the waiting commit gate"
        assert server.wave_received.is_set(), "Cancellation must follow both actual wave requests"
        job.Cancel("owner:test")

        return await asyncio.wait_for(job.Wait(), 3)

    snapshot = asyncio.run(CancelAfterGate())
    assert snapshot.state is JobState.CANCELLED, "Owned traversal cancellation did not finish"
    assert LocalModelStore(fixture.root).Open().revision == 1, "Cancelled waiter committed a page"
    assert sorted(server.requests) == ["/alpha", "/beta", "/index"], (
        "Cancellation started a later frontier wave"
    )
    assert len(snapshot.artifacts) == 4, "Actual beta captures or prior seed acquisitions were lost"
    revision = LocalModelStore(fixture.root).Open().revision
    assert revision == 1 and len(job.EventsSince()) == snapshot.last_sequence + 1, (
        "Cancelled traversal emitted work after its owner terminal state"
    )


def test_GlobalDeadlineDrainsWorkersAndRetainsPriorCommit(tmp_path, owned_pages, monkeypatch):
    """Expire the observed real global timer after both owned second-wave requests reach target."""

    server = owned_pages(delays={"/alpha": 10, "/beta": 10})
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    job = fixture.Job(provider)
    original = asyncio.timeout
    global_deadline = []

    def ObserveDeadline(delay):
        """Retain the actual global timeout owner without replacing expiry/cancellation behavior."""

        deadline = original(delay)

        if delay == 30:
            global_deadline.append(deadline)

        return deadline

    monkeypatch.setattr(asyncio, "timeout", ObserveDeadline)

    async def ExpireAfterActualWave():
        """Move the observed real timer only after live children and the prior seed commit exist."""

        job.Start()
        seen = await asyncio.to_thread(server.wave_received.wait, 5)
        assert seen, "Both actual owned wave requests must precede the deadline test"
        assert len(global_deadline) == 1, "The real traversal deadline was not uniquely observed"
        global_deadline[0].reschedule(asyncio.get_running_loop().time())

        return await asyncio.wait_for(job.Wait(), 3)

    snapshot = asyncio.run(ExpireAfterActualWave())
    assert global_deadline[0].expired(), "Test did not expire the actual global timer"
    assert snapshot.state is JobState.FAILED, "Expired traversal falsely completed"
    assert snapshot.failure.code is JobFailureCode.TIMEOUT, "Whole-operation deadline was hidden"
    assert "Web traversal deadline" in snapshot.failure.message, "A different timeout was tested"
    assert LocalModelStore(fixture.root).Open().revision == 1, "Deadline erased prior seed commit"
    assert "/shared" not in server.requests, "Deadline allowed another frontier wave"


def ObserveCapturedBetaBeforeAlpha(monkeypatch, fixture, job):
    """Install a test-only custody barrier while preserving actual acquisition and ordered gates."""

    original_acquire = LocalPageCaptureProvider.Acquire
    beta_captured = asyncio.Event()

    async def OrderCapturedSibling(self, context, *, before_commit=None, publish_progress=True):
        """Wait for actual beta custody before allowing the real alpha commit/failure boundary."""

        async def Gate():
            """Signal only after beta's immutable original stdout and body have been stored."""

            assert before_commit is not None, "The actual traversal must supply its ordered gate"

            if self._target.value.endswith("/beta"):
                records = tuple(item.evidence for item in job.Snapshot().artifacts)
                bodies = tuple(item for item in records if item.reference.role == "response-body"
                    and item.reference.sha256 == hashlib.sha256(Body("/beta")).hexdigest())
                assert len(bodies) == 1, "Beta must retain its exact original body before signaling"
                body = bodies[0]
                store = LocalEvidenceStore(fixture.root / "evidence")
                assert store.Get(body.evidence_id) == body and store.Read(body.reference) == (
                    Body("/beta")), "Beta signal must follow actual immutable source custody"
                assert len([item for item in records if item.reference.role == "stdout"
                    and item.provenance == body.provenance]) == 1, (
                        "Beta signal must follow its original same-run stdout acquisition"
                    )
                beta_captured.set()

            elif self._target.value.endswith("/alpha"):
                await beta_captured.wait()

            await before_commit()

        return await original_acquire(self, context, before_commit=Gate,
                                      publish_progress=publish_progress)

    monkeypatch.setattr(LocalPageCaptureProvider, "Acquire", OrderCapturedSibling)

    return beta_captured


@pytest.mark.parametrize("failure", ["conflict", "lost-ack", "event"])
def test_OrderedSaveFailuresDrainWaitingSiblingAndPreserveActualState(
    tmp_path, owned_pages, monkeypatch, failure,
):
    """A predecessor's CAS/post-Save failure never releases its captured successor as complete."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    original_save = LocalModelStore.Save
    original_event = JobContext.ModelChanged

    def FailSave(self, state, *, expected_revision):
        """Fail actual alpha CAS or its acknowledgement, never substituting the real owner write."""

        if expected_revision == 1 and failure == "conflict":
            raise WorkspaceConflictError("synthetic private failure")

        result = original_save(self, state, expected_revision=expected_revision)

        if expected_revision == 1 and failure == "lost-ack":
            raise OSError("synthetic private failure")

        return result

    def FailEvent(self, delta):
        """Fail actual alpha post-Save delivery after the canonical owner has committed it."""

        if LocalModelStore(fixture.root).Open().revision == 2 and failure == "event":
            raise RuntimeError("synthetic private failure")

        return original_event(self, delta)

    monkeypatch.setattr(LocalModelStore, "Save", FailSave)
    monkeypatch.setattr(JobContext, "ModelChanged", FailEvent)
    job = fixture.Job(provider)
    beta_captured = ObserveCapturedBetaBeforeAlpha(monkeypatch, fixture, job)
    snapshot = Run(job)
    assert beta_captured.is_set(), "The failure scenario must include a captured waiting beta"
    assert snapshot.state is JobState.FAILED, "Failed predecessor released another canonical Save"
    expected_revision = 1 if failure == "conflict" else 2
    assert LocalModelStore(fixture.root).Open().revision == expected_revision, (
        "Actual CAS or post-Save state was falsely rolled back or advanced by beta"
    )
    assert len(snapshot.artifacts) == 6, "Captured waiting sibling raw evidence was erased"
    assert len(provider.CompletedUrls) == 1, "Ambiguous alpha transition was counted acknowledged"
    assert "/shared" not in server.requests, "Failed wave launched another discovered page"
    assert "synthetic private failure" not in snapshot.failure.message, (
        "Owning exception context leaked into terminal diagnostics"
    )


def test_ExpiredConsentWhileWaitingForOrderedCommitDeniesSave(tmp_path, owned_pages, monkeypatch):
    """The ordered admission await precedes fresh final consent, model composition and CAS."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    current_time = [NOW]
    scopes = LocalScopeStore(fixture.root)
    scope = scopes.Open("local")
    scopes.Save(replace(scope, authorization=replace(scope.authorization,
        valid_until=(NOW + timedelta(seconds=1)).isoformat())))
    provider = LocalWebTraversalProvider(fixture.root, fixture.pages[0].source, fixture.pages,
        "local", fixture.policy, clock=lambda: current_time[0])
    original = JobContext.ModelChanged

    def ExpireAfterAlpha(self, delta):
        """Advance the decision clock only after alpha commits, while beta waits its turn."""

        original(self, delta)

        if LocalModelStore(fixture.root).Open().revision == 2:
            current_time[0] += timedelta(seconds=1)

    monkeypatch.setattr(JobContext, "ModelChanged", ExpireAfterAlpha)
    job = fixture.Job(provider)
    beta_captured = ObserveCapturedBetaBeforeAlpha(monkeypatch, fixture, job)
    snapshot = Run(job)
    assert beta_captured.is_set(), "Consent expiry must follow actual waiting beta acquisition"
    assert snapshot.state is JobState.FAILED, "Commit gate reused expired earlier authority"
    assert snapshot.failure.code is JobFailureCode.AUTHORIZATION, "Fresh expiry denial was hidden"
    assert LocalModelStore(fixture.root).Open().revision == 2, "Expired beta was saved"
    assert len(snapshot.artifacts) == 6, "Expiry erased already captured beta evidence"


def test_TruncatedLexicalFrontierNeverClaimsTraversalComplete(tmp_path, owned_pages):
    """Existing lexical omission remains a truthful traversal failure after the captured page."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(frontier_limits=CapturedWebLimits(max_candidates=1))
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Truncated lexical frontier falsely completed"
    assert snapshot.failure.code is JobFailureCode.OUTPUT_LIMIT, "Lexical truncation was hidden"
    assert server.requests == ["/index"], "Truncated frontier was treated as fully discovered"
    assert LocalModelStore(fixture.root).Open().revision == 1, "Captured seed commit was lost"


def test_ExistingSinglePageDefaultBehaviorStillPublishesOnePageProgress(tmp_path, owned_pages):
    """The additive traversal commit hook retains ordinary page acquisition's default contract."""

    server = owned_pages()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = LocalPageCaptureProvider(fixture.root, fixture.pages[0].source,
        fixture.pages[0].expected_body, "local", fixture.policy, clock=lambda: NOW)
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    assert snapshot.progress.completed == snapshot.progress.total == 1, (
        "Additive traversal support changed one-page default progress"
    )
    assert server.requests == ["/index"], "Ordinary one-page provider began implicit traversal"


def test_ActualMinimalTwoDigitBodyReplyUsesSameGovernedTraversalPath(tmp_path):
    """An actual minimal60-byte HTTP header must not reject a reviewed55-byte page body."""

    body = Body("/beta")
    wire = b"HTTP/1.0 200 \r\ncontent-length:55\r\ncontent-type:text/html\r\n\r\n" + body
    server = OwnedWireServer(wire)

    try:
        fixture = Fixture.Create(tmp_path / "workspace", server.origin)
        page = fixture.pages[2]
        provider = LocalWebTraversalProvider(fixture.root, page.source, (page,),
            "local", fixture.policy, clock=lambda: NOW)
        snapshot = Run(fixture.Job(provider))
        assert snapshot.state is JobState.COMPLETED, snapshot.failure
        assert server.accepted == 1, "Minimal body acceptance fetched an unselected candidate"
        observation = SourceObservations(fixture.root)[0]
        assert observation.attributes["header_size_bytes"] == 60, (
            "Actual minimal wire metadata was replaced by an assumed larger header"
        )
        assert len(snapshot.artifacts) == 2, "Original minimal reply acquisition was not retained"

    finally:
        server.Close()


def test_OwnedTargetCloseJoinsActualResponseFinalizerBeforeReturning(monkeypatch):
    """Teardown must join an owned response thread even after its HTTP handler has returned."""

    server = OwnedPages()
    response_finish = threading.Event()
    finish_entered = threading.Event()
    join_entered = threading.Event()
    response_threads = []
    failures = []
    original_finish = server.server.RequestHandlerClass.finish

    def HoldActualFinalizer(self):
        """Pause the actual request worker after normal buffered response cleanup."""

        original_finish(self)
        response_threads.append(threading.current_thread())
        finish_entered.set()
        response_finish.wait(5)

    monkeypatch.setattr(server.server.RequestHandlerClass, "finish", HoldActualFinalizer)

    def CloseOwnedTarget():
        """Preserve exceptions from the fixture-close thread for assertions in the test owner."""

        try:
            server.Close()

        except BaseException as error:
            failures.append(error)

    closer = threading.Thread(target=CloseOwnedTarget)

    try:
        with socket.create_connection(server.server.server_address, timeout=2) as connection:
            connection.sendall(b"GET /index HTTP/1.0\r\n\r\n")
            assert finish_entered.wait(2), "Actual request never reached its finalizer gate"
            original_join = response_threads[0].join

            def ObserveActualJoin(timeout=None):
                """Observe native server ownership joining the exact held response worker."""

                join_entered.set()
                original_join(timeout)

            monkeypatch.setattr(response_threads[0], "join", ObserveActualJoin)
            closer.start()
            assert join_entered.wait(2), "Fixture Close omitted its live response worker join"
            assert closer.is_alive(), "Fixture Close returned before the response finalizer drained"
            response_finish.set()
            closer.join(2)
            assert not closer.is_alive(), "Fixture Close did not finish after owned worker release"
            assert not failures, "Owned response finalizer drain raised a teardown failure"
            assert not response_threads[0].is_alive(), "Actual response worker survived Close"

    finally:
        response_finish.set()

        if closer.ident is not None:
            closer.join(2)

        server.Close()


def test_MissingOwnedResponseHoldSignalRefusesInsteadOfReleasingBody(
    tmp_path, owned_pages, monkeypatch,
):
    """An exhausted fixture hold cannot silently admit an uninverted successful response."""

    hold = threading.Event()
    monkeypatch.setattr(hold, "wait", lambda timeout: False)
    server = owned_pages(holds={"/index": hold})
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    snapshot = Run(fixture.Job(provider))
    assert snapshot.state is JobState.FAILED, "Missing capture gate silently released page bytes"
    assert snapshot.failure.code is JobFailureCode.PROVIDER, "Actual incomplete reply was hidden"
    assert server.requests == ["/index"], "Missing response gate advanced the frontier"
    assert not provider.CompletedUrls, "Unacknowledged fixture response became a completed page"
    assert LocalModelStore(fixture.root).Open().revision == 0, "Unreleased page entered model state"
    record = snapshot.artifacts[0].evidence
    raw = LocalEvidenceStore(fixture.root / "evidence").Read(record.reference)
    assert json.loads(raw) == {"schema_version": 1, "error": "protocol"}, (
        "Missing fixture gate lost the original truthful worker refusal"
    )
