# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent actual Chromium rendering, durable custody and real descendant cleanup."""

from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import json
import os
import signal
import socket
import sys
import time
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.captured_web import ReadCapturedWebFrontier
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.jobs import JobEventKind, JobSpec, JobState, ScanJob
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ObjectKind
from fuzzy1337.page_capture import (
    PAGE_BROWSER_CAPABILITY,
    PAGE_CAPTURE_PROVIDER_ID,
    BrowserPageCaptureLimits,
    KnownSyntheticHtmlBody,
    LocalPageCaptureProvider,
    PageRenderer,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.page_capture_fixture import NOW, Run
from tests.integration.test_page_capture_execution import OwnedWireServer

FIXTURES = Path(__file__).resolve().parents[1] / "contract/fixtures"
BROWSER_TREE = FIXTURES / "owned_browser_tree.py"


def Oracle() -> dict:
    """Read the handwritten expectations without deriving or updating them from the renderer.

    Returns:
        Reviewed independent source/DOM/version facts from the pinned repository fixture.
    """

    return json.loads((FIXTURES / "browser-dom.oracle.v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def actual_browser() -> None:
    """Fail missing required CI prerequisites; ordinary optional runs explicitly skip.

    This checks capability only and launches no browser or preliminary HTTP request.
    """

    if os.environ.get("FUZZY1337_RUN_PLAYWRIGHT_ACCEPTANCE") != "1":
        pytest.skip("Optional genuine Chromium acceptance is disabled; not acceptance")

    assert sys.platform == "linux", "Required Chromium acceptance needs Linux descendant ownership"
    own_children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")

    try:
        with own_children.open("rb"):
            pass

    except OSError:
        pytest.fail("Required Chromium acceptance lacks the actual Linux child ownership interface")

    try:
        installed = metadata.version("playwright")

    except metadata.PackageNotFoundError:
        pytest.fail("Required genuine Chromium acceptance has no installed Playwright package")

    assert installed == Oracle()["playwright_version"], "Installed Playwright differs from the pin"


def CreateWorkspace(root: Path, origin: str) -> RequestTemplate:
    """Create explicit owned source/candidate/IP consent and an empty canonical model.

    Args:
        root: Current case's new workspace directory.
        origin: Literal loopback origin already bound by the case's exact wire server.

    Returns:
        Concrete anonymous source template admitted by the exact persisted scope.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned browser fixture"), "synthetic")
    LocalModelStore(root).Create()
    targets = (Target(TargetKind.URL, origin + "/docs/index"),
               Target(TargetKind.URL, origin + "/selected-next"),
               Target(TargetKind.IP, "127.0.0.1"))
    LocalScopeStore(root).Create(ScopeSnapshot("local", "synthetic", ScopeAuthorization(
        AuthorizationState.GRANTED, "owner:test", "approval:owned-browser"),
        targets=targets, allow=targets))

    return RequestTemplate(Endpoint("synthetic", origin, "/docs/index"))


@pytest.mark.serial
def test_ActualChromiumRendersClosedBodyAndReopensCanonicalCustody(
    tmp_path, actual_browser, monkeypatch,
):
    """Run the governed production provider once and retain exact handwritten DOM/evidence facts."""

    del actual_browser
    oracle = Oracle()
    body = (FIXTURES / "browser-dom.owned.v1.html").read_bytes()
    assert len(body) == oracle["source_size_bytes"], "Owned HTML size changed from the oracle"
    assert hashlib.sha256(body).hexdigest() == oracle["source_sha256"], (
        "Owned HTML digest changed from the independent reviewed input"
    )
    headers = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
               b"Content-Length: 423\r\nConnection: close\r\n\r\n")
    server = OwnedWireServer(headers + body)
    resource_sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    observed = []
    execute = LocalExecutor.Execute

    async def Observe(executor, request, **kwargs):
        """Observe original real execution facts while returning its result object unchanged."""

        result = await execute(executor, request, **kwargs)
        observed.append((request, kwargs.get("own_descendants"), result))

        return result

    monkeypatch.setattr(LocalExecutor, "Execute", Observe)

    try:
        resource_sink.bind(("127.0.0.1", 19008))
        resource_sink.listen(4)
        resource_sink.setblocking(False)
        root = tmp_path / "workspace"
        source = CreateWorkspace(root, server.origin)
        policy = ImpactPolicy("local", permissions=(CapabilityPermission(
            PAGE_BROWSER_CAPABILITY, PAGE_CAPTURE_PROVIDER_ID, ImpactLevel.SAFE),))
        provider = LocalPageCaptureProvider(root, source,
            KnownSyntheticHtmlBody(oracle["fixture_id"]), "local", policy,
            renderer=PageRenderer.PLAYWRIGHT_OFFLINE, limits=BrowserPageCaptureLimits(),
            clock=lambda: NOW)
        job = ScanJob(JobSpec("job:actual-browser", "synthetic", "scope:local", "owner:test",
            PAGE_CAPTURE_PROVIDER_ID, 20), provider,
            evidence_store=LocalEvidenceStore(root / "evidence"))
        snapshot = Run(job)
        assert snapshot.state is JobState.COMPLETED, (
            f"Actual pinned Chromium production provider failed: {snapshot.failure}"
        )
        authority = server.origin.removeprefix("http://")
        expected_request = (f"GET /docs/index HTTP/1.1\r\nHost: {authority}\r\n"
            "Connection: close\r\nAccept: text/html\r\nAccept-Encoding: identity\r\n\r\n").encode()
        assert server.accepted == 1 and server.requests == [expected_request], (
            "Browser rendering must preserve exactly one approved native acquisition GET"
        )

        with pytest.raises(BlockingIOError):
            resource_sink.accept()

        assert len(observed) == 1 and observed[0][1] is True, (
            "The actual provider must use one real execution with descendant ownership"
        )
        request, _, execution = observed[0]
        expected_invocation = AdapterInvocation(PAGE_CAPTURE_PROVIDER_ID,
            AdapterRequest(PAGE_BROWSER_CAPABILITY,
                Target(TargetKind.URL, server.origin + "/docs/index").Reference(), ImpactLevel.SAFE,
                {"url": server.origin + "/docs/index", "timeout_seconds": 2.0,
                 "fixture_id": "owned-browser-dom.v1", "max_body_bytes": 16384}),
            (sys.executable, "-I", "-m", "fuzzy1337.browser_page_worker",
             server.origin + "/docs/index", "2.0", "owned-browser-dom.v1", "16384"), 9, "1")
        assert request.invocation == expected_invocation, (
            "Browser acquisition changed the approved original worker argv/request/deadline"
        )
        assert execution.execution.state is ExecutionState.SUCCEEDED and (
            execution.execution.exit_code == 0 and execution.stderr == b""
        ), "Genuine browser execution must finish successfully without diagnostic source leakage"
        captures = {item.evidence.reference.role: item.evidence for item in snapshot.artifacts}
        assert set(captures) == {"stdout", "response-body"}, (
            "Success must retain exactly original stdout and verified response body"
        )
        store = LocalEvidenceStore(root / "evidence")
        stdout = store.Read(captures["stdout"].reference)
        assert stdout == execution.stdout, "Stored stdout differs from the original worker bytes"
        assert store.Read(captures["response-body"].reference) == body, (
            "Stored response body differs from the independent exact owned HTTP response"
        )
        report = json.loads(stdout)
        expected = {"schema_version": 1, "fixture_id": "owned-browser-dom.v1",
            "url": server.origin + "/docs/index", "address": "127.0.0.1",
            "port": int(authority.rsplit(":", 1)[1]), "scheme": "http", "status": 200,
            "http_version": "HTTP/1.1", "content_type": "text/html", "declared_charset": "utf-8",
            "content_length": 423, "header_count": 3, "header_size_bytes": len(headers),
            "body_sha256": oracle["source_sha256"], "body_base64": base64.b64encode(body).decode(),
            "renderer_profile": oracle["profile"], "input_body_sha256": oracle["source_sha256"],
            "dom_sha256": oracle["expected_dom_sha256"],
            "dom_size_bytes": oracle["expected_dom_size_bytes"],
            **{key: oracle[key] for key in ("playwright_version", "chromium_version",
                "element_count", "anchor_count", "form_count", "input_count",
                "blocked_request_count")}}
        assert report == expected, "Actual Chromium DOM facts differ from the handwritten oracle"
        invocation_sha = InvocationDigest(expected_invocation)

        for capture in captures.values():
            assert store.Get(capture.evidence_id) == capture, "Evidence manifest failed reopening"
            assert capture.provenance.source_id == PAGE_CAPTURE_PROVIDER_ID and (
                capture.provenance.source_version == "1"
                and capture.provenance.tool_version == oracle["chromium_version"]
                and capture.provenance.invocation_sha256 == invocation_sha
                and capture.provenance.execution == execution.execution
            ), "Custody must bind original worker identity, real engine and terminal status"

        state = LocalModelStore(root).Open()
        assert state.revision == 1 and len(state.Objects(ObjectKind.ENDPOINT)) == 2, (
            "The exact source and one lexical candidate must form one canonical transition"
        )
        assert len(state.observations) == 2 and not state.relations and all(
            item.identity.kind is ObjectKind.ENDPOINT for item in state.objects
        ), "Acquisition must create only source/lexical facts, without findings or host claims"
        source_observation = next(item for item in state.observations
                                  if item.kind == "http.synthetic-page-browser")
        link = next(item for item in state.observations if item.kind == "web.lexical-link")
        candidate = RequestTemplate(Endpoint("synthetic", server.origin, "/selected-next"))
        assert source_observation.subject_reference == source.endpoint.Identity().Reference(), (
            "Browser source observation lost its canonical source endpoint identity"
        )
        assert link.subject_reference == candidate.endpoint.Identity().Reference() and (
            tuple(link.attributes["source_ordinals"]) == (1,)
        ), "The original reviewed anchor must produce exactly its selected canonical candidate"
        assert source_observation.attributes["invocation_sha256"] == invocation_sha and (
            source_observation.attributes["frontier_complete"] is True
            and source_observation.attributes["frontier_anchor_count"] == 1
        ), "Canonical source must retain exact original invocation and completed lexical custody"
        assert all(source_observation.attributes[key] == value for key, value in report.items()
                   if key != "body_base64"), "Source observation dropped genuine browser facts"
        frontier = ReadCapturedWebFrontier(root, source, captures["response-body"], "local", at=NOW)
        assert len(frontier.entries) == 1 and frontier.entries[0].template == candidate, (
            "Retained exact body must independently reopen the single lexical candidate"
        )
        assert source_observation.attributes["frontier_digest"] == frontier.frontier_digest, (
            "Stored browser interpretation differs from the independently reopened body frontier"
        )
        kinds = [event.kind for event in job.EventsSince()]
        assert kinds.count(JobEventKind.MODEL_DELTA) == 1 and (
            kinds.index(JobEventKind.MODEL_DELTA) > max(index for index, kind in enumerate(kinds)
                if kind is JobEventKind.ARTIFACT)
        ), "One canonical transition must follow both retained original evidence artifacts"
        expected_model = CanonicalModelJson(state.ToDict())

    finally:
        server.Close()
        resource_sink.close()

    moved = tmp_path / "relocated"
    root.rename(moved)
    assert CanonicalModelJson(LocalModelStore(moved).Open().ToDict()) == expected_model, (
        "Canonical source and browser interpretation changed after targets closed and relocation"
    )
    reopened = LocalEvidenceStore(moved / "evidence")

    for capture in captures.values():
        assert reopened.Get(capture.evidence_id) == capture, "Relocation changed custody metadata"
        expected_bytes = stdout if capture.reference.role == "stdout" else body
        assert reopened.Read(capture.reference) == expected_bytes, "Relocation lost evidence bytes"

    retained = ReadCapturedWebFrontier(moved, source, captures["response-body"], "local", at=NOW)
    assert retained.frontier_digest == frontier.frontier_digest, (
        "The original lexical frontier must reopen after target shutdown and workspace relocation"
    )


def Identity(process_id: int) -> int | None:
    """Read only one explicitly recorded owned PID's kernel start identity, including zombies.

    Args:
        process_id: PID already recorded by the current case's owned browser fixture.

    Returns:
        Start ticks while the identity exists, or None after its complete removal.
    """

    try:
        stat = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")

    except FileNotFoundError:
        return None

    return int(stat.rsplit(")", 1)[1].split()[19])


def Recorded(root: Path) -> list[dict]:
    """Read only this fixture's explicit descendant snapshot, without host enumeration.

    Args:
        root: Current isolated test directory.

    Returns:
        Explicit PID/start/name entries written only after genuine engine/page creation.
    """

    path = root / "identities.json"

    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


def ReapRecorded(root: Path) -> None:
    """Bound emergency cleanup to recorded matching owned PID handles if acceptance fails.

    Args:
        root: Current isolated test directory, never an arbitrary process selector.
    """

    (root / "release").write_text("owned fixture release", encoding="ascii")
    deadline = time.monotonic() + 2

    while True:
        records = Recorded(root)

        for record in records:
            process_id = record["pid"]

            try:
                descriptor = os.pidfd_open(process_id)

            except ProcessLookupError:
                continue

            try:
                if Identity(process_id) == record["started_ticks"]:
                    try:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)

                    except ProcessLookupError:
                        pass

                    try:
                        os.waitpid(process_id, os.WNOHANG)

                    except ChildProcessError:
                        pass

            finally:
                os.close(descriptor)

        if not any(Identity(item["pid"]) == item["started_ticks"] for item in records):
            return

        if time.monotonic() >= deadline:
            pytest.fail("Recorded actual browser descendants survived bounded fixture teardown")

        time.sleep(0.01)


@pytest.fixture
def owned_browser_tree(tmp_path, actual_browser) -> Iterator[Path]:
    """Own only current fixture fallback descendants and restore pytest's subreaper state."""

    del actual_browser
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert library.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0, "Cannot read test subreaper"
    assert library.prctl(36, 1, 0, 0, 0) == 0, "Cannot own failed real browser fixture descendants"

    try:
        yield tmp_path

    finally:
        try:
            ReapRecorded(tmp_path)

        finally:
            assert library.prctl(36, previous.value, 0, 0, 0) == 0, "Cannot restore test subreaper"


def TreeRequest(root: Path) -> LocalExecutionRequest:
    """Bind the single closed about:blank fixture to an explicit original invocation grant.

    Args:
        root: Current case's owned readiness/release directory.

    Returns:
        Actual executor request for this test-only file, without browser flags or navigation.
    """

    invocation = AdapterInvocation("native.owned-browser-fixture",
        AdapterRequest("test.owned-browser", "target:owned-browser", ImpactLevel.PASSIVE),
        (sys.executable, "-I", str(BROWSER_TREE), str(root)), 8, "owned-browser-tree.v1")

    return LocalExecutionRequest(invocation,
        CapabilityDescriptor("test.owned-browser", invocation.adapter_id, ImpactLevel.PASSIVE),
        ExecutionAuthorization("authorization:owned-browser", "scope:owned-browser",
            "policy:owned-browser", InvocationDigest(invocation)),
        resources=ExecutionResources(4096, 4096))


@pytest.mark.parametrize("stop", ["cancellation", "timeout"])
def test_ActualNodeAndChromiumAreReapedBeforeStoppedExecutionReturns(owned_browser_tree, stop):
    """Stop a genuine ready engine tree and check known identities before fallback teardown."""

    root = owned_browser_tree

    async def Execute():
        """Use explicit actual-ready stdout for cancellation, never race a fast normal render."""

        ready_output = asyncio.Event()
        cancellation = asyncio.Event()
        ready_marker = b"owned-browser-ready\n"
        ready_bytes = bytearray()

        def Observe(event: ExecutionEvent) -> None:
            """Acknowledge the exact bounded readiness stream across arbitrary read chunks."""

            if event.kind is ExecutionEventKind.STDOUT:
                remaining = len(ready_marker) + 1 - len(ready_bytes)
                ready_bytes.extend(event.data[:remaining])

                if ready_bytes == ready_marker:
                    ready_output.set()

        task = asyncio.create_task(LocalExecutor(root).Execute(TreeRequest(root),
            own_descendants=True, cancellation=cancellation, on_event=Observe))

        try:
            if stop == "cancellation":
                await asyncio.wait_for(ready_output.wait(), 7)
                cancellation.set()

            return await task

        finally:
            if not task.done():
                task.cancel()

            await asyncio.gather(task, return_exceptions=True)

    result = asyncio.run(Execute())
    assert (root / "ready.json").is_file(), "The actual Node/Chromium page never became ready"
    ready = json.loads((root / "ready.json").read_text(encoding="utf-8"))
    oracle = Oracle()
    assert ready == {"playwright_version": oracle["playwright_version"],
                     "chromium_version": oracle["chromium_version"], "url": "about:blank"}, (
        "Cleanup acceptance did not run the exact pinned genuine offline browser"
    )
    records = Recorded(root)
    names = [record["executable"] for record in records]
    assert "node" in names and any("chrome" in name for name in names), (
        "Genuine driver and Chromium identities must be recorded before the stop barrier"
    )
    remaining = [record["pid"] for record in records
                 if Identity(record["pid"]) == record["started_ticks"]]
    assert not remaining, f"Executor returned before browser descendants vanished: {remaining}"
    termination = ExecutionTermination.CANCELLATION if stop == "cancellation" else (
        ExecutionTermination.TIMEOUT)
    state = ExecutionState.CANCELLED if stop == "cancellation" else ExecutionState.TIMED_OUT
    assert result.termination is termination and result.execution.state is state, (
        "Verified descendant cleanup must preserve the requested stop reason and terminal state"
    )
    assert result.execution.exit_code == -signal.SIGKILL, "Original worker signal status was lost"
    assert result.stdout == b"owned-browser-ready\n" and result.stderr == b"", (
        "Actual engine fixture streams changed or readiness was never reached"
    )
    assert result.events[-1].kind is ExecutionEventKind.COMPLETED, (
        "Completed execution can be acknowledged only after genuine descendant cleanup"
    )
