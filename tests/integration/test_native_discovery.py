# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual governed native worker acquisition against pytest-owned localhost fixtures."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fuzzy1337.discovery import (
    NATIVE_HTTP_CAPABILITY,
    NATIVE_HTTP_PROVIDER_ID,
    DiscoveryLimits,
    NativeDiscoveryProvider,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobSpec, JobState, ScanJob
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactLevel, ImpactPolicy, PolicyEngine
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

NOW = datetime(2026, 10, 13, tzinfo=UTC)


@pytest.fixture
def owned_http() -> Iterator[tuple[str, list[str]]]:
    """Own one finite localhost target and always release its listener and thread."""

    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        """Explicit status, redirect, failure and slow routes for the native sensor."""

        def do_GET(self) -> None:
            """Serve only bounded synthetic responses with intentional secret markers."""

            calls.append(self.path)
            assert (
                "Authorization" not in self.headers and "Cookie" not in self.headers
            ), 'do_GET boundary invariant failed'

            if self.path == "/malformed":
                self.wfile.write(b"invalid status secret\r\n\r\n")
                return

            if self.path == "/slow":
                time.sleep(1)

            self.send_response(302 if self.path == "/redirect" else 200, "secret reason")
            self.send_header("Set-Cookie", "secret cookie")
            self.send_header("Authorization", "secret credential")

            if self.path == "/redirect":
                self.send_header("Location", "/unchecked")

            try:
                self.end_headers()
                self.wfile.write(b"secret body")

            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            """Suppress incidental server text in reproducible test output."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}", calls

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def Fixture(tmp_path: Path, urls: tuple[str, ...]):
    """Initialize canonical owned storage and explicitly authorize exact endpoint/IP membership."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Native fixture"), "synthetic")
    LocalModelStore(root).Create()
    targets = tuple(Target(TargetKind.URL, url) for url in urls)
    ip = Target(TargetKind.IP, "127.0.0.1")
    scope = ScopeSnapshot("local", "synthetic", ScopeAuthorization(
        AuthorizationState.GRANTED, "owner:test", "approval:fixture",
    ), targets=(*targets, ip), allow=(*targets, ip))
    LocalScopeStore(root).Create(scope)
    policy = ImpactPolicy("local", permissions=(CapabilityPermission(
        NATIVE_HTTP_CAPABILITY, NATIVE_HTTP_PROVIDER_ID, ImpactLevel.SAFE,
    ),))
    return root, targets, scope, policy


def Job(root, targets, policy, *, limits=DiscoveryLimits(), identifier="job:fixture"):
    """Use the actual producer, governed executor, worker, jobs, stores and interfaces."""

    producer = NativeDiscoveryProvider(root, targets, "local", policy,
                                       limits=limits, clock=lambda: NOW)
    return ScanJob(JobSpec(identifier, "synthetic", "scope:local", "owner:test",
                          NATIVE_HTTP_PROVIDER_ID), producer,
                   evidence_store=LocalEvidenceStore(root / "evidence"))


def Run(job):
    """Await a real sensor job without invoking a manual or bypassed scan path."""

    async def StartAndWait():
        """Observe the canonical asynchronous lifecycle."""

        job.Start()
        return await job.Wait()

    return asyncio.run(StartAndWait())


def test_RealDiscoveryEvidenceModelEventsRepeatAndReopen(tmp_path, owned_http):
    """Actual response facts persist before events and repeated runs preserve logical identity."""

    base, calls = owned_http
    root, targets, _, policy = Fixture(tmp_path, (base + "/health", base + "/redirect"))
    job = Job(root, targets, policy)
    snapshot = Run(job)
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    assert calls == ["/health", "/redirect"], "Redirects must never become unchecked requests"
    state = LocalModelStore(root).Open()
    assert (
        len(state.Objects(ObjectKind.HOST)) == 1
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        len(state.Objects(ObjectKind.PORT)) == len(state.Objects(ObjectKind.SERVICE)) == 1
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        len(state.Objects(ObjectKind.ENDPOINT)) == 2
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        len(state.relations) == 4
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        [event.kind for event in job.EventsSince()].count(JobEventKind.MODEL_DELTA) == 2
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    evidence = LocalEvidenceStore(root / "evidence")

    for artifact in snapshot.artifacts:
        raw = evidence.Read(artifact.evidence.reference)
        assert set(json.loads(raw)) == {
            "schema_version", "url", "address", "port", "scheme", "status",
        }, 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
        assert (
            b"secret" not in raw and b"Location" not in raw
        ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'

    object_ids = tuple(item.Reference() for item in state.objects)
    relation_ids = tuple(item.Reference() for item in state.relations)
    repeated = Run(Job(root, targets, policy, identifier="job:repeat"))
    assert (
        repeated.state is JobState.COMPLETED
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    reopened = LocalModelStore(root).Open()
    assert (
        tuple(item.Reference() for item in reopened.objects) == object_ids
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        tuple(item.Reference() for item in reopened.relations) == relation_ids
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'
    assert (
        len(reopened.observations) > len(state.observations)
    ), 'Real Discovery Evidence Model Events Repeat And Reopen boundary invariant failed'


def test_LaterProtocolFailurePreservesEarlierObservedState(tmp_path, owned_http):
    """A partial run keeps verified earlier evidence and fails instead of truncating to success."""

    base, calls = owned_http
    root, targets, _, policy = Fixture(tmp_path, (base + "/health", base + "/malformed"))
    snapshot = Run(Job(root, targets, policy))
    assert (
        snapshot.state is JobState.FAILED and snapshot.failure.code is JobFailureCode.PROVIDER
    ), 'Later Protocol Failure Preserves Earlier Observed State boundary invariant failed'
    assert (
        calls == ["/health", "/malformed"] and len(snapshot.artifacts) == 2
    ), 'Later Protocol Failure Preserves Earlier Observed State boundary invariant failed'
    assert (
        len(LocalModelStore(root).Open().Objects(ObjectKind.ENDPOINT)) == 1
    ), 'Later Protocol Failure Preserves Earlier Observed State boundary invariant failed'


@pytest.mark.parametrize("case", ["unknown", "expired", "excluded", "changed"])
def test_RealGovernedBoundaryPreventsUnauthorizedRequest(tmp_path, owned_http, monkeypatch, case):
    """Current consent and destinations are checked at launch, including post-grant change."""

    base, calls = owned_http
    root, targets, scope, policy = Fixture(tmp_path, (base + "/health",))
    store = LocalScopeStore(root)

    if case == "unknown":
        store.Save(replace(scope, authorization=ScopeAuthorization()))

    elif case == "expired":
        store.Save(replace(scope, authorization=replace(scope.authorization,
            valid_until="2026-10-12T00:00:00+00:00")))

    elif case == "excluded":
        store.Save(replace(scope, exclusions=(Target(TargetKind.IP, "127.0.0.1"),)))

    else:
        original = PolicyEngine.Authorize

        def Change(self, *args, **kwargs):
            """Revoke consent strictly between exact grant issuance and actual launch."""

            grant = original(self, *args, **kwargs)
            store.Save(replace(scope, authorization=ScopeAuthorization(AuthorizationState.REVOKED)))
            return grant

        monkeypatch.setattr(PolicyEngine, "Authorize", Change)

    snapshot = Run(Job(root, targets, policy))
    assert (
        snapshot.state is JobState.FAILED
    ), 'Real Governed Boundary Prevents Unauthorized Request boundary invariant failed'
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION
    ), 'Real Governed Boundary Prevents Unauthorized Request boundary invariant failed'
    assert (
        not calls and not snapshot.artifacts and not LocalModelStore(root).Open().objects
    ), 'Real Governed Boundary Prevents Unauthorized Request boundary invariant failed'


def test_ActualSlowResponseProducesTimeoutWithoutFacts(tmp_path, owned_http):
    """The complete socket deadline records a safe timeout and fails the real job."""

    base, calls = owned_http
    root, targets, _, policy = Fixture(tmp_path, (base + "/slow",))
    snapshot = Run(Job(root, targets, policy,
                       limits=DiscoveryLimits(request_timeout_seconds=0.1, timeout_seconds=5)))
    assert (
        calls == ["/slow"] and snapshot.failure.code is JobFailureCode.TIMEOUT
    ), 'Actual Slow Response Produces Timeout Without Facts boundary invariant failed'
    assert (
        snapshot.state is JobState.FAILED and not LocalModelStore(root).Open().objects
    ), 'Actual Slow Response Produces Timeout Without Facts boundary invariant failed'
    assert (
        json.loads(LocalEvidenceStore(root / "evidence").Read(
        snapshot.artifacts[0].evidence.reference,
    ))["error"] == "timeout"
    ), 'Actual Slow Response Produces Timeout Without Facts boundary invariant failed'


def test_ActualCancellationReapsWorkerBeforeTerminalState(tmp_path, owned_http):
    """A real waiting HTTP worker is owned and terminated before the job becomes cancelled."""

    base, calls = owned_http
    root, targets, _, policy = Fixture(tmp_path, (base + "/slow",))
    job = Job(root, targets, policy)

    async def Cancel():
        """Wait for actual target contact then cancel through the owner-only job API."""

        job.Start()

        async with asyncio.timeout(5):
            while not calls:
                await asyncio.sleep(0.01)

        return await job.CancelAndWait("owner:test", grace_seconds=0.5)

    snapshot = asyncio.run(Cancel())
    assert (
        snapshot.state is JobState.CANCELLED and calls == ["/slow"]
    ), 'Actual Cancellation Reaps Worker Before Terminal State boundary invariant failed'
    assert (
        not LocalModelStore(root).Open().objects
    ), 'Actual Cancellation Reaps Worker Before Terminal State boundary invariant failed'


def test_ConsumerActorGuardDeniesFreshActorBetweenProbes(tmp_path, owned_http):
    """A consumer-specific expected actor is checked anew before each real endpoint launch."""

    base, calls = owned_http
    root, targets, scope, policy = Fixture(tmp_path, (base + "/first", base + "/second"))
    store = LocalScopeStore(root)

    def ValidateActor(context):
        """Further deny a changed consumer actor without replacing standard scope policy."""

        if context.scope.authorization.authority_reference != "owner:test":
            raise PermissionError("consumer actor changed")

    producer = NativeDiscoveryProvider(root, targets, "local", policy, clock=lambda: NOW,
                                       context_validator=ValidateActor)
    job = ScanJob(JobSpec("job:actor", "synthetic", "scope:local", "owner:test",
                          NATIVE_HTTP_PROVIDER_ID), producer,
                   evidence_store=LocalEvidenceStore(root / "evidence"))

    async def ObserveAndChange():
        """Change still-granted actor after the first actual saved discovery update."""

        job.Start()
        changed = False

        async for event in job.Events():
            if event.kind is JobEventKind.MODEL_DELTA and not changed:
                store.Save(replace(scope, authorization=replace(
                    scope.authorization, authority_reference="owner:replacement",
                    record_reference="consent:replacement",
                )))
                changed = True

        return await job.Wait()

    result = asyncio.run(ObserveAndChange())
    assert result.failure.code is JobFailureCode.AUTHORIZATION and calls == ["/first"], (
        "Changed consent actor must prevent the second real probe"
    )
    assert len(LocalModelStore(root).Open().Objects(ObjectKind.ENDPOINT)) == 1, (
        "Earlier verified discovery must survive later consumer-actor denial"
    )


def test_ConsumerGuardReadsActorAtActualPrelaunch(tmp_path, owned_http, monkeypatch):
    """A final guarded launch sees changed current consent instead of the issuance snapshot."""

    base, calls = owned_http
    root, targets, scope, policy = Fixture(tmp_path, (base + "/first",))
    store = LocalScopeStore(root)
    original = PolicyEngine.Authorize
    observed = []

    def ValidateActor(context):
        """Observe the current actor at both issuance and actual final launch."""

        actor = context.scope.authorization.authority_reference
        observed.append(actor)

        if actor != "owner:test":
            raise PermissionError("consumer actor changed")

    def Change(self, *args, **kwargs):
        """Record a fresh different attester strictly after issuing the original grant."""

        grant = original(self, *args, **kwargs)
        store.Save(replace(scope, authorization=replace(
            scope.authorization, authority_reference="owner:replacement",
        )))
        return grant

    monkeypatch.setattr(PolicyEngine, "Authorize", Change)
    producer = NativeDiscoveryProvider(root, targets, "local", policy, clock=lambda: NOW,
                                       context_validator=ValidateActor)
    job = ScanJob(JobSpec("job:actor", "synthetic", "scope:local", "owner:test",
                          NATIVE_HTTP_PROVIDER_ID), producer,
                   evidence_store=LocalEvidenceStore(root / "evidence"))
    result = Run(job)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and not calls, (
        "Changed prelaunch actor must prevent actual worker execution"
    )
    assert observed == ["owner:test", "owner:replacement"], (
        "Trusted consumer guard must see current issuance and launch context"
    )
