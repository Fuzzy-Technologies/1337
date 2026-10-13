# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual one-page worker/jobs/policy/evidence/model integration against pytest-owned listeners."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import socket
import threading
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta

import pytest

from fuzzy1337.captured_web import ProjectCapturedWebFrontier, ReadCapturedWebFrontier
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobContext, JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectKind,
)
from fuzzy1337.page_capture import PageCaptureLimits
from fuzzy1337.policy import Digest, ImpactPolicy, PolicyEngine
from fuzzy1337.requests import (
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.workspace import WorkspaceConflictError
from tests.contract.page_capture_fixture import (
    NOW,
    Body,
    Fixture,
    Oracle,
    Run,
    Wire,
    WorkspaceBytes,
)


class OwnedWireServer:
    """Own a finite raw localhost listener without readiness probes or server-generated headers."""

    def __init__(self, wire: bytes, *, address: str = "127.0.0.1", hold_seconds: float = 0,
                 chunk_size: int = 4096, delay_seconds: float = 0) -> None:
        """Bind the literal listener before starting its bounded accept/response thread."""

        family = socket.AF_INET6 if address == "::1" else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.settimeout(0.1)
        self.listener.bind((address, 0))
        self.listener.listen(4)
        port = self.listener.getsockname()[1]
        self.origin = f"http://[{address}]:{port}" if family == socket.AF_INET6 else (
            f"http://{address}:{port}"
        )
        self.wire = wire
        self.hold_seconds = hold_seconds
        self.chunk_size = chunk_size
        self.delay_seconds = delay_seconds
        self.requests: list[bytes] = []
        self.accepted = 0
        self.stopping = threading.Event()
        self.received = threading.Event()
        self.thread = threading.Thread(target=self.Serve, daemon=True)
        self.thread.start()

    def Serve(self) -> None:
        """Accept finite owned requests and send only explicit synthetic bytes until teardown."""

        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()

            except socket.timeout:
                continue

            except OSError:
                return

            self.accepted += 1

            with connection:
                connection.settimeout(0.5)
                request = bytearray()

                try:
                    while b"\r\n\r\n" not in request and len(request) < 4096:
                        chunk = connection.recv(min(1024, 4096 - len(request)))

                        if not chunk:
                            break

                        request.extend(chunk)

                    self.requests.append(bytes(request))
                    self.received.set()

                    for position in range(0, len(self.wire), self.chunk_size):
                        if self.stopping.wait(self.delay_seconds):
                            break

                        connection.sendall(self.wire[position:position + self.chunk_size])

                    self.stopping.wait(self.hold_seconds)

                except (OSError, TimeoutError):
                    pass

    def Close(self) -> None:
        """Release the listener and join its finite thread even after test cancellation/failure."""

        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), "Owned listener teardown did not finish"


@pytest.fixture
def owned_wire() -> Iterator:
    """Own all requested synthetic listeners and guarantee teardown without target downloads."""

    servers: list[OwnedWireServer] = []

    def Start(wire: bytes | None = None, **kwargs) -> OwnedWireServer:
        """Start an explicit versioned synthetic wire profile, with no healthcheck request."""

        server = OwnedWireServer(Wire() if wire is None else wire, **kwargs)
        servers.append(server)

        return server

    try:
        yield Start

    finally:
        for server in servers:
            server.Close()


def Captures(snapshot):
    """Index the actual owning job attachments by their declared evidence roles."""

    return {artifact.evidence.reference.role: artifact.evidence for artifact in snapshot.artifacts}


def test_ExactOwnedWireWorkerOracleEvidenceModelAndEvents(tmp_path, owned_wire):
    """Full assembled path makes the exact one GET and one saved source/lexical transition."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    job = fixture.Job()
    snapshot = Run(job)
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    oracle = Oracle()
    authority = server.origin.removeprefix("http://")
    expected_request = (
        f"GET /docs/index HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
        "Accept: text/html\r\nAccept-Encoding: identity\r\n\r\n"
    ).encode()
    assert (
        server.requests == [expected_request] and server.accepted == 1
    ), (
        'Expected invariant: server.requests == [expected_request] and '
        'server.accepted == 1'
    )
    store = LocalEvidenceStore(fixture.root / "evidence")
    captures = Captures(snapshot)
    assert (
        set(captures) == set(oracle["model_from_empty"]["success_evidence_roles"])
    ), (
        'Expected invariant: set(captures) == '
        'set(oracle["model_from_empty"]["success_evidence_roles"])'
    )
    stdout = store.Read(store.Get(captures["stdout"].evidence_id).reference)
    body = store.Read(store.Get(captures["response-body"].evidence_id).reference)
    assert (
        body == Body() and hashlib.sha256(body).hexdigest() == oracle["body"]["sha256"]
    ), (
        'Expected invariant: body == Body() and hashlib.sha256(body).hexdigest() '
        '== oracle["body"]["sha256"]'
    )
    record = json.loads(stdout)

    for name in ("status", "http_version", "content_type", "declared_charset", "content_length",
                 "header_count", "header_size_bytes"):
        assert (
            record[name] == oracle["wire"][name]
        ), (
            'Expected invariant: record[name] == oracle["wire"][name]'
        )

    retained = WorkspaceBytes(fixture.root)

    for discarded in oracle["wire"]["not_retained_values"]:
        assert (
            discarded.encode() not in retained
        ), (
            'Expected invariant: discarded.encode() not in retained'
        )

    state = LocalModelStore(fixture.root).Open()
    expected = oracle["model_from_empty"]
    assert (
        state.revision == expected["revision_after_one_save"]
    ), (
        'Expected invariant: state.revision == '
        'expected["revision_after_one_save"]'
    )
    assert (
        len(state.Objects(ObjectKind.ENDPOINT)) == expected["endpoint_count"]
    ), (
        'Expected invariant: len(state.Objects(ObjectKind.ENDPOINT)) == '
        'expected["endpoint_count"]'
    )
    assert (
        len(state.observations) == expected["total_observation_count"]
    ), (
        'Expected invariant: len(state.observations) == '
        'expected["total_observation_count"]'
    )
    assert (
        not state.relations and not state.Objects(ObjectKind.FINDING)
    ), (
        'Expected invariant: not state.relations and not '
        'state.Objects(ObjectKind.FINDING)'
    )
    assert (
        not state.Objects(ObjectKind.HOST) and not state.Objects(ObjectKind.PORT)
    ), (
        'Expected invariant: not state.Objects(ObjectKind.HOST) and not '
        'state.Objects(ObjectKind.PORT)'
    )
    assert (
        not state.Objects(ObjectKind.SERVICE)
    ), (
        'Expected invariant: not state.Objects(ObjectKind.SERVICE)'
    )
    links = [item for item in state.observations if item.kind == "web.lexical-link"]
    observed = {RequestsFromObject(next(obj for obj in state.objects
        if obj.Reference() == item.subject_reference))[0].endpoint.path_template:
        tuple(item.attributes["source_ordinals"]) for item in links}
    assert (
        observed == {item["path"]: tuple(item["ordinals"])
                            for item in oracle["frontier"]["entries"]}
    ), (
        'Expected invariant: observed == {item["path"]: tuple(item["ordinals"]) '
        'for item in oracle["frontier"]["entries"]}'
    )
    source = next(item for item in state.observations if item.kind == "http.synthetic-page")
    assert (
        source.subject_reference == fixture.source.endpoint.Identity().Reference()
    ), (
        'Expected invariant: source.subject_reference == '
        'fixture.source.endpoint.Identity().Reference()'
    )
    assert (
        source.provenance.execution.state.value == "succeeded"
    ), (
        'Expected invariant: source.provenance.execution.state.value == '
        '"succeeded"'
    )
    assert (
        len(source.provenance.evidence_references) == 2
    ), (
        'Expected invariant: len(source.provenance.evidence_references) == 2'
    )
    assert (
        source.attributes["frontier_anchor_count"] == 10
    ), (
        'Expected invariant: source.attributes["frontier_anchor_count"] == 10'
    )
    assert (
        source.attributes["frontier_processed_anchors"] == 10
    ), (
        'Expected invariant: source.attributes["frontier_processed_anchors"] == '
        '10'
    )
    assert (
        source.attributes["frontier_complete"] is True
    ), (
        'Expected invariant: source.attributes["frontier_complete"] is True'
    )
    assert (
        source.attributes["frontier_discarded_candidates"] == 0
    ), (
        'Expected invariant: source.attributes["frontier_discarded_candidates"] '
        '== 0'
    )
    events = job.EventsSince()
    assert (
        sum(event.kind is JobEventKind.MODEL_DELTA for event in events) == 1
    ), (
        'Expected invariant: sum(event.kind is JobEventKind.MODEL_DELTA for event '
        'in events) == 1'
    )
    assert (
        sum(event.kind is JobEventKind.HEARTBEAT for event in events) == 2
    ), (
        'Expected invariant: sum(event.kind is JobEventKind.HEARTBEAT for event '
        'in events) == 2'
    )
    assert (
        [event.kind for event in events].index(JobEventKind.MODEL_DELTA) > max(
            index for index, event in enumerate(events) if event.kind is JobEventKind.ARTIFACT
        )
    ), (
        'Expected invariant: [event.kind for event in '
        'events].index(JobEventKind.MODEL_DELTA) > max( index for index, event in '
        'enumerate(events) if event.kind is JobEventKind.ARTIFACT )'
    )
    assert (
        snapshot.progress.completed == snapshot.progress.total == 1
    ), (
        'Expected invariant: snapshot.progress.completed == '
        'snapshot.progress.total == 1'
    )


def test_UnicodeConsentRetainsDistinctOwningDigestsAndPinnedSnapshot(tmp_path, owned_wire):
    """Non-ASCII consent gives unequal valid hashes without denying the unchanged launch scope."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin, unicode_consent=True)
    before = LocalScopeStore(fixture.root).Open("local")
    snapshot = Run(fixture.Job())
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    state = LocalModelStore(fixture.root).Open()
    source = next(item for item in state.observations if item.kind == "http.synthetic-page")
    policy_digest = Digest(before.ToDict())
    frontier_digest = hashlib.sha256(CanonicalModelJson(before.ToDict())).hexdigest()
    assert (
        policy_digest != frontier_digest
    ), (
        'Expected invariant: policy_digest != frontier_digest'
    )
    assert (
        source.attributes["launch_policy_scope_sha256"] == policy_digest
    ), (
        'Expected invariant: source.attributes["launch_policy_scope_sha256"] == '
        'policy_digest'
    )
    assert (
        source.attributes["frontier_scope_sha256"] == frontier_digest
    ), (
        'Expected invariant: source.attributes["frontier_scope_sha256"] == '
        'frontier_digest'
    )
    assert (
        LocalScopeStore(fixture.root).Open("local") == before and server.accepted == 1
    ), (
        'Expected invariant: LocalScopeStore(fixture.root).Open("local") == '
        'before and server.accepted == 1'
    )


def test_CompleteSourceAndCandidateRequestsAttributesAndHistorySurvive(tmp_path, owned_wire):
    """Both source and candidate owner collections compose completely with unrelated state."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    model = LocalModelStore(fixture.root)
    initial = model.Open()
    alpha = replace(fixture.source.endpoint, path_template="/alpha")
    prior_source = RequestTemplate(fixture.source.endpoint, (
        InjectionPoint(InjectionLocation.QUERY, "existing_source", ValueBinding("source-input")),
    ))
    prior_alpha = RequestTemplate(alpha, (
        InjectionPoint(InjectionLocation.QUERY, "existing_candidate", ValueBinding("alpha-input")),
    ))
    attribution = ModelProvenance("synthetic-existing", "run:previous", NOW.isoformat(),
        fixture.scope.Reference(), fixture.scope.targets[0].Reference(), "old-v1")
    patches = tuple(replace(ProjectRequests((template,), provenance=(attribution,)),
        attributes={**ProjectRequests((template,), provenance=(attribution,)).attributes,
                    "unrelated": "retained"}) for template in (prior_source, prior_alpha))
    seeded, _ = initial.Apply(objects=patches)
    model.Save(seeded, expected_revision=initial.revision)
    snapshot = Run(fixture.Job())
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    reopened = model.Open()
    assert (
        reopened.revision == seeded.revision + 1
    ), (
        'Expected invariant: reopened.revision == seeded.revision + 1'
    )

    for template in (prior_source, prior_alpha):
        obj = next(item for item in reopened.objects
                   if item.identity == template.endpoint.Identity())
        assert (
            template in RequestsFromObject(obj)
        ), (
            'Expected invariant: template in RequestsFromObject(obj)'
        )
        assert (
            len(RequestsFromObject(obj)) == 2 and obj.attributes["unrelated"] == "retained"
        ), (
            'Expected invariant: len(RequestsFromObject(obj)) == 2 and '
            'obj.attributes["unrelated"] == "retained"'
        )
        assert (
            attribution in obj.provenance
        ), (
            'Expected invariant: attribution in obj.provenance'
        )

    assert (
        set(item.Reference() for item in seeded.observations) <= {
            item.Reference() for item in reopened.observations
        }
    ), (
        'Expected invariant: set(item.Reference() for item in '
        'seeded.observations) <= { item.Reference() for item in '
        'reopened.observations }'
    )
    body_capture = Captures(snapshot)["response-body"]
    frontier = ReadCapturedWebFrontier(fixture.root, fixture.source, body_capture, "local", at=NOW)
    candidate_ids = {entry.template.endpoint.Identity().Reference() for entry in frontier.entries}
    existing = tuple(obj for obj in reopened.objects if obj.Reference() in candidate_ids)
    projection = ProjectCapturedWebFrontier(frontier, existing=existing)
    replayed, delta = reopened.Apply(objects=projection.object_patches,
                                     observations=projection.observations)
    assert (
        replayed == reopened and delta.revision == reopened.revision
    ), (
        'Expected invariant: replayed == reopened and delta.revision == '
        'reopened.revision'
    )


@pytest.mark.parametrize("variant,error", [
    ("same-length-secret", "body-policy"), ("truncated", "protocol"),
    ("extra", "protocol"), ("redirect", "response-policy"),
    ("bad-header", "protocol"), ("wrong-length", "body-policy"),
    ("keep-alive", "timeout"), ("slow", "timeout"),
])
def test_ActualWorkerFailurePrivacyTerminalOutcomeAndNoModel(tmp_path, owned_wire, variant, error):
    """Unexpected response bytes never enter any retained stream/model/evidence/event channel."""

    wire = Wire()
    kwargs = {}
    marker = b"synthetic-secret-marker"

    if variant == "same-length-secret":
        secret = (marker * 30)[:541]
        wire = wire[:-541] + secret

    elif variant == "truncated":
        wire = wire[:-1]

    elif variant == "extra":
        wire += marker

    elif variant == "redirect":
        wire = wire.replace(b"200 Synthetic reason", b"302 synthetic-secret-marker")

    elif variant == "bad-header":
        wire = wire.replace(b"X-Discarded:", b"X Bad:")

    elif variant == "wrong-length":
        wire = wire.replace(b"Content-Length: 541", b"Content-Length: 542")

    elif variant == "keep-alive":
        kwargs["hold_seconds"] = 0.8

    else:
        kwargs.update(chunk_size=1, delay_seconds=0.01)

    server = owned_wire(wire, **kwargs)
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider(limits=PageCaptureLimits(request_timeout_seconds=0.2))
    job = fixture.Job(provider=provider)
    snapshot = Run(job)
    assert snapshot.state is JobState.FAILED, snapshot.failure
    assert (
        snapshot.failure.code is (JobFailureCode.TIMEOUT if error == "timeout"
                                         else JobFailureCode.PROVIDER)
    ), (
        'Expected invariant: snapshot.failure.code is (JobFailureCode.TIMEOUT if '
        'error == "timeout" else JobFailureCode.PROVIDER)'
    )
    captures = Captures(snapshot)
    assert (
        set(captures) == {"stdout"}
    ), (
        'Expected invariant: set(captures) == {"stdout"}'
    )
    raw = LocalEvidenceStore(fixture.root / "evidence").Read(captures["stdout"].reference)
    assert (
        raw == f'{{"error":"{error}","schema_version":1}}\n'.encode()
    ), (
        'Expected invariant: raw == '
        'f\'{{"error":"{error}","schema_version":1}}\\n\'.encode()'
    )
    assert (
        captures["stdout"].provenance.execution.state.value == "failed"
    ), (
        'Expected invariant: captures["stdout"].provenance.execution.state.value '
        '== "failed"'
    )
    assert (
        marker not in WorkspaceBytes(fixture.root)
    ), (
        'Expected invariant: marker not in WorkspaceBytes(fixture.root)'
    )
    assert (
        marker.decode() not in str(snapshot.failure)
    ), (
        'Expected invariant: marker.decode() not in str(snapshot.failure)'
    )
    assert (
        all(marker.decode() not in str(event.data) for event in job.EventsSince())
    ), (
        'Expected invariant: all(marker.decode() not in str(event.data) for event '
        'in job.EventsSince())'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 0 and server.accepted == 1
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 0 '
        'and server.accepted == 1'
    )
    assert (
        not any(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince())
    ), (
        'Expected invariant: not any(event.kind is JobEventKind.MODEL_DELTA for '
        'event in job.EventsSince())'
    )


@pytest.mark.parametrize("stage", ["grant", "launch", "after-body", "after-composition"])
def test_ScopeRevocationAtEachOwningBoundaryDeniesFurtherWork(tmp_path, owned_wire,
                                                            monkeypatch, stage):
    """Actual scope mutations cannot substitute stale grant/capture/model authority."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    scopes = LocalScopeStore(fixture.root)

    def Revoke():
        """Persist a genuine owner revision with revoked consent, without changing producer code."""

        current = scopes.Open("local")
        scopes.Save(replace(current, authorization=replace(current.authorization,
                                                           state=AuthorizationState.REVOKED)))

    if stage == "grant":
        Revoke()

    elif stage == "launch":
        original = PolicyEngine.Authorize

        def AuthorizeThenRevoke(self, *args, **kwargs):
            """Change persisted consent after the grant and before final actual launch."""

            grant = original(self, *args, **kwargs)
            Revoke()

            return grant

        monkeypatch.setattr(PolicyEngine, "Authorize", AuthorizeThenRevoke)

    elif stage == "after-body":
        original = JobContext.CaptureEvidence

        def CaptureThenRevoke(self, *args, **kwargs):
            """Retain the already acquired body then revoke before lexical interpretation."""

            artifact = original(self, *args, **kwargs)

            if artifact.evidence.reference.role == "response-body":
                Revoke()

            return artifact

        monkeypatch.setattr(JobContext, "CaptureEvidence", CaptureThenRevoke)

    else:
        original = provider.FinalAuthority

        def RevokeBeforeFinalCheck(*args, **kwargs):
            """Change scope after composition, immediately before the real final owner read."""

            Revoke()

            return original(*args, **kwargs)

        monkeypatch.setattr(provider, "FinalAuthority", RevokeBeforeFinalCheck)

    snapshot = Run(fixture.Job(provider=provider))
    assert (
        snapshot.state is JobState.FAILED
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED'
    )
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION
    ), (
        'Expected invariant: snapshot.failure.code is '
        'JobFailureCode.AUTHORIZATION'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 0
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 0'
    )
    assert (
        server.accepted == (0 if stage in ("grant", "launch") else 1)
    ), (
        'Expected invariant: server.accepted == (0 if stage in ("grant", '
        '"launch") else 1)'
    )
    assert (
        len(snapshot.artifacts) == (0 if stage in ("grant", "launch") else 2)
    ), (
        'Expected invariant: len(snapshot.artifacts) == (0 if stage in ("grant", '
        '"launch") else 2)'
    )


@pytest.mark.parametrize("change", ["revision", "unicode-metadata", "expiry"])
def test_FinalFreshAuthorityAfterAllModelAndEvidenceWork(tmp_path, owned_wire,
                                                        monkeypatch, change):
    """Full snapshot equality and a freshly read expiry clock apply after expensive composition."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin, unicode_consent=True,
        valid_until=(NOW + timedelta(seconds=1)).isoformat())
    current_time = [NOW]
    provider = fixture.Provider(clock=lambda: current_time[0])
    original = provider.FinalAuthority

    def ChangeAtBoundary(*args, **kwargs):
        """Move actual owning revision/metadata or decision clock after prior successful checks."""

        if change == "expiry":
            current_time[0] += timedelta(seconds=1)

        else:
            scopes = LocalScopeStore(fixture.root)
            current = scopes.Open("local")
            authorization = replace(current.authorization,
                record_reference="approval:\u0438\u0437\u043c\u0435\u043d\u0435\u043d\u043e")
            scopes.Save(current if change == "revision" else replace(current,
                                                                     authorization=authorization))

        return original(*args, **kwargs)

    monkeypatch.setattr(provider, "FinalAuthority", ChangeAtBoundary)
    snapshot = Run(fixture.Job(provider=provider))
    assert (
        snapshot.state is JobState.FAILED
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED'
    )
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION
    ), (
        'Expected invariant: snapshot.failure.code is '
        'JobFailureCode.AUTHORIZATION'
    )
    assert (
        "before model Save" in snapshot.failure.message
    ), (
        'Expected invariant: "before model Save" in snapshot.failure.message'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 0 and len(snapshot.artifacts) == 2
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 0 '
        'and len(snapshot.artifacts) == 2'
    )


@pytest.mark.parametrize("failure", ["before", "after", "unknown", "conflict"])
def test_SaveAcknowledgementFailureReopensAndReportsActualKnownState(tmp_path, owned_wire,
                                                                  monkeypatch, failure):
    """A Save exception can occur after a durable commit and must never fabricate rollback."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    original_save = provider._model.Save
    original_open = provider._model.Open
    saving = [False]

    def SaveWithFailure(self, state, *, expected_revision):
        """Inject prewrite/conflict or postcommit lost acknowledgement at the actual owner seam."""

        if failure in ("after", "unknown"):
            original_save(state, expected_revision=expected_revision)

        saving[0] = True

        if failure == "conflict":
            raise WorkspaceConflictError("synthetic-private-context")

        raise OSError("synthetic-private-context")

    def OpenWithUncertainty(self):
        """Make post-Save owner reopen unavailable only for the ambiguous acknowledgement case."""

        if self is provider._model and saving[0] and failure == "unknown":
            raise OSError("synthetic-private-context")

        return original_open()

    monkeypatch.setattr(LocalModelStore, "Save", SaveWithFailure)
    monkeypatch.setattr(LocalModelStore, "Open", OpenWithUncertainty)
    job = fixture.Job(provider=provider)
    snapshot = Run(job)
    assert (
        snapshot.state is JobState.FAILED and snapshot.failure.code is JobFailureCode.STORAGE
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED and '
        'snapshot.failure.code is JobFailureCode.STORAGE'
    )
    expected = {"before": "was not committed", "after": "committed; Save acknowledgement",
                "unknown": "acknowledgement is uncertain", "conflict": "revision conflict"}
    assert (
        expected[failure] in snapshot.failure.message
    ), (
        'Expected invariant: expected[failure] in snapshot.failure.message'
    )
    assert (
        "synthetic-private-context" not in snapshot.failure.message
    ), (
        'Expected invariant: "synthetic-private-context" not in '
        'snapshot.failure.message'
    )
    state = LocalModelStore(fixture.root).Open()
    assert (
        state.revision == (1 if failure in ("after", "unknown") else 0)
    ), (
        'Expected invariant: state.revision == (1 if failure in ("after", '
        '"unknown") else 0)'
    )
    assert (
        len(snapshot.artifacts) == 2
    ), (
        'Expected invariant: len(snapshot.artifacts) == 2'
    )
    assert (
        not any(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince())
    ), (
        'Expected invariant: not any(event.kind is JobEventKind.MODEL_DELTA for '
        'event in job.EventsSince())'
    )


def test_PostSaveModelEventFailureRetainsModelAndWorkerSuccess(tmp_path, owned_wire, monkeypatch):
    """Exhausted event delivery cannot erase the saved page or change its actual worker outcome."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)

    def FailDelivery(self, delta):
        """Inject the consumer event failure after the owning Save has committed."""

        raise RuntimeError("synthetic-private-context")

    monkeypatch.setattr(JobContext, "ModelChanged", FailDelivery)
    snapshot = Run(fixture.Job())
    assert (
        snapshot.state is JobState.FAILED and "committed" in snapshot.failure.message
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED and "committed" in '
        'snapshot.failure.message'
    )
    state = LocalModelStore(fixture.root).Open()
    assert (
        state.revision == 1
    ), (
        'Expected invariant: state.revision == 1'
    )
    source = next(item for item in state.observations if item.kind == "http.synthetic-page")
    assert (
        source.provenance.execution.state.value == "succeeded" and len(snapshot.artifacts) == 2
    ), (
        'Expected invariant: source.provenance.execution.state.value == '
        '"succeeded" and len(snapshot.artifacts) == 2'
    )


def test_ActualWorkerCancellationCleansChildAndStartsNoFurtherRequest(tmp_path, owned_wire):
    """Cooperative owning cancellation finishes governed process cleanup before terminal state."""

    server = owned_wire(hold_seconds=2)
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    job = fixture.Job()

    async def CancelInFlight():
        """Observe the actual owned server request before cancelling its owning running job."""

        job.Start()
        seen = await asyncio.to_thread(server.received.wait, 2)
        assert seen, "Actual worker never reached the owned listener"
        job.Cancel("owner:test")

        return await job.Wait()

    snapshot = asyncio.run(CancelInFlight())
    assert (
        snapshot.state is JobState.CANCELLED and server.accepted == 1
    ), (
        'Expected invariant: snapshot.state is JobState.CANCELLED and '
        'server.accepted == 1'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 0 and not snapshot.artifacts
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 0 '
        'and not snapshot.artifacts'
    )


def test_PostSaveCancellationKeepsCommittedModelWithoutDeliveredDelta(tmp_path, owned_wire,
                                                                    monkeypatch):
    """Cancellation after durable Save retains the committed model and actual worker success."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    job = fixture.Job(provider=provider)
    original = provider._model.Save

    def SaveThenCancel(self, state, *, expected_revision):
        """Cancel owning job only after the actual model owner has returned from commit."""

        result = original(state, expected_revision=expected_revision)
        job.Cancel("owner:test")

        return result

    monkeypatch.setattr(LocalModelStore, "Save", SaveThenCancel)
    snapshot = Run(job)
    assert (
        snapshot.state is JobState.CANCELLED
    ), (
        'Expected invariant: snapshot.state is JobState.CANCELLED'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 1
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 1'
    )
    assert (
        len(snapshot.artifacts) == 2
    ), (
        'Expected invariant: len(snapshot.artifacts) == 2'
    )
    assert (
        not any(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince())
    ), (
        'Expected invariant: not any(event.kind is JobEventKind.MODEL_DELTA for '
        'event in job.EventsSince())'
    )


@pytest.mark.parametrize("mode", ["corrupt", "missing", "actual-oversized"])
def test_ActualManifestGetAndReadFailuresRetainArtifactsWithoutModel(tmp_path, owned_wire,
                                                                 monkeypatch, mode):
    """Get's internally eager actual-reference Read is bounded before owner bytes allocate."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = fixture.Provider()
    original = provider.VerifyEvidence

    def DamageBeforeVerification(record, expected, provenance, role):
        """Damage the actual immutable file or inject a copied oversized owner reference."""

        if role == "response-body":
            path = fixture.root / "evidence" / record.reference.locator

            if mode == "corrupt":
                path.write_bytes(b"x" * len(expected))

            elif mode == "missing":
                path.unlink()

            else:
                reference = copy.copy(record.reference)
                object.__setattr__(reference, "size_bytes", 65537)
                provider._evidence.Read(reference)

        return original(record, expected, provenance, role)

    monkeypatch.setattr(provider, "VerifyEvidence", DamageBeforeVerification)
    snapshot = Run(fixture.Job(provider=provider))
    assert (
        snapshot.state is JobState.FAILED
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED'
    )
    assert (
        snapshot.failure.code is JobFailureCode.NORMALIZATION
    ), (
        'Expected invariant: snapshot.failure.code is '
        'JobFailureCode.NORMALIZATION'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 0 and len(snapshot.artifacts) == 2
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 0 '
        'and len(snapshot.artifacts) == 2'
    )


def test_NoImplicitProviderPermissionAndNoContextOwnershipReuse(tmp_path, owned_wire):
    """A loopback service/catalog does not replace explicit distinct impact-policy permission."""

    server = owned_wire()
    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    provider = replace(fixture, policy=ImpactPolicy("deny")).Provider()
    snapshot = Run(fixture.Job(provider=provider))
    assert (
        snapshot.state is JobState.FAILED
    ), (
        'Expected invariant: snapshot.state is JobState.FAILED'
    )
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION
    ), (
        'Expected invariant: snapshot.failure.code is '
        'JobFailureCode.AUTHORIZATION'
    )
    assert (
        server.accepted == 0 and not snapshot.artifacts
    ), (
        'Expected invariant: server.accepted == 0 and not snapshot.artifacts'
    )


def test_ActualIpv6LiteralLoopbackAcquisitionWhenRunnerOwnsIt(tmp_path, owned_wire):
    """IPv6 loopback follows the same actual one-connection worker and durable owner path."""

    try:
        server = owned_wire(address="::1")

    except OSError:
        pytest.skip("Runner cannot own an IPv6 loopback listener")

    fixture = Fixture.Create(tmp_path / "workspace", server.origin)
    snapshot = Run(fixture.Job())
    assert snapshot.state is JobState.COMPLETED, snapshot.failure
    assert (
        server.accepted == 1 and b"Host: [::1]:" in server.requests[0]
    ), (
        'Expected invariant: server.accepted == 1 and b"Host: [::1]:" in '
        'server.requests[0]'
    )
    assert (
        LocalModelStore(fixture.root).Open().revision == 1
    ), (
        'Expected invariant: LocalModelStore(fixture.root).Open().revision == 1'
    )
