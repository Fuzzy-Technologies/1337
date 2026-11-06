# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise governed endpoint discovery on the original attack-path fixture handlers."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType
from urllib.parse import urlsplit

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore, ObjectKind, RelationKind
from fuzzy1337.quickscan import QuickScanSummary, RunQuickScan
from fuzzy1337.scan_commands import OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

PACK = Path(__file__).resolve().parents[2] / "labs/targets/attack-path-mini"
WORKSPACE_ID = "attack-path-discovery"
OWNER = "operator:attack-path-discovery"
SCOPE_ID = "owned"


def LoadFixtureModule(name: str) -> ModuleType:
    """Read the exact repository-owned handler module without starting its default listener."""

    spec = importlib.util.spec_from_file_location(
        f"attack_path_fixture_{name}", PACK / f"{name}.py")
    assert spec is not None and spec.loader is not None, "The owned lab module must be loadable"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def TrackRequests(handler: type[BaseHTTPRequestHandler],
                  requests: list[tuple[str, str, str, bool]], role: str,
                  monkeypatch: pytest.MonkeyPatch) -> None:
    """Record only request coordinates and credential presence, preserving original responses."""

    parse = handler.parse_request

    def Parse(self: BaseHTTPRequestHandler) -> bool:
        """Observe actual accepted HTTP requests before dispatching to the fixture."""

        if not parse(self):
            return False

        hasCredentials = any(name in self.headers for name in (
            "Authorization", "Cookie", "X-1337-Authorization", "X-1337-Service",
        ))
        requests.append((role, self.command, self.path, hasCredentials))
        return True

    monkeypatch.setattr(handler, "parse_request", Parse)


@contextmanager
def OwnedHealthEndpoints(
    monkeypatch: pytest.MonkeyPatch, requests: list[tuple[str, str, str, bool]],
) -> Iterator[tuple[Target, ...]]:
    """Run the original Portal, Identity and Billing handlers on owned ephemeral loopback."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    identity = LoadFixtureModule("identity")
    billing = LoadFixtureModule("billing")

    def Stop(server: ThreadingHTTPServer, thread: Thread) -> None:
        """Stop and reap one test listener before allowing offline verification."""

        server.shutdown()
        thread.join(timeout=3)
        assert not thread.is_alive(), "The owned discovery service thread must terminate"

    targets = []

    with ExitStack() as cleanup:
        for role, serverType, handler in (
            ("portal", portal.PortalServer, portal.PortalRequestHandler),
            ("identity", ThreadingHTTPServer, identity.IdentityRequestHandler),
            ("billing", ThreadingHTTPServer, billing.BillingRequestHandler),
        ):
            TrackRequests(handler, requests, role, monkeypatch)
            server = cleanup.enter_context(serverType(("127.0.0.1", 0), handler))
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
            thread.start()
            cleanup.callback(Stop, server, thread)
            targets.append(Target(TargetKind.URL, f"http://127.0.0.1:{server.server_port}/health"))

        yield tuple(targets)


def CheckAcquisitions(root: Path, result: QuickScanSummary, targets: tuple[Target, ...]) -> None:
    """Join each exact job's original worker record to the corresponding persisted observation."""

    assert result.ExitCode() == 0, result.snapshot.failure
    store = LocalEvidenceStore(root / "evidence")
    model = LocalModelStore(root).Open()
    job = result.snapshot.spec.job_id
    endpoints = {item.attributes["url"]: item for item in model.Objects(ObjectKind.ENDPOINT)}
    observations = {item.subject_reference: item for item in model.observations
                    if item.kind == "http.response" and item.provenance.run_reference == job}
    assert len(result.snapshot.artifacts) == len(observations) == len(targets), (
        "Each selected endpoint must have one current observation and original acquisition"
    )

    for target, artifact in zip(targets, result.snapshot.artifacts, strict=True):
        record = artifact.evidence
        assert artifact.job_id == job and store.Get(record.evidence_id) == record, (
            "The original worker evidence must belong to the exact executing job"
        )
        assert record.provenance.workspace_id == WORKSPACE_ID, "Evidence workspace drifted"
        assert record.provenance.scope_reference == f"scope:{SCOPE_ID}", "Evidence scope drifted"
        assert record.provenance.source_id == "native.http", "Evidence provider drifted"
        assert json.loads(store.Read(record.reference)) == {
            "schema_version": 1,
            "url": target.value,
            "address": "127.0.0.1",
            "port": urlsplit(target.value).port,
            "scheme": "http",
            "status": 200,
        }, "The native record must contain only the observed exact endpoint and its HTTP status"
        endpoint = endpoints[target.value]
        observed = observations[endpoint.Reference()]
        assert endpoint.attributes["method"] == "GET", "Discovery must not infer POST admission"
        assert observed.kind == "http.response" and observed.attributes == {
            "status": 200, "redirect_followed": False,
        }, "The normalized observation must preserve the worker's response status"
        assert observed.provenance.target_reference == target.Reference(), (
            "Target provenance drifted"
        )
        assert observed.provenance.evidence_references == (record.reference,), (
            "The normalized observation must cite the same retained raw worker record"
        )


def test_AttackPathServicesProduceAttributedEndpointObservationsWithoutPathClaims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify governed discovery, durable evidence, repeat identity and offline reopen."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned attack-path discovery"),
                                     WORKSPACE_ID)
    LocalModelStore(root).Create()
    requests: list[tuple[str, str, str, bool]] = []
    now = datetime.now(UTC)

    with OwnedHealthEndpoints(monkeypatch, requests) as targets:
        members = (*targets, Target(TargetKind.IP, "127.0.0.1"))
        LocalScopeStore(root).Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
            AuthorizationState.GRANTED, OWNER, "approval:attack-path-discovery",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=1)).isoformat(),
        ), targets=members, allow=members))
        denied = asyncio.run(RunQuickScan(root, SCOPE_ID, targets, OWNER, clock=lambda: now))
        assert denied.ExitCode() == 3 and not requests and not denied.snapshot.artifacts, (
            "Registered scope alone must never authorize a fixture contact"
        )
        assert not LocalModelStore(root).Open().objects, "A denied scan must create no model facts"

        first = asyncio.run(RunQuickScan(root, SCOPE_ID, targets, OWNER, approve_safe_http=True,
                                         clock=lambda: now))
        CheckAcquisitions(root, first, targets)
        model = LocalModelStore(root).Open()
        objectIds = {item.Reference() for item in model.objects}
        relationIds = {item.Reference() for item in model.relations}

        repeated = asyncio.run(RunQuickScan(root, SCOPE_ID, targets, OWNER, approve_safe_http=True,
                                            clock=lambda: now + timedelta(seconds=1)))
        CheckAcquisitions(root, repeated, targets)
        assert requests == [
            (role, "GET", "/health", False) for _ in range(2)
            for role in ("portal", "identity", "billing")
        ], "Discovery must issue only the selected anonymous GET per service in each run"

    current = LocalModelStore(root).Open()
    assert {item.Reference() for item in current.objects} == objectIds, (
        "An unchanged rehearsal must retain the same logical objects"
    )
    assert {item.Reference() for item in current.relations} == relationIds, (
        "An unchanged rehearsal must retain the same logical relations"
    )
    assert sum(item.kind == "http.response" for item in current.observations) == 6, (
        "Two scans must preserve two attributed HTTP observation histories"
    )
    assert {item.kind for item in current.relations} == {
        RelationKind.HAS_PORT, RelationKind.HOSTS_SERVICE, RelationKind.EXPOSES,
    }, "Endpoint availability must not be promoted into inferred pivot connectivity"
    reopened = OpenWorkspace(root)
    assert reopened["verified_evidence_records"] == 6, (
        "Reopen must verify both complete sets of original evidence after target teardown"
    )
    assert reopened["relation_count"] == 9, (
        "The three endpoints must retain exactly their attributable host, port and service edges"
    )
    assert reopened["object_counts"] == {
        kind.value: {ObjectKind.HOST: 1, ObjectKind.PORT: 3, ObjectKind.SERVICE: 3,
                     ObjectKind.ENDPOINT: 3}.get(kind, 0) for kind in ObjectKind
    }, "The observed endpoint facts must not create a Finding or a seeded business object"


def test_ExcludedBillingEndpointLeavesNoDiscoveryEvidenceOrFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Honor an exact Billing exclusion even with granted consent and SAFE discovery enabled."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned attack-path discovery"),
                                     WORKSPACE_ID)
    initial = LocalModelStore(root).Create()
    requests: list[tuple[str, str, str, bool]] = []
    now = datetime.now(UTC)

    with OwnedHealthEndpoints(monkeypatch, requests) as (_, _, billing):
        address = Target(TargetKind.IP, "127.0.0.1")
        members = (billing, address)
        scopeStore = LocalScopeStore(root)
        scopeStore.Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
            AuthorizationState.GRANTED, OWNER, "approval:attack-path-discovery",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=1)).isoformat(),
        ), targets=members, allow=members, exclusions=(billing,)))
        scope = scopeStore.Open(SCOPE_ID)
        assert scope.Check(billing, at=now).reason is ScopeDecisionReason.EXCLUDED, (
            "The exact Billing URL exclusion must take precedence over its allow rule."
        )
        assert scope.Check(address, at=now).Allowed(), (
            "The literal loopback destination must remain allowed."
        )

        denied = asyncio.run(RunQuickScan(root, SCOPE_ID, (billing,), OWNER,
                                         approve_safe_http=True, clock=lambda: now))
        assert denied.snapshot.state is JobState.FAILED and denied.ExitCode() == 3, (
            "Excluded Billing discovery must return a failed authorization outcome."
        )
        assert denied.snapshot.failure is not None and (
            denied.snapshot.failure.code is JobFailureCode.AUTHORIZATION
        ), "The discovery job must retain the typed authorization failure."
        assert not denied.snapshot.artifacts, "Denied discovery must retain no acquisitions."

    assert not requests, "Excluded Billing discovery must not contact any owned listener."
    assert LocalModelStore(root).Open() == initial, (
        "Offline reopen must retain the empty model without Findings or reachability facts."
    )
    assert OpenWorkspace(root)["verified_evidence_records"] == 0 and not any(
        item.is_file() for item in (root / "evidence").rglob("*")
    ), "Offline reopen must find no evidence records or worker files."
