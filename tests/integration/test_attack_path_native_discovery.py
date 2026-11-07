# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise governed endpoint discovery on the original attack-path fixture handlers."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
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

from fuzzy1337.adapters import ExecutionState
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
    *, billingHealthWire: bytes | None = None,
) -> Iterator[tuple[Target, ...]]:
    """Run the original Portal, Identity and Billing handlers on owned ephemeral loopback."""

    monkeypatch.setitem(sys.modules, "http_common", LoadFixtureModule("http_common"))
    portal = LoadFixtureModule("portal")
    identity = LoadFixtureModule("identity")
    billing = LoadFixtureModule("billing")

    if billingHealthWire is not None:
        original = billing.BillingRequestHandler.do_GET

        def ServeBillingHealth(self: BaseHTTPRequestHandler) -> None:
            """Substitute only the selected Billing health response in this test."""

            if self.path == "/health":
                self.close_connection = True
                self.wfile.write(billingHealthWire)
            else:
                original(self)

        monkeypatch.setattr(billing.BillingRequestHandler, "do_GET", ServeBillingHealth)

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


def CheckAcquisitions(
    root: Path, result: QuickScanSummary, targets: tuple[Target, ...], *, expectedExit: int = 0,
    failedProbes: int = 0,
) -> None:
    """Join each exact job's original worker record to the corresponding persisted observation."""

    assert result.ExitCode() == expectedExit, result.snapshot.failure
    store = LocalEvidenceStore(root / "evidence")
    model = LocalModelStore(root).Open()
    job = result.snapshot.spec.job_id
    endpoints = {item.attributes["url"]: item for item in model.Objects(ObjectKind.ENDPOINT)}
    observations = {item.subject_reference: item for item in model.observations
                    if item.kind == "http.response" and item.provenance.run_reference == job}
    assert len(result.snapshot.artifacts) == len(targets) + failedProbes, (
        "Each completed probe must retain its original acquisition."
    )
    assert len(observations) == len(targets), (
        "Only successful probes must have an attributed HTTP observation."
    )

    for target, artifact in zip(targets, result.snapshot.artifacts[:len(targets)], strict=True):
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

    originalEvidence = LocalEvidenceStore(root / "evidence")
    originals = tuple(
        (artifact.evidence, originalEvidence.Read(artifact.evidence.reference))
        for result in (first, repeated) for artifact in result.snapshot.artifacts
    )
    assert len({record.evidence_id for record, _ in originals}) == 6, (
        "The two jobs must retain six separately attributed original acquisitions."
    )
    observedRequests = tuple(requests)
    relocated = tmp_path / "relocated"
    shutil.copytree(root, relocated)
    assert OpenWorkspace(relocated) == reopened, (
        "Offline relocation must preserve workspace metadata and all verified evidence counts."
    )
    assert LocalModelStore(relocated).Open() == current, (
        "Offline relocation must preserve all objects, relations and attributed observations."
    )
    assert LocalWorkspaceStore(relocated).Open() == LocalWorkspaceStore(root).Open(), (
        "Relocation must preserve exact job and relative evidence references."
    )
    relocatedEvidence = LocalEvidenceStore(relocated / "evidence")

    for record, content in originals:
        assert relocatedEvidence.Get(record.evidence_id) == record, (
            "Offline relocation changed an original evidence identity or its provenance."
        )
        assert relocatedEvidence.Read(record.reference) == content, (
            "Offline relocation changed the immutable original worker bytes."
        )

    CheckAcquisitions(relocated, first, targets)
    CheckAcquisitions(relocated, repeated, targets)
    assert tuple(requests) == observedRequests, "Offline verification must not contact any target."


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


def test_LaterBillingExclusionPreservesOnlyPortalDiscovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain the verified Portal result and stop when the next selected endpoint is excluded."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned attack-path discovery"),
                                     WORKSPACE_ID)
    LocalModelStore(root).Create()
    requests: list[tuple[str, str, str, bool]] = []
    now = datetime.now(UTC)

    with OwnedHealthEndpoints(monkeypatch, requests) as (portal, identity, billing):
        address = Target(TargetKind.IP, "127.0.0.1")
        selected = (portal, billing, identity)
        members = (*selected, address)
        scopeStore = LocalScopeStore(root)
        scopeStore.Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
            AuthorizationState.GRANTED, OWNER, "approval:attack-path-discovery",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=1)).isoformat(),
        ), targets=members, allow=members, exclusions=(billing,)))
        scope = scopeStore.Open(SCOPE_ID)
        assert scope.Check(billing, at=now).reason is ScopeDecisionReason.EXCLUDED, (
            "The Billing URL exclusion must take precedence over its allow rule."
        )
        assert all(
            scope.Check(target, at=now).Allowed() for target in (portal, identity, address)
        ), "Portal, Identity and the literal loopback destination must remain allowed."
        result = asyncio.run(RunQuickScan(root, SCOPE_ID, selected, OWNER,
                                         approve_safe_http=True, clock=lambda: now))
        assert result.snapshot.state is JobState.FAILED and result.snapshot.failure is not None, (
            "Partial discovery must fail when the next endpoint is excluded."
        )
        assert result.snapshot.failure.code is JobFailureCode.AUTHORIZATION, (
            "The partial job must retain its typed authorization failure."
        )

    assert requests == [("portal", "GET", "/health", False)], (
        "Discovery must contact only Portal before aborting at the Billing exclusion."
    )
    CheckPortalOnlyDiscovery(root, result, portal, expectedExit=3)


def CheckPortalOnlyDiscovery(
    root: Path, result: QuickScanSummary, portal: Target, *, expectedExit: int,
    failedProbes: int = 0,
) -> None:
    """Verify that only the successful Portal probe contributed facts after offline reopen."""

    CheckAcquisitions(root, result, (portal,), expectedExit=expectedExit, failedProbes=failedProbes)
    reopened = OpenWorkspace(root)
    records = tuple(artifact.evidence for artifact in result.snapshot.artifacts)
    record = records[0]
    workspace = LocalWorkspaceStore(root).Open()
    assert (
        reopened["verified_evidence_records"] == 1 + failedProbes
        and set(workspace.evidence_record_references) == {item.evidence_id for item in records}
        and set(workspace.evidence_references) == {item.reference for item in records}
    ), "Offline reopen must verify only the original acquisitions for the probes that ran."
    assert reopened["object_counts"] == {
        kind.value: int(kind in {ObjectKind.HOST, ObjectKind.PORT, ObjectKind.SERVICE,
                                ObjectKind.ENDPOINT}) for kind in ObjectKind
    }, "Only Portal discovery may contribute facts and no Finding may be inferred."
    model = LocalModelStore(root).Open()
    assert sum(item.kind == "http.response" for item in model.observations) == 1, (
        "Offline reopen must retain exactly one Portal HTTP response."
    )
    assert all(
        item.provenance.target_reference == portal.Reference()
        and item.provenance.run_reference == result.snapshot.spec.job_id
        and item.provenance.evidence_references == (record.reference,)
        for item in model.observations
    ), "Every persisted observation must be attributable to the original Portal acquisition."
    assert len(model.relations) == 3 and {item.kind for item in model.relations} == {
        RelationKind.HAS_PORT, RelationKind.HOSTS_SERVICE, RelationKind.EXPOSES,
    }, "Portal discovery must retain only its attributable edges without inferred reachability."


def test_LaterMalformedBillingHealthPreservesOnlyPortalDiscovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep Portal facts and typed failure evidence when Billing sends an invalid status line."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned attack-path discovery"),
                                     WORKSPACE_ID)
    LocalModelStore(root).Create()
    requests: list[tuple[str, str, str, bool]] = []
    now = datetime.now(UTC)

    with OwnedHealthEndpoints(
        monkeypatch, requests, billingHealthWire=b"HTTP/1.1 invalid\r\nContent-Length: 0\r\n\r\n",
    ) as (portal, identity, billing):
        selected = (portal, billing, identity)
        members = (*selected, Target(TargetKind.IP, "127.0.0.1"))
        LocalScopeStore(root).Create(ScopeSnapshot(SCOPE_ID, WORKSPACE_ID, ScopeAuthorization(
            AuthorizationState.GRANTED, OWNER, "approval:attack-path-discovery",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=1)).isoformat(),
        ), targets=members, allow=members))
        result = asyncio.run(RunQuickScan(root, SCOPE_ID, selected, OWNER,
                                         approve_safe_http=True, clock=lambda: now))

    assert requests == [
        ("portal", "GET", "/health", False), ("billing", "GET", "/health", False),
    ], "Discovery must make exactly two anonymous requests and stop before Identity."
    assert result.snapshot.state is JobState.FAILED and result.snapshot.failure is not None, (
        "A malformed Billing response must fail the partial discovery job."
    )
    assert result.snapshot.failure.code is JobFailureCode.PROVIDER, (
        "The partial job must preserve its typed worker failure."
    )
    CheckPortalOnlyDiscovery(root, result, portal, expectedExit=4, failedProbes=1)

    failedArtifact = result.snapshot.artifacts[1]
    record = failedArtifact.evidence
    evidence = LocalEvidenceStore(root / "evidence")
    assert failedArtifact.job_id == result.snapshot.spec.job_id and (
        evidence.Get(record.evidence_id) == record
    ), "The original Billing worker failure must remain attached to the partial job."
    assert json.loads(evidence.Read(record.reference)) == {
        "schema_version": 1, "error": "protocol",
    }, "An invalid HTTP status line must retain only the original protocol error record."
    execution = record.provenance.execution
    assert execution is not None and execution.state is ExecutionState.FAILED and (
        execution.exit_code == 1
    ), "The retained error must come from the actual failed worker."
