# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline discovery plan, governed execution, persistence and truthful failure tests."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fuzzy1337 import discovery
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.adapters.native_http import NATIVE_HTTP_CAPABILITY, NATIVE_HTTP_PROVIDER_ID
from fuzzy1337.discovery import DiscoveryLimits, NativeDiscoveryProvider
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors.contracts import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobSpec, JobState, ScanJob
from fuzzy1337.model import LocalModelStore
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
URL = "http://127.0.0.1:8080/health"


def Fixture(tmp_path: Path):
    """Create an explicitly owned authorized synthetic scope/model without networking."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    LocalModelStore(root).Create()
    target = Target(TargetKind.URL, URL)
    ip = Target(TargetKind.IP, "127.0.0.1")
    scope = ScopeSnapshot("local", "synthetic", ScopeAuthorization(
        AuthorizationState.GRANTED, "owner:test", "approval:fixture",
    ), targets=(target, ip), allow=(target, ip))
    LocalScopeStore(root).Create(scope)
    policy = ImpactPolicy("local", permissions=(CapabilityPermission(
        NATIVE_HTTP_CAPABILITY, NATIVE_HTTP_PROVIDER_ID, ImpactLevel.SAFE,
    ),))
    return root, target, scope, policy


def Outcome(raw: bytes | None = None, *, state=ExecutionState.SUCCEEDED,
            termination=ExecutionTermination.PROCESS_EXIT, exit_code=0):
    """Produce a real-contract bounded executor result without any subprocess or sockets."""

    payload = json.dumps({"schema_version": 1, "url": URL, "address": "127.0.0.1",
                          "port": 8080, "scheme": "http", "status": 200}).encode()
    return LocalExecutionResult(AdapterExecution(state, exit_code, 0.1), termination,
        payload if raw is None else raw, b"", (
            ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.COMPLETED, termination=termination),
        ))


def Job(root, target, policy, *, limits=DiscoveryLimits(), provider=None, **changes):
    """Bind canonical job/evidence ownership to the typed discovery producer."""

    producer = provider or NativeDiscoveryProvider(root, (target,), "local", policy,
                                                  limits=limits, clock=lambda: NOW)
    spec = JobSpec("job:fixture", "synthetic", "scope:local", "owner:test",
                   NATIVE_HTTP_PROVIDER_ID)
    return ScanJob(replace(spec, **changes), producer,
                   evidence_store=LocalEvidenceStore(root / "evidence"))


def Run(job, discovery_runner):
    """Run the async job lifecycle on the owned deterministic event loop."""

    async def StartAndWait():
        """Start and await the job without bypassing its failure-state boundary."""

        job.Start()
        return await job.Wait()

    return discovery_runner.run(StartAndWait())


@pytest.fixture(scope="module")
def owned_discovery_runner() -> Iterator[asyncio.Runner]:
    """Initialize Windows loop self-pipes before the unchanged unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def discovery_runner(owned_discovery_runner: asyncio.Runner) -> Iterator[asyncio.Runner]:
    """Reuse the owned loop and reap pending tasks at every test boundary."""

    yield owned_discovery_runner

    async def Cleanup() -> None:
        """Cancel and await every unfinished task without opening another loop."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_discovery_runner.run(Cleanup())


@pytest.fixture
def fake_executor(monkeypatch):
    """Replace process execution while preserving real policy launch validation."""

    class Executor:
        """Offline executor fixture with observable cleanup and exact policy validation."""

        calls = 0
        outcome = Outcome()
        error = None
        before = None
        block = False
        cleaned = False

        def __init__(self, root, *, clock):
            """Retain the injected clock only; never launch a process."""

            self.clock = clock

        async def Execute(self, request, *, grant, context_provider, on_event, cancellation):
            """Validate fresh authority and return the configured finite synthetic outcome."""

            if self.error is not None:
                raise self.error

            if self.before is not None:
                self.before()

            PolicyEngine().Validate(grant, request.invocation, request.capability,
                                    context_provider(), at=self.clock())
            type(self).calls += 1
            on_event(ExecutionEvent(0, ExecutionEventKind.STARTED))

            try:
                if self.block:
                    await cancellation.wait()
                    return Outcome(b"", state=ExecutionState.CANCELLED,
                        termination=ExecutionTermination.CANCELLATION, exit_code=-15)

                return self.outcome

            finally:
                type(self).cleaned = True

    monkeypatch.setattr(discovery, "GovernedLocalExecutor", Executor)
    return Executor


def test_DiscoveryPersistsVerifiedModelAndStreamsDelta(tmp_path, fake_executor, discovery_runner):
    """Sensor facts and verified raw output enter existing storage before the update event."""

    root, target, _, policy = Fixture(tmp_path)
    job = Job(root, target, policy)
    snapshot = Run(job, discovery_runner)
    assert (
        snapshot.state is JobState.COMPLETED and fake_executor.calls == 1
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    state = LocalModelStore(root).Open()
    assert (
        len(state.objects) == 4 and len(state.relations) == 3
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    assert (
        any(event.kind is JobEventKind.MODEL_DELTA for event in job.EventsSince())
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    assert (
        len(snapshot.artifacts) == 1
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    assert (
        LocalEvidenceStore(root / "evidence").Read(snapshot.artifacts[0].evidence.reference)
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    references = tuple(item.Reference() for item in state.objects)
    repeated = Run(Job(root, target, policy), discovery_runner)
    assert (
        repeated.state is JobState.COMPLETED
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'
    assert (
        tuple(item.Reference() for item in LocalModelStore(root).Open().objects) == references
    ), 'Discovery Persists Verified Model And Streams Delta boundary invariant failed'


@pytest.mark.parametrize("changes", [
    {"max_endpoints": True}, {"max_endpoints": 0}, {"max_endpoints": 17},
    {"request_timeout_seconds": 0}, {"interval_seconds": True},
    {"interval_seconds": float("nan")}, {"interval_seconds": 0},
    {"timeout_seconds": 61}, {"timeout_seconds": float("inf")},
])
def test_PlanRejectsUnboundedLimits(changes):
    """No invalid resource parameter can weaken the finite discovery contract."""

    with pytest.raises(ValueError):
        DiscoveryLimits(**changes)


def test_FirstUsefulUpdateBudgetIncludesStartupAllowance():
    """The advertised first-update budget is distinct from the complete scan budget."""

    assert (
        DiscoveryLimits().FirstUpdateBudgetSeconds == 4
    ), 'First Useful Update Budget Includes Startup Allowance boundary invariant failed'
    assert (
        DiscoveryLimits(timeout_seconds=1).FirstUpdateBudgetSeconds == 1
    ), 'First Useful Update Budget Includes Startup Allowance boundary invariant failed'


def test_LimitHugeIntegersAreRejectedWithoutOverflow():
    """Plan interval and total deadline validation checks hard bounds before float conversion."""

    for name in ("interval_seconds", "timeout_seconds"):
        with pytest.raises(ValueError):
            DiscoveryLimits(**{name: 10 ** 10000})


@pytest.mark.parametrize("case", ["limits", "policy", "empty", "list", "kind", "duplicate"])
def test_ProducerRejectsInvalidTypedPlan(tmp_path, case):
    """Construction validates the plan without reading files or starting workers."""

    target = Target(TargetKind.URL, URL)
    args = {"targets": (target,), "policy": ImpactPolicy("local"), "limits": DiscoveryLimits()}

    if case == "limits":
        args["limits"] = None

    elif case == "policy":
        args["policy"] = None

    elif case == "empty":
        args["targets"] = ()

    elif case == "list":
        args["targets"] = [target]

    elif case == "kind":
        args["targets"] = (Target(TargetKind.IP, "127.0.0.1"),)

    else:
        args["targets"] = (target, target)

    with pytest.raises(ValueError):
        NativeDiscoveryProvider(tmp_path / "absent", scope_id="local", **args)


@pytest.mark.parametrize("changes", [
    {"workspace_id": "foreign"}, {"provider_id": "foreign.provider"},
    {"scope_reference": "scope:foreign"},
])
def test_JobOwnershipMismatchCannotProbe(tmp_path, fake_executor, changes, discovery_runner):
    """A discovery provider cannot consume an unrelated job's authority or storage."""

    root, target, _, policy = Fixture(tmp_path)
    snapshot = Run(Job(root, target, policy, **changes), discovery_runner)
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0
    ), 'Job Ownership Mismatch Cannot Probe boundary invariant failed'


@pytest.mark.parametrize("case", ["unknown", "expired", "excluded", "policy", "changed"])
def test_CurrentAuthorityDeniedBeforeProbe(tmp_path, fake_executor, case, discovery_runner):
    """Fresh policy checks block unconsented, expired, excluded and changed scope."""

    root, target, scope, policy = Fixture(tmp_path)
    store = LocalScopeStore(root)

    if case == "unknown":
        store.Save(replace(scope, authorization=ScopeAuthorization()))

    elif case == "expired":
        store.Save(replace(scope, authorization=replace(scope.authorization,
            valid_until="2026-10-12T00:00:00+00:00")))

    elif case == "excluded":
        store.Save(replace(scope, exclusions=(Target(TargetKind.IP, "127.0.0.1"),)))

    elif case == "policy":
        policy = ImpactPolicy("local")

    else:
        def Change():
            """Revoke current consent after grant issuance but before launch validation."""

            store.Save(replace(scope, authorization=ScopeAuthorization(AuthorizationState.REVOKED)))

        fake_executor.before = staticmethod(Change)

    snapshot = Run(Job(root, target, policy), discovery_runner)
    assert (
        snapshot.state is JobState.FAILED
    ), 'Current Authority Denied Before Probe boundary invariant failed'
    assert (
        snapshot.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0
    ), 'Current Authority Denied Before Probe boundary invariant failed'
    assert (
        not LocalModelStore(root).Open().objects
    ), 'Current Authority Denied Before Probe boundary invariant failed'


@pytest.mark.parametrize("case,code", [
    ("output", JobFailureCode.OUTPUT_LIMIT), ("deadline", JobFailureCode.TIMEOUT),
    ("worker-timeout", JobFailureCode.TIMEOUT), ("malformed", JobFailureCode.NORMALIZATION),
    ("worker-failure", JobFailureCode.PROVIDER),
])
def test_WorkerOutcomesRemainTruthful(tmp_path, fake_executor, case, code, discovery_runner):
    """Partial, failed and malformed worker results cannot create successful model facts."""

    root, target, _, policy = Fixture(tmp_path)

    if case == "output":
        result = Outcome(b"", state=ExecutionState.FAILED,
                          termination=ExecutionTermination.OUTPUT_LIMIT, exit_code=1)

    elif case == "deadline":
        result = Outcome(b"", state=ExecutionState.TIMED_OUT,
                          termination=ExecutionTermination.TIMEOUT, exit_code=-15)

    elif case == "malformed":
        result = Outcome(b'{"body":"secret"}')

    else:
        name = "timeout" if case == "worker-timeout" else "connection"
        result = Outcome(json.dumps({"schema_version": 1, "error": name}).encode(),
                          state=ExecutionState.FAILED, exit_code=124 if name == "timeout" else 1)

    fake_executor.outcome = result
    snapshot = Run(Job(root, target, policy), discovery_runner)
    assert (
        snapshot.state is JobState.FAILED and snapshot.failure.code is code
    ), 'Worker Outcomes Remain Truthful boundary invariant failed'
    assert (
        not LocalModelStore(root).Open().objects
    ), 'Worker Outcomes Remain Truthful boundary invariant failed'

    if case == "malformed":
        assert not snapshot.artifacts, "Unvalidated output must never enter raw evidence"


@pytest.mark.parametrize("error,code", [
    (LocalExecutionError("fixture"), JobFailureCode.PROVIDER),
    (PermissionError("fixture"), JobFailureCode.AUTHORIZATION),
    (OSError("fixture"), JobFailureCode.STORAGE),
])
def test_LaunchErrorsAreClassified(tmp_path, fake_executor, error, code, discovery_runner):
    """Execution and storage faults retain their cause without claiming discovery success."""

    root, target, _, policy = Fixture(tmp_path)
    fake_executor.error = error
    snapshot = Run(Job(root, target, policy), discovery_runner)
    assert (
        snapshot.failure.code is code and not snapshot.artifacts
    ), 'Launch Errors Are Classified boundary invariant failed'


def test_ModelStorageFailureRetainsVerifiedEvidence(
    tmp_path, monkeypatch, fake_executor, discovery_runner,
):
    """A failed model commit leaves actual verified sensor evidence available for diagnostics."""

    root, target, _, policy = Fixture(tmp_path)

    def Fail(*args, **kwargs):
        """Simulate a storage fault without touching another subsystem's authoritative state."""

        raise OSError("fixture storage failure")

    monkeypatch.setattr(LocalModelStore, "Save", Fail)
    snapshot = Run(Job(root, target, policy), discovery_runner)
    assert (
        snapshot.failure.code is JobFailureCode.STORAGE and len(snapshot.artifacts) == 1
    ), 'Model Storage Failure Retains Verified Evidence boundary invariant failed'
    assert (
        not LocalModelStore(root).Open().objects
    ), 'Model Storage Failure Retains Verified Evidence boundary invariant failed'


def test_MissingInitialStateIsStorageFailure(tmp_path, fake_executor, discovery_runner):
    """The producer never invents an unrelated workspace or rebuilds missing authoritative state."""

    target = Target(TargetKind.URL, URL)
    snapshot = Run(Job(tmp_path / "absent", target, ImpactPolicy("local")), discovery_runner)
    assert (
        snapshot.failure.code is JobFailureCode.STORAGE and fake_executor.calls == 0
    ), 'Missing Initial State Is Storage Failure boundary invariant failed'


def test_EvidenceVerificationFailureCannotPersistModel(
    tmp_path, monkeypatch, fake_executor, discovery_runner,
):
    """Corrupt owned evidence is rejected before canonical model persistence."""

    root, target, _, policy = Fixture(tmp_path)
    monkeypatch.setattr(discovery.NativeHttpAdapter, "NormalizeReport",
                        lambda *args: (_ for _ in ()).throw(ValueError("fixture")))
    snapshot = Run(Job(root, target, policy), discovery_runner)
    assert (
        snapshot.failure.code is JobFailureCode.NORMALIZATION and len(snapshot.artifacts) == 1
    ), 'Evidence Verification Failure Cannot Persist Model boundary invariant failed'


def test_CancellationWaitsForOwnedExecutionCleanup(tmp_path, fake_executor, discovery_runner):
    """Cancellation cannot publish success while the worker still owns resources."""

    root, target, _, policy = Fixture(tmp_path)
    fake_executor.block = True
    job = Job(root, target, policy)

    async def Cancel():
        """Cancel only after execution starts and wait for provider cleanup."""

        job.Start()

        while not fake_executor.calls:
            await asyncio.sleep(0)

        return await job.CancelAndWait("owner:test")

    snapshot = discovery_runner.run(Cancel())
    assert (
        snapshot.state is JobState.CANCELLED and fake_executor.cleaned
    ), 'Cancellation Waits For Owned Execution Cleanup boundary invariant failed'
    assert (
        not snapshot.artifacts and not LocalModelStore(root).Open().objects
    ), 'Cancellation Waits For Owned Execution Cleanup boundary invariant failed'


def test_TotalDeadlineCancelsOwnedExecution(tmp_path, fake_executor, discovery_runner):
    """The total provider deadline terminates blocked acquisition truthfully."""

    root, target, _, policy = Fixture(tmp_path)
    fake_executor.block = True
    snapshot = Run(
        Job(root, target, policy, limits=DiscoveryLimits(timeout_seconds=0.05)),
        discovery_runner,
    )
    assert (
        snapshot.failure.code is JobFailureCode.TIMEOUT and fake_executor.cleaned
    ), 'Total Deadline Cancels Owned Execution boundary invariant failed'


def test_ContextGuardMustBeCallableBeforeAnyStateAccess(tmp_path):
    """A malformed trusted consumer hook is rejected during side-effect-free construction."""

    with pytest.raises(ValueError, match="callable"):
        NativeDiscoveryProvider(tmp_path / "absent", (Target(TargetKind.URL, URL),), "local",
                                ImpactPolicy("local"), context_validator=1)


def test_ContextGuardIsAdditionalAtIssuanceAndFinalLaunch(
    tmp_path, fake_executor, discovery_runner,
):
    """A successful consumer guard sees fresh context twice without replacing core policy."""

    root, target, _, policy = Fixture(tmp_path)
    observed = []

    def Validate(context):
        """Record immutable current decision inputs without altering or granting authority."""

        observed.append(context.scope.revision)

    provider = NativeDiscoveryProvider(root, (target,), "local", policy, clock=lambda: NOW,
                                       context_validator=Validate)
    result = Run(Job(root, target, policy, provider=provider), discovery_runner)
    assert result.state is JobState.COMPLETED, (
        "Valid additional context guard must permit ordinarily authorized execution"
    )
    assert observed == [0, 0] and fake_executor.calls == 1, (
        "Context guard must run at issuance and governed final launch"
    )
    denied = NativeDiscoveryProvider(root, (target,), "local", ImpactPolicy("denied"),
                                     clock=lambda: NOW, context_validator=Validate)
    result = Run(Job(root, target, policy, provider=denied), discovery_runner)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 1, (
        "A passing consumer hook must never bypass ordinary missing-capability denial"
    )


@pytest.mark.parametrize("fail_at", [1, 2])
def test_ContextGuardDenialCannotLaunchWorker(tmp_path, fake_executor, fail_at, discovery_runner):
    """Additional consumer denial is enforced before issuance and at actual final launch."""

    root, target, _, policy = Fixture(tmp_path)
    observed = []

    def Validate(context):
        """Deny at the configured boundary without changing current authoritative scope."""

        observed.append(context)

        if len(observed) == fail_at:
            raise PermissionError("consumer condition denied")

    provider = NativeDiscoveryProvider(root, (target,), "local", policy, clock=lambda: NOW,
                                       context_validator=Validate)
    result = Run(Job(root, target, policy, provider=provider), discovery_runner)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0, (
        "Denied trusted context guard must prevent every probe"
    )


@pytest.mark.parametrize("response", [False, True, "approved", 1])
def test_ContextGuardMustSynchronouslyReturnNone(
    tmp_path, fake_executor, response, discovery_runner,
):
    """No accidental truthy/falsey consumer return can become an authorization decision."""

    root, target, _, policy = Fixture(tmp_path)
    provider = NativeDiscoveryProvider(root, (target,), "local", policy, clock=lambda: NOW,
                                       context_validator=lambda context: response)
    result = Run(Job(root, target, policy, provider=provider), discovery_runner)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0, (
        "Non-None context-validator return must fail closed before any execution"
    )


def test_AsyncContextGuardIsClosedAndCannotSilentlySkipValidation(
    tmp_path, fake_executor, discovery_runner,
):
    """An accidentally async guard is rejected and its unawaited bare coroutine is closed."""

    root, target, _, policy = Fixture(tmp_path)
    coroutines = []

    async def AsyncValidate(context):
        """Never run because trusted guards must validate synchronously at the launch boundary."""

        raise AssertionError("async context guard must not run")

    def Validate(context):
        """Expose the mistaken coroutine for explicit cleanup verification."""

        response = AsyncValidate(context)
        coroutines.append(response)
        return response

    provider = NativeDiscoveryProvider(root, (target,), "local", policy, clock=lambda: NOW,
                                       context_validator=Validate)
    result = Run(Job(root, target, policy, provider=provider), discovery_runner)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0, (
        "Async context guard must never be treated as completed authorization"
    )
    assert inspect.getcoroutinestate(coroutines[0]) == inspect.CORO_CLOSED, (
        "Rejected bare coroutine must be closed rather than leak pending validation"
    )


def test_GenericSdkDoesNotEquateAttesterWithJobOwner(tmp_path, fake_executor, discovery_runner):
    """Optional consumer binding does not impose authentication semantics on all SDK operators."""

    root, target, scope, policy = Fixture(tmp_path)
    LocalScopeStore(root).Save(replace(scope, authorization=replace(
        scope.authorization, authority_reference="attester:different",
    )))
    result = Run(Job(root, target, policy), discovery_runner)
    assert result.state is JobState.COMPLETED and fake_executor.calls == 1, (
        "Ordinary generic SDK must retain distinct attester and executing owner semantics"
    )


def test_CustomAwaitableGuardIsRejectedWithoutEvaluatingIt(
    tmp_path, fake_executor, discovery_runner,
):
    """Non-coroutine awaitables cannot defer or silently skip synchronous consumer checks."""

    root, target, _, policy = Fixture(tmp_path)

    class DeferredValidation:
        """Synthetic awaitable whose evaluation would violate the synchronous guard contract."""

        def __await__(self):
            """Fail if an invalid trusted hook is accidentally scheduled or awaited."""

            raise AssertionError("deferred context guard must not run")
            yield

    provider = NativeDiscoveryProvider(root, (target,), "local", policy, clock=lambda: NOW,
                                       context_validator=lambda context: DeferredValidation())
    result = Run(Job(root, target, policy, provider=provider), discovery_runner)
    assert result.failure.code is JobFailureCode.AUTHORIZATION and fake_executor.calls == 0, (
        "Deferred non-coroutine context validator must fail closed synchronously"
    )
