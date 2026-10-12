# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual scope-store, policy and executor integration using owned offline processes."""

from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionEventKind,
    LocalExecutionError,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.policy import (
    CapabilityPermission,
    GovernedLocalExecutor,
    ImpactPolicy,
    PolicyConfirmation,
    PolicyContext,
    PolicyDenialReason,
    PolicyDeniedError,
    PolicyEngine,
)
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

AT = datetime(2026, 10, 11, 10, tzinfo=timezone.utc)
TARGET = Target(TargetKind.IP, "127.0.0.1")
OTHER = Target(TargetKind.IP, "127.0.0.2")
FIXTURE_SCRIPT = '''# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Write an offline launch marker and bounded streams from an owned child."""

import sys
from pathlib import Path


def Main():
    """Record that launch occurred and preserve the requested terminal code."""

    Path(sys.argv[1]).write_text("launched", encoding="utf-8")
    print("owned synthetic output")
    print("owned diagnostic", file=sys.stderr)

    return int(sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(Main())
'''


def Setup(tmp_path: Path, exit_code: int = 0):
    """Create a real portable scope and an exact confirmed offline invocation."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Policy fixture"), "synthetic")
    store = LocalScopeStore(root)
    store.Create(ScopeSnapshot(
        "synthetic", "synthetic", ScopeAuthorization(
            AuthorizationState.GRANTED, "operator:synthetic", "approval:owned-lab"
        ), targets=(TARGET, OTHER), allow=(TARGET, OTHER),
    ))
    script = root / "owned_fixture.py"
    script.write_text(FIXTURE_SCRIPT, encoding="utf-8")
    marker = root / "launch-marker.txt"
    invocation = AdapterInvocation(
        "native.synthetic", AdapterRequest(
            "test.synthetic", TARGET.Reference(), ImpactLevel.STANDARD
        ), (sys.executable, str(script), str(marker), str(exit_code)), 5, "synthetic-1",
    )
    capability = CapabilityDescriptor("test.synthetic", "native.synthetic", ImpactLevel.STANDARD)
    policy = ImpactPolicy("synthetic", maximum_impact=ImpactLevel.STANDARD, permissions=(
        CapabilityPermission("test.synthetic", "native.synthetic", ImpactLevel.STANDARD),
    ))

    def CurrentContext():
        """Read current persisted scope and trusted pinned destination observations."""

        return PolicyContext(store.Open("synthetic"), policy, TARGET, (TARGET,))

    engine = PolicyEngine()
    plan = engine.Plan(invocation, capability, CurrentContext(), at=AT)
    grant = engine.Authorize(invocation, capability, CurrentContext(), at=AT, confirmation=(
        PolicyConfirmation(plan.intent_sha256, "approval:exact-plan")
    ))
    request = LocalExecutionRequest(invocation, capability, grant.authorization)

    return root, marker, store, CurrentContext, grant, request


@pytest.mark.parametrize("exit_code", (0, 7))
def test_GovernedRealProcessPreservesOutputEventsAndTerminalTruth(tmp_path, exit_code):
    """Policy-approved owned processes retain the existing executor's full terminal contract."""

    root, marker, _, context_provider, grant, request = Setup(tmp_path, exit_code)
    observed = []
    result = asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
        request, grant=grant, context_provider=context_provider, on_event=observed.append
    ))
    assert marker.read_text(encoding="utf-8") == "launched", "Approved invocation did not launch"
    assert result.execution.exit_code == exit_code, "Policy facade changed the child's exit code"
    expected = ExecutionState.SUCCEEDED if exit_code == 0 else ExecutionState.FAILED
    assert result.execution.state == expected, "Failed child execution became policy success"
    assert result.stdout.strip() == b"owned synthetic output", "Governance lost raw stdout"
    assert result.stderr.strip() == b"owned diagnostic", "Governance lost raw stderr"
    assert observed == list(result.events), "Governance lost lifecycle events"
    assert observed[0].kind == ExecutionEventKind.STARTED, "Started event is missing"
    assert observed[-1].kind == ExecutionEventKind.COMPLETED, "Completion event is missing"


def test_PersistedScopeEditDuringWorkspaceValidationIsCaughtAtLaunch(tmp_path, monkeypatch):
    """The facade reopens scope after executor preparation, rather than checking an old snapshot."""

    root, marker, store, context_provider, grant, request = Setup(tmp_path)
    original_resolve = LocalExecutor.ResolveWorkspace

    def ResolveAndChangeScope(executor, workspace):
        """Simulate a consent revision during preparation immediately before launch."""

        path = original_resolve(executor, workspace)
        store.Save(replace(store.Open("synthetic"), allow=(TARGET,)))

        return path

    monkeypatch.setattr(LocalExecutor, "ResolveWorkspace", ResolveAndChangeScope)

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
            request, grant=grant, context_provider=context_provider
        ))

    assert denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED'
    )
    assert not marker.exists(), "A stale grant started its owned process"


def test_AllowlistedButChangedActualDestinationInvalidatesLaunchGrant(tmp_path):
    """Even another allowed destination requires a newly reviewed exact intent."""

    root, marker, _, context_provider, grant, request = Setup(tmp_path)

    def ChangedDestination():
        """Present a changed current destination, without broadening scope membership."""

        return replace(context_provider(), destinations=(OTHER,))

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
            request, grant=grant, context_provider=ChangedDestination
        ))

    assert denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED'
    )
    assert not marker.exists(), "A destination change started a stale invocation"


def test_DeniedCurrentScopeStopsLaunchWithoutProcessOrSuccessEvents(tmp_path):
    """Revocation immediately before execution is enforced against persisted current scope."""

    root, marker, store, context_provider, grant, request = Setup(tmp_path)
    scope = store.Open("synthetic")
    store.Save(replace(scope, authorization=ScopeAuthorization(AuthorizationState.REVOKED)))
    observed = []

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
            request, grant=grant, context_provider=context_provider, on_event=observed.append
        ))

    assert denied.value.reason == PolicyDenialReason.SCOPE_DENIED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.SCOPE_DENIED'
    )
    assert not marker.exists(), "Revoked scope started a child process"
    assert observed == [], "Denied execution emitted misleading lifecycle events"


def test_ExpiredGrantStopsLaunch(tmp_path):
    """An exact previously approved invocation still expires before process creation."""

    root, marker, _, context_provider, grant, request = Setup(tmp_path)

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT + timedelta(minutes=5)).Execute(
            request, grant=grant, context_provider=context_provider
        ))

    assert denied.value.reason == PolicyDenialReason.GRANT_EXPIRED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.GRANT_EXPIRED'
    )
    assert not marker.exists(), "Expired grant started a child process"


def test_SubstitutedSdkEnvelopeCannotBypassPolicyFacade(tmp_path):
    """A request with a matching invocation but unrelated envelope is rejected before launch."""

    root, marker, _, context_provider, grant, request = Setup(tmp_path)
    request = replace(request, authorization=replace(
        request.authorization, authorization_id="authorization:substituted"
    ))

    with pytest.raises(PolicyDeniedError) as denied:
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
            request, grant=grant, context_provider=context_provider
        ))

    assert denied.value.reason == PolicyDenialReason.GRANT_CHANGED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.GRANT_CHANGED'
    )
    assert not marker.exists(), "Substituted envelope started a child process"


def test_FailedCurrentContextReadNeverDegradesToSdkExecution(tmp_path):
    """An unavailable authority store cannot implicitly skip governance."""

    root, marker, _, _, grant, request = Setup(tmp_path)

    def UnavailableContext():
        """Represent an unavailable or malformed persisted authority read."""

        raise OSError("synthetic authority is unavailable")

    with pytest.raises(OSError, match="synthetic authority"):
        asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
            request, grant=grant, context_provider=UnavailableContext
        ))

    assert not marker.exists(), "Authority read failure started a child process"


def test_PreCancelledPolicyExecutionRetainsNoLaunchBehavior(tmp_path):
    """A cancelled request performs no launch and cannot become a successful scan."""

    root, marker, _, context_provider, grant, request = Setup(tmp_path)
    cancellation = asyncio.Event()
    cancellation.set()
    result = asyncio.run(GovernedLocalExecutor(root, clock=lambda: AT).Execute(
        request, grant=grant, context_provider=context_provider, cancellation=cancellation
    ))
    assert result.execution.state == ExecutionState.CANCELLED, (
        "Precancelled execution became success"
    )
    assert not marker.exists(), "Precancelled policy execution started a child process"


def test_ConcurrentGovernedInvocationsKeepIndependentExactGrantBindings(tmp_path):
    """One facade can run two distinct approved invocations without mutable shared grant state."""

    root, marker, _, context_provider, first_grant, first_request = Setup(tmp_path)
    second_marker = root / "second-marker.txt"
    second_invocation = replace(first_request.invocation, argv=(
        *first_request.invocation.argv[:2], str(second_marker), "7"
    ))
    engine = PolicyEngine()
    second_plan = engine.Plan(
        second_invocation, first_request.capability, context_provider(), at=AT
    )
    second_grant = engine.Authorize(
        second_invocation, first_request.capability, context_provider(), at=AT,
        confirmation=PolicyConfirmation(second_plan.intent_sha256, "approval:second-plan"),
    )
    second_request = replace(
        first_request, invocation=second_invocation, authorization=second_grant.authorization
    )

    async def RunBoth():
        """Launch both exact grants concurrently through one shared facade."""

        executor = GovernedLocalExecutor(root, clock=lambda: AT)

        return await asyncio.gather(
            executor.Execute(first_request, grant=first_grant, context_provider=context_provider),
            executor.Execute(second_request, grant=second_grant, context_provider=context_provider),
        )

    results = asyncio.run(RunBoth())
    assert [item.execution.exit_code for item in results] == [0, 7], (
        "Concurrent grants crossed jobs"
    )
    assert marker.exists() and second_marker.exists(), "Concurrent owned invocation was lost"


def test_UntypedPolicyGrantIsRejectedBeforeLaunch(tmp_path):
    """The launch facade requires its exact typed grant, rather than an SDK envelope alone."""

    root, marker, _, context_provider, _, request = Setup(tmp_path)

    with pytest.raises(ValueError, match="PolicyGrant"):
        asyncio.run(GovernedLocalExecutor(root).Execute(
            request, grant=None, context_provider=context_provider
        ))

    assert not marker.exists(), "An untyped grant reached process creation"


@pytest.mark.parametrize("mode", ("async", "value"))
def test_AsyncOrNonvoidPreLaunchHookIsRejectedBeforeProcessCreation(tmp_path, mode):
    """A mistaken asynchronous policy hook cannot be silently ignored by the SDK executor."""

    root, marker, _, _, _, request = Setup(tmp_path)

    async def AsyncHook(current_request):
        """Represent a mistaken asynchronous upstream hook that would otherwise never run."""

        raise RuntimeError("must not run")

    def ValueHook(current_request):
        """Represent a mistaken boolean-returning policy hook."""

        return False

    hook = AsyncHook if mode == "async" else ValueHook

    with pytest.raises(LocalExecutionError, match="synchronous and return None"):
        asyncio.run(LocalExecutor(root).Execute(request, pre_launch=hook))

    assert not marker.exists(), "Malformed policy hook reached process creation"
