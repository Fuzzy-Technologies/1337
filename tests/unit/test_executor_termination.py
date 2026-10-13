# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic owned-process exit, signaling denial and bounded cleanup tests."""

from __future__ import annotations

import asyncio
import errno
import signal
import sys
from collections.abc import Iterator
from types import SimpleNamespace
from typing import cast

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    local,
)
from fuzzy1337.executors.local import LocalExecutionError, LocalExecutor


class OwnedProcess:
    """Represent an owned child whose independent wait controls observed exit."""

    def __init__(self, *, blocked_waits: int = 0) -> None:
        """Configure a finite number of cancellation-responsive hanging waits."""

        self.pid = 31415
        self.returncode: int | None = None
        self.waits = 0
        self.blocked_waits = blocked_waits

    async def Wait(self) -> int:
        """Publish exit only after this independent owned-child wait finishes."""

        self.waits += 1

        if self.waits <= self.blocked_waits:
            await asyncio.Event().wait()

        self.returncode = 0

        return 0

    wait = Wait


@pytest.fixture(scope="module")
def owned_runner() -> Iterator[asyncio.Runner]:
    """Initialize the owned loop before the unchanged Windows unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def runner(owned_runner: asyncio.Runner) -> Iterator[asyncio.Runner]:
    """Cancel and reap all test-owned tasks without creating another event loop."""

    yield owned_runner

    async def Cleanup() -> None:
        """Reap cancellation-responsive tasks at every isolated test boundary."""

        pending = asyncio.all_tasks() - {asyncio.current_task()}

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

    owned_runner.run(Cleanup())


@pytest.fixture
def executor(tmp_path, monkeypatch) -> LocalExecutor:
    """Use POSIX signaling doubles without changing the host platform or network guard."""

    monkeypatch.setattr(local, "os", SimpleNamespace(name="posix", environ={}))
    monkeypatch.setattr(local, "signal", SimpleNamespace(
        SIGTERM=signal.SIGTERM, SIGKILL=getattr(signal, "SIGKILL", 9),
    ))

    return LocalExecutor(tmp_path)


@pytest.mark.parametrize("phase", [signal.SIGTERM, getattr(signal, "SIGKILL", 9)])
def test_ExitedChildEpermRequiresIndependentWaitAndDisappearedGroup(
    executor, runner, monkeypatch, phase,
) -> None:
    """Recover the exit race only after reaping and non-mutating absent-group proof."""

    child = OwnedProcess(blocked_waits=0 if phase == signal.SIGTERM else 1)
    signals = []

    def Signal(process_id: int, selected: int) -> None:
        """Inject one signaling race while checking exact ownership and proof ordering."""

        assert process_id == child.pid, "Only the explicitly owned process may be addressed."
        signals.append(selected)

        if selected == 0:
            assert child.returncode == 0 and child.waits, "Group proof must follow observed exit."

            raise ProcessLookupError(errno.ESRCH, "synthetic absent group")

        if selected == phase:
            raise PermissionError(errno.EPERM, "synthetic zombie group")

    monkeypatch.setattr(local, "KillProcessGroup", Signal)
    runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))
    expected = [signal.SIGTERM, 0] if phase == signal.SIGTERM else [signal.SIGTERM, phase, 0]
    assert signals == expected, "Recovery must not mutate any process after observing child exit."
    assert child.returncode == 0, "A recovered denial must independently confirm owned-child exit."


@pytest.mark.parametrize("phase", [signal.SIGTERM, getattr(signal, "SIGKILL", 9)])
def test_LiveChildDenialAndHangingWaitRemainBoundedFailures(
    executor, runner, monkeypatch, phase,
) -> None:
    """A still-live owned child cannot turn denied cleanup into indefinite or successful work."""

    child = OwnedProcess(blocked_waits=10)
    signals = []

    def Signal(process_id: int, selected: int) -> None:
        """Deny only the selected phase without changing child liveness."""

        assert process_id == child.pid, "Signaling must remain bound to the owned child."
        signals.append(selected)

        if selected == phase:
            raise PermissionError(errno.EPERM, "synthetic live group")

    async def Scenario() -> None:
        """Bound the whole scenario and verify no waiter is abandoned after denial."""

        with pytest.raises(LocalExecutionError):
            await asyncio.wait_for(
                executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01), 0.5,
            )

        assert child.returncode is None, "Genuine live-child denial cannot fabricate observed exit."
        assert asyncio.all_tasks() == {asyncio.current_task()}, "Denied cleanup must reap waiters."

    monkeypatch.setattr(local, "KillProcessGroup", Signal)
    runner.run(Scenario())
    assert 0 not in signals, "A group-disappearance proof cannot precede actual child exit."


@pytest.mark.parametrize("error", [
    PermissionError(errno.EACCES, "synthetic denial"),
    PermissionError("synthetic errno-less denial"),
    OSError(errno.EIO, "synthetic OS error"),
    ProcessLookupError("synthetic unconfirmed group disappearance"),
])
def test_OtherSignalingErrorsCannotBecomeAuthorizationOrRecoveredExit(
    executor, runner, monkeypatch, error,
) -> None:
    """Only the reviewed EPERM race is recoverable; all other OS errors remain provider faults."""

    child = OwnedProcess()

    def Signal(*_arguments: int) -> None:
        """Reject the initial signal with the exact synthetic OS failure."""

        raise error

    monkeypatch.setattr(local, "KillProcessGroup", Signal)

    with pytest.raises(LocalExecutionError):
        runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    assert child.waits == 0, "Non-EPERM denial must not infer a future successful process exit."


@pytest.mark.parametrize("proof", ["present", "denied", "errno_less"])
def test_ReapedChildCannotSuppressRemainingOrInaccessibleGroup(
    executor, runner, monkeypatch, proof,
) -> None:
    """Observed child exit alone cannot hide surviving descendants or an inaccessible group."""

    child = OwnedProcess()
    signals = []

    def Signal(process_id: int, selected: int) -> None:
        """Model a remaining group after an independently reaped child."""

        assert process_id == child.pid, "Existence checks must use only the original owned group."
        signals.append(selected)

        if selected:
            raise PermissionError(errno.EPERM, "synthetic exit race")

        if proof == "denied":
            raise PermissionError(errno.EPERM, "synthetic inaccessible remaining group")

        if proof == "errno_less":
            raise ProcessLookupError("synthetic unconfirmed disappearance")

    monkeypatch.setattr(local, "KillProcessGroup", Signal)

    with pytest.raises(LocalExecutionError):
        runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    assert signals == [signal.SIGTERM, 0], "Reaped or reused groups must receive no new mutation."
    assert child.returncode == 0, "This regression must independently observe child exit."


@pytest.mark.parametrize("hanging", [False, True])
def test_DisappearedGroupStillRequiresBoundedObservedChildExit(
    executor, runner, monkeypatch, hanging,
) -> None:
    """ESRCH cannot silently abandon a live child or an unresolved owned waiter."""

    child = OwnedProcess(blocked_waits=10 if hanging else 0)

    def Signal(*_arguments: int) -> None:
        """Report disappearance without publishing child exit on the caller's behalf."""

        raise ProcessLookupError(errno.ESRCH, "synthetic group disappearance")

    monkeypatch.setattr(local, "KillProcessGroup", Signal)

    if hanging:
        with pytest.raises(LocalExecutionError):
            runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    else:
        runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    assert child.waits == 1, "Group disappearance must still independently observe the owned child."


def test_AlreadyObservedExitPreservesOwnershipGuard(executor, runner, monkeypatch) -> None:
    """Never signal a potentially reused process identifier after its owned child was reaped."""

    child = OwnedProcess()
    child.returncode = 0

    def Signal(*_arguments: int) -> None:
        """Reject every signal, including non-mutating probes, after known prior exit."""

        raise AssertionError("An already-reaped child identifier must never be signaled")

    monkeypatch.setattr(local, "KillProcessGroup", Signal)
    runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))
    assert child.waits == 0, "The existing observed-exit ownership guard must remain unchanged."


def test_KillWaitCannotHangAfterSuccessfulSignal(executor, runner, monkeypatch) -> None:
    """Successful TERM/KILL signaling still requires bounded actual child-exit observation."""

    child = OwnedProcess(blocked_waits=10)
    signals = []
    monkeypatch.setattr(local, "KillProcessGroup",
                        lambda process_id, selected: signals.append(selected))

    async def Scenario() -> None:
        """A cancellation-responsive but unresolved waiter cannot keep cleanup alive forever."""

        with pytest.raises(LocalExecutionError, match="forced termination"):
            await asyncio.wait_for(
                executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01), 0.5,
            )

        assert asyncio.all_tasks() == {asyncio.current_task()}, (
            "Timed-out cleanup must reap waiters."
        )

    runner.run(Scenario())
    assert signals == [signal.SIGTERM, getattr(signal, "SIGKILL", 9)], (
        "A hanging child may receive only the two bounded owned termination attempts."
    )


def test_ReapOperatingSystemErrorRemainsExplicitProviderFault(executor, runner, monkeypatch):
    """A post-launch wait error cannot escape as a false pre-launch policy denial."""

    child = OwnedProcess()

    async def Wait() -> int:
        """Reject the owned reaping operation without publishing a successful return code."""

        raise PermissionError(errno.EPERM, "synthetic reap denial")

    child.wait = Wait
    monkeypatch.setattr(local, "KillProcessGroup", lambda *_arguments: None)

    with pytest.raises(LocalExecutionError, match="observe owned"):
        runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    assert child.returncode is None, "An OS reaping error cannot fabricate an owned exit."


def test_WindowsSignalDenialCannotUsePosixRaceRecovery(executor, runner, monkeypatch):
    """Windows EPERM remains an explicit provider fault without POSIX group-disappearance proof."""

    child = OwnedProcess()

    def Terminate() -> None:
        """Reject the Windows-owned handle operation before any exit observation."""

        raise PermissionError(errno.EPERM, "synthetic Windows denial")

    child.terminate = Terminate
    monkeypatch.setattr(local, "os", SimpleNamespace(name="nt"))

    with pytest.raises(LocalExecutionError):
        runner.run(executor.Terminate(cast(asyncio.subprocess.Process, child), 0.01))

    assert child.waits == 0, "POSIX-only recovery must not reinterpret Windows signaling denial."


def test_AbortPipeDrainingCannotHoldTheCleanupShieldForever(executor, runner, monkeypatch):
    """A hanging owned pipe after observer failure must produce a bounded cleanup error."""

    invocation = AdapterInvocation(
        "test.provider", AdapterRequest("test.local", "target:synthetic", ImpactLevel.SAFE),
        (sys.executable, "-c", "print('synthetic')"), timeout_seconds=1,
    )
    request = LocalExecutionRequest(
        invocation, CapabilityDescriptor("test.local", "test.provider", ImpactLevel.SAFE),
        ExecutionAuthorization("authorization:test", "scope:local", "policy:test",
                               InvocationDigest(invocation)),
        resources=ExecutionResources(terminate_grace_seconds=0.01),
    )

    async def Scenario() -> None:
        """Leave one synthetic pipe open with a finite fallback even if the regression returns."""

        child = OwnedProcess()
        child.stdout = asyncio.StreamReader()
        child.stderr = asyncio.StreamReader()
        child.stdout.feed_data(b"synthetic")
        child.stderr.feed_eof()

        async def Start(*_arguments):
            """Return only this test-owned process/pipe double without subprocess execution."""

            return cast(asyncio.subprocess.Process, child)

        def Observe(event) -> None:
            """Fail the first handoff so cleanup drains never invoke this observer again."""

            raise RuntimeError("synthetic observer failure")

        async def ReleaseFallback() -> None:
            """Ensure a broken implementation still leaves the test-owned pipe finite."""

            await asyncio.sleep(0.5)
            child.stdout.feed_eof()

        monkeypatch.setattr(executor, "StartProcess", Start)
        monkeypatch.setattr(local, "KillProcessGroup", lambda *_arguments: None)
        release = asyncio.create_task(ReleaseFallback())

        try:
            with pytest.raises(LocalExecutionError, match="cleanup"):
                await executor.Execute(request, on_event=Observe)

            assert not release.done(), (
                "Owned pipe cleanup must finish before the fallback deadline."
            )
            assert child.returncode == 0, "This regression must independently reap the owned child."

        finally:
            release.cancel()
            await asyncio.gather(release, return_exceptions=True)

        assert asyncio.all_tasks() == {asyncio.current_task()}, (
            "Aborted cleanup must reap all tasks."
        )

    runner.run(Scenario())
