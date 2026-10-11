# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic local job lifecycle, event ownership and cancellation checks."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import NormalizedObservation
from fuzzy1337.evidence import EvidenceProvenance, EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.jobs import (
    JobArtifact,
    JobContext,
    JobError,
    JobEvent,
    JobEventKind,
    JobFailure,
    JobFailureCode,
    JobProgress,
    JobSpec,
    JobState,
    ScanJob,
)
from fuzzy1337.model import ModelDelta


class FunctionProvider:
    """Run one deterministic callback without external tools or target access."""

    def __init__(self, callback: Callable[[JobContext], Awaitable[None]]) -> None:
        """Bind the callback used by a lifecycle test."""

        self.callback = callback

    async def Run(self, context: JobContext) -> None:
        """Use the same provider contract as real scan orchestration."""

        await self.callback(context)


def Spec() -> JobSpec:
    """Return synthetic non-secret job attribution."""

    return JobSpec("job:test", "workspace-test", "scope:local", "owner:test", "test.provider")


def Provenance(**changes: object) -> EvidenceProvenance:
    """Return matching synthetic evidence provenance with deliberate variations."""

    provenance = EvidenceProvenance(
        "workspace-test", "scope:local", "test.provider", "1", None,
        "2026-10-11T00:00:00Z", "2026-10-11T00:00:00Z",
    )

    return replace(provenance, **changes)


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), float("inf"), "1"])
def test_JobDeadlineRejectsUnboundedValues(value: object) -> None:
    """Reject non-finite and ambiguous time bounds at the immutable contract."""

    with pytest.raises(ValueError, match="timeout_seconds"):
        replace(Spec(), timeout_seconds=value)


@pytest.mark.parametrize("changes", [
    {"job_id": ""}, {"workspace_id": "outside\nworkspace"}, {"scope_reference": ""},
    {"owner_reference": ""}, {"provider_id": "invalid Provider"},
])
def test_JobRequiresExplicitOwnership(changes: dict[str, object]) -> None:
    """Reject missing, multiline and invalid machine attribution."""

    with pytest.raises(ValueError):
        replace(Spec(), **changes)


@pytest.mark.parametrize(("completed", "total"), [
    (True, None), (-1, None), (0, False), (2, 1), (0, 0), (1, "1"),
])
def test_ProgressRequiresMeasuredBoundedCounts(completed: object, total: object) -> None:
    """Reject booleans, negative counts and contradictory totals."""

    with pytest.raises(ValueError):
        JobProgress(completed, total)  # type: ignore[arg-type]


@pytest.mark.parametrize(("code", "message"), [
    ("provider", "failed"), (JobFailureCode.PROVIDER, ""),
    (JobFailureCode.INTERNAL, "a" * 513),
])
def test_FailureRequiresTypedSafeMessage(code: object, message: str) -> None:
    """Keep structured failures bounded and free of implicit exception text."""

    with pytest.raises(ValueError):
        JobFailure(code, message)  # type: ignore[arg-type]


@pytest.mark.parametrize("max_events", [True, 0, 4, "5"])
def test_JobHistoryReservesTerminalNotifications(max_events: object) -> None:
    """Require enough bounded history to report failure and final ownership."""

    with pytest.raises(ValueError, match="max_events"):
        ScanJob(Spec(), FunctionProvider(Empty), max_events=max_events)  # type: ignore[arg-type]


async def Empty(context: JobContext) -> None:
    """Complete an empty deterministic workflow."""

    context.CheckCancellation()


def test_QueuedStatusIsImmediateAndProviderDoesNotBlockStart() -> None:
    """Expose an initial state before a blocked provider gets any execution time."""

    async def Scenario() -> None:
        """Drive lifecycle with explicit gates instead of polling or wall-clock sleeps."""

        entered = asyncio.Event()
        release = asyncio.Event()

        async def Provider(context: JobContext) -> None:
            """Stay running until the deterministic release gate is set."""

            entered.set()

            await release.wait()

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()
        initial = job.Snapshot()
        assert initial.state is JobState.QUEUED, "Start must return an immediate queued snapshot."
        assert initial.last_sequence == 0, "Queued status must be the first retained event."
        assert not entered.is_set(), "Start must not execute a long-running provider inline."

        with pytest.raises(RuntimeError, match="already started"):
            job.Start()

        await entered.wait()

        assert job.Snapshot().state is JobState.RUNNING, "Provider must have running ownership."
        release.set()

        result = await job.Wait()

        assert result.state is JobState.COMPLETED, "Successful provider must complete exactly once."
        assert [event.data for event in job.EventsSince()] == [
            JobState.QUEUED, JobState.RUNNING, JobState.COMPLETED,
        ], "Normal lifecycle must preserve exact state order."
        assert not job.Cancel("owner:test"), "Terminal cancellation must be idempotent."

        with pytest.raises(RuntimeError, match="terminal"):
            job.Finish(JobState.COMPLETED)

        with pytest.raises(RuntimeError, match="once"):
            await job.Run()

    asyncio.run(Scenario())


def test_QueuedCancellationPreventsProviderInvocationAndRejectsOtherOwner() -> None:
    """Keep cancellation ownership explicit and never launch a cancelled queued job."""

    async def Scenario() -> None:
        """Cancel before the scheduled provider receives its first event-loop turn."""

        called = False

        async def Provider(context: JobContext) -> None:
            """Record a launch that queued cancellation must prevent."""

            nonlocal called
            called = True

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        with pytest.raises(PermissionError, match="owning operator"):
            job.Cancel("owner:other")

        assert job.Cancel("owner:test"), "The resolved owning principal may cancel the queued job."
        result = await job.Wait()
        assert result.state is JobState.CANCELLED, "Queued cancellation must remain cancellation."
        assert not called, "Queued cancellation must not invoke the provider."
        assert result.failure is None, "Cancellation is distinct from classified failure."
        assert len(job.EventsSince()) == 3, (
            "Queued cancellation must emit request and terminal once."
        )

    asyncio.run(Scenario())


def test_RunningCancellationWaitsForCleanup() -> None:
    """Expose cancellation intent immediately while retaining running cleanup ownership."""

    async def Scenario() -> None:
        """Use explicit cleanup gates to prove the terminal event occurs after cleanup."""

        entered = asyncio.Event()
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()

        async def Provider(context: JobContext) -> None:
            """Observe the cooperative cancellation signal and perform owned cleanup."""

            entered.set()

            await context.Cancellation.wait()

            cleanup_started.set()

            await release_cleanup.wait()

            context.CheckCancellation()

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        await entered.wait()

        assert job.Cancel("owner:test"), "Running cancellation must produce a new intent event."
        assert not job.Cancel("owner:test"), "Repeated cancellation must not duplicate intent."

        await cleanup_started.wait()

        assert job.Snapshot().state is JobState.RUNNING, "Cleanup must retain running ownership."
        release_cleanup.set()

        result = await job.CancelAndWait("owner:test")

        assert result.state is JobState.CANCELLED, "Cleanup must finish before cancellation seals."
        assert result.cancellation_requested, "Terminal snapshot must retain cancellation intent."

    asyncio.run(Scenario())


def test_ForcedCancellationAwaitsProviderCleanup() -> None:
    """Cancel an unresponsive cooperative provider task and await its cleanup."""

    async def Scenario() -> None:
        """Use a short grace deadline with explicit cancellation cleanup evidence."""

        entered = asyncio.Event()
        cleaned = asyncio.Event()

        async def Provider(context: JobContext) -> None:
            """Wait indefinitely but obey task cancellation in a finally block."""

            entered.set()

            try:
                await asyncio.Event().wait()

            finally:
                cleaned.set()

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        await entered.wait()

        result = await job.CancelAndWait("owner:test", grace_seconds=0.01)

        assert result.state is JobState.CANCELLED, "Forced task cancellation must remain explicit."
        assert cleaned.is_set(), "Owned task cleanup must precede terminal reporting."

        with pytest.raises(ValueError, match="grace_seconds"):
            await job.CancelAndWait("owner:test", grace_seconds=0)

    asyncio.run(Scenario())


def test_DetachedWaitAndStreamConsumersCannotCancelTheProvider() -> None:
    """Keep producer ownership independent of individual cancelled UI consumers."""

    async def Scenario() -> None:
        """Detach a waiter and a blocked event subscriber while provider work continues."""

        entered = asyncio.Event()
        release = asyncio.Event()

        async def Provider(context: JobContext) -> None:
            """Complete only after the test permits provider progress."""

            entered.set()

            await release.wait()

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        await entered.wait()

        async def Follow() -> None:
            """Follow future events from the running cursor."""

            async for event in job.Events(job.Snapshot().last_sequence):
                assert event.job_id == "job:test", "Every subscriber must follow its own job."

        waiter = asyncio.create_task(job.Wait())
        follower = asyncio.create_task(Follow())

        await asyncio.sleep(0)

        waiter.cancel()
        follower.cancel()

        with pytest.raises(asyncio.CancelledError):
            await waiter

        with pytest.raises(asyncio.CancelledError):
            await follower

        assert job.Snapshot().state is JobState.RUNNING, "Detached clients must not kill the job."
        release.set()

        assert (await job.Wait()).state is JobState.COMPLETED, "The owned provider must finish."

    asyncio.run(Scenario())


def test_EventReplayDoesNotMissUpdatesWhileConsumerIsPaused() -> None:
    """Retain events produced between consumer yields without missing the wakeup."""

    async def Scenario() -> None:
        """Run a producer to completion while its first subscriber yield is paused."""

        entered = asyncio.Event()
        release = asyncio.Event()

        async def Provider(context: JobContext) -> None:
            """Produce two distinct event types before the terminal transition."""

            entered.set()

            await release.wait()

            context.Progress(1, 2)
            context.Heartbeat()

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()
        stream = job.Events()
        first = await anext(stream)

        await entered.wait()

        release.set()

        await job.Wait()

        rest = [event async for event in stream]
        assert [first, *rest] == list(job.EventsSince()), "Paused clients must replay every event."
        assert [event.sequence for event in rest] == [1, 2, 3, 4], "Cursors must remain contiguous."
        assert job.EventsSince(4) == (), "Terminal cursor replay must be empty and deterministic."

        for cursor in (True, -2, 5, "0"):
            with pytest.raises(ValueError, match="sequence"):
                job.EventsSince(cursor)  # type: ignore[arg-type]

        assert [event async for event in job.Events(4)] == [], "Terminal followers must return."

    asyncio.run(Scenario())


def test_ProgressIsMonotonicAndModelAndObservationEventsAreTyped() -> None:
    """Publish live structured contracts without inventing a second model schema."""

    async def Provider(context: JobContext) -> None:
        """Exercise unknown totals, fixed totals and rejected progress regressions."""

        context.Progress(0)
        context.Progress(1, 2)

        for completed, total in ((0, 2), (1, None), (1, 3)):
            with pytest.raises(ValueError, match="monotonic"):
                context.Progress(completed, total)

        context.Progress(2, 2)
        context.Observe(NormalizedObservation("host", "target:local", {"alive": True}))
        context.ModelChanged(ModelDelta(0, 0))

    async def Scenario() -> None:
        """Complete a producer and verify immutable payloads retain their typed values."""

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        result = await job.Wait()

        assert result.progress == JobProgress(2, 2), (
            "Snapshot must retain the last measured counts."
        )
        assert result.state is JobState.COMPLETED, "Valid structured events must preserve success."
        assert isinstance(job.EventsSince()[-2].data, ModelDelta), (
            "Model events must reuse ModelDelta."
        )

    asyncio.run(Scenario())


@pytest.mark.parametrize("code", list(JobFailureCode))
def test_ClassifiedFailuresStayExplicitAndRetainEventOrder(code: JobFailureCode) -> None:
    """Preserve each failure code before exactly one failed terminal state."""

    async def Provider(context: JobContext) -> None:
        """Raise an explicit user-safe provider failure."""

        raise JobError(JobFailure(code, "Synthetic classified failure"))

    async def Scenario() -> None:
        """Collect terminal failure without converting it to a successful workflow."""

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        result = await job.Wait()

        assert result.state is JobState.FAILED, "Classified provider failures must remain failed."
        assert result.failure is not None and result.failure.code is code, (
            "Failure code must persist."
        )
        assert job.EventsSince()[-2].kind is JobEventKind.FAILURE, (
            "Failure must precede terminal state."
        )

    asyncio.run(Scenario())


def test_UnknownExceptionTextIsNotCopiedIntoEvents() -> None:
    """Avoid accidentally publishing raw exception arguments or credential values."""

    async def Provider(context: JobContext) -> None:
        """Use a non-sensitive sentinel that represents forbidden exception disclosure."""

        raise RuntimeError("synthetic-private-argument")

    async def Scenario() -> None:
        """Verify only a deliberate generic classification leaves the provider boundary."""

        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        result = await job.Wait()

        assert result.failure is not None, (
            "Unexpected failures must have a terminal classification."
        )
        assert result.failure.code is JobFailureCode.INTERNAL, "Unknown failures must be internal."
        assert "synthetic-private" not in repr(job.EventsSince()), (
            "Raw exceptions must stay private."
        )

    asyncio.run(Scenario())


def test_ProviderCannotConvertAnExpiredDeadlineToSuccessfulCompletion() -> None:
    """Retain timeout truth even when a provider mistakenly swallows task cancellation."""

    async def Provider(context: JobContext) -> None:
        """Simulate a cancellation-suppressing provider that returns after its deadline."""

        try:
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            return

    async def Scenario() -> None:
        """Verify expired deadline state independently of cancellation propagation."""

        job = ScanJob(replace(Spec(), timeout_seconds=0.01), FunctionProvider(Provider))
        job.Start()

        result = await job.Wait()

        assert result.state is JobState.FAILED, "An expired job deadline must never become success."
        assert result.failure is not None and result.failure.code is JobFailureCode.TIMEOUT, (
            "Suppressed cancellation must still preserve timeout classification."
        )

    asyncio.run(Scenario())


def test_DeadlineAndEventLimitFailAndCleanTheProvider() -> None:
    """Distinguish job deadlines and bounded history exhaustion from cancellation success."""

    async def Scenario() -> None:
        """Verify deterministic cleanup and bounded terminal records for both limits."""

        cleaned = asyncio.Event()

        async def Slow(context: JobContext) -> None:
            """Wait beyond the job deadline but always run cleanup."""

            try:
                await asyncio.Event().wait()

            finally:
                cleaned.set()

        slow = ScanJob(replace(Spec(), timeout_seconds=0.01), FunctionProvider(Slow))
        slow.Start()

        result = await slow.Wait()

        assert cleaned.is_set(), "Timeout must await provider cleanup."
        assert result.failure is not None and result.failure.code is JobFailureCode.TIMEOUT, (
            "Job deadline must remain an explicit timeout failure."
        )

        async def Noisy(context: JobContext) -> None:
            """Exhaust the finite event history without retaining unbounded data."""

            for _ in range(100):
                context.Heartbeat()

        noisy = ScanJob(Spec(), FunctionProvider(Noisy), max_events=6)
        noisy.Start()

        limited = await noisy.Wait()

        assert len(noisy.EventsSince()) <= 6, (
            "Terminal reporting must remain inside the event budget."
        )
        assert limited.failure is not None, "History exhaustion must produce a retained failure."
        assert limited.failure.code is JobFailureCode.OUTPUT_LIMIT, (
            "History budget must be classified."
        )
        assert noisy.EventsSince()[-1].data is JobState.FAILED, "Limit failure must end explicitly."

    asyncio.run(Scenario())


def test_EvidenceAttachmentsAreOwnedDeduplicatedAndRetainedOnFailure(tmp_path: Path) -> None:
    """Capture existing immutable evidence without silently losing it on later failure."""

    async def Provider(context: JobContext) -> None:
        """Publish evidence, reject cross-context attribution and fail afterwards."""

        first = context.CaptureEvidence(b"synthetic", "stdout", "text/plain", Provenance())
        second = context.CaptureEvidence(b"synthetic", "stdout", "text/plain", Provenance())
        assert first == second, "Exact evidence attachment replay must be idempotent."

        for field_name, value in (
            ("workspace_id", "workspace-other"), ("scope_reference", "scope:other"),
            ("source_id", "other.provider"),
        ):
            with pytest.raises(ValueError, match="owning job"):
                context.CaptureEvidence(
                    b"other", "stdout", "text/plain", Provenance(**{field_name: value}),
                )

        raise JobError(JobFailure(JobFailureCode.PROVIDER, "Synthetic failure after evidence"))

    async def Scenario() -> None:
        """Read the retained record through the real evidence store after terminal failure."""

        store = LocalEvidenceStore(tmp_path)
        job = ScanJob(Spec(), FunctionProvider(Provider), evidence_store=store)
        job.Start()

        result = await job.Wait()

        assert result.state is JobState.FAILED, (
            "Preserved evidence does not turn failure into success."
        )
        assert len(result.artifacts) == 1, "Exact replay must not duplicate owned evidence."
        artifact = result.artifacts[0]
        assert artifact.job_id == "job:test", "Snapshot attachment must preserve its job owner."
        assert store.Read(artifact.evidence.reference) == b"synthetic", (
            "Stored evidence must remain."
        )
        attachments = [
            event for event in job.EventsSince() if event.kind is JobEventKind.ARTIFACT
        ]
        assert len(attachments) == 1, (
            "Exact evidence replay must emit one attachment event."
        )

    asyncio.run(Scenario())


def test_MissingAndFailedEvidenceStoresStayClassified(tmp_path: Path, monkeypatch) -> None:
    """Never report a successful job when its raw evidence could not be preserved."""

    async def Provider(context: JobContext) -> None:
        """Require evidence publication for a complete synthetic workflow."""

        context.CaptureEvidence(b"synthetic", "stdout", "text/plain", Provenance())

    def FailPublication(*args, **kwargs) -> None:
        """Inject an actual evidence-storage classification without raw exception leakage."""

        raise EvidenceStorageError("synthetic-storage-detail")

    async def Scenario() -> None:
        """Compare absent and failing stores through the same provider contract."""

        for store in (None, LocalEvidenceStore(tmp_path)):
            if store is not None:
                monkeypatch.setattr(LocalEvidenceStore, "Put", FailPublication)

            job = ScanJob(Spec(), FunctionProvider(Provider), evidence_store=store)
            job.Start()

            result = await job.Wait()

            assert result.failure is not None, "Missing evidence must block successful completion."
            assert result.failure.code is JobFailureCode.STORAGE, (
                "Evidence failure must be storage."
            )
            assert result.artifacts == (), "Unpublished evidence must not become an attachment."

    asyncio.run(Scenario())


def test_ContextCannotWriteAfterTerminalAndLoopOwnershipIsEnforced() -> None:
    """Reject stale producer writes and lifecycle access from another event loop."""

    contexts: list[JobContext] = []
    job = ScanJob(Spec(), FunctionProvider(Empty))

    async def Provider(context: JobContext) -> None:
        """Retain one context to exercise its invalid post-terminal use."""

        contexts.append(context)

    async def FirstLoop() -> None:
        """Own the started provider and verify post-terminal access rejection."""

        nonlocal job
        job = ScanJob(Spec(), FunctionProvider(Provider))
        job.Start()

        await job.Wait()

        with pytest.raises(RuntimeError, match="running"):
            contexts[0].Heartbeat()

    asyncio.run(FirstLoop())

    async def OtherLoop() -> None:
        """Reject mutations from an unrelated owner loop."""

        with pytest.raises(RuntimeError, match="owning event loop"):
            await job.Wait()

        with pytest.raises(RuntimeError, match="owning event loop"):
            job.Cancel("owner:test")

    asyncio.run(OtherLoop())


def test_LifecycleBeforeStartAndInvalidTerminalTransitionFailClosed() -> None:
    """Do not permit lifecycle methods to invent ownership before Start."""

    job = ScanJob(Spec(), FunctionProvider(Empty))
    assert job.Snapshot().last_sequence == -1, "An unstarted job must have no recorded events."

    with pytest.raises(RuntimeError):
        job.Start()

    async def Scenario() -> None:
        """Exercise missing start and invalid failure/state pairings."""

        with pytest.raises(RuntimeError, match="owning event loop"):
            await job.Wait()

        job.Start()

        with pytest.raises(ValueError, match="terminal state"):
            job.Finish(JobState.RUNNING)

        with pytest.raises(ValueError, match="terminal state"):
            job.Finish(JobState.FAILED)

        assert (await job.Wait()).state is JobState.COMPLETED, (
            "Rejected transitions must not mutate."
        )

    asyncio.run(Scenario())


def test_EventDiscriminatorsAndArtifactOwnersCannotContradict(tmp_path: Path) -> None:
    """Validate explicit schema versions and cross-job attachment ownership."""

    record = LocalEvidenceStore(tmp_path).Put(b"synthetic", "stdout", "text/plain", Provenance())
    artifact = JobArtifact("job:test", "workspace-test", record)

    with pytest.raises(ValueError, match="workspace"):
        JobArtifact("job:test", "workspace-other", record)

    with pytest.raises(ValueError, match="EvidenceRecord"):
        JobArtifact("job:test", "workspace-test", None)  # type: ignore[arg-type]

    for changes in (
        {"sequence": True}, {"schema_version": 2}, {"kind": "state"},
        {"data": None}, {"kind": JobEventKind.ARTIFACT, "data": artifact, "job_id": "job:other"},
    ):
        event = JobEvent("job:test", 0, JobEventKind.STATE, JobState.QUEUED)

        with pytest.raises(ValueError):
            replace(event, **changes)
