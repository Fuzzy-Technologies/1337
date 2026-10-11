# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental owned scan jobs with bounded, ordered lifecycle and model events."""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from fuzzy1337.adapters import (
    AdapterReport,
    ExecutionState,
    NormalizedObservation,
)
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
)
from fuzzy1337.executors.contracts import (
    ExecutionEvent,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    RequireIdentifier,
    RequireReference,
)
from fuzzy1337.executors.local import EventCallback, LocalExecutionError
from fuzzy1337.model import ModelDelta

JOB_SCHEMA_VERSION = 1
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})


class JobState(StrEnum):
    """Canonical local job states, distinct from a single process exit state."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobEventKind(StrEnum):
    """Version-one sequenced event discriminators."""

    STATE = "state"
    PROGRESS = "progress"
    HEARTBEAT = "heartbeat"
    CANCELLATION_REQUESTED = "cancellation_requested"
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    MODEL_DELTA = "model_delta"
    FAILURE = "failure"


class JobFailureCode(StrEnum):
    """Machine-readable job failures without raw provider exception text."""

    AUTHORIZATION = "authorization"
    PROVIDER = "provider"
    NORMALIZATION = "normalization"
    STORAGE = "storage"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    INTERNAL = "internal"


def RequirePositiveSeconds(value: float, field_name: str) -> None:
    """Reject non-finite, nonpositive and boolean time bounds.

    Args:
        value: Seconds for a local deadline or cancellation grace.
        field_name: Non-secret field label in validation errors.

    Raises:
        ValueError: The bound is not a positive finite number.
    """

    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{field_name} must be a positive finite number")


@dataclass(frozen=True, slots=True)
class JobSpec:
    """Immutable attribution and bounds; scope references do not issue approval."""

    job_id: str
    workspace_id: str
    scope_reference: str
    owner_reference: str
    provider_id: str
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        """Require explicit non-secret ownership and a bounded job deadline."""

        for field_name in ("job_id", "scope_reference", "owner_reference"):
            RequireReference(getattr(self, field_name), field_name)

        RequireIdentifier(self.workspace_id, "workspace_id")
        RequireIdentifier(self.provider_id, "provider_id")
        RequirePositiveSeconds(self.timeout_seconds, "timeout_seconds")


@dataclass(frozen=True, slots=True)
class JobProgress:
    """Measured work counters; a missing total means completion is unknown."""

    completed: int
    total: int | None = None

    def __post_init__(self) -> None:
        """Reject ambiguous counts rather than inventing a completion percentage."""

        if type(self.completed) is not int or self.completed < 0:
            raise ValueError("completed must be a non-negative integer")

        if self.total is not None and (
            type(self.total) is not int or self.total < 1 or self.completed > self.total
        ):
            raise ValueError("total must be positive and at least completed")


@dataclass(frozen=True, slots=True)
class JobFailure:
    """Classified non-secret failure retained in both events and terminal snapshot."""

    code: JobFailureCode
    message: str

    def __post_init__(self) -> None:
        """Validate the failure discriminator and bounded user-safe description."""

        if not isinstance(self.code, JobFailureCode):
            raise ValueError("code must be a JobFailureCode")

        RequireReference(self.message, "message")

        if len(self.message) > 512:
            raise ValueError("message must not exceed 512 characters")


class JobError(RuntimeError):
    """Carry an explicit safe failure classification across the provider boundary."""

    def __init__(self, failure: JobFailure) -> None:
        """Bind a deliberate non-secret failure, not arbitrary exception text.

        Args:
            failure: Validated user-safe classification for the owning job.
        """

        self.failure = failure
        super().__init__(failure.message)


@dataclass(frozen=True, slots=True)
class JobArtifact:
    """Attach an immutable evidence record to one job and workspace."""

    job_id: str
    workspace_id: str
    evidence: EvidenceRecord

    def __post_init__(self) -> None:
        """Reject an attachment whose evidence belongs to another workspace."""

        RequireReference(self.job_id, "job_id")
        RequireReference(self.workspace_id, "workspace_id")

        if not isinstance(self.evidence, EvidenceRecord):
            raise ValueError("evidence must be an EvidenceRecord")

        if self.evidence.provenance.workspace_id != self.workspace_id:
            raise ValueError("evidence workspace must match the owning job")


JobEventData = (
    JobState | JobProgress | NormalizedObservation | JobArtifact | ModelDelta | JobFailure | None
)
_EVENT_TYPES = {
    JobEventKind.STATE: JobState,
    JobEventKind.PROGRESS: JobProgress,
    JobEventKind.OBSERVATION: NormalizedObservation,
    JobEventKind.ARTIFACT: JobArtifact,
    JobEventKind.MODEL_DELTA: ModelDelta,
    JobEventKind.FAILURE: JobFailure,
    JobEventKind.HEARTBEAT: type(None),
    JobEventKind.CANCELLATION_REQUESTED: type(None),
}


@dataclass(frozen=True, slots=True)
class JobEvent:
    """Typed, immutable, schema-v1 event with a zero-based contiguous cursor."""

    job_id: str
    sequence: int
    kind: JobEventKind
    data: JobEventData
    schema_version: int = JOB_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validate the discriminator and prohibit cross-job artifact attachment."""

        RequireReference(self.job_id, "job_id")

        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("sequence must be a non-negative integer")

        if type(self.schema_version) is not int or self.schema_version != JOB_SCHEMA_VERSION:
            raise ValueError("unsupported job schema_version")

        if not isinstance(self.kind, JobEventKind) or not isinstance(
            self.data, _EVENT_TYPES[self.kind],
        ):
            raise ValueError("event data must match its kind")

        if isinstance(self.data, JobArtifact) and self.data.job_id != self.job_id:
            raise ValueError("artifact must belong to the event job")


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    """Detached lifecycle state and retained artifact ownership for one job."""

    spec: JobSpec
    state: JobState
    last_sequence: int
    progress: JobProgress | None
    failure: JobFailure | None
    artifacts: tuple[JobArtifact, ...]
    cancellation_requested: bool
    schema_version: int = JOB_SCHEMA_VERSION


class JobProvider(Protocol):
    """Trusted provider that obeys cancellation and cleans owned resources."""

    async def Run(self, context: JobContext) -> None:
        """Execute one preapproved bounded workflow through the shared context.

        Args:
            context: Job-owned event, cancellation and evidence boundary.
        """


class JobContext:
    """Provider-facing event operations that cannot mutate terminal lifecycle state."""

    def __init__(self, job: ScanJob) -> None:
        """Bind this context to exactly one owning job.

        Args:
            job: Handle that owns provider execution and artifacts.
        """

        self._job = job

    @property
    def Spec(self) -> JobSpec:
        """Return immutable ownership and deadline attribution.

        Returns:
            The owning job specification, never an authorization grant.
        """

        return self._job.Spec

    @property
    def Cancellation(self) -> asyncio.Event:
        """Expose the cooperative signal accepted by the executor.

        Returns:
            Signal set by the owning handle's cancellation boundary.
        """

        return self._job._cancellation

    def CheckCancellation(self) -> None:
        """Stop forward work when cancellation is requested; cleanup may retain evidence.

        Raises:
            asyncio.CancelledError: The owner has requested cancellation.
        """

        if self.Cancellation.is_set():
            raise asyncio.CancelledError

    def Progress(self, completed: int, total: int | None = None) -> None:
        """Publish monotonic counters without altering an already known total.

        Args:
            completed: Measured completed units, never a guessed percentage.
            total: Optional positive fixed count for the same work unit.

        Raises:
            ValueError: Progress regresses or the known total changes.
            JobError: The event budget is exhausted.
        """

        progress = JobProgress(completed, total)
        previous = self._job._progress

        if previous is not None and (
            progress.completed < previous.completed
            or (previous.total is not None and progress.total != previous.total)
        ):
            raise ValueError("progress must be monotonic with a fixed known total")

        self._job.Publish(JobEventKind.PROGRESS, progress)
        self._job._progress = progress

    def Heartbeat(self) -> None:
        """Publish provider liveness without inventing completed work."""

        self._job.Publish(JobEventKind.HEARTBEAT, None)

    def Observe(self, observation: NormalizedObservation) -> None:
        """Publish one existing immutable provider-neutral observation.

        Args:
            observation: Structured interpretation; raw payload stays in evidence.
        """

        self._job.Publish(JobEventKind.OBSERVATION, observation)

    def ModelChanged(self, delta: ModelDelta) -> None:
        """Notify consumers of a delta already accepted by the shared model owner.

        Args:
            delta: Existing model transition, not an instruction to mutate state.
        """

        self._job.Publish(JobEventKind.MODEL_DELTA, delta)

    def CaptureEvidence(
        self, data: bytes, role: str, media_type: str, provenance: EvidenceProvenance,
    ) -> JobArtifact:
        """Publish raw bytes through the existing store and attach their ownership.

        Cancelled cleanup may retain evidence while the job is still running.
        Published records survive subsequent failure. No secrets are collected
        automatically; providers are responsible for approved non-secret content.

        Args:
            data: Bounded approved raw content.
            role: Existing evidence role identifier.
            media_type: Payload type without raw contents.
            provenance: Attribution matching this job's workspace, scope and provider.

        Returns:
            Immutable job-owned attachment to the existing evidence format.

        Raises:
            ValueError: The provenance belongs to another job context.
            JobError: No evidence store is bound, publication fails or budget is exhausted.
        """

        self._job.RequireRunning()

        if (
            provenance.workspace_id != self.Spec.workspace_id
            or provenance.scope_reference != self.Spec.scope_reference
            or provenance.source_id != self.Spec.provider_id
        ):
            raise ValueError("evidence provenance must match the owning job context")

        store = self._job._evidence_store

        if store is None:
            raise JobError(JobFailure(JobFailureCode.STORAGE, "No job evidence store is bound"))

        try:
            record = store.Put(data, role, media_type, provenance)

        except EvidenceError as error:
            raise JobError(JobFailure(
                JobFailureCode.STORAGE, "Could not preserve job evidence",
            )) from error

        artifact = JobArtifact(self.Spec.job_id, self.Spec.workspace_id, record)

        if artifact not in self._job._artifacts:
            self._job._artifacts.append(artifact)
            self._job.Publish(JobEventKind.ARTIFACT, artifact)

        return artifact


class ScanJob:
    """Own one local asynchronous provider and a replayable bounded event stream."""

    def __init__(
        self,
        spec: JobSpec,
        provider: JobProvider,
        *,
        evidence_store: LocalEvidenceStore | None = None,
        max_events: int = 10_000,
    ) -> None:
        """Configure a job without invoking its provider or starting a task.

        Args:
            spec: Immutable non-secret ownership and resource bounds.
            provider: Trusted first-party workflow, responsible for preapproved actions.
            evidence_store: Optional existing raw evidence store for this workspace.
            max_events: Total retained events, including reserved terminal notifications.

        Raises:
            ValueError: Event history cannot reserve lifecycle/failure notifications.
        """

        if type(max_events) is not int or max_events < 5:
            raise ValueError("max_events must be an integer of at least five")

        self._spec = spec
        self._provider = provider
        self._evidence_store = evidence_store
        self._max_events = max_events
        self._state = JobState.QUEUED
        self._events: list[JobEvent] = []
        self._artifacts: list[JobArtifact] = []
        self._progress: JobProgress | None = None
        self._failure: JobFailure | None = None
        self._task: asyncio.Task[None] | None = None
        self._cancellation = asyncio.Event()
        self._changed = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def Spec(self) -> JobSpec:
        """Return read-only job ownership that remains fixed after construction.

        Returns:
            Immutable workspace, scope, principal and provider attribution.
        """

        return self._spec

    def Start(self) -> None:
        """Expose queued status immediately and schedule the owned provider.

        Must be called once from the loop that owns all subsequent operations.

        Raises:
            RuntimeError: There is no running loop or this job was already started.
        """

        if self._loop is not None:
            raise RuntimeError("job has already started")

        self._loop = asyncio.get_running_loop()
        self.Append(JobEventKind.STATE, JobState.QUEUED)
        self._task = self._loop.create_task(self.Run(), name=f"1337-job:{self.Spec.job_id}")

    def RequireLoop(self) -> None:
        """Enforce single-loop mutation and reject operations before start.

        Raises:
            RuntimeError: The current loop does not own this started job.
        """

        if self._loop is None or asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("job operations require its owning event loop")

    def RequireRunning(self) -> None:
        """Prevent detached providers from writing after a terminal transition.

        Raises:
            RuntimeError: The job is not running or this loop does not own it.
        """

        self.RequireLoop()

        if self._state is not JobState.RUNNING:
            raise RuntimeError("provider events require a running job")

    def Append(self, kind: JobEventKind, data: JobEventData) -> None:
        """Record an internal notification without executing consumer callbacks.

        Args:
            kind: Typed event discriminator.
            data: Immutable payload matching the discriminator.
        """

        self._events.append(JobEvent(self.Spec.job_id, len(self._events), kind, data))
        changed = self._changed
        self._changed = asyncio.Event()
        changed.set()

    def Publish(self, kind: JobEventKind, data: JobEventData) -> None:
        """Bound provider events while reserving cancellation/failure/terminal slots.

        Args:
            kind: Provider observation discriminator.
            data: Existing typed contract value.

        Raises:
            JobError: The history budget is exhausted.
            RuntimeError: The provider no longer owns a running job.
        """

        self.RequireRunning()

        if len(self._events) >= self._max_events - 3:
            raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT, "Job event budget exhausted"))

        self.Append(kind, data)

    def Snapshot(self) -> JobSnapshot:
        """Return detached current state, including partial evidence after failure.

        Returns:
            Immutable ownership, state, cursor, progress, failure and artifact snapshot.
        """

        return JobSnapshot(
            self.Spec, self._state, len(self._events) - 1, self._progress, self._failure,
            tuple(self._artifacts), self._cancellation.is_set(),
        )

    def EventsSince(self, sequence: int = -1) -> tuple[JobEvent, ...]:
        """Replay retained events strictly after a previously observed cursor.

        Args:
            sequence: Last observed event sequence; -1 starts at the queued event.

        Returns:
            Detached ordered events without consuming them for other readers.

        Raises:
            ValueError: The cursor is invalid or beyond the current stream.
        """

        if type(sequence) is not int or sequence < -1 or sequence >= len(self._events):
            raise ValueError("sequence must be -1 or a retained event cursor")

        return tuple(self._events[sequence + 1:])

    async def Events(self, sequence: int = -1) -> AsyncIterator[JobEvent]:
        """Replay and then follow notifications until the single terminal state.

        Cancellation detaches only this consumer. No callback can block the producer.

        Args:
            sequence: Last observed retained cursor; -1 replays from the start.

        Yields:
            Immutable notifications in contiguous sequence order.
        """

        self.RequireLoop()
        self.EventsSince(sequence)

        while True:
            pending = self.EventsSince(sequence)

            if pending:
                for event in pending:
                    sequence = event.sequence

                    yield event

                continue

            if self._state.value in _TERMINAL_STATES:
                return

            changed = self._changed

            await changed.wait()

    def Cancel(self, requested_by: str) -> bool:
        """Request cancellation only for the handle's resolved owner principal.

        Queued jobs terminate without invoking the provider. Running jobs retain
        ownership until provider cleanup completes. Authentication is upstream.

        Args:
            requested_by: Authenticated principal reference supplied by the caller.

        Returns:
            True for a new request, False when already requested or terminal.

        Raises:
            PermissionError: The principal is not the owning operator.
        """

        self.RequireLoop()

        if requested_by != self.Spec.owner_reference:
            raise PermissionError("only the owning operator may cancel this job")

        if self._state.value in _TERMINAL_STATES or self._cancellation.is_set():
            return False

        self._cancellation.set()
        self.Append(JobEventKind.CANCELLATION_REQUESTED, None)

        if self._state is JobState.QUEUED:
            self.Finish(JobState.CANCELLED)

        return True

    async def CancelAndWait(
        self, requested_by: str, *, grace_seconds: float = 1.0,
    ) -> JobSnapshot:
        """Signal, then cancel the owned task after the cooperative grace period.

        Task cancellation awaits provider cleanup; trusted providers must honor it.

        Args:
            requested_by: Resolved owning principal reference.
            grace_seconds: Positive bounded cooperative wait before task cancellation.

        Returns:
            Terminal snapshot after provider-owned resources are cleaned.
        """

        RequirePositiveSeconds(grace_seconds, "grace_seconds")
        self.Cancel(requested_by)
        task = self._task

        if task is None:
            raise RuntimeError("job has not started")

        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=grace_seconds)

        except TimeoutError:
            task.cancel()

            await asyncio.shield(task)

        return self.Snapshot()

    async def Wait(self) -> JobSnapshot:
        """Await terminal ownership without allowing a consumer to cancel the job.

        Returns:
            Detached terminal snapshot; failures are explicit data, not success.

        Raises:
            RuntimeError: This job has not been started on the current loop.
            asyncio.CancelledError: This waiting consumer is cancelled independently.
        """

        self.RequireLoop()

        if self._task is None:
            raise RuntimeError("job has not started")

        await asyncio.shield(self._task)

        return self.Snapshot()

    def Finish(self, state: JobState, failure: JobFailure | None = None) -> None:
        """Seal one terminal state after provider cleanup and retain all artifacts.

        Args:
            state: Final job state.
            failure: Required classified failure for a failed terminal state.

        Raises:
            RuntimeError: A terminal state already exists.
            ValueError: The new state or failure pairing is invalid.
        """

        self.RequireLoop()

        if self._state.value in _TERMINAL_STATES:
            raise RuntimeError("job already has a terminal state")

        if state.value not in _TERMINAL_STATES or (state is JobState.FAILED) != (
            failure is not None
        ):
            raise ValueError("terminal state must match its failure classification")

        self._failure = failure

        if failure is not None:
            self.Append(JobEventKind.FAILURE, failure)

        self._state = state
        self.Append(JobEventKind.STATE, state)

    async def Run(self) -> None:
        """Own provider execution, cleanup and exact terminal lifecycle classification."""

        self.RequireLoop()

        if self._state is JobState.CANCELLED:
            return

        if self._state is not JobState.QUEUED:
            raise RuntimeError("provider may run only once from queued state")

        self._state = JobState.RUNNING
        self.Append(JobEventKind.STATE, JobState.RUNNING)
        context = JobContext(self)

        try:
            async with asyncio.timeout(self.Spec.timeout_seconds) as deadline:
                await self._provider.Run(context)

            if deadline.expired():
                raise JobError(JobFailure(JobFailureCode.TIMEOUT, "Job deadline exceeded"))

            context.CheckCancellation()

        except asyncio.CancelledError:
            self.Finish(JobState.CANCELLED)

        except TimeoutError:
            self.Finish(JobState.FAILED, JobFailure(
                JobFailureCode.TIMEOUT, "Job deadline exceeded",
            ))

        except JobError as error:
            self.Finish(JobState.FAILED, error.failure)

        except Exception:
            self.Finish(JobState.FAILED, JobFailure(
                JobFailureCode.INTERNAL, "Job provider raised an unclassified exception",
            ))

        else:
            self.Finish(JobState.COMPLETED)


class LocalExecutionCallable(Protocol):
    """Exact existing executor call; callers may bind governed policy parameters."""

    async def __call__(
        self,
        request: LocalExecutionRequest,
        *,
        on_event: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
    ) -> LocalExecutionResult:
        """Execute the exact authorized request with cooperative cancellation.

        Args:
            request: Existing bound capability, scope, policy and immutable invocation.
            on_event: Optional executor observer, never a raw output logger.
            cancellation: Shared job-owned cooperative signal.

        Returns:
            Existing terminal executor contract after all resource cleanup.
        """


ResultHandler = Callable[[JobContext, AdapterReport], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class LocalExecutionJob:
    """Bridge one exact authorized local execution into job-owned evidence and events."""

    request: LocalExecutionRequest
    execute: LocalExecutionCallable
    result_handler: ResultHandler | None = None

    async def Run(self, context: JobContext) -> None:
        """Preserve raw output before process classification and optional normalization.

        Args:
            context: Owner of cancellation, event history and raw evidence attachments.

        Raises:
            JobError: Ownership, execution, storage or normalization fails.
            asyncio.CancelledError: The process observes cooperative cancellation.
        """

        spec = context.Spec

        if (
            self.request.authorization.scope_reference != spec.scope_reference
            or self.request.invocation.adapter_id != spec.provider_id
        ):
            raise JobError(JobFailure(
                JobFailureCode.AUTHORIZATION, "Execution context does not match the owning job",
            ))

        context.CheckCancellation()
        started_at = datetime.now(UTC).isoformat()

        def OnEvent(event: ExecutionEvent) -> None:
            """Expose activity without copying raw stream bytes or arguments into events.

            Args:
                event: Existing executor event; only liveness is projected here.
            """

            context.Heartbeat()

        try:
            result = await self.execute(
                self.request, on_event=OnEvent, cancellation=context.Cancellation,
            )

        except LocalExecutionError as error:
            raise JobError(JobFailure(
                JobFailureCode.PROVIDER, "Could not launch the approved local execution",
            )) from error

        except PermissionError as error:
            raise JobError(JobFailure(
                JobFailureCode.AUTHORIZATION, "The governed executor denied job execution",
            )) from error

        provenance = EvidenceProvenance(
            workspace_id=spec.workspace_id,
            scope_reference=spec.scope_reference,
            source_id=spec.provider_id,
            source_version=self.request.invocation.provider_version or "unknown",
            tool_version=self.request.invocation.provider_version,
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            invocation_sha256=InvocationDigest(self.request.invocation),
            execution=result.execution,
        )
        artifacts = tuple(
            context.CaptureEvidence(data, role, "application/octet-stream", provenance)
            for role, data in (("stdout", result.stdout), ("stderr", result.stderr))
        )

        if result.termination is ExecutionTermination.OUTPUT_LIMIT:
            raise JobError(JobFailure(
                JobFailureCode.OUTPUT_LIMIT, "Execution output budget exceeded",
            ))

        if result.termination is ExecutionTermination.TIMEOUT:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT, "Local execution deadline exceeded"))

        if result.execution.state is ExecutionState.CANCELLED:
            raise asyncio.CancelledError

        if result.execution.state is not ExecutionState.SUCCEEDED:
            raise JobError(JobFailure(
                JobFailureCode.PROVIDER, "Local execution returned a failure",
            ))

        context.CheckCancellation()

        if self.result_handler is not None:
            report = AdapterReport(
                self.request.invocation, result.execution,
                tuple(artifact.evidence.reference for artifact in artifacts),
            )

            try:
                await self.result_handler(context, report)

            except JobError:
                raise

            except asyncio.CancelledError:
                raise

            except Exception as error:
                raise JobError(JobFailure(
                    JobFailureCode.NORMALIZATION, "Could not normalize local execution evidence",
                )) from error
