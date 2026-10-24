# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental bounded async traversal over explicitly selected reviewed loopback pages."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fuzzy1337.adapters import AdapterDescriptor
from fuzzy1337.adapters.page_capture import (
    PAGE_CAPTURE_PROVIDER_ID,
    KnownBody,
    KnownSyntheticHtmlBody,
    PageCaptureLimits,
    Seconds,
)
from fuzzy1337.captured_web import CapturedWebFrontier, CapturedWebLimits, WebInteger, WebSource
from fuzzy1337.jobs import JobContext, JobError, JobFailure, JobFailureCode
from fuzzy1337.page_capture import LocalPageCaptureProvider
from fuzzy1337.policy import ImpactPolicy, UtcNow
from fuzzy1337.requests import RequestTemplate

__all__ = ["OwnedTraversalPage", "WebTraversalLimits", "LocalWebTraversalProvider"]


@dataclass(frozen=True, slots=True)
class OwnedTraversalPage:
    """Bind one exact anonymous structural source to an explicit reviewed body selection."""

    source: RequestTemplate
    expected_body: KnownSyntheticHtmlBody

    def __post_init__(self) -> None:
        """Revalidate exact typed sources and closed catalog metadata without issuing permission."""

        WebSource(self.source)
        KnownBody(self.expected_body)


@dataclass(frozen=True, slots=True)
class WebTraversalLimits:
    """Bound pages, depth, concurrent workers, aggregate admitted bodies, starts and duration."""

    max_pages: int = 16
    max_depth: int = 4
    concurrency: int = 2
    max_total_body_bytes: int = 65536
    start_interval_seconds: float = 0.05
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject coercions, unbounded concurrency, nonfinite durations and inconsistent counts."""

        WebInteger(self.max_pages, 1, 16)
        WebInteger(self.max_depth, 0, 4)
        WebInteger(self.concurrency, 1, 4)
        WebInteger(self.max_total_body_bytes, 1, 1024 * 1024)
        Seconds(self.start_interval_seconds, 1)
        Seconds(self.timeout_seconds, 60)


class LocalWebTraversalProvider:
    """Compose current governed page acquisition with a deterministic finite breadth frontier."""

    def __init__(
        self, workspace_root: Path, source: RequestTemplate,
        pages: tuple[OwnedTraversalPage, ...], scope_id: str, policy: ImpactPolicy, *,
        limits: WebTraversalLimits = WebTraversalLimits(),
        page_limits: PageCaptureLimits = PageCaptureLimits(),
        frontier_limits: CapturedWebLimits = CapturedWebLimits(),
        clock: Callable[[], datetime] = UtcNow,
    ) -> None:
        """Validate an explicit same-origin finite catalog before any transport or mutation.

        Args:
            workspace_root: Existing owner-created workspace/model/scope/evidence directory.
            source: Selected anonymous concrete seed GET; it must also occur in pages.
            pages: At most sixteen distinct same-origin selected loopback sources and body IDs.
            scope_id: Existing consented scope, independently reopened per page launch and Save.
            policy: Separate current SAFE synthetic-page capability permission.
            limits: Finite traversal budgets; omitted reachable selected work fails explicitly.
            page_limits: Existing per-request body and timeout limits, never transport expansion.
            frontier_limits: Existing bounded lexical interpretation; truncation fails traversal.
            clock: Aware decision clock used by every unchanged page authority boundary.

        Raises:
            ValueError: Selection, nested contracts or budgets are invalid or noncanonical.
        """

        seed, seed_target = WebSource(source)

        if type(pages) is not tuple or not 1 <= len(pages) <= 16 or (
            type(limits) is not WebTraversalLimits
        ):
            raise ValueError("web traversal requires exact bounded selected pages and limits")

        checked_limits = WebTraversalLimits(limits.max_pages, limits.max_depth, limits.concurrency,
            limits.max_total_body_bytes, limits.start_interval_seconds, limits.timeout_seconds)
        providers: dict[str, LocalPageCaptureProvider] = {}
        body_sizes: dict[str, int] = {}
        selected_sources: dict[str, RequestTemplate] = {}

        for page in pages:
            if type(page) is not OwnedTraversalPage:
                raise ValueError("web traversal requires exact selected page records")

            selected, target = WebSource(page.source)
            KnownBody(page.expected_body)

            if selected.endpoint.origin != seed.endpoint.origin or (
                selected.endpoint.workspace_id != seed.endpoint.workspace_id
                or target.value in providers
            ):
                raise ValueError("web traversal selection origins differ or URLs are duplicated")

            providers[target.value] = LocalPageCaptureProvider(workspace_root, selected,
                page.expected_body, scope_id, policy, limits=page_limits,
                frontier_limits=frontier_limits, clock=clock)
            body_sizes[target.value] = page.expected_body.size_bytes
            selected_sources[target.value] = selected

        if seed_target.value not in providers or (
            selected_sources[seed_target.value] != seed
        ):
            raise ValueError("web traversal seed must have its exact explicit page selection")

        self._providers = providers
        self._body_sizes = body_sizes
        self._seed_url = seed_target.value
        self._scope_id = scope_id
        self._workspace_id = seed.endpoint.workspace_id
        self._limits = checked_limits
        self._completed_urls: tuple[str, ...] = ()
        self._unselected_count = 0
        self._started = False

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return the existing page provider declaration without a new authority namespace.

        Returns:
            The unchanged native.loopback-page SAFE capability declaration.
        """

        return self._providers[self._seed_url].Descriptor

    @property
    def CompletedUrls(self) -> tuple[str, ...]:
        """Expose measured committed pages in deterministic breadth/URL order.

        Returns:
            Actual acknowledged page commits, retained on later failure or cancellation.
        """

        return self._completed_urls

    @property
    def UnselectedCandidates(self) -> int:
        """Count unique allowed lexical candidates that lack an explicit page selection.

        Returns:
            Count-only omissions; they were never launched or treated as completed work.
        """

        return self._unselected_count

    async def Run(self, context: JobContext) -> None:
        """Traverse selected discovered pages; drain owned children before every terminal result.

        Concurrent acquisition is separate from ordered synchronous model commits. Each page
        repeats current scope/policy checks; links, catalog identities and prior grants do not
        authorize another request. Redirects are refused by the existing worker and never
        followed. Earlier committed pages and actual acquisitions survive later failure.

        Args:
            context: Actual matching job owner, cancellation signal and evidence/event boundary.

        Raises:
            JobError: Ownership, budget, current authorization, acquisition or persistence fails.
            asyncio.CancelledError: Cancellation after all owned tasks/processes are drained.
        """

        if type(context) is not JobContext or self._started or (
            context.Spec.workspace_id != self._workspace_id
            or context.Spec.provider_id != PAGE_CAPTURE_PROVIDER_ID
            or context.Spec.scope_reference != "scope:" + self._scope_id
        ):
            raise JobError(JobFailure(JobFailureCode.AUTHORIZATION,
                "Web traversal context does not match its single-use owners"))

        self._started = True

        try:
            async with asyncio.timeout(self._limits.timeout_seconds):
                await self.Traverse(context)

        except TimeoutError:
            raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                "Web traversal deadline exceeded; inspect retained pages and evidence")) from None

    async def Traverse(self, context: JobContext) -> None:
        """Own the finite frontier and reserve whole-wave body/page budgets before dispatch.

        Args:
            context: Already validated current owning job.

        Raises:
            JobError: A configured bound would omit selected reachable work.
        """

        pending = {self._seed_url: 0}
        visited: set[str] = set()
        unselected: set[str] = set()
        reserved_bytes = 0
        next_start = [asyncio.get_running_loop().time()]
        context.Progress(0)

        while pending:
            context.CheckCancellation()
            depth = min(pending.values())
            wave = tuple(sorted(url for url in pending if pending[url] == depth)[
                :self._limits.concurrency])
            wave_bytes = sum(self._body_sizes[url] for url in wave)

            if depth > self._limits.max_depth or (
                len(visited) + len(wave) > self._limits.max_pages
                or reserved_bytes + wave_bytes > self._limits.max_total_body_bytes
            ):
                raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                    "Web traversal budget omitted reachable selected pages; prior pages retained"))

            reserved_bytes += wave_bytes
            visited.update(wave)

            for url in wave:
                del pending[url]

            frontiers = await self.AcquireWave(context, wave, next_start)

            for frontier in frontiers:
                if not frontier.complete:
                    raise JobError(JobFailure(JobFailureCode.OUTPUT_LIMIT,
                        "Web traversal lexical frontier was truncated; prior pages retained"))

                for entry in frontier.entries:
                    url = entry.target.value

                    if url not in self._providers:
                        unselected.add(url)

                    elif url not in visited:
                        pending[url] = min(pending.get(url, depth + 1), depth + 1)

            self._unselected_count = len(unselected)

        context.CheckCancellation()
        context.Progress(len(self._completed_urls), len(self._completed_urls))

    async def AcquireWave(
        self, context: JobContext, wave: tuple[str, ...], next_start: list[float],
    ) -> tuple[CapturedWebFrontier, ...]:
        """Acquire concurrently but admit model Save blocks in explicit sorted wave order.

        Args:
            context: Existing evidence/model event owner with cooperative cancellation.
            wave: Selected URLs in deterministic order, at most configured concurrency.
            next_start: Single-loop monotonic start gate shared across traversal waves.

        Returns:
            Verified acknowledged frontiers in dispatch order, independent of wire completion.

        Raises:
            JobError: A page failed; siblings are drained before its fixed owning failure escapes.
        """

        start_lock = asyncio.Lock()
        commit_condition = asyncio.Condition()
        next_commit = [0]

        async def AcquirePage(index: int, url: str) -> CapturedWebFrontier:
            """Rate-limit actual launch and order the final synchronous owner commit phase."""

            async with start_lock:
                while True:
                    context.CheckCancellation()
                    remaining = next_start[0] - asyncio.get_running_loop().time()

                    if remaining <= 0:
                        break

                    await asyncio.sleep(remaining)

                context.CheckCancellation()
                next_start[0] = asyncio.get_running_loop().time() + (
                    self._limits.start_interval_seconds)

            async def BeforeCommit() -> None:
                """Wait for every earlier sorted page commit before composing the current model."""

                async with commit_condition:
                    await commit_condition.wait_for(lambda: next_commit[0] == index
                        or context.Cancellation.is_set())

                context.CheckCancellation()

            provider = self._providers[url]

            try:
                async with asyncio.timeout(provider.limits.timeout_seconds):
                    frontier = await provider.Acquire(context,
                        before_commit=BeforeCommit, publish_progress=False)

            except TimeoutError:
                raise JobError(JobFailure(JobFailureCode.TIMEOUT,
                    "Web traversal page deadline exceeded; prior pages and evidence retained")) \
                    from None

            self._completed_urls += (url,)
            context.Progress(len(self._completed_urls))

            async with commit_condition:
                next_commit[0] += 1
                commit_condition.notify_all()

            return frontier

        tasks: list[asyncio.Task[CapturedWebFrontier]] = []

        async def WakeCancelledWaiters() -> None:
            """Wake gate waiters when a sibling cooperatively exits with CancelledError."""

            await context.Cancellation.wait()

            async with commit_condition:
                commit_condition.notify_all()

        cancellation_task = asyncio.create_task(WakeCancelledWaiters())

        try:
            async with asyncio.TaskGroup() as group:
                for index, url in enumerate(wave):
                    tasks.append(group.create_task(AcquirePage(index, url)))

        except ExceptionGroup as group_error:
            failures = group_error.subgroup(JobError)

            if failures is not None:
                failure = failures.exceptions[0]
                assert isinstance(failure, JobError), "Wave unexpectedly nested its page failure"
                raise failure from None

            raise JobError(JobFailure(JobFailureCode.PROVIDER,
                "Web traversal page task failed; owned workers were drained")) from None

        finally:
            cancellation_task.cancel()

            await asyncio.gather(cancellation_task, return_exceptions=True)

        context.CheckCancellation()

        return tuple(task.result() for task in tasks)
