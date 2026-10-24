# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite early-wake unit model with real asyncio task/lock/timeout ownership, no transport."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_crawl, web_traversal
from fuzzy1337.jobs import JobContext, JobError, JobFailureCode, JobSpec

URLS = tuple("http://127.0.0.1:32123/" + path for path in ("index", "alpha", "beta"))


def CheckEarlyWakeRateGate(engine: str, stop: str, monkeypatch, runner: asyncio.Runner) -> None:
    """Exercise actual producer methods while replacing only their local clock/sleeper view."""

    async def Case() -> None:
        """Keep the actual event loop and its scheduler clock unchanged throughout each case."""

        real_loop = asyncio.get_running_loop()
        before = asyncio.all_tasks()
        cancellation = asyncio.Event()
        spec = JobSpec("job:rate-unit", "rate-unit", "scope:rate-unit", "actor:rate-unit",
            "native.loopback-page")
        context = JobContext(SimpleNamespace(Spec=spec, _cancellation=cancellation,
            _progress=None, Publish=lambda *_args: None))
        state = SimpleNamespace(now=0.0, waits=[], dispatches=[], commits=[], tasks=[],
            operation=None, operation_when=None)
        ticks = (0.02, 0.04, 0.05, 0.07, 0.09, 0.10)

        async def Sleep(delay: float) -> None:
            """Return repeatedly early without waiting for wall time or changing the real loop."""

            index = len(state.waits)
            assert index < len(ticks) and delay > 0, (
                "Rate gate renewed its original deadline or attempted an unbounded extra wait"
            )
            state.waits.append(delay)

            await asyncio.sleep(0)
            state.now = ticks[index]

            if index == 1 and stop == "cancel":
                cancellation.set()

            elif index == 1 and stop == "budget" and engine == "web":
                assert state.operation is not None and state.operation.when() == (
                    state.operation_when
                ), "The original operation timeout must not renew during early rate wakes"
                state.operation.reschedule(real_loop.time())

                await real_loop.create_future()

            await asyncio.sleep(0)

        def Timeout(delay: float):
            """Retain the actual outer timeout object; page timeouts keep their ordinary owner."""

            owner = asyncio.timeout(delay)

            if delay == 30:
                assert state.operation is None, "Traversal must create only one original timeout"
                state.operation, state.operation_when = owner, owner.when()

            return owner

        def CreateTask(coroutine):
            """Measure native acquisition dispatch at task creation without replacing the task."""

            if engine == "native" and coroutine.cr_code.co_name == "Acquire":
                state.dispatches.append((coroutine.cr_frame.f_locals["url"], state.now))

            task = asyncio.create_task(coroutine)
            state.tasks.append(task)

            return task

        proxy = SimpleNamespace(**{name: getattr(asyncio, name) for name in (
            "Lock", "Condition", "TaskGroup", "CancelledError", "gather", "ensure_future",
            "shield", "Task", "current_task", "wait", "FIRST_COMPLETED")},
            get_running_loop=lambda: SimpleNamespace(time=lambda: state.now),
            sleep=Sleep, timeout=Timeout, create_task=CreateTask)

        def Frontier(url: str):
            """Supply lexical unit links without establishing any acquisition/evidence claim."""

            return SimpleNamespace(complete=True, entries=tuple(SimpleNamespace(
                target=SimpleNamespace(value=value)) for value in URLS[1:] if url == URLS[0]))

        if engine == "web":
            provider = object.__new__(web_traversal.LocalWebTraversalProvider)
            provider._limits = web_traversal.WebTraversalLimits(max_pages=3, max_depth=1,
                concurrency=2, timeout_seconds=30)
            provider._seed_url, provider._workspace_id, provider._scope_id = (
                URLS[0], "rate-unit", "rate-unit")
            provider._started = False
            provider._completed_urls = ()
            provider._unselected_count = 0
            provider._body_sizes = dict.fromkeys(URLS, 1)

            def Page(url: str):
                """Replace transport only, retaining the actual producer's ordered commit gate."""

                async def Acquire(_context, *, before_commit, publish_progress):
                    """Record dispatch and cross the real commit condition without external work."""

                    state.dispatches.append((url, state.now))

                    await asyncio.sleep(0)
                    await before_commit()
                    state.commits.append(url)

                    return Frontier(url)

                return SimpleNamespace(limits=SimpleNamespace(timeout_seconds=1), Acquire=Acquire)

            provider._providers = {url: Page(url) for url in URLS}
            monkeypatch.setattr(web_traversal, "asyncio", proxy)
            operation = provider.Run(context)

        else:
            provider = object.__new__(native_crawl.NativeCrawlProvider)
            provider.seed_url = URLS[0]
            provider.limits = native_crawl.NativeCrawlLimits(max_pages=3, max_depth=1,
                concurrency=2, timeout_seconds=0.05 if stop == "budget" else 30)
            provider._origin = 0.0
            provider.completed_urls = ()

            async def Acquire(_context, url: str):
                """Keep the original scheduled task asynchronous without a worker or request."""

                await asyncio.sleep(0)

                return SimpleNamespace(url=url)

            def Commit(_context, page):
                """Observe the actual producer's ordered commit loop without a model Save."""

                state.commits.append(page.url)
                provider.completed_urls += (page.url,)

                return URLS[1:] if page.url == URLS[0] else ()

            provider.Acquire, provider.Commit = Acquire, Commit
            monkeypatch.setattr(native_crawl, "asyncio", proxy)
            operation = provider.Traverse(context)

        if stop == "complete":
            await operation
            assert state.waits == pytest.approx((0.05, 0.03, 0.01, 0.05, 0.03, 0.01)), (
                "Each early return must wait only the remainder of the same original rate deadline"
            )
            assert [time for _url, time in state.dispatches] == [0, 0.05, 0.10], (
                "No producer dispatch may precede its original monotonic rate deadline"
            )
            assert state.commits == list(URLS), "Rate waiting must preserve sorted commit order"

        else:
            if stop == "cancel":
                with pytest.raises(asyncio.CancelledError):
                    await operation

            else:
                with pytest.raises(JobError) as error:
                    await operation

                assert error.value.failure.code is JobFailureCode.TIMEOUT, (
                    "The original operation budget must remain a truthful timeout"
                )

            assert state.dispatches == [(URLS[0], 0.0)] and state.commits == [URLS[0]], (
                "Cancellation or original budget expiry during early wakes must prevent "
                "new dispatch"
            )
            expected_waits = (0.05, 0.03, 0.01) if engine == "native" and stop == "budget" else (
                0.05, 0.03)
            assert state.waits == pytest.approx(expected_waits), (
                "Cancellation/budget checks must run before any renewed wait or launch"
            )

        if engine == "native":
            assert provider._origin == 0, "Native operation origin must never renew on progress"

        elif stop == "budget":
            assert state.operation.expired(), "The original actual timeout must drive termination"

        else:
            assert state.operation.when() == state.operation_when, (
                "Early wakes must leave the original outer operation deadline unchanged"
            )

        assert asyncio.get_running_loop() is real_loop, (
            "Unit model must not replace the actual loop"
        )
        assert all(task.done() for task in state.tasks), "Every producer-created task must settle"
        assert asyncio.all_tasks() == before, "Rate gate termination must leave no owned child task"

    runner.run(Case())
