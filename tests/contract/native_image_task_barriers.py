# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite controlled-task readiness barriers; never engine execution or process ownership."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from fuzzy1337.jobs import JobSnapshot

T = TypeVar("T")


class EarlyOperationCompletion(AssertionError):
    """Retain the actual early result without presenting readiness or cancellation as complete."""

    def __init__(self, result: object) -> None:
        """Expose an original returned summary and bounded terminal diagnostics.

        Args:
            result: Actual operation return value before the controlled readiness signal.
        """

        self.result = result
        snapshot = getattr(result, "snapshot", None)
        detail = (f"state={snapshot.state.value}; failure={snapshot.failure}" if
                  isinstance(snapshot, JobSnapshot) else f"result_type={type(result).__name__}")
        super().__init__("Owned operation completed before readiness: " + detail)


@asynccontextmanager
async def OwnedTaskAtReadiness(
    operation: Coroutine[Any, Any, T], readiness: asyncio.Event, *, timeout_seconds: float = 5.0,
) -> AsyncIterator[asyncio.Task[T]]:
    """Own a controlled operation through readiness, early termination and every caller exit.

    Args:
        operation: One not-yet-scheduled operation using the current test's cooperative controls.
        readiness: Exact controlled worker signal, never a substituted success outcome.
        timeout_seconds: Finite readiness deadline used only when neither task completes.

    Yields:
        Actual still-running operation task after readiness, retained until caller exit.

    Raises:
        EarlyOperationCompletion: The original operation returned before readiness.
        TimeoutError: Neither readiness nor terminal execution arrived before the deadline.
        BaseException: The original operation or caller exception, after settling owned tasks.
    """

    task = asyncio.create_task(operation)
    ready_waiter = asyncio.create_task(readiness.wait())

    try:
        done, _ = await asyncio.wait((task, ready_waiter), timeout=timeout_seconds,
                                     return_when=asyncio.FIRST_COMPLETED)

        if task in done:
            raise EarlyOperationCompletion(task.result())

        if ready_waiter not in done:
            raise TimeoutError("Owned operation neither became ready nor terminated")

        yield task

    finally:
        ready_waiter.cancel()

        if not task.done():
            task.cancel()

        await asyncio.gather(ready_waiter, task, return_exceptions=True)
