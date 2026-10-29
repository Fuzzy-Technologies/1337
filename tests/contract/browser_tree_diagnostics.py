# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded test-only custody for genuine browser readiness failures; no engine substitute."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.executors import ExecutionEvent, LocalExecutionRequest, LocalExecutionResult

FIXTURE_FILE_BYTES = 16384
DIAGNOSTIC_BYTES = 2 * 1024 * 1024


async def AwaitBrowserReadiness(
    execution: asyncio.Task, readiness: asyncio.Event, *, timeout_seconds: float,
) -> str:
    """Observe readiness or original execution completion without cancelling that execution.

    Args:
        execution: Original owned executor task, whose terminal outcome remains untouched.
        readiness: Exact stdout-marker signal from the independent acceptance observer.
        timeout_seconds: Existing readiness deadline, supplied explicitly by the caller.

    Returns:
        Ready, execution-complete or readiness-deadline, without hiding early execution failure.
    """

    ready_waiter = asyncio.create_task(readiness.wait())

    try:
        await asyncio.wait((execution, ready_waiter), timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED)

        if readiness.is_set():
            return "ready"

        if execution.done():
            return "execution-complete"

        return "readiness-deadline"

    finally:
        ready_waiter.cancel()

        await asyncio.gather(ready_waiter, return_exceptions=True)


def OriginalEvents(events: tuple[ExecutionEvent, ...]) -> list[dict]:
    """Detach exact original event fields without stream decoding or rechunking.

    Args:
        events: Already bounded original executor or observer events.

    Returns:
        Exact ordered sequence, kind, byte hex and termination fields.
    """

    return [{"sequence": event.sequence, "kind": event.kind, "data_hex": event.data.hex(),
             "termination": event.termination} for event in events]


def FixtureFiles(root: Path) -> dict:
    """Read only four explicit fixture files, with finite bytes and no process enumeration.

    Args:
        root: Current case's owned readiness and identity directory.

    Returns:
        Explicit absence, bounded raw bytes or read errors for each fixed file.
    """

    files = {}

    for name in ("ready.json", "ready.pending", "identities.json", "identities.pending"):
        descriptor = None

        try:
            path = root / name
            before = path.stat(follow_symlinks=False)

            if not stat.S_ISREG(before.st_mode):
                files[name] = {"state": "not-regular"}

                continue

            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                getattr(os, "O_BINARY", 0))
            opened = os.fstat(descriptor)

            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                files[name] = {"state": "identity-changed"}

                continue

            raw = bytearray()

            while len(raw) <= FIXTURE_FILE_BYTES:
                chunk = os.read(descriptor, FIXTURE_FILE_BYTES + 1 - len(raw))

                if not chunk:
                    break

                raw.extend(chunk)

            files[name] = {"state": "present", "size_bytes": opened.st_size,
                "data_hex": bytes(raw[:FIXTURE_FILE_BYTES]).hex(),
                "truncated": len(raw) > FIXTURE_FILE_BYTES}

        except FileNotFoundError:
            files[name] = {"state": "absent"}

        except OSError as error:
            files[name] = {"state": "unreadable", "error": str(error)[:4096]}

        finally:
            if descriptor is not None:
                os.close(descriptor)

    return files


def WriteBrowserTreeDiagnostics(
    destination: Path, root: Path, request: LocalExecutionRequest, *,
    result: LocalExecutionResult | None, error: BaseException | None,
    observed_events: tuple[ExecutionEvent, ...], ready_bytes: bytes, wait_outcome: str,
) -> str:
    """Persist original failure custody before readiness assertions or fallback fixture cleanup.

    Args:
        destination: Explicit current acceptance artifact path, distinct for each stop case.
        root: Current owned fixture directory; only its four fixed output files are read.
        request: Exact original closed fixture request and finite stream limits.
        result: Original terminal executor result when available, never a synthesized success.
        error: Original raised execution exception if no terminal result was returned.
        observed_events: Exact bounded events delivered before an exception or terminal outcome.
        ready_bytes: Exact bounded readiness-prefix bytes observed across stream chunks.
        wait_outcome: Explicit result of racing readiness with original task completion.

    Returns:
        Concise diagnostic summary including original stderr for pytest/JUnit failures.
    """

    terminal = None if result is None else {
        "execution": json.loads(SerializeContract(result.execution)),
        "termination": result.termination, "stdout_hex": result.stdout.hex(),
        "stderr_hex": result.stderr.hex(), "events": OriginalEvents(result.events)}
    exception = None if error is None else {"type": type(error).__name__,
        "module": type(error).__module__, "message": str(error)[:4096]}
    payload = {"schema_version": 1, "test_process_id": os.getpid(),
        "fixture_directory": str(root), "request": json.loads(SerializeContract(request)),
        "wait_outcome": wait_outcome, "ready_bytes_hex": ready_bytes.hex(),
        "observed_events": OriginalEvents(observed_events), "terminal_result": terminal,
        "execution_exception": exception, "fixture_files": FixtureFiles(root)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    if len(raw) > DIAGNOSTIC_BYTES:
        raise AssertionError("Closed browser diagnostic exceeded its two-MiB custody ceiling")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    details = f"wait={wait_outcome}; terminal={None if terminal is None else terminal['execution']}"
    stderr = b"".join(event.data for event in observed_events if event.kind == "stderr") if (
        result is None) else result.stderr

    return f"{details}; exception={exception}; stderr={stderr!r}; diagnostics={destination}"
