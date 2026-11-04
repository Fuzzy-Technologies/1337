# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal shared isolated HTTPS pipe owner; typed source admission remains with callers."""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from pathlib import Path

from fuzzy1337.intel_references import RequireReferenceUrl
from fuzzy1337.intelligence_transport import (
    FORMAT_EXIT,
    HTTP_EXIT,
    REDIRECT_EXIT,
    SIZE_EXIT,
    TIMEOUT_EXIT,
)

__all__: tuple[str, ...] = ()
MAX_RECEIVER_BYTES = 16 * 1024 * 1024


def ReceiveIsolatedHttps(
    url: str, max_bytes: int, timeout_seconds: float, *, accept_kind: str = "json",
) -> tuple[bytes, str, int | None]:
    """Own a bounded isolated receiver without granting public source admission.

    Args:
        url: Canonical query-free HTTPS locator already selected by a typed owning profile.
        max_bytes: Positive retained-body ceiling, at most the existing 16 MiB transport bound.
        timeout_seconds: Total process lifetime budget from 0.05 through 60 seconds.
        accept_kind: Fixed json, gzip or zip resource preference; HTTP encoding remains identity.

    Returns:
        Original complete or partial bytes, explicit transport-state token and observed status.
        No source authenticity, parsing, custody, retries or redirect following is implied.

    Raises:
        ValueError: A structural locator, byte, deadline or resource-kind bound is invalid.
        BaseException: Caller interruption is propagated after worker termination and drain.
    """

    RequireReferenceUrl(url)

    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_RECEIVER_BYTES:
        raise ValueError("isolated receiver byte limit must be positive and at most 16 MiB")

    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
        or not 0.05 <= timeout_seconds <= 60):
        raise ValueError("isolated receiver timeout must be finite and within 0.05..60 seconds")

    if type(accept_kind) is not str or accept_kind not in ("json", "gzip", "zip"):
        raise ValueError("isolated receiver resource kind must be json, gzip or zip")

    worker = Path(__file__).with_name("intelligence_transport.py")
    arguments = [sys.executable, "-I", "-S", str(worker), url,
                 str(max_bytes), str(timeout_seconds)]

    if accept_kind != "json":
        arguments.append(accept_kind)

    started = time.monotonic()

    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={},
        )

    except OSError:
        return b"", 'transport-failed', None

    timed_out = False

    try:
        remaining = max(0.0, timeout_seconds - (time.monotonic() - started))
        output, _ = process.communicate(timeout=remaining)

    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        output, _ = process.communicate()

    except BaseException:
        process.kill()
        process.communicate()

        raise

    line, separator, body = output.partition(b"\n")
    status = None

    if separator and len(line) <= 128:
        try:
            metadata = json.loads(line)

            if (
                isinstance(metadata, dict) and set(metadata) == {"status"}
                and type(metadata["status"]) is int and 100 <= metadata["status"] <= 599
            ):
                status = metadata["status"]

        except (ValueError, UnicodeError):
            pass

    if status is None or len(body) > max_bytes:
        return b"", (
            'timed-out' if timed_out else 'transport-failed'
        ), status

    state = {
        0: 'succeeded', REDIRECT_EXIT: 'redirect-rejected',
        HTTP_EXIT: 'http-rejected', FORMAT_EXIT: 'format-rejected',
        SIZE_EXIT: 'size-exceeded', TIMEOUT_EXIT: 'timed-out',
    }.get(process.returncode, 'transport-failed')

    if timed_out:
        state = 'timed-out'

    if state == 'succeeded' and status != 200:
        state = 'transport-failed'

    return body, state, status
