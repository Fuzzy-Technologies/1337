# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Render only a fully verified reviewed native body through a fixed offline Chromium context."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import sys
import time
from collections.abc import Sequence
from importlib import import_module, metadata
from typing import Any

from fuzzy1337.adapters.browser_page import (
    BROWSER_ERROR_EXITS,
    MAX_BLOCKED_REQUESTS,
    MAX_DOM_BYTES,
    MAX_DOM_ELEMENTS,
    RENDER_SECONDS,
    ParseBrowserRecord,
)
from fuzzy1337.adapters.page_capture import (
    CHROMIUM_VERSION,
    ERROR_EXITS,
    PAGE_BROWSER_PROFILE,
    PLAYWRIGHT_VERSION,
    CanonicalRecord,
    DecodeBody,
    Integer,
    KnownBody,
    KnownSyntheticHtmlBody,
)
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.page_capture_worker import (
    PageBodyPolicyError,
    PageProtocolError,
    PageResponsePolicyError,
    Probe,
    WorkerInputs,
)


class BrowserRenderError(RuntimeError):
    """One fixed renderer failure category, without exception, source or DOM diagnostics."""


def RemainingMilliseconds(deadline: float) -> int:
    """Return a positive bounded remainder from the one renderer budget, never a fresh timeout.

    Args:
        deadline: Shared monotonic renderer deadline including package/startup/operations/close.

    Returns:
        Positive remaining milliseconds, never the unbounded third-party timeout value zero.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise BrowserRenderError("renderer-timeout")

    return max(1, int(remaining * 1000))


async def Render(body: bytes, expected_body: KnownSyntheticHtmlBody) -> dict[str, object]:
    """Measure fixed DOM facts from already admitted non-secret bytes without browser navigation.

    Args:
        body: Exact reviewed complete native response body, verified before this function/import.
        expected_body: Exact finite reviewed selection, independently revalidated before import.

    Returns:
        Bounded DOM counts/digest and actual pinned engine versions; never arbitrary DOM text.

    Raises:
        BrowserRenderError: Dependency, version, timeout or closed offline policy is unsupported.
    """

    deadline = time.monotonic() + RENDER_SECONDS

    try:
        expected = KnownBody(expected_body)

        if type(body) is not bytes or len(body) != expected.size_bytes or (
            hashlib.sha256(body).hexdigest() != expected.sha256
        ):
            raise ValueError("renderer body differs from reviewed catalog")

    except (ValueError, TypeError, AttributeError):
        raise BrowserRenderError("renderer-policy") from None

    manager: Any = None
    browser: Any = None
    context: Any = None
    blocked = 0
    pages = 0
    policy_failed = False

    async def AbortRequest(route: Any) -> None:
        """Abort every browser HTTP request, retaining only a finite blocked-attempt count.

        Args:
            route: Browser-owned request interception; no URL/value is retained or followed.
        """

        nonlocal blocked, policy_failed
        blocked += 1
        policy_failed = policy_failed or blocked > MAX_BLOCKED_REQUESTS

        await route.abort(error_code="blockedbyclient")

    async def CloseSocket(route: Any) -> None:
        """Refuse any unexpected WebSocket without establishing an upstream connection.

        Args:
            route: Browser-owned intercepted socket, deliberately never connected to a server.
        """

        nonlocal policy_failed
        policy_failed = True

        await route.close()

    async def RefuseExtraPage(page: Any) -> None:
        """Keep only the single explicitly created about:blank page and close unexpected pages.

        Args:
            page: Actual context-created page; no caller-supplied navigation is admitted.
        """

        nonlocal pages, policy_failed
        pages += 1

        if pages > 1:
            policy_failed = True

            await page.close(run_before_unload=False)

    async def RefuseDownload(download: Any) -> None:
        """Cancel any unexpected download without retaining files or download metadata.

        Args:
            download: Browser-owned attempt; the fixed context already refuses downloads.
        """

        nonlocal policy_failed
        policy_failed = True

        await download.cancel()

    try:
        async with asyncio.timeout(RENDER_SECONDS):
            try:
                installed_version = metadata.version("playwright")

            except metadata.PackageNotFoundError:
                raise BrowserRenderError("renderer-unavailable") from None

            if installed_version != PLAYWRIGHT_VERSION:
                raise BrowserRenderError("renderer-version")

            try:
                api = import_module("playwright.async_api")

            except ImportError:
                raise BrowserRenderError("renderer-unavailable") from None

            manager = await api.async_playwright().start()
            browser = await manager.chromium.launch(headless=True,
                timeout=RemainingMilliseconds(deadline))
            chromium_version = browser.version

            if chromium_version != CHROMIUM_VERSION:
                raise BrowserRenderError("renderer-version")

            context = await browser.new_context(offline=True, java_script_enabled=False,
                service_workers="block", accept_downloads=False)
            context.set_default_timeout(RemainingMilliseconds(deadline))
            context.on("page", RefuseExtraPage)

            await context.route("**/*", AbortRequest)
            await context.route_web_socket("**/*", CloseSocket)
            page = await context.new_page()
            page.on("download", RefuseDownload)

            if page.url != "about:blank":
                raise BrowserRenderError("renderer-policy")

            await page.set_content(body.decode("utf-8", errors="strict"), wait_until="load",
                                   timeout=RemainingMilliseconds(deadline))
            serialized = await page.content()

            if type(serialized) is not str or len(serialized) > MAX_DOM_BYTES:
                raise BrowserRenderError("renderer-policy")

            dom = serialized.encode("utf-8", errors="strict")
            Integer(len(dom), 1, MAX_DOM_BYTES)
            counts = []

            for selector in ("*", "a", "form", "input"):
                RemainingMilliseconds(deadline)
                counts.append(Integer(await page.locator(selector).count(), 0, MAX_DOM_ELEMENTS))

            Integer(counts[0], 1, MAX_DOM_ELEMENTS)

            if policy_failed or pages != 1 or len(context.pages) != 1 or (
                page.url != "about:blank"
            ):
                raise BrowserRenderError("renderer-policy")

            result = {"playwright_version": installed_version, "chromium_version": chromium_version,
                "dom_sha256": hashlib.sha256(dom).hexdigest(), "dom_size_bytes": len(dom),
                "element_count": counts[0], "anchor_count": counts[1], "form_count": counts[2],
                "input_count": counts[3], "blocked_request_count": blocked}

            await context.close()
            context = None

            await browser.close()
            browser = None

            await manager.stop()
            manager = None
            RemainingMilliseconds(deadline)

            return result

    except TimeoutError:
        raise BrowserRenderError("renderer-timeout") from None

    finally:
        # Expired operations receive no renewed close budget; the verified descendant owner
        # still kills/reaps the whole worker tree before any execution result can complete.
        for resource in (context, browser, manager):
            if resource is not None and time.monotonic() < deadline:
                try:
                    close = resource.stop if resource is manager else resource.close

                    await asyncio.wait_for(close(), RemainingMilliseconds(deadline) / 1000)

                except Exception:
                    pass


def Main(argv: Sequence[str] | None = None) -> int:
    """Acquire once with unchanged Probe before optional browser import or any renderer launch.

    Args:
        argv: Exact four canonical native URL/timeout/fixture/body-limit process tokens.

    Returns:
        Zero only for a fully admitted browser report, otherwise a fixed bounded failure code.
        Post-acquisition renderer failure retains the complete verified original native group.
    """

    error = "input"
    native: dict[str, object] | None = None
    result: dict[str, object] | None = None

    try:
        RequireLinuxOwnership()
        arguments = tuple(sys.argv[1:]) if argv is None else argv
        inputs = WorkerInputs(arguments)
        native = Probe(*inputs)
        expected = KnownSyntheticHtmlBody(inputs[2])
        body = DecodeBody(native, expected)
        metrics = asyncio.run(Render(body, expected))
        result = {**native, "renderer_profile": PAGE_BROWSER_PROFILE,
                  "input_body_sha256": expected.sha256, **metrics}
        ParseBrowserRecord(CanonicalRecord(result), inputs[0], expected, inputs[3])

    except (TimeoutError, socket.timeout):
        error = "timeout" if native is None else "renderer-timeout"

    except PageProtocolError:
        error = "protocol"

    except PageResponsePolicyError:
        error = "response-policy"

    except PageBodyPolicyError:
        error = "body-policy"

    except BrowserRenderError as failure:
        category = str(failure)
        error = category if category in BROWSER_ERROR_EXITS else "renderer"

    except LocalExecutionError:
        error = "renderer-unavailable"

    except OSError:
        error = "connection" if native is None else "renderer"

    except Exception:
        error = "input" if native is None else "renderer"

    else:
        sys.stdout.buffer.write(CanonicalRecord(result))

        return 0

    record = {"schema_version": 1, "renderer_profile": PAGE_BROWSER_PROFILE, "error": error}

    if native is not None:
        record = {**native, **record, "input_body_sha256": native["body_sha256"]}

    sys.stdout.buffer.write(CanonicalRecord(record))

    return {**ERROR_EXITS, **BROWSER_ERROR_EXITS}[error]


if __name__ == "__main__":
    raise SystemExit(Main())
