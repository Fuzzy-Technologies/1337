# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Hold only an actual offline about:blank Chromium tree for bounded ownership acceptance."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from importlib import metadata
from pathlib import Path


def RecordTree(root: Path) -> None:
    """Record identities reachable only through this fixture's owned kernel child lists.

    Args:
        root: Explicit directory belonging to the current isolated pytest case.
    """

    pending = [os.getpid()]
    records = []
    visited = set()

    while pending:
        process_id = pending.pop()

        if process_id in visited:
            continue

        visited.add(process_id)
        process_root = Path(f"/proc/{process_id}")

        try:
            stat = (process_root / "stat").read_text(encoding="ascii")
            name = stat.split("(", 1)[1].rsplit(")", 1)[0]
            started = int(stat.rsplit(")", 1)[1].split()[19])
            executable = os.readlink(process_root / "exe").rsplit("/", 1)[-1]
            records.append({"pid": process_id, "started_ticks": started, "name": name,
                            "executable": executable})

            for task in (process_root / "task").iterdir():
                children = (task / "children").read_text(encoding="ascii")
                pending.extend(int(child) for child in children.split())

        except FileNotFoundError:
            continue

        if len(visited) > 64:
            raise RuntimeError("Owned about:blank process tree exceeded the fixture bound")

    names = [record["executable"] for record in records]

    if "node" not in names or not any("chrome" in name for name in names):
        raise RuntimeError("Actual Node and Chromium identities were not recorded")

    temporary = root / "identities.pending"
    temporary.write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
    temporary.replace(root / "identities.json")


async def Run(root: Path) -> None:
    """Create a pinned real engine before exposing the finite owner-controlled stop barrier.

    Args:
        root: Current test directory containing only fixture readiness/release/identity files.
    """

    from playwright.async_api import async_playwright

    installed = metadata.version("playwright")

    if installed != "1.64.1":
        raise RuntimeError("Owned browser acceptance requires pinned Playwright 1.64.1")

    async with async_playwright() as driver:
        browser = await driver.chromium.launch(headless=True, timeout=5000)

        try:
            if browser.version != "156.0.8078.4":
                raise RuntimeError("Owned browser acceptance requires pinned Chromium")

            context = await browser.new_context(offline=True, java_script_enabled=False,
                service_workers="block", accept_downloads=False)
            page = await context.new_page()

            if page.url != "about:blank":
                raise RuntimeError("Owned browser fixture must remain about:blank")

            RecordTree(root)
            record = {"playwright_version": installed, "chromium_version": browser.version,
                      "url": page.url}
            temporary = root / "ready.pending"
            temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
            temporary.replace(root / "ready.json")
            sys.stdout.buffer.write(b"owned-browser-ready\n")
            sys.stdout.buffer.flush()
            deadline = time.monotonic() + 12

            while not (root / "release").is_file() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)

            await context.close()

        finally:
            await browser.close()


def Main() -> int:
    """Accept only this case's output directory and launch no navigated or scripted content.

    Returns:
        Zero after an explicit release or the bounded emergency lifetime.
    """

    if len(sys.argv) != 2:
        raise ValueError("Owned browser fixture requires its single case directory")

    root = Path(sys.argv[1]).resolve(strict=True)

    if not root.is_dir():
        raise ValueError("Owned browser fixture requires an existing case directory")

    asyncio.run(Run(root))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
