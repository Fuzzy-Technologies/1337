# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in genuine Chromium acceptance of the installed offline graph and fixed control script."""

from __future__ import annotations

import json
import os
import re
from importlib import metadata
from pathlib import Path

import pytest

from fuzzy1337.path_rendering import SCRIPT
from tests.e2e.test_path_rendering_cli import Console
from tests.path_command_helpers import SmallArguments, SmallGraph, Value


def ScriptCoverage(functions, size):
    """Measure executed V8 block-range characters with inner ranges overriding their parents.

    Args:
        functions: Genuine precise coverage function/block ranges for the exact fixed ASCII script.
        size: Exact script length in UTF-16 units, equal to ASCII characters for this fixed script.

    Returns:
        Executed fraction of declared script range characters; never a Python coverage proxy.
    """

    counts = [0] * size
    ranges = [item for function in functions for item in function["ranges"]]

    for item in sorted(ranges, key=lambda item: item["endOffset"] - item["startOffset"],
                       reverse=True):
        for index in range(item["startOffset"], min(size, item["endOffset"])):
            counts[index] = item["count"]

    return sum(value > 0 for value in counts) / size


def test_RequiredActualChromiumUsesOfflineArtifactControlsDownloadsAndCsp(tmp_path):
    """Require actual installed-artifact interaction and >80% fixed-script block coverage."""

    if os.environ.get("FUZZY1337_RUN_PLAYWRIGHT_ACCEPTANCE") != "1":
        pytest.skip("Optional actual graph Chromium acceptance is disabled; not acceptance")

    assert metadata.version("playwright") == "1.64.1", "Required browser differs from explicit pin"
    from playwright.sync_api import sync_playwright

    context = SmallGraph(tmp_path)
    hostile = '</script><script>window.renderedXss=true</script>&"'
    arguments = Value(SmallArguments(context), "--context", hostile)
    result = Console([*arguments, "--html"])
    ordinary = Console([*arguments, "--json"])
    assert result.returncode == ordinary.returncode == 0, "Installed graph producer failed"
    artifact = tmp_path / "path.html"
    artifact.write_text(result.stdout, encoding="utf-8")
    errors = []
    external = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--disable-background-networking"])
        browserContext = browser.new_context(accept_downloads=True)
        browserContext.route(re.compile(r"https?://"), lambda route: (
            external.append(route.request.url), route.abort()))
        page = browserContext.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        cdp = browserContext.new_cdp_session(page)
        cdp.send("Debugger.enable")
        cdp.send("Profiler.enable")
        cdp.send("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
        page.goto(artifact.as_uri(), wait_until="load")
        graph = page.locator("#path-graph")
        initial = graph.get_attribute("viewBox")
        page.locator("#zoom-in").click()
        assert graph.get_attribute("viewBox") != initial, "Actual zoom-in control did not execute"
        page.locator("#zoom-out").click()
        page.locator("#reset-view").click()
        assert graph.get_attribute("viewBox") == initial, "Actual reset did not restore exact view"
        graph.hover()
        page.mouse.wheel(0, -120)
        page.wait_for_function("initial => document.getElementById('path-graph').getAttribute("
                               "'viewBox') !== initial", arg=initial)
        zoomed = graph.get_attribute("viewBox")
        assert float(zoomed.split()[2]) < float(initial.split()[2]), (
            "Actual wheel-in event did not decrease the visible graph width"
        )
        page.mouse.wheel(0, 120)
        page.wait_for_function("previous => document.getElementById('path-graph').getAttribute("
                               "'viewBox') !== previous", arg=zoomed)
        assert float(graph.get_attribute("viewBox").split()[2]) > float(zoomed.split()[2]), (
            "Actual wheel-out event did not increase the visible graph width"
        )
        page.locator("#reset-view").click()
        graph.dispatch_event("pointermove", {"clientX": 0, "clientY": 0})
        bounds = graph.bounding_box()
        assert bounds is not None, "Original graph has no visible browser geometry"
        beforePan = tuple(float(value) for value in graph.get_attribute("viewBox").split())
        page.mouse.move(bounds["x"] + 8, bounds["y"] + 8)
        page.mouse.down()
        page.mouse.move(bounds["x"] + 48, bounds["y"] + 28)
        page.mouse.up()
        afterPan = tuple(float(value) for value in graph.get_attribute("viewBox").split())
        assert afterPan[:2] != beforePan[:2] and afterPan[2:] == beforePan[2:], (
            "Actual drag must move the graph origin without changing the visible width/height"
        )
        graph.dispatch_event("pointercancel", {"pointerId": 1})
        page.locator("#reset-view").click()
        edge = page.locator("#path-graph a.edge").first
        anchor = edge.get_attribute("href")
        detail = page.locator(anchor)
        detail.evaluate("element => { element.open = false; }")
        edge.locator("text").click()
        assert detail.get_attribute("open") is not None, "Actual edge click lost inspection"
        detail.evaluate("element => { element.open = false; }")
        edge.focus()
        edge.press("Enter")
        assert detail.get_attribute("open") is not None, "Keyboard inspection failed"
        assert "UNKNOWN" in detail.inner_text(), "Original unassessed state was hidden"
        assert page.evaluate("window.renderedXss") is None, "Source text executed as browser code"
        page.evaluate('''() => {
            const injected = document.createElement("script");
            injected.textContent = "window.unpinnedScriptExecuted = true";
            document.body.appendChild(injected);
        }''')
        assert page.evaluate("window.unpinnedScriptExecuted") is None, (
            "Artifact CSP permitted executable code outside its exact fixed script hash"
        )

        with page.expect_download() as selected:
            page.get_by_text("Download exact JSON", exact=True).click()

        downloaded = tmp_path / "downloaded.json"
        selected.value.save_as(downloaded)
        assert downloaded.read_bytes() == ordinary.stdout.encode(), "JSON download changed bytes"

        with page.expect_download() as selected:
            page.get_by_text("Download static SVG", exact=True).click()

        selected.value.save_as(tmp_path / "downloaded.svg")
        assert (tmp_path / "downloaded.svg").read_text().startswith("<svg"), (
            "Actual static graph download is not a standalone SVG"
        )
        coverage = cdp.send("Profiler.takePreciseCoverage")["result"]
        scripts = []

        for entry in coverage:
            if entry["url"] != artifact.as_uri():
                continue

            source = cdp.send("Debugger.getScriptSource", {"scriptId": entry["scriptId"]})

            if source["scriptSource"] == SCRIPT:
                scripts.append(entry)

        assert len(scripts) == 1, "Actual V8 coverage did not bind the exact fixed source script"
        fraction = ScriptCoverage(scripts[0]["functions"], len(SCRIPT))
        assert fraction > 0.8, "Actual graph control block coverage is not strictly above 80%"
        output = Path("functional-evidence")
        output.mkdir(exist_ok=True)
        (output / "path-renderer-coverage.json").write_text(json.dumps({
            "profile": 1, "executed_block_character_fraction": fraction,
            "script": scripts[0]}, sort_keys=True), encoding="utf-8")
        (output / "path-renderer.html").write_text(result.stdout, encoding="utf-8")
        page.locator("#path-graph").screenshot(path=str(output / "path-renderer.png"))
        assert not errors and not external, "Offline graph had errors or attempted network access"
        noScript = browser.new_context(java_script_enabled=False)
        static = noScript.new_page()
        static.goto(artifact.as_uri(), wait_until="load")
        assert static.locator("#path-graph a.edge").count() == 5 and (
            "UNKNOWN" in static.locator("details").first.inner_text()
        ), "No-script graph or original explanations disappeared"
        noScript.close()
        browserContext.close()
        browser.close()
