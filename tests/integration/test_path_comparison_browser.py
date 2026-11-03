# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in genuine Chromium proof of actual static paired artifacts and exact original downloads."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from importlib import metadata
from pathlib import Path

import pytest

from fuzzy1337.path_rendering import GraphSvg
from tests.contract.reachability_fixture import Fixture
from tests.contract.test_path_comparison_contract import PairArguments
from tests.e2e.test_path_comparison_cli import Console
from tests.path_command_helpers import Files


def test_RequiredActualChromiumRendersStaticPairProofDownloadsAndNoScript(tmp_path):
    """Use genuine original-source Console output; absent browser prerequisites are not PASS."""

    if os.environ.get("FUZZY1337_RUN_PLAYWRIGHT_ACCEPTANCE") != "1":
        pytest.skip("Optional genuine comparison Chromium acceptance disabled; not acceptance")

    assert metadata.version("playwright") == "1.64.1", "Browser package differs from explicit pin."
    from playwright.sync_api import sync_playwright

    fixture = Fixture.Create(tmp_path / "workspace")
    hostile = '</script><script>window.renderedXss=true</script><img src="https://invalid.example/">'
    fixture.graph["context_reference"] = hostile

    for phase in fixture.graph["phases"]:
        if phase["id"] in ("confirmed", "remediation"):
            phase["overrides"].append({"relation": "source-detour", "state": "UNKNOWN",
                                       "confidence": 0.0})
    before, after = fixture.Phase("confirmed"), fixture.Phase("remediation")
    arguments = PairArguments(fixture, before, after)
    retained = Files(fixture.root)
    rendered = Console([*arguments, "--html"])
    machine = Console([*arguments, "--json"])
    assert rendered.returncode == machine.returncode == 0, "Original paired admission failed."
    comparison = json.loads(machine.stdout)
    assert comparison["before"]["analysis"]["coverage"]["unknown_transitions"] > 0, (
        "The browser fixture lacks an actual original UNKNOWN transition."
    )
    artifact = tmp_path / "comparison.html"
    artifact.write_text(rendered.stdout, encoding="utf-8")
    errors = []
    external = []
    facts = {"profile": 1, "javascript": "none", "images_rendered": False,
             "no_script_readable": False, "downloads": {}}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--disable-background-networking"])
        context = browser.new_context(accept_downloads=True)
        context.route(re.compile(r"https?://"), lambda route: (
            external.append(route.request.url), route.abort()))
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(artifact.as_uri(), wait_until="load")
        assert page.locator("script").count() == page.locator("iframe").count() == 0 and not (
            page.evaluate("Boolean(window.renderedXss)")
        ), "Static comparison introduced executable script, a frame or source-controlled markup."
        assert page.locator("section.phase").count() == 2 and page.locator("img").count() == 2, (
            "Original Before/After images or independent proof panels disappeared."
        )
        focus_states = [next(transition["state"]
            for transition in comparison[side]["analysis"]["transitions"]
            if transition["relation_reference"] == comparison["focus_transition"])
            for side in ("before", "after")]
        readable_states = ["Focus state: " + state for state in focus_states]
        assert page.locator("section.phase .focus-state").all_text_contents() == readable_states, (
            "Readable focus labels differ from the original selected transition states."
        )

        for index, side in enumerate(("before", "after")):
            proof = page.locator("section.phase").nth(index).locator("details pre").inner_text()
            assert json.loads(proof) == comparison[side] and '\n  "analysis": {' in proof, (
                "Readable proof panels changed original fields or omitted two-space indentation."
            )
        assert page.locator("img").evaluate_all(
            "images => images.every(image => image.complete && image.naturalWidth > 0)"
        ), "Genuine Chromium did not decode both isolated original SVG data images."
        facts["images_rendered"] = True
        csp = page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute("content")
        assert all(value in csp for value in ("default-src 'none'", "script-src 'none'",
            "img-src data:", "frame-src 'none'", "object-src 'none'", "base-uri 'none'",
            "form-action 'none'")), "The static artifact weakened its fixed offline CSP."
        expected = {
            "path-comparison.json": machine.stdout.encode(),
            "before-path.svg": GraphSvg(comparison["before"], fixture.model)[0].encode(),
            "after-path.svg": GraphSvg(comparison["after"], fixture.model)[0].encode(),
        }

        for name, raw in expected.items():
            link = page.locator('a[download="' + name + '"]')
            uri = link.get_attribute("href")
            assert base64.b64decode(uri.split(",", 1)[1]) == raw, (
                "Original resource bytes changed before the actual browser download."
            )

            with page.expect_download() as pending:
                link.click()

            download = pending.value
            saved = tmp_path / name
            download.save_as(saved)
            assert saved.read_bytes() == raw and download.suggested_filename == name, (
                "Actual browser download changed original graph or exact paired machine bytes."
            )
            facts["downloads"][name] = hashlib.sha256(raw).hexdigest()

        page.locator("#comparison-json").evaluate("element => element.parentElement.open = true")
        assert json.loads(page.locator("#comparison-json").inner_text()) == comparison, (
            "Escaped original paired JSON differs from actual machine output."
        )
        assert "UNKNOWN" in page.locator("body").inner_text() and "BLOCKED" in page.locator(
            "section.phase"
        ).nth(1).inner_text(), "Original uncertainty or focus blocking proof disappeared."
        assert not external and not errors, "Static artifact had network activity or errors."
        output = Path("functional-evidence")
        output.mkdir(exist_ok=True)
        (output / "path-comparison.html").write_text(rendered.stdout, encoding="utf-8")
        page.screenshot(path=str(output / "path-comparison.png"), full_page=True)
        no_script_context = browser.new_context(java_script_enabled=False)
        static = no_script_context.new_page()
        static.goto(artifact.as_uri(), wait_until="load")
        assert static.locator("img").evaluate_all(
            "images => images.length === 2 && images.every(image => image.complete && "
            "image.naturalWidth > 0)"
        ) and "Before" in static.locator("body").inner_text() and "After" in static.locator(
            "body"
        ).inner_text(), "No-script artifact lost original graph images or labelled proof text."
        assert static.locator("section.phase .focus-state").all_text_contents() == (
            readable_states
        ), (
            "Script-disabled presentation lost its readable original focus states."
        )
        facts["focus_states"] = focus_states
        facts["proof_json_indentation"] = 2
        facts["no_script_readable"] = True
        facts["external_requests"] = external
        facts["page_errors"] = errors
        (output / "path-comparison-browser-facts.json").write_text(
            json.dumps(facts, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        no_script_context.close()
        context.close()
        browser.close()

    assert Files(fixture.root) == retained, "Static artifact interaction wrote owners."
