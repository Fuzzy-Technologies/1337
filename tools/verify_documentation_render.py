# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove representative documentation mathematics renders as local SVG glyphs."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

LOCALES = ("en", "ru", "zh-cn")


class RenderedMath(HTMLParser):
    """Collect actual MathJax SVG containers from Chromium's rendered DOM."""

    def __init__(self) -> None:
        """Initialize an empty SVG proof and visible mathematical text buffer."""

        super().__init__()
        self.containers = 0
        self.svg_count = 0
        self.math_depth = 0
        self.depth = 0
        self.visible_math: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record a renderer-owned container or a contained SVG element.

        Args:
            tag: Element name supplied by the standard HTML parser.
            attrs: Parsed attribute pairs; no JavaScript is evaluated here.
        """

        if tag in {"br", "img", "meta", "link", "input", "hr", "source", "wbr"}:
            return

        self.depth += 1

        if tag == "mjx-container" and dict(attrs).get("jax") == "SVG":
            self.containers += 1
            self.math_depth = self.depth

        if tag == "svg" and self.math_depth:
            self.svg_count += 1

    def handle_endtag(self, tag: str) -> None:
        """Close mathematical scopes without inspecting ordinary source code blocks.

        Args:
            tag: Closed element name supplied by HTMLParser.
        """

        if tag == "mjx-container":
            self.math_depth = 0

        self.depth = max(0, self.depth - 1)

    def handle_data(self, data: str) -> None:
        """Collect only text inside actual rendered mathematical containers.

        Args:
            data: Visible element text; executable scripts are outside this scope.
        """

        if self.math_depth:
            self.visible_math.append(data)


def ValidateRenderedMath(dom: str) -> dict[str, int]:
    """Reject missing SVG mathematics or leaked canonical TeX delimiters.

    Args:
        dom: Post-JavaScript Chromium DOM of the representative overview page.

    Returns:
        Counts proving at least the inline and block representative formulas render.

    Raises:
        ValueError: The browser did not produce two SVG formulas or delimiters remain.
    """

    parsed = RenderedMath()
    parsed.feed(dom)

    if parsed.containers < 2 or parsed.svg_count < parsed.containers:
        raise ValueError("Inline and block formula examples must render to MathJax SVG")

    if any(marker in "".join(parsed.visible_math) for marker in ("\\(", "\\)", "\\[", "\\]", "$$")):
        raise ValueError("Rendered mathematics leaked source delimiters")

    return {"containers": parsed.containers, "svgElements": parsed.svg_count}


def VerifyDocumentationRender(api_root: Path, browser: str) -> dict[str, dict[str, int]]:
    """Render all locale overview pages using a bounded offline Chromium invocation.

    Args:
        api_root: Built reference containing en, ru, and zh-cn overview pages.
        browser: Explicit installed Chromium/Chrome executable selected by the caller.

    Returns:
        Locale-scoped actual SVG rendering evidence.

    Raises:
        ValueError: A locale page is missing or formula rendering fails.
        OSError: Chromium cannot be executed.
        subprocess.SubprocessError: Chromium fails or exceeds the bounded deadline.
    """

    evidence = {}

    for locale in LOCALES:
        page = (api_root / locale / "index.html").resolve(strict=True)
        result = subprocess.run(
            [browser, "--headless", "--disable-gpu", "--no-sandbox", "--dump-dom",
             "--virtual-time-budget=8000", "--host-resolver-rules=MAP * ~NOTFOUND",
             page.as_uri()],
            capture_output=True, text=True, check=True, timeout=30,
        )
        evidence[locale] = ValidateRenderedMath(result.stdout)

    return evidence


def Main() -> int:
    """Run the real browser proof; missing browser support is a failing gate.

    Returns:
        Zero after all locales have actual rendered mathematical evidence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-root", type=Path, default=Path("_build/api-reference"))
    parser.add_argument(
        "--browser", default=shutil.which("google-chrome") or shutil.which("chromium"),
    )
    parser.add_argument("--output", type=Path, default=Path("_build/docs/render.json"))
    arguments = parser.parse_args()

    if not arguments.browser:
        raise RuntimeError("A real Chromium browser is required for documentation render proof")

    evidence = VerifyDocumentationRender(arguments.api_root, arguments.browser)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
