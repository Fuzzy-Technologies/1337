# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Require real rendered mathematics rather than successful markup generation."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.verify_documentation_render import (
    LOCALES,
    Main,
    ValidateRenderedMath,
    VerifyDocumentationRender,
)


def MathDom(text: str = "x") -> str:
    """Create two representative browser-generated SVG formula containers."""

    return 2 * f'<mjx-container jax="SVG"><svg><title>{text}</title></svg></mjx-container>'


def test_ActualSvgFormulasAreAccepted() -> None:
    """Accept inline and block SVG output while ignoring literal examples in source blocks."""

    evidence = ValidateRenderedMath(MathDom() + '<pre><code>\\(x\\)</code></pre>')
    assert evidence == {"containers": 2, "svgElements": 2}, "Actual SVG proof was lost"


@pytest.mark.parametrize("dom", (
    '<span class="arithmatex">\\(x\\)</span>',
    '<mjx-container jax="CHTML"><span>x</span></mjx-container>',
    '<mjx-container jax="SVG"></mjx-container>' * 2,
    MathDom("\\(x\\)"),
    MathDom("$$x$$"),
))
def test_UnrenderedOrLeakedMathematicsIsRejected(dom: str) -> None:
    """Reject merely present resources, failed rendering, and visible source delimiters."""

    with pytest.raises(ValueError):
        ValidateRenderedMath(dom)


def test_AllLocalesUseBoundedOfflineBrowser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the renderer uses locale output and bounds its external process authority."""

    calls = []

    for locale in LOCALES:
        page = tmp_path / locale / "index.html"
        page.parent.mkdir()
        page.write_text("unrendered", encoding="utf-8")

    def Run(command: list[str], **options: object) -> SimpleNamespace:
        """Record the external boundary and supply a completed browser DOM."""

        calls.append((command, options))

        return SimpleNamespace(stdout=MathDom())

    monkeypatch.setattr(subprocess, "run", Run)
    evidence = VerifyDocumentationRender(tmp_path, "reviewed-chromium")
    assert set(evidence) == set(LOCALES), "A locale lacked real rendering proof"
    assert len(calls) == 3, "Every locale must pass the external renderer"

    for command, options in calls:
        assert command[0] == "reviewed-chromium", "Renderer executable was silently changed"
        assert "--host-resolver-rules=MAP * ~NOTFOUND" in command, (
            "Renderer enabled remote resources"
        )
        assert options["timeout"] == 30 and options["check"], "Browser failure/deadline was hidden"


def test_BrowserFailurePropagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never convert browser startup failure into successful formula evidence."""

    page = tmp_path / "en/index.html"
    page.parent.mkdir()
    page.write_text("unrendered", encoding="utf-8")

    def Run(*args: object, **kwargs: object) -> None:
        """Simulate a bounded browser process failure."""

        raise subprocess.TimeoutExpired("chromium", 30)

    monkeypatch.setattr(subprocess, "run", Run)

    with pytest.raises(subprocess.TimeoutExpired):
        VerifyDocumentationRender(tmp_path, "chromium")


def test_RenderCliPreservesLocaleEvidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise command parsing and evidence serialization after the bounded browser proof."""

    for locale in LOCALES:
        path = tmp_path / locale / "index.html"
        path.parent.mkdir()
        path.write_text("before rendering", encoding="utf-8")

    def Run(*args: object, **kwargs: object) -> SimpleNamespace:
        """Supply successful DOM proof at the unit-tested browser boundary."""

        return SimpleNamespace(stdout=MathDom())

    monkeypatch.setattr(subprocess, "run", Run)
    output = tmp_path / "evidence/render.json"
    monkeypatch.setattr(sys, "argv", ["render", "--api-root", str(tmp_path),
                                      "--browser", "fixture-browser", "--output", str(output)])
    assert Main() == 0, "Rendering CLI rejected valid locale proofs"
    assert set(json.loads(output.read_text())) == set(LOCALES), (
        "CLI dropped locale rendering evidence"
    )


def test_MissingBrowserFailsCli(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing real browser capability cannot turn a documentation gate green."""

    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "argv", ["render"])

    with pytest.raises(RuntimeError, match="real Chromium"):
        Main()
