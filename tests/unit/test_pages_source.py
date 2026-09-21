"""Tests for pages source behavior."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGES = (ROOT / "index.md", ROOT / "ru/index.md", ROOT / "zh-cn/index.md")
CSS = ROOT / "static/style.css"
CONFIG = ROOT / "_config.yml"
SITEMAP = ROOT / "sitemap.xml"

SITESOURCEFILES = {
    "_config.yml",
    "_layouts/default.html",
    "index.md",
    "llms.txt",
    "ru/index.md",
    "sitemap.xml",
    "static/style.css",
    "zh-cn/index.md",
}
SITESOURCEROOTS = {Path(path).parts[0] for path in SITESOURCEFILES}
EXPECTEDEXCLUDEDROOTS = {
    ".dockerignore",
    ".github",
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "DEVELOPMENT_PROTOCOL.md",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "compose.yaml",
    "contracts",
    "docs",
    "labs",
    "prompts",
    "pyproject.toml",
    "src",
    "tests",
    "uv.lock",
}

BLOCKHTMLINDENT = re.compile(r"^ {4,}</?[A-Za-z]")
CLASSATTRIBUTE = re.compile(r'class="([^"]+)"')
CONFIGEXCLUDEITEM = re.compile(r"^\s{2}-\s+(.+?)\s*$")
PAIREDTAGS = (
    "section",
    "div",
    "header",
    "nav",
    "footer",
    "blockquote",
    "p",
    "span",
    "a",
    "h1",
    "h2",
    "h3",
    "ul",
    "li",
    "pre",
    "code",
    "strong",
)


def Read(path: Path) -> str:
    """Provide deterministic test support for read."""

    return path.read_text(encoding="utf-8")


def PageClasses(content: str) -> set[str]:
    """Provide deterministic test support for page classes."""

    classes: set[str] = set()
    for value in CLASSATTRIBUTE.findall(content):
        classes.update(value.split())
    return classes


def TrackedFiles() -> set[str]:
    """Provide deterministic test support for tracked files."""

    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {path for path in result.stdout.split("\0") if path}


def ConfiguredPageExcludes() -> set[str]:
    """Provide deterministic test support for configured page excludes."""

    excludes: set[str] = set()
    inExcludeBlock = False

    for line in Read(CONFIG).splitlines():
        if line == "exclude:":
            inExcludeBlock = True
            continue

        if not inExcludeBlock:
            continue

        match = CONFIGEXCLUDEITEM.match(line)
        if match:
            excludes.add(match.group(1).strip("'\"").rstrip("/"))
            continue

        if line and not line.startswith(" "):
            break

    return excludes


def test_PagesDoNotIndentRawHtmlAsMarkdownCode() -> None:
    """Verify pages do not indent raw html as markdown code."""

    violations: list[str] = []

    for page in PAGES:
        for lineNumber, line in enumerate(Read(page).splitlines(), start=1):
            if BLOCKHTMLINDENT.match(line):
                violations.append(f"{page.relative_to(ROOT)}:{lineNumber}: {line.strip()}")

    assert not violations, (
        "Raw HTML indented by four or more spaces is rendered as Markdown code:\n"
        + "\n".join(violations)
    )


def test_PagesHaveBalancedHtmlTags() -> None:
    """Verify pages have balanced html tags."""

    for page in PAGES:
        content = Read(page)

        for tag in PAIREDTAGS:
            opening = len(re.findall(rf"<{tag}(?:[ >])", content))
            closing = content.count(f"</{tag}>")
            assert opening == closing, (
                f"{page.relative_to(ROOT)} has unbalanced <{tag}> tags: "
                f"{opening} opening, {closing} closing"
            )


def test_LocalizedPagesKeepTheSameComponentStructure() -> None:
    """Verify localized pages keep the same component structure."""

    pages = [Read(page) for page in PAGES]
    referenceClasses = PageClasses(pages[0])

    assert all(page.count('<section class="content-section">') == 8 for page in pages), (
        "localized pages keep the same component structure invariant failed."
    )
    assert all(PageClasses(page) == referenceClasses for page in pages[1:]), (
        "localized pages keep the same component structure invariant failed."
    )


def test_SiteCssCoversAllPageClasses() -> None:
    """Verify site css covers all page classes."""

    css = Read(CSS)
    classes = set()

    for page in PAGES:
        classes.update(PageClasses(Read(page)))

    missing = sorted(name for name in classes if f".{name}" not in css)
    assert not missing, f"Page classes without CSS selectors: {', '.join(missing)}"


def test_SimplifiedChinesePageHasNativeFontFallbacks() -> None:
    """Verify simplified chinese page has native font fallbacks."""

    css = Read(CSS)

    assert 'html[lang="zh-CN"] body' in css, (
        "simplified chinese page has native font fallbacks invariant failed."
    )
    assert '"PingFang SC"' in css, (
        "simplified chinese page has native font fallbacks invariant failed."
    )
    assert '"Microsoft YaHei"' in css, (
        "simplified chinese page has native font fallbacks invariant failed."
    )
    assert '"Noto Sans SC"' in css, (
        "simplified chinese page has native font fallbacks invariant failed."
    )


def test_LanguageRoutesArePresentOnAllPages() -> None:
    """Verify language routes are present on all pages."""

    routes = (
        "{{ '/' | relative_url }}",
        "{{ '/ru/' | relative_url }}",
        "{{ '/zh-cn/' | relative_url }}",
    )

    for page in PAGES:
        content = Read(page)
        assert all(route in content for route in routes), (
            "language routes are present on all pages invariant failed."
        )
        assert 'class="lang-button active"' in content, (
            "language routes are present on all pages invariant failed."
        )


def test_PagesPublishBoundaryMatchesCanonicalExcludes() -> None:
    """Verify pages publish boundary matches canonical excludes."""

    excludedRoots = ConfiguredPageExcludes()

    assert excludedRoots == EXPECTEDEXCLUDEDROOTS, (
        "pages publish boundary matches canonical excludes invariant failed."
    )
    assert not SITESOURCEROOTS & excludedRoots, (
        "pages publish boundary matches canonical excludes invariant failed."
    )


def test_PagesPublishBoundaryRejectsUnclassifiedTrackedFiles() -> None:
    """Verify pages publish boundary rejects unclassified tracked files."""

    if shutil.which("git") is None:
        pytest.skip("git is not installed in the container quality image")

    tracked = TrackedFiles()
    trackedRoots = {Path(path).parts[0] for path in tracked}
    nonSiteRoots = trackedRoots - SITESOURCEROOTS

    missingExcludes = sorted(nonSiteRoots - EXPECTEDEXCLUDEDROOTS)
    assert not missingExcludes, (
        "Tracked repository roots would be published by GitHub Pages unless "
        f"explicitly excluded: {', '.join(missingExcludes)}"
    )

    unapprovedSiteFiles = sorted(
        path
        for path in tracked
        if Path(path).parts[0] in SITESOURCEROOTS
        and path not in SITESOURCEFILES
    )
    assert not unapprovedSiteFiles, (
        "Files inside public Pages roots require explicit approval in "
        f"SITE_SOURCE_FILES: {', '.join(unapprovedSiteFiles)}"
    )


def test_SitemapContainsOnlyPublicLocalizedRoutes() -> None:
    """Verify sitemap contains only public localized routes."""

    sitemap = Read(SITEMAP)
    routes = (
        "{{ '/' | absolute_url }}",
        "{{ '/ru/' | absolute_url }}",
        "{{ '/zh-cn/' | absolute_url }}",
    )

    assert sitemap.count("<url>") == len(routes), (
        "sitemap contains only public localized routes invariant failed."
    )
    assert all(f"<loc>{route}</loc>" in sitemap for route in routes), (
        "sitemap contains only public localized routes invariant failed."
    )

    for language in ("en", "ru", "zh-CN", "x-default"):
        assert f'hreflang="{language}"' in sitemap, (
            "sitemap contains only public localized routes invariant failed."
        )
