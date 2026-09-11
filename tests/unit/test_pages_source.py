import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGES = (ROOT / "index.md", ROOT / "ru/index.md", ROOT / "zh-cn/index.md")
CSS = ROOT / "static/style.css"
CONFIG = ROOT / "_config.yml"
SITEMAP = ROOT / "sitemap.xml"

SITE_SOURCE_ROOTS = {
    "_config.yml",
    "_layouts",
    "index.md",
    "llms.txt",
    "ru",
    "sitemap.xml",
    "static",
    "zh-cn",
}

BLOCK_HTML_INDENT = re.compile(r"^ {4,}</?[A-Za-z]")
CLASS_ATTRIBUTE = re.compile(r'class="([^"]+)"')
CONFIG_EXCLUDE_ITEM = re.compile(r"^\s{2}-\s+(.+?)\s*$")
PAIRED_TAGS = (
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


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def page_classes(content: str) -> set[str]:
    classes: set[str] = set()
    for value in CLASS_ATTRIBUTE.findall(content):
        classes.update(value.split())
    return classes


def tracked_root_entries() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        Path(path).parts[0]
        for path in result.stdout.split("\0")
        if path
    }


def configured_page_excludes() -> set[str]:
    excludes: set[str] = set()
    in_exclude_block = False

    for line in read(CONFIG).splitlines():
        if line == "exclude:":
            in_exclude_block = True
            continue

        if not in_exclude_block:
            continue

        match = CONFIG_EXCLUDE_ITEM.match(line)
        if match:
            excludes.add(match.group(1).strip("'\"").rstrip("/"))
            continue

        if line and not line.startswith(" "):
            break

    return excludes


def test_pages_do_not_indent_raw_html_as_markdown_code() -> None:
    violations: list[str] = []

    for page in PAGES:
        for line_number, line in enumerate(read(page).splitlines(), start=1):
            if BLOCK_HTML_INDENT.match(line):
                violations.append(f"{page.relative_to(ROOT)}:{line_number}: {line.strip()}")

    assert not violations, (
        "Raw HTML indented by four or more spaces is rendered as Markdown code:\n"
        + "\n".join(violations)
    )


def test_pages_have_balanced_html_tags() -> None:
    for page in PAGES:
        content = read(page)

        for tag in PAIRED_TAGS:
            opening = len(re.findall(rf"<{tag}(?:[ >])", content))
            closing = content.count(f"</{tag}>")
            assert opening == closing, (
                f"{page.relative_to(ROOT)} has unbalanced <{tag}> tags: "
                f"{opening} opening, {closing} closing"
            )


def test_localized_pages_keep_the_same_component_structure() -> None:
    pages = [read(page) for page in PAGES]
    reference_classes = page_classes(pages[0])

    assert all(page.count('<section class="content-section">') == 8 for page in pages)
    assert all(page_classes(page) == reference_classes for page in pages[1:])


def test_site_css_covers_all_page_classes() -> None:
    css = read(CSS)
    classes = set()

    for page in PAGES:
        classes.update(page_classes(read(page)))

    missing = sorted(name for name in classes if f".{name}" not in css)
    assert not missing, f"Page classes without CSS selectors: {', '.join(missing)}"


def test_simplified_chinese_page_has_native_font_fallbacks() -> None:
    css = read(CSS)

    assert 'html[lang="zh-CN"] body' in css
    assert '"PingFang SC"' in css
    assert '"Microsoft YaHei"' in css
    assert '"Noto Sans SC"' in css


def test_language_routes_are_present_on_all_pages() -> None:
    routes = (
        "{{ '/' | relative_url }}",
        "{{ '/ru/' | relative_url }}",
        "{{ '/zh-cn/' | relative_url }}",
    )

    for page in PAGES:
        content = read(page)
        assert all(route in content for route in routes)
        assert 'class="lang-button active"' in content


def test_pages_publish_boundary_is_explicit_and_fail_closed() -> None:
    tracked_roots = tracked_root_entries()
    excluded_roots = configured_page_excludes()
    non_site_roots = tracked_roots - SITE_SOURCE_ROOTS

    missing_excludes = sorted(non_site_roots - excluded_roots)
    assert not missing_excludes, (
        "Tracked repository roots would be published by GitHub Pages unless "
        f"explicitly excluded: {', '.join(missing_excludes)}"
    )

    published_but_excluded = sorted(SITE_SOURCE_ROOTS & excluded_roots)
    assert not published_but_excluded, (
        "Required Pages sources must not be excluded: "
        + ", ".join(published_but_excluded)
    )


def test_sitemap_contains_only_public_localized_routes() -> None:
    sitemap = read(SITEMAP)
    routes = (
        "{{ '/' | absolute_url }}",
        "{{ '/ru/' | absolute_url }}",
        "{{ '/zh-cn/' | absolute_url }}",
    )

    assert sitemap.count("<url>") == len(routes)
    assert all(f"<loc>{route}</loc>" in sitemap for route in routes)

    for language in ("en", "ru", "zh-CN", "x-default"):
        assert f'hreflang="{language}"' in sitemap
