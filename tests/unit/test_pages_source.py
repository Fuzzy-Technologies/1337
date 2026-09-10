import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGES = (ROOT / "index.md", ROOT / "ru/index.md")
CSS = ROOT / "static/style.css"

BLOCK_HTML_INDENT = re.compile(r"^ {4,}</?[A-Za-z]")
CLASS_ATTRIBUTE = re.compile(r'class="([^"]+)"')
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
            opening = len(re.findall(rf"<{tag}\\b", content))
            closing = content.count(f"</{tag}>")
            assert opening == closing, (
                f"{page.relative_to(ROOT)} has unbalanced <{tag}> tags: "
                f"{opening} opening, {closing} closing"
            )


def test_localized_pages_keep_the_same_component_structure() -> None:
    english = read(PAGES[0])
    russian = read(PAGES[1])

    assert english.count('<section class="content-section">') == 8
    assert russian.count('<section class="content-section">') == 8
    assert page_classes(english) == page_classes(russian)


def test_site_css_covers_all_page_classes() -> None:
    css = read(CSS)
    classes = set()

    for page in PAGES:
        classes.update(page_classes(read(page)))

    missing = sorted(name for name in classes if f".{name}" not in css)
    assert not missing, f"Page classes without CSS selectors: {', '.join(missing)}"


def test_language_routes_are_present_on_both_pages() -> None:
    english = read(PAGES[0])
    russian = read(PAGES[1])

    assert "{{ '/ru/' | relative_url }}" in english
    assert "{{ '/' | relative_url }}" in russian
    assert 'class="lang-button active"' in english
    assert 'class="lang-button active"' in russian
