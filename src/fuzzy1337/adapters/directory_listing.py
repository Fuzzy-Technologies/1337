# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Recognize one bounded classic HTML directory-index structure for 1337Scope (Litoscope)."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import unquote

__all__ = ["MAX_DIRECTORY_INDEX_BODY_BYTES", "SupportedDirectoryIndex"]

MAX_DIRECTORY_INDEX_BODY_BYTES = 4096
_MAX_TAGS = 256
_MAX_DEPTH = 8
_MAX_ATTRIBUTES = 8
_MAX_TOKEN_BYTES = 1024
_MAX_ENTRY_BYTES = 256
_MAX_ENTRIES = 64
_VOID = frozenset({"meta", "hr", "br", "img"})
_CONTAINERS = frozenset({"pre", "table", "ul"})
_CHILDREN = {
    "html": frozenset({"head", "body"}),
    "head": frozenset({"title", "meta"}),
    "title": frozenset(),
    "body": frozenset({"h1", "pre", "table", "ul", "hr", "br", "p", "address"}),
    "h1": frozenset(),
    "pre": frozenset({"a", "br", "hr", "img"}),
    "table": frozenset({"thead", "tbody", "tr"}),
    "thead": frozenset({"tr"}),
    "tbody": frozenset({"tr"}),
    "tr": frozenset({"th", "td"}),
    "th": frozenset({"a", "img", "br"}),
    "td": frozenset({"a", "img", "br"}),
    "ul": frozenset({"li"}),
    "li": frozenset({"a", "img", "br"}),
    "a": frozenset({"img"}),
    "p": frozenset({"br"}),
    "address": frozenset({"br"}),
}
_ATTRIBUTES = frozenset({"href", "src", "alt", "title", "class", "id", "charset", "lang",
    "border", "cellspacing", "cellpadding", "align", "width", "height"})
_ATTRIBUTE_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
_ENTRY = re.compile(r"[A-Za-z0-9._~!$&'()+,;=@%\-]{1,255}/?")
_SORT = re.compile(r"\?C=[NMSD];O=[AD]")
_HEADING = re.compile(r"Index of /[^\x00-\x20<>?#\\]{0,500}")
_START_TOKEN = re.compile(
    r"<[A-Za-z][A-Za-z0-9]*(?:[ \t\r\n]+[A-Za-z][A-Za-z0-9-]*"
    r"(?:[ \t\r\n]*=[ \t\r\n]*(?:\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+))?)*[ \t\r\n]*/?>",
    re.ASCII,
)
_END_TOKEN = re.compile(r"</[A-Za-z][A-Za-z0-9]*[ \t\r\n]*>")


def CompleteMarkup(text: str) -> bool:
    """Bound complete original markup tokens before HTMLParser can forgive unfinished syntax.

    Args:
        text: Already bounded strict UTF-8 source with unsupported controls refused.

    Returns:
        Whether every original tag/comment/declaration token is complete and within 1024 bytes.
    """

    index = 0

    while True:
        start = text.find("<", index)

        if start == -1:
            return True

        if text.startswith("<!--", start):
            end = text.find("-->", start + 4)

            if end == -1:
                return False

            index = end + 3

        else:
            cursor = start + 1
            quote = ""

            while cursor < len(text):
                character = text[cursor]

                if quote:
                    if character == quote:
                        quote = ""

                elif character in "\"'":
                    quote = character

                elif character == ">":
                    break

                elif character == "<":
                    return False

                cursor += 1

            if cursor == len(text):
                return False

            index = cursor + 1
            token = text[start:index]

            if token.startswith("</"):
                if _END_TOKEN.fullmatch(token) is None:
                    return False

            elif not token.startswith(("<!", "<?")) and _START_TOKEN.fullmatch(token) is None:
                return False

        if len(text[start:index].encode("utf-8")) > _MAX_TOKEN_BYTES:
            return False


class UnsupportedDirectoryIndex(ValueError):
    """The supplied complete response does not have the selected finite index structure."""


class DirectoryIndexParser(HTMLParser):
    """Require a closed classic index tree and related visible relative entry labels."""

    def __init__(self) -> None:
        """Keep only a bounded stack, two headings and the currently open transient label."""

        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.seen: set[str] = set()
        self.tags = 0
        self.declaration = False
        self.closed_root = False
        self.container_seen = False
        self.container_open = False
        self.title: list[str] = []
        self.heading: list[str] = []
        self.entry_label: str | None = None
        self.anchor_text: list[str] = []
        self.anchor_image = False
        self.entries = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Check finite original token, parent relationship and non-hidden structural fields.

        Args:
            tag: Lowercase element name supplied by the standard HTMLParser callback.
            attrs: Decoded attribute names and optional values supplied by HTMLParser.
        """

        self.tags += 1
        token = self.get_starttag_text()

        if self.tags > _MAX_TAGS or self.closed_root or token is None or (
            len(token.encode("utf-8")) > _MAX_TOKEN_BYTES
            or tag not in _CHILDREN and tag not in _VOID
            or len(attrs) > _MAX_ATTRIBUTES
        ):
            raise UnsupportedDirectoryIndex

        attributes: dict[str, str] = {}

        for name, value in attrs:
            if name in attributes or name not in _ATTRIBUTES or (
                _ATTRIBUTE_NAME.fullmatch(name) is None or value is None
                or len(value.encode("utf-8")) > _MAX_ENTRY_BYTES
                or any(ord(character) < 32 for character in value)
                or name in {"class", "id"} and "hidden" in value.lower().split()
            ):
                raise UnsupportedDirectoryIndex

            attributes[name] = value

        if not self.stack:
            if tag != "html" or "html" in self.seen:
                raise UnsupportedDirectoryIndex

        elif tag not in _CHILDREN[self.stack[-1]]:
            raise UnsupportedDirectoryIndex

        if tag in {"html", "head", "title", "body", "h1"}:
            if tag in self.seen:
                raise UnsupportedDirectoryIndex

            self.seen.add(tag)

        if tag == "head" and "body" in self.seen or tag == "body" and (
            "head" not in self.seen or "title" not in self.seen
        ):
            raise UnsupportedDirectoryIndex

        if tag in _CONTAINERS:
            if self.container_seen or self.stack != ["html", "body"] or "h1" not in self.seen:
                raise UnsupportedDirectoryIndex

            self.container_seen = self.container_open = True

        if tag == "a":
            if not self.container_open or "href" not in attributes:
                raise UnsupportedDirectoryIndex

            href = attributes["href"]
            self.entry_label = None

            if href != "../" and _SORT.fullmatch(href) is None:
                if _ENTRY.fullmatch(href) is None or re.search(r"%(?![0-9A-Fa-f]{2})", href):
                    raise UnsupportedDirectoryIndex

                label = unquote(href, encoding="utf-8", errors="strict").removesuffix("/")

                if label in {".", ".."} or not label or any(
                    character in "/\\<>?#:" or ord(character) < 32 for character in label
                ):
                    raise UnsupportedDirectoryIndex

                self.entry_label = label + ("/" if href.endswith("/") else "")

            self.anchor_text = []
            self.anchor_image = False

        if tag == "img" and self.stack[-1] == "a":
            self.anchor_image = True

        if tag not in _VOID:
            if len(self.stack) >= _MAX_DEPTH:
                raise UnsupportedDirectoryIndex

            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Admit XML-style spelling only for HTML void tags without inventing closure.

        Args:
            tag: Parsed self-closing element name supplied by HTMLParser.
            attrs: Decoded attribute names and optional values supplied by HTMLParser.
        """

        if tag not in _VOID:
            raise UnsupportedDirectoryIndex

        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        """Require exact stack closure before retaining one related basename entry count.

        Args:
            tag: Lowercase closing element name supplied by HTMLParser.
        """

        if not self.stack or self.stack[-1] != tag:
            raise UnsupportedDirectoryIndex

        if tag == "a" and self.entry_label is not None:
            label = "".join(self.anchor_text).strip()

            if label == self.entry_label:
                self.entries += 1

            elif label or not self.anchor_image:
                raise UnsupportedDirectoryIndex

            if self.entries > _MAX_ENTRIES:
                raise UnsupportedDirectoryIndex

        if tag in _CONTAINERS:
            self.container_open = False

        self.stack.pop()

        if tag == "html":
            self.closed_root = True

    def handle_data(self, data: str) -> None:
        """Inspect visible headings and one entry label; escaped markup is never a tag.

        Args:
            data: Transient parsed character data supplied by HTMLParser.
        """

        if "<" in data or ">" in data or not self.stack and data.strip():
            raise UnsupportedDirectoryIndex

        if not self.stack:
            return

        parent = self.stack[-1]

        if parent in {"html", "head", "ul", "table", "thead", "tbody", "tr"} and data.strip():
            raise UnsupportedDirectoryIndex

        if parent == "title":
            self.title.append(data)

        elif parent == "h1":
            self.heading.append(data)

        elif parent == "a":
            self.anchor_text.append(data)

    def handle_comment(self, data: str) -> None:
        """Ignore bounded comment contents rather than discovering fictitious tags or links.

        Args:
            data: Transient comment contents supplied by HTMLParser.
        """

        if len(data.encode("utf-8")) + 7 > _MAX_TOKEN_BYTES:
            raise UnsupportedDirectoryIndex

    def handle_decl(self, decl: str) -> None:
        """Allow one plain HTML doctype before the root, with no internal/external declarations.

        Args:
            decl: Original declaration contents supplied by HTMLParser.
        """

        if self.declaration or self.stack or self.closed_root or decl.lower() != "doctype html":
            raise UnsupportedDirectoryIndex

        self.declaration = True

    def handle_pi(self, data: str) -> None:
        """Reject processing instructions outside the selected inert HTML grammar.

        Args:
            data: Transient processing-instruction contents supplied by HTMLParser.
        """

        raise UnsupportedDirectoryIndex

    def unknown_decl(self, data: str) -> None:
        """Reject non-HTML declarations instead of interpreting an alternate markup language.

        Args:
            data: Transient unrecognized declaration contents supplied by HTMLParser.
        """

        raise UnsupportedDirectoryIndex

    def Matches(self) -> bool:
        """Return only the fully closed related-heading and nonempty entry-structure predicate.

        Returns:
            Whether the complete finite tree has related headings and one or more entries.
        """

        title = " ".join("".join(self.title).split())
        heading = " ".join("".join(self.heading).split())

        return (self.closed_root and not self.stack and self.container_seen
            and self.seen == {"html", "head", "title", "body", "h1"}
            and _HEADING.fullmatch(title) is not None and title == heading
            and 1 <= self.entries <= _MAX_ENTRIES)


def SupportedDirectoryIndex(body: bytes) -> bool:
    """Recognize a complete finite classic index, without asserting file access or following links.

    Args:
        body: Complete transient response bytes, limited to 4096 bytes and strict UTF-8.

    Returns:
        Whether closed matching index headings and relative basename-labelled entries exist.
        False means this finite structure was not established, never that a site is secure.
    """

    if type(body) is not bytes or not 1 <= len(body) <= MAX_DIRECTORY_INDEX_BODY_BYTES:
        return False

    try:
        text = body.decode("utf-8", errors="strict")

        if any(ord(character) < 32 and character not in "\r\n\t" for character in text):
            return False

        if not CompleteMarkup(text):
            return False

        parser = DirectoryIndexParser()
        parser.feed(text)

        if parser.rawdata:
            return False

        parser.close()

        return parser.Matches()

    except (UnicodeError, UnsupportedDirectoryIndex, AssertionError):
        return False
