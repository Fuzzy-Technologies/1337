# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Interpret finite HTML observations without inferring browser execution."""

from __future__ import annotations

import re
from html.parser import HTMLParser

REFLECTION_TAG = "fuzzy1337-probe"
REFLECTION_MARKER = f"<{REFLECTION_TAG}>owned</{REFLECTION_TAG}>"
_INERT = frozenset({
    "iframe", "math", "noembed", "noframes", "noscript", "plaintext", "script", "select",
    "style", "svg", "template", "textarea", "title", "xmp",
})
_AMBIGUOUS_SCRIPT_DATA = re.compile(r"<!--.*<script[\t\n\f\r />]",
                                    re.ASCII | re.IGNORECASE | re.DOTALL)


class ReflectionParser(HTMLParser):
    """Recognize the exact inert probe element in ordinary HTML element content."""

    def __init__(self, text: str) -> None:
        """Retain physical source lines for exact marker matching at token offsets.

        Args:
            text: Complete admitted UTF-8 response decoded by the caller.
        """

        super().__init__(convert_charrefs=False)
        self.lines = text.split("\n")
        self.inert: list[str] = []
        self.matches = 0
        self.unsupported = False

    # HTMLParser dispatches through these standard-library callback names.
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Count complete raw markers outside excluded lexical contexts.

        Args:
            tag: Normalized HTML start-tag name reported by the parser.
            attrs: Parsed attributes. The raw marker spelling determines eligibility.
        """

        if tag in _INERT:
            self.inert.append(tag)

        elif tag == REFLECTION_TAG and not self.inert:
            line, column = self.getpos()

            if self.lines[line - 1].startswith(REFLECTION_MARKER, column):
                self.matches += 1

    def _HandleData(self, data: str) -> None:
        """Exclude script data whose closing boundary the lexical parser cannot establish.

        Args:
            data: Text token reported by the standard-library parser.
        """

        if self.inert and self.inert[-1] == "script" and _AMBIGUOUS_SCRIPT_DATA.search(data):
            self.unsupported = True

    handle_data = _HandleData

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Treat a trailing slash conservatively for inert HTML elements.

        Args:
            tag: Normalized name of the start token with a trailing slash.
            attrs: Parsed attributes, which cannot close an inert context.
        """

        if tag in _INERT:
            self.inert.append(tag)

        if tag == "script":
            # HTML ignores the slash, while HTMLParser does not enter script-data mode.
            self.unsupported = True

    def handle_endtag(self, tag: str) -> None:
        """Close the innermost inert context except terminal plaintext.

        Args:
            tag: Normalized closing-tag name reported by the parser.
        """

        if self.inert and self.inert[-1] == tag and tag != "plaintext":
            self.inert.pop()


def MatchesHtmlReflection(status: int, mediaType: str, body: bytes) -> bool:
    """Recognize one lexical element from a complete bounded UTF-8 HTML response.

    Args:
        status: Actual complete HTTP response status.
        mediaType: Normalized response media category.
        body: Complete bounded transient response body.

    Returns:
        Whether exactly one supported inert marker occupies ordinary HTML element content.
    """

    if (status != 200 or mediaType != "text/html" or b"<![" in body
        or REFLECTION_MARKER.encode() not in body):
        return False

    try:
        text = body.decode("utf-8")
        parser = ReflectionParser(text)
        parser.feed(text)
        parser.close()

    except (UnicodeError, ValueError, AssertionError):
        return False

    return not parser.unsupported and parser.matches == 1
