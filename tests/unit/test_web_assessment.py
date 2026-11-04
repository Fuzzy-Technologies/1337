# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep a native lexical observation within the admitted HTML probe profile."""

import pytest

from fuzzy1337.adapters.web_assessment import MatchesHtmlReflection

MARKER = b"<fuzzy1337-probe>owned</fuzzy1337-probe>"


@pytest.mark.parametrize(("status", "media", "body", "matched"), [
    (200, "text/html", b"<main>\n" + MARKER + b"</main>", True),
    (200, "text/html", b"<template/>" + MARKER + b"</template>" + MARKER, True),
    (200, "text/html", b"<!--" + MARKER + b"-->", False),
    (200, "text/html", b"<textarea>" + MARKER + b"</textarea>", False),
    (200, "text/html", b"<plaintext>" + MARKER + b"</plaintext>" + MARKER, False),
    (200, "text/html", b"<script>" + MARKER + b"</script>", False),
    (200, "text/html", b"<script><!--<ScRiPt\n></script>" + MARKER + b"</script>", False),
    (200, "text/html", b"<script/><!--<script></script>" + MARKER + b"</script>", False),
    (200, "text/html", b"<script><!-- ordinary text --></script>" + MARKER, True),
    (200, "text/html", b"<!-- <script><!--<script></script> -->" + MARKER, True),
    (200, "text/html", b"<frameset><frame>" + MARKER + b"</frameset>", False),
    (200, "text/html", b"<frameset><frame></frameset>" + MARKER, False),
    (200, "text/html", b"<frameset/>" + MARKER, False),
    (200, "text/html", b"<!-- <frameset> -->" + MARKER, True),
    (200, "text/html", b"<main title='<frameset>'>" + MARKER + b"</main>", True),
    (200, "text/html", b"<xmp/>" + MARKER, False),
    (200, "text/html", b"<div title='" + MARKER + b"'>example</div>", False),
    (200, "text/html", b"\xff" + MARKER, False),
    (200, "text/html", MARKER + MARKER, False),
    (200, "text/html", b"<![INVALID[anything]]>" + MARKER, False),
    (200, "text/plain", MARKER, False),
    (404, "text/html", MARKER, False),
])
def test_OnlyOneExactOwnedMarkerInElementContentMatches(status, media, body, matched):
    """Ignore escaped, inert, invalid, ambiguous and incompatible response content."""

    assert MatchesHtmlReflection(status, media, body) is matched, (
        "A lexical match requires the exact unique probe in the declared response context."
    )
