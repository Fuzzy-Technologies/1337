# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent complete-document oracle for conservative legacy exposition detection."""

import pytest

from fuzzy1337.adapters.native_web import MatchesPrometheus
from fuzzy1337.adapters.prometheus_exposition import (
    MAX_PROMETHEUS_BODY_BYTES,
    MAX_PROMETHEUS_LINE_BYTES,
    SupportedExposition,
)

DOCUMENT = b"# HELP active_jobs Current active jobs\n# TYPE active_jobs gauge\nactive_jobs 3\n"


@pytest.mark.parametrize("body", [
    DOCUMENT,
    b"# TYPE active_jobs gauge\n# HELP active_jobs Current active jobs\nactive_jobs 3\n",
    DOCUMENT + b"unrelated_untyped_sample 0.5 1234\n",
    b"# HELP calls_total Calls\\ncount\n# TYPE calls_total counter\n"
    b'calls_total{route="a}b",message="quote\\\" and slash\\\\ and newline\\n"} +Inf\n',
    b"# HELP readings Values\n# TYPE readings untyped\n"
    b"readings NaN\nreadings -Inf\nreadings +1.5e-3 -123\n",
    b"# HELP latency_seconds Request latency\n# TYPE latency_seconds histogram\n"
    b'latency_seconds_bucket{le="0.1"} 1\nlatency_seconds_bucket{le="+Inf"} 2\n'
    b"latency_seconds_sum 0.3\nlatency_seconds_count 2\n",
    b"# TYPE work_seconds summary\n# HELP work_seconds Work latency\n"
    b'work_seconds{quantile="0.5"} 0.1\nwork_seconds_sum 0.2\nwork_seconds_count 2\n',
    b"\t # HELP active_jobs Current active jobs\n# TYPE active_jobs gauge\n"
    b'active_jobs { } 3\n',
    b"# A comment\n\n" + DOCUMENT + b'active_jobs{city="\xc3\xa9",} .5\n',
])
def test_CompleteSupportedFamiliesMatch(body: bytes) -> None:
    """Generic families allow both metadata orders and explicit histogram/summary suffixes."""

    assert SupportedExposition(body), "A supported complete legacy family was refused."


@pytest.mark.parametrize("body", [
    b"", DOCUMENT[:-1], DOCUMENT + b"trailing junk\n", b"<html>" + DOCUMENT + b"</html>\n",
    DOCUMENT + b"\xff\n", DOCUMENT + b"# bad\x00comment\n", DOCUMENT.replace(b"\n", b"\r\n"),
    b"# HELP a Description\n# TYPE b gauge\nb 1\n",
    b"# HELP a Description\n# TYPE a gauge\nb 1\n",
    b"# HELP a Description\na 1\n", b"# TYPE a gauge\na 1\n", b"a 1\n",
    DOCUMENT + b"# HELP active_jobs Duplicate\n", DOCUMENT + b"# TYPE active_jobs gauge\n",
    b"# HELP a Description\n# HELP a Duplicate\n# TYPE a gauge\na 1\n",
    b"# TYPE a gauge\n# TYPE a gauge\n# HELP a Description\na 1\n",
    b"a 1\n# HELP a Late description\n# TYPE a gauge\na 2\n",
    DOCUMENT + b'active_jobs{x="a",x="b"} 1\n',
    DOCUMENT + b'active_jobs{x="bad\\t"} 1\n',
    DOCUMENT + b'active_jobs{x="unterminated} 1\n',
    DOCUMENT + b'active_jobs{x="x" junk} 1\n',
    DOCUMENT + b'active_jobs{x="x" y="y"} 1\n',
    DOCUMENT + b'active_jobs{x="x",,} 1\n',
    DOCUMENT + b'active_jobs{1x="x"} 1\n',
    DOCUMENT + b'active_jobs{ x "x"} 1\n',
    DOCUMENT + b'active_jobs{x=x} 1\n',
    DOCUMENT + b'active_jobs{x="a"\n',
    DOCUMENT + b'active_jobs{"x"="a"} 1\n',
    DOCUMENT + b"active_jobs +NaN\n", DOCUMENT + b"active_jobs 1.2.3\n",
    DOCUMENT + b"active_jobs 1 trailing\n", DOCUMENT + b"active_jobs 1 12.3\n",
    DOCUMENT + b"active_jobs 1 # {trace_id=1} 2\n", DOCUMENT + b"# EOF\n",
    DOCUMENT + b"# UNIT active_jobs jobs\n", DOCUMENT + b'"modern.name" 1\n',
    b"# HELP a Unsupported\\q\n# TYPE a gauge\na 1\n",
    b"# HELP a Description\n# TYPE a unknown\na 1\n",
    b"# HELP a Description\n# TYPE a gauge extra\na 1\n",
    b"# HELP\n" + DOCUMENT, b"# TYPE a\n" + DOCUMENT,
    b"# HELP a Description\n# TYPE a histogram\na 1\n",
    b"# HELP a Description\n# TYPE a histogram\na_bucket 1\n",
    b"# HELP a Description\n# TYPE a summary\na 1\n",
    b'a_bucket{le="1"} 1\n# HELP a Description\n# TYPE a histogram\na_count 1\n',
    b'a_sum 1\n# HELP a Description\n# TYPE a summary\na_count 1\n',
    DOCUMENT + b"#" + b"x" * MAX_PROMETHEUS_LINE_BYTES + b"\n",
    DOCUMENT + b"# padding\n" * (MAX_PROMETHEUS_BODY_BYTES // 10),
])
def test_InvalidIncompleteOrUnassociatedDocumentsDoNotMatch(body: bytes) -> None:
    """Embedded fragments, malformed labels and unrelated declarations never establish exposure."""

    assert not SupportedExposition(body), "An unsupported or incomplete document matched."


@pytest.mark.parametrize("status,media,expected", [
    (200, "text/plain", True), (True, "text/plain", False), (403, "text/plain", False),
    (302, "text/plain", False), (200, "application/octet-stream", False), (200, "other", False),
])
def test_HttpPredicateRequiresActualSuccessfulPlainResponse(status, media, expected) -> None:
    """Valid bytes cannot override the actual status or content-type category."""

    assert MatchesPrometheus(status, media, DOCUMENT) is expected, "HTTP predicate drifted."


def test_ExactDecodedBodyLimitAcceptsACompleteBoundedDocument() -> None:
    """The byte cap is inclusive and independent from the per-line bound."""

    body = DOCUMENT

    while len(body) + 1002 < MAX_PROMETHEUS_BODY_BYTES:
        body += b"#" + b"x" * 1000 + b"\n"

    body += b"#" + b"x" * (MAX_PROMETHEUS_BODY_BYTES - len(body) - 2) + b"\n"
    assert len(body) == MAX_PROMETHEUS_BODY_BYTES, "The independent fixture missed the exact cap."
    assert SupportedExposition(body), "The inclusive 256 KiB document bound changed."
    assert not SupportedExposition(body + b"\n"), "A complete oversized document was admitted."
