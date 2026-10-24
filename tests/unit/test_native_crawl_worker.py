# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure and mocked finite crawl transport tests, without sockets, processes or target oracles."""

import hashlib
import io
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_crawl_worker as worker
from fuzzy1337.adapters.native_crawl import (
    EXCLUSION_CODES,
    NATIVE_CRAWL_PROFILE,
    BuildCrawlInput,
    CanonicalRecord,
    CrawlRequestBytes,
    EncodeCrawlInput,
    NativeCrawlRecordError,
    ParseCrawlRecord,
)

URL = "http://127.0.0.1:8080/index"
LEAF = "http://127.0.0.1:8080/leaf"


def Input(url=URL, selected=None, **limits):
    """Build explicitly selected unit metadata without scope or permission claims."""

    return BuildCrawlInput("unit", url, url,
                          (URL, LEAF) if selected is None else selected, **limits)


def Wire(body=b"", status=200, media=b"text/html", extra=b""):
    """Handwrite finite raw response framing for unit admission, not functional scanner truth."""

    return (f"HTTP/1.1 {status} Unit\r\nContent-Length: {len(body)}\r\n".encode()
            + b"Content-Type: " + media + b"\r\n" + extra + b"\r\n" + body)


class FakeSocket:
    """Script bounded reads and observe exact request, peer verification and closure."""

    def __init__(self, parts, peer=("127.0.0.1", 8080)):
        """Copy finite scripted data without opening a descriptor."""

        self.parts = list(parts)
        self.peer = peer
        self.sent = []
        self.timeouts = []
        self.connections = []
        self.closed = False

    def Connect(self, destination):
        """Observe one literal connection selection without network access."""

        self.connections.append(destination)

    def GetPeerName(self):
        """Expose a scripted actual socket peer."""

        return self.peer

    def SetTimeout(self, timeout):
        """Observe remaining-time updates without renewing the request deadline."""

        self.timeouts.append(timeout)

    def SendAll(self, value):
        """Record actual request bytes supplied to the scripted send."""

        self.sent.append(value)

    def Receive(self, maximum):
        """Return at most the requested bytes from the next bounded scripted read."""

        if not self.parts:
            return b""

        value = self.parts.pop(0)

        if len(value) > maximum:
            self.parts.insert(0, value[maximum:])

        return value[:maximum]

    def Close(self):
        """Observe release on every success, refusal or exception."""

        self.closed = True

    connect = Connect
    getpeername = GetPeerName
    settimeout = SetTimeout
    sendall = SendAll
    recv = Receive
    close = Close


def Transport(monkeypatch, parts, peer=("127.0.0.1", 8080)):
    """Replace only the worker's socket namespace with a descriptor-free scripted factory."""

    connection = FakeSocket(parts, peer)
    families = []

    def Socket(family, kind):
        """Record exactly one literal-family socket request without using the socket module."""

        families.append((family, kind))

        return connection

    monkeypatch.setattr(worker, "socket", SimpleNamespace(
        AF_INET=4, AF_INET6=6, SOCK_STREAM=1, socket=Socket))

    return connection, families


@pytest.mark.parametrize("body,status,media,outcome", [
    (b"", 200, b"text/html", "html"),
    (b"\xffopaque", 200, b"text/plain", "non-html"),
    (b"\xffopaque", 200, b"application/octet-stream", "non-html"),
    (b'<a href="/leaf">unparsed</a>', 404, b"text/html", "client-error"),
])
def test_MockedCompleteResponsesUseExactlyOneRequestAndClose(
    monkeypatch, body, status, media, outcome,
):
    """Only complete admitted response metadata survives; terminal bodies never become links."""

    raw = Wire(body, status, media, b"Set-Cookie: unit-private-cookie\r\n")
    transport, families = Transport(monkeypatch, [raw[:13], raw[13:]])
    record = worker.Probe(EncodeCrawlInput(Input()))
    assert record["outcome"] == outcome, "Complete response outcome was misclassified."
    assert ParseCrawlRecord(CanonicalRecord(record), Input()) == record, (
        "The real producer metadata must pass independent original-record admission."
    )
    assert transport.sent == [CrawlRequestBytes(URL)], "The worker retried or rewrote its GET."
    assert transport.connections == [("127.0.0.1", 8080)] and families == [(4, 1)], (
        "The worker attempted an alternate address, family or connection."
    )
    assert transport.closed and record["frontier"]["anchor_count"] == 0, (
        "Terminal completion leaked a socket or incorrectly interpreted a terminal body."
    )
    assert b"unit-private-cookie" not in CanonicalRecord(record), "Raw header values leaked."
    assert record["response"]["body_sha256"] == hashlib.sha256(body).hexdigest(), (
        "Complete admitted body attribution changed."
    )


def test_LexicalFilteringEmitsOnlyAdmittedUrlsAndCompleteOrdinals(monkeypatch):
    """Pure lexical semantics discard raw credential/query/off-origin and unselected hrefs."""

    body = (b'<a href="/leaf">one</a><a href="/leaf#private-fragment">two</a>'
        b'<!-- <a href="/hidden">comment</a> -->'
        b'<script>"<a href=\'/hidden\'>script</a>"</script>'
        b'<a href="/not-selected-sensitive">unselected</a>'
        b'<a href="http://user:private-password@127.0.0.1:8080/leaf">credentials</a>'
        b'<a href="/leaf?token=private-query">query</a>'
        b'<a href="http://example.test/private-off-origin">foreign</a>'
        b'<a href="#private-only">fragment</a><a>absent</a><a href="/index">source</a>')
    transport, _ = Transport(monkeypatch, [Wire(body)])
    record = worker.Probe(EncodeCrawlInput(Input()))
    frontier = record["frontier"]
    assert len(frontier["entries"]) == 1 and frontier["entries"][0]["url"] == LEAF, (
        "Only explicitly selected candidates may leave the worker."
    )
    assert frontier["entries"][0]["ordinals"] == [1, 2], (
        "Duplicate selected links lost their complete one-based source occurrences."
    )
    assert frontier["anchor_count"] == 9 and sum(frontier["exclusion_counts"].values()) == 7, (
        "Comment/script text must not contribute anchors, and every admitted slot needs accounting."
    )
    assert frontier["exclusion_counts"]["not-admitted"] == 1, (
        "Unselected same-origin links must remain count-only."
    )
    raw = CanonicalRecord(record)

    for marker in (b"not-selected-sensitive", b"private-password", b"private-query",
                   b"private-off-origin", b"private-fragment", b"private-only", b"hidden"):
        assert marker not in raw, "Rejected href or ignored source text leaked into the record."

    assert transport.closed, "Lexical completion leaked its transport."


@pytest.mark.parametrize("peer", [("127.0.0.2", 8080), ("127.0.0.1", 8081)])
def test_PeerAddressAndPortAreVerifiedBeforeAnyRequest(monkeypatch, peer):
    """A literal address match alone cannot substitute a different connected peer port."""

    transport, _ = Transport(monkeypatch, [Wire()], peer)

    with pytest.raises(worker.CrawlRefusal, match="protocol"):
        worker.Probe(EncodeCrawlInput(Input()))

    assert not transport.sent and transport.closed, "Peer refusal sent bytes or leaked a socket."


def test_Ipv6KeepsExactSelectedPeerAndBracketedHost(monkeypatch):
    """IPv6 uses its fixed literal family without a resolver or alternate spelling."""

    url = "http://[::1]:8080/index"
    transport, families = Transport(monkeypatch, [Wire()], ("::1", 8080, 0, 0))
    record = worker.Probe(EncodeCrawlInput(Input(url, (url,))))
    assert families == [(6, 1)] and transport.connections == [("::1", 8080)], (
        "IPv6 selected a different literal family or destination."
    )
    assert record["source"]["address"] == "::1" and b"Host: [::1]:8080\r\n" in transport.sent[0], (
        "IPv6 source identity or exact request Host was rewritten."
    )


@pytest.mark.parametrize("raw,code", [
    (b"", "protocol"), (b"HTTP/1.1 200 OK\n\n", "protocol"),
    (b"HTTP/2 200 Unit\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n", "protocol"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 00\r\nContent-Type: text/html\r\n\r\n", "protocol"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "protocol"),
    (Wire(extra=b"content-length: 0\r\n"), "protocol"),
    (Wire(extra=b" folded\r\n"), "protocol"),
    (Wire(extra=b"X: \xff\r\n"), "protocol"),
    (Wire(extra=b"X : value\r\n"), "protocol"),
    (Wire(extra=b"Content-Encoding: identity\r\n"), "response-policy"),
    (Wire(extra=b"Transfer-Encoding: chunked\r\n"), "response-policy"),
    (Wire(status=100), "response-policy"), (Wire(status=204), "response-policy"),
    (Wire(status=302, extra=b"Location: /private\r\n"), "response-policy"),
    (Wire(status=500), "response-policy"), (Wire(media=b"application/json"), "response-policy"),
    (Wire(media=b"text/plain; charset=utf-8"), "response-policy"),
    (Wire(extra=b"X: " + b"x" * 4096 + b"\r\n"), "output-limit"),
    (Wire(extra=b"".join(f"X{index}: v\r\n".encode() for index in range(63))), "output-limit"),
    (Wire().replace(b"Content-Length: 0", b"Content-Length: 16385"), "output-limit"),
    (b"x" * 16385 + b"\r\n\r\n", "output-limit"),
], ids=lambda value: value if isinstance(value, str) else f"wire-{len(value)}")
def test_FiniteHeaderGrammarRefusesWithoutBodyFacts(raw, code):
    """Unsupported wire/status/media never produces a successful empty or negative response."""

    with pytest.raises(worker.CrawlRefusal, match=code):
        worker.Headers(raw, 16384)


def test_HeaderCaseAndHtmlCharsetUseTheExistingFiniteOwsGrammar():
    """Only the reviewed HTML optional UTF-8 spelling widens the finite media categories."""

    headers = worker.Headers(Wire(media=b"TEXT/HTML \t;\t CHARSET = UTF-8"), 16384)
    assert headers["media_type"] == "text/html", "Admitted HTML media was not normalized."
    assert headers["header_fields"] == 2, "Header counting included unobserved fields."


def test_FullMarkupWorkLimitRefusesBeforeAnyMetadataPublication():
    """A body within the hard byte ceiling can still exceed the existing lexical-work budget."""

    with pytest.raises(worker.CrawlRefusal, match="output-limit"):
        worker.Frontier(b"<i>" * 8193, Input(max_body_bytes=65536))


@pytest.mark.parametrize("parts", [[b""], [Wire(b"unit")[:-1]], [Wire() + b"x"],
                                    [Wire(), b"trailing"], [b"x" * 16384]])
def test_IncompleteAndTrailingResponsesAlwaysClose(monkeypatch, parts):
    """Complete timely EOF is mandatory, including after a zero Content-Length body."""

    transport, _ = Transport(monkeypatch, parts)

    with pytest.raises(worker.CrawlRefusal):
        worker.Probe(EncodeCrawlInput(Input()))

    assert transport.closed, "A failed framing path leaked its socket."


@pytest.mark.parametrize("body,code", [
    (b"\xffprivate-invalid-utf8", "html-policy"),
    (b"\xef\xbb\xbfprivate-bom", "html-policy"),
    (b'<a href="/leaf">valid prefix</a><base href="/private">', "html-policy"),
    (b"<!--private-incomplete", "html-policy"),
    (b"<a>" * 1025, "output-limit"),
    (b"<!--" + b"x" * 4090 + b"-->", "output-limit"),
])
def test_UnadmittedHtmlEmitsOnlyTheClosedFailureWithoutDigest(monkeypatch, capsys, body, code):
    """Invalid suffixes and parser limits cannot retain a prefix or rejected body digest."""

    transport, _ = Transport(monkeypatch, [Wire(body)])
    assert worker.Main([EncodeCrawlInput(Input()).decode()]) == 2, "Invalid HTML became success."
    captured = capsys.readouterr()
    assert captured.out.encode() == CanonicalRecord(worker.Refused(code)), (
        "A refusal retained body metadata, partial links or diagnostic source content."
    )
    assert not captured.err and transport.closed, "Refusal leaked diagnostics or its transport."


def test_ProgressNeverRenewsTheOriginalRequestDeadline(monkeypatch, capsys):
    """Partial response headers consume the same finite request deadline."""

    transport, _ = Transport(monkeypatch, [b"HTTP/1.1 200", b" more"])
    readings = iter((0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 1.1))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: next(readings)))
    code = worker.Main([EncodeCrawlInput(Input(request_timeout_ms=1000)).decode()])
    assert code == 2 and capsys.readouterr().out.encode() == CanonicalRecord(
        worker.Refused("timeout")), "Progress reset the deadline or emitted partial success."
    assert transport.timeouts == pytest.approx((0.9, 0.7, 0.5)) and transport.closed, (
        "Remaining time was renewed or timeout cleanup was skipped."
    )


@pytest.mark.parametrize("arguments", [[], ["{}", "extra"], ["private-invalid"], ["\ud800"],
                                      ["x" * 24577]])
def test_InvalidInputRefusesBeforeAnySocket(monkeypatch, capsys, arguments):
    """No argument alias, caller flag, malformed JSON or oversized input reaches transport."""

    def ForbiddenSocket(*_arguments):
        """Make any unexpected socket creation an observable unit failure."""

        pytest.fail("Invalid crawl input attempted a socket")

    monkeypatch.setattr(worker, "socket", SimpleNamespace(socket=ForbiddenSocket))
    assert worker.Main(arguments) == 2, "Invalid input did not emit a refusal exit."
    captured = capsys.readouterr()
    assert captured.out.encode() == CanonicalRecord(worker.Refused("input")) and not captured.err, (
        "Invalid input leaked its raw value or diagnostic text."
    )


@pytest.mark.parametrize("error,code", [(OSError("private"), "connection"),
    (TimeoutError("private"), "timeout"), (RuntimeError("private"), "internal"),
    (worker.CrawlRefusal("output-limit"), "output-limit")])
def test_MainSanitizesFailuresAndUsesBinaryCanonicalOutput(monkeypatch, error, code):
    """Exceptions never enter output and text newline translation cannot alter binary JSON."""

    def Fail(_raw):
        """Inject a bounded deterministic failure without touching the transport boundary."""

        raise error

    output = io.BytesIO()
    stream = io.TextIOWrapper(output, encoding="utf-8", newline="\r\n")
    monkeypatch.setattr(worker, "sys", SimpleNamespace(stdout=stream))
    monkeypatch.setattr(worker, "Probe", Fail)
    assert worker.Main([EncodeCrawlInput(Input()).decode()]) == 2, "Failure became success."
    assert output.getvalue() == CanonicalRecord(worker.Refused(code)), (
        "Binary canonical output changed or retained private exception text."
    )


def test_MainUsesTheOriginalProcessArgumentAndAdmitsItsActualMockedReport(monkeypatch, capsys):
    """Main and Probe share exact input joins without a separate permissive output path."""

    transport, _ = Transport(monkeypatch, [Wire()])
    argument = EncodeCrawlInput(Input()).decode()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(
        argv=["worker", argument], stdout=worker.sys.stdout))
    assert worker.Main() == 0, "An actual mocked complete worker path failed admission."
    captured = capsys.readouterr()
    parsed = ParseCrawlRecord(captured.out.encode(), Input())
    assert parsed["outcome"] == "html" and parsed["profile"] == NATIVE_CRAWL_PROFILE, (
        "Main lost the actual complete record or original profile binding."
    )
    assert not captured.err and transport.closed, "Success leaked diagnostics or transport."


def test_UnexpectedProducedRecordsAndCodesCannotReachOutput(monkeypatch, capsys):
    """Even internal producer corruption becomes a fixed refusal rather than raw metadata."""

    monkeypatch.setattr(worker, "Probe", lambda _raw: {"body": "private-corrupt-output"})
    assert worker.Main([EncodeCrawlInput(Input()).decode()]) == 2, (
        "Corrupt metadata became success."
    )
    assert capsys.readouterr().out.encode() == CanonicalRecord(worker.Refused("internal")), (
        "Unadmitted internal output bypassed final record verification."
    )

    with pytest.raises(NativeCrawlRecordError):
        worker.Refused("private-unknown-code")

    with pytest.raises(NativeCrawlRecordError):
        worker.CrawlRefusal("private-unknown-code")

    assert set(worker.Refused("internal")) == {"schema_version", "profile", "outcome", "error"}, (
        "The closed refusal shape widened."
    )
    assert len(EXCLUSION_CODES) == 10, "Closed lexical rejection categories changed."
