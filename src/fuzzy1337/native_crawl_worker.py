# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""One fixed loopback GET with transient content and selected-only canonical metadata."""

from __future__ import annotations

import hashlib
import re
import socket
import sys
import time
from collections.abc import Sequence
from typing import Literal, TypedDict

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.native_crawl import (
    ERROR_CODES,
    EXCLUSION_CODES,
    MAX_ANCHORS,
    MAX_HEADER_BYTES,
    MAX_HEADER_FIELDS,
    MAX_INPUT_BYTES,
    MAX_LINE_BYTES,
    NATIVE_CRAWL_PROFILE,
    CanonicalRecord,
    CrawlEndpoint,
    CrawlEntry,
    CrawlFrontier,
    CrawlInput,
    CrawlObservedRecord,
    CrawlRecord,
    CrawlRefusedRecord,
    CrawlRequestBytes,
    CrawlTemplate,
    NativeCrawlRecordError,
    ParseCrawlInput,
    ParseCrawlRecord,
)
from fuzzy1337.captured_web import Candidate, ParseAnchors

_STATUS = re.compile(rb"(HTTP/1\.[01]) ([0-9]{3}) [\x20-\x7e]*")
_FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(rb"(?:0|[1-9][0-9]*)")
_HTML = re.compile(rb"text/html(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*utf-8)?", re.IGNORECASE)
_LEXICAL_LIMITS = frozenset({
    "captured web anchor count exceeds the admission budget",
    "captured web markup token exceeds the byte budget",
    "captured web markup work exceeds the admission budget",
})


class CrawlHeaders(TypedDict):
    """Admitted transient header interpretation, without retained arbitrary values."""

    http_version: str
    status: int
    media_type: str
    header_bytes: int
    header_fields: int
    content_length: int


class CrawlRefusal(Exception):
    """A closed safe worker failure, never a diagnostic carrying rejected response material."""

    def __init__(self, error: str) -> None:
        """Bind only a declared fixed refusal classification.

        Args:
            error: Exact packaged failure code.
        """

        if error not in ERROR_CODES:
            raise NativeCrawlRecordError("crawl refusal classification is unsupported")

        self.error = error
        super().__init__(error)


def Remaining(deadline: float) -> float:
    """Debit the same monotonic request deadline without renewing it on progress.

    Args:
        deadline: Original complete request end time.

    Returns:
        Positive remaining request seconds.
    """

    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError

    return remaining


def Headers(raw: bytes, max_body_bytes: int) -> CrawlHeaders:
    """Admit strict finite framing/media/status while discarding arbitrary header values.

    Args:
        raw: Complete original header section including CRLFCRLF.
        max_body_bytes: Already admitted body ceiling from the immutable input.

    Returns:
        Complete normalized framing facts without body facts or raw header values.
    """

    if type(raw) is not bytes or not raw.endswith(b"\r\n\r\n"):
        raise CrawlRefusal("protocol")

    lines = raw[:-4].split(b"\r\n")

    if len(raw) > MAX_HEADER_BYTES or len(lines) > MAX_HEADER_FIELDS + 1 or any(
        len(line) + 2 > MAX_LINE_BYTES for line in lines
    ):
        raise CrawlRefusal("output-limit")

    status_match = _STATUS.fullmatch(lines[0])

    if status_match is None:
        raise CrawlRefusal("protocol")

    status = int(status_match[2])
    values: dict[bytes, bytes] = {}

    for line in lines[1:]:
        name, separator, value = line.partition(b":")

        if not separator or _FIELD.fullmatch(name) is None or name.lower() in values or any(
            byte != 9 and not 32 <= byte <= 126 for byte in value
        ):
            raise CrawlRefusal("protocol")

        values[name.lower()] = value.strip(b" \t")

    if status != 200 and not 400 <= status <= 499 or (
        b"content-encoding" in values or b"transfer-encoding" in values
    ):
        raise CrawlRefusal("response-policy")

    length_text = values.get(b"content-length", b"")
    media = values.get(b"content-type")

    if _LENGTH.fullmatch(length_text) is None or media is None:
        raise CrawlRefusal("protocol")

    length = int(length_text)

    if length > max_body_bytes:
        raise CrawlRefusal("output-limit")

    if _HTML.fullmatch(media) is not None:
        category = "text/html"

    elif media.lower() in {b"text/plain", b"application/octet-stream"}:
        category = media.decode("ascii").lower()

    else:
        raise CrawlRefusal("response-policy")

    return {"http_version": status_match[1].decode("ascii"), "status": status,
        "media_type": category, "header_bytes": len(raw), "header_fields": len(values),
        "content_length": length}


def Frontier(body: bytes, selection: CrawlInput) -> CrawlFrontier:
    """Interpret complete admitted HTML and emit only selected canonical candidate identities.

    Args:
        body: Transient complete body, never stored or echoed.
        selection: Original validated fixed input.

    Returns:
        Full deduplicated selected-only frontier and closed rejection counts.
    """

    try:
        anchors = ParseAnchors(body)

    except ValueError as error:
        code = "output-limit" if error.args and error.args[0] in _LEXICAL_LIMITS else "html-policy"

        raise CrawlRefusal(code) from None

    if len(anchors) > MAX_ANCHORS:
        raise CrawlRefusal("output-limit")

    source = CrawlTemplate(selection["workspace_id"], selection["source_url"])
    target = CrawlEndpoint(selection["source_url"])[0]
    selected = set(selection["selected_urls"])
    counters = dict.fromkeys(EXCLUSION_CODES, 0)
    occurrences: dict[str, list[int]] = {}

    for ordinal, href in enumerate(anchors, 1):
        candidate, reason = Candidate(href, source, target)

        if reason is not None:
            if reason not in counters:
                raise CrawlRefusal("internal")

            counters[reason] += 1

        elif candidate is None:
            raise CrawlRefusal("internal")

        elif candidate.value not in selected:
            counters["not-admitted"] += 1

        else:
            occurrences.setdefault(candidate.value, []).append(ordinal)

    if len(occurrences) > 15:
        raise CrawlRefusal("output-limit")

    entries: list[CrawlEntry] = []

    for url in sorted(occurrences):
        template = CrawlTemplate(selection["workspace_id"], url)
        entries.append({"url": url, "request_reference": template.Reference(),
            "endpoint_reference": template.endpoint.Identity().Reference(),
            "ordinals": occurrences[url]})

    return {"complete": True, "anchor_count": len(anchors), "entries": entries,
            "exclusion_counts": counters}


def Probe(raw_input: bytes) -> CrawlObservedRecord:
    """Own one exact selected literal request, then publish only complete admitted metadata.

    Args:
        raw_input: Sole original canonical input argument, revalidated before creating a socket.

    Returns:
        Complete selected-only record, without original body/header custody or authority.
    """

    selection = ParseCrawlInput(raw_input)
    _, address, port, _, _ = CrawlEndpoint(selection["source_url"])
    request = CrawlRequestBytes(selection["source_url"])
    deadline = time.monotonic() + selection["request_timeout_ms"] / 1000
    family = socket.AF_INET6 if address == "::1" else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)

    try:
        connection.settimeout(Remaining(deadline))
        connection.connect((address, port))
        Remaining(deadline)
        peer = connection.getpeername()

        if peer[0] != address or peer[1] != port:
            raise CrawlRefusal("protocol")

        connection.settimeout(Remaining(deadline))
        connection.sendall(request)
        Remaining(deadline)
        incoming = bytearray()

        while b"\r\n\r\n" not in incoming:
            if len(incoming) >= MAX_HEADER_BYTES:
                raise CrawlRefusal("output-limit")

            connection.settimeout(Remaining(deadline))
            part = connection.recv(min(4096, MAX_HEADER_BYTES - len(incoming)))
            Remaining(deadline)

            if not part:
                raise CrawlRefusal("protocol")

            incoming.extend(part)

        boundary = incoming.index(b"\r\n\r\n") + 4
        headers = Headers(bytes(incoming[:boundary]), selection["max_body_bytes"])
        body = incoming[boundary:]
        length = headers["content_length"]

        if len(body) > length:
            raise CrawlRefusal("protocol")

        while len(body) < length:
            connection.settimeout(Remaining(deadline))
            part = connection.recv(min(4096, length - len(body)))
            Remaining(deadline)

            if not part:
                raise CrawlRefusal("protocol")

            body.extend(part)

        connection.settimeout(Remaining(deadline))
        trailing = connection.recv(1)
        Remaining(deadline)

        if trailing:
            raise CrawlRefusal("protocol")

    finally:
        connection.close()

    outcome: Literal["html", "non-html", "client-error"]

    if headers["status"] >= 400:
        outcome = "client-error"

    elif headers["media_type"] != "text/html":
        outcome = "non-html"

    else:
        outcome = "html"

    frontier = Frontier(bytes(body), selection) if outcome == "html" else CrawlFrontier(
        complete=True, anchor_count=0, entries=[],
        exclusion_counts=dict.fromkeys(EXCLUSION_CODES, 0))
    Remaining(deadline)
    template = CrawlTemplate(selection["workspace_id"], selection["source_url"])
    record: CrawlObservedRecord = {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
        "outcome": outcome, "input_sha256": hashlib.sha256(raw_input).hexdigest(),
        "selected_urls_sha256": hashlib.sha256(
            SerializeContract(selection["selected_urls"]).encode("ascii")).hexdigest(),
        "source": {"url": selection["source_url"], "address": peer[0], "port": peer[1],
            "request_reference": template.Reference(),
            "endpoint_reference": template.endpoint.Identity().Reference(),
            "request_size_bytes": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest()},
        "response": {"http_version": headers["http_version"], "status": headers["status"],
            "media_type": headers["media_type"], "header_bytes": headers["header_bytes"],
            "header_fields": headers["header_fields"], "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest()}, "frontier": frontier}

    try:
        raw = CanonicalRecord(record)

    except NativeCrawlRecordError:
        raise CrawlRefusal("output-limit") from None

    ParseCrawlRecord(raw, selection)
    Remaining(deadline)

    return record


def Refused(error: str) -> CrawlRefusedRecord:
    """Construct the closed refusal without any selected or rejected material.

    Args:
        error: Fixed packaged error code.

    Returns:
        Exact four-field refusal.
    """

    if error not in ERROR_CODES:
        raise NativeCrawlRecordError("crawl refusal classification is unsupported")

    return {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
            "outcome": "refused", "error": error}


def Emit(record: CrawlRecord) -> int:
    """Write exact binary JSON without platform text translation or diagnostics.

    Args:
        record: Already admitted observation or fixed refusal.

    Returns:
        Zero for admitted complete observations, two for closed refusals.
    """

    sys.stdout.buffer.write(CanonicalRecord(record))
    sys.stdout.buffer.flush()

    return 2 if record["outcome"] == "refused" else 0


def Main(argv: Sequence[str] | None = None) -> int:
    """Admit one fixed argument and emit only a complete record or closed safe refusal.

    Args:
        argv: Exactly one canonical ASCII JSON argument, with no flags or caller files.

    Returns:
        Zero for an admitted observation or two for an emitted fixed refusal.
    """

    arguments = sys.argv[1:] if argv is None else argv

    try:
        if len(arguments) != 1 or type(arguments[0]) is not str or (
            not 1 <= len(arguments[0]) <= MAX_INPUT_BYTES
        ):
            raise NativeCrawlRecordError("crawl requires one bounded canonical argument")

        raw_input = arguments[0].encode("ascii")
        selection = ParseCrawlInput(raw_input)

    except Exception:
        return Emit(Refused("input"))

    record: CrawlRecord

    try:
        record = Probe(raw_input)
        ParseCrawlRecord(CanonicalRecord(record), selection)

    except CrawlRefusal as error:
        record = Refused(error.error)

    except TimeoutError:
        record = Refused("timeout")

    except OSError:
        record = Refused("connection")

    except Exception:
        record = Refused("internal")

    return Emit(record)


if __name__ == "__main__":
    raise SystemExit(Main())
