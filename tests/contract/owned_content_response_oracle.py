# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten content-capture source bytes and outcomes; no production parser or catalog truth."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

PRIMARY_PATH = "/research/content"
SECOND_PATH = "/alternate/plain"
SEED_PATH = "/discover/owned"
LONG_PATH = "/" + "p" * 1023
SEGMENT_PATH = "/" + "/".join("s" for _ in range(64))
SOURCE_PATHS = (PRIMARY_PATH, SECOND_PATH, SEED_PATH, LONG_PATH, SEGMENT_PATH)
REJECTED_MARKER = b"OWNED-REJECTED-CONTENT-MARKER-73"
PROFILE = "owned-content-response-capture.v1"
MAX_CASES = 72
SEED_BODY = (b'<!doctype html><html><body><a href="/research/content">content</a>'
    b'<a href="/alternate/plain">plain</a></body></html>')


def BytePart(raw: bytes) -> dict[str, object]:
    """Describe exact independent source bytes with standard encoding and digest primitives."""

    return {"base64": base64.b64encode(raw).decode("ascii"), "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest()}


def RequestBytes(url: str) -> bytes:
    """Write the exact new-profile anonymous GET grammar without a production request helper."""

    parsed = urlsplit(url)

    return (f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n"
        "Accept: text/html, text/plain\r\nAccept-Encoding: identity\r\n"
        "User-Agent: 1337-owned-content-response/1\r\n\r\n").encode("ascii")


def Headers(body: bytes, *extra: bytes, media: bytes = b"text/html; charset=utf-8") -> bytes:
    """Author one finite complete header section; custom originals stay byte-preserving."""

    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media + b"\r\nContent-Length: " +
        str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n" +
        b"".join(line + b"\r\n" for line in extra) + b"\r\n")


def PaddedHeaders(size: int, body_size: int) -> bytes:
    """Freeze exact boundary header sizes using bounded distinct lines, never unbounded padding."""

    if size not in (16384, 16385) or body_size not in (1, 65536):
        raise ValueError("Only the explicit independent boundary headers may be rendered")

    prefix = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
        str(body_size).encode("ascii") + b"\r\nConnection: close\r\n")
    remaining = size - len(prefix) - 2
    fields = []

    for index in range(5):
        if remaining == 0:
            break

        length = min(4096, remaining)

        if 0 < remaining - length < 16:
            length -= 16

        name = f"X-Pad-{index}: ".encode("ascii")
        fields.append(name + b"p" * (length - len(name) - 2) + b"\r\n")
        remaining -= length

    if remaining != 0:
        raise ValueError("Independent header padding exceeded its five-field bound")

    return prefix + b"".join(fields) + b"\r\n"


@dataclass(frozen=True, slots=True)
class ContentCase:
    """Bind exact source originals to independently chosen expected outcomes, never source IDs."""

    name: str
    headers: bytes
    body: bytes
    error: str | None = None
    header_absent: bool | None = True
    media_type: str = "text/html"
    path: str = PRIMARY_PATH
    extra: bytes = b""
    eof_mode: str = "close"

    def Wire(self) -> bytes:
        """Return exact served bytes, including deliberately rejected trailing material."""

        return self.headers + self.body + self.extra

    def ExpectedRecord(self, url: str) -> dict[str, object]:
        """Build handwritten expected worker shape from original source bytes and selected URL."""

        if self.error is not None:
            return {"schema_version": 1, "profile": PROFILE, "outcome": "refused",
                "error": self.error}

        parsed = urlsplit(url)
        wire = self.Wire()

        return {"schema_version": 1, "profile": PROFILE, "outcome": "captured", "url": url,
            "address": parsed.hostname, "port": parsed.port, "media_type": self.media_type,
            "request": BytePart(RequestBytes(url)), "response_headers": BytePart(self.headers),
            "response_body": BytePart(self.body), "response": {
                "size_bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()}}

    def FrozenFacts(self) -> dict[str, object]:
        """Freeze independent source hashes, field-name truth and rejection-retention exclusions."""

        parts = {name: BytePart(raw) for name, raw in (("headers", self.headers),
            ("body", self.body), ("extra", self.extra), ("wire", self.Wire()))}

        return {"path": self.path, "parts": {name: {key: value for key, value in part.items()
            if key != "base64"} for name, part in parts.items()}, "eof_mode": self.eof_mode,
            "worker_exit": 0 if self.error is None else 2,
            "outcome": "captured" if self.error is None else "refused", "error": self.error,
            "header_absent": self.header_absent if self.error is None else None,
            "media_type": self.media_type if self.error is None else None,
            "new_operation_forbidden_hashes": sorted({part["sha256"] for part in parts.values()
                if part["size_bytes"] > 0}) if self.error is not None else [],
            "rejected_marker_hex": REJECTED_MARKER.hex() if self.error is not None else None}

    def ExpectedStdout(self, url: str) -> bytes:
        """Encode exact expected original stdout with standard canonical ASCII JSON only."""

        return json.dumps(self.ExpectedRecord(url), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")


def CaseMatrix() -> tuple[ContentCase, ...]:
    """Declare fixed admitted/refused originals independently of any producer implementation."""

    body = b"<p>Owned content alpha.</p>\n"
    decoy = b"<pre>X-Content-Type-Options: nosniff</pre>\n"
    marker = REJECTED_MARKER
    maximum_marker_body = marker + b"m" * (65536 - len(marker))
    rejected = Headers(marker)
    mixed = (b"HTTP/1.1 200 OK\r\ncOnNeCtIoN:\tCLOSE \t\r\n"
        b"X-CONTENT-TYPE-OPTIONS:\t \r\ncontent-length:\t" + str(len(body)).encode() +
        b" \t\r\nDATE: Thu, 01 Jan 2037 00:00:00 GMT\r\n"
        b"Content-TYPE:\tTeXt/HtMl \t; \tcharset=utf-8 \t\r\n"
        b"Server: Independent-Fixture/7\r\nETag: \"mutable-7\"\r\n"
        b"X-Experiment: arbitrary-a\tb\r\n\r\n")
    cases = [
        ContentCase("missing", Headers(body), body),
        ContentCase("fixed", Headers(body, b"X-Content-Type-Options: owned-any-value"), body,
            header_absent=False),
        ContentCase("body-decoy", Headers(decoy), decoy),
        ContentCase("header-order-case-ows-values", mixed, body, header_absent=False),
        ContentCase("date-custom-values-a", Headers(body, b"Date: Mon, 01 Jan 2001 00:00:00 GMT",
            b"X-Owned-Value: changing-one"), body),
        ContentCase("date-custom-values-b", Headers(body, b"Date: Thu, 01 Jan 2037 00:00:00 GMT",
            b"X-Owned-Value: changing-two"), body),
        ContentCase("body-alpha", Headers(b"alpha"), b"alpha"),
        ContentCase("body-bravo", Headers(b"bravo"), b"bravo"),
        ContentCase("empty-body", Headers(b""), b""),
        ContentCase("utf8-bom", Headers(b"\xef\xbb\xbfOwned \xe2\x98\x83\n"),
            b"\xef\xbb\xbfOwned \xe2\x98\x83\n"),
        ContentCase("second-concrete-path", Headers(b"Independent plain text.\n",
            media=b"text/plain"),
            b"Independent plain text.\n", path=SECOND_PATH, media_type="text/plain"),
        ContentCase("path-limit", Headers(b"path limit"), b"path limit", path=LONG_PATH),
        ContentCase("segments-limit", Headers(b"segment limit"), b"segment limit",
            path=SEGMENT_PATH),
        ContentCase("field-limit", Headers(b"f", *(f"X-{n:02d}: f".encode()
            for n in range(61))), b"f"),
        ContentCase("line-limit", Headers(b"l", b"X-Line: " + b"l" * 4086), b"l"),
        ContentCase("header-limit", PaddedHeaders(16384, 1), b"h", media_type="text/plain"),
        ContentCase("body-limit", Headers(b"b" * 65536), b"b" * 65536),
        ContentCase("wire-limit", PaddedHeaders(16384, 65536), b"w" * 65536,
            media_type="text/plain"),
        ContentCase("duplicate-length", rejected[:-2] + b"content-length: " +
            str(len(marker)).encode() + b"\r\n\r\n", marker, "protocol"),
        ContentCase("missing-length", rejected.replace(b"Content-Length: " +
            str(len(marker)).encode() + b"\r\n", b""), marker, "protocol"),
        ContentCase("length-leading-zero", rejected.replace(b"Content-Length: ",
            b"Content-Length: 0"), marker, "protocol"),
        ContentCase("length-negative", rejected.replace(b"Content-Length: ",
            b"Content-Length: -"), marker, "protocol"),
        ContentCase("length-comma", rejected.replace(b"Content-Length: ",
            b"Content-Length: 1,"), marker, "protocol"),
        ContentCase("declared-body-over-limit", Headers(b"x" * 65537), marker, "body-policy"),
        ContentCase("declared-length-huge", rejected.replace(b"Content-Length: " +
            str(len(marker)).encode(), b"Content-Length: " + b"9" * 512), marker, "body-policy"),
        ContentCase("invalid-utf8", Headers(marker + b"\xff"), marker + b"\xff", "body-policy"),
        ContentCase("early-eof", Headers(marker + b"x"), marker, "protocol"),
        ContentCase("extra-byte", rejected, marker, "protocol", extra=b"!"),
        ContentCase("extra-byte-at-maximum", Headers(maximum_marker_body), maximum_marker_body,
            "protocol", extra=b"!"),
        ContentCase("second-response", rejected, marker, "protocol",
            extra=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        ContentCase("held-eof", rejected, marker, "timeout", eof_mode="hold-until-peer-eof"),
        ContentCase("redirect", rejected.replace(b"200 OK", b"302 Found")[:-2] +
            b"Location: /alternate/plain\r\n\r\n", marker, "response-policy"),
        ContentCase("status-not-200", rejected.replace(b"200 OK", b"403 Forbidden"),
            marker, "response-policy"),
        ContentCase("status-http10", rejected.replace(b"HTTP/1.1", b"HTTP/1.0"),
            marker, "response-policy"),
        ContentCase("duplicate-field", Headers(marker, b"X-Owned: one", b"x-owned: two"),
            marker, "response-policy"),
        ContentCase("folded-field", Headers(marker, b"X-Owned: one\r\n two"),
            marker, "response-policy"),
        ContentCase("bare-lf", rejected.replace(b"\r\n", b"\n"), marker, "protocol"),
        ContentCase("space-before-colon", rejected.replace(b"Content-Type:", b"Content-Type :"),
            marker, "response-policy"),
        ContentCase("invalid-field-name", Headers(marker, b"X(Owned): value"),
            marker, "response-policy"),
        ContentCase("invalid-field-value", Headers(marker, b"X-Owned: \x01"),
            marker, "response-policy"),
        ContentCase("unsupported-media", Headers(marker, media=b"application/json"),
            marker, "response-policy"),
        ContentCase("quoted-charset", Headers(marker, media=b'text/html; charset="utf-8"'),
            marker, "response-policy"),
        ContentCase("extra-media-parameter", Headers(marker,
            media=b"text/plain; charset=utf-8; other=value"), marker, "response-policy"),
        ContentCase("field-overflow", Headers(marker, *(f"X-{n:02d}: f".encode()
            for n in range(62))), marker, "response-policy"),
        ContentCase("line-overflow", Headers(marker, b"X-Line: " + b"l" * 4087),
            marker, "response-policy"),
        ContentCase("header-overflow", PaddedHeaders(16385, 1), marker, "response-policy"),
    ]

    for name in ("Transfer-Encoding", "Content-Encoding", "Trailer", "TE", "Upgrade",
        "Location", "Set-Cookie", "Set-Cookie2", "Cookie", "Authorization",
        "Proxy-Authorization", "WWW-Authenticate", "Proxy-Authenticate"):
        value = "identity" if name == "Content-Encoding" else "owned-rejected-value"
        cases.append(ContentCase("excluded-" + name.lower(),
            Headers(marker, (name + ": " + value).encode("ascii")), marker, "response-policy"))

    if len(cases) > MAX_CASES or len({case.name for case in cases}) != len(cases):
        raise ValueError("Independent content matrix must remain finite and uniquely named")

    return tuple(cases)


def MatrixManifest() -> dict[str, object]:
    """Expose source-only expected facts; no example receipt, evidence ID or ACK is invented."""

    return {"schema_version": 1, "profile": "independent-owned-content-response-oracle.v1",
        "production_contract_base": "c2bbd15dcc000e52f18f4c066b0075148ebffd4e",
        "runtime_acceptance": "not-run", "worker_profile": PROFILE,
        "contract_clarifications": ["refusal code member is error",
            "canonical CL above65536 is body-policy before body reads",
            "malformed or ambiguous CL and early/trailing EOF are protocol",
            "header/line overflow is response-policy before interpreting values"],
        "refusal_fields": ["schema_version", "profile", "outcome", "error"],
        "transport_refusal": {"error": "connection", "required_contacts": 0,
            "later_owned_method":
                "held bound non-listening fixture socket, never random-port probe",
            "fixture_and_execution": "deferred-unrun"},
        "input_rejections": InputRejections(),
        "cases": {case.name: case.FrozenFacts() for case in CaseMatrix()}}


def InputRejections() -> dict[str, str]:
    """Freeze deliberately unsupported URL spellings; every one requires zero socket contacts."""

    prefix = "http://127.0.0.1:15432"

    return {"dns": "http://localhost:15432/research/content",
        "https": "https://127.0.0.1:15432/research/content",
        "low-port": "http://127.0.0.1:80/research/content",
        "leading-zero-port": "http://127.0.0.1:015432/research/content",
        "expanded-ipv6": "http://[0:0:0:0:0:0:0:1]:15432/research/content",
        "ipv6-zone": "http://[::1%25lo]:15432/research/content",
        "ipv4-mapped": "http://[::ffff:127.0.0.1]:15432/research/content",
        "user-information": "http://user-marker@127.0.0.1:15432/research/content",
        "empty-query": prefix + PRIMARY_PATH + "?",
        "query": prefix + PRIMARY_PATH + "?owned-marker=1",
        "empty-fragment": prefix + PRIMARY_PATH + "#",
        "percent-path": prefix + "/research/%63ontent",
        "dot-segment": prefix + "/research/../content",
        "double-slash": prefix + "/research//content",
        "backslash": prefix + "/research\\content",
        "path-variable": prefix + "/research/{content}",
        "path-overflow": prefix + "/" + "p" * 1024,
        "segments-overflow": prefix + "/" + "/".join("s" for _ in range(65)),
        "trailing-empty-segment-overflow": prefix + "/" + "/".join("s" for _ in range(64)) + "/",
        "url-overflow": prefix + "/" + "u" * 2048}


def Canonical(value: object) -> bytes:
    """Encode independent oracle metadata without nonstandard JSON values."""

    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
        allow_nan=False).encode("ascii") + b"\n"
