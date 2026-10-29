# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed synthetic loopback HTML inputs and exact verified worker record admission."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedObservation,
)
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.scope import Target, TargetKind

PAGE_CAPTURE_VERSION = "1"
PAGE_CAPTURE_PROVIDER_ID = "native.loopback-page"
PAGE_CAPTURE_CAPABILITY = "http.synthetic-page-capture"
PAGE_BROWSER_CAPABILITY = "http.synthetic-page-browser"
PAGE_BROWSER_PROFILE = "playwright-chromium-offline.v1"
PLAYWRIGHT_VERSION = "1.64.1"
CHROMIUM_VERSION = "156.0.8078.4"
BROWSER_FIXTURE_ID = "owned-browser-dom.v1"
MAX_RECORD_BYTES = 98304
MAX_BODY_BYTES = 65536
MAX_HEADER_BYTES = 16384
MAX_HEADER_FIELDS = 64
MAX_LINE_BYTES = 4096
MAX_STDERR_BYTES = 1024
FIXTURE_ID = "owned-loopback-html.v1"
FIXTURE_SIZE_BYTES = 541
FIXTURE_SHA256 = "c0b909f728bdcc098193c1fd268f056eea33c27b6537cd504fa77c3a25afe817"
_REVIEWED_BODIES = MappingProxyType({
    FIXTURE_ID: (FIXTURE_SHA256, FIXTURE_SIZE_BYTES),
    BROWSER_FIXTURE_ID: (
        "75d60b34385f3c65068edcde7a37da78db796290b95be0ab9beb2cdc03fe3e71", 423),
    "owned-traversal-index.v1": (
        "f3058581088204e59828513b2c97b2e5d78f8551b66847ad461694f846039847", 220),
    "owned-traversal-alpha.v1": (
        "b4c02acd68dcb9e0b7876129211a0973a4ddfa3bb1497fe9866b19bdcf930778", 81),
    "owned-traversal-beta.v1": (
        "6280766abcb3598cc72f439892490485a2cf1bf7f1b0db2944a138794ec1f68f", 55),
    "owned-traversal-shared.v1": (
        "5f33a7d34dfa15c0170b83ccdbaf7abdf8be1fb7fdbfd74b79cfb64a2033ada4", 65),
})
ERROR_EXITS = {"input": 64, "connection": 1, "timeout": 124, "protocol": 1,
               "response-policy": 1, "body-policy": 1}
_SUCCESS_FIELDS = frozenset({
    "schema_version", "fixture_id", "url", "address", "port", "scheme", "status",
    "http_version", "content_type", "declared_charset", "content_length", "header_size_bytes",
    "header_count", "body_sha256", "body_base64",
})
_DESCRIPTOR = AdapterDescriptor(PAGE_CAPTURE_PROVIDER_ID, "Owned loopback HTML acquisition",
    PAGE_CAPTURE_VERSION, (PAGE_CAPTURE_CAPABILITY,), ImpactLevel.SAFE)
_BROWSER_DESCRIPTOR = AdapterDescriptor(PAGE_CAPTURE_PROVIDER_ID,
    "Owned offline HTML browser rendering", PAGE_CAPTURE_VERSION,
    (PAGE_BROWSER_CAPABILITY,), ImpactLevel.SAFE)

__all__ = [
    "PAGE_CAPTURE_VERSION", "PAGE_CAPTURE_PROVIDER_ID", "PAGE_CAPTURE_CAPABILITY",
    "PAGE_BROWSER_CAPABILITY", "PAGE_BROWSER_PROFILE", "PageRenderer",
    "KnownSyntheticHtmlBody", "PageCaptureLimits", "BrowserPageCaptureLimits",
    "PageCaptureRecordError",
    "NativeLoopbackPageAdapter",
]


class PageRenderer(str, Enum):
    """Select one fixed page implementation without arbitrary programs, flags or content."""

    NATIVE = "native"
    PLAYWRIGHT_OFFLINE = PAGE_BROWSER_PROFILE


class PageCaptureRecordError(ValueError):
    """Untrusted output cannot establish a bounded attributable synthetic page."""


def Integer(value: object, minimum: int, maximum: int) -> int:
    """Validate exact bounded integers before conversions or input-derived allocation.

    Args:
        value: Explicit integer, excluding booleans and coercion.
        minimum: Inclusive admitted lower bound.
        maximum: Inclusive admitted upper bound.

    Returns:
        Original exact integer.
    """

    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("page capture integer is outside its admitted bounds")

    return value


def Seconds(value: object, maximum: float) -> float:
    """Validate numeric request/provider seconds before finite floating-point conversion.

    Args:
        value: Exact finite int/float seconds, excluding booleans.
        maximum: Inclusive profile ceiling; the minimum is 0.05 seconds.

    Returns:
        Validated deadline as a float.
    """

    if not isinstance(value, (int, float)) or type(value) not in (int, float) or (
        not 0.05 <= value <= maximum
    ):
        raise ValueError("page capture deadline is outside its admitted bounds")

    if not math.isfinite(value):
        raise ValueError("page capture deadline must be finite")

    return float(value)


@dataclass(frozen=True, slots=True)
class KnownSyntheticHtmlBody:
    """Select a finite reviewed non-secret body; selection supplies no execution authority."""

    fixture_id: str
    sha256: str = field(init=False)
    size_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        """Derive immutable catalog identity without files, arbitrary digests or defaults."""

        if type(self.fixture_id) is not str or len(self.fixture_id) > 64 or (
            self.fixture_id not in _REVIEWED_BODIES
        ):
            raise ValueError("page capture requires an explicit reviewed fixture identifier")

        digest, size = _REVIEWED_BODIES[self.fixture_id]
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "size_bytes", size)


def KnownBody(value: object) -> KnownSyntheticHtmlBody:
    """Revalidate copied catalog records including the exact types of derived fields.

    Args:
        value: Explicit closed fixture selection requiring complete typed validation.

    Returns:
        Original unchanged catalog record; never arbitrary body approval.
    """

    if type(value) is not KnownSyntheticHtmlBody or type(value.sha256) is not str or (
        type(value.size_bytes) is not int
        or KnownSyntheticHtmlBody(value.fixture_id) != value
    ):
        raise ValueError("page capture requires an unchanged typed closed body selection")

    return value


@dataclass(frozen=True, slots=True)
class PageCaptureLimits:
    """Finite one-request body and whole-operation deadlines, with no expansion knobs."""

    max_body_bytes: int = 16384
    request_timeout_seconds: float = 2.0
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        """Reject coercions, huge/nonfinite seconds and inconsistent startup budgets."""

        Integer(self.max_body_bytes, 1, MAX_BODY_BYTES)
        request = Seconds(self.request_timeout_seconds, 5)
        provider = Seconds(self.timeout_seconds, 15)

        if provider < request + 1:
            raise ValueError("page capture provider budget must include request plus startup")


@dataclass(frozen=True, slots=True)
class BrowserPageCaptureLimits:
    """Browser-only budgets covering helper readiness, worker, cleanup and source custody."""

    max_body_bytes: int = 16384
    request_timeout_seconds: float = 2.0
    timeout_seconds: float = 18.0

    def __post_init__(self) -> None:
        """Require the finite whole-operation margin without expanding native page defaults."""

        Integer(self.max_body_bytes, 1, MAX_BODY_BYTES)
        request = Seconds(self.request_timeout_seconds, 5)
        provider = Seconds(self.timeout_seconds, 30)

        if provider < 3 + math.ceil(request + 7) + 3 + 1:
            raise ValueError(
                "browser provider budget must cover readiness, worker, cleanup and Save")


def Destination(value: object) -> tuple[Target, str, int, str, str]:
    """Require the exact canonical anonymous HTTP URL at 127.0.0.1 or ::1, without DNS.

    Args:
        value: Exact canonical ASCII URL, at most 2048 bytes, without query or credentials.

    Returns:
        Canonical target, literal address, port, concrete path and Host authority.

    Raises:
        ValueError: URL text or any structural destination component is unsupported.
    """

    if type(value) is not str or not value or len(value) > 2048:
        raise ValueError("page capture requires bounded canonical loopback URL text")

    try:
        value.encode("ascii")
        target = Target(TargetKind.URL, value)
        parsed = urlsplit(value)
        address = parsed.hostname
        path = parsed.path
        port = 80 if parsed.port is None else parsed.port

        if target.value != value or parsed.scheme != "http" or address not in (
            "127.0.0.1", "::1"
        ) or parsed.username is not None or parsed.password is not None or (
            parsed.query or parsed.fragment or not path or len(path) > 1024
            or any(character in "%{}?\\#" or character.isspace() or ord(character) < 32
                   or ord(character) == 127 for character in path)
        ):
            raise ValueError("unsupported destination")

    except (ValueError, UnicodeError):
        raise ValueError("page capture requires an exact anonymous literal-loopback HTTP URL") \
            from None

    return target, address, port, path, parsed.netloc


def CanonicalRecord(record: Mapping[str, object]) -> bytes:
    """Encode the one flat strict worker record in sorted compact UTF-8 JSON plus LF.

    Args:
        record: Already bounded validated worker fields or fixed failure metadata.

    Returns:
        Canonical sorted compact JSON bytes with exactly one final LF.
    """

    return json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse duplicate JSON fields instead of allowing last-key-wins interpretation.

    Args:
        pairs: JSON decoder's bounded object members in observed order.

    Returns:
        Original fields as a dictionary, only when every name is unique.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker field")

        result[key] = value

    return result


def RejectConstant(value: str) -> None:
    """Refuse nonstandard NaN/Infinity JSON without returning input-derived text.

    Args:
        value: Transient unsupported numeric token; it is never echoed or retained.
    """

    raise ValueError("nonfinite worker field")


def FlatJson(raw: bytes) -> dict[str, object]:
    """Bound nesting before JSON decode and require byte-for-byte canonical flat output.

    Args:
        raw: Exact immutable stdout bytes, at most 98304 bytes.

    Returns:
        The flat decoded record after duplicate/nonfinite/encoding rejection.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RECORD_BYTES:
        raise ValueError("worker record exceeds its byte bound")

    depth = 0
    quoted = False
    escaped = False

    for byte in raw:
        if quoted:
            if escaped:
                escaped = False

            elif byte == 92:
                escaped = True

            elif byte == 34:
                quoted = False

        elif byte == 34:
            quoted = True

        elif byte == 123:
            depth += 1

            if depth > 1:
                raise ValueError("worker record must be flat")

        elif byte == 125:
            depth -= 1

        elif byte in (91, 93):
            raise ValueError("worker record must have scalar fields")

    record = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueObject,
                        parse_constant=RejectConstant)

    if type(record) is not dict or raw != CanonicalRecord(record):
        raise ValueError("worker record must use the exact canonical encoding")

    return record


def DecodeBody(record: Mapping[str, object], expected: KnownSyntheticHtmlBody) -> bytes:
    """Admit only canonical standard base64 for the exact reviewed UTF-8 body sequence.

    Args:
        record: Flat metadata with a bounded canonical body_base64 field.
        expected: Previously validated closed known-body catalog selection.

    Returns:
        Exact reviewed non-secret body bytes, with strict UTF-8 and no BOM.
    """

    encoded = record["body_base64"]

    if type(encoded) is not str or len(encoded) != 4 * math.ceil(expected.size_bytes / 3):
        raise ValueError("body encoding differs from the reviewed declaration")

    body = base64.b64decode(encoded, validate=True)

    if base64.b64encode(body).decode("ascii") != encoded or len(body) != expected.size_bytes or (
        hashlib.sha256(body).hexdigest() != expected.sha256 or body.startswith(b"\xef\xbb\xbf")
    ):
        raise ValueError("body bytes differ from the reviewed declaration")

    body.decode("utf-8", errors="strict")

    return body


def ParseRecord(raw: bytes, url: str, expected_body: KnownSyntheticHtmlBody,
                max_body_bytes: int) -> dict[str, object]:
    """Independently validate all fixed failure/success fields before evidence publication.

    Args:
        raw: Exact bounded stdout, never stderr or an HTTP transcript.
        url: Exact prepared approved canonical URL.
        expected_body: Explicit unchanged closed catalog selection.
        max_body_bytes: Selected admitted integer body bound.

    Returns:
        Exact flat record, containing known non-secret bytes only on success.

    Raises:
        PageCaptureRecordError: Shape, encoding, metadata, endpoint or body is inconsistent.
    """

    try:
        expected = KnownBody(expected_body)
        Integer(max_body_bytes, 1, MAX_BODY_BYTES)

        if expected.size_bytes > max_body_bytes:
            raise ValueError("selected body does not fit")

        target, address, port, _, _ = Destination(url)
        record = FlatJson(raw)
        Integer(record.get("schema_version"), 1, 1)

        if "error" in record:
            if set(record) != {"schema_version", "error"} or (
                type(record["error"]) is not str or record["error"] not in ERROR_EXITS
            ):
                raise ValueError("unknown failure record")

            return record

        if set(record) != _SUCCESS_FIELDS or record["fixture_id"] != expected.fixture_id or (
            record["url"] != target.value or record["address"] != address
            or record["scheme"] != "http" or record["http_version"] not in (
                "HTTP/1.0", "HTTP/1.1"
            ) or record["content_type"] != "text/html"
            or record["declared_charset"] not in (None, "utf-8")
            or record["body_sha256"] != expected.sha256
        ):
            raise ValueError("worker metadata differs from the prepared destination/body")

        Integer(record["port"], port, port)
        Integer(record["status"], 200, 200)
        Integer(record["content_length"], expected.size_bytes, expected.size_bytes)
        count = Integer(record["header_count"], 2, MAX_HEADER_FIELDS)
        minimum = 58 + len(str(expected.size_bytes)) + (
            14 if record["declared_charset"] is not None else 0
        ) + (
            4 * (count - 2) + max(0, count - 53)
        )
        Integer(record["header_size_bytes"], minimum,
                min(MAX_HEADER_BYTES, MAX_LINE_BYTES * (count + 1) + 2))
        DecodeBody(record, expected)

        return record

    except (ValueError, TypeError, AttributeError, OverflowError, KeyError, RecursionError,
            binascii.Error):
        raise PageCaptureRecordError("page capture record violated the closed safe grammar") \
            from None


def Execution(execution: object) -> AdapterExecution:
    """Revalidate exact terminal execution records before comparing equality or persisting.

    Args:
        execution: Exact owning record, including finite nonnegative duration and terminal state.

    Returns:
        Original validated execution; later job failure remains a separate outcome.
    """

    if type(execution) is not AdapterExecution or type(execution.state) is not ExecutionState or (
        type(execution.duration_seconds) not in (int, float)
        or not 0 <= execution.duration_seconds <= sys.float_info.max
        or not math.isfinite(execution.duration_seconds)
        or execution.exit_code is not None and type(execution.exit_code) is not int
    ):
        raise PageCaptureRecordError("page capture requires exact finite execution metadata")

    if AdapterExecution(execution.state, execution.exit_code,
                        execution.duration_seconds) != execution:
        raise PageCaptureRecordError("page capture execution metadata is inconsistent")

    return execution


def Reference(reference: object) -> EvidenceReference:
    """Validate the exact bounded immutable stdout reference before invoking its reader.

    Args:
        reference: Exact immutable application/json stdout reference, at most 98304 bytes.

    Returns:
        Original role/locator/digest/size-validated reference.
    """

    if type(reference) is not EvidenceReference or type(reference.sha256) is not str or (
        not re.fullmatch(r"[0-9a-f]{64}", reference.sha256)
        or reference.role != "stdout" or reference.media_type != "application/json"
        or reference.locator != "blobs/sha256/" + reference.sha256
    ):
        raise PageCaptureRecordError("page capture requires its exact stdout evidence role")

    Integer(reference.size_bytes, 1, MAX_RECORD_BYTES)

    return reference


class NativeLoopbackPageAdapter:
    """Prepare and normalize only the distinct SAFE closed synthetic-page capability."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes], *,
                 renderer: PageRenderer = PageRenderer.NATIVE) -> None:
        """Bind an existing owning evidence reader without target probes or filesystem reads.

        Args:
            evidence_reader: Actual owner integrity reader, never a caller-selected file loader.
            renderer: Exact finite implementation selection; the native default stays unchanged.
        """

        if not callable(evidence_reader) or type(renderer) is not PageRenderer:
            raise ValueError("page capture evidence reader must be callable")

        self._read_evidence = evidence_reader
        self._renderer = renderer

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return packaged provider/version/capability metadata without granting authority.

        Returns:
            Immutable separate SAFE synthetic-page declaration with no privilege requirement.
        """

        return _DESCRIPTOR if self._renderer is PageRenderer.NATIVE else _BROWSER_DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Report first-party package availability without network or tool discovery.

        Returns:
            Packaged provider availability/version, without permission to launch.
        """

        return AdapterHealth(PAGE_CAPTURE_PROVIDER_ID, AdapterHealthState.AVAILABLE,
                             PAGE_CAPTURE_VERSION)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Prepare the exact bounded argv; actual launch requires existing current policy.

        Args:
            request: Exact SAFE request with URL, timeout, quota and explicit closed fixture ID.

        Returns:
            Exact current interpreter/module/argv with startup-inclusive executor timeout.

        Raises:
            ValueError: Types, capability, parameters, target or closed catalog are invalid.
        """

        capability = PAGE_CAPTURE_CAPABILITY if self._renderer is PageRenderer.NATIVE else (
            PAGE_BROWSER_CAPABILITY)

        if type(request) is not AdapterRequest or type(request.capability) is not str or (
            request.capability != capability
            or type(request.target_reference) is not str
            or request.impact is not ImpactLevel.SAFE
            or type(request.credential_references) is not tuple
            or request.credential_references or type(request.parameters) is not MappingProxyType
            or len(request.parameters) != 4
            or set(request.parameters) != {"url", "timeout_seconds", "fixture_id", "max_body_bytes"}
        ):
            raise ValueError("page capture requires its exact anonymous SAFE input parameters")

        target, _, _, _, _ = Destination(request.parameters["url"])
        timeout = Seconds(request.parameters["timeout_seconds"], 5)
        fixture_id = request.parameters["fixture_id"]

        if type(fixture_id) is not str:
            raise ValueError("page capture requires an exact text fixture identifier")

        body = KnownSyntheticHtmlBody(fixture_id)
        maximum = Integer(request.parameters["max_body_bytes"], 1, MAX_BODY_BYTES)

        if body.size_bytes > maximum or request.target_reference != target.Reference():
            raise ValueError("page capture selected body or exact target binding differs")

        module = "fuzzy1337.page_capture_worker" if self._renderer is PageRenderer.NATIVE else (
            "fuzzy1337.browser_page_worker")
        startup = 1 if self._renderer is PageRenderer.NATIVE else 7

        return AdapterInvocation(PAGE_CAPTURE_PROVIDER_ID, request, (
            sys.executable, "-I", "-m", module, target.value,
            str(timeout), body.fixture_id, str(maximum),
        ), math.ceil(timeout + startup), PAGE_CAPTURE_VERSION)

    def ValidateInvocation(
        self, invocation: object, *, allow_legacy: bool = False,
    ) -> AdapterInvocation:
        """Reconstruct exact nested request/argv fields and their owning invocation digest.

        Args:
            invocation: Typed prepared invocation or copied wrapper requiring nested revalidation.
            allow_legacy: Admit exact historical argv only for read-only report interpretation.
                Current launch/provider validation leaves this disabled.

        Returns:
            Original invocation only after exact reconstruction and owning SHA agreement.
        """

        if type(invocation) is not AdapterInvocation or type(invocation.argv) is not tuple or (
            len(invocation.argv) not in ((7, 8) if allow_legacy is True else (8,))
            or any(type(argument) is not str for argument in invocation.argv)
            or type(invocation.timeout_seconds) is not int
            or type(invocation.adapter_id) is not str
            or type(invocation.provider_version) is not str
        ):
            raise PageCaptureRecordError("page capture requires an exact prepared invocation")

        prepared = self.PrepareInvocation(invocation.request)

        if allow_legacy is True and self._renderer is PageRenderer.NATIVE and (
            invocation.argv == (prepared.argv[0], *prepared.argv[2:])
        ):
            prepared = replace(prepared, argv=invocation.argv)

        if invocation != prepared or InvocationDigest(invocation) != InvocationDigest(prepared):
            raise PageCaptureRecordError("page capture invocation differs from preparation")

        return invocation

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Return one source response envelope after exact invocation/evidence/body validation.

        No Host/Port/Service, relationships, findings or lexical connectivity are synthesized.

        Args:
            report: Successful real execution, exact invocation and sole bounded stdout evidence.

        Returns:
            One normalized source response observation, without mutation or new connectivity.

        Raises:
            PageCaptureRecordError: Any successful report binding is unsupported or inconsistent.
        """

        try:
            if type(report) is not AdapterReport or type(report.evidence) is not tuple or (
                len(report.evidence) != 1
            ):
                raise ValueError("invalid report shape")

            invocation = self.ValidateInvocation(report.invocation, allow_legacy=True)
            execution = Execution(report.execution)

            if execution.state is not ExecutionState.SUCCEEDED or execution.exit_code != 0:
                raise ValueError("unsuccessful report")

            reference = Reference(report.evidence[0])
            raw = self._read_evidence(reference)

            if type(raw) is not bytes or len(raw) != reference.size_bytes or (
                hashlib.sha256(raw).hexdigest() != reference.sha256
            ):
                raise ValueError("stdout evidence differs from its exact reference")

            parameters = invocation.request.parameters
            parser = ParseRecord

            if self._renderer is PageRenderer.PLAYWRIGHT_OFFLINE:
                from fuzzy1337.adapters.browser_page import ParseBrowserRecord

                parser = ParseBrowserRecord

            record = parser(raw, cast(str, parameters["url"]),
                KnownSyntheticHtmlBody(cast(str, parameters["fixture_id"])),
                cast(int, parameters["max_body_bytes"]))

            if "error" in record:
                raise ValueError("failure record cannot become a successful page")

            metadata = {key: value for key, value in record.items() if key != "body_base64"}

            kind = "http.synthetic-page" if self._renderer is PageRenderer.NATIVE else (
                "http.synthetic-page-browser")

            return AdapterResult(report, (NormalizedObservation(kind,
                invocation.request.target_reference, metadata),))

        except (ValueError, TypeError, AttributeError, OverflowError, KeyError, OSError):
            raise PageCaptureRecordError("page capture report could not be safely normalized") \
                from None
