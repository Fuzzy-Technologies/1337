# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit native Git HEAD response checks and bounded original-report interpretation."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections.abc import Callable

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterHealth,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedFinding,
    NormalizedObservation,
)
from fuzzy1337.adapters.native_http import Endpoint, RequestTimeout
from fuzzy1337.scope import Target

NATIVE_WEB_VERSION = "1"
NATIVE_WEB_PROVIDER_ID = "native.web-check"
NATIVE_WEB_CAPABILITY = "web.git-head-check"
NATIVE_WEB_CHECK_ID = "native.git-head-exposure"
MAX_NATIVE_WEB_RECORD_BYTES = 4096
MAX_NATIVE_WEB_BODY_BYTES = 4096
NATIVE_WEB_MEDIA_TYPES = frozenset({"text/plain", "application/octet-stream", "other"})
NATIVE_WEB_ERROR_EXITS = {
    "input": 64, "timeout": 124, "connection": 1, "tls": 1, "protocol": 1,
    "response-policy": 1,
}
_HEAD = re.compile(
    rb"ref: refs/heads/[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
    rb"(?:/[A-Za-z0-9][A-Za-z0-9_-]{0,63}){0,7}(?:\r?\n)?"
)
_SHA256 = re.compile(r"[a-f0-9]{64}")
_DESCRIPTOR = AdapterDescriptor(
    NATIVE_WEB_PROVIDER_ID, "Native Git HEAD response check", NATIVE_WEB_VERSION,
    (NATIVE_WEB_CAPABILITY,), ImpactLevel.STANDARD,
)


class NativeWebRecordError(ValueError):
    """Original worker output cannot establish the declared native check observation."""


def NativeWebEndpoint(value: object) -> tuple[Target, str, int, str]:
    """Require already-canonical exact native destinations without rewriting operator input."""

    result = Endpoint(value)

    if value != result[0].value:
        raise ValueError("native web requires an already canonical exact URL")

    return result


def CanonicalRecord(record: dict[str, object]) -> bytes:
    """Encode the sole canonical bounded original worker JSON representation."""

    return (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode("utf-8")


def MatchesGitHead(status: int, media_type: str, body: bytes) -> bool:
    """Recognize only the complete bounded symbolic HEAD profile, never source recovery.

    Args:
        status: Actual complete HTTP response status.
        media_type: Fixed normalized response-media category.
        body: Transient complete response bytes, never retained by this check.

    Returns:
        Whether HTTP 200/plain-or-octet response bytes satisfy the declared grammar.
    """

    return (type(status) is int and status == 200 and media_type in {
        "text/plain", "application/octet-stream",
    } and isinstance(body, bytes) and len(body) <= MAX_NATIVE_WEB_BODY_BYTES
        and _HEAD.fullmatch(body) is not None)


def ParseNativeWebRecord(raw: bytes, url: str) -> dict[str, object]:
    """Verify canonical original check metadata without reconstructing absent HTTP bytes.

    Args:
        raw: Original bounded stdout bytes from the native worker.
        url: Exact approved canonical invocation URL.

    Returns:
        Revalidated fixed error or successful response-predicate observation.

    Raises:
        NativeWebRecordError: Canonical JSON, types, dimensions or invocation joins differ.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_NATIVE_WEB_RECORD_BYTES:
        raise NativeWebRecordError("native web record exceeds its byte bound")

    try:
        record = json.loads(raw)

        if type(record) is not dict or CanonicalRecord(record) != raw or (
            type(record.get("schema_version")) is not int or record["schema_version"] != 1
        ):
            raise ValueError

        if "error" in record:
            if set(record) != {"schema_version", "error"} or (
                type(record["error"]) is not str
                or record["error"] not in NATIVE_WEB_ERROR_EXITS
            ):
                raise ValueError

            return record

        target, address, port, scheme = NativeWebEndpoint(url)
        expected = {"schema_version", "check_id", "profile_version", "url", "address",
                    "port", "scheme", "status", "media_type", "body_bytes", "body_sha256",
                    "matched"}

        if set(record) != expected or record["check_id"] != NATIVE_WEB_CHECK_ID or (
            record["profile_version"] != NATIVE_WEB_VERSION
            or record["url"] != target.value or record["address"] != address
            or type(record["port"]) is not int or record["port"] != port
            or record["scheme"] != scheme or type(record["status"]) is not int
            or not 200 <= record["status"] <= 499
            or type(record["body_bytes"]) is not int
            or not 0 <= record["body_bytes"] <= MAX_NATIVE_WEB_BODY_BYTES
            or type(record["media_type"]) is not str
            or record["media_type"] not in NATIVE_WEB_MEDIA_TYPES
            or type(record["body_sha256"]) is not str
            or _SHA256.fullmatch(record["body_sha256"]) is None
            or type(record["matched"]) is not bool
        ):
            raise ValueError

        if record["matched"] and (record["status"] != 200 or (
            record["media_type"] == "other" or not 17 <= record["body_bytes"] <= 537
        )):
            raise ValueError

        if record["body_bytes"] == 0 and (
            record["body_sha256"] != hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError

        return record

    except (ValueError, TypeError, OverflowError, RecursionError):
        raise NativeWebRecordError("native web output violates the fixed check record") from None


class NativeWebAdapter:
    """Prepare one explicit STANDARD native check; interpretation creates no authority."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes]) -> None:
        """Bind the actual immutable evidence owner without contacting any endpoint."""

        self._read_evidence = evidence_reader

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return fixed first-party check identity and required STANDARD impact."""

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Report packaged code availability without probing or authorizing a target."""

        return AdapterHealth(NATIVE_WEB_PROVIDER_ID, AdapterHealthState.AVAILABLE,
                             NATIVE_WEB_VERSION)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Bind exact query-free literal URL and deadline to one shell-free native worker.

        Args:
            request: STANDARD check request containing only URL and finite request timeout.

        Returns:
            Current-interpreter invocation with a bounded startup-inclusive deadline.

        Raises:
            ValueError: Capability, target, credentials or selected parameters are unsupported.
        """

        if request.capability != NATIVE_WEB_CAPABILITY or (
            request.impact is not ImpactLevel.STANDARD or request.credential_references
            or set(request.parameters) != {"url", "timeout_seconds"}
        ):
            raise ValueError("native web requires the exact STANDARD credential-free check")

        target, _, _, _ = NativeWebEndpoint(request.parameters["url"])
        timeout = RequestTimeout(request.parameters["timeout_seconds"])

        if request.target_reference != target.Reference():
            raise ValueError("native web request must bind its exact URL")

        return AdapterInvocation(
            NATIVE_WEB_PROVIDER_ID, request,
            (sys.executable, "-I", "-m", "fuzzy1337.native_web_worker", target.value, str(timeout)),
            math.ceil(timeout + 1), NATIVE_WEB_VERSION,
        )

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Verify original stdout/stderr, then interpret the bounded native worker verdict.

        Args:
            report: Owning successful execution and exact original stdout/stderr references.

        Returns:
            One response-predicate observation and an optional exposure Finding envelope.

        Raises:
            NativeWebRecordError: Original execution, evidence, invocation or report differs.
        """

        if report.invocation != self.PrepareInvocation(report.invocation.request) or (
            report.execution.state is not ExecutionState.SUCCEEDED
            or report.execution.exit_code != 0
            or len(report.evidence) != 2
            or tuple(item.role for item in report.evidence) != ("stdout", "stderr")
        ):
            raise NativeWebRecordError("native web requires the original successful execution")

        values = []

        for reference in report.evidence:
            maximum = MAX_NATIVE_WEB_RECORD_BYTES if reference.role == "stdout" else 0

            if reference.size_bytes > maximum:
                raise NativeWebRecordError("native web original stream exceeds its bound")

            value = self._read_evidence(reference)

            if type(value) is not bytes or len(value) != reference.size_bytes or (
                hashlib.sha256(value).hexdigest() != reference.sha256
            ):
                raise NativeWebRecordError("native web original stream differs from its reference")

            values.append(value)

        record = ParseNativeWebRecord(values[0], str(report.invocation.request.parameters["url"]))

        if "error" in record:
            raise NativeWebRecordError("a failed response check cannot produce findings")

        subject = report.invocation.request.target_reference
        attributes = {key: record[key] for key in (
            "check_id", "profile_version", "status", "media_type", "body_bytes", "body_sha256",
            "matched",
        )}
        findings = (NormalizedFinding(
            "git-head-exposure", subject, "Exposed supported Git HEAD symbolic reference",
            {"check_id": NATIVE_WEB_CHECK_ID, "severity": "low"},
        ),) if record["matched"] else ()

        return AdapterResult(report, (
            NormalizedObservation("native.web-response-check", subject, attributes),
        ), findings=findings)
