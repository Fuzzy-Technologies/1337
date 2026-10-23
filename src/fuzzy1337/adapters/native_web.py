# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite native web response checks and bounded original-report interpretation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit

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
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.adapters.native_http import Endpoint, RequestTimeout
from fuzzy1337.requests import Endpoint as RequestEndpoint
from fuzzy1337.requests import InjectionLocation, InjectionPoint, RequestTemplate, ValueBinding
from fuzzy1337.scope import Target, TargetKind

NATIVE_WEB_VERSION = "1"
NATIVE_WEB_PROVIDER_ID = "native.web-check"
NATIVE_WEB_CAPABILITY = "web.git-head-check"
NATIVE_WEB_CHECK_ID = "native.git-head-exposure"
NATIVE_FILE_CANARY_CHECK_ID = "native.file-canary-disclosure"
NATIVE_FILE_CANARY_CAPABILITY = "web.file-canary-check"
NATIVE_FILE_CANARY_PROFILE = "owned-loopback-file-canary-query-v1"
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
_FILE_PATHS = frozenset({"/files/vulnerable", "/files/fixed", "/files/decoy"})
_FILE_QUERIES = frozenset({"name=hello.txt", "name=..%2Fprivate%2Fcanary.txt",
                           "name=..%2Fprivate%2Fmissing.txt"})
_FILE_CANARY = b"owned-private-file-canary\n"


@dataclass(frozen=True, slots=True)
class NativeWebCheck:
    """Describe one finite packaged predicate without granting request authority."""

    check_id: str
    capability: str
    finding_id: str
    title: str
    predicate: Callable[[int, str, bytes], bool]
    request_profile: str | None = None


class NativeWebRecordError(ValueError):
    """Original worker output cannot establish the declared native check observation."""


def NativeWebEndpoint(
    value: object, *, check_id: str = NATIVE_WEB_CHECK_ID,
) -> tuple[Target, str, int, str]:
    """Require already-canonical exact native destinations without rewriting operator input.

    Args:
        value: Exact query-free Git URL or closed owned-loopback canary-pack URL.
        check_id: Explicit registered check; the Git default retains query refusal.

    Returns:
        Exact typed URL target, canonical literal address, effective port and scheme.
    """

    check = NativeWebCheckFor(check_id)

    if check.check_id == NATIVE_FILE_CANARY_CHECK_ID:
        if type(value) is not str or not value.isascii() or len(value) > 2048:
            raise ValueError("owned canary requires a bounded exact ASCII URL")

        parsed = urlsplit(value)

        if parsed.path not in _FILE_PATHS or parsed.query not in _FILE_QUERIES:
            raise ValueError("owned canary requires one reviewed pack path and exact query")

        base = parsed._replace(query="").geturl()
        target, address, port, scheme = Endpoint(base)

        if base != target.value or not ipaddress.ip_address(address).is_loopback:
            raise ValueError("owned canary requires an exact literal loopback destination")

        selected = Target(TargetKind.URL, value)

        if selected.value != value:
            raise ValueError("owned canary requires already canonical query spelling")

        return selected, address, port, scheme

    result = Endpoint(value)

    if value != result[0].value:
        raise ValueError("native web requires an already canonical exact URL")

    return result


def CanonicalRecord(record: dict[str, object]) -> bytes:
    """Encode the sole canonical original worker JSON representation.

    Args:
        record: Fixed safe worker metadata containing only standard finite JSON values.

    Returns:
        Sorted compact UTF-8 JSON bytes terminated by exactly one LF.
    """

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


def MatchesFileCanary(status: int, media_type: str, body: bytes) -> bool:
    """Recognize only the complete non-secret marker declared by the owned local pack.

    Args:
        status: Actual complete HTTP response status.
        media_type: Fixed normalized response-media category.
        body: Transient complete response bytes from the explicit owned request.

    Returns:
        Whether the admitted response equals the entire fixed non-secret canary.
    """

    return (type(status) is int and status == 200 and media_type in {
        "text/plain", "application/octet-stream",
    } and type(body) is bytes and body == _FILE_CANARY)


_CHECKS = MappingProxyType({
    NATIVE_WEB_CHECK_ID: NativeWebCheck(NATIVE_WEB_CHECK_ID, NATIVE_WEB_CAPABILITY,
        "git-head-exposure", "Exposed supported Git HEAD symbolic reference", MatchesGitHead),
    NATIVE_FILE_CANARY_CHECK_ID: NativeWebCheck(NATIVE_FILE_CANARY_CHECK_ID,
        NATIVE_FILE_CANARY_CAPABILITY, "file-canary-disclosure",
        "Owned non-secret file canary disclosed", MatchesFileCanary, NATIVE_FILE_CANARY_PROFILE),
})
_DESCRIPTOR = AdapterDescriptor(
    NATIVE_WEB_PROVIDER_ID, "Native bounded response checks", NATIVE_WEB_VERSION,
    tuple(check.capability for check in _CHECKS.values()), ImpactLevel.STANDARD,
)


def NativeWebCheckFor(check_id: str) -> NativeWebCheck:
    """Resolve an explicit finite packaged check without accepting dynamic implementations.

    Args:
        check_id: Exact registered predicate identity.

    Returns:
        Immutable declaration for the selected packaged check.
    """

    if type(check_id) is not str or check_id not in _CHECKS:
        raise ValueError("native web check is not registered")

    return _CHECKS[check_id]


def NativeFileCanaryTemplate(workspace_id: str, url: str) -> RequestTemplate:
    """Bind the closed owned query coordinate to the existing anonymous request model.

    Args:
        workspace_id: Owning existing workspace identifier.
        url: Exact admitted loopback canary-pack URL, including its fixed query.

    Returns:
        One structural GET template without concrete values, credentials or sessions.
    """

    target, _, _, _ = NativeWebEndpoint(url, check_id=NATIVE_FILE_CANARY_CHECK_ID)
    parsed = urlsplit(target.value)

    return RequestTemplate(RequestEndpoint(workspace_id,
        f"{parsed.scheme}://{parsed.netloc}", parsed.path), (
            InjectionPoint(InjectionLocation.QUERY, "name", ValueBinding("native-file-input")),
        ))


def NativeWebParameters(
    url: str, timeout_seconds: object, *, check_id: str = NATIVE_WEB_CHECK_ID,
    workspace_id: str | None = None,
) -> dict[str, object]:
    """Build exact check-specific intent fields without introducing request-value rendering.

    Args:
        url: Already canonical explicit target admitted by the selected request profile.
        timeout_seconds: Finite complete-request deadline.
        check_id: Explicit registered predicate; the Git default preserves its old fields.
        workspace_id: Required owning workspace for the structural canary request.

    Returns:
        Exact bounded parameters binding URL, predicate and optional structural request.
    """

    NativeWebEndpoint(url, check_id=check_id)
    parameters: dict[str, object] = {"url": url,
                                   "timeout_seconds": RequestTimeout(timeout_seconds)}

    if check_id == NATIVE_FILE_CANARY_CHECK_ID:
        if type(workspace_id) is not str:
            raise ValueError("owned canary requires its request workspace")

        template = NativeFileCanaryTemplate(workspace_id, url)
        parameters.update({"check_id": check_id, "request_profile": NATIVE_FILE_CANARY_PROFILE,
            "request_template": template.ToDict(),
            "injection_reference": template.injection_points[0].Reference(template.Reference())})

    return parameters


def ParseNativeWebRecord(
    raw: bytes, url: str, *, check_id: str = NATIVE_WEB_CHECK_ID,
    workspace_id: str | None = None,
) -> dict[str, object]:
    """Verify canonical original check metadata without reconstructing absent HTTP bytes.

    Args:
        raw: Original bounded stdout bytes from the native worker.
        url: Exact approved canonical invocation URL.
        check_id: Exact selected packaged predicate, defaulting to the original Git check.
        workspace_id: Original canary-template workspace; absent for the Git profile.

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

        check = NativeWebCheckFor(check_id)
        target, address, port, scheme = NativeWebEndpoint(url, check_id=check_id)
        expected = {"schema_version", "check_id", "profile_version", "url", "address",
                    "port", "scheme", "status", "media_type", "body_bytes", "body_sha256",
                    "matched"}

        if check_id == NATIVE_FILE_CANARY_CHECK_ID:
            if type(workspace_id) is not str:
                raise ValueError

            template = NativeFileCanaryTemplate(workspace_id, url)
            expected.update({"request_profile", "request_reference", "injection_reference"})

            if record.get("request_profile") != NATIVE_FILE_CANARY_PROFILE or (
                record.get("request_reference") != template.Reference()
                or record.get("injection_reference") != (
                    template.injection_points[0].Reference(template.Reference()))
            ):
                raise ValueError

        if set(record) != expected or record["check_id"] != check.check_id or (
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

        if check_id == NATIVE_WEB_CHECK_ID and record["matched"] and (record["status"] != 200 or (
            record["media_type"] == "other" or not 17 <= record["body_bytes"] <= 537
        )):
            raise ValueError

        if check_id == NATIVE_FILE_CANARY_CHECK_ID and record["matched"] != (
            record["status"] == 200 and record["media_type"] != "other"
            and record["body_bytes"] == len(_FILE_CANARY)
            and record["body_sha256"] == hashlib.sha256(_FILE_CANARY).hexdigest()
        ):
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
        """Return fixed first-party check identity and required STANDARD impact.

        Returns:
            Fixed packaged provider identity and its finite explicitly selected capabilities.
        """

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Report packaged code availability without probing or authorizing a target.

        Returns:
            Packaged provider availability/version, without a target or trust decision.
        """

        return AdapterHealth(NATIVE_WEB_PROVIDER_ID, AdapterHealthState.AVAILABLE,
                             NATIVE_WEB_VERSION)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Bind one exact registered URL profile and deadline to an isolated native worker.

        Args:
            request: STANDARD URL/deadline request; the canary profile additionally binds
                its exact check, profile, anonymous request template and injection reference.

        Returns:
            Current-interpreter invocation with a bounded startup-inclusive deadline.

        Raises:
            ValueError: Capability, target, credentials or selected parameters are unsupported.
        """

        check_id = request.parameters.get("check_id", NATIVE_WEB_CHECK_ID)

        if type(check_id) is not str:
            raise ValueError("native web requires an exact registered check")

        check = NativeWebCheckFor(check_id)

        if request.capability != check.capability or (
            request.impact is not ImpactLevel.STANDARD or request.credential_references
        ):
            raise ValueError("native web requires the exact STANDARD credential-free check")

        expected = {"url", "timeout_seconds"}

        if check_id == NATIVE_FILE_CANARY_CHECK_ID:
            expected.update({"check_id", "request_profile", "request_template",
                             "injection_reference"})

        if set(request.parameters) != expected:
            raise ValueError("native web requires exact check-specific parameters")

        target, _, _, _ = NativeWebEndpoint(request.parameters.get("url"), check_id=check_id)
        timeout = RequestTimeout(request.parameters["timeout_seconds"])
        suffix: tuple[str, ...] = ()
        workspace_id = None

        if check_id == NATIVE_FILE_CANARY_CHECK_ID:
            template = RequestTemplate.FromDict(JsonValue(
                request.parameters.get("request_template")))
            workspace_id = template.endpoint.workspace_id
            suffix = (check_id, workspace_id)

        if JsonValue(request.parameters) != NativeWebParameters(target.value, timeout,
            check_id=check_id, workspace_id=workspace_id):
            raise ValueError("native web request differs from its exact check profile")

        if request.target_reference != target.Reference():
            raise ValueError("native web request must bind its exact URL")

        return AdapterInvocation(
            NATIVE_WEB_PROVIDER_ID, request,
            (sys.executable, "-I", "-m", "fuzzy1337.native_web_worker", target.value,
             str(timeout), *suffix),
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

        parameters = report.invocation.request.parameters
        check = NativeWebCheckFor(str(parameters.get("check_id", NATIVE_WEB_CHECK_ID)))
        workspace_id = None

        if check.check_id == NATIVE_FILE_CANARY_CHECK_ID:
            workspace_id = RequestTemplate.FromDict(JsonValue(
                parameters["request_template"])).endpoint.workspace_id

        record = ParseNativeWebRecord(values[0], str(parameters["url"]),
                                      check_id=check.check_id, workspace_id=workspace_id)

        if "error" in record:
            raise NativeWebRecordError("a failed response check cannot produce findings")

        subject = report.invocation.request.target_reference
        attributes = {key: record[key] for key in (
            "check_id", "profile_version", "status", "media_type", "body_bytes", "body_sha256",
            "matched",
        )}

        if check.check_id == NATIVE_FILE_CANARY_CHECK_ID:
            attributes.update({key: record[key] for key in (
                "request_profile", "request_reference", "injection_reference",
            )})

        findings = (NormalizedFinding(
            check.finding_id, subject, check.title,
            {"check_id": check.check_id, "severity": "low"},
        ),) if record["matched"] else ()

        return AdapterResult(report, (
            NormalizedObservation("native.web-response-check", subject, attributes),
        ), findings=findings)
