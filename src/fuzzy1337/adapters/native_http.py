# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded native HTTP preparation and verified non-sensitive record normalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import sys
from collections.abc import Callable
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
    NormalizedObservation,
    ObjectEnrichment,
    RelationEnrichment,
)
from fuzzy1337.scope import Target, TargetKind

DISCOVERY_VERSION = "1"
NATIVE_HTTP_PROVIDER_ID = "native.http"
NATIVE_HTTP_CAPABILITY = "http.endpoint-discovery"
NATIVE_HTTP_MAX_RECORD_BYTES = 4096
NATIVE_HTTP_MAX_URL_BYTES = 2048
NATIVE_HTTP_MAX_REQUEST_SECONDS = 10
NATIVE_HTTP_ERROR_CODES = frozenset({"timeout", "connection", "protocol", "tls", "input"})

__all__ = [
    "DISCOVERY_VERSION", "NATIVE_HTTP_PROVIDER_ID", "NATIVE_HTTP_CAPABILITY",
    "NATIVE_HTTP_MAX_RECORD_BYTES", "NATIVE_HTTP_MAX_URL_BYTES",
    "NATIVE_HTTP_MAX_REQUEST_SECONDS", "NATIVE_HTTP_ERROR_CODES", "NativeHttpAdapter",
    "NativeHttpRecordError", "Endpoint", "RequestTimeout", "ParseRecord",
]

_DESCRIPTOR = AdapterDescriptor(
    NATIVE_HTTP_PROVIDER_ID, "Native HTTP discovery", DISCOVERY_VERSION,
    (NATIVE_HTTP_CAPABILITY,), ImpactLevel.SAFE,
)


class NativeHttpRecordError(ValueError):
    """Native output cannot safely produce attributable discovery facts."""


def Endpoint(value: object) -> tuple[Target, str, int, str]:
    """Validate one bounded unicast literal-IP URL without resolving any host.

    Args:
        value: Explicit HTTP(S) URL without credentials or fragments.

    Returns:
        Canonical URL target, literal IP, explicit/default port and scheme.

    Raises:
        ValueError: URL/address shape or resource bounds are unsupported.
    """

    if not isinstance(value, str):
        raise ValueError("native HTTP URL must be bounded text")

    try:
        if len(value.encode("utf-8")) > NATIVE_HTTP_MAX_URL_BYTES:
            raise ValueError("endpoint input exceeds its bound")

        target = Target(TargetKind.URL, value)
        parsed = urlsplit(target.value)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port or {"http": 80, "https": 443}[parsed.scheme]

        if len(target.value.encode("ascii")) > NATIVE_HTTP_MAX_URL_BYTES or parsed.query:
            raise ValueError("canonical endpoint is oversized or query-bearing")

        if address.is_unspecified or address.is_multicast or (
            address == ipaddress.IPv4Address("255.255.255.255")
        ) or (isinstance(address, ipaddress.IPv6Address) and (
            address.scope_id is not None or address.ipv4_mapped is not None
        )):
            raise ValueError("endpoint address is unsupported")

    except ValueError:
        # URL/IP parser errors can echo target tokens; do not surface their text.
        pass

    else:
        return target, str(address), port, parsed.scheme

    raise ValueError("native HTTP requires a bounded unscoped unicast literal-IP URL")


def RequestTimeout(value: object) -> float:
    """Require a finite per-probe deadline from 0.05 through ten seconds.

    Args:
        value: Approved request timeout in seconds, excluding booleans.

    Returns:
        Validated timeout as a float.

    Raises:
        ValueError: The timeout is nonnumeric, nonfinite or outside hard bounds.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)) or (
        not 0.05 <= value <= NATIVE_HTTP_MAX_REQUEST_SECONDS or not math.isfinite(value)
    ):
        raise ValueError("native HTTP timeout_seconds must be from 0.05 through 10")

    return float(value)


def ParseRecord(raw: bytes, url: str) -> dict[str, object]:
    """Reject untrusted fields and destinations before bytes enter evidence or model state.

    Args:
        raw: Bounded exact worker stdout, containing one strict schema-v1 JSON record.
        url: Approved canonical target used to bind successful observations.

    Returns:
        Validated successful observation or a fixed-code failure record.

    Raises:
        NativeHttpRecordError: Bytes, schema, shape, destination or status are invalid.
    """

    if not isinstance(raw, bytes) or len(raw) > NATIVE_HTTP_MAX_RECORD_BYTES:
        raise NativeHttpRecordError("native HTTP record exceeds the byte budget")

    def Object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject ambiguous duplicate fields while decoding the sole flat record."""

        result: dict[str, object] = {}

        for key, item in pairs:
            if key in result:
                raise NativeHttpRecordError("native HTTP record has duplicate fields")

            result[key] = item

        return result

    def Constant(value: str) -> object:
        """Reject nonstandard JSON numeric constants at the decoder boundary."""

        raise NativeHttpRecordError("native HTTP record contains a nonfinite value")

    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=Object,
                            parse_constant=Constant)

    except (ValueError, RecursionError):
        record = None

    if record is None:
        raise NativeHttpRecordError("native HTTP record must be strict UTF-8 JSON")

    if not isinstance(record, dict) or type(record.get("schema_version")) is not int or (
        record["schema_version"] != 1
    ):
        raise NativeHttpRecordError("native HTTP record requires schema version 1")

    if "error" in record:
        if set(record) != {"schema_version", "error"} or (
            not isinstance(record["error"], str) or record["error"] not in NATIVE_HTTP_ERROR_CODES
        ):
            raise NativeHttpRecordError("native HTTP error record must use a fixed safe code")

        return record

    target, address, port, scheme = Endpoint(url)

    status = record.get("status")

    if set(record) != {"schema_version", "url", "address", "port", "scheme", "status"} or (
        record.get("url") != target.value or record.get("address") != address
        or type(record.get("port")) is not int or record["port"] != port
        or record.get("scheme") != scheme or type(status) is not int
        or not 200 <= status <= 599
    ):
        raise NativeHttpRecordError("native HTTP record differs from the approved endpoint")

    return record


class NativeHttpAdapter:
    """First-party SAFE literal-endpoint worker adapter; preparation grants no authority."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes]) -> None:
        """Bind the existing verified evidence reader without probing a target.

        Args:
            evidence_reader: Immutable owned-store reader; never a filesystem locator loader.
        """

        self._read_evidence = evidence_reader

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return finite SAFE capability metadata without starting execution.

        Returns:
            Native worker identity, version and declared SAFE endpoint capability.
        """

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Declare the packaged first-party worker without external tool discovery.

        Returns:
            Packaged provider availability, without probing a target or granting authority.
        """

        return AdapterHealth(
            NATIVE_HTTP_PROVIDER_ID, AdapterHealthState.AVAILABLE, DISCOVERY_VERSION,
        )

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Prepare one exact shell-free literal endpoint probe under hard timeout bounds.

        Args:
            request: SAFE http.endpoint-discovery request with url and timeout_seconds only.

        Returns:
            Current interpreter worker argv and bounded startup-inclusive executor timeout.

        Raises:
            ValueError: Capability, impact, credentials, target or parameters are unsupported.
        """

        if request.capability != NATIVE_HTTP_CAPABILITY or request.impact is not ImpactLevel.SAFE:
            raise ValueError("native HTTP requires the SAFE endpoint-discovery capability")

        if request.credential_references or set(request.parameters) != {"url", "timeout_seconds"}:
            raise ValueError("native HTTP accepts only url and timeout_seconds without credentials")

        target, _, _, _ = Endpoint(request.parameters["url"])
        timeout = RequestTimeout(request.parameters["timeout_seconds"])

        if request.target_reference != target.Reference():
            raise ValueError("native HTTP target_reference must identify the exact URL")

        return AdapterInvocation(
            NATIVE_HTTP_PROVIDER_ID, request,
            (sys.executable, "-m", "fuzzy1337.native_http_worker", target.value, str(timeout)),
            math.ceil(timeout + 1), DISCOVERY_VERSION,
        )

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Normalize only successful verified worker evidence into SDK sensor envelopes.

        Args:
            report: Actual governed invocation, successful execution and sole stdout reference.

        Returns:
            Host/port/service/endpoint observations and relations, with no findings or storage.

        Raises:
            NativeHttpRecordError: Invocation, output, evidence, outcome or binding is invalid.
            ValueError: The recorded request violates the preparation contract.
        """

        if report.invocation != self.PrepareInvocation(report.invocation.request) or (
            report.execution.state is not ExecutionState.SUCCEEDED
        ):
            raise NativeHttpRecordError(
                "native HTTP report must match successful prepared execution",
            )

        if len(report.evidence) != 1 or report.evidence[0].role != "stdout":
            raise NativeHttpRecordError("native HTTP report requires exactly one stdout reference")

        reference = report.evidence[0]

        if reference.size_bytes > NATIVE_HTTP_MAX_RECORD_BYTES:
            raise NativeHttpRecordError("native HTTP evidence exceeds the byte budget")

        raw = self._read_evidence(reference)

        if len(raw) != reference.size_bytes or hashlib.sha256(raw).hexdigest() != reference.sha256:
            raise NativeHttpRecordError("native HTTP evidence bytes differ from their reference")

        record = ParseRecord(raw, str(report.invocation.request.parameters["url"]))

        if "error" in record:
            raise NativeHttpRecordError("a native HTTP error cannot become successful discovery")

        host = "host:" + str(record["address"])
        port = f"{host}/tcp/{record['port']}"
        service = port + "/service"
        endpoint = report.invocation.request.target_reference
        objects = (
            ObjectEnrichment("host", host, {"address": record["address"], "state": "up"}),
            ObjectEnrichment("port", port, {
                "protocol": "tcp", "number": record["port"], "state": "open",
            }),
            ObjectEnrichment("service", service, {"name": record["scheme"]}),
            ObjectEnrichment("endpoint", endpoint, {
                "url": record["url"], "method": "GET", "status": record["status"],
            }),
        )
        relations = (
            RelationEnrichment("has-port", host, port),
            RelationEnrichment("hosts-service", port, service),
            RelationEnrichment("exposes", service, endpoint),
        )

        return AdapterResult(
            report, (NormalizedObservation("http.response", endpoint, {
                "status": record["status"], "redirect_followed": False,
            }),), object_enrichments=objects, relation_enrichments=relations,
        )
