# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure bounded crawl admission and original-report normalization, without authority or I/O."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections.abc import Callable, Mapping
from typing import Literal, TypedDict, cast
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
    SerializeContract,
)
from fuzzy1337.adapters.contracts import JsonValue, RequireIdentifier
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.scope import Target, TargetKind

NATIVE_CRAWL_PROVIDER_ID = "native.crawl"
NATIVE_CRAWL_CAPABILITY = "http.owned-loopback-crawl"
NATIVE_CRAWL_VERSION = "1"
NATIVE_CRAWL_PROFILE = "owned-loopback-content-crawl.v1"
MAX_INPUT_BYTES = 24576
MAX_RECORD_BYTES = 65536
MAX_BODY_BYTES = 65536
MAX_HEADER_BYTES = 16384
MAX_HEADER_FIELDS = 64
MAX_LINE_BYTES = 4096
MAX_REQUEST_BYTES = 2048
MAX_ANCHORS = 1024
EXCLUSION_CODES = (
    "missing-href", "invalid-url", "fragment-only", "non-http", "credentials", "query",
    "off-origin", "unsupported-path", "source-target", "not-admitted",
)
ERROR_CODES = frozenset({"input", "connection", "timeout", "protocol", "response-policy",
                         "html-policy", "output-limit", "internal"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_FIELDS = {"schema_version", "profile", "workspace_id", "seed_url", "source_url",
                 "selected_urls", "max_body_bytes", "request_timeout_ms"}
_OBSERVED_FIELDS = {"schema_version", "profile", "outcome", "input_sha256",
                    "selected_urls_sha256", "source", "response", "frontier"}
_DESCRIPTOR = AdapterDescriptor(NATIVE_CRAWL_PROVIDER_ID, "Owned loopback content crawl",
    NATIVE_CRAWL_VERSION, (NATIVE_CRAWL_CAPABILITY,), ImpactLevel.SAFE)


class CrawlInput(TypedDict):
    """Detached exact immutable-invocation input; scope and actors remain parent-owned."""

    schema_version: int
    profile: str
    workspace_id: str
    seed_url: str
    source_url: str
    selected_urls: list[str]
    max_body_bytes: int
    request_timeout_ms: int


class CrawlSource(TypedDict):
    """Selected request identity and worker-attributed actual peer/request facts."""

    url: str
    address: str
    port: int
    request_reference: str
    endpoint_reference: str
    request_size_bytes: int
    request_sha256: str


class CrawlResponse(TypedDict):
    """Complete admitted response metadata, never original header/body custody."""

    http_version: str
    status: int
    media_type: str
    header_bytes: int
    header_fields: int
    body_bytes: int
    body_sha256: str


class CrawlEntry(TypedDict):
    """One admitted selected lexical candidate with complete occurrence attribution."""

    url: str
    request_reference: str
    endpoint_reference: str
    ordinals: list[int]


class CrawlFrontier(TypedDict):
    """Complete selected-only lexical interpretation or an exact empty terminal frontier."""

    complete: bool
    anchor_count: int
    entries: list[CrawlEntry]
    exclusion_counts: dict[str, int]


class CrawlObservedRecord(TypedDict):
    """An attributed successful worker observation, without execution permission."""

    schema_version: int
    profile: str
    outcome: Literal["html", "non-html", "client-error"]
    input_sha256: str
    selected_urls_sha256: str
    source: CrawlSource
    response: CrawlResponse
    frontier: CrawlFrontier


class CrawlRefusedRecord(TypedDict):
    """Closed safe refusal without selected or rejected response material."""

    schema_version: int
    profile: str
    outcome: Literal["refused"]
    error: str


CrawlRecord = CrawlObservedRecord | CrawlRefusedRecord


class NativeCrawlRecordError(ValueError):
    """Input or original worker metadata cannot establish the declared finite observation."""


def CrawlInteger(value: object, minimum: int, maximum: int) -> int:
    """Require an exact finite integer.

    Args:
        value: Untrusted primitive.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.

    Returns:
        The exact admitted integer.
    """

    if type(value) is not int or not minimum <= value <= maximum:
        raise NativeCrawlRecordError("crawl integer is outside its admitted bounds")

    return value


def CrawlText(value: object, maximum: int = MAX_RECORD_BYTES) -> str:
    """Require bounded single-line ASCII without exposing rejected text.

    Args:
        value: Untrusted text primitive.
        maximum: Inclusive character and byte bound.

    Returns:
        Original exact ASCII text.
    """

    if type(value) is not str or not 1 <= len(value) <= maximum or not value.isascii() or (
        any(character in value for character in "\r\n\x00")
    ):
        raise NativeCrawlRecordError("crawl text is outside its admitted bounds")

    return value


def CrawlObject(value: object, fields: set[str]) -> dict[str, object]:
    """Require a closed exact JSON object.

    Args:
        value: Decoded untrusted value.
        fields: Entire allowed and required key set.

    Returns:
        The original dictionary with verified keys.
    """

    if type(value) is not dict or value.keys() != fields:
        raise NativeCrawlRecordError("crawl object has an unsupported shape")

    return cast(dict[str, object], value)


def BoundCrawlTree(value: object) -> None:
    """Bound metadata before recursive canonical rendering or interpretation.

    Args:
        value: JSON or already frozen adapter metadata.
    """

    pending = [(value, 1)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 4096 or depth > 8:
            raise NativeCrawlRecordError("crawl JSON exceeds its finite tree budget")

        if isinstance(item, Mapping):
            if len(item) > 4096:
                raise NativeCrawlRecordError("crawl JSON exceeds its finite tree budget")

            for key, child in item.items():
                CrawlText(key)
                pending.append((child, depth + 1))

        elif type(item) in (list, tuple):
            sequence = cast(list[object] | tuple[object, ...], item)

            if len(sequence) > 4096:
                raise NativeCrawlRecordError("crawl JSON exceeds its finite tree budget")

            pending.extend((child, depth + 1) for child in sequence)

        elif type(item) is str:
            CrawlText(item)

        elif item is not None and type(item) not in (int, bool):
            raise NativeCrawlRecordError("crawl JSON has an unsupported primitive")


def CanonicalCrawlJson(value: Mapping[str, object], maximum: int) -> bytes:
    """Serialize bounded metadata without widening semantic admission.

    Args:
        value: Explicit mapping with finite JSON values.
        maximum: Complete encoded byte ceiling.

    Returns:
        Sorted compact ASCII JSON with no newline.
    """

    BoundCrawlTree(value)

    try:
        raw = SerializeContract(value).encode("ascii")

    except (ValueError, RecursionError, UnicodeError, TypeError):
        raise NativeCrawlRecordError("crawl metadata is not canonical JSON") from None

    if not 1 <= len(raw) <= maximum:
        raise NativeCrawlRecordError("crawl JSON exceeds its byte budget")

    return raw


def CanonicalRecord(value: Mapping[str, object]) -> bytes:
    """Encode one bounded record; callers still require semantic record admission.

    Args:
        value: Explicit finite JSON mapping.

    Returns:
        Canonical ASCII bytes, at most 65536, without newline or BOM.
    """

    return CanonicalCrawlJson(value, MAX_RECORD_BYTES)


def UniqueCrawlObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse duplicate keys before JSON loses their ambiguity.

    Args:
        pairs: Original decoder object members.

    Returns:
        The unique original dictionary.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise NativeCrawlRecordError("crawl JSON has duplicate fields")

        result[key] = value

    return result


def RejectCrawlNumber(_value: str) -> object:
    """Refuse floats and nonstandard constants without echoing their tokens.

    Args:
        _value: Untrusted decoder token, deliberately discarded.

    Returns:
        Never returns; all such numeric tokens are unsupported.
    """

    raise NativeCrawlRecordError("crawl JSON requires exact integer numbers")


def ReadCrawlJson(raw: bytes, maximum: int) -> dict[str, object]:
    """Read strict canonical metadata under independent byte and tree bounds.

    Args:
        raw: Complete original bytes.
        maximum: Inclusive input or output byte bound.

    Returns:
        Detached unique canonical object.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise NativeCrawlRecordError("crawl JSON exceeds its byte budget")

    try:
        value: object = json.loads(raw.decode("ascii"), object_pairs_hook=UniqueCrawlObject,
                                   parse_float=RejectCrawlNumber, parse_constant=RejectCrawlNumber)

        if type(value) is not dict or CanonicalCrawlJson(value, maximum) != raw:
            raise NativeCrawlRecordError("crawl JSON is not canonical")

    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise NativeCrawlRecordError("crawl JSON is not an admitted canonical object") from None

    return cast(dict[str, object], value)


def CrawlEndpoint(url: object) -> tuple[Target, str, int, str, str]:
    """Validate the exact selected literal-loopback HTTP destination without DNS.

    Args:
        url: Already canonical anonymous concrete selected URL.

    Returns:
        Target, literal IP, effective port, exact path and Host authority.
    """

    value = CrawlText(url, 2048)

    try:
        parsed = urlsplit(value)
        target = Target(TargetKind.URL, value)
        address = parsed.hostname
        port = parsed.port or 80

        if value != target.value or parsed.scheme != "http" or (
            address not in {"127.0.0.1", "::1"} or "?" in value or "#" in value
            or parsed.username is not None or parsed.password is not None
            or "%" in parsed.path or "{" in parsed.path or "}" in parsed.path
        ):
            raise ValueError

        Endpoint("crawl", "http://" + parsed.netloc, parsed.path)

    except ValueError:
        raise NativeCrawlRecordError("crawl requires an exact selected loopback HTTP URL") from None

    return target, address, port, parsed.path, parsed.netloc


def CrawlTemplate(workspace_id: str, url: str) -> RequestTemplate:
    """Recompute the anonymous structural request using the existing request owner.

    Args:
        workspace_id: Existing explicit non-secret workspace identifier.
        url: Exact admitted selected URL.

    Returns:
        Concrete anonymous GET without values, session or body.
    """

    workspace = CrawlText(workspace_id, 64)

    try:
        RequireIdentifier(workspace, "workspace_id")
        _, _, _, path, authority = CrawlEndpoint(url)

        return RequestTemplate(Endpoint(workspace, "http://" + authority, path))

    except ValueError:
        raise NativeCrawlRecordError("crawl request identity is unsupported") from None


def CrawlRequestBytes(url: str) -> bytes:
    """Construct the sole exact request without automatic or caller headers.

    Args:
        url: Exact admitted selected URL.

    Returns:
        Complete anonymous request bytes with no body or trailing data.
    """

    _, _, _, path, authority = CrawlEndpoint(url)
    raw = (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n"
           "Accept: text/html, text/plain, application/octet-stream\r\n"
           "Accept-Encoding: identity\r\n\r\n").encode("ascii")

    if len(raw) > MAX_REQUEST_BYTES:
        raise NativeCrawlRecordError("crawl request exceeds its byte budget")

    return raw


def CheckCrawlInput(value: object) -> CrawlInput:
    """Admit every input field before canonical invocation construction.

    Args:
        value: Detached closed JSON input object.

    Returns:
        Fully checked detached typed input.
    """

    data = CrawlObject(value, _INPUT_FIELDS)
    CrawlInteger(data["schema_version"], 1, 1)

    if data["profile"] != NATIVE_CRAWL_PROFILE:
        raise NativeCrawlRecordError("crawl input profile is unsupported")

    workspace = CrawlText(data["workspace_id"], 64)
    seed = CrawlText(data["seed_url"], 2048)
    source = CrawlText(data["source_url"], 2048)
    selected = data["selected_urls"]

    if type(selected) is not list or not 1 <= len(selected) <= 16:
        raise NativeCrawlRecordError("crawl requires a finite exact selected set")

    urls = [CrawlText(item, 2048) for item in selected]

    if urls != sorted(set(urls)) or seed not in urls or source not in urls:
        raise NativeCrawlRecordError("crawl selection is duplicated, unsorted or incomplete")

    origin = CrawlTemplate(workspace, seed).endpoint.origin

    for url in urls:
        if CrawlTemplate(workspace, url).endpoint.origin != origin:
            raise NativeCrawlRecordError("crawl selection origins differ")

        CrawlRequestBytes(url)

    CrawlInteger(data["max_body_bytes"], 1, MAX_BODY_BYTES)
    CrawlInteger(data["request_timeout_ms"], 50, 5000)

    return cast(CrawlInput, data)


def EncodeCrawlInput(parameters: Mapping[str, object]) -> bytes:
    """Bind the existing frozen adapter metadata to one admitted immutable argument.

    Args:
        parameters: Entire crawl input object, including frozen adapter mappings/tuples.

    Returns:
        Canonical complete ASCII argument bytes, at most 24576.
    """

    BoundCrawlTree(parameters)
    data = CheckCrawlInput(JsonValue(parameters))

    return CanonicalCrawlJson(data, MAX_INPUT_BYTES)


def ParseCrawlInput(raw: bytes) -> CrawlInput:
    """Independently admit the original worker argument without granting execution.

    Args:
        raw: Entire original canonical argument bytes.

    Returns:
        Fully checked detached input with no authority fields.
    """

    return CheckCrawlInput(ReadCrawlJson(raw, MAX_INPUT_BYTES))


def BuildCrawlInput(
    workspace_id: str, seed_url: str, source_url: str, selected_urls: tuple[str, ...],
    *, max_body_bytes: int = 16384, request_timeout_ms: int = 3000,
) -> CrawlInput:
    """Build one exact input from explicitly selected non-secret metadata.

    Args:
        workspace_id: Existing owning workspace identifier.
        seed_url: Exact original seed selected by the caller.
        source_url: Current exact selected page.
        selected_urls: Sorted distinct immutable admitted same-origin set.
        max_body_bytes: Complete body/allocation quota from 1 through 65536.
        request_timeout_ms: Shared request milliseconds from 50 through 5000.

    Returns:
        Detached admitted input suitable for AdapterRequest.parameters.
    """

    if type(selected_urls) is not tuple:
        raise NativeCrawlRecordError("crawl selection requires an exact immutable tuple")

    data = {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
        "workspace_id": workspace_id, "seed_url": seed_url, "source_url": source_url,
        "selected_urls": list(selected_urls), "max_body_bytes": max_body_bytes,
        "request_timeout_ms": request_timeout_ms}

    return ParseCrawlInput(EncodeCrawlInput(data))


def CrawlDigest(value: object) -> str:
    """Validate an attributed digest without claiming absent original bytes.

    Args:
        value: Untrusted digest primitive.

    Returns:
        Exact lowercase SHA-256 text.
    """

    text = CrawlText(value, 64)

    if _SHA256.fullmatch(text) is None:
        raise NativeCrawlRecordError("crawl digest is unsupported")

    return text


def CheckCrawlResponse(value: object, selection: CrawlInput, outcome: str) -> CrawlResponse:
    """Check complete admitted response dimensions and terminal semantics.

    Args:
        value: Untrusted response facts.
        selection: Original admitted invocation input.
        outcome: Selected admitted record branch.

    Returns:
        Strict response facts, without reconstructing absent bodies or headers.
    """

    data = CrawlObject(value, {"http_version", "status", "media_type", "header_bytes",
                           "header_fields", "body_bytes", "body_sha256"})
    version = CrawlText(data["http_version"], 8)
    media = CrawlText(data["media_type"], 24)
    status = CrawlInteger(data["status"], 200, 499)
    size = CrawlInteger(data["body_bytes"], 0, selection["max_body_bytes"])
    count = CrawlInteger(data["header_fields"], 2, MAX_HEADER_FIELDS)
    digest = CrawlDigest(data["body_sha256"])

    if version not in {"HTTP/1.0", "HTTP/1.1"} or media not in {
        "text/html", "text/plain", "application/octet-stream",
    } or (size == 0 and digest != hashlib.sha256(b"").hexdigest()):
        raise NativeCrawlRecordError("crawl response facts are unsupported")

    if (outcome == "html" and (status != 200 or media != "text/html")) or (
        outcome == "non-html" and (status != 200 or media == "text/html")
    ) or (outcome == "client-error" and not 400 <= status <= 499):
        raise NativeCrawlRecordError("crawl response differs from its declared outcome")

    minimum = len(f"{version} {status} \r\nContent-Length:{size}\r\nContent-Type:{media}"
                  "\r\n\r\n".encode("ascii")) + 4 * (count - 2)
    CrawlInteger(data["header_bytes"], minimum, min(MAX_HEADER_BYTES,
                                              MAX_LINE_BYTES * (count + 1) + 2))

    return cast(CrawlResponse, data)


def CheckCrawlFrontier(value: object, selection: CrawlInput, outcome: str) -> CrawlFrontier:
    """Validate selected-only candidates, canonical identities and complete ordinal accounting.

    Args:
        value: Untrusted complete frontier object.
        selection: Exact original immutable selection.
        outcome: HTML or terminal admitted outcome.

    Returns:
        Strict complete frontier with no unselected URLs.
    """

    data = CrawlObject(value, {"complete", "anchor_count", "entries", "exclusion_counts"})
    anchors = CrawlInteger(data["anchor_count"], 0, MAX_ANCHORS)
    counters = CrawlObject(data["exclusion_counts"], set(EXCLUSION_CODES))
    excluded = sum(CrawlInteger(item, 0, MAX_ANCHORS) for item in counters.values())
    entries = data["entries"]

    if data["complete"] is not True or type(entries) is not list or len(entries) > 15:
        raise NativeCrawlRecordError("crawl frontier is incomplete or excessive")

    urls: list[str] = []
    used: set[int] = set()

    for value_entry in entries:
        entry = CrawlObject(value_entry, {
            "url", "request_reference", "endpoint_reference", "ordinals"})
        url = CrawlText(entry["url"], 2048)

        if url not in selection["selected_urls"] or url == selection["source_url"]:
            raise NativeCrawlRecordError("crawl candidate is not in its admitted selection")

        template = CrawlTemplate(selection["workspace_id"], url)

        if entry["request_reference"] != template.Reference() or (
            entry["endpoint_reference"] != template.endpoint.Identity().Reference()
        ):
            raise NativeCrawlRecordError("crawl candidate identity differs")

        ordinals = entry["ordinals"]

        if type(ordinals) is not list or not 1 <= len(ordinals) <= MAX_ANCHORS:
            raise NativeCrawlRecordError("crawl candidate occurrences are unsupported")

        checked = [CrawlInteger(item, 1, anchors) for item in ordinals]

        if checked != sorted(set(checked)) or used.intersection(checked):
            raise NativeCrawlRecordError("crawl occurrence attribution is ambiguous")

        used.update(checked)
        urls.append(url)

    if urls != sorted(set(urls)) or len(used) + excluded != anchors or (
        outcome != "html" and (anchors != 0 or entries or excluded != 0)
    ):
        raise NativeCrawlRecordError("crawl frontier accounting or terminal state differs")

    return cast(CrawlFrontier, data)


def ParseCrawlRecord(raw: bytes, expected_input: Mapping[str, object]) -> CrawlRecord:
    """Verify original canonical worker metadata and all independently recomputable joins.

    Args:
        raw: Complete original bounded stdout, never fabricated response bytes.
        expected_input: Original owning invocation's entire exact parameters.

    Returns:
        Strict admitted observation or closed refusal for parent failure classification.
    """

    input_bytes = EncodeCrawlInput(expected_input)
    selection = ParseCrawlInput(input_bytes)
    data = ReadCrawlJson(raw, MAX_RECORD_BYTES)
    CrawlInteger(data.get("schema_version"), 1, 1)

    if data.get("profile") != NATIVE_CRAWL_PROFILE:
        raise NativeCrawlRecordError("crawl record profile is unsupported")

    if data.get("outcome") == "refused":
        CrawlObject(data, {"schema_version", "profile", "outcome", "error"})

        if CrawlText(data["error"], 24) not in ERROR_CODES:
            raise NativeCrawlRecordError("crawl refusal classification is unsupported")

        return cast(CrawlRefusedRecord, data)

    CrawlObject(data, _OBSERVED_FIELDS)
    outcome = CrawlText(data["outcome"], 16)

    if outcome not in {"html", "non-html", "client-error"} or (
        CrawlDigest(data["input_sha256"]) != hashlib.sha256(input_bytes).hexdigest()
        or CrawlDigest(data["selected_urls_sha256"]) != hashlib.sha256(
            SerializeContract(selection["selected_urls"]).encode("ascii")).hexdigest()
    ):
        raise NativeCrawlRecordError("crawl record differs from its original input")

    _, address, port, _, _ = CrawlEndpoint(selection["source_url"])
    template = CrawlTemplate(selection["workspace_id"], selection["source_url"])
    request = CrawlRequestBytes(selection["source_url"])
    expected_source = {"url": selection["source_url"], "address": address, "port": port,
        "request_reference": template.Reference(),
        "endpoint_reference": template.endpoint.Identity().Reference(),
        "request_size_bytes": len(request), "request_sha256": hashlib.sha256(request).hexdigest()}
    source = CrawlObject(data["source"], set(expected_source))

    if any(type(source[key]) is not type(item) or source[key] != item
           for key, item in expected_source.items()):
        raise NativeCrawlRecordError("crawl source, peer or request identity differs")

    response = CheckCrawlResponse(data["response"], selection, outcome)
    frontier = CheckCrawlFrontier(data["frontier"], selection, outcome)

    if response["body_bytes"] == 0 and frontier["anchor_count"] != 0:
        raise NativeCrawlRecordError("an empty crawl body cannot contain anchor slots")

    return cast(CrawlObservedRecord, data)


class NativeCrawlAdapter:
    """Prepare one fixed SAFE worker and normalize verified original streams without storage."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes]) -> None:
        """Bind the existing evidence reader without accessing any source or target.

        Args:
            evidence_reader: Owning immutable store reader, not a file locator loader.
        """

        self._read_evidence = evidence_reader

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return finite provider metadata without authority or target contact.

        Returns:
            The fixed packaged SAFE crawl capability.
        """

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Describe the packaged provider without a probe or installation.

        Returns:
            Packaged provider availability and contract version.
        """

        return AdapterHealth(NATIVE_CRAWL_PROVIDER_ID, AdapterHealthState.AVAILABLE,
                             NATIVE_CRAWL_VERSION)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Bind one immutable selected-only argument to the isolated fixed packaged worker.

        Args:
            request: Exact SAFE capability request without credentials or extra parameters.

        Returns:
            Shell-free invocation with its startup-inclusive finite timeout.
        """

        if type(request) is not AdapterRequest or request.capability != NATIVE_CRAWL_CAPABILITY or (
            request.impact is not ImpactLevel.SAFE or request.credential_references
        ):
            raise NativeCrawlRecordError("crawl requires its exact anonymous SAFE capability")

        raw = EncodeCrawlInput(request.parameters)
        selection = ParseCrawlInput(raw)

        if request.target_reference != Target(TargetKind.URL, selection["source_url"]).Reference():
            raise NativeCrawlRecordError("crawl request target differs from its exact source")

        return AdapterInvocation(NATIVE_CRAWL_PROVIDER_ID, request,
            (sys.executable, "-I", "-m", "fuzzy1337.native_crawl_worker", raw.decode("ascii")),
            math.ceil(selection["request_timeout_ms"] / 1000) + 1, NATIVE_CRAWL_VERSION)

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Normalize only exact successful execution and both verified original streams.

        Args:
            report: Actual executor-owned report and original stdout/empty-stderr references.

        Returns:
            Attributed response/link observations; no Findings, model writes or authority.
        """

        try:
            if type(report) is not AdapterReport or (
                report.invocation != self.PrepareInvocation(report.invocation.request)
                or report.execution.state is not ExecutionState.SUCCEEDED
                or type(report.execution.exit_code) is not int or report.execution.exit_code != 0
                or type(report.execution.duration_seconds) not in (int, float)
                or not math.isfinite(report.execution.duration_seconds)
                or report.execution.duration_seconds < 0 or len(report.evidence) != 2
                or tuple(item.role for item in report.evidence) != ("stdout", "stderr")
            ):
                raise NativeCrawlRecordError(
                    "crawl report is not its original successful execution")

            streams: list[bytes] = []

            for reference in report.evidence:
                maximum = MAX_RECORD_BYTES if reference.role == "stdout" else 0

                if type(reference) is not EvidenceReference or reference.size_bytes > maximum:
                    raise NativeCrawlRecordError("crawl original stream exceeds its bound")

                raw = self._read_evidence(reference)

                if type(raw) is not bytes or len(raw) != reference.size_bytes or (
                    hashlib.sha256(raw).hexdigest() != reference.sha256
                ):
                    raise NativeCrawlRecordError("crawl original evidence binding differs")

                streams.append(raw)

            record = ParseCrawlRecord(streams[0], report.invocation.request.parameters)

            if record["outcome"] == "refused":
                raise NativeCrawlRecordError("crawl refusal cannot become a successful observation")

        except Exception:
            raise NativeCrawlRecordError("crawl original report is unadmitted") from None

        source = record["source"]
        frontier = record["frontier"]
        shared = {"input_sha256": record["input_sha256"],
                  "selected_urls_sha256": record["selected_urls_sha256"]}
        observations = [NormalizedObservation("web.owned-crawl-response",
            report.invocation.request.target_reference, {**shared, "source": source,
                "response": record["response"], "outcome": record["outcome"],
                "anchor_count": frontier["anchor_count"],
                "exclusion_counts": frontier["exclusion_counts"]})]

        for entry in frontier["entries"]:
            observations.append(NormalizedObservation("web.owned-crawl-link",
                Target(TargetKind.URL, entry["url"]).Reference(), {**shared,
                    "source_target_reference": report.invocation.request.target_reference,
                    "source_request_reference": source["request_reference"],
                    "source_endpoint_reference": source["endpoint_reference"],
                    "candidate_request_reference": entry["request_reference"],
                    "candidate_endpoint_reference": entry["endpoint_reference"],
                    "source_ordinals": entry["ordinals"]}))

        return AdapterResult(report, tuple(observations))
