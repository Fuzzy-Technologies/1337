# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional reviewed Nuclei HTTP profiles and evidence-backed JSONL normalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
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
    SerializeContract,
)
from fuzzy1337.adapters.contracts import JsonValue, RequireIdentifier, RequireText

NUCLEI_ADAPTER_VERSION = "1"
NUCLEI_MAX_TEMPLATES = 32
NUCLEI_TEMPLATE_MAX_BYTES = 256 * 1024
NUCLEI_JSONL_MAX_BYTES = 4 * 1024 * 1024
NUCLEI_JSONL_MAX_RECORDS = 4096
NUCLEI_JSONL_MAX_LINE_BYTES = 128 * 1024
NUCLEI_MAX_TIMEOUT_SECONDS = 300
NUCLEI_MAX_RATE_LIMIT = 10
NUCLEI_HEALTH_TIMEOUT_SECONDS = 3
NUCLEI_HEALTH_MAX_BYTES = 16 * 1024

__all__ = [
    "NUCLEI_ADAPTER_VERSION", "NUCLEI_MAX_TEMPLATES", "NUCLEI_TEMPLATE_MAX_BYTES",
    "NUCLEI_JSONL_MAX_BYTES", "NUCLEI_JSONL_MAX_RECORDS", "NUCLEI_JSONL_MAX_LINE_BYTES",
    "NUCLEI_MAX_TIMEOUT_SECONDS", "NUCLEI_MAX_RATE_LIMIT", "NUCLEI_HEALTH_TIMEOUT_SECONDS",
    "NUCLEI_HEALTH_MAX_BYTES", "NucleiTemplate", "NucleiProfile", "NucleiAdapter",
    "NucleiReportError",
]

_DESCRIPTOR = AdapterDescriptor(
    "native.nuclei", "Nuclei", NUCLEI_ADAPTER_VERSION,
    ("web.http-template-check",), ImpactLevel.STANDARD,
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_VERSION_PATTERN = re.compile(r"^3\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z._-]+)?$")
_HEALTH_VERSION_PATTERN = re.compile(
    r"(?:Nuclei Engine Version:|Current nuclei version:|Nuclei version)\s*v?(3\.[0-9]+"
    r"\.[0-9]+(?:[-+][0-9A-Za-z._-]+)?)", re.IGNORECASE,
)
_EMPTY_CONFIG = b"{}\n"
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical", "unknown"})


class NucleiReportError(ValueError):
    """Nuclei raw evidence cannot safely produce normalized findings."""


def RequireArtifactPath(value: str) -> None:
    """Require an explicit local file path without Nuclei list expansion.

    Args:
        value: Operator-selected absolute file path, never a directory or URL.

    Raises:
        ValueError: The path is relative, ambiguous, or contains an option separator.
    """

    RequireText(value, "artifact path")

    if not Path(value).is_absolute() or "," in value or ".." in Path(value).parts:
        raise ValueError("Nuclei artifacts require absolute paths without list expansion")


@dataclass(frozen=True, slots=True)
class NucleiTemplate:
    """Exact locally reviewed YAML artifact and non-secret acquisition provenance.

    The review reference attests to a single HTTP GET at the exact input URL, no
    other protocols, redirects, executable expressions, payload expansion, local
    file access, global matchers, credentials, or external callbacks. Digests
    validate bytes; they do not perform that semantic review or authenticate it.
    """

    template_id: str
    path: str
    sha256: str
    size_bytes: int
    source_reference: str
    source_revision: str
    review_reference: str
    reviewed_profile: str

    def __post_init__(self) -> None:
        """Reject missing provenance or a review for another execution profile."""

        RequireIdentifier(self.template_id, "template_id")
        RequireArtifactPath(self.path)

        if not isinstance(self.sha256, str) or not _SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError("template sha256 must be a lowercase SHA-256 digest")

        RequireInteger(self.size_bytes, 1, NUCLEI_TEMPLATE_MAX_BYTES, "template size")

        for value in (self.source_reference, self.source_revision, self.review_reference):
            RequireText(value, "template provenance")

        if self.reviewed_profile != "single-get-exact-url":
            raise ValueError("Nuclei requires a reviewed single-get-exact-url template")


@dataclass(frozen=True, slots=True)
class NucleiProfile:
    """Trusted finite template set with an explicit empty operator configuration."""

    profile_id: str
    templates: tuple[NucleiTemplate, ...]
    configuration_path: str

    def __post_init__(self) -> None:
        """Freeze a finite reviewed set before any preparation or process invocation."""

        RequireIdentifier(self.profile_id, "profile_id")
        RequireArtifactPath(self.configuration_path)
        templates = tuple(self.templates)

        if not 1 <= len(templates) <= NUCLEI_MAX_TEMPLATES or any(
            not isinstance(item, NucleiTemplate) for item in templates
        ):
            raise ValueError("Nuclei requires a nonempty bounded reviewed template set")

        if len({item.template_id for item in templates}) != len(templates) or (
            len({item.path for item in templates}) != len(templates)
        ):
            raise ValueError("Nuclei template identities and file paths must be unique")

        if self.configuration_path in {item.path for item in templates}:
            raise ValueError("Nuclei configuration cannot alias a template")

        object.__setattr__(self, "templates", templates)

    @property
    def Digest(self) -> str:
        """Bind all template attribution and the empty config into one request digest.

        Returns:
            SHA-256 of deterministic SDK serialization, without accessing files.
        """

        metadata = {
            "profile_id": self.profile_id,
            "templates": self.templates,
            "configuration_path": self.configuration_path,
            "configuration_sha256": hashlib.sha256(_EMPTY_CONFIG).hexdigest(),
        }

        return hashlib.sha256(SerializeContract(metadata).encode("utf-8")).hexdigest()


def RequireInteger(value: object, minimum: int, maximum: int, field_name: str) -> int:
    """Validate a finite integer budget without accepting booleans.

    Args:
        value: Candidate budget.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.
        field_name: Error context.

    Returns:
        Validated integer.

    Raises:
        ValueError: The value is outside the supported bounds.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field_name} must be an integer from {minimum} through {maximum}")

    return value


def CanonicalUrl(value: object) -> str:
    """Require one credential-free HTTP(S) URL with a literal unicast address.

    Args:
        value: Exact authorized URL, including its explicit path.

    Returns:
        Canonical literal URL with an explicit port and no DNS expansion.

    Raises:
        ValueError: The URL has unsupported authority, credentials, or expansion.
    """

    if not isinstance(value, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ) or (
        any(character in value for character in ("\\", ","))
    ):
        raise ValueError("Nuclei requires one explicit HTTP(S) URL")

    try:
        parsed = urlsplit(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        supplied_port = parsed.port
        port = supplied_port if supplied_port is not None else (
            443 if parsed.scheme == "https" else 80
        )

    except ValueError as error:
        raise ValueError("Nuclei URL requires one literal IP and a valid port") from error

    if parsed.scheme not in {"http", "https"} or parsed.username is not None or (
        parsed.password is not None or parsed.fragment or parsed.query
        or "%" in str(address) or address.is_multicast or address.is_unspecified
        or address == ipaddress.IPv4Address("255.255.255.255")
        or not 1 <= port <= 65535
    ):
        raise ValueError("Nuclei URL must be unicast HTTP(S) without credentials/query/fragment")

    host = f"[{address}]" if address.version == 6 else str(address)

    return f"{parsed.scheme}://{host}:{port}{parsed.path or '/'}"


def VerifyArtifact(path: str, sha256: str, size_bytes: int) -> bytes:
    """Read one exact owned regular file and verify its review-bound bytes.

    Args:
        path: Operator-selected absolute path.
        sha256: Expected lowercase digest.
        size_bytes: Exact expected size, also the read budget.

    Returns:
        Verified bytes without following observed filesystem links.

    Raises:
        ValueError: The artifact is missing, linked, changed, or unreadable.
    """

    candidate = Path(path)

    try:
        for component in (*reversed(candidate.parents), candidate):
            metadata = component.lstat()

            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", False):
                raise ValueError("Nuclei artifacts cannot traverse filesystem links")

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Nuclei artifacts must be singly linked regular files")

        with candidate.open("rb") as stream:
            raw = stream.read(size_bytes + 1)

    except OSError as error:
        raise ValueError("Nuclei artifact is unavailable") from error

    if len(raw) != size_bytes or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("Nuclei artifact differs from the reviewed digest/size")

    return raw


def ReadVersion(executable: str) -> AdapterHealth:
    """Run only the local version command with fixed capture and elapsed budgets.

    Args:
        executable: Trusted operator-selected executable, not caller flags.

    Returns:
        Observed Nuclei 3.x availability/version, never scan authority.
    """

    resolved = shutil.which(executable)

    if resolved is None:
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.UNAVAILABLE,
                             detail="Nuclei executable is not available")

    try:
        process = subprocess.Popen(
            (resolved, "-version", "-duc"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, bufsize=0,
        )

    except OSError:
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.UNAVAILABLE,
                             detail="Nuclei version probe could not start")

    assert process.stdout is not None, "PIPE must create a bounded capture handle"
    pipe = process.stdout
    output: list[bytes] = []
    capture_failed = threading.Event()

    def Capture() -> None:
        """Drain a finite version output without accumulating unbounded bytes."""

        remaining = NUCLEI_HEALTH_MAX_BYTES + 1

        try:
            while remaining:
                chunk = os.read(pipe.fileno(), min(4096, remaining))

                if not chunk:
                    break

                output.append(chunk)
                remaining -= len(chunk)

            if not remaining:
                process.kill()

        except (OSError, ValueError):
            capture_failed.set()

    worker = threading.Thread(target=Capture, daemon=True)
    worker.start()
    timed_out = False

    try:
        process.wait(timeout=NUCLEI_HEALTH_TIMEOUT_SECONDS)

    except subprocess.TimeoutExpired:
        timed_out = True

        try:
            process.kill()

        except ProcessLookupError:
            pass

        process.wait(timeout=NUCLEI_HEALTH_TIMEOUT_SECONDS)

    worker.join(timeout=NUCLEI_HEALTH_TIMEOUT_SECONDS)
    pipe.close()
    raw = b"".join(output)
    match = _HEALTH_VERSION_PATTERN.search(raw.decode("utf-8", errors="replace"))

    if timed_out or worker.is_alive() or capture_failed.is_set() or (
        len(raw) > NUCLEI_HEALTH_MAX_BYTES or process.returncode != 0 or match is None
    ):
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.DEGRADED,
                             detail="Nuclei version probe failed its finite 3.x contract")

    return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.AVAILABLE, match[1])


def UniqueJsonObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys rather than silently replacing provider facts.

    Args:
        pairs: One decoded object's original key/value sequence.

    Returns:
        Object preserving the unique provider fields.

    Raises:
        NucleiReportError: A provider object repeats a key.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise NucleiReportError("Nuclei JSONL contains duplicate keys")

        result[key] = value

    return result


def RejectJsonConstant(value: str) -> None:
    """Reject non-standard numeric constants in provider JSON.

    Args:
        value: Non-standard constant supplied by the JSON decoder.

    Raises:
        NucleiReportError: Non-finite JSON is outside the evidence contract.
    """

    raise NucleiReportError(f"Nuclei JSONL contains a non-finite constant: {value}")


def ParseJsonl(raw: bytes) -> tuple[Mapping[str, object], ...]:
    """Decode bounded UTF-8 JSONL while rejecting malformed or ambiguous records.

    Args:
        raw: Verified stdout bytes, including an optional trailing newline.

    Returns:
        Ordered provider objects; empty output means no reported matches.

    Raises:
        NucleiReportError: Byte, record, structural, or JSON validation fails.
    """

    if len(raw) > NUCLEI_JSONL_MAX_BYTES:
        raise NucleiReportError("Nuclei JSONL exceeds the byte budget")

    lines = raw.splitlines()

    if len(lines) > NUCLEI_JSONL_MAX_RECORDS:
        raise NucleiReportError("Nuclei JSONL exceeds the record budget")

    records: list[Mapping[str, object]] = []

    for line in lines:
        if not line or len(line) > NUCLEI_JSONL_MAX_LINE_BYTES:
            raise NucleiReportError("Nuclei JSONL has an empty or oversized record")

        try:
            value: object = json.loads(line.decode("utf-8"), object_pairs_hook=UniqueJsonObject,
                                       parse_constant=RejectJsonConstant)

        except (ValueError, RecursionError) as error:
            raise NucleiReportError("Nuclei JSONL is invalid or truncated UTF-8 JSON") from error

        if not isinstance(value, dict):
            raise NucleiReportError("Nuclei JSONL records must be objects")

        pending: list[tuple[object, int]] = [(value, 0)]
        nodes = 0

        while pending:
            nested, depth = pending.pop()
            nodes += 1

            if depth > 16 or nodes > 4096:
                raise NucleiReportError("Nuclei JSONL exceeds the structural budget")

            if isinstance(nested, dict):
                pending.extend((item, depth + 1) for item in nested.values())

            elif isinstance(nested, list):
                pending.extend((item, depth + 1) for item in nested)

            elif isinstance(nested, float) and not math.isfinite(nested):
                raise NucleiReportError("Nuclei JSONL contains a non-finite number")

        records.append(cast(Mapping[str, object], value))

    return tuple(records)


class NucleiAdapter:
    """Prepare reviewed local profiles and normalize existing executor/evidence facts."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes],
                 profile: NucleiProfile, executable: str = "nuclei",
                 provider_version: str | None = None) -> None:
        """Bind trusted configuration without discovering, installing, or invoking tools.

        Args:
            evidence_reader: Usually LocalEvidenceStore.Read, never file discovery.
            profile: Operator-approved finite reviewed HTTP template collection.
            executable: Trusted executable name or absolute path.
            provider_version: Earlier observed Nuclei 3.x version; required for preparation.

        Raises:
            ValueError: A profile, executable, or known version is unsupported.
        """

        RequireText(executable, "Nuclei executable")

        if not isinstance(profile, NucleiProfile):
            raise ValueError("Nuclei requires an explicit reviewed profile")

        if provider_version is not None and (
            not isinstance(provider_version, str)
            or not _VERSION_PATTERN.fullmatch(provider_version)
        ):
            raise ValueError("Nuclei provider_version must identify an observed 3.x version")

        self._read_evidence = evidence_reader
        self._profile = profile
        self._executable = executable
        self._provider_version = provider_version

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return finite capability metadata without granting scan authority.

        Returns:
            Existing SDK declaration for a reviewed STANDARD HTTP profile.
        """

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Observe only a bounded local version command.

        Returns:
            Tool availability and version, with no target or template execution.
        """

        return ReadVersion(self._executable)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Validate exact reviewed artifacts and prepare a finite shell-free command.

        Args:
            request: Approved exact URL, profile digest, timeout and request-rate limit.

        Returns:
            Invocation requiring a separate exact ExecutionAuthorization.

        Raises:
            ValueError: Metadata or local artifacts fail the reviewed profile contract.
        """

        invocation = self.BuildInvocation(request)
        VerifyArtifact(self._profile.configuration_path, hashlib.sha256(_EMPTY_CONFIG).hexdigest(),
                       len(_EMPTY_CONFIG))

        for template in self._profile.templates:
            VerifyArtifact(template.path, template.sha256, template.size_bytes)

        return invocation

    def BuildInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Build deterministic metadata, also usable during replay without template files.

        Args:
            request: Capability request with a review-bound profile digest.

        Returns:
            Bounded deterministic argv without filesystem or process activity.

        Raises:
            ValueError: The request is outside the supported finite profile.
        """

        if not _DESCRIPTOR.Supports(request.capability) or (
            request.impact is not ImpactLevel.STANDARD
        ):
            raise ValueError("Nuclei requires its reviewed HTTP capability with STANDARD impact")

        if self._provider_version is None or request.credential_references:
            raise ValueError("Nuclei requires an observed version and cannot accept credentials")

        if set(request.parameters) != {"url", "profile_sha256", "timeout_seconds", "rate_limit"}:
            raise ValueError("Nuclei parameters: url, profile_sha256, timeout_seconds, rate_limit")

        if request.parameters["profile_sha256"] != self._profile.Digest:
            raise ValueError("Nuclei request is not bound to the reviewed profile digest")

        url = CanonicalUrl(request.parameters["url"])
        timeout = RequireInteger(request.parameters["timeout_seconds"], 1,
                                 NUCLEI_MAX_TIMEOUT_SECONDS, "Nuclei timeout")
        rate = RequireInteger(request.parameters["rate_limit"], 1, NUCLEI_MAX_RATE_LIMIT,
                              "Nuclei rate limit")
        arguments = [self._executable, "-u", url, "-config", self._profile.configuration_path,
                     "-pt", "http", "-jsonl", "-silent", "-nc", "-omit-raw", "-omit-template",
                     "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-rl", str(rate),
                     "-bs", "1", "-c", "1", "-retries", "0", "-mhe", "1", "-timeout",
                     str(min(timeout, 30)), "-rsr", "1048576", "-rss", "1048576"]

        for template in self._profile.templates:
            arguments.extend(("-t", template.path))

        return AdapterInvocation(_DESCRIPTOR.adapter_id, request, tuple(arguments), timeout,
                                 self._provider_version)

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Normalize exact verified JSONL without altering execution or storing state.

        Args:
            report: Terminal executor facts and immutable stdout/stderr references.

        Returns:
            Provider-neutral findings and explicit run/parse observations.

        Raises:
            NucleiReportError: Invocation/evidence binding or successful output is invalid.
            ValueError: Original request fails finite profile validation.
        """

        expected = self.BuildInvocation(report.invocation.request)

        if report.invocation != expected:
            raise NucleiReportError("Nuclei report does not match the reviewed invocation")

        references = [item for item in report.evidence if item.role == "stdout"]

        if len(references) != 1:
            raise NucleiReportError("Nuclei report requires exactly one stdout reference")

        reference = references[0]

        if reference.size_bytes > NUCLEI_JSONL_MAX_BYTES:
            raise NucleiReportError("Nuclei JSONL exceeds the byte budget")

        raw = self._read_evidence(reference)

        if len(raw) != reference.size_bytes or hashlib.sha256(raw).hexdigest() != reference.sha256:
            raise NucleiReportError("Nuclei stdout differs from its evidence digest/size")

        try:
            records = ParseJsonl(raw)
            findings = tuple(self.NormalizeFinding(report, item) for item in records)

        except (NucleiReportError, ValueError) as error:
            if report.execution.state is ExecutionState.SUCCEEDED:
                raise NucleiReportError("successful Nuclei output is invalid") from error

            diagnostic = NormalizedObservation(
                "nuclei.parse", report.invocation.request.target_reference,
                {"complete": False, "status": "invalid-or-partial",
                 "execution_state": report.execution.state.value})

            return AdapterResult(report, observations=(diagnostic,))

        run = NormalizedObservation("nuclei.run", report.invocation.request.target_reference, {
            "execution_state": report.execution.state.value,
            "complete": report.execution.state is ExecutionState.SUCCEEDED,
            "reported_matches": len(findings),
            "provider_version": report.invocation.provider_version,
            "profile_sha256": self._profile.Digest, "profile_id": self._profile.profile_id,
            "template_provenance": JsonValue(self._profile.templates),
        })

        return AdapterResult(report, observations=(run,), findings=findings)

    def NormalizeFinding(self, report: AdapterReport,
                         record: Mapping[str, object]) -> NormalizedFinding:
        """Bind a provider match to the exact template/URL and its enclosing evidence.

        Args:
            report: Original invocation and execution facts.
            record: One bounded unique-key JSONL object.

        Returns:
            Existing SDK finding with source identity and reviewed template provenance.

        Raises:
            NucleiReportError: A match is unbound, outside profile, or malformed.
        """

        template = next((item for item in self._profile.templates
                         if item.template_id == record.get("template-id")), None)
        expected_url = CanonicalUrl(report.invocation.request.parameters["url"])
        info = record.get("info")

        if template is None or record.get("type") != "http" or (
            not isinstance(info, dict)
            or ("matcher-status" in record and record["matcher-status"] is not True)
        ):
            raise NucleiReportError("Nuclei match is outside the reviewed HTTP template set")

        if CanonicalUrl(record.get("matched-at")) != expected_url:
            raise NucleiReportError("Nuclei match URL differs from the exact approved target")

        if "host" in record and CanonicalUrl(record["host"]) != expected_url:
            raise NucleiReportError("Nuclei input host differs from the exact approved target")

        if "ip" in record and record["ip"] != urlsplit(expected_url).hostname:
            raise NucleiReportError("Nuclei reported address differs from the approved literal IP")

        if "template-path" in record and record["template-path"] != template.path:
            raise NucleiReportError("Nuclei match template path differs from the reviewed artifact")

        summary = info.get("name")
        severity = info.get("severity")
        matcher = record.get("matcher-name", "")

        if not isinstance(summary, str) or not summary or not isinstance(severity, str) or (
            severity not in _SEVERITIES or not isinstance(matcher, str)
        ):
            raise NucleiReportError("Nuclei finding needs a name, valid severity, and matcher")

        RequireText(summary, "Nuclei summary")
        identity = hashlib.sha256(SerializeContract({"template_id": template.template_id,
            "template_sha256": template.sha256, "url": expected_url, "matcher": matcher,
        }).encode("utf-8")).hexdigest()
        attributes: dict[str, object] = {
            "provider": _DESCRIPTOR.adapter_id,
            "provider_version": report.invocation.provider_version,
            "source_finding_id": f"nuclei:{identity}", "template_id": template.template_id,
            "template_sha256": template.sha256, "template_source": template.source_reference,
            "template_revision": template.source_revision,
            "template_review": template.review_reference,
            "profile_sha256": self._profile.Digest, "matched_at": expected_url,
            "matcher_name": matcher, "severity": severity,
            "complete": report.execution.state is ExecutionState.SUCCEEDED,
            "execution_state": report.execution.state.value,
        }

        for field_name in ("description", "reference", "tags", "classification", "metadata"):
            if field_name in info:
                attributes[field_name] = info[field_name]

        return NormalizedFinding("web.template-match", report.invocation.request.target_reference,
                                 summary, attributes)
