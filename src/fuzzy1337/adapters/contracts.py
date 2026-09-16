"""Provider-neutral contracts for governed security-tool adapters."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Protocol, runtime_checkable

ADAPTER_CONTRACT_VERSION = 1

_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ImpactLevel(StrEnum):
    """Declared maximum impact for a provider, independent from authorization."""

    PASSIVE = "PASSIVE"
    SAFE = "SAFE"
    STANDARD = "STANDARD"
    ACTIVE = "ACTIVE"
    INTRUSIVE = "INTRUSIVE"


class AdapterHealthState(StrEnum):
    """Health state reported by an adapter without implying execution authority."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ExecutionState(StrEnum):
    """Terminal executor state preserved for adapter normalization."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


def _require_identifier(value: str, field_name: str) -> None:
    """Reject identifiers that cannot be used as stable machine-readable keys."""
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase machine-readable identifier")


def _require_text(value: str, field_name: str) -> None:
    """Reject empty or multi-line user-visible contract text."""
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} must be non-empty single-line text")


def _freeze_json(value: object) -> object:
    """Return a recursively immutable JSON-like value or fail closed."""
    if value is None or isinstance(value, (bool, int, str)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("contract metadata must not contain non-finite numbers")
        return value

    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError("contract metadata keys must be non-empty strings")
            frozen[key] = _freeze_json(nested_value)

        return MappingProxyType(dict(sorted(frozen.items())))

    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)

    raise ValueError("contract metadata must contain JSON-compatible values")


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    """Freeze a JSON object while retaining a read-only mapping contract."""
    frozen = _freeze_json(value)
    if not isinstance(frozen, Mapping):
        raise ValueError("contract metadata must be a JSON object")
    return frozen


def _unique_identifiers(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    """Validate a stable identifier collection without changing declaration order."""
    normalized = tuple(values)
    for value in normalized:
        _require_identifier(value, field_name)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must contain unique values")
    return normalized


def _unique_references(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    """Validate opaque non-secret references without assigning their semantics."""
    normalized = tuple(values)
    for value in normalized:
        _require_text(value, field_name)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must contain unique values")
    return normalized


def _json_value(value: object) -> object:
    """Render one immutable contract value as deterministic JSON-compatible data."""
    if isinstance(value, StrEnum):
        return value.value

    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}

    if isinstance(value, Mapping):
        rendered: dict[str, object] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise ValueError("contract mappings must use string keys")
            rendered[key] = _json_value(nested_value)

        return dict(sorted(rendered.items()))

    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]

    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("contract values must not contain non-finite numbers")

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    raise ValueError("contract values must be JSON-compatible")


def serialize_contract(value: object) -> str:
    """Serialize a contract value with stable key order and no non-JSON numbers."""
    return json.dumps(
        _json_value(value),
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    """Static provider declaration consumed by capability and policy layers."""

    adapter_id: str
    display_name: str
    version: str
    capabilities: tuple[str, ...]
    maximum_impact: ImpactLevel
    required_privileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate provider declarations before an adapter can be registered."""
        _require_identifier(self.adapter_id, "adapter_id")
        _require_text(self.display_name, "display_name")
        _require_text(self.version, "version")
        if not isinstance(self.maximum_impact, ImpactLevel):
            raise ValueError("maximum_impact must be an ImpactLevel")
        if not self.capabilities:
            raise ValueError("capabilities must not be empty")
        object.__setattr__(
            self,
            "capabilities",
            _unique_identifiers(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self,
            "required_privileges",
            _unique_identifiers(self.required_privileges, "required_privileges"),
        )

    def supports(self, capability: str) -> bool:
        """Return whether this provider declares a capability without authorizing it."""
        return capability in self.capabilities


@dataclass(frozen=True, slots=True)
class AdapterHealth:
    """Observed adapter health and provider version at a bounded check boundary."""

    adapter_id: str
    state: AdapterHealthState
    provider_version: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        """Reject ambiguous health values before callers act on them."""
        _require_identifier(self.adapter_id, "adapter_id")
        if not isinstance(self.state, AdapterHealthState):
            raise ValueError("state must be an AdapterHealthState")
        if self.provider_version is not None:
            _require_text(self.provider_version, "provider_version")
        if self.detail is not None:
            _require_text(self.detail, "detail")


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Approved capability request passed to an adapter for invocation preparation."""

    capability: str
    target_reference: str
    impact: ImpactLevel
    parameters: Mapping[str, object] = field(default_factory=dict)
    credential_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate request metadata while keeping credentials as opaque references."""
        _require_identifier(self.capability, "capability")
        _require_text(self.target_reference, "target_reference")
        if not isinstance(self.impact, ImpactLevel):
            raise ValueError("impact must be an ImpactLevel")
        object.__setattr__(self, "parameters", _freeze_mapping(self.parameters))
        object.__setattr__(
            self,
            "credential_references",
            _unique_references(self.credential_references, "credential_references"),
        )


@dataclass(frozen=True, slots=True)
class AdapterInvocation:
    """Prepared non-secret command metadata owned by a future executor boundary."""

    adapter_id: str
    request: AdapterRequest
    argv: tuple[str, ...]
    timeout_seconds: int
    provider_version: str | None = None

    def __post_init__(self) -> None:
        """Require a bounded explicit argv without invoking a process."""
        _require_identifier(self.adapter_id, "adapter_id")
        arguments = tuple(self.argv)
        if not arguments:
            raise ValueError("argv must contain an executable")
        for argument in arguments:
            _require_text(argument, "argv entry")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds < 1
        ):
            raise ValueError("timeout_seconds must be a positive integer")
        if self.provider_version is not None:
            _require_text(self.provider_version, "provider_version")
        object.__setattr__(self, "argv", arguments)


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Reference immutable raw evidence without embedding raw provider payloads."""

    role: str
    locator: str
    sha256: str
    media_type: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Accept only relative, hash-addressed evidence references."""
        _require_identifier(self.role, "role")
        _require_text(self.locator, "locator")
        locator = PurePosixPath(self.locator)
        if (
            not self.locator
            or "\\" in self.locator
            or locator.is_absolute()
            or ".." in locator.parts
        ):
            raise ValueError("locator must be a relative evidence path")
        if not _SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        _require_text(self.media_type, "media_type")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
        ):
            raise ValueError("size_bytes must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class AdapterExecution:
    """Terminal executor outcome preserved before adapter parsing and normalization."""

    state: ExecutionState
    exit_code: int | None
    duration_seconds: float

    def __post_init__(self) -> None:
        """Prevent failed, timed-out, or cancelled execution from becoming success."""
        if not isinstance(self.state, ExecutionState):
            raise ValueError("state must be an ExecutionState")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise ValueError("exit_code must be an integer or None")
        if not math.isfinite(self.duration_seconds) or self.duration_seconds < 0:
            raise ValueError("duration_seconds must be a non-negative finite number")
        if self.state is ExecutionState.SUCCEEDED and self.exit_code != 0:
            raise ValueError("successful execution requires exit_code 0")
        if self.state is ExecutionState.FAILED and self.exit_code in (None, 0):
            raise ValueError("failed execution requires a non-zero exit_code")
        if self.state is ExecutionState.TIMED_OUT and self.exit_code == 0:
            raise ValueError("timed-out execution cannot report exit_code 0")
        if self.state is ExecutionState.CANCELLED and self.exit_code == 0:
            raise ValueError("cancelled execution cannot report exit_code 0")


@dataclass(frozen=True, slots=True)
class AdapterReport:
    """Executor-owned facts and raw-evidence references supplied to an adapter parser."""

    invocation: AdapterInvocation
    execution: AdapterExecution
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        """Freeze evidence ordering and reject ambiguous duplicate references."""
        evidence = tuple(self.evidence)
        locator_roles = tuple((item.locator, item.role) for item in evidence)
        if len(set(locator_roles)) != len(locator_roles):
            raise ValueError("evidence references must be unique by locator and role")
        object.__setattr__(self, "evidence", evidence)


@dataclass(frozen=True, slots=True)
class NormalizedObservation:
    """Provider-neutral observation envelope for a later Security Object Model update."""

    kind: str
    subject_reference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze generic observation fields without assigning core schema semantics."""
        _require_identifier(self.kind, "kind")
        _require_text(self.subject_reference, "subject_reference")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """Provider-neutral finding envelope backed by the enclosing raw evidence."""

    kind: str
    subject_reference: str
    summary: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze generic finding attributes while retaining a human-readable summary."""
        _require_identifier(self.kind, "kind")
        _require_text(self.subject_reference, "subject_reference")
        _require_text(self.summary, "summary")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class ObjectEnrichment:
    """Generic object attribute enrichment without introducing provider-owned types."""

    object_kind: str
    object_reference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Keep object enrichment references typed and immutable."""
        _require_identifier(self.object_kind, "object_kind")
        _require_text(self.object_reference, "object_reference")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class RelationEnrichment:
    """Generic relation attribute enrichment without mutating shared state directly."""

    relation_kind: str
    source_reference: str
    target_reference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Keep relation references typed and immutable."""
        _require_identifier(self.relation_kind, "relation_kind")
        _require_text(self.source_reference, "source_reference")
        _require_text(self.target_reference, "target_reference")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Normalized adapter output that remains separate from persistence and policy."""

    report: AdapterReport
    observations: tuple[NormalizedObservation, ...] = ()
    findings: tuple[NormalizedFinding, ...] = ()
    object_enrichments: tuple[ObjectEnrichment, ...] = ()
    relation_enrichments: tuple[RelationEnrichment, ...] = ()

    def __post_init__(self) -> None:
        """Freeze result collections so downstream consumers receive stable evidence."""
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "object_enrichments", tuple(self.object_enrichments))
        object.__setattr__(self, "relation_enrichments", tuple(self.relation_enrichments))


@runtime_checkable
class ToolAdapter(Protocol):
    """Provider contract that cannot execute outside the future governed executor."""

    @property
    def descriptor(self) -> AdapterDescriptor:
        """Return the immutable provider declaration."""
        ...

    def check_health(self) -> AdapterHealth:
        """Return a bounded health result without claiming authorization."""
        ...

    def prepare_invocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Prepare a bounded invocation from an already-approved request."""
        ...

    def normalize_report(self, report: AdapterReport) -> AdapterResult:
        """Normalize an executor report without mutating shared security state."""
        ...
