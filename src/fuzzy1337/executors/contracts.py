"""Typed contracts for governed executor providers and local process execution."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterExecution,
    AdapterInvocation,
    ImpactLevel,
    ToolAdapter,
    serialize_contract,
)

EXECUTOR_CONTRACT_VERSION = 1

_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IMPACT_ORDER = {impact: index for index, impact in enumerate(ImpactLevel)}


def _require_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase machine-readable identifier")


def _require_reference(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} must be a non-empty single-line reference")


def _unique_identifiers(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    normalized = tuple(values)
    for value in normalized:
        _require_identifier(value, field_name)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must contain unique values")
    return normalized


def invocation_digest(invocation: AdapterInvocation) -> str:
    """Bind an authorization record to the exact immutable adapter invocation."""
    return hashlib.sha256(serialize_contract(invocation).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    """One executable capability derived from a provider declaration."""

    identifier: str
    adapter_id: str
    maximum_impact: ImpactLevel
    required_privileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.identifier, "identifier")
        _require_identifier(self.adapter_id, "adapter_id")
        if not isinstance(self.maximum_impact, ImpactLevel):
            raise ValueError("maximum_impact must be an ImpactLevel")
        object.__setattr__(
            self,
            "required_privileges",
            _unique_identifiers(self.required_privileges, "required_privileges"),
        )


def capability_descriptors(descriptor: AdapterDescriptor) -> tuple[CapabilityDescriptor, ...]:
    """Expand one adapter declaration into deterministic capability records."""
    return tuple(
        CapabilityDescriptor(
            identifier=capability,
            adapter_id=descriptor.adapter_id,
            maximum_impact=descriptor.maximum_impact,
            required_privileges=descriptor.required_privileges,
        )
        for capability in descriptor.capabilities
    )


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    """Upstream scope/policy decision bound to one exact prepared invocation."""

    authorization_id: str
    scope_reference: str
    policy_reference: str
    invocation_sha256: str
    granted_privileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_reference(self.authorization_id, "authorization_id")
        _require_reference(self.scope_reference, "scope_reference")
        _require_reference(self.policy_reference, "policy_reference")
        if not _SHA256_PATTERN.fullmatch(self.invocation_sha256):
            raise ValueError("invocation_sha256 must be a lowercase SHA-256 digest")
        object.__setattr__(
            self,
            "granted_privileges",
            _unique_identifiers(self.granted_privileges, "granted_privileges"),
        )


@dataclass(frozen=True, slots=True)
class ExecutionResources:
    """Portable resource bounds enforced by the local executor."""

    max_stdout_bytes: int = 4 * 1024 * 1024
    max_stderr_bytes: int = 4 * 1024 * 1024
    terminate_grace_seconds: float = 1.0

    def __post_init__(self) -> None:
        for field_name in ("max_stdout_bytes", "max_stderr_bytes"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")
        if (
            isinstance(self.terminate_grace_seconds, bool)
            or not isinstance(self.terminate_grace_seconds, (int, float))
            or not math.isfinite(self.terminate_grace_seconds)
            or self.terminate_grace_seconds <= 0
        ):
            raise ValueError("terminate_grace_seconds must be a positive finite number")


def _freeze_environment(environment: Mapping[str, str]) -> Mapping[str, str]:
    frozen: dict[str, str] = {}
    for name, value in environment.items():
        if not isinstance(name, str) or not _ENVIRONMENT_NAME_PATTERN.fullmatch(name):
            raise ValueError("environment names must use portable variable syntax")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("environment values must be strings without NUL bytes")
        frozen[name] = value

    return MappingProxyType(dict(sorted(frozen.items())))


@dataclass(frozen=True, slots=True)
class LocalExecutionRequest:
    """Fully bound request accepted by the local subprocess executor."""

    invocation: AdapterInvocation
    capability: CapabilityDescriptor
    authorization: ExecutionAuthorization
    workspace: str = "."
    environment: Mapping[str, str] = field(default_factory=dict)
    resources: ExecutionResources = field(default_factory=ExecutionResources)

    def __post_init__(self) -> None:
        if self.invocation.adapter_id != self.capability.adapter_id:
            raise ValueError("capability adapter_id must match the invocation")
        if self.invocation.request.capability != self.capability.identifier:
            raise ValueError("capability identifier must match the invocation")
        if _IMPACT_ORDER[self.invocation.request.impact] > _IMPACT_ORDER[self.capability.maximum_impact]:
            raise ValueError("invocation impact exceeds the capability maximum")
        if self.authorization.invocation_sha256 != invocation_digest(self.invocation):
            raise ValueError("authorization does not match the invocation")
        if not set(self.capability.required_privileges).issubset(
            self.authorization.granted_privileges
        ):
            raise ValueError("authorization does not grant every required privilege")

        _require_reference(self.workspace, "workspace")
        path = PurePosixPath(self.workspace)
        if "\\" in self.workspace or path.is_absolute() or ".." in path.parts:
            raise ValueError("workspace must be a relative path inside the executor root")
        object.__setattr__(self, "workspace", path.as_posix())
        object.__setattr__(self, "environment", _freeze_environment(self.environment))


class ExecutionEventKind(StrEnum):
    """Structured progress events emitted by an executor."""

    STARTED = "started"
    STDOUT = "stdout"
    STDERR = "stderr"
    COMPLETED = "completed"


class ExecutionTermination(StrEnum):
    """Why the local executor stopped owning the process."""

    PROCESS_EXIT = "process_exit"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    OUTPUT_LIMIT = "output_limit"


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    """One monotonically sequenced executor observation."""

    sequence: int
    kind: ExecutionEventKind
    data: bytes = b""
    termination: ExecutionTermination | None = None

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("sequence must be a non-negative integer")
        if not isinstance(self.kind, ExecutionEventKind):
            raise ValueError("kind must be an ExecutionEventKind")
        if not isinstance(self.data, bytes):
            raise ValueError("data must be bytes")
        if self.kind in {ExecutionEventKind.STDOUT, ExecutionEventKind.STDERR}:
            if not self.data or self.termination is not None:
                raise ValueError("stream events require data and no termination")
        elif self.data:
            raise ValueError("lifecycle events must not contain stream data")
        if self.kind is ExecutionEventKind.COMPLETED:
            if not isinstance(self.termination, ExecutionTermination):
                raise ValueError("completed events require a termination reason")
        elif self.termination is not None:
            raise ValueError("only completed events may declare termination")


@dataclass(frozen=True, slots=True)
class LocalExecutionResult:
    """Complete local process outcome plus bounded raw output and event history."""

    execution: AdapterExecution
    termination: ExecutionTermination
    stdout: bytes
    stderr: bytes
    events: tuple[ExecutionEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.termination, ExecutionTermination):
            raise ValueError("termination must be an ExecutionTermination")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("stdout and stderr must be bytes")
        events = tuple(self.events)
        if not events or events[-1].kind is not ExecutionEventKind.COMPLETED:
            raise ValueError("events must end with a completed event")
        if tuple(event.sequence for event in events) != tuple(range(len(events))):
            raise ValueError("events must use contiguous sequence numbers")
        if events[-1].termination is not self.termination:
            raise ValueError("terminal event must match the result termination")
        object.__setattr__(self, "events", events)


AdapterLoader = Callable[[], ToolAdapter]


@dataclass(slots=True)
class _AdapterRegistration:
    descriptor: AdapterDescriptor
    loader: AdapterLoader
    instance: ToolAdapter | None = None


class LazyAdapterRegistry:
    """Resolve declared providers only when one of their capabilities is requested."""

    def __init__(self) -> None:
        self._registrations: dict[str, _AdapterRegistration] = {}
        self._providers_by_capability: dict[str, list[str]] = {}

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return declared capabilities without loading provider implementations."""
        return tuple(sorted(self._providers_by_capability))

    def register(self, descriptor: AdapterDescriptor, loader: AdapterLoader) -> None:
        """Register immutable metadata and a lazy provider factory."""
        if descriptor.adapter_id in self._registrations:
            raise ValueError(f"Adapter is already registered: {descriptor.adapter_id}")
        if not callable(loader):
            raise TypeError("loader must be callable")
        self._registrations[descriptor.adapter_id] = _AdapterRegistration(descriptor, loader)
        for capability in descriptor.capabilities:
            self._providers_by_capability.setdefault(capability, []).append(descriptor.adapter_id)

    def resolve(self, capability: str, adapter_id: str | None = None) -> ToolAdapter:
        """Load one provider deterministically and validate its declared identity."""
        providers = self._providers_by_capability.get(capability)
        if not providers:
            raise LookupError(f"Unknown capability: {capability}")
        if adapter_id is None:
            if len(providers) != 1:
                raise LookupError(f"Capability requires an explicit adapter_id: {capability}")
            adapter_id = providers[0]
        elif adapter_id not in providers:
            raise LookupError(f"Adapter {adapter_id} does not provide capability {capability}")

        registration = self._registrations[adapter_id]
        if registration.instance is None:
            candidate = registration.loader()
            if not isinstance(candidate, ToolAdapter):
                raise TypeError("loader must return a ToolAdapter")
            if candidate.descriptor != registration.descriptor:
                raise ValueError("loaded ToolAdapter descriptor does not match registration")
            registration.instance = candidate
        return registration.instance
