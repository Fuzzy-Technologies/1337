"""Типизированные контракты управляемых исполнителей и локальных процессов."""

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
    SerializeContract,
    ToolAdapter,
)

EXECUTORCONTRACTVERSION = 1

IDENTIFIERPATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
ENVIRONMENTNAMEPATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SHA256PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMPACTORDER = {impact: index for index, impact in enumerate(ImpactLevel)}


def RequireIdentifier(value: str, fieldName: str) -> None:
    """Отклоняет идентификатор, непригодный для стабильного ключа."""

    if not isinstance(value, str) or not IDENTIFIERPATTERN.fullmatch(value):
        raise ValueError(f"{fieldName} must be a lowercase machine-readable identifier")


def RequireReference(value: str, fieldName: str) -> None:
    """Отклоняет пустую или многострочную непрозрачную ссылку."""

    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{fieldName} must be a non-empty single-line reference")


def UniqueIdentifiers(values: tuple[str, ...], fieldName: str) -> tuple[str, ...]:
    """Проверяет уникальные идентификаторы, сохраняя их порядок."""

    normalized = tuple(values)
    for value in normalized:
        RequireIdentifier(value, fieldName)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{fieldName} must contain unique values")
    return normalized


def InvocationDigest(invocation: AdapterInvocation) -> str:
    """Связывает авторизацию с точным неизменяемым вызовом адаптера."""

    return hashlib.sha256(SerializeContract(invocation).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    """Описывает одну исполняемую возможность провайдера."""

    identifier: str
    adapterId: str
    maximumImpact: ImpactLevel
    requiredPrivileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Проверяет возможность до регистрации провайдера."""

        RequireIdentifier(self.identifier, "identifier")
        RequireIdentifier(self.adapterId, "adapterId")
        if not isinstance(self.maximumImpact, ImpactLevel):
            raise ValueError("maximumImpact must be an ImpactLevel")
        object.__setattr__(
            self,
            "requiredPrivileges",
            UniqueIdentifiers(self.requiredPrivileges, "requiredPrivileges"),
        )


def CapabilityDescriptors(descriptor: AdapterDescriptor) -> tuple[CapabilityDescriptor, ...]:
    """Разворачивает декларацию адаптера в детерминированные возможности."""

    return tuple(
        CapabilityDescriptor(
            identifier=capability,
            adapterId=descriptor.adapterId,
            maximumImpact=descriptor.maximumImpact,
            requiredPrivileges=descriptor.requiredPrivileges,
        )
        for capability in descriptor.capabilities
    )


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    """Хранит решение scope и policy для одного подготовленного вызова."""

    authorizationId: str
    scopeReference: str
    policyReference: str
    invocationSha256: str
    grantedPrivileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Проверяет ссылки, digest и выданные привилегии."""

        RequireReference(self.authorizationId, "authorizationId")
        RequireReference(self.scopeReference, "scopeReference")
        RequireReference(self.policyReference, "policyReference")
        if not SHA256PATTERN.fullmatch(self.invocationSha256):
            raise ValueError("invocationSha256 must be a lowercase SHA-256 digest")
        object.__setattr__(
            self,
            "grantedPrivileges",
            UniqueIdentifiers(self.grantedPrivileges, "grantedPrivileges"),
        )


@dataclass(frozen=True, slots=True)
class ExecutionResources:
    """Задаёт переносимые ресурсные ограничения локального исполнителя."""

    maxStdoutBytes: int = 4 * 1024 * 1024
    maxStderrBytes: int = 4 * 1024 * 1024
    terminateGraceSeconds: float = 1.0

    def __post_init__(self) -> None:
        """Отклоняет неположительные и неограниченные лимиты."""

        for fieldName in ("maxStdoutBytes", "maxStderrBytes"):
            value = getattr(self, fieldName)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{fieldName} must be a positive integer")
        if (
            isinstance(self.terminateGraceSeconds, bool)
            or not isinstance(self.terminateGraceSeconds, (int, float))
            or not math.isfinite(self.terminateGraceSeconds)
            or self.terminateGraceSeconds <= 0
        ):
            raise ValueError("terminateGraceSeconds must be a positive finite number")


def FreezeEnvironment(environment: Mapping[str, str]) -> Mapping[str, str]:
    """Проверяет и замораживает окружение дочернего процесса."""

    frozen: dict[str, str] = {}
    for name, value in environment.items():
        if not isinstance(name, str) or not ENVIRONMENTNAMEPATTERN.fullmatch(name):
            raise ValueError("environment names must use portable variable syntax")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("environment values must be strings without NUL bytes")
        frozen[name] = value

    return MappingProxyType(dict(sorted(frozen.items())))


@dataclass(frozen=True, slots=True)
class LocalExecutionRequest:
    """Хранит полностью связанный запрос локального исполнителя."""

    invocation: AdapterInvocation
    capability: CapabilityDescriptor
    authorization: ExecutionAuthorization
    workspace: str = "."
    environment: Mapping[str, str] = field(default_factory=dict)
    resources: ExecutionResources = field(default_factory=ExecutionResources)

    def __post_init__(self) -> None:
        """Проверяет согласованность вызова, авторизации и рабочей области."""

        if self.invocation.adapterId != self.capability.adapterId:
            raise ValueError("capability adapterId must match the invocation")
        if self.invocation.request.capability != self.capability.identifier:
            raise ValueError("capability identifier must match the invocation")
        if IMPACTORDER[self.invocation.request.impact] > IMPACTORDER[self.capability.maximumImpact]:
            raise ValueError("invocation impact exceeds the capability maximum")
        if self.authorization.invocationSha256 != InvocationDigest(self.invocation):
            raise ValueError("authorization does not match the invocation")
        if not set(self.capability.requiredPrivileges).issubset(
            self.authorization.grantedPrivileges
        ):
            raise ValueError("authorization does not grant every required privilege")

        RequireReference(self.workspace, "workspace")
        path = PurePosixPath(self.workspace)
        if "\\" in self.workspace or path.is_absolute() or ".." in path.parts:
            raise ValueError("workspace must be a relative path inside the executor root")
        object.__setattr__(self, "workspace", path.as_posix())
        object.__setattr__(self, "environment", FreezeEnvironment(self.environment))


class ExecutionEventKind(StrEnum):
    """Перечисляет структурированные события прогресса исполнителя."""

    STARTED = "started"
    STDOUT = "stdout"
    STDERR = "stderr"
    COMPLETED = "completed"


class ExecutionTermination(StrEnum):
    """Объясняет причину завершения владения дочерним процессом."""

    PROCESSEXIT = "process_exit"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    OUTPUTLIMIT = "output_limit"


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    """Хранит одно последовательно пронумерованное наблюдение."""

    sequence: int
    kind: ExecutionEventKind
    data: bytes = b""
    termination: ExecutionTermination | None = None

    def __post_init__(self) -> None:
        """Проверяет данные и причину события для его типа."""

        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
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
    """Хранит исход процесса, ограниченный вывод и историю событий."""

    execution: AdapterExecution
    termination: ExecutionTermination
    stdout: bytes
    stderr: bytes
    events: tuple[ExecutionEvent, ...]

    def __post_init__(self) -> None:
        """Проверяет непрерывность и конечное событие результата."""

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
class AdapterRegistration:
    """Хранит ленивую фабрику и необязательный экземпляр адаптера."""

    descriptor: AdapterDescriptor
    loader: AdapterLoader
    instance: ToolAdapter | None = None


class LazyAdapterRegistry:
    """Загружает провайдера только при запросе его возможности."""

    def __init__(self) -> None:
        """Создаёт пустой реестр деклараций и ленивых фабрик."""

        self.registrations: dict[str, AdapterRegistration] = {}
        self.providersByCapability: dict[str, list[str]] = {}

    @property
    def Capabilities(self) -> tuple[str, ...]:
        """Возвращает возможности без загрузки реализаций провайдеров."""

        return tuple(sorted(self.providersByCapability))

    def Register(self, descriptor: AdapterDescriptor, loader: AdapterLoader) -> None:
        """Регистрирует неизменяемые метаданные и ленивую фабрику."""

        if descriptor.adapterId in self.registrations:
            raise ValueError(f"Adapter is already registered: {descriptor.adapterId}")
        if not callable(loader):
            raise TypeError("loader must be callable")
        self.registrations[descriptor.adapterId] = AdapterRegistration(descriptor, loader)
        for capability in descriptor.capabilities:
            self.providersByCapability.setdefault(capability, []).append(descriptor.adapterId)

    def Resolve(self, capability: str, adapterId: str | None = None) -> ToolAdapter:
        """Детерминированно загружает и проверяет один провайдер."""

        providers = self.providersByCapability.get(capability)
        if not providers:
            raise LookupError(f"Unknown capability: {capability}")
        if adapterId is None:
            if len(providers) != 1:
                raise LookupError(f"Capability requires an explicit adapterId: {capability}")
            adapterId = providers[0]

        elif adapterId not in providers:
            raise LookupError(f"Adapter {adapterId} does not provide capability {capability}")

        registration = self.registrations[adapterId]
        if registration.instance is None:
            candidate = registration.loader()
            if not isinstance(candidate, ToolAdapter):
                raise TypeError("loader must return a ToolAdapter")
            if candidate.Descriptor != registration.descriptor:
                raise ValueError("loaded ToolAdapter descriptor does not match registration")
            registration.instance = candidate
        return registration.instance
