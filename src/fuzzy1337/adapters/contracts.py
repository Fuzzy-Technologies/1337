"""Независимые от провайдера контракты управляемых адаптеров."""

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

ADAPTERCONTRACTVERSION = 1

IDENTIFIERPATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ImpactLevel(StrEnum):
    """Задаёт максимальное влияние провайдера независимо от авторизации."""

    PASSIVE = "PASSIVE"
    SAFE = "SAFE"
    STANDARD = "STANDARD"
    ACTIVE = "ACTIVE"
    INTRUSIVE = "INTRUSIVE"


class AdapterHealthState(StrEnum):
    """Описывает состояние адаптера без полномочий на выполнение."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ExecutionState(StrEnum):
    """Сохраняет конечное состояние исполнителя для нормализации."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEDOUT = "timedOut"
    CANCELLED = "cancelled"


def RequireIdentifier(value: str, fieldName: str) -> None:
    """Отклоняет идентификаторы, непригодные для стабильных ключей."""

    if not isinstance(value, str) or not IDENTIFIERPATTERN.fullmatch(value):
        raise ValueError(f"{fieldName} must be a lowercase machine-readable identifier")


def RequireText(value: str, fieldName: str) -> None:
    """Отклоняет пустой или многострочный текст контракта."""

    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{fieldName} must be non-empty single-line text")


def FreezeJson(value: object) -> object:
    """Возвращает неизменяемое JSON-подобное значение либо отклоняет его."""

    if value is None or isinstance(value, (bool, int, str)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("contract metadata must not contain non-finite numbers")
        return value

    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, nestedValue in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError("contract metadata keys must be non-empty strings")
            frozen[key] = FreezeJson(nestedValue)

        return MappingProxyType(dict(sorted(frozen.items())))

    if isinstance(value, (list, tuple)):
        return tuple(FreezeJson(item) for item in value)

    raise ValueError("contract metadata must contain JSON-compatible values")


def FreezeMapping(value: Mapping[str, object]) -> Mapping[str, object]:
    """Замораживает JSON-объект как отображение только для чтения."""

    frozen = FreezeJson(value)
    if not isinstance(frozen, Mapping):
        raise ValueError("contract metadata must be a JSON object")
    return frozen


def UniqueIdentifiers(values: tuple[str, ...], fieldName: str) -> tuple[str, ...]:
    """Проверяет идентификаторы без изменения порядка объявления."""

    normalized = tuple(values)
    for value in normalized:
        RequireIdentifier(value, fieldName)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{fieldName} must contain unique values")
    return normalized


def UniqueReferences(values: tuple[str, ...], fieldName: str) -> tuple[str, ...]:
    """Проверяет непрозрачные несекретные ссылки без назначения семантики."""

    normalized = tuple(values)
    for value in normalized:
        RequireText(value, fieldName)

    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{fieldName} must contain unique values")
    return normalized


def JsonValue(value: object) -> object:
    """Преобразует значение контракта в детерминированные JSON-данные."""

    if isinstance(value, StrEnum):
        return value.value

    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: JsonValue(getattr(value, field.name)) for field in fields(value)}

    if isinstance(value, Mapping):
        rendered: dict[str, object] = {}
        for key, nestedValue in value.items():
            if not isinstance(key, str):
                raise ValueError("contract mappings must use string keys")
            rendered[key] = JsonValue(nestedValue)

        return dict(sorted(rendered.items()))

    if isinstance(value, (list, tuple)):
        return [JsonValue(item) for item in value]

    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("contract values must not contain non-finite numbers")

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    raise ValueError("contract values must be JSON-compatible")


def SerializeContract(value: object) -> str:
    """Сериализует контракт со стабильным порядком допустимых JSON-значений."""

    return json.dumps(
        JsonValue(value),
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    """Описывает провайдера для слоёв возможностей и политик."""

    adapterId: str
    displayName: str
    version: str
    capabilities: tuple[str, ...]
    maximumImpact: ImpactLevel
    requiredPrivileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Проверяет объявление провайдера до регистрации адаптера."""

        RequireIdentifier(self.adapterId, "adapterId")
        RequireText(self.displayName, "displayName")
        RequireText(self.version, "version")
        if not isinstance(self.maximumImpact, ImpactLevel):
            raise ValueError("maximum_impact must be an ImpactLevel")
        if not self.capabilities:
            raise ValueError("capabilities must not be empty")
        object.__setattr__(
            self,
            "capabilities",
            UniqueIdentifiers(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self,
            "requiredPrivileges",
            UniqueIdentifiers(self.requiredPrivileges, "requiredPrivileges"),
        )

    def Supports(self, capability: str) -> bool:
        """Проверяет объявление возможности без выдачи авторизации."""

        return capability in self.capabilities


@dataclass(frozen=True, slots=True)
class AdapterHealth:
    """Фиксирует состояние адаптера и версию провайдера."""

    adapterId: str
    state: AdapterHealthState
    providerVersion: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        """Отклоняет неоднозначное состояние до его использования."""

        RequireIdentifier(self.adapterId, "adapterId")
        if not isinstance(self.state, AdapterHealthState):
            raise ValueError("state must be an AdapterHealthState")
        if self.providerVersion is not None:
            RequireText(self.providerVersion, "providerVersion")
        if self.detail is not None:
            RequireText(self.detail, "detail")


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Хранит одобренный запрос возможности для подготовки вызова."""

    capability: str
    targetReference: str
    impact: ImpactLevel
    parameters: Mapping[str, object] = field(default_factory=dict)
    credentialReferences: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Проверяет метаданные, сохраняя credentials непрозрачными ссылками."""

        RequireIdentifier(self.capability, "capability")
        RequireText(self.targetReference, "targetReference")
        if not isinstance(self.impact, ImpactLevel):
            raise ValueError("impact must be an ImpactLevel")
        object.__setattr__(self, "parameters", FreezeMapping(self.parameters))
        object.__setattr__(
            self,
            "credentialReferences",
            UniqueReferences(self.credentialReferences, "credentialReferences"),
        )


@dataclass(frozen=True, slots=True)
class AdapterInvocation:
    """Хранит подготовленные несекретные метаданные команды."""

    adapterId: str
    request: AdapterRequest
    argv: tuple[str, ...]
    timeoutSeconds: int
    providerVersion: str | None = None

    def __post_init__(self) -> None:
        """Требует ограниченный явный argv без запуска процесса."""

        RequireIdentifier(self.adapterId, "adapterId")
        arguments = tuple(self.argv)
        if not arguments:
            raise ValueError("argv must contain an executable")
        for argument in arguments:
            RequireText(argument, "argv entry")
        if (
            isinstance(self.timeoutSeconds, bool)
            or not isinstance(self.timeoutSeconds, int)
            or self.timeoutSeconds < 1
        ):
            raise ValueError("timeoutSeconds must be a positive integer")
        if self.providerVersion is not None:
            RequireText(self.providerVersion, "providerVersion")
        object.__setattr__(self, "argv", arguments)


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Ссылается на неизменяемое доказательство без встраивания данных."""

    role: str
    locator: str
    sha256: str
    mediaType: str
    sizeBytes: int

    def __post_init__(self) -> None:
        """Принимает только относительные ссылки с адресацией по хешу."""

        RequireIdentifier(self.role, "role")
        RequireText(self.locator, "locator")
        locator = PurePosixPath(self.locator)
        if (
            not self.locator
            or "\\" in self.locator
            or locator.is_absolute()
            or ".." in locator.parts
        ):
            raise ValueError("locator must be a relative evidence path")
        if not SHA256PATTERN.fullmatch(self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        RequireText(self.mediaType, "mediaType")
        if (
            isinstance(self.sizeBytes, bool)
            or not isinstance(self.sizeBytes, int)
            or self.sizeBytes < 0
        ):
            raise ValueError("size_bytes must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class AdapterExecution:
    """Сохраняет результат исполнителя до разбора и нормализации."""

    state: ExecutionState
    exitCode: int | None
    durationSeconds: float

    def __post_init__(self) -> None:
        """Не позволяет ошибке, тайм-ауту или отмене стать успехом."""

        if not isinstance(self.state, ExecutionState):
            raise ValueError("state must be an ExecutionState")
        if self.exitCode is not None and (
            isinstance(self.exitCode, bool) or not isinstance(self.exitCode, int)
        ):
            raise ValueError("exitCode must be an integer or None")
        if not math.isfinite(self.durationSeconds) or self.durationSeconds < 0:
            raise ValueError("durationSeconds must be a non-negative finite number")
        if self.state is ExecutionState.SUCCEEDED and self.exitCode != 0:
            raise ValueError("successful execution requires exitCode 0")
        if self.state is ExecutionState.FAILED and self.exitCode in (None, 0):
            raise ValueError("failed execution requires a non-zero exitCode")
        if self.state is ExecutionState.TIMEDOUT and self.exitCode == 0:
            raise ValueError("timed-out execution cannot report exitCode 0")
        if self.state is ExecutionState.CANCELLED and self.exitCode == 0:
            raise ValueError("cancelled execution cannot report exitCode 0")


@dataclass(frozen=True, slots=True)
class AdapterReport:
    """Передаёт парсеру факты исполнителя и ссылки на доказательства."""

    invocation: AdapterInvocation
    execution: AdapterExecution
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        """Фиксирует порядок доказательств и отклоняет дубликаты ссылок."""

        evidence = tuple(self.evidence)
        locatorRoles = tuple((item.locator, item.role) for item in evidence)
        if len(set(locatorRoles)) != len(locatorRoles):
            raise ValueError("evidence references must be unique by locator and role")
        object.__setattr__(self, "evidence", evidence)


@dataclass(frozen=True, slots=True)
class NormalizedObservation:
    """Описывает наблюдение для последующего обновления Security Object Model."""

    kind: str
    subjectReference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Фиксирует поля наблюдения без семантики основной схемы."""

        RequireIdentifier(self.kind, "kind")
        RequireText(self.subjectReference, "subjectReference")
        object.__setattr__(self, "attributes", FreezeMapping(self.attributes))


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """Описывает находку, подтверждённую сырым доказательством."""

    kind: str
    subjectReference: str
    summary: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Фиксирует атрибуты находки и сохраняет читаемое описание."""

        RequireIdentifier(self.kind, "kind")
        RequireText(self.subjectReference, "subjectReference")
        RequireText(self.summary, "summary")
        object.__setattr__(self, "attributes", FreezeMapping(self.attributes))


@dataclass(frozen=True, slots=True)
class ObjectEnrichment:
    """Дополняет объект без введения типов провайдера."""

    objectKind: str
    objectReference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Сохраняет ссылки объекта типизированными и неизменяемыми."""

        RequireIdentifier(self.objectKind, "objectKind")
        RequireText(self.objectReference, "objectReference")
        object.__setattr__(self, "attributes", FreezeMapping(self.attributes))


@dataclass(frozen=True, slots=True)
class RelationEnrichment:
    """Дополняет связь без прямого изменения общего состояния."""

    relationKind: str
    sourceReference: str
    targetReference: str
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Сохраняет ссылки связи типизированными и неизменяемыми."""

        RequireIdentifier(self.relationKind, "relationKind")
        RequireText(self.sourceReference, "sourceReference")
        RequireText(self.targetReference, "targetReference")
        object.__setattr__(self, "attributes", FreezeMapping(self.attributes))


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Хранит вывод адаптера отдельно от хранения и политик."""

    report: AdapterReport
    observations: tuple[NormalizedObservation, ...] = ()
    findings: tuple[NormalizedFinding, ...] = ()
    objectEnrichments: tuple[ObjectEnrichment, ...] = ()
    relationEnrichments: tuple[RelationEnrichment, ...] = ()

    def __post_init__(self) -> None:
        """Фиксирует коллекции результата для стабильного потребления."""

        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "objectEnrichments", tuple(self.objectEnrichments))
        object.__setattr__(self, "relationEnrichments", tuple(self.relationEnrichments))


@runtime_checkable
class ToolAdapter(Protocol):
    """Задаёт контракт провайдера для управляемого исполнителя."""

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Возвращает неизменяемое объявление провайдера."""

        ...

    def CheckHealth(self) -> AdapterHealth:
        """Возвращает ограниченный результат состояния без авторизации."""

        ...

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Подготавливает ограниченный вызов из одобренного запроса."""

        ...

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Нормализует отчёт без изменения общего состояния безопасности."""

        ...
