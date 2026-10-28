# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inspect source-attributed CVE product declarations without evaluating applicability."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import FreezeMapping, JsonValue
from fuzzy1337.intel_references import ReferenceSource
from fuzzy1337.intelligence import (
    BoundedJson,
    IntelligenceFeed,
    IntelligenceObject,
    IntelligenceSnapshot,
    IntelligenceText,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.model import CanonicalModelJson

__all__ = ("CveAffectedContainer", "CveAffectedStatements", "ParseCveAffectedStatements")

APPLICABILITY_PROFILE_VERSION = 1
CVE_SCHEMA_REVISION = "5533f6038cc0434e544e69240c704906d591de46"
MAX_CONTAINERS = 65
MAX_PRODUCTS_PER_CONTAINER = 128
MAX_TOTAL_PRODUCTS = 1024
MAX_DECLARATION_ITEMS = 256
MAX_DECLARATION_BYTES = 64 * 1024
_FORMAT_VERSIONS = frozenset({"5.2", "5.2.0"})
_STATUSES = frozenset({"affected", "unaffected", "unknown"})
_PRODUCT_FIELDS = frozenset({
    "vendor", "product", "collectionURL", "packageName", "cpes", "modules", "programFiles",
    "programRoutines", "platforms", "repo", "defaultStatus", "versions", "packageURL",
})


def DeclarationObject(value: object) -> Mapping[str, object]:
    """Detach and freeze a size/depth-bounded JSON object, including direct construction.

    Args:
        value: Candidate declaration mapping containing JSON-compatible source metadata.

    Returns:
        Read-only detached declaration within the configured byte and nesting bounds.
    """

    if not isinstance(value, Mapping):
        raise ValueError("declaration must be a JSON object")

    try:
        encoded = CanonicalModelJson(value)

    except (RecursionError, TypeError) as error:
        raise ValueError("declaration must contain bounded JSON data") from error

    if len(encoded) > MAX_DECLARATION_BYTES:
        raise ValueError("declaration exceeds its byte bound")

    return FreezeMapping(IntelligenceObject(BoundedJson(encoded)))


def DeclarationArray(value: object, maximum: int, *, unique: bool = False) -> tuple[object, ...]:
    """Keep bounded source array order and enforce uniqueness only where required.

    Args:
        value: Explicit nonempty source list or tuple whose order must be retained.
        maximum: Inclusive maximum permitted number of entries.
        unique: Whether identical canonical JSON entries must be rejected.

    Returns:
        Ordered tuple of source entries without semantic conversion.
    """

    if not isinstance(value, (list, tuple)) or not value or len(value) > maximum:
        raise ValueError("declaration must be a nonempty bounded array")

    if unique and len({CanonicalModelJson(item) for item in value}) != len(value):
        raise ValueError("declaration array contains duplicate entries")

    return tuple(value)


def DeclarationStatus(value: object) -> None:
    """Reject missing or coerced statuses without changing the publisher's three states.

    Args:
        value: Explicit source status that must be affected, unaffected, or unknown.
    """

    if not isinstance(value, str) or value not in _STATUSES:
        raise ValueError("declaration status must be affected, unaffected, or unknown")


def ValidateVersion(value: object) -> None:
    """Validate explicit version/range/change shape without comparing or sorting versions.

    Args:
        value: Source version declaration with optional range bounds and status changes.
    """

    data = IntelligenceObject(JsonValue(value))
    fields = {"version", "status", "versionType", "lessThan", "lessThanOrEqual", "changes"}

    if set(data) - fields:
        raise ValueError("unsupported version declaration field")

    IntelligenceText(data.get("version"), "version", 4096)
    DeclarationStatus(data.get("status"))
    bounds = [name for name in ("lessThan", "lessThanOrEqual") if name in data]

    if len(bounds) > 1:
        raise ValueError("version range must declare only one upper bound")

    if "versionType" in data:
        IntelligenceText(data["versionType"], "versionType", 512)

    if bounds:
        IntelligenceText(data.get("versionType"), "range versionType", 512)
        IntelligenceText(data[bounds[0]], "version upper bound", 4096)

    elif "changes" in data:
        raise ValueError("status changes require an explicit version range")

    if "changes" in data:
        positions = set()

        for value in DeclarationArray(data["changes"], MAX_DECLARATION_ITEMS, unique=True):
            change = IntelligenceObject(value)

            if set(change) != {"at", "status"}:
                raise ValueError("status change requires exact at and status fields")

            position = IntelligenceText(change["at"], "change version", 4096)
            DeclarationStatus(change["status"])

            if position in positions:
                raise ValueError("status changes must not repeat a version position")

            positions.add(position)


def ValidateProduct(value: object) -> Mapping[str, object]:
    """Freeze a complete product declaration and validate consumed identity/status fields.

    Args:
        value: Complete source product declaration containing identity and status metadata.

    Returns:
        Read-only detached product declaration with original field values and array order.
    """

    data = DeclarationObject(value)

    if set(data) - _PRODUCT_FIELDS:
        raise ValueError("unsupported product declaration field")

    if not ({"vendor", "product"} <= data.keys() or
            {"collectionURL", "packageName"} <= data.keys()):
        raise ValueError("product requires vendor/product or collectionURL/packageName")

    for name, limit in (("vendor", 2048), ("product", 8192), ("collectionURL", 8192),
                        ("packageName", 8192), ("repo", 8192), ("packageURL", 8192)):
        if name in data:
            IntelligenceText(data[name], name, limit)

    if not {"versions", "defaultStatus"}.intersection(data):
        raise ValueError("product requires versions or defaultStatus")

    if "defaultStatus" in data:
        DeclarationStatus(data["defaultStatus"])

    if "versions" in data:
        for version in DeclarationArray(data["versions"], MAX_DECLARATION_ITEMS, unique=True):
            ValidateVersion(version)

    for name in ("cpes", "modules", "programFiles", "platforms", "programRoutines"):
        if name not in data:
            continue

        values = data[name]

        if name != "platforms" and values == ():
            continue

        for item in DeclarationArray(values, MAX_DECLARATION_ITEMS, unique=True):
            if name == "programRoutines":
                routine = IntelligenceObject(JsonValue(item))

                if set(routine) != {"name"}:
                    raise ValueError("program routine requires an exact name field")

                item = routine["name"]

            IntelligenceText(item, name, 16384)

    return data


@dataclass(frozen=True, slots=True)
class CveAffectedContainer:
    """Retain one CNA/ADP provider and its ordered, unevaluated product declarations."""

    role: str
    index: int
    provider: Mapping[str, object]
    products: tuple[Mapping[str, object], ...] | None

    def __post_init__(self) -> None:
        """Validate bounds and freeze declarations without filling omitted source fields."""

        if self.role not in ("cna", "adp") or type(self.index) is not int or self.index < 0:
            raise ValueError("container requires an explicit CNA/ADP role and array index")

        if self.role == "cna" and self.index != 0:
            raise ValueError("the CNA container index must be zero")

        provider = DeclarationObject(self.provider)
        IntelligenceText(provider.get("orgId"), "provider orgId", 256)
        object.__setattr__(self, "provider", provider)

        if self.products is not None:
            values = DeclarationArray(self.products, MAX_PRODUCTS_PER_CONTAINER)
            object.__setattr__(self, "products", tuple(ValidateProduct(item) for item in values))

    def ToDict(self) -> dict[str, object]:
        """Return detached upstream field names while keeping an omitted affected array absent.

        Returns:
            Container location, original provider metadata, and optional affected declarations.
        """

        result = {"role": self.role, "index": self.index,
                  "providerMetadata": JsonValue(self.provider)}

        if self.products is not None:
            result["affected"] = JsonValue(self.products)

        return result


@dataclass(frozen=True, slots=True)
class CveAffectedStatements:
    """Keep an original byte-bound snapshot with additional source-only inspection declarations."""

    snapshot: IntelligenceSnapshot
    format_version: str
    containers: tuple[CveAffectedContainer, ...]

    def __post_init__(self) -> None:
        """Require one original CVE snapshot and coherent ordered source container locations."""

        if not isinstance(self.snapshot, IntelligenceSnapshot) or (
            self.snapshot.feed is not IntelligenceFeed.CVE or len(self.snapshot.records) != 1
        ):
            raise ValueError("affected statements require one original CVE snapshot")

        if not isinstance(self.format_version, str) or self.format_version not in _FORMAT_VERSIONS:
            raise ValueError("unsupported applicability source format")

        if not isinstance(self.containers, (tuple, list)) or len(self.containers) > MAX_CONTAINERS:
            raise ValueError("affected containers exceed their bound")

        containers = tuple(self.containers)

        for position, container in enumerate(containers):
            role, index = ("cna", 0) if position == 0 else ("adp", position - 1)

            if not isinstance(container, CveAffectedContainer) or (
                container.role != role or container.index != index
            ):
                raise ValueError("source container order or index is inconsistent")

        if self.snapshot.records[0].data["state"] == "REJECTED":
            if containers:
                raise ValueError("rejected CVE records cannot supply affected declarations")

        elif not containers or containers[0].products is None:
            raise ValueError("published CVE records require CNA affected declarations")

        if sum(len(item.products or ()) for item in containers) > MAX_TOTAL_PRODUCTS:
            raise ValueError("affected products exceed their total bound")

        object.__setattr__(self, "containers", containers)

    def ToDict(self) -> dict[str, object]:
        """Return deterministic detached inspection metadata with the original snapshot binding.

        Returns:
            Profile/source format, unchanged schema-v1 snapshot, and ordered source containers.
        """

        return {"profile_version": APPLICABILITY_PROFILE_VERSION,
                "format_version": self.format_version,
                "snapshot_reference": self.snapshot.Reference(),
                "snapshot": self.snapshot.Content(),
                "containers": [container.ToDict() for container in self.containers]}


def ParseCveAffectedStatements(
    payload: bytes, catalog_version: str, source: ReferenceSource, evidence: EvidenceReference,
) -> CveAffectedStatements:
    """Inspect CVE 5.2 source product declarations without matching or changing any finding.

    Args:
        payload: Explicit authorized uncompressed UTF-8 source bytes, at most 16 MiB.
        catalog_version: Exact caller-supplied source-list revision, unchanged in the snapshot.
        source: Explicit publisher/license/import attribution bound to the source bytes.
        evidence: Original raw evidence reference with the same source digest and length.

    Returns:
        Frozen ordered source statements and the original schema-v1 CVE snapshot. Byte
        binding establishes custody only; it authenticates neither publisher nor applicability.

    Raises:
        ValueError: Source bytes, original snapshot, declaration shape, or bounds are invalid.
    """

    snapshot = ParseIntelligenceSnapshot(payload, IntelligenceFeed.CVE, catalog_version,
                                         source, evidence)
    document = IntelligenceObject(BoundedJson(payload))
    version = IntelligenceText(document.get("dataVersion"), "CVE source format", 16)

    if version not in _FORMAT_VERSIONS:
        raise ValueError("applicability inspection supports only CVE format 5.2/5.2.0")

    containers = []

    if snapshot.records[0].data["state"] == "PUBLISHED":
        source_containers = IntelligenceObject(document["containers"])
        cna = IntelligenceObject(source_containers["cna"])
        adps = source_containers.get("adp", [])

        if not isinstance(adps, list) or len(adps) >= MAX_CONTAINERS:
            raise ValueError("ADP containers exceed their bound")

        for position, value in enumerate([cna, *adps]):
            container = IntelligenceObject(value)
            products = None

            if "affected" in container:
                products = cast(tuple[Mapping[str, object], ...], DeclarationArray(
                    container["affected"], MAX_PRODUCTS_PER_CONTAINER,
                ))

            containers.append(CveAffectedContainer(
                "cna" if position == 0 else "adp", 0 if position == 0 else position - 1,
                cast(Mapping[str, object], container.get("providerMetadata")), products,
            ))

    return CveAffectedStatements(snapshot, version, tuple(containers))
