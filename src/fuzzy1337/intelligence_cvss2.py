# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inspect bounded source-attributed CVSS 2 statements without calculating scores."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import FreezeMapping, JsonValue
from fuzzy1337.intel_references import ReferenceSource
from fuzzy1337.intelligence import (
    BoundedJson,
    IntelligenceArray,
    IntelligenceFeed,
    IntelligenceNumber,
    IntelligenceObject,
    IntelligenceSnapshot,
    IntelligenceText,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.model import CanonicalModelJson

__all__ = ("CveCvss2Assessment", "CveCvss2Statements", "ParseCveCvss2Statements")

CVSS2_PROFILE_VERSION = 1
CVE_SCHEMA_REVISION = "5533f6038cc0434e544e69240c704906d591de46"
CVSS2_SCHEMA_BLOB = "caa64037aab6d6feffae1a25929c7c27f13714dd"
MAX_CONTAINERS = 65
MAX_METRICS = 256
MAX_ASSESSMENTS = 1024
MAX_CONTEXT_BYTES = 64 * 1024
_FORMAT_VERSIONS = frozenset({"5.2", "5.2.0"})
_BASE_METRICS = frozenset({"AV", "AC", "Au", "C", "I", "A"})
_SCORE_FIELDS = frozenset({"baseScore", "temporalScore", "environmentalScore"})
_CIA_VALUES = {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}
_REQUIREMENT_VALUES = {"L": "LOW", "M": "MEDIUM", "H": "HIGH", "ND": "NOT_DEFINED"}
_METRIC_FIELDS = {
    "AV": ("accessVector", {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL"}),
    "AC": ("accessComplexity", {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}),
    "Au": ("authentication", {"M": "MULTIPLE", "S": "SINGLE", "N": "NONE"}),
    "C": ("confidentialityImpact", _CIA_VALUES),
    "I": ("integrityImpact", _CIA_VALUES),
    "A": ("availabilityImpact", _CIA_VALUES),
    "E": ("exploitability", {"U": "UNPROVEN", "POC": "PROOF_OF_CONCEPT", "F": "FUNCTIONAL",
                            "H": "HIGH", "ND": "NOT_DEFINED"}),
    "RL": ("remediationLevel", {"OF": "OFFICIAL_FIX", "TF": "TEMPORARY_FIX", "W": "WORKAROUND",
                               "U": "UNAVAILABLE", "ND": "NOT_DEFINED"}),
    "RC": ("reportConfidence", {"UC": "UNCONFIRMED", "UR": "UNCORROBORATED", "C": "CONFIRMED",
                               "ND": "NOT_DEFINED"}),
    "CDP": ("collateralDamagePotential", {"N": "NONE", "L": "LOW", "LM": "LOW_MEDIUM",
                                         "MH": "MEDIUM_HIGH", "H": "HIGH", "ND": "NOT_DEFINED"}),
    "TD": ("targetDistribution", {"N": "NONE", "L": "LOW", "M": "MEDIUM", "H": "HIGH",
                                 "ND": "NOT_DEFINED"}),
    "CR": ("confidentialityRequirement", _REQUIREMENT_VALUES),
    "IR": ("integrityRequirement", _REQUIREMENT_VALUES),
    "AR": ("availabilityRequirement", _REQUIREMENT_VALUES),
}


def Cvss2Context(value: object) -> Mapping[str, object]:
    """Detach and freeze one bounded source context, including direct construction.

    Args:
        value: Provider or complete metric mapping containing JSON-compatible source data.

    Returns:
        Read-only detached source object within the byte and nesting bounds.
    """

    if not isinstance(value, Mapping):
        raise ValueError("CVSS 2 context must be a JSON object")

    encoded = CanonicalModelJson(value)

    if len(encoded) > MAX_CONTEXT_BYTES:
        raise ValueError("CVSS 2 context exceeds its byte bound")

    return FreezeMapping(IntelligenceObject(BoundedJson(encoded)))


def ValidateCvss2(value: object) -> None:
    """Validate explicit source vector/field declarations without computing a score.

    Args:
        value: Complete consumed CVSS 2 object with required version, vector and base score.

    Raises:
        ValueError: Required fields, vector grammar, scores or explicit field agreement fail.
    """

    data = IntelligenceObject(JsonValue(value))
    allowed = {"version", "vectorString", *_SCORE_FIELDS,
               *(field for field, _ in _METRIC_FIELDS.values())}

    if set(data) - allowed or data.get("version") != "2.0":
        raise ValueError("unsupported CVSS 2 assessment field or version")

    vector = IntelligenceText(data.get("vectorString"), "CVSS 2 vector", 2048)
    metrics: dict[str, str] = {}

    for component in vector.split("/"):
        parts = component.split(":")

        if len(parts) != 2 or parts[0] not in _METRIC_FIELDS or parts[0] in metrics:
            raise ValueError("CVSS 2 vector contains invalid or repeated metric names")

        name, token = parts

        if token not in _METRIC_FIELDS[name][1]:
            raise ValueError("CVSS 2 vector contains an invalid metric value")

        metrics[name] = token

    if not _BASE_METRICS.issubset(metrics):
        raise ValueError("CVSS 2 vector requires every base metric")

    IntelligenceNumber(data.get("baseScore"), 10)

    for field in _SCORE_FIELDS - {"baseScore"}:
        if field in data:
            IntelligenceNumber(data[field], 10)

    for name, (field, values) in _METRIC_FIELDS.items():
        if field not in data:
            continue

        explicit = data[field]

        if not isinstance(explicit, str) or explicit not in values.values():
            raise ValueError("CVSS 2 assessment contains an invalid enumerated field")

        if name in metrics and explicit != values[metrics[name]]:
            raise ValueError("CVSS 2 assessment field and vector token disagree")


@dataclass(frozen=True, slots=True)
class CveCvss2Assessment:
    """Retain one ordered source metric with its complete provider and scenario context."""

    role: str
    index: int
    metric_index: int
    provider: Mapping[str, object]
    metric: Mapping[str, object]

    def __post_init__(self) -> None:
        """Validate source coordinates and consumed CVSS 2 while freezing complete contexts."""

        if self.role not in ("cna", "adp") or type(self.index) is not int or self.index < 0:
            raise ValueError("CVSS 2 assessment requires a bounded CNA/ADP source position")

        if (self.role == "cna" and self.index != 0) or (
            self.role == "adp" and self.index >= MAX_CONTAINERS - 1
        ):
            raise ValueError("CVSS 2 source index is outside its container role bound")

        if type(self.metric_index) is not int or not 0 <= self.metric_index < MAX_METRICS:
            raise ValueError("CVSS 2 assessment requires a bounded metric index")

        provider = Cvss2Context(self.provider)
        IntelligenceText(provider.get("orgId"), "CVSS 2 provider orgId", 256)
        metric = Cvss2Context(self.metric)
        ValidateCvss2(metric.get("cvssV2_0"))
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "metric", metric)

    def ToDict(self) -> dict[str, object]:
        """Return detached source fields and original container/metric coordinates.

        Returns:
            Complete provider/metric objects without inferred scenarios or score conversions.
        """

        return {"role": self.role, "index": self.index, "metric_index": self.metric_index,
                "providerMetadata": JsonValue(self.provider), "metric": JsonValue(self.metric)}


@dataclass(frozen=True, slots=True)
class CveCvss2Statements:
    """Keep unchanged source-bound snapshot bytes and ordered legacy assessment statements."""

    snapshot: IntelligenceSnapshot
    format_version: str
    assessments: tuple[CveCvss2Assessment, ...]

    def __post_init__(self) -> None:
        """Require original CVE state, bounded typed assessments and strictly ordered locations."""

        if not isinstance(self.snapshot, IntelligenceSnapshot) or (
            self.snapshot.feed is not IntelligenceFeed.CVE or len(self.snapshot.records) != 1
        ):
            raise ValueError("CVSS 2 statements require one original CVE snapshot")

        if not isinstance(self.format_version, str) or self.format_version not in _FORMAT_VERSIONS:
            raise ValueError("unsupported CVSS 2 source format")

        if not isinstance(self.assessments, (tuple, list)) or (
            len(self.assessments) > MAX_ASSESSMENTS
        ):
            raise ValueError("CVSS 2 assessments exceed their count bound")

        assessments = tuple(self.assessments)
        previous = (-1, -1)

        for assessment in assessments:
            if not isinstance(assessment, CveCvss2Assessment):
                raise ValueError("CVSS 2 statements require typed source assessments")

            position = (0 if assessment.role == "cna" else assessment.index + 1,
                        assessment.metric_index)

            if position <= previous:
                raise ValueError("CVSS 2 assessment source positions must be strictly ordered")

            previous = position

        if self.snapshot.records[0].data["state"] == "REJECTED" and assessments:
            raise ValueError("rejected CVE records cannot supply positive CVSS 2 assessments")

        object.__setattr__(self, "assessments", assessments)

    def ToDict(self) -> dict[str, object]:
        """Return detached inspection data with the original snapshot and source binding.

        Returns:
            Profile/source versions, unchanged original snapshot and ordered source assessments.
        """

        return {"profile_version": CVSS2_PROFILE_VERSION, "format_version": self.format_version,
                "snapshot_reference": self.snapshot.Reference(),
                "snapshot": self.snapshot.Content(),
                "assessments": [assessment.ToDict() for assessment in self.assessments]}


def ParseCveCvss2Statements(
    payload: bytes, catalog_version: str, source: ReferenceSource, evidence: EvidenceReference,
) -> CveCvss2Statements:
    """Inspect explicit CVE 5.2 CVSS 2 source statements without changing existing snapshots.

    Args:
        payload: Explicit authorized uncompressed UTF-8 CVE source bytes, at most 16 MiB.
        catalog_version: Exact caller-supplied source-list revision retained in the snapshot.
        source: Explicit publisher/license/import attribution bound to the same source bytes.
        evidence: Original raw evidence reference with the same source digest and byte length.

    Returns:
        Frozen ordered assessments and the unchanged original schema-one CVE snapshot.
        Hash binding establishes custody, without authenticating the publisher or its scores.

    Raises:
        ValueError: Source binding, consumed assessment structure, or configured bounds fail.
    """

    snapshot = ParseIntelligenceSnapshot(payload, IntelligenceFeed.CVE, catalog_version,
                                         source, evidence)
    document = IntelligenceObject(BoundedJson(payload))
    version = IntelligenceText(document.get("dataVersion"), "CVE source format", 16)

    if version not in _FORMAT_VERSIONS:
        raise ValueError("CVSS 2 source inspection supports only CVE format 5.2/5.2.0")

    assessments = []

    if snapshot.records[0].data["state"] == "PUBLISHED":
        containers = IntelligenceObject(document["containers"])
        cna = IntelligenceObject(containers["cna"])
        adps = IntelligenceArray(containers.get("adp", []), MAX_CONTAINERS - 1)

        for position, value in enumerate([cna, *adps]):
            container = IntelligenceObject(value)
            metrics = IntelligenceArray(container.get("metrics", []), MAX_METRICS)

            for index, value in enumerate(metrics):
                metric = IntelligenceObject(value)

                if "cvssV2_0" in metric:
                    assessments.append(CveCvss2Assessment(
                        "cna" if position == 0 else "adp", 0 if position == 0 else position - 1,
                        index, IntelligenceObject(container.get("providerMetadata")), metric,
                    ))

                    if len(assessments) > MAX_ASSESSMENTS:
                        raise ValueError("CVSS 2 assessments exceed their total bound")

    return CveCvss2Statements(snapshot, version, tuple(assessments))
