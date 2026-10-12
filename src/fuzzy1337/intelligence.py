# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental bounded offline intelligence assertions and verified finding observations."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import xml.etree.ElementTree as element_tree
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Finding
from fuzzy1337.intel_references import (
    NormalizeReferenceTime,
    ReferenceFields,
    ReferenceSource,
    RejectReferenceConstant,
    RequireReferenceText,
    UniqueReferenceObject,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelAttributes,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectKind,
    Observation,
    RequireModelReference,
)
from fuzzy1337.workspace import DecodeEvidenceReference, LocalWorkspaceStore

__all__ = (
    "IntelligenceFeed", "IntelligenceRecord", "IntelligenceSnapshot",
    "ParseIntelligenceSnapshot", "ApplyVerifiedEnrichment",
)

INTELLIGENCE_SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 500_000
MAX_DEPTH = 32
MAX_SELECTED_RECORDS = 64
_CVE_FORMAT_VERSIONS = frozenset({"5.0", "5.0.0", "5.1", "5.1.0", "5.1.1", "5.2", "5.2.0"})
_CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_CWE_PATTERN = re.compile(r"CWE-[1-9][0-9]{0,9}\Z")
_DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_TIME_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.+\Z")
_DECIMAL_PATTERN = re.compile(r"(?:0(?:\.[0-9]+)?|1(?:\.0+)?)\Z")
_CWE_NAMESPACE = "http://cwe.mitre.org/cwe-7"
_CVSS3_METRICS = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN",
    "I": "HLN", "A": "HLN", "E": "XHFPU", "RL": "XUWTO", "RC": "XCRU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML", "MAV": "XNALP", "MAC": "XLH",
    "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH",
    "MA": "XNLH",
}
_CVSS4_METRICS = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN",
    "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN", "E": "XAPU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML", "MAV": "XNALP", "MAC": "XLH",
    "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA", "MVC": "XNLH", "MVI": "XNLH",
    "MVA": "XNLH", "MSC": "XNLH", "MSI": "XNLHS", "MSA": "XNLHS", "S": "XNP",
    "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH", "U": "X Clear Green Amber Red",
}


class IntelligenceFeed(StrEnum):
    """Name supported upstream formats without authenticating their attributed publishers."""

    CVE = "cve-record-5"
    CWE = "cwe-xml-7"
    KEV = "cisa-kev-json"
    EPSS = "first-epss-csv"


def IntelligenceText(value: object, name: str, limit: int = 8192) -> str:
    """Validate bounded printable metadata; source bytes retain unnormalized upstream prose.

    Args:
        value: Candidate metadata scalar without type coercion.
        name: Field label used for validation errors.
        limit: Maximum permitted UTF-8 byte length.

    Returns:
        Unchanged printable bounded metadata.
    """

    text = RequireReferenceText(value, name, limit)

    if not text.isprintable():
        raise ValueError(f"{name} must be printable metadata")

    return text


def IntelligenceIdentifier(value: object) -> str:
    """Require an exact case-preserved CVE or CWE ID rather than normalizing a fuzzy match.

    Args:
        value: Explicit external identifier supplied by a source or finding owner.

    Returns:
        Validated identifier without normalization or an existence assertion.
    """

    identifier = IntelligenceText(value, "identifier", 64)

    if not (_CVE_PATTERN.fullmatch(identifier) or _CWE_PATTERN.fullmatch(identifier)):
        raise ValueError("identifier must be an exact CVE or CWE identifier")

    return identifier


def IntelligenceTime(value: object) -> str:
    """Normalize explicitly offset-aware calendar timestamps with a strict date prefix.

    Args:
        value: Calendar timestamp with an explicit timezone offset.

    Returns:
        Canonical UTC timestamp with fixed microsecond precision.
    """

    text = IntelligenceText(value, "timestamp", 128)

    if not _TIME_PATTERN.fullmatch(text):
        raise ValueError("timestamp must use an explicit calendar date and UTC offset")

    return NormalizeReferenceTime(text)


def IntelligenceDate(value: object) -> str:
    """Validate a source calendar day without accepting reduced, ordinal, or week dates.

    Args:
        value: Explicit YYYY-MM-DD source calendar date.

    Returns:
        Validated unchanged calendar date.
    """

    text = IntelligenceText(value, "date", 10)

    if not _DATE_PATTERN.fullmatch(text):
        raise ValueError("date must use YYYY-MM-DD")

    return date.fromisoformat(text).isoformat()


def IntelligenceNumber(value: object, maximum: float) -> float:
    """Reject booleans, unbounded integers, nonfinite values, and out-of-range source scores.

    Args:
        value: Numeric source score without string or boolean coercion.
        maximum: Inclusive maximum for this metric family.

    Returns:
        Finite non-negative floating-point source score.
    """

    if type(value) not in (int, float):
        raise ValueError("score must be a bounded non-negative number")

    scalar = cast(int | float, value)

    if not 0 <= scalar <= maximum:
        raise ValueError("score must be a bounded non-negative number")

    result = float(scalar)

    if not math.isfinite(result):
        raise ValueError("score must be finite")

    return result


def IntelligenceObject(value: object) -> dict[str, object]:
    """Require an upstream object while leaving unconsumed fields in retained raw evidence.

    Args:
        value: Decoded candidate source object.

    Returns:
        Explicit dictionary without guessed fields.
    """

    if not isinstance(value, dict):
        raise ValueError("source field must be a JSON object")

    return cast(dict[str, object], value)


def IntelligenceArray(value: object, maximum: int = MAX_RECORDS) -> list[object]:
    """Require a finite explicit upstream array before iterating decoded records.

    Args:
        value: Decoded candidate source array.
        maximum: Maximum number of entries for this boundary.

    Returns:
        Explicit bounded list without scalar iteration.
    """

    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("source field must be a bounded JSON array")

    return value


def BoundedJson(payload: bytes) -> object:
    """Parse bounded strict JSON with duplicate, numeric-token, encoding, and depth rejection.

    Args:
        payload: UTF-8 source or snapshot bytes within the configured byte bound.

    Returns:
        Detached JSON values with bounded structure and finite numbers.
    """

    if not isinstance(payload, bytes) or len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("intelligence payload must be bounded bytes")

    def Number(token: str) -> int | float:
        """Reject large numeric tokens before conversion, including exponent overflow."""

        if len(token) > 32:
            raise ValueError("numeric token exceeds its bound")

        result = float(token) if any(character in token for character in ".eE") else int(token)

        if isinstance(result, float) and not math.isfinite(result):
            raise ValueError("numeric token must be finite")

        return result

    try:
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=UniqueReferenceObject,
            parse_constant=RejectReferenceConstant, parse_int=Number, parse_float=Number,
        )

    except (UnicodeError, RecursionError) as error:
        raise ValueError("intelligence requires bounded valid UTF-8 JSON") from error

    pending = [(document, 0)]

    while pending:
        value, depth = pending.pop()

        if depth > MAX_DEPTH:
            raise ValueError("intelligence JSON exceeds its depth bound")

        children = value.values() if isinstance(value, dict) else value if isinstance(
            value, list,
        ) else ()
        pending.extend((child, depth + 1) for child in children)

    return document


def CvssAssessment(value: object, assessor: str) -> dict[str, object]:
    """Preserve an asserted 3.0/3.1/4.0 score/vector and validate grammar without calculating.

    Args:
        value: Upstream CVSS fields including version, vectorString, and baseScore.
        assessor: Explicit CNA or ADP attribution from the source container.

    Returns:
        Normalized source assessment without score conversion or target applicability.
    """

    data = IntelligenceObject(value)
    version = IntelligenceText(data.get("version"), "CVSS version", 8)

    if version not in ("3.0", "3.1", "4.0"):
        raise ValueError("unsupported CVSS assessment version")

    vector = IntelligenceText(data.get("vectorString"), "CVSS vector", 2048)
    components = vector.split("/")

    if components.pop(0) != f"CVSS:{version}":
        raise ValueError("CVSS vector prefix must match its asserted version")

    allowed = _CVSS4_METRICS if version == "4.0" else _CVSS3_METRICS
    keys = []

    for component in components:
        parts = component.split(":")

        if len(parts) != 2 or parts[0] not in allowed or parts[0] in keys:
            raise ValueError("CVSS vector has invalid or repeated metric names")

        key, metric = parts
        options = allowed[key].split() if key == "U" and version == "4.0" else allowed[key]

        if metric not in options or (not isinstance(options, list) and len(metric) != 1):
            raise ValueError("CVSS vector has an invalid metric value")

        keys.append(key)

    base = tuple(allowed)[:11 if version == "4.0" else 8]

    if not set(base).issubset(keys):
        raise ValueError("CVSS vector must contain every base metric")

    if version == "4.0" and keys != sorted(keys, key=tuple(allowed).index):
        raise ValueError("CVSS 4.0 metrics must use the specification order")

    return {
        "version": version, "vector": vector,
        "base_score": IntelligenceNumber(data.get("baseScore"), 10),
        "assessor": IntelligenceText(assessor, "assessor", 256),
    }


def RecordData(feed: IntelligenceFeed, value: object) -> Mapping[str, object]:
    """Validate exact normalized fields independently of an upstream parser or JSON transport.

    Args:
        feed: Supported source family defining the normalized assertion field set.
        value: Candidate normalized record data.

    Returns:
        Recursively immutable validated source assertion fields.
    """

    fields_by_feed = {
        IntelligenceFeed.CVE: {"state", "description", "cwe_ids", "cvss", "unsupported_metrics"},
        IntelligenceFeed.CWE: {"name", "status"},
        IntelligenceFeed.KEV: {
            "date_added", "due_date", "vendor", "product", "name", "required_action",
            "ransomware_use",
        },
        IntelligenceFeed.EPSS: {"probability", "percentile", "model_version"},
    }
    data = ReferenceFields(JsonValue(value), fields_by_feed[feed])

    if feed is IntelligenceFeed.CVE:
        if data["state"] not in ("PUBLISHED", "REJECTED"):
            raise ValueError("CVE state must remain published or rejected")

        if data["description"] is not None:
            IntelligenceText(data["description"], "description")

        for identifier in IntelligenceArray(data["cwe_ids"], 256):
            if not IntelligenceIdentifier(identifier).startswith("CWE-"):
                raise ValueError("CVE weakness classifications must use CWE identifiers")

        for assessment in IntelligenceArray(data["cvss"], 256):
            details = ReferenceFields(assessment, {"version", "vector", "base_score", "assessor"})
            CvssAssessment({"version": details["version"], "vectorString": details["vector"],
                            "baseScore": details["base_score"]}, cast(str, details["assessor"]))

        for name in IntelligenceArray(data["unsupported_metrics"], 256):
            IntelligenceText(name, "unsupported metric", 128)

        if data["state"] == "REJECTED" and (data["cvss"] or data["cwe_ids"]):
            raise ValueError("rejected CVE records cannot carry vulnerability assessments")

    elif feed is IntelligenceFeed.CWE:
        IntelligenceText(data["name"], "name")
        IntelligenceText(data["status"], "status", 128)

    elif feed is IntelligenceFeed.KEV:
        added = IntelligenceDate(data["date_added"])
        due = IntelligenceDate(data["due_date"])

        if due < added:
            raise ValueError("KEV due date must not precede addition")

        for name in ("vendor", "product", "name", "required_action"):
            IntelligenceText(data[name], name)

        if data["ransomware_use"] not in ("Known", "Unknown"):
            raise ValueError("KEV ransomware assertion must remain Known or Unknown")

    else:
        IntelligenceNumber(data["probability"], 1)
        IntelligenceNumber(data["percentile"], 1)
        IntelligenceText(data["model_version"], "model_version", 128)

    return ModelAttributes(data)


@dataclass(frozen=True, slots=True)
class IntelligenceRecord:
    """Retain one version-bound external assertion, never a newly detected vulnerability."""

    feed: IntelligenceFeed
    identifier: str
    catalog_version: str
    effective_at: str
    data: Mapping[str, object]

    def __post_init__(self) -> None:
        """Freeze typed fields, exact identifiers, and source assertions deterministically."""

        if not isinstance(self.feed, IntelligenceFeed):
            raise ValueError("feed must be an IntelligenceFeed")

        identifier = IntelligenceIdentifier(self.identifier)

        if identifier.startswith("CWE-") != (self.feed is IntelligenceFeed.CWE):
            raise ValueError("record identifier does not match its feed")

        IntelligenceText(self.catalog_version, "catalog_version", 256)
        object.__setattr__(self, "effective_at", IntelligenceTime(self.effective_at))
        object.__setattr__(self, "data", RecordData(self.feed, self.data))

    def ToDict(self) -> dict[str, object]:
        """Return detached normalized assertions with version-bound identity fields.

        Returns:
            Complete feed, identifier, version, source time, and assertion fields.
        """

        return {
            "feed": self.feed.value, "identifier": self.identifier,
            "catalog_version": self.catalog_version, "effective_at": self.effective_at,
            "data": JsonValue(self.data),
        }

    def Reference(self) -> str:
        """Identify exact normalized content without changing a Security Object identity.

        Returns:
            Domain-separated intel-record reference covering exact normalized content.
        """

        return "intel-record:" + hashlib.sha256(CanonicalModelJson({
            "domain": "fuzzy1337.intelligence.record.v1", "content": self.ToDict(),
        })).hexdigest()

    def CanonicalUrl(self) -> str:
        """Return a canonical public identifier locator without a fetch or existence claim.

        Returns:
            Public CVE or CWE identifier URL independent of installation paths.
        """

        if self.feed is IntelligenceFeed.CWE:
            return f"https://cwe.mitre.org/data/definitions/{self.identifier[4:]}.html"

        return f"https://www.cve.org/CVERecord?id={self.identifier}"

    @classmethod
    def FromDict(cls, value: object) -> IntelligenceRecord:
        """Decode exact normalized record fields without trusting stored type or version claims.

        Args:
            value: Detached exact normalized record JSON fields.

        Returns:
            Typed immutable version-bound source assertion.
        """

        data = ReferenceFields(value, {"feed", "identifier", "catalog_version", "effective_at",
                                       "data"})

        return cls(
            IntelligenceFeed(IntelligenceText(data["feed"], "feed")),
            IntelligenceText(data["identifier"], "identifier"),
            IntelligenceText(data["catalog_version"], "catalog_version"),
            IntelligenceText(data["effective_at"], "effective_at"),
            cast(Mapping[str, object], data["data"]),
        )


@dataclass(frozen=True, slots=True)
class IntelligenceSnapshot:
    """Pin one parsed artifact, explicit source/license/version metadata, and raw evidence."""

    feed: IntelligenceFeed
    catalog_version: str
    source: ReferenceSource
    evidence: EvidenceReference
    records: tuple[IntelligenceRecord, ...]

    def __post_init__(self) -> None:
        """Freeze records while checking type, source binding, chronology, and uniqueness."""

        if (
            not isinstance(self.feed, IntelligenceFeed)
            or not isinstance(self.source, ReferenceSource)
        ):
            raise ValueError("snapshot requires typed feed and source attribution")

        IntelligenceText(self.catalog_version, "catalog_version", 256)

        if not isinstance(self.evidence, EvidenceReference):
            raise ValueError("snapshot evidence must use EvidenceReference")

        DecodeEvidenceReference(JsonValue(self.evidence))

        if self.evidence.sha256 != self.source.artifact_sha256:
            raise ValueError("snapshot evidence and attributed source digests disagree")

        if not isinstance(self.records, (tuple, list)) or len(self.records) > MAX_RECORDS:
            raise ValueError("snapshot records must be a bounded sequence")

        for record in self.records:
            if not isinstance(record, IntelligenceRecord) or (
                record.feed is not self.feed or record.catalog_version != self.catalog_version
            ):
                raise ValueError("record feed and catalog version must match the snapshot")

            if record.effective_at > self.source.acquired_at:
                raise ValueError("source assertion must not follow artifact acquisition")

        if len({record.identifier for record in self.records}) != len(self.records):
            raise ValueError("snapshot identifiers must be unique")

        object.__setattr__(self, "records", tuple(sorted(
            self.records, key=lambda item: item.identifier,
        )))

    def Content(self) -> dict[str, object]:
        """Return exact normalized content and detached source/raw-artifact attribution.

        Returns:
            Complete schema-v1 snapshot fields before adding its content reference.
        """

        return {
            "schema_version": INTELLIGENCE_SCHEMA_VERSION, "feed": self.feed.value,
            "catalog_version": self.catalog_version, "source": self.source.ToDict(),
            "evidence": JsonValue(self.evidence),
            "records": [item.ToDict() for item in self.records],
        }

    def Reference(self) -> str:
        """Hash all source, license, version, evidence, and parsed content fields together.

        Returns:
            Domain-separated intel-snapshot reference for the full attributed revision.
        """

        return "intel-snapshot:" + hashlib.sha256(CanonicalModelJson({
            "domain": "fuzzy1337.intelligence.snapshot.v1", "content": self.Content(),
        })).hexdigest()

    def Serialize(self) -> bytes:
        """Serialize bounded strict schema-v1 JSON with its recomputable content reference.

        Returns:
            Canonical UTF-8 interchange bytes within the snapshot byte bound.
        """

        payload = CanonicalModelJson({**self.Content(), "reference": self.Reference()})

        if len(payload) > MAX_SOURCE_BYTES:
            raise ValueError("snapshot transport exceeds its byte bound")

        return payload

    @classmethod
    def Deserialize(cls, payload: bytes) -> IntelligenceSnapshot:
        """Recompute strict transport content; byte integrity is reverified at the consumer.

        Args:
            payload: Bounded UTF-8 exact schema-v1 snapshot document.

        Returns:
            Immutable validated content-addressed source snapshot.
        """

        data = ReferenceFields(BoundedJson(payload), {
            "schema_version", "feed", "catalog_version", "source", "evidence", "records",
            "reference",
        })

        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError("unsupported intelligence schema_version")

        snapshot = cls(
            IntelligenceFeed(IntelligenceText(data["feed"], "feed")),
            IntelligenceText(data["catalog_version"], "catalog_version"),
            ReferenceSource.FromDict(data["source"]), DecodeEvidenceReference(data["evidence"]),
            tuple(IntelligenceRecord.FromDict(value) for value in IntelligenceArray(
                data["records"],
            )),
        )

        if data["reference"] != snapshot.Reference():
            raise ValueError("snapshot content reference mismatch")

        return snapshot


def ParseCve(payload: bytes, catalog_version: str) -> tuple[IntelligenceRecord, ...]:
    """Parse supported CVE Record 5.x CNA/ADP assertions and rejected/unsupported states.

    Args:
        payload: Bounded explicitly supplied CVE Record JSON bytes.
        catalog_version: Exact source-list revision independent of its JSON schema version.

    Returns:
        One version-bound record retaining separate supported source assessments.
    """

    document = IntelligenceObject(BoundedJson(payload))

    if (
        document.get("dataType") != "CVE_RECORD"
        or document.get("dataVersion") not in _CVE_FORMAT_VERSIONS
    ):
        raise ValueError("unsupported CVE Record format")

    metadata = IntelligenceObject(document.get("cveMetadata"))
    identifier = IntelligenceIdentifier(metadata.get("cveId"))
    state = metadata.get("state")
    effective = IntelligenceTime(metadata.get("dateUpdated"))
    containers = IntelligenceObject(document.get("containers"))
    cna = IntelligenceObject(containers.get("cna"))
    records = [cna, *(IntelligenceObject(value) for value in IntelligenceArray(
        containers.get("adp", []), 256,
    ))]
    descriptions = IntelligenceArray(cna.get("descriptions" if state == "PUBLISHED"
                                           else "rejectedReasons", []), 256)
    description = None

    if descriptions:
        item = IntelligenceObject(next((item for item in descriptions if IntelligenceObject(
            item,
        ).get("lang") == "en"), descriptions[0]))
        raw = item.get("value")

        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 8192:
            raise ValueError("CVE description must be bounded text")

        description = IntelligenceText(" ".join(raw.split()), "description")

    cwe_ids: set[str] = set()
    metrics = []
    unsupported = set()

    if state == "PUBLISHED":
        for container in records:
            assessor = IntelligenceText(IntelligenceObject(container.get("providerMetadata")).get(
                "orgId",
            ), "assessor", 256)

            for problem in IntelligenceArray(container.get("problemTypes", []), 256):
                for problem_description in IntelligenceArray(IntelligenceObject(problem).get(
                    "descriptions", [],
                ), 256):
                    cwe = IntelligenceObject(problem_description).get("cweId")

                    if cwe is not None:
                        cwe_ids.add(IntelligenceIdentifier(cwe))

            for metric in IntelligenceArray(container.get("metrics", []), 256):
                for name, assessment in IntelligenceObject(metric).items():
                    versions = {"cvssV3_0": "3.0", "cvssV3_1": "3.1", "cvssV4_0": "4.0"}

                    if name in versions:
                        parsed = CvssAssessment(assessment, assessor)

                        if parsed["version"] != versions[name]:
                            raise ValueError("CVSS field name and version disagree")

                        metrics.append(parsed)

                    elif name.startswith("cvss") or name == "other":
                        unsupported.add(IntelligenceText(name, "unsupported metric", 128))

    data = {"state": state, "description": description, "cwe_ids": sorted(cwe_ids),
            "cvss": sorted(metrics, key=CanonicalModelJson),
            "unsupported_metrics": sorted(unsupported)}

    return (IntelligenceRecord(IntelligenceFeed.CVE, identifier, catalog_version, effective, data),)


def ParseCwe(payload: bytes, catalog_version: str) -> tuple[IntelligenceRecord, ...]:
    """Parse bounded namespace-7 CWE XML without DTD/entity expansion or external references.

    Args:
        payload: Bounded UTF-8 CWE catalog XML bytes.
        catalog_version: Exact expected Weakness_Catalog version attribute.

    Returns:
        Version-bound weakness records from the declared weakness collection.
    """

    if not isinstance(payload, bytes) or len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("CWE payload must be bounded bytes")

    try:
        text = payload.decode("utf-8")

        if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
            raise ValueError("CWE XML must not declare DTDs or entities")

        depth = 0
        records: list[IntelligenceRecord] = []
        nodes = 0
        effective = ""
        parents = []

        for event, node in element_tree.iterparse(io.StringIO(text), events=("start", "end")):
            if event == "start":
                depth += 1
                nodes += 1
                parents.append(node.tag)

                if depth > MAX_DEPTH or nodes > MAX_RECORDS * 16:
                    raise ValueError("CWE XML exceeds its structural bound")

                if nodes == 1:
                    if node.tag != f"{{{_CWE_NAMESPACE}}}Weakness_Catalog" or node.get(
                        "Version",
                    ) != catalog_version:
                        raise ValueError("CWE namespace or catalog version mismatch")

                    effective = IntelligenceTime(IntelligenceDate(node.get("Date")) + "T00:00:00Z")

                if node.tag == f"{{{_CWE_NAMESPACE}}}Weakness":
                    if depth != 3 or parents[-2] != f"{{{_CWE_NAMESPACE}}}Weaknesses":
                        raise ValueError("CWE weakness must belong to the weakness collection")

                    records.append(IntelligenceRecord(
                        IntelligenceFeed.CWE,
                        "CWE-" + IntelligenceText(node.get("ID"), "CWE ID", 10),
                        catalog_version, effective,
                        {"name": node.get("Name"), "status": node.get("Status")},
                    ))

                    if len(records) > MAX_RECORDS:
                        raise ValueError("CWE catalog exceeds its record bound")

            else:
                depth -= 1
                parents.pop()
                node.clear()

        return tuple(records)

    except (UnicodeError, element_tree.ParseError) as error:
        raise ValueError("CWE source must be valid UTF-8 XML") from error


def ParseKev(payload: bytes, catalog_version: str) -> tuple[IntelligenceRecord, ...]:
    """Parse CISA catalog membership and dates without deriving target exploitation or absence.

    Args:
        payload: Bounded CISA KEV catalog JSON bytes.
        catalog_version: Exact expected catalogVersion field.

    Returns:
        Source membership assertions preserving dates and ransomware uncertainty.
    """

    document = IntelligenceObject(BoundedJson(payload))
    entries = IntelligenceArray(document.get("vulnerabilities"))

    if document.get("catalogVersion") != catalog_version or type(document.get("count")) is not int:
        raise ValueError("KEV catalog requires an exact version and integer count")

    if document["count"] != len(entries):
        raise ValueError("KEV count disagrees with the supplied artifact")

    effective = IntelligenceTime(document.get("dateReleased"))
    records = []

    for entry in entries:
        item = IntelligenceObject(entry)
        data = {
            "date_added": item.get("dateAdded"), "due_date": item.get("dueDate"),
            "vendor": item.get("vendorProject"), "product": item.get("product"),
            "name": item.get("vulnerabilityName"), "required_action": item.get("requiredAction"),
            "ransomware_use": item.get("knownRansomwareCampaignUse"),
        }
        record = IntelligenceRecord(IntelligenceFeed.KEV, IntelligenceIdentifier(item.get("cveID")),
                                    catalog_version, effective, data)

        if cast(str, record.data["date_added"]) > effective[:10]:
            raise ValueError("KEV addition must not follow its catalog release")

        records.append(record)

    return tuple(records)


def ParseEpss(payload: bytes, catalog_version: str) -> tuple[IntelligenceRecord, ...]:
    """Parse uncompressed FIRST daily CSV with exact model/date metadata and bounded scores.

    Args:
        payload: Bounded uncompressed UTF-8 daily score CSV bytes.
        catalog_version: Exact expected score model version, never the API version.

    Returns:
        Daily probability/percentile assertions with their exact score timestamp.
    """

    if not isinstance(payload, bytes) or len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("EPSS payload must be bounded bytes")

    try:
        stream = io.StringIO(payload.decode("utf-8"), newline="")
        metadata_line = stream.readline()

        if len(metadata_line) > 512 or not metadata_line.startswith("#"):
            raise ValueError("EPSS requires model/version and score-date metadata")

        metadata = {}

        for component in metadata_line.strip()[1:].split(","):
            key, separator, value = component.partition(":")

            if not separator or key in metadata:
                raise ValueError("EPSS metadata fields must be unique and explicit")

            metadata[key] = value

        if (
            set(metadata) != {"model_version", "score_date"}
            or metadata["model_version"] != catalog_version
        ):
            raise ValueError("EPSS catalog version must match its model metadata")

        effective = IntelligenceTime(metadata["score_date"])
        reader = csv.reader(stream, strict=True)

        if next(reader, None) != ["cve", "epss", "percentile"]:
            raise ValueError("EPSS requires exact cve,epss,percentile columns")

        records: list[IntelligenceRecord] = []

        for row in reader:
            if len(row) != 3 or len(records) >= MAX_RECORDS:
                raise ValueError("EPSS rows must match columns and record bounds")

            values = []

            for value in row[1:]:
                if len(value) > 32 or not _DECIMAL_PATTERN.fullmatch(value):
                    raise ValueError("EPSS scores must be finite decimal probabilities")

                values.append(IntelligenceNumber(float(value), 1))

            records.append(IntelligenceRecord(
                IntelligenceFeed.EPSS, IntelligenceIdentifier(row[0]), catalog_version, effective,
                {"probability": values[0], "percentile": values[1],
                 "model_version": catalog_version},
            ))

        return tuple(records)

    except (UnicodeError, csv.Error) as error:
        raise ValueError("EPSS source must be valid bounded UTF-8 CSV") from error


def ParseIntelligenceSnapshot(
    payload: bytes, feed: IntelligenceFeed, catalog_version: str,
    source: ReferenceSource, evidence: EvidenceReference,
) -> IntelligenceSnapshot:
    """Bind a bounded pure parser result to exact attributed source bytes and raw evidence.

    Args:
        payload: Authorized uncompressed UTF-8 artifact bytes.
        feed: Explicit supported source format.
        catalog_version: Exact CVE-list revision, CWE/KEV version, or EPSS model version.
        source: Explicit publisher/license/import attribution with the actual artifact digest.
        evidence: Existing raw-artifact reference; verification reads are consumer-owned.

    Returns:
        Immutable deterministic source assertion snapshot; no review approval is created.

    Raises:
        ValueError: Format, bounds, identities, source metadata, times or byte binding are invalid.
    """

    if not isinstance(payload, bytes) or len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("intelligence payload must be bounded bytes")

    if not isinstance(feed, IntelligenceFeed) or not isinstance(source, ReferenceSource):
        raise ValueError("parser requires typed feed and source attribution")

    IntelligenceText(catalog_version, "catalog_version", 256)

    if not isinstance(evidence, EvidenceReference) or (
        source.artifact_sha256 != hashlib.sha256(payload).hexdigest()
        or evidence.sha256 != source.artifact_sha256 or evidence.size_bytes != len(payload)
    ):
        raise ValueError("source bytes, attributed digest, and raw evidence must agree")

    parser = {
        IntelligenceFeed.CVE: ParseCve, IntelligenceFeed.CWE: ParseCwe,
        IntelligenceFeed.KEV: ParseKev, IntelligenceFeed.EPSS: ParseEpss,
    }[feed]

    try:
        return IntelligenceSnapshot(
            feed, catalog_version, source, evidence, parser(payload, catalog_version),
        )

    except KeyError as error:
        raise ValueError("source document is missing a consumed required field") from error


def ApplyVerifiedEnrichment(
    state: ModelState, finding_reference: str, identifiers: tuple[str, ...],
    snapshots: tuple[IntelligenceSnapshot, ...], provenance: ModelProvenance,
    workspace_root: Path, *, as_of: str, max_age_seconds: int,
) -> tuple[ModelState, ModelDelta]:
    """Verify and reparse sources, then append exact-ID assertions without modifying finding triage.

    Args:
        state: Owning canonical model with an existing evidence-linked finding.
        finding_reference: Existing canonical finding object reference.
        identifiers: Explicit exact CVE/CWE associations supplied by the finding owner.
        snapshots: Explicit immutable source snapshots; no automatic discovery occurs.
        provenance: Caller-supplied attribution for this interpretation, never authorization.
        workspace_root: Existing owning workspace directory and evidence partition.
        as_of: Explicit offset-aware interpretation time; no wall clock is consulted.
        max_age_seconds: Explicit non-negative freshness budget, distinct from a risk policy.

    Returns:
        Proposed immutable model state/delta containing only a new attributable observation.

    Raises:
        ValueError: Inputs, source/subject ownership, chronology or reparse agreement are invalid.
        EvidenceError: A detector, source or attribution artifact is missing, corrupt or unsafe.
    """

    if not isinstance(state, ModelState) or not isinstance(provenance, ModelProvenance):
        raise ValueError("enrichment requires typed state and provenance")

    RequireModelReference(finding_reference)
    entities = [entity for entity in state.Objects(ObjectKind.FINDING)
                if entity.Reference() == finding_reference]

    if not entities:
        raise ValueError("enrichment requires an existing canonical finding")

    finding = Finding.FromObject(entities[0])

    if (
        not isinstance(identifiers, (tuple, list))
        or not 1 <= len(identifiers) <= MAX_SELECTED_RECORDS
    ):
        raise ValueError("enrichment requires a bounded explicit identifier sequence")

    requested = tuple(sorted(IntelligenceIdentifier(value) for value in identifiers))

    if len(set(requested)) != len(requested):
        raise ValueError("enrichment identifiers must be unique")

    if not isinstance(snapshots, (tuple, list)) or not 1 <= len(snapshots) <= 16 or any(
        not isinstance(snapshot, IntelligenceSnapshot) for snapshot in snapshots
    ):
        raise ValueError("enrichment requires a bounded typed snapshot sequence")

    if type(max_age_seconds) is not int or not 0 <= max_age_seconds <= 10 * 365 * 86400:
        raise ValueError("freshness budget must be a bounded non-negative integer")

    observed = IntelligenceTime(as_of)

    if provenance.observed_at != observed:
        raise ValueError("enrichment as-of time must match its interpretation attribution")

    workspace = LocalWorkspaceStore(workspace_root)

    if workspace.Open().workspace_id != state.workspace_id:
        raise ValueError("enrichment evidence must belong to the model workspace")

    evidence_store = LocalEvidenceStore(workspace.root / "evidence")
    evidence = {
        reference for record in finding.provenance for reference in record.evidence_references
    }
    evidence.update(provenance.evidence_references)
    matches = []
    matched = set()
    seen = set()

    for snapshot in sorted(snapshots, key=lambda item: item.Reference()):
        reference = snapshot.Reference()

        if reference in seen:
            raise ValueError("enrichment snapshots must be unique")

        seen.add(reference)

        if snapshot.source.acquired_at > observed:
            raise ValueError("source acquisition must not follow the enrichment as-of time")

        raw = evidence_store.Read(snapshot.evidence)
        reparsed = ParseIntelligenceSnapshot(
            raw, snapshot.feed, snapshot.catalog_version, snapshot.source, snapshot.evidence,
        )

        if reparsed != snapshot:
            raise ValueError("supplied snapshot disagrees with its verified source bytes")

        evidence.add(snapshot.evidence)

        for record in snapshot.records:
            if record.identifier not in requested:
                continue

            fresh_at = record.effective_at if snapshot.feed is IntelligenceFeed.EPSS else (
                snapshot.source.acquired_at
            )
            age = (
                datetime.fromisoformat(observed) - datetime.fromisoformat(fresh_at)
            ).total_seconds()
            matched.add(record.identifier)
            matches.append({
                "snapshot_reference": reference, "record_reference": record.Reference(),
                "record": record.ToDict(), "source": snapshot.source.ToDict(),
                "canonical_url": record.CanonicalUrl(), "evidence": JsonValue(snapshot.evidence),
                "freshness_at": fresh_at, "age_seconds": age, "stale": age > max_age_seconds,
                "association_state": "candidate", "review": None,
            })

            if len(matches) > MAX_SELECTED_RECORDS:
                raise ValueError("selected intelligence exceeds its observation record bound")

    for evidence_reference in sorted(evidence, key=CanonicalModelJson):
        evidence_store.Read(evidence_reference)

    attributed = replace(provenance, evidence_references=tuple(evidence))
    observation = Observation("finding-intelligence", finding_reference, {
        "schema_version": INTELLIGENCE_SCHEMA_VERSION, "as_of": observed,
        "max_age_seconds": max_age_seconds, "requested_identifiers": requested,
        "unmatched_identifiers": tuple(
            identifier for identifier in requested if identifier not in matched
        ),
        "source_assertions": matches,
    }, attributed)

    return state.Apply(observations=(observation,))
