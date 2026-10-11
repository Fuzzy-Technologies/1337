# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental normalized findings within the canonical workspace Security Object Model."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

from fuzzy1337.adapters.contracts import JsonValue, RequireIdentifier
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelAttributes,
    ModelDelta,
    ModelProvenance,
    ModelSequence,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    ProvenanceCollection,
    RequireModelReference,
    SecurityObject,
)
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    WorkspaceFields,
)

FINDING_SCHEMA_VERSION = 1
_FINDING_FIELDS = {
    "schema_version", "fingerprint", "subject_reference", "check_id", "location_key",
    "summary", "severity", "confidence", "status", "status_reason", "remediation",
}


class FindingSeverity(StrEnum):
    """Describe normalized impact without deriving severity from a provider name."""

    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Separate detection from an explicitly attributed operator disposition."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class Remediation:
    """Preserve advisory text and ordered steps without executing remediation."""

    summary: str | None = None
    steps: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Freeze bounded, nonempty text sequences and canonicalize reference ordering."""

        if self.summary is not None:
            RequireWorkspaceText(self.summary, "remediation summary")

        for field_name in ("steps", "references"):
            values = tuple(RequireWorkspaceText(value, field_name) for value in ModelSequence(
                getattr(self, field_name), field_name,
            ))

            if field_name == "references":
                values = tuple(sorted(set(values)))

            object.__setattr__(self, field_name, values)

        ModelAttributes(cast(dict[str, object], JsonValue(self)))

    @classmethod
    def FromDict(cls, value: object) -> Remediation:
        """Decode exact remediation fields without silently dropping unknown instructions.

        Args:
            value: Strict JSON object containing summary, steps, and references.

        Returns:
            Immutable validated advisory fields.

        Raises:
            ValueError: Fields, text, collection types, or size limits are invalid.
        """

        record = WorkspaceFields(value, {"summary", "steps", "references"}, "remediation")
        summary = record["summary"]

        references = ModelSequence(record["references"], "references")
        remediation = cls(
            None if summary is None else RequireWorkspaceText(summary, "remediation summary"),
            cast(tuple[str, ...], ModelSequence(record["steps"], "steps")),
            cast(tuple[str, ...], references),
        )

        if len(remediation.references) != len(references):
            raise ValueError("remediation references must be unique")

        return remediation


@dataclass(frozen=True, slots=True)
class Finding:
    """Normalize one finding interpretation while leaving authority and bytes with their owners.

    A value may represent an attributed update. The enclosing model requires
    evidence linkage, and detector ingestion requires incoming evidence. Triage
    updates may reuse the evidence retained by the existing model object.
    """

    subject_reference: str
    check_id: str
    location_key: str
    summary: str
    provenance: tuple[ModelProvenance, ...]
    severity: FindingSeverity = FindingSeverity.UNKNOWN
    confidence: float = 0.0
    status: FindingStatus = FindingStatus.OPEN
    status_reason: str | None = None
    remediation: Remediation = field(default_factory=Remediation)

    def __post_init__(self) -> None:
        """Validate typed fields and freeze attributed metadata without I/O or authorization."""

        if not RequireModelReference(self.subject_reference).startswith("object:"):
            raise ValueError("finding subject must be an object reference")

        RequireIdentifier(self.check_id, "check_id")
        RequireWorkspaceText(self.location_key, "location_key")
        RequireWorkspaceText(self.summary, "summary")

        if (
            not isinstance(self.severity, FindingSeverity)
            or not isinstance(self.status, FindingStatus)
        ):
            raise ValueError("severity and status must use typed finding enums")

        if (
            isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float))
            or not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be a finite number between zero and one")

        if self.status_reason is not None:
            RequireWorkspaceText(self.status_reason, "status_reason")

        elif self.status is not FindingStatus.OPEN:
            raise ValueError("triaged finding status requires an explicit reason")

        if not isinstance(self.remediation, Remediation):
            raise ValueError("remediation must be a Remediation")

        object.__setattr__(self, "confidence", float(self.confidence))
        object.__setattr__(self, "provenance", ProvenanceCollection(self.provenance))
        ModelAttributes(self.ToAttributes())

    def Fingerprint(self) -> str:
        """Identify a check at one subject/location independently of mutable metadata.

        Returns:
            Lowercase SHA-256 of domain-separated canonical first-party identity fields.
        """

        return hashlib.sha256(CanonicalModelJson({
            "namespace": "finding", "subject_reference": self.subject_reference,
            "check_id": self.check_id, "location_key": self.location_key,
        })).hexdigest()

    def ToAttributes(self) -> dict[str, object]:
        """Render the strict finding attribute document owned by the existing model object.

        Returns:
            Detached JSON-compatible versioned fields, excluding separately retained provenance.
        """

        return {
            "schema_version": FINDING_SCHEMA_VERSION, "fingerprint": self.Fingerprint(),
            "subject_reference": self.subject_reference, "check_id": self.check_id,
            "location_key": self.location_key, "summary": self.summary,
            "severity": self.severity.value, "confidence": self.confidence,
            "status": self.status.value, "status_reason": self.status_reason,
            "remediation": JsonValue(self.remediation),
        }

    def ToObject(self, workspace_id: str) -> SecurityObject:
        """Project this interpretation into the one canonical Security Object Model.

        Args:
            workspace_id: Owning workspace; subject existence is checked by ModelState.

        Returns:
            Finding object with a provider-independent identity and typed provenance.

        Raises:
            ValueError: The workspace identity is malformed.
        """

        return SecurityObject(
            ObjectIdentity(workspace_id, ObjectKind.FINDING, self.Fingerprint()),
            self.ToAttributes(), self.provenance,
        )

    @classmethod
    def FromAttributes(cls, attributes: object, provenance: object) -> Finding:
        """Decode strict normalized fields and prove their declared fingerprint.

        Args:
            attributes: JSON fields or a frozen model mapping.
            provenance: Nonempty sequence of typed ModelProvenance records.

        Returns:
            Validated finding interpretation.

        Raises:
            ValueError: Schema, field types, attribution, or fingerprint are invalid.
        """

        record = WorkspaceFields(JsonValue(attributes), _FINDING_FIELDS, "finding")

        version = RequireWorkspaceInteger(record["schema_version"], "schema_version")

        if version != FINDING_SCHEMA_VERSION:
            raise ValueError("unsupported finding schema version")

        reason = record["status_reason"]
        finding = cls(
            subject_reference=RequireWorkspaceText(
                record["subject_reference"], "subject_reference",
            ),
            check_id=RequireWorkspaceText(record["check_id"], "check_id"),
            location_key=RequireWorkspaceText(record["location_key"], "location_key"),
            summary=RequireWorkspaceText(record["summary"], "summary"),
            provenance=ProvenanceCollection(provenance),
            severity=FindingSeverity(RequireWorkspaceText(record["severity"], "severity")),
            confidence=record["confidence"],  # type: ignore[arg-type]
            status=FindingStatus(RequireWorkspaceText(record["status"], "status")),
            status_reason=None if reason is None else RequireWorkspaceText(reason, "status_reason"),
            remediation=Remediation.FromDict(record["remediation"]),
        )

        if record["fingerprint"] != finding.Fingerprint():
            raise ValueError("finding fingerprint disagrees with canonical identity")

        return finding

    @classmethod
    def FromObject(cls, entity: SecurityObject) -> Finding:
        """Read a finding projection without copying it into another authoritative store.

        Args:
            entity: Existing typed finding object.

        Returns:
            Validated immutable interpretation sharing the canonical provenance contract.

        Raises:
            ValueError: The input is not a finding or its identity disagrees with its fields.
        """

        if not isinstance(entity, SecurityObject) or entity.identity.kind is not ObjectKind.FINDING:
            raise ValueError("entity must be a finding SecurityObject")

        finding = cls.FromAttributes(entity.attributes, entity.provenance)

        if entity.identity.key != finding.Fingerprint():
            raise ValueError("finding object key disagrees with its fingerprint")

        return finding


def ValidateFindingObject(entity: SecurityObject) -> None:
    """Validate a generic SOM creation/read through the canonical finding field boundary.

    Args:
        entity: Generic SecurityObject whose kind is finding.

    Raises:
        ValueError: Attributes or immutable identity are not a canonical finding.
    """

    Finding.FromObject(entity)


def ValidateFindingTransition(previous: object, following: object) -> None:
    """Enforce disposition transitions equally for helpers and generic model updates.

    Args:
        previous: Previous typed status value, or None for creation.
        following: Incoming typed status value.

    Raises:
        ValueError: Creation is triaged or a closed disposition is changed without reopening.
    """

    next_status = FindingStatus(cast(str, following))

    if previous is None:
        if next_status is not FindingStatus.OPEN:
            raise ValueError("new finding must have open status")

        return

    current_status = FindingStatus(cast(str, previous))

    if (
        current_status in (FindingStatus.DISMISSED, FindingStatus.RESOLVED)
        and next_status not in (current_status, FindingStatus.OPEN)
    ):
        raise ValueError("dismissed or resolved finding must reopen before changing disposition")


def Findings(state: ModelState, status: FindingStatus | None = None) -> tuple[Finding, ...]:
    """Query normalized findings from the same snapshot used by all workflow lenses.

    Args:
        state: Canonical immutable workspace model.
        status: Optional typed disposition filter; None selects every finding.

    Returns:
        Immutable projections ordered by canonical object reference.

    Raises:
        ValueError: The snapshot or status filter is untyped.
    """

    if not isinstance(state, ModelState) or (
        status is not None and not isinstance(status, FindingStatus)
    ):
        raise ValueError("state and status must use typed contracts")

    findings = tuple(Finding.FromObject(entity) for entity in state.Objects(ObjectKind.FINDING))

    return tuple(finding for finding in findings if status is None or finding.status is status)


def ApplyFindings(
    state: ModelState, findings: tuple[Finding, ...],
) -> tuple[ModelState, ModelDelta]:
    """Deduplicate evidence-linked detector output while preserving existing operator triage.

    Args:
        state: Canonical workspace snapshot with finding subjects already present.
        findings: Ordered untriaged detections; current metadata follows explicit batch order.

    Returns:
        New canonical snapshot and delta; replay preserves revision and existing observations.

    Raises:
        ValueError: Inputs, incoming evidence, subject bindings, or detector status are invalid.
    """

    if not isinstance(state, ModelState):
        raise ValueError("state must be a ModelState")

    current = {entity.identity.key: Finding.FromObject(entity) for entity in state.Objects(
        ObjectKind.FINDING,
    )}
    objects = []
    observations = []
    known_observations = {item.Reference() for item in state.observations}

    for finding in ModelSequence(findings, "findings"):
        if not isinstance(finding, Finding):
            raise ValueError("findings must contain Finding values")

        if finding.status is not FindingStatus.OPEN or finding.status_reason is not None:
            raise ValueError("detector ingestion requires untriaged open findings")

        if not any(record.evidence_references for record in finding.provenance):
            raise ValueError("detected finding requires incoming evidence references")

        reference = finding.ToObject(state.workspace_id).Reference()
        novel = False

        for provenance in finding.provenance:
            observation = Observation(
                "finding-detection", reference, finding.ToAttributes(), provenance,
            )
            observations.append(observation)
            novel = novel or observation.Reference() not in known_observations
            known_observations.add(observation.Reference())

        if not novel:
            continue

        previous = current.get(finding.Fingerprint())

        if previous is not None:
            finding = replace(finding, status=previous.status, status_reason=previous.status_reason)

        objects.append(finding.ToObject(state.workspace_id))

    return state.Apply(objects=tuple(objects), observations=tuple(observations))


def ApplyVerifiedFindings(
    state: ModelState, findings: tuple[Finding, ...], workspace_root: Path,
) -> tuple[ModelState, ModelDelta]:
    """Verify owned raw evidence before applying one otherwise pure detector batch.

    Args:
        state: Canonical snapshot belonging to workspace_root.
        findings: Ordered untriaged detections; all evidence bytes are checked first.
        workspace_root: Existing operator-owned local workspace directory.

    Returns:
        In-memory transition ready for LocalModelStore.Save; this function writes nothing.

    Raises:
        ValueError: Workspace ownership, inputs, evidence links, or model fields are invalid.
        EvidenceError: Incoming raw evidence is missing, corrupt, or unsafe.
        OSError: Workspace metadata cannot be read.
    """

    if not isinstance(state, ModelState):
        raise ValueError("state must be a ModelState")

    workspace = LocalWorkspaceStore(workspace_root)

    if workspace.Open().workspace_id != state.workspace_id:
        raise ValueError("finding evidence must belong to the model workspace")

    evidence_store = LocalEvidenceStore(workspace.root / "evidence")
    batch = ModelSequence(findings, "findings")
    verified = set()

    for finding in batch:
        if not isinstance(finding, Finding):
            raise ValueError("findings must contain Finding values")

        for provenance in finding.provenance:
            for reference in provenance.evidence_references:
                if reference not in verified:
                    evidence_store.Read(reference)
                    verified.add(reference)

    return ApplyFindings(state, cast(tuple[Finding, ...], batch))


def TransitionFinding(
    state: ModelState, reference: str, status: FindingStatus,
    provenance: ModelProvenance, reason: str,
) -> tuple[ModelState, ModelDelta]:
    """Apply one explicit attributed disposition without running a check or remediation.

    Args:
        state: Canonical workspace model containing the finding.
        reference: Existing canonical finding object reference.
        status: Requested typed disposition; closed dispositions must reopen first.
        provenance: Attribution for this operator decision, not an authorization grant.
        reason: Nonempty explanation retained with the current status and observation history.

    Returns:
        Canonical model transition preserving prior evidence/acquisition history.

    Raises:
        ValueError: Subject, status, reason, attribution, or lifecycle is invalid.
    """

    if not isinstance(state, ModelState) or not isinstance(status, FindingStatus):
        raise ValueError("state and status must use typed contracts")

    RequireModelReference(reference)
    RequireWorkspaceText(reason, "reason")
    entities = [
        entity for entity in state.Objects(ObjectKind.FINDING) if entity.Reference() == reference
    ]

    if not entities:
        raise ValueError("finding must exist in the current model")

    current = Finding.FromObject(entities[0])
    updated = replace(current, status=status, status_reason=reason, provenance=(provenance,))

    return state.Apply(objects=(updated.ToObject(state.workspace_id),))
