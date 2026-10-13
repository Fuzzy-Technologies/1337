# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Immutable evidence-linked report projections over canonical workspace snapshots."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from fuzzy1337.adapters.contracts import EvidenceReference, ExecutionState, JsonValue
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import (
    MAX_MODEL_BYTES,
    CanonicalModelJson,
    ModelProvenance,
    ModelSequence,
    ModelState,
    ObjectKind,
    Relation,
    RequireModelReference,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, RequireWorkspaceText

REPORT_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 32 * 1024 * 1024
_OWASP_2021 = (
    "Broken_Access_Control", "Cryptographic_Failures", "Injection", "Insecure_Design",
    "Security_Misconfiguration", "Vulnerable_and_Outdated_Components",
    "Identification_and_Authentication_Failures", "Software_and_Data_Integrity_Failures",
    "Security_Logging_and_Monitoring_Failures", "Server-Side_Request_Forgery_(SSRF)",
)
_IDENTIFIERS = {
    "cve": r"CVE-[0-9]{4}-[0-9]{4,}", "cwe": r"CWE-[1-9][0-9]*",
    "capec": r"CAPEC-[1-9][0-9]*", "attack": r"T[0-9]{4}(?:\.[0-9]{3})?",
    "atlas": r"AML\.T[0-9]{4}(?:\.[0-9]{3})?", "owasp-top10": r"A(?:0[1-9]|10):2021",
}


def ReportText(value: object, field_name: str, limit: int = 4096) -> str:
    """Require bounded printable non-secret report context without scalar coercion.

    Args:
        value: Caller-owned metadata, never raw acquired content.
        field_name: Field named in a validation failure.
        limit: Maximum UTF-8 bytes permitted for the scalar.

    Returns:
        Validated unmodified printable text.

    Raises:
        ValueError: Text, controls, UTF-8, or the byte bound is invalid.
    """

    text = RequireWorkspaceText(value, field_name)
    CanonicalModelJson(text)

    if not text.strip() or not text.isprintable() or len(text.encode("utf-8")) > limit:
        raise ValueError(f"{field_name} must be bounded printable text")

    return text


@dataclass(frozen=True, slots=True)
class ReportReference:
    """Display an explicit external identifier/version without creating a reference catalog."""

    family: str
    external_id: str
    catalog_version: str

    def __post_init__(self) -> None:
        """Validate fixed publisher link grammar without fetching or proving catalog membership."""

        for name in ("family", "external_id", "catalog_version"):
            ReportText(getattr(self, name), name, 128)

        pattern = _IDENTIFIERS.get(self.family)

        if pattern is None or re.fullmatch(pattern, self.external_id) is None:
            raise ValueError("reference family or external identifier is unsupported")

        if self.family == "owasp-top10" and self.catalog_version != "2021":
            raise ValueError("OWASP Top 10 links require exact supported catalog version 2021")

    def Url(self) -> str:
        """Generate one fixed publisher HTTPS URL from a validated identifier.

        Returns:
            Canonical publisher locator; current pages do not pin historical content.
        """

        if self.family == "cve":
            return f"https://www.cve.org/CVERecord?id={self.external_id}"

        if self.family == "cwe":
            return f"https://cwe.mitre.org/data/definitions/{self.external_id[4:]}.html"

        if self.family == "capec":
            return f"https://capec.mitre.org/data/definitions/{self.external_id[6:]}.html"

        if self.family == "attack":
            return "https://attack.mitre.org/techniques/" + self.external_id.replace(".", "/") + "/"

        if self.family == "atlas":
            return f"https://atlas.mitre.org/techniques/{self.external_id}"

        category = int(self.external_id[1:3])

        return f"https://top10.owasp.org/2021/A{category:02d}_2021-{_OWASP_2021[category - 1]}/"

    def ToDict(self) -> dict[str, object]:
        """Expose identifier/version/link metadata with explicit publisher-revision semantics.

        Returns:
            Detached fields without a membership or mapping-approval claim.
        """

        return {
            "family": self.family, "external_id": self.external_id,
            "catalog_version": self.catalog_version, "url": self.Url(),
            "link_revision": "2021" if self.family == "owasp-top10" else "publisher-current",
        }


@dataclass(frozen=True, slots=True)
class FindingReferences:
    """Attribute explicit reference context to evidence already linked to one canonical finding."""

    finding_reference: str
    references: tuple[ReportReference, ...]
    rationale: str
    provenance: ModelProvenance

    def __post_init__(self) -> None:
        """Freeze link context; existence and evidence ownership belong to the report."""

        if not RequireModelReference(self.finding_reference).startswith("object:"):
            raise ValueError("reference context requires a canonical finding object reference")

        ReportText(self.rationale, "rationale")

        if (
            not isinstance(self.provenance, ModelProvenance)
            or not self.provenance.evidence_references
        ):
            raise ValueError("reference context requires typed evidence-linked attribution")

        references = ModelSequence(self.references, "references")

        if not 1 <= len(references) <= 32 or any(
            not isinstance(item, ReportReference) for item in references
        ):
            raise ValueError("reference context must contain 1..32 ReportReference values")

        typed = tuple(item for item in references if isinstance(item, ReportReference))

        if len(set(typed)) != len(typed):
            raise ValueError("reference context must not contain duplicate identities")

        object.__setattr__(self, "references", tuple(sorted(
            typed, key=lambda item: (item.family, item.external_id, item.catalog_version),
        )))

    def ToDict(self) -> dict[str, object]:
        """Expose accountable context without upgrading a link to a verified classification.

        Returns:
            Canonical finding reference, link metadata, rationale, and supplied attribution.
        """

        return {
            "finding_reference": self.finding_reference,
            "references": [item.ToDict() for item in self.references],
            "rationale": self.rationale, "provenance": JsonValue(self.provenance),
            "interpretation": "attributed-context",
        }


@dataclass(frozen=True, slots=True)
class ReportSnapshot:
    """Project one immutable model revision without inferring completeness or security success."""

    state: ModelState
    reference_bindings: tuple[FindingReferences, ...] = ()
    _checked_evidence: tuple[EvidenceReference, ...] = field(default=(), init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate bounded model/context ownership without reading files or raw evidence."""

        if not isinstance(self.state, ModelState):
            raise ValueError("report state must be a ModelState")

        if len(CanonicalModelJson(self.state.ToDict())) > MAX_MODEL_BYTES:
            raise ValueError("report model exceeds the canonical snapshot byte limit")

        bindings = ModelSequence(self.reference_bindings, "reference_bindings")

        if len(bindings) > 1024 or any(
            not isinstance(item, FindingReferences) for item in bindings
        ):
            raise ValueError("reference_bindings requires at most 1024 FindingReferences values")

        typed = tuple(item for item in bindings if isinstance(item, FindingReferences))

        if len({item.finding_reference for item in typed}) != len(typed):
            raise ValueError("reference bindings must be unique by canonical finding")

        entities = {item.Reference(): item for item in self.state.Objects(ObjectKind.FINDING)}

        for binding in typed:
            entity = entities.get(binding.finding_reference)

            if entity is None:
                raise ValueError("reference binding requires a finding present in this snapshot")

            evidence = {reference for record in entity.provenance
                        for reference in record.evidence_references}

            if not set(binding.provenance.evidence_references) <= evidence:
                raise ValueError("reference context evidence must be linked to its finding")

        object.__setattr__(self, "reference_bindings", tuple(sorted(
            typed, key=lambda item: item.finding_reference,
        )))

        if len(CanonicalModelJson([item.ToDict() for item in typed])) > 1024 * 1024:
            raise ValueError("report reference context exceeds the byte limit")

    def SnapshotDigest(self) -> str:
        """Pin the exact canonical source snapshot independently of report formatting.

        Returns:
            Lowercase SHA-256 of the full model document, including attribution and revision.
        """

        return hashlib.sha256(CanonicalModelJson(self.state.ToDict())).hexdigest()

    def EvidenceReferences(self) -> tuple[EvidenceReference, ...]:
        """Collect unique acquisition references across canonical entities and observation history.

        Returns:
            Typed references ordered by their complete canonical metadata.
        """

        entities: tuple[SecurityObject | Relation, ...] = (
            *self.state.objects, *self.state.relations,
        )
        records = [record for entity in entities
                   for record in entity.provenance]
        records.extend(item.provenance for item in self.state.observations)
        references = {reference for record in records for reference in record.evidence_references}

        return tuple(sorted(references, key=CanonicalModelJson))

    def ToDict(self) -> dict[str, object]:
        """Render schema-v1 model/finding/context layers with honest byte-integrity metadata.

        Returns:
            Detached deterministic JSON fields; raw artifacts and inferred facts are absent.
        """

        findings = []
        statuses = {status.value: 0 for status in FindingStatus}
        severities = {severity.value: 0 for severity in FindingSeverity}

        for entity in self.state.Objects(ObjectKind.FINDING):
            finding = Finding.FromObject(entity)
            findings.append({"reference": entity.Reference(), "normalized": finding.ToAttributes()})
            statuses[finding.status.value] += 1
            severities[finding.severity.value] += 1

        references = self.EvidenceReferences()
        entities: tuple[SecurityObject | Relation, ...] = (
            *self.state.objects, *self.state.relations,
        )
        executions = {
            CanonicalModelJson(record): record for entity in entities
            for record in entity.provenance if record.execution is not None
        }
        executions.update({
            CanonicalModelJson(item.provenance): item.provenance for item in self.state.observations
            if item.provenance.execution is not None
        })
        outcomes = [JsonValue(executions[key]) for key in sorted(executions)]
        failed = sum(record.execution is not None and record.execution.state is not
                     ExecutionState.SUCCEEDED for record in executions.values())

        return {
            "schema_version": REPORT_SCHEMA_VERSION, "workspace_id": self.state.workspace_id,
            "model_revision": self.state.revision, "snapshot_sha256": self.SnapshotDigest(),
            "scan_completeness": "not-assessed", "model": self.state.ToDict(),
            "summary": {
                "objects": len(self.state.objects), "relations": len(self.state.relations),
                "observations": len(self.state.observations), "findings": len(findings),
                "active_findings": statuses["open"] + statuses["confirmed"],
                "finding_statuses": statuses, "finding_severities": severities,
                "failed_execution_records": failed,
            },
            "findings": findings, "execution_outcomes": outcomes,
            "reference_bindings": [item.ToDict() for item in self.reference_bindings],
            "evidence_integrity": {
                "linked_references": [JsonValue(item) for item in references],
                "checked_references": [JsonValue(item) for item in self._checked_evidence],
                "unverified_count": len(references) - len(self._checked_evidence),
            },
        }


def VerifyReportEvidence(report: ReportSnapshot, workspace_root: Path) -> ReportSnapshot:
    """Verify every owned raw artifact atomically before creating a checked report projection.

    Args:
        report: Pure snapshot/context projection; no source model is changed.
        workspace_root: Explicit existing owning workspace; no local path enters the output.

    Returns:
        New immutable report carrying the exact checked reference metadata.

    Raises:
        ValueError: Report typing or workspace ownership is invalid.
        EvidenceError: Any artifact is missing, unsafe, incorrectly sized, or corrupt.
        OSError: Workspace metadata cannot be read.
    """

    if not isinstance(report, ReportSnapshot):
        raise ValueError("report must be a ReportSnapshot")

    workspace = LocalWorkspaceStore(workspace_root)

    if workspace.Open().workspace_id != report.state.workspace_id:
        raise ValueError("report evidence must belong to the canonical model workspace")

    references = report.EvidenceReferences()
    store = LocalEvidenceStore(workspace.root / "evidence")

    for reference in references:
        store.Read(reference)

    checked = replace(report)
    object.__setattr__(checked, "_checked_evidence", references)

    return checked
