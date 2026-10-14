# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit finding predicates over verified current synthetic configuration acquisitions."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    EvidenceReference,
    ExecutionState,
)
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactOperation,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactSnapshot,
)
from fuzzy1337.artifact_policy import (
    ArtifactAcceptance,
    ArtifactGrant,
    ArtifactPlan,
    ArtifactPolicyContext,
    GovernedArtifactExecutor,
)
from fuzzy1337.configuration_evidence import (
    Candidates,
    ConfigurationOperationCapture,
    VerifiedCapture,
)
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionResources,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    Observation,
    Relation,
    RequireModelReference,
    SecurityObject,
)
from fuzzy1337.policy import RequireDigest
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.workspace import RequireWorkspaceText

__all__ = ["CiFindingCriterion", "CiPredicateResult", "EvaluateConfigurationCriterion"]


@dataclass(frozen=True, slots=True)
class CiFindingCriterion:
    """Caller-selected conjunction and count limit, with explicit completeness acknowledgement."""

    severities: tuple[FindingSeverity, ...]
    statuses: tuple[FindingStatus, ...]
    max_matches: int
    acknowledge_unassessed_completeness: bool

    def __post_init__(self) -> None:
        """Reject coercion, implicit selections, duplicate labels and unacknowledged completeness.

        Raises:
            ValueError: Selections or limits are not exact supported values, or acknowledgement
                was not explicitly true. No severity order or risk score is inferred.
        """

        for values, expected in ((self.severities, FindingSeverity),
                                 (self.statuses, FindingStatus)):
            if type(values) is not tuple or not values or any(
                type(item) is not expected for item in values
            ) or len(set(values)) != len(values):
                raise ValueError("CI criterion requires explicit unique typed selections")

        if type(self.max_matches) is not int or not 0 <= self.max_matches <= 1024 or (
            type(self.acknowledge_unassessed_completeness) is not bool
            or not self.acknowledge_unassessed_completeness
        ):
            raise ValueError("CI criterion requires a bound and completeness acknowledgement")

    def ToDict(self) -> dict[str, object]:
        """Describe the exact selected predicate without ranking labels or asserting clean scans.

        Returns:
            Deterministic detached criterion fields with explicitly acknowledged limitations.
        """

        self.__post_init__()

        return {"severities": sorted(item.value for item in self.severities),
            "statuses": sorted(item.value for item in self.statuses),
            "max_matches": self.max_matches,
            "acknowledge_unassessed_completeness": self.acknowledge_unassessed_completeness}


@dataclass(frozen=True, slots=True)
class CiPredicateResult:
    """Criterion-only outcome with exact current-execution selection and full snapshot pin."""

    satisfied: bool
    snapshot_sha256: str
    run_reference: str
    selected_finding_references: tuple[str, ...]
    matched_finding_references: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate exact immutable output fields without treating construction as source proof.

        Raises:
            ValueError: A field has a foreign type, malformed identity or inconsistent selection.
        """

        if type(self.satisfied) is not bool or type(self.snapshot_sha256) is not str or (
            type(self.run_reference) is not str
        ):
            raise ValueError("CI result requires exact immutable scalar fields")

        RequireDigest(self.snapshot_sha256)
        RequireWorkspaceText(self.run_reference, "CI run reference")

        if not re.fullmatch(r"artifact-run:[0-9a-f]{32}", self.run_reference):
            raise ValueError("CI result requires an original run identity")

        for values in (self.selected_finding_references, self.matched_finding_references):
            if type(values) is not tuple or len(values) > 1024 or any(
                type(item) is not str or not RequireModelReference(item).startswith("object:")
                for item in values
            ) or tuple(sorted(set(values))) != values:
                raise ValueError("CI result requires exact unique ordered finding references")

        if not set(self.matched_finding_references) <= set(self.selected_finding_references):
            raise ValueError("CI matched findings must belong to the proven selection")

    def ToDict(self) -> dict[str, object]:
        """Separate selected finding facts from discovery completeness and full report contents.

        Returns:
            Criterion status, selection, count and exact saved-model/source-run attribution.
        """

        self.__post_init__()

        return {"status": "satisfied" if self.satisfied else "violated",
            "scope": "selected-profile-finding-predicate", "scan_completeness": "not-assessed",
            "snapshot_sha256": self.snapshot_sha256, "run_reference": self.run_reference,
            "selected_findings": list(self.selected_finding_references),
            "matched_findings": list(self.matched_finding_references),
            "selected_count": len(self.selected_finding_references),
            "matched_count": len(self.matched_finding_references)}


def EvaluatePredicate(
    model: ModelState, selected: tuple[Finding, ...], criterion: CiFindingCriterion,
    snapshot_sha256: str, run_reference: str,
) -> CiPredicateResult:
    """Apply the explicit conjunction to already verified source-selected current interpretations.

    Args:
        model: Exact saved model used only for canonical finding references.
        selected: Current saved interpretations whose original source/run proof was verified.
        criterion: Exact caller-selected severity/status conjunction and count limit.
        snapshot_sha256: Full verified model pin, not a revision-only assertion.
        run_reference: Original executed configuration run whose detections form the selection.

    Returns:
        Criterion satisfaction only; zero matching facts makes no universal discovery claim.

    Raises:
        ValueError: An unknown severity lacks explicit selection or typed reconstruction fails.
    """

    if type(criterion) is not CiFindingCriterion:
        raise ValueError("CI predicate requires its exact typed criterion")

    criterion.__post_init__()

    if type(selected) is not tuple or any(type(item) is not Finding for item in selected):
        raise ValueError("CI selection requires exact typed findings")

    for finding in selected:
        if Finding.FromAttributes(finding.ToAttributes(), finding.provenance) != finding:
            raise ValueError("CI finding differs from its reconstructed contract")

        if finding.severity is FindingSeverity.UNKNOWN and (
            FindingSeverity.UNKNOWN not in criterion.severities
        ):
            raise ValueError("CI finding severity is unassessed by the explicit predicate")

    references = tuple(sorted(item.ToObject(model.workspace_id).Reference() for item in selected))
    matched = tuple(sorted(item.ToObject(model.workspace_id).Reference() for item in selected
        if item.severity in criterion.severities and item.status in criterion.statuses))

    return CiPredicateResult(len(matched) <= criterion.max_matches, snapshot_sha256,
                             run_reference, references, matched)


def RequireModelContracts(model: ModelState) -> None:
    """Reject foreign nested record implementations before invoking their serializers or equality.

    Args:
        model: Exact immutable model candidate at the CI consumer boundary.

    Raises:
        ValueError: Any collection, entity, identity or provenance uses a foreign runtime type.
    """

    for values, expected in ((model.objects, SecurityObject), (model.relations, Relation),
                             (model.observations, Observation)):
        if type(values) is not tuple or any(type(item) is not expected for item in values):
            raise ValueError("CI model collections require exact original record types")

    for entity in model.objects:
        if type(entity.identity) is not ObjectIdentity:
            raise ValueError("CI model requires exact original identities")

    entities: tuple[SecurityObject | Relation, ...] = (*model.objects, *model.relations)
    provenance = [record for entity in entities for record in entity.provenance]
    provenance.extend(item.provenance for item in model.observations)

    for record in provenance:
        if type(record) is not ModelProvenance or type(record.evidence_references) is not tuple or (
            any(type(item) is not EvidenceReference for item in record.evidence_references)
            or record.execution is not None and type(record.execution) is not AdapterExecution
        ):
            raise ValueError("CI model requires exact original provenance contracts")


def RequireCaptureContracts(capture: ConfigurationOperationCapture,
                            records: tuple[EvidenceRecord, ...]) -> None:
    """Reject foreign nested implementations before original-record reads or callable serializers.

    Args:
        capture: Original first-party configuration capture already checked for its exact type.
        records: Exact original source acquisitions from the owning job.

    Raises:
        ValueError: An SDK/evidence nested record has a foreign runtime type or changed receipt.
    """

    outcome = capture.outcome
    prepared = capture.prepared

    for value, expected in ((outcome.raw_result, LocalExecutionResult),
        (outcome.grant, ArtifactGrant), (outcome.acceptance, ArtifactAcceptance),
        (prepared.invocation, AdapterInvocation),
        (prepared.capability, CapabilityDescriptor), (prepared.resources, ExecutionResources)):
        if type(value) is not expected:
            raise ValueError("CI capture requires exact original SDK record types")

    for nested_value, nested_type in ((outcome.grant.plan, ArtifactPlan),
        (outcome.grant.authorization, ExecutionAuthorization),
        (outcome.raw_result.execution, AdapterExecution),
        (outcome.raw_result.termination, ExecutionTermination),
        (prepared.operation, ArtifactOperation)):
        if type(nested_value) is not nested_type:
            raise ValueError("CI capture requires exact original SDK child contracts")

    if type(outcome.raw_result.execution.state) is not ExecutionState:
        raise ValueError("CI capture requires an exact original execution state")

    if type(outcome.raw_result.events) is not tuple or any(
        type(item) is not ExecutionEvent for item in outcome.raw_result.events
    ) or type(outcome.manifests) is not tuple:
        raise ValueError("CI capture requires exact immutable SDK collections")

    manifests = list(outcome.manifests)

    for snapshot in (capture.stage.input, capture.stage.scanner, capture.stage.material):
        if type(snapshot) is not ArtifactSnapshot or (
            type(snapshot.consent) is not ArtifactReadConsent
        ):
            raise ValueError("CI capture requires exact original stage partitions")

        manifests.append(snapshot.manifest)

    for manifest in manifests:
        if type(manifest) is not ArtifactManifest or type(manifest.files) is not tuple or any(
            type(item) is not ArtifactFile for item in manifest.files
        ):
            raise ValueError("CI capture requires exact original selected manifests")

        if type(manifest.profile) is not ArtifactProfile or type(manifest.role) is not ArtifactRole:
            raise ValueError("CI capture requires exact original manifest labels")

    if type(records) is not tuple or len(records) != 4 or any(
        type(record) is not EvidenceRecord or type(record.reference) is not EvidenceReference
        or type(record.provenance) is not EvidenceProvenance for record in records
    ):
        raise ValueError("CI capture requires exact original acquisition contracts")

    outcome.__post_init__()


def EvaluateConfigurationCriterion(
    model: ModelState, capture: ConfigurationOperationCapture, records: tuple[EvidenceRecord, ...],
    workspace_root: Path, *, expected_snapshot_sha256: str, criterion: CiFindingCriterion,
    context_provider: Callable[[], ArtifactPolicyContext],
) -> CiPredicateResult:
    """Verify original source/run proof before selecting only current execution's saved findings.

    Args:
        model: Exact owner-read saved snapshot; its complete contents must match the selected pin.
        capture: Exact original typed SDK execution, request, stage and acquisition readings.
        records: Four original immutable acquisitions from the actual owning job.
        workspace_root: Existing workspace whose owners verify original manifests and bytes.
        expected_snapshot_sha256: Saved JSON export's lowercase complete model digest.
        criterion: Explicit typed predicate, count limit and completeness acknowledgement.
        context_provider: Fresh scope/owner/policy lookup; possession of historical bytes grants
            no current acceptance or execution authority.

    Returns:
        Predicate result for exactly source-proven current detections, retaining saved triage.
        Unrelated and absent historical detections do not enter this selection.

    Raises:
        ValueError: Typed reconstruction, snapshot pin, original capture or saved source proof
            differs, or selected uncertainty was not explicitly handled.
        ArtifactDeniedError: Original grant is no longer currently acceptable.
        EvidenceError: Original owning manifests or bytes cannot be verified.
        OSError: Existing owning storage cannot be read.
    """

    if type(model) is not ModelState or type(capture) is not ConfigurationOperationCapture or (
        type(criterion) is not CiFindingCriterion or type(expected_snapshot_sha256) is not str
    ):
        raise ValueError("CI gate requires exact first-party contracts")

    criterion.__post_init__()
    RequireDigest(expected_snapshot_sha256)
    ConfigurationOperationCapture(capture.outcome, capture.prepared, capture.stage,
                                  capture.started_at, capture.finished_at)
    RequireCaptureContracts(capture, records)
    RequireModelContracts(model)
    rebuilt_model = ModelState.FromDict(model.ToDict())

    if rebuilt_model != model or ReportSnapshot(rebuilt_model).SnapshotDigest() != (
        expected_snapshot_sha256
    ):
        raise ValueError("CI gate requires the complete exact saved snapshot")

    if LocalModelStore(workspace_root).Open() != rebuilt_model:
        raise ValueError("CI gate basis differs from its current owning saved model")

    facts, envelope, raw = VerifiedCapture(records, workspace_root)

    if facts.acceptance.refusal is not None or envelope != capture.Envelope() or (
        raw["configuration-stdout"] != capture.outcome.raw_result.stdout
        or raw["configuration-stderr"] != capture.outcome.raw_result.stderr
    ):
        raise ValueError("CI gate requires this exact successful original capture")

    GovernedArtifactExecutor(workspace_root).ValidateAcceptanceFresh(capture.outcome,
        capture.prepared, capture.stage, context_provider)
    asset, inventory, candidates = Candidates(facts, raw)
    objects = {item.Reference(): item for item in rebuilt_model.objects}
    saved_asset = objects.get(asset.Reference())

    if saved_asset is None or saved_asset.attributes != asset.attributes or (
        facts.provenance not in saved_asset.provenance
        or inventory not in rebuilt_model.observations
    ):
        raise ValueError("CI gate has no exact saved processed-source proof")

    selected = []

    for candidate in candidates:
        reference = candidate.ToObject(model.workspace_id).Reference()
        entity = objects.get(reference)
        detection = Observation("finding-detection", reference, candidate.ToAttributes(),
                                facts.provenance)

        if entity is None or facts.provenance not in entity.provenance or (
            detection not in rebuilt_model.observations
        ):
            raise ValueError("CI gate has no exact saved current-detection proof")

        current = Finding.FromObject(entity)
        attributes = current.ToAttributes()
        expected = candidate.ToAttributes()

        for field_name in ("status", "status_reason"):
            attributes.pop(field_name)
            expected.pop(field_name)

        if attributes != expected:
            raise ValueError("CI saved interpretation differs from its original source facts")

        selected.append(current)

    return EvaluatePredicate(rebuilt_model, tuple(selected), criterion, expected_snapshot_sha256,
                             capture.outcome.run_id)
