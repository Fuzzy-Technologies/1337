# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Separate original-record verification and fresh in-memory synthetic image interpretation."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

from fuzzy1337.adapters import (
    AdapterExecution,
    EvidenceReference,
    ExecutionState,
    SerializeContract,
)
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactStage, FreezePhysicalIdentity
from fuzzy1337.artifact_policy import (
    ArtifactAcceptance,
    ArtifactDeniedError,
    ArtifactExecutionOutcome,
    ArtifactPolicyContext,
    ArtifactStagePayload,
    ArtifactVersionProof,
    GovernedArtifactExecutor,
    ParseObservedImageVersion,
    PreparedArtifact,
    VerifyArtifactReplay,
    VerifySyntheticImagePayloadReplay,
)
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.findings import ApplyFindings
from fuzzy1337.images import SyntheticTrivyCandidates
from fuzzy1337.model import ModelDelta, ModelProvenance, ModelState
from fuzzy1337.policy import Digest
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields

SYNTHETIC_IMAGE_CONTRACT_VERSION = 1
_FAMILY = "owned-synthetic-image-wire-v1"
_VERSION = "0.75.0-synthetic"
_ROLE_LIMITS = {
    "provider-version": (16 * 1024, "application/json"),
    "provider-version-stderr": (16 * 1024, "text/plain"),
    "stdout": (4 * 1024 * 1024, "application/json"),
    "stderr": (1024 * 1024, "text/plain"),
    "artifact-version-receipt": (1024 * 1024, "application/json"),
    "artifact-scan-receipt": (1024 * 1024, "application/json"),
}

__all__ = [
    "SYNTHETIC_IMAGE_CONTRACT_VERSION", "SyntheticImageReplay",
    "ApplyVerifiedSyntheticTrivyImages", "VerifySyntheticTrivyImageReplay",
]


@dataclass(frozen=True, slots=True)
class SyntheticImageReplay:
    """Immutable original attribution and refusal facts; never live execution or model authority."""

    workspace_id: str
    owner_ref: str
    version_acceptance: ArtifactAcceptance
    scan_acceptance: ArtifactAcceptance
    provenance: ModelProvenance
    version_started_at: str
    version_finished_at: str
    scan_started_at: str
    scan_finished_at: str
    version_prerequisite_sha256: str
    records: tuple[EvidenceRecord, ...]


@dataclass(frozen=True, slots=True)
class Capture:
    """Internal detached original facts and bounded stream bytes after record verification."""

    envelope: dict[str, Any]
    plan: dict[str, Any]
    acceptance: ArtifactAcceptance
    stdout: bytes
    stderr: bytes
    execution: AdapterExecution


class ImageEvidenceStore(LocalEvidenceStore):
    """Bound actual owning-manifest references before Get's eager raw verification."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Enforce the six-role consumer budget before any owning-store raw allocation.

        Args:
            reference: Actual parsed owning record or caller-supplied source reference.

        Returns:
            Bounded original bytes after the existing evidence owner's integrity checks.

        Raises:
            ValueError: Actual role, media type or byte size exceeds the image capture contract.
            EvidenceError: Canonical owning-store bytes or filesystem boundaries fail verification.
        """

        if type(reference) is not EvidenceReference or reference.role not in _ROLE_LIMITS:
            raise ValueError("synthetic image read requires its bounded original source role")

        limit, media_type = _ROLE_LIMITS[reference.role]

        if type(reference.size_bytes) is not int or not 0 <= reference.size_bytes <= limit or (
            reference.media_type != media_type
        ):
            raise ValueError("synthetic image actual record exceeds its role budget")

        return super().Read(reference)


def Fields(value: object, expected: set[str]) -> dict[str, Any]:
    """Require exact consumer-owned fields using the existing workspace schema validator.

    Args:
        value: Previously bounded decoded original capture object.
        expected: Complete field-name set; no defaults or ignored extensions.

    Returns:
        Original detached dictionary; invalid shapes fail without reflecting source text.
    """

    return cast(dict[str, Any], WorkspaceFields(value, expected, "synthetic image capture"))


def Detached(value: object) -> dict[str, Any]:
    """Render an original typed SDK payload with its owning canonical serializer.

    Args:
        value: Exact immutable producer payload; never a caller-selected serialization hook.

    Returns:
        Detached original JSON object for comparison with recorded capture evidence.
    """

    return cast(dict[str, Any], json.loads(SerializeContract(value)))


def VerifyOperation(
    records: dict[str, EvidenceRecord], raw: dict[str, bytes], operation: str,
) -> Capture:
    """Verify one original operation envelope, terminal facts and three exact acquisitions.

    Args:
        records: Six original immutable owning-workspace manifests indexed by role.
        raw: Independently verified bytes for those exact records.
        operation: Consumer-internal version or scan role selection.

    Returns:
        Detached original capture, including a truthful original SCAN refusal.

    Raises:
        ValueError: Bounded JSON, original SDK facts, provenance or chronology is inconsistent.
    """

    roles = ("provider-version", "provider-version-stderr", "artifact-version-receipt") if (
        operation == "version"
    ) else ("stdout", "stderr", "artifact-scan-receipt")

    if raw[roles[2]].startswith(b"\xef\xbb\xbf"):
        raise ValueError("synthetic image capture requires UTF-8 without a byte-order marker")

    envelope = Fields(ParseJson(raw[roles[2]], 1024 * 1024), {
        "schema_version", "artifact_metadata", "prepared_payload", "stage_payload",
        "collection_started_at", "collection_finished_at",
    })

    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise ValueError("synthetic image capture envelope requires schema one")

    metadata = envelope["artifact_metadata"]

    if not isinstance(metadata, dict) or type(metadata.get("schema_version")) is not int or (
        metadata.get("schema_version") != 2
    ):
        raise ValueError("synthetic image capture requires original SDK schema two")

    receipt = VerifyArtifactReplay(metadata, raw[roles[0]], raw[roles[1]])
    plan = metadata["grant"]["plan"]

    if (
        plan["profile"] != ArtifactProfile.SYNTHETIC_IMAGE.value
        or plan["producer_family"] != _FAMILY or plan["provider_version"] != _VERSION
        or plan["operation"] != operation
    ):
        raise ValueError("synthetic image capture requires its exact reviewed operation family")

    VerifySyntheticImagePayloadReplay(
        metadata, envelope["prepared_payload"], envelope["stage_payload"],
    )
    started = NormalizeEvidenceTime(envelope["collection_started_at"])
    finished = NormalizeEvidenceTime(envelope["collection_finished_at"])
    checked = NormalizeEvidenceTime(receipt.checked_at)

    if (
        started != envelope["collection_started_at"]
        or finished != envelope["collection_finished_at"]
        or started >= finished
        or not (
            NormalizeEvidenceTime(metadata["grant"]["issued_at"]) <= started <= checked <= finished
        )
    ):
        raise ValueError("synthetic image capture window contradicts its original grant or receipt")

    actual = metadata["raw_facts"]["execution"]
    execution = AdapterExecution(ExecutionState(actual["state"]), actual["exit_code"],
                                 actual["duration_seconds"])

    for role in roles:
        source = records[role].provenance

        if (
            source.workspace_id != plan["workspace_id"]
            or source.scope_reference != plan["scope_reference"]
            or source.source_id != "synthetic.trivy" or source.source_version != "1"
            or source.tool_version != _VERSION or source.started_at != started
            or source.finished_at != finished
            or source.invocation_sha256 != plan["invocation_sha256"]
            or source.execution != execution
        ):
            raise ValueError("synthetic image evidence differs from original operation attribution")

    return Capture(envelope, plan, receipt, raw[roles[0]], raw[roles[1]], execution)


def VerifyPair(version: Capture, scan: Capture) -> str:
    """Verify original two-operation relationships without performing current authorization.

    Args:
        version: Verified original VERSION acquisition facts.
        scan: Verified original SCAN acquisition facts, including possible refusal.

    Returns:
        Exact original VERSION prerequisite digest recorded in the SCAN plan.

    Raises:
        ValueError: The original pair reuses or contradicts acquisition, content or authority facts.
    """

    version_stage = version.envelope["stage_payload"]
    scan_stage = scan.envelope["stage_payload"]
    prerequisite = Digest({
        "artifact_metadata": version.envelope["artifact_metadata"],
        "prepared_payload": version.envelope["prepared_payload"],
        "stage_payload": version_stage,
    })
    same_fields = (
        "owner_ref", "profile", "provider_version", "input_manifest_sha256",
        "scanner_manifest_sha256", "material_manifest_sha256", "workspace_id",
        "scope_reference", "scope_revision", "scope_sha256", "policy_reference",
        "policy_revision", "policy_sha256", "target_reference", "producer_family",
    )

    if (
        version.acceptance.refusal is not None
        or any(version.plan[name] != scan.plan[name] for name in same_fields)
        or version.envelope["artifact_metadata"]["manifests"] != (
            scan.envelope["artifact_metadata"]["manifests"]
        )
        or version.envelope["prepared_payload"]["workspace_root"] != (
            scan.envelope["prepared_payload"]["workspace_root"]
        )
        or version_stage["executable"] != scan_stage["executable"]
        or version_stage["executable_identity"] != scan_stage["executable_identity"]
        or any(version_stage[name] == scan_stage[name]
               for name in ("root", "root_identity", "lease"))
        or version.acceptance.run_id == scan.acceptance.run_id
        or version.acceptance.grant_id == scan.acceptance.grant_id
        or version.plan["request_sha256"] == scan.plan["request_sha256"]
        or version.plan["invocation_sha256"] == scan.plan["invocation_sha256"]
        or (scan.acceptance.marker_identity is not None and
            version.acceptance.marker_identity == scan.acceptance.marker_identity)
        or scan.plan["version_run_id"] != version.acceptance.run_id
        or scan.plan["version_grant_id"] != version.acceptance.grant_id
        or scan.plan["version_prerequisite_sha256"] != prerequisite
        or version.envelope["collection_finished_at"] > scan.envelope["collection_started_at"]
        or NormalizeEvidenceTime(version.acceptance.checked_at) > NormalizeEvidenceTime(
            scan.envelope["artifact_metadata"]["grant"]["issued_at"]
        )
    ):
        raise ValueError("synthetic image captures do not form their exact original operation pair")

    ParseObservedImageVersion(version.stdout)

    if StageCopies(version_stage) & StageCopies(scan_stage):
        raise ValueError("synthetic image pair reuses original physical staging material")

    return prerequisite


def StageCopies(stage_payload: dict[str, Any]) -> set[tuple[int, ...]]:
    """Collect every original physical staged copy independently of its partition or file name.

    Args:
        stage_payload: Original detached stage facts checked by the owning SDK grammar.

    Returns:
        Root, partition and selected-copy device/inode identities; original executable is excluded.
    """

    identities = {FreezePhysicalIdentity(stage_payload["root_identity"], 2)}

    for snapshot in stage_payload["partitions"]:
        identities.add(FreezePhysicalIdentity(snapshot["directory_identity"], 2))

        for _, identity in snapshot["identities"]:
            identities.add(FreezePhysicalIdentity(identity, 5)[:2])

    return identities


def VerifyRecords(
    records: tuple[EvidenceRecord, ...], workspace_root: Path,
) -> tuple[SyntheticImageReplay, Capture, Capture]:
    """Verify six bounded original store-owned records before admitting any interpretation.

    Args:
        records: Exact six-role immutable manifests, never content-only references.
        workspace_root: Existing workspace owning their canonical evidence store.

    Returns:
        Immutable original attribution and both detached operation captures.

    Raises:
        ValueError: Record identity, profile, payload, time or attribution is inconsistent.
        EvidenceError: A source manifest or raw blob fails owning-store integrity checks.
        OSError: Owning workspace metadata cannot be inspected.
    """

    if not isinstance(records, tuple) or len(records) != 6 or any(
        type(record) is not EvidenceRecord or type(record.reference) is not EvidenceReference
        for record in records
    ):
        raise ValueError("synthetic image verification requires six original typed records")

    by_role = {record.reference.role: record for record in records}

    if set(by_role) != set(_ROLE_LIMITS):
        raise ValueError("synthetic image verification requires its six exact distinct roles")

    try:
        workspace = LocalWorkspaceStore(workspace_root)
        workspace_id = workspace.Open().workspace_id
        store = ImageEvidenceStore(workspace.root / "evidence")

    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValueError("synthetic image owning workspace cannot be verified") from None

    except OSError as error:
        raise type(error)("synthetic image owning workspace cannot be read") from None

    raw = {}

    for role, record in by_role.items():
        limit, media_type = _ROLE_LIMITS[role]

        if record.reference.size_bytes > limit or record.reference.media_type != media_type:
            raise ValueError("synthetic image record exceeds its role byte/media-type contract")

        try:
            if record.provenance.workspace_id != workspace_id or (
                store.Get(record.evidence_id) != record
            ):
                raise ValueError("synthetic image record differs from its immutable manifest")

            raw[role] = store.Read(record.reference)

        except EvidenceError as error:
            raise type(error)("synthetic image source evidence cannot be verified") from None

    try:
        version = VerifyOperation(by_role, raw, "version")
        scan = VerifyOperation(by_role, raw, "scan")
        prerequisite = VerifyPair(version, scan)
        provenance = ModelProvenance(
            "synthetic.trivy", scan.acceptance.run_id, scan.envelope["collection_finished_at"],
            scan.plan["scope_reference"], scan.plan["target_reference"], _VERSION,
            tuple(record.reference for record in records), scan.execution,
        )

    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, ArtifactDeniedError):
        raise ValueError("synthetic image original capture facts are inconsistent") from None

    facts = SyntheticImageReplay(
        workspace_id, scan.plan["owner_ref"], version.acceptance, scan.acceptance, provenance,
        version.envelope["collection_started_at"], version.envelope["collection_finished_at"],
        scan.envelope["collection_started_at"], scan.envelope["collection_finished_at"],
        prerequisite, tuple(sorted(records, key=lambda record: record.reference.role)),
    )

    return facts, version, scan


def VerifySyntheticTrivyImageReplay(
    records: tuple[EvidenceRecord, ...], workspace_root: Path,
) -> SyntheticImageReplay:
    """Verify saved original two-operation facts without live stage, authority or model access.

    Args:
        records: Six original immutable source records, including actual empty stderr streams.
        workspace_root: Existing or relocated owning workspace with verified retained evidence.

    Returns:
        Original immutable attribution and refusal receipts, including failed SCAN facts.
        This result grants no execution or model-application authority.

    Raises:
        ValueError: Original record/payload/pair bindings or bounded JSON are inconsistent.
        EvidenceError: Owning manifests or raw bytes cannot be independently verified.
        OSError: Owning workspace metadata cannot be read.
    """

    return VerifyRecords(records, workspace_root)[0]


def ApplyVerifiedSyntheticTrivyImages(
    state: ModelState, version_proof: ArtifactVersionProof, scan_outcome: ArtifactExecutionOutcome,
    scan_prepared: PreparedArtifact, scan_stage: ArtifactStage,
    records: tuple[EvidenceRecord, ...], workspace_root: Path,
    *, context_provider: Callable[[], ArtifactPolicyContext],
) -> tuple[ModelState, ModelDelta]:
    """Propose one isolated synthetic image transition after canonical fresh paired acceptance.

    Args:
        state: Original immutable model snapshot belonging to the evidence workspace.
        version_proof: Actual original accepted VERSION outcome, request and physical stage.
        scan_outcome: Actual unchanged SCAN outcome; failed or refused results cannot apply.
        scan_prepared: Original proof-bound exact SCAN request, never a relabelled native report.
        scan_stage: Original separate physical SCAN stage, not a relocated capture.
        records: Six exact original store-owned records and capture envelopes.
        workspace_root: Existing workspace owning model, records and original physical stages.
        context_provider: Synchronous factual context lookup for canonical SDK acceptance.

    Returns:
        Updated in-memory snapshot and aggregate delta; no save, launch, evidence write or report.

    Raises:
        ValueError: Types, original records, pair, wire or exact package correlation disagree.
        ArtifactDeniedError: Canonical fresh original material, authority or grant validity rejects.
        EvidenceError: Stored manifests or retained bytes fail integrity verification.
        OSError: Current workspace or original material cannot be read.
    """

    if (
        type(state) is not ModelState or type(version_proof) is not ArtifactVersionProof
        or type(scan_outcome) is not ArtifactExecutionOutcome
        or type(scan_prepared) is not PreparedArtifact or type(scan_stage) is not ArtifactStage
    ):
        raise ValueError("synthetic image application requires the original typed runs and model")

    facts, version, scan = VerifyRecords(records, workspace_root)

    if state.workspace_id != facts.workspace_id or scan.acceptance.refusal is not None:
        raise ValueError("synthetic image application requires a successful original owned SCAN")

    for capture, outcome, prepared, stage in (
        (version, version_proof.outcome, version_proof.prepared, version_proof.stage),
        (scan, scan_outcome, scan_prepared, scan_stage),
    ):
        if (
            capture.envelope["artifact_metadata"] != outcome.Metadata()
            or capture.envelope["prepared_payload"] != Detached(prepared.Payload())
            or capture.envelope["stage_payload"] != Detached(ArtifactStagePayload(stage))
            or capture.stdout != outcome.raw_result.stdout
            or capture.stderr != outcome.raw_result.stderr
        ):
            raise ValueError("synthetic image records do not belong to these exact original runs")

    try:
        version_payload = ParseJson(version.stdout, 16 * 1024)
        payload = ParseJson(scan.stdout, 4 * 1024 * 1024)
        candidates = SyntheticTrivyCandidates(
            state.workspace_id, payload, version_payload,
            cast(dict[str, object], version_payload["VulnerabilityDB"]),
            facts.provenance,
        )
        objects, relations, observations, findings = candidates
        observations = [replace(item, attributes={**item.attributes,
            "scan_completeness": "not-assessed"}) if item.kind == "image-inventory" else item
            for item in observations]

    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("synthetic image wire cannot produce reviewed candidates") from None

    try:
        GovernedArtifactExecutor(workspace_root).ValidatePairAcceptanceFresh(
            (version_proof.outcome, version_proof.prepared, version_proof.stage),
            (scan_outcome, scan_prepared, scan_stage), context_provider,
        )

    except ArtifactDeniedError as error:
        raise ArtifactDeniedError(error.reason) from None

    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValueError("synthetic image current authority cannot be verified") from None

    except OSError as error:
        raise type(error)("synthetic image current authority or material cannot be read") from None

    updated, inventory = state.Apply(
        objects=tuple(objects), relations=tuple(relations), observations=tuple(observations),
    )
    updated, detections = ApplyFindings(updated, tuple(findings))
    created = set(inventory.created) | set(detections.created)
    changed = (set(inventory.updated) | set(detections.updated)) - created
    updated = replace(updated, revision=state.revision + bool(created or changed))

    return updated, ModelDelta(state.revision, updated.revision,
                               tuple(sorted(created)), tuple(sorted(changed)))
