# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Review verified offline MCP declarations against an explicitly approved snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Literal, cast

from fuzzy1337.adapters.contracts import EvidenceReference
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceStorageError,
    LocalEvidenceStore,
    ParseEvidenceManifest,
    RequireEvidenceDigest,
)
from fuzzy1337.findings import ApplyFindings, Finding, FindingSeverity, Remediation
from fuzzy1337.mcp_inventory import ProjectInventory, RedactedText
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    PrepareModelState,
    RequireModelReference,
)
from fuzzy1337.workspace import (
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    WorkspaceConflictError,
)

__all__ = (
    "ApproveMcpBaseline",
    "McpBaselineApproval",
    "McpDriftChange",
    "McpDriftReview",
    "McpDriftUnknown",
    "ReviewMcpDrift",
)

_APPROVAL_KIND = "mcp-baseline-approval"
_REVIEW_KIND = "mcp-declaration-review"
_SOURCE = "mcp-declaration-drift"
_PROFILE = "offline-v1"
_REVIEW_EVIDENCE_ROLE = "mcp-declaration-diff-redacted"
_SNAPSHOT_EVIDENCE_ROLE = "mcp-inventory-redacted"
_SNAPSHOT_SOURCE = "mcp-inventory-local"
_SERVER_KEY_PREFIX = "mcp:v1:"
_MAX_INVENTORY_BYTES = 256 * 1024
_REACH_SECTIONS = {
    "tools": "tool", "resources": "resource", "resource_templates": "resource-template",
}
_HINTS = ("destructiveHint", "idempotentHint", "openWorldHint", "readOnlyHint")
_SUMMARIES = {
    "mcp.tool-added": "The inventory declares an additional tool.",
    "mcp.tool-removed": "The inventory no longer declares a previously observed tool.",
    "mcp.tool-input-schema-changed": "The retained input schema declaration changed.",
    "mcp.tool-side-effect-changed": "A declared tool side-effect hint changed.",
    "mcp.resource-added": "The inventory declares an additional resource locator.",
    "mcp.resource-removed": "The inventory no longer declares a previously observed resource.",
    "mcp.resource-template-added": "The inventory declares an additional resource template.",
    "mcp.resource-template-removed": "A previously observed resource template is absent.",
    "mcp.server-instructions-changed": "The redacted fingerprint of server instructions changed.",
}

type DriftStatus = Literal["no-baseline", "unchanged", "unknown", "drift"]
type DriftValue = str | bool | None


@dataclass(frozen=True, slots=True)
class McpDriftChange:
    """Describe a proven metadata change and the workspace object it concerns.

    A missing before/after value means established absence for a membership
    change. Schema and instruction values are fingerprints of retained data.
    Schema paths are relative JSON Pointers into the redacted input schema.
    """

    checkId: str
    subjectReference: str
    section: str
    field: str
    objectKey: str | None
    before: DriftValue
    after: DriftValue
    paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class McpDriftUnknown:
    """Describe uncomparable values or membership due to an optional field or section.

    Optional fields carry known values where supplied. Section membership
    records retain the exact declared completeness status on each side.
    """

    subjectReference: str
    section: str
    field: str
    objectKey: str | None
    before: DriftValue
    after: DriftValue


@dataclass(frozen=True, slots=True)
class McpBaselineApproval:
    """Return the saved model, exact operator decision and its selected snapshot."""

    state: ModelState
    delta: ModelDelta
    serverReference: str
    snapshotReference: str
    decisionReference: str


@dataclass(frozen=True, slots=True)
class McpDriftReview:
    """Return one verified review with immutable evidence and normalized finding references.

    A missing baseline yields no review observation or derived evidence.
    Otherwise, drift takes precedence over unknown coverage in the status;
    unknown details remain available alongside confirmed changes.
    """

    state: ModelState
    delta: ModelDelta
    serverReference: str
    snapshotReference: str
    baselineReference: str | None
    baselineDecisionReference: str | None
    reviewReference: str | None
    status: DriftStatus
    changes: tuple[McpDriftChange, ...] = ()
    unknowns: tuple[McpDriftUnknown, ...] = ()
    findingReferences: tuple[str, ...] = ()
    evidence: EvidenceRecord | None = None


@dataclass(frozen=True, slots=True)
class VerifiedMcpSnapshot:
    """Keep the immutable selected observation and matched redacted evidence together."""

    observation: Observation
    evidence: EvidenceRecord
    inventory: dict[str, object]


def Digest(value: object) -> str:
    """Fingerprint canonical JSON without persisting the raw value.

    Args:
        value: JSON-compatible redacted declaration.

    Returns:
        Lowercase SHA-256 digest with the standard prefix.
    """

    return "sha256:" + hashlib.sha256(CanonicalModelJson(value)).hexdigest()


def OpenDriftState(model: LocalModelStore, expectedRevision: int) -> ModelState:
    """Open the caller-selected compare-and-swap basis before touching evidence.

    Args:
        model: Existing local model owner.
        expectedRevision: Current model revision selected by the caller.

    Returns:
        Validated model state at that exact revision.

    Raises:
        WorkspaceConflictError: Current state differs from the selected revision.
    """

    RequireWorkspaceInteger(expectedRevision, "expected model revision")
    state = model.Open()

    if state.revision != expectedRevision:
        raise WorkspaceConflictError("model revision changed; reopen before MCP declaration review")

    return state


def DriftServer(state: ModelState, serverReference: str) -> ObjectIdentity:
    """Select the workspace-local canonical MCP server without reading its latest projection.

    Args:
        state: Current model state.
        serverReference: Canonical object reference explicitly selected by the caller.

    Returns:
        Stable server identity used to reconstruct descriptor membership.

    Raises:
        ValueError: The reference is invalid or does not select a local MCP server.
    """

    RequireModelReference(serverReference)
    server = next((item.identity for item in state.Objects(ObjectKind.SERVICE)
                   if item.Reference() == serverReference), None)

    if server is None or not server.key.startswith(_SERVER_KEY_PREFIX):
        raise ValueError("MCP drift server is missing from the selected workspace")

    return server


def ReadDriftManifest(store: LocalEvidenceStore, evidenceReference: str) -> EvidenceRecord:
    """Verify a bounded manifest through the existing local evidence owner before blob access.

    Args:
        store: Owning evidence store.
        evidenceReference: Exact SHA-256 manifest identity.

    Returns:
        Validated evidence manifest without loading its payload.

    Raises:
        ValueError: The manifest identity is malformed.
        EvidenceError: The manifest is missing, unreadable or violates its identity or schema.
    """

    if not evidenceReference.startswith("sha256:"):
        raise ValueError("MCP evidence manifest identity must be a SHA-256 reference")

    digest = evidenceReference.removeprefix("sha256:")
    RequireEvidenceDigest(digest)

    try:
        data = store.ReadStoredBytes(("records", f"{digest}.json"), EVIDENCE_MANIFEST_MAX_BYTES)
        record = ParseEvidenceManifest(data)

    except FileNotFoundError as error:
        raise EvidenceNotFoundError("MCP evidence manifest is missing") from error

    except OSError as error:
        raise EvidenceStorageError("MCP evidence manifest could not be read") from error

    except ValueError as error:
        raise EvidenceIntegrityError("MCP evidence manifest violates its schema") from error

    if record.evidence_id != evidenceReference:
        raise EvidenceIntegrityError("MCP evidence manifest digest differs from its reference")

    return record


def VerifyDriftEvidence(store: LocalEvidenceStore, expected: EvidenceRecord) -> None:
    """Verify the manifest with its exact derived byte bound before checking stored bytes.

    Args:
        store: Owning evidence store.
        expected: Exact record derived from two verified, bounded redacted snapshots.

    Raises:
        EvidenceError: Manifest or payload is missing, inconsistent or fails integrity checks.
    """

    if ReadDriftManifest(store, expected.evidence_id) != expected:
        raise EvidenceIntegrityError("MCP diff evidence differs from its verified derivation")

    store.Read(expected.reference)


def LoadDriftSnapshot(
    state: ModelState, server: ObjectIdentity, snapshots: dict[str, Observation],
    store: LocalEvidenceStore, snapshotReference: str,
) -> VerifiedMcpSnapshot:
    """Recover and bind one immutable snapshot and its exact importer-owned redacted evidence.

    Args:
        state: Authoritative model at the selected CAS revision.
        server: Server selected from the same workspace.
        snapshots: Model observations indexed by canonical reference.
        store: Local evidence owner for that workspace.
        snapshotReference: Selected immutable observation reference.

    Returns:
        Verified acquisition, including the normalized historical declaration.

    Raises:
        ValueError: Snapshot selection, provenance, digest, or membership disagrees.
        EvidenceError: The referenced redacted manifest or bytes cannot be verified.
    """

    RequireModelReference(snapshotReference)
    snapshot = snapshots.get(snapshotReference)
    serverReference = server.Reference()

    if (snapshot is None or snapshot.kind != "mcp-inventory-snapshot"
            or snapshot.subject_reference != serverReference):
        raise ValueError("selected MCP snapshot does not belong to the selected server")

    evidence = ReadDriftManifest(store, snapshot.provenance.run_reference)
    acquired = evidence.provenance
    expectedProvenance = ModelProvenance(
        _SNAPSHOT_SOURCE, evidence.evidence_id, acquired.finished_at, acquired.scope_reference,
        serverReference, _PROFILE, (evidence.reference,),
    )

    if not 1 <= evidence.reference.size_bytes <= _MAX_INVENTORY_BYTES:
        raise EvidenceIntegrityError("MCP snapshot evidence exceeds the inventory byte bound")

    if (
        acquired.workspace_id != state.workspace_id
        or acquired.source_id != _SNAPSHOT_SOURCE or acquired.source_version != _PROFILE
        or acquired.execution is not None or acquired.invocation_sha256 is not None
        or acquired.tool_version is not None or acquired.started_at != acquired.finished_at
        or evidence.reference.role != _SNAPSHOT_EVIDENCE_ROLE
        or evidence.reference.media_type != "application/json"
        or snapshot.provenance != expectedProvenance
    ):
        raise ValueError("MCP snapshot evidence attribution does not match its observation")

    payload = store.Read(evidence.reference)

    try:
        receipt = json.loads(payload)
        inventory = receipt["inventory"]
        digest = Digest(inventory)

        if (
            set(receipt) != {"schema_version", "profile", "server_key", "snapshot_digest",
                             "inventory", "actor_ref", "read_consent_reference"}
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["profile"] != _PROFILE
            or receipt["server_key"] != server.key.removeprefix(_SERVER_KEY_PREFIX)
            or receipt["snapshot_digest"] != digest or CanonicalModelJson(receipt) != payload
            or snapshot.attributes["snapshot_digest"] != digest
        ):
            raise ValueError("MCP snapshot receipt does not match its observation")

        reconstructed, _, reconstructedReference = ProjectInventory(
            state, server, inventory, digest, expectedProvenance,
        )

    except (IndexError, KeyError, TypeError, ValueError, RecursionError) as error:
        raise ValueError("MCP redacted receipt is invalid or disagrees with its model") from error

    if reconstructed is not state or reconstructedReference != snapshotReference:
        raise ValueError("MCP snapshot membership does not match its verified redacted evidence")

    return VerifiedMcpSnapshot(snapshot, evidence, inventory)


def BaselineDecisions(
    snapshots: dict[str, Observation], serverReference: str,
) -> tuple[Observation, ...]:
    """Validate and order the selected server's append-only approval observations.

    Args:
        snapshots: Exact CAS model observations indexed by canonical reference.
        serverReference: Canonical server reference used for review.

    Returns:
        Baseline decisions in insertion order, with the active decision last.

    Raises:
        ValueError: Decision history is inconsistent with its predecessor or review.
    """

    decisions = tuple(item for item in snapshots.values() if item.kind == _APPROVAL_KIND
                      and item.subject_reference == serverReference)
    ordered = tuple(sorted(decisions, key=lambda item: RequireWorkspaceInteger(
        item.attributes.get("sequence"), "MCP approval sequence",
    )))
    previous: str | None = None
    priorSnapshot: object = None
    approvals = set()

    for sequence, decision in enumerate(ordered, start=1):
        fields = decision.attributes
        selected = snapshots.get(RequireModelReference(fields.get("snapshot_reference")))
        reviewReference = fields.get("review_reference")
        provenance = decision.provenance

        if (
            fields.get("sequence") != sequence or fields.get("previous_decision") != previous
            or fields.get("schema_version") != 1 or selected is None
            or selected.kind != "mcp-inventory-snapshot"
            or selected.subject_reference != serverReference
            or selected.attributes.get("snapshot_digest") != fields.get("snapshot_digest")
            or provenance.source_id != _SOURCE or provenance.provider_version != _PROFILE
            or provenance.target_reference != serverReference
            or provenance.scope_reference != selected.provenance.scope_reference
            or provenance.evidence_references != selected.provenance.evidence_references
            or provenance.execution is not None or provenance.run_reference in approvals
        ):
            raise ValueError("MCP baseline decision history is invalid")

        if previous is not None:
            review = snapshots.get(RequireModelReference(reviewReference))

            if (
                review is None or review.kind != _REVIEW_KIND
                or review.subject_reference != serverReference
                or review.attributes.get("baseline_decision") != previous
                or review.attributes.get("baseline_snapshot") != priorSnapshot
                or review.attributes.get("current_snapshot") != selected.Reference()
            ):
                raise ValueError("MCP baseline decision has no matching historical review")

        elif reviewReference is not None:
            raise ValueError("first MCP baseline decision cannot have a prior review")

        approvals.add(provenance.run_reference)
        previous = decision.Reference()
        priorSnapshot = selected.Reference()

    return ordered


def SchemaChanges(before: object, after: object, pointer: str = "") -> tuple[str, ...]:
    """Find differing nodes in already normalized structure without exposing values.

    Args:
        before: Baseline redacted schema node.
        after: Candidate redacted schema node.
        pointer: JSON Pointer of the node relative to the input schema root.

    Returns:
        Deterministic paths to added, removed or changed nodes; arrays compare as units.
    """

    if isinstance(before, dict) and isinstance(after, dict):
        paths = []

        for key in sorted(before.keys() | after.keys()):
            child = pointer + "/" + key.replace("~", "~0").replace("/", "~1")

            if key not in before or key not in after:
                paths.append(child)

            else:
                paths.extend(SchemaChanges(before[key], after[key], child))

        return tuple(paths)

    if CanonicalModelJson(before) == CanonicalModelJson(after):
        return ()

    return (pointer,)


def DiffDeclarations(
    server: ObjectIdentity, baseline: VerifiedMcpSnapshot, current: VerifiedMcpSnapshot,
) -> tuple[tuple[McpDriftChange, ...], tuple[McpDriftUnknown, ...]]:
    """Compare redacted positive declarations using explicit membership completeness.

    Args:
        server: Canonical identity common to both verified snapshots.
        baseline: Previously approved declaration and source evidence.
        current: Candidate declaration and source evidence.

    Returns:
        Deterministically ordered changes and unknown metadata comparisons.
    """

    changes: list[McpDriftChange] = []
    unknowns: list[McpDriftUnknown] = []
    serverReference = server.Reference()

    def CompareOptional(
        subject: str, section: str, field: str, key: str | None, check: str,
        before: DriftValue, after: DriftValue,
    ) -> None:
        """Record unknown omissions or known changes without imposing default values.

        Args:
            subject: Stable existing model object reference.
            section: Source inventory section or server metadata.
            field: Retained declaration field.
            key: Tool name if the field describes a tool.
            check: Stable rule identifier for a known change.
            before: Baseline declaration; None means unknown.
            after: Candidate declaration; None means unknown.
        """

        if before is None or after is None:
            unknowns.append(McpDriftUnknown(subject, section, field, key, before, after))

        elif before != after:
            changes.append(McpDriftChange(check, subject, section, field, key, before, after))

    beforeSections = cast(dict[str, dict[str, object]], baseline.inventory["sections"])
    afterSections = cast(dict[str, dict[str, object]], current.inventory["sections"])

    for section, kind in _REACH_SECTIONS.items():
        beforeSection = beforeSections[section]
        afterSection = afterSections[section]
        beforeStatus = cast(str, beforeSection["status"])
        afterStatus = cast(str, afterSection["status"])
        beforeItems = {cast(str, item["key"]): item
                       for item in cast(list[dict[str, object]], beforeSection["items"])}
        afterItems = {cast(str, item["key"]): item
                      for item in cast(list[dict[str, object]], afterSection["items"])}

        if beforeStatus != "complete" or afterStatus != "complete":
            unknowns.append(McpDriftUnknown(
                serverReference, section, "membership", None, beforeStatus, afterStatus,
            ))

        for key in sorted(beforeItems.keys() | afterItems.keys()):
            reference = ObjectIdentity(
                server.workspace_id, ObjectKind.ASSET, f"{server.key}:{kind}:{key}",
            ).Reference()
            before = beforeItems.get(key)
            after = afterItems.get(key)

            if before is None and beforeStatus == "complete":
                changes.append(McpDriftChange(
                    f"mcp.{kind}-added", reference, section, "membership", key, None, key,
                ))

            elif after is None and afterStatus == "complete":
                changes.append(McpDriftChange(
                    f"mcp.{kind}-removed", reference, section, "membership", key, key, None,
                ))

            if kind != "tool":
                continue

            if before is None or after is None:
                present = beforeItems[key] if before is not None else afterItems[key]
                hints = cast(dict[str, bool | None], present["annotations"])

                for hint in _HINTS:
                    if hints[hint] is None:
                        unknowns.append(McpDriftUnknown(
                            reference, section, f"annotations/{hint}", key, None, None,
                        ))

                continue

            oldSchema, newSchema = before["input_schema"], after["input_schema"]
            paths = SchemaChanges(oldSchema, newSchema)

            if paths:
                changes.append(McpDriftChange(
                    "mcp.tool-input-schema-changed", reference, section, "input_schema", key,
                    Digest(oldSchema), Digest(newSchema), paths,
                ))

            oldHints = cast(dict[str, bool | None], before["annotations"])
            newHints = cast(dict[str, bool | None], after["annotations"])

            for hint in _HINTS:
                CompareOptional(
                    reference, section, f"annotations/{hint}", key,
                    "mcp.tool-side-effect-changed", oldHints[hint], newHints[hint],
                )

    CompareOptional(
        serverReference, "server", "instructions_fingerprint", None,
        "mcp.server-instructions-changed",
        cast(str | None, baseline.inventory["instructions_fingerprint"]),
        cast(str | None, current.inventory["instructions_fingerprint"]),
    )

    return tuple(changes), tuple(unknowns)


def SnapshotSource(snapshot: VerifiedMcpSnapshot) -> dict[str, object]:
    """Link a derived change record to its exact original redacted acquisition.

    Args:
        snapshot: One verified immutable snapshot and its manifest.

    Returns:
        Canonical snapshot, evidence, scope and source-time references.
    """

    return {
        "snapshot_reference": snapshot.observation.Reference(),
        "snapshot_digest": snapshot.observation.attributes["snapshot_digest"],
        "evidence_manifest": snapshot.evidence.evidence_id,
        "scope_reference": snapshot.observation.provenance.scope_reference,
        "observed_at": snapshot.observation.provenance.observed_at,
    }


def BuildDriftReview(
    state: ModelState, server: ObjectIdentity, decision: Observation,
    baseline: VerifiedMcpSnapshot, current: VerifiedMcpSnapshot,
) -> tuple[McpDriftReview, Observation, bytes, tuple[Finding, ...]]:
    """Prepare deterministic derived evidence and the exact observation and findings it supports.

    Args:
        state: Selected model before changes.
        server: Shared canonical MCP server.
        decision: Active approval of the verified baseline.
        baseline: Verified approved inventory revision.
        current: Verified inventory revision being assessed.

    Returns:
        Review projection, immutable fact, derived evidence bytes and incoming findings.
    """

    changes, unknowns = DiffDeclarations(server, baseline, current)
    status: DriftStatus = "unchanged"

    if changes:
        status = "drift"

    elif any(item.field == "membership" or item.before != item.after for item in unknowns):
        status = "unknown"

    serverReference = server.Reference()
    decisionReference = decision.Reference()
    baselineReference = baseline.observation.Reference()
    snapshotReference = current.observation.Reference()
    payload = CanonicalModelJson({
        "schema_version": 1,
        "profile": _PROFILE,
        "server_reference": serverReference,
        "baseline_decision": decisionReference,
        "baseline": SnapshotSource(baseline),
        "current": SnapshotSource(current),
        "status": status,
        "changes": changes,
        "unknowns": unknowns,
    })
    digest = hashlib.sha256(payload).hexdigest()
    source = current.observation.provenance
    evidence = EvidenceRecord(EvidenceReference(
        _REVIEW_EVIDENCE_ROLE, f"blobs/sha256/{digest}", digest, "application/json", len(payload),
    ), EvidenceProvenance(
        state.workspace_id, source.scope_reference, _SOURCE, _PROFILE, None,
        source.observed_at, source.observed_at,
    ))
    provenance = ModelProvenance(
        _SOURCE, evidence.evidence_id, source.observed_at, source.scope_reference,
        serverReference, _PROFILE, (evidence.reference,),
    )
    findings = tuple(
        Finding(
            change.subjectReference, change.checkId, change.field, _SUMMARIES[change.checkId],
            (provenance,), FindingSeverity.INFORMATIONAL, 1.0,
            remediation=Remediation("Review the declaration before approving the new baseline."),
        )
        for change in changes
    )
    fact = Observation(_REVIEW_KIND, serverReference, {
        "schema_version": 1,
        "baseline_decision": decisionReference,
        "baseline_snapshot": baselineReference,
        "current_snapshot": snapshotReference,
        "status": status,
        "change_count": len(changes),
        "unknown_count": len(unknowns),
    }, provenance)
    result = McpDriftReview(
        state, ModelDelta(state.revision, state.revision), serverReference, snapshotReference,
        baselineReference, decisionReference, fact.Reference(), status, changes, unknowns,
        tuple(sorted(finding.ToObject(state.workspace_id).Reference() for finding in findings)),
        evidence,
    )

    return result, fact, payload, findings


def VerifyApprovalReview(
    state: ModelState, server: ObjectIdentity, snapshots: dict[str, Observation],
    store: LocalEvidenceStore, previous: Observation, current: VerifiedMcpSnapshot,
    reviewReference: str | None,
) -> None:
    """Reconstruct the exact selected review and verify its retained diff before approval.

    Args:
        state: Current read basis for the workspace model.
        server: Canonical identity of the reviewed MCP server.
        snapshots: Model observations indexed by canonical reference.
        store: Owning evidence store.
        previous: Approval decision serving as the baseline of the selected review.
        current: Verified candidate that the selected review compared against that baseline.
        reviewReference: Exact saved review observation named by the operator.

    Raises:
        ValueError: Review selection, source or historical comparison bindings disagree.
        EvidenceError: An original acquisition or derived review fails evidence verification.
    """

    if reviewReference is None:
        raise ValueError("MCP baseline advancement requires selection of a saved review")

    baseline = LoadDriftSnapshot(
        state, server, snapshots, store, cast(str, previous.attributes["snapshot_reference"]),
    )
    result, fact, _, _ = BuildDriftReview(state, server, previous, baseline, current)

    if reviewReference != fact.Reference() or snapshots.get(reviewReference) != fact:
        raise ValueError("selected MCP review does not bind its baseline and snapshot")

    VerifyDriftEvidence(store, cast(EvidenceRecord, result.evidence))


def ReviewMcpDrift(
    model: LocalModelStore, *, serverReference: str, snapshotReference: str,
    expectedRevision: int,
) -> McpDriftReview:
    """Review one exact offline inventory against the active explicitly approved baseline.

    Repeated review of the same approval and snapshot verifies the stored
    evidence and returns the existing review. This operation never approves a
    snapshot. A stale CAS after evidence publication can leave unlinked, valid
    redacted evidence for the same deterministic replay.

    Args:
        model: Existing selected local workspace model owner.
        serverReference: Canonical server object from this workspace.
        snapshotReference: Immutable inventory snapshot selected for review.
        expectedRevision: Exact current model CAS basis.

    Returns:
        Review status, change and unknown details, evidence, findings and saved model state.

    Raises:
        ValueError: Selection or verified snapshot, model, or review bindings disagree.
        WorkspaceConflictError: Coupled model revision changed.
        EvidenceError: An original or derived evidence record cannot be verified or published.
        OSError: Required local storage operations fail.
    """

    state = OpenDriftState(model, expectedRevision)
    server = DriftServer(state, serverReference)
    snapshots = {item.Reference(): item for item in state.observations}
    store = LocalEvidenceStore(model.root / "evidence")
    current = LoadDriftSnapshot(state, server, snapshots, store, snapshotReference)
    decisions = BaselineDecisions(snapshots, serverReference)

    if not decisions:
        saved = model.Save(state, expected_revision=expectedRevision)

        return McpDriftReview(
            saved, ModelDelta(state.revision, state.revision), serverReference, snapshotReference,
            None, None, None, "no-baseline",
        )

    decision = decisions[-1]
    baselineReference = cast(str, decision.attributes["snapshot_reference"])
    baseline = current if baselineReference == snapshotReference else LoadDriftSnapshot(
        state, server, snapshots, store, baselineReference,
    )
    result, fact, payload, findings = BuildDriftReview(state, server, decision, baseline, current)
    evidence = cast(EvidenceRecord, result.evidence)

    if fact.Reference() in snapshots:
        VerifyDriftEvidence(store, evidence)
        saved = model.Save(state, expected_revision=expectedRevision)

        return replace(result, state=saved)

    withFindings, findingsDelta = ApplyFindings(state, findings)
    # Fold the review fact and new finding observations into the same model CAS.
    proposal = replace(
        withFindings, revision=state.revision + 1,
        observations=(*withFindings.observations, fact),
    )
    delta = ModelDelta(
        state.revision, proposal.revision, (*findingsDelta.created, fact.Reference()),
        findingsDelta.updated,
    )
    PrepareModelState(proposal)
    retained = store.Put(payload, _REVIEW_EVIDENCE_ROLE, "application/json", evidence.provenance)

    if retained != evidence:
        raise ValueError("MCP review evidence publication differs from its verified derivation")

    VerifyDriftEvidence(store, evidence)
    saved = model.Save(proposal, expected_revision=expectedRevision)

    return replace(result, state=saved, delta=delta)


def ApproveMcpBaseline(
    model: LocalModelStore, *, serverReference: str, snapshotReference: str, actorReference: str,
    approvalReference: str, approvedAt: str, expectedRevision: int,
    reviewReference: str | None = None,
) -> McpBaselineApproval:
    """Append an explicit operator baseline decision bound to the selected verified revision.

    The first decision approves a directly inspected acquisition. Subsequent
    decisions require the exact saved review against the current decision.
    Replaying an identical approval identifier verifies its original evidence
    and returns the original decision, even if it is no longer active.

    Args:
        model: Existing selected local workspace model owner.
        serverReference: Canonical server object from that workspace.
        snapshotReference: Exact immutable snapshot approved as the baseline.
        actorReference: Explicit non-secret operator reference.
        approvalReference: Explicit non-secret decision reference unique to this server.
        approvedAt: Timestamp of the operator's decision with a UTC offset.
        expectedRevision: Exact current model CAS basis.
        reviewReference: Exact persisted review fact selected by the operator on advancement.

    Returns:
        Saved model state, immutable approval decision and associated references.

    Raises:
        ValueError: Input, approval history or reviewed selection is invalid or disagrees.
        WorkspaceConflictError: Coupled model revision changed.
        EvidenceError: A selected snapshot or review evidence record cannot be verified.
        OSError: Required local storage operations fail.
    """

    for value in (actorReference, approvalReference):
        RequireWorkspaceText(value, "MCP approval attribution")

        if len(value) > 4096 or RedactedText(value) != value:
            raise ValueError("MCP approval attribution must use bounded non-secret references")

    state = OpenDriftState(model, expectedRevision)
    server = DriftServer(state, serverReference)
    snapshots = {item.Reference(): item for item in state.observations}
    store = LocalEvidenceStore(model.root / "evidence")
    current = LoadDriftSnapshot(state, server, snapshots, store, snapshotReference)
    decisions = BaselineDecisions(snapshots, serverReference)
    source = current.observation.provenance
    provenance = ModelProvenance(
        _SOURCE, approvalReference, approvedAt, source.scope_reference,
        serverReference, _PROFILE, (current.evidence.reference,),
    )
    fields = {
        "schema_version": 1,
        "snapshot_reference": snapshotReference,
        "snapshot_digest": current.observation.attributes["snapshot_digest"],
        "review_reference": reviewReference,
        "actor_reference": actorReference,
    }

    for index, item in enumerate(decisions):
        if item.provenance.run_reference == approvalReference:
            if item.provenance != provenance or any(
                item.attributes.get(key) != value for key, value in fields.items()
            ):
                raise ValueError("MCP approval reference already identifies a different decision")

            if index:
                VerifyApprovalReview(
                    state, server, snapshots, store, decisions[index - 1], current, reviewReference,
                )

            saved = model.Save(state, expected_revision=expectedRevision)

            return McpBaselineApproval(
                saved, ModelDelta(state.revision, state.revision), serverReference,
                snapshotReference, item.Reference(),
            )

    previous = decisions[-1] if decisions else None

    if previous is not None:
        baselineReference = cast(str, previous.attributes["snapshot_reference"])

        if baselineReference == snapshotReference:
            raise ValueError("selected MCP snapshot is already the active baseline")

        VerifyApprovalReview(state, server, snapshots, store, previous, current, reviewReference)

    elif reviewReference is not None:
        raise ValueError("first MCP baseline approval cannot reference a prior review")

    decision = Observation(_APPROVAL_KIND, serverReference, {
        **fields,
        "sequence": len(decisions) + 1,
        "previous_decision": previous.Reference() if previous is not None else None,
    }, provenance)
    proposal, delta = state.Apply(observations=(decision,))
    saved = model.Save(proposal, expected_revision=expectedRevision)

    return McpBaselineApproval(
        saved, delta, serverReference, snapshotReference, decision.Reference(),
    )
