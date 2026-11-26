# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify offline MCP review across real model, evidence, finding and approval owners."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceIntegrityError, LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingSeverity
from fuzzy1337.mcp_drift import (
    ApproveMcpBaseline,
    McpBaselineApproval,
    McpDriftReview,
    ReviewMcpDrift,
)
from fuzzy1337.mcp_inventory import ImportMcpInventory, McpInventoryImport
from fuzzy1337.model import LocalModelStore, ModelState, ObjectIdentity, ObjectKind
from fuzzy1337.report_commands import OpenReportInput
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceConfiguration,
    WorkspaceConflictError,
)

_SAMPLE = Path(__file__).parents[1] / "contract" / "fixtures" / "mcp.inventory.v1.json"
_WORKSPACE = "catalog-review"
_ACQUIRED = "2026-11-26T12:30:00+00:00"
_APPROVED = "2026-11-26T12:45:00+00:00"


def CreateModel(root: Path, workspaceId: str = _WORKSPACE) -> LocalModelStore:
    """Create an owned temporary workspace with existing scope and model state.

    Args:
        root: A new test directory.
        workspaceId: Workspace identity for this isolated model.

    Returns:
        A local model owner holding its initial state.
    """

    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Offline catalog review"), workspaceId)
    LocalScopeStore(root).Create(ScopeSnapshot("demo", workspaceId))
    model = LocalModelStore(root)
    model.Create()

    return model


def ImportSource(
    model: LocalModelStore, source: dict[str, Any], serverKey: str = "catalog",
    observedAt: str = _ACQUIRED,
) -> McpInventoryImport:
    """Import a benign owned declaration through the original SDK.

    Args:
        model: Existing local model owner.
        source: Synthetic declaration source, serialized to a new temporary file.
        serverKey: Caller-selected canonical MCP server key.
        observedAt: Explicit source acquisition time.

    Returns:
        Verified canonical import result.
    """

    path = model.root / "source-test.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    return ImportMcpInventory(
        model, path, serverKey=serverKey, scopeId="demo",
        consent=ArtifactReadConsent("actor:collector", "consent:fixture"),
        observedAt=observedAt, expectedRevision=model.Open().revision,
    )


def ApproveFixture(
    model: LocalModelStore, selected: McpInventoryImport, approvalReference: str = "approval:one",
    reviewReference: str | None = None,
) -> McpBaselineApproval:
    """Approve one exact verified acquisition using explicit benign operator references.

    Args:
        model: Existing local model owner.
        selected: Selected importer result with stable server and snapshot references.
        approvalReference: Unique operator decision reference.
        reviewReference: Saved review observation when advancing a baseline.

    Returns:
        Acknowledged CAS transition or exact replay.
    """

    return ApproveMcpBaseline(
        model, serverReference=selected.serverReference,
        snapshotReference=selected.snapshotReference,
        actorReference="actor:operator", approvalReference=approvalReference, approvedAt=_APPROVED,
        expectedRevision=model.Open().revision, reviewReference=reviewReference,
    )


def RunReview(model: LocalModelStore, selected: McpInventoryImport) -> McpDriftReview:
    """Review the selected offline snapshot against the active baseline.

    Args:
        model: Local workspace model.
        selected: Immutable snapshot and server references returned by import.

    Returns:
        Verified review, saved findings and deterministic evidence.
    """

    return ReviewMcpDrift(
        model, serverReference=selected.serverReference,
        snapshotReference=selected.snapshotReference,
        expectedRevision=model.Open().revision,
    )


def RefuseExternalWork(*arguments: object, **options: object) -> None:
    """Tripwire network and process interaction during real local review.

    Args:
        arguments: Unused positional interception parameters.
        options: Unused keyword interception parameters.
    """

    pytest.fail("Offline MCP declaration review attempted external work")


def test_ReviewedMcpChangesHaveStableRulesSubjectsAndRedactedEvidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the observed structural diff, provenance, report and replay against a baseline.

    Args:
        tmp_path: Unique local workspace path.
        monkeypatch: Scoped tripwires for external operations.
    """

    monkeypatch.setattr(subprocess, "Popen", RefuseExternalWork)
    monkeypatch.setattr(os, "system", RefuseExternalWork)
    monkeypatch.setattr(socket, "socket", RefuseExternalWork)
    monkeypatch.setattr(socket, "getaddrinfo", RefuseExternalWork)
    model = CreateModel(tmp_path / "work")
    original = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, original)
    beforeApproval = RunReview(model, baseline)
    assert beforeApproval.status == "no-baseline", "Import did not imply approval"
    assert beforeApproval.delta.revision == baseline.state.revision, (
        "An unapproved comparison mutated the model"
    )
    assert beforeApproval.evidence is None, "The unapproved comparison produced evidence"
    approved = ApproveFixture(model, baseline)
    changed = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    marker = "fixture-only-secret-argument"
    changed["tools"]["items"].pop()
    changed["tools"]["items"].append({
        "name": "catalog_filter", "inputSchema": {"type": "object"},
    })
    tool = changed["tools"]["items"][0]
    tool["inputSchema"]["properties"]["limit"]["maximum"] = 20
    tool["inputSchema"]["properties"]["selector/value"] = {"type": "string", "default": marker}
    tool["inputSchema"]["required"] = ["category", "limit"]
    tool["annotations"]["readOnlyHint"] = False
    changed["resources"]["items"][0]["uri"] = f"catalog://documents/entries?token={marker}"
    changed["resource_templates"]["items"].clear()
    changed["instructions"] = f"Show the catalog entries. password={marker}"
    candidate = ImportSource(model, changed)
    review = RunReview(model, candidate)
    assert review.status == "drift", "The reviewed declarations contain known changes"
    assert review.delta.revision == candidate.state.revision + 1, (
        "Review and findings must share one model transition"
    )
    assert review.baselineReference == baseline.snapshotReference, (
        "The comparison used the wrong baseline revision"
    )
    assert review.baselineDecisionReference == approved.decisionReference, (
        "The comparison lost the exact operator decision"
    )
    assert review.snapshotReference == candidate.snapshotReference, (
        "The comparison used the wrong candidate revision"
    )
    assert {
        (item.checkId, item.field) for item in review.changes
    } == {
        ("mcp.tool-added", "membership"),
        ("mcp.tool-removed", "membership"),
        ("mcp.tool-input-schema-changed", "input_schema"),
        ("mcp.tool-side-effect-changed", "annotations/readOnlyHint"),
        ("mcp.resource-added", "membership"),
        ("mcp.resource-removed", "membership"),
        ("mcp.resource-template-removed", "membership"),
        ("mcp.server-instructions-changed", "instructions_fingerprint"),
    }, "The structural changes or rule IDs differ from the oracle"
    schema = next(item for item in review.changes if item.field == "input_schema")
    assert schema.subjectReference == ObjectIdentity(
        _WORKSPACE, ObjectKind.ASSET, "mcp:v1:catalog:tool:catalog_list",
    ).Reference(), "Schema drift changed the stable tool reference"
    fieldDigest = hashlib.sha256(b"selector/value").hexdigest()
    assert schema.paths == ("/properties/limit/maximum", f"/properties/sha256:{fieldDigest}",
                            "/required"), "The schema paths lost a changed structural location"
    assert schema.before != schema.after, "The changed schema has identical fingerprints"
    assert any(item.objectKey == "catalog_filter" and item.before is None and item.after is None
               for item in review.unknowns), "An omitted hint on an added tool remains unknown"
    assert review.evidence is not None, "The review lacks derived evidence"
    store = LocalEvidenceStore(model.root / "evidence")
    payload = store.Read(store.Get(review.evidence.evidence_id).reference)
    evidence = json.loads(payload)
    assert marker.encode() not in payload, "Synthetic credential leaked into review evidence"
    assert b"Show the catalog entries" not in payload, (
        "Raw instructions leaked into review evidence"
    )
    assert b"catalog://documents" not in payload, "Raw locator leaked into review evidence"
    assert evidence["baseline"]["evidence_manifest"] == baseline.evidence.evidence_id, (
        "Baseline acquisition manifest was not retained"
    )
    assert evidence["current"]["evidence_manifest"] == candidate.evidence.evidence_id, (
        "Candidate acquisition manifest was not retained"
    )
    assert evidence["baseline"]["snapshot_reference"] == baseline.snapshotReference, (
        "Baseline evidence lost the immutable reference"
    )
    assert evidence["current"]["snapshot_reference"] == candidate.snapshotReference, (
        "Candidate evidence lost the immutable reference"
    )
    assert evidence["current"]["scope_reference"] == "scope:demo", (
        "Candidate source scope was not retained"
    )
    assert review.evidence.reference in OpenReportInput(model.root).report.EvidenceReferences(), (
        "The report could not verify the review evidence"
    )
    assert len(review.findingReferences) == len(review.changes), (
        "Each proven change needs a corresponding finding"
    )
    findings = Findings(model.Open())
    assert {item.ToObject(_WORKSPACE).Reference() for item in findings} == set(
        review.findingReferences,
    ), "Model and review finding identities disagree"
    assert all(item.severity is FindingSeverity.INFORMATIONAL for item in findings), (
        "Declaration drift alone is informational"
    )
    assert {
        (finding.subject_reference, finding.check_id) for finding in findings
    } == {(change.subjectReference, change.checkId) for change in review.changes}, (
        "Finding subjects and checks must match the verified diff"
    )
    replay = RunReview(model, candidate)
    assert replay.state == review.state and replay.delta.created == (), (
        "Identical CI review mutated saved state"
    )
    assert replay.reviewReference == review.reviewReference, "Identical CI changed review identity"
    assert replay.evidence == review.evidence, "Identical CI changed evidence identity"
    assert len(list((model.root / "evidence" / "records").iterdir())) == 3, (
        "Identical CI review duplicated evidence records"
    )


def test_ReorderingAndAbsentAnnotationsHaveDefinedReviewStatus(tmp_path: Path) -> None:
    """Ignore declaration ordering and distinguish omitted hints from explicit boolean changes.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)

    for section in ("tools", "capabilities", "resources", "resource_templates", "prompts"):
        source[section]["items"].reverse()

    reordered = ImportSource(model, source, observedAt="2026-11-26T12:31:00+00:00")
    review = RunReview(model, reordered)
    assert review.status == "unchanged" and review.changes == (), (
        "Declaration order caused false drift"
    )
    assert any(item.field == "annotations/readOnlyHint" and item.objectKey == "catalog_count"
               and item.before is None and item.after is None for item in review.unknowns), (
        "An omitted hint was not retained as unknown"
    )

    source["tools"]["items"][1]["annotations"].pop("readOnlyHint")
    source.pop("instructions")
    unknown = RunReview(model, ImportSource(model, source))
    assert unknown.status == "unknown" and unknown.findingReferences == (), (
        "Unknown values should not produce drift findings"
    )
    assert any(item.field == "annotations/readOnlyHint" and item.objectKey == "catalog_list"
               and item.before is True and item.after is None for item in unknown.unknowns), (
        "An omitted annotation does not imply a boolean change"
    )
    assert any(item.field == "instructions_fingerprint" and item.before is not None
               and item.after is None for item in unknown.unknowns), (
        "Omitted instructions should remain unknown"
    )


@pytest.mark.parametrize("status", ["incomplete", "unsupported", "unknown", "omitted", "complete"])
def test_OnlyCompleteCandidateCanEstablishRemoval(tmp_path: Path, status: str) -> None:
    """Require an affirmative complete empty section before recording tool removal.

    Args:
        tmp_path: Unique local workspace path.
        status: Explicit or omitted inventory section state.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)

    if status == "omitted":
        source.pop("tools")

    else:
        source["tools"] = {"status": status, "items": []}

    review = RunReview(model, ImportSource(model, source))

    if status == "complete":
        assert review.status == "drift", (
            "Complete empty enumeration proves prior membership changed"
        )
        assert {item.checkId for item in review.changes} == {"mcp.tool-removed"}, (
            "Unexpected rule changed in the empty complete inventory"
        )
        assert len(review.changes) == 2, "Both previously observed tools are absent"

    else:
        assert review.status == "unknown", "Partial input must carry incomplete comparison status"
        assert review.changes == () and review.findingReferences == (), (
            "Truncated membership cannot establish removal"
        )
        assert any(
            item.section == "tools" and item.before == "complete"
            and item.after == ("unknown" if status == "omitted" else status)
            for item in review.unknowns
        ), "The source section status was discarded"


def test_ReviewDecisionsAppendAndReplayWithoutReactivatingHistory(tmp_path: Path) -> None:
    """Select an exact review to advance the baseline and retain previous decisions on replay.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    first = ApproveFixture(model, baseline)
    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)

    with pytest.raises(ValueError, match="selection of a saved review"):
        ApproveFixture(model, candidate, "approval:two")

    review = RunReview(model, candidate)

    with pytest.raises(ValueError, match="does not bind"):
        ApproveFixture(model, candidate, "approval:two", baseline.snapshotReference)

    with pytest.raises(ValueError, match="already identifies"):
        ApproveFixture(model, candidate, "approval:one", review.reviewReference)

    advanced = ApproveFixture(model, candidate, "approval:two", review.reviewReference)
    assert advanced.delta.revision == review.state.revision + 1, (
        "Baseline advancement did not append exactly one decision"
    )
    assert advanced.decisionReference != first.decisionReference, (
        "Distinct decision references collided"
    )
    history = {
        item.Reference(): item.attributes for item in model.Open().observations
        if item.kind == "mcp-baseline-approval"
    }
    assert history[first.decisionReference]["previous_decision"] is None, (
        "Bootstrap must begin a new history"
    )
    assert history[advanced.decisionReference]["previous_decision"] == first.decisionReference, (
        "Advancement lost its prior decision"
    )
    assert history[advanced.decisionReference]["review_reference"] == review.reviewReference, (
        "Advancement lost the exact operator-reviewed result"
    )
    assert history[advanced.decisionReference]["actor_reference"] == "actor:operator", (
        "The decision did not preserve human attribution"
    )
    latest = history[advanced.decisionReference]
    assert latest["snapshot_reference"] == candidate.snapshotReference, (
        "The decision lost the approved immutable snapshot"
    )
    replay = ApproveFixture(model, baseline)
    assert replay.decisionReference == first.decisionReference and replay.state == advanced.state, (
        "Replaying a historical decision changed the active baseline"
    )
    after = RunReview(model, candidate)
    assert after.status == "unchanged", "The candidate should match its newly approved baseline"
    assert after.baselineDecisionReference == advanced.decisionReference, (
        "The review did not use the newest baseline decision"
    )

    with pytest.raises(ValueError, match="already the active baseline"):
        ApproveFixture(model, candidate, "approval:three", after.reviewReference)


def test_McpReviewRefusesCrossBindingAndCorruptEvidence(tmp_path: Path) -> None:
    """Fail before mutating state for wrong server, workspace, stale CAS or corrupted sources.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    other = ImportSource(model, source, serverKey="other")
    foreign = ImportSource(CreateModel(tmp_path / "foreign", "other-workspace"), source)
    state = model.Open()

    for selected in (other.snapshotReference, foreign.snapshotReference):
        with pytest.raises(ValueError, match="does not belong"):
            ReviewMcpDrift(
                model, serverReference=baseline.serverReference, snapshotReference=selected,
                expectedRevision=state.revision,
            )

    with pytest.raises(ValueError, match="server is missing"):
        RunReview(model, foreign)

    with pytest.raises(WorkspaceConflictError, match="revision changed"):
        ReviewMcpDrift(
            model, serverReference=baseline.serverReference,
            snapshotReference=baseline.snapshotReference, expectedRevision=0,
        )

    forged = next(
        item for item in state.observations if item.Reference() == baseline.snapshotReference
    )
    forged = replace(forged, attributes={**forged.attributes, "sections": {}})
    forgedState, _ = state.Apply(observations=(forged,))
    model.Save(forgedState, expected_revision=state.revision)

    with pytest.raises(ValueError, match="membership does not match"):
        RunReview(model, replace(baseline, snapshotReference=forged.Reference()))

    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)
    snapshotPath = model.root / "evidence" / baseline.evidence.reference.locator
    snapshotPath.write_bytes(b"corrupt")

    with pytest.raises(EvidenceIntegrityError):
        RunReview(model, candidate)

    assert model.Open() == candidate.state, "Corrupt source evidence caused a model mutation"


def test_DerivedReviewEvidenceIsRequiredForReplayAndApproval(tmp_path: Path) -> None:
    """Reject replay or advancement when the recorded diff bytes fail integrity checks.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)
    review = RunReview(model, candidate)
    assert review.evidence is not None, "The reviewed revision lacks derived evidence"
    (model.root / "evidence" / review.evidence.reference.locator).write_bytes(b"corrupt")

    with pytest.raises(EvidenceIntegrityError):
        RunReview(model, candidate)

    with pytest.raises(EvidenceIntegrityError):
        ApproveFixture(model, candidate, "approval:two", review.reviewReference)

    assert model.Open() == review.state, "Corrupt diff evidence caused a model mutation"


def test_HistoricalApprovalReplayRequiresItsOriginalVerifiedDiff(tmp_path: Path) -> None:
    """Revalidate the original review when replaying a superseded advancement.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)
    review = RunReview(model, candidate)
    advanced = ApproveFixture(model, candidate, "approval:two", review.reviewReference)
    source["tools"]["items"][0]["inputSchema"]["properties"]["limit"]["maximum"] = 20
    latest = ImportSource(model, source)
    nextReview = RunReview(model, latest)
    newest = ApproveFixture(model, latest, "approval:three", nextReview.reviewReference)
    replay = ApproveFixture(model, candidate, "approval:two", review.reviewReference)
    assert replay.decisionReference == advanced.decisionReference, (
        "Replaying the verified historic advancement changed the decision"
    )
    assert replay.state == newest.state, "An earlier decision changed the active baseline"
    assert review.evidence is not None, "The earlier approval lacks verified diff evidence"
    (model.root / "evidence" / review.evidence.reference.locator).write_bytes(b"corrupt")

    with pytest.raises(EvidenceIntegrityError):
        ApproveFixture(model, candidate, "approval:two", review.reviewReference)

    assert model.Open() == newest.state, "Failed historic replay must preserve the active baseline"


def test_McpManifestAdmissionBoundsBeforeBlobReads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject oversized originals and a foreign derived manifest without reading either blob.

    Args:
        tmp_path: Unique local workspace path.
        monkeypatch: Scoped tripwire on reading the substituted blob.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)
    review = RunReview(model, candidate)
    assert review.evidence is not None, "The original review lacks derived evidence"
    evidence = LocalEvidenceStore(model.root / "evidence")
    oversized = b" " * (256 * 1024 + 1)
    oversizedOriginal = evidence.Put(
        oversized, baseline.evidence.reference.role, "application/json",
        baseline.evidence.provenance,
    )
    oversizedDerived = evidence.Put(
        oversized, review.evidence.reference.role, "application/json", review.evidence.provenance,
    )
    observed = next(
        item for item in review.state.observations if item.Reference() == baseline.snapshotReference
    )
    forged = replace(observed, provenance=replace(
        observed.provenance, run_reference=oversizedOriginal.evidence_id,
        evidence_references=(oversizedOriginal.reference,),
    ))
    state, _ = review.state.Apply(observations=(forged,))
    model.Save(state, expected_revision=review.state.revision)
    expectedPath = evidence.root / "records" / (review.evidence.evidence_id[7:] + ".json")
    expectedPath.write_bytes(oversizedDerived.Serialize())
    originalRead = LocalEvidenceStore.ReadStoredBytes

    def GuardBlob(store: LocalEvidenceStore, parts: tuple[str, ...], maxBytes: int) -> bytes:
        """Refuse the specific oversized blob while retaining real safe reads.

        Args:
            store: Existing owning evidence reader.
            parts: Store-selected manifest or blob path components.
            maxBytes: Existing read bound in bytes.

        Returns:
            Verified owner bytes for all permitted reads.
        """

        assert parts[-1] != oversizedOriginal.reference.sha256, "Unadmitted blob was read"

        return originalRead(store, parts, maxBytes)

    monkeypatch.setattr(LocalEvidenceStore, "ReadStoredBytes", GuardBlob)

    with pytest.raises(EvidenceIntegrityError, match="inventory byte bound"):
        RunReview(model, replace(baseline, snapshotReference=forged.Reference()))

    with pytest.raises(EvidenceIntegrityError, match="manifest digest differs"):
        RunReview(model, candidate)

    assert model.Open() == state, "Failed manifest admission mutated the model"


def test_IncompleteSectionsPreservePositiveChangesWithUnknownMembership(tmp_path: Path) -> None:
    """Keep verified positive declarations while incomplete membership stays unknown.

    Args:
        tmp_path: Unique local workspace path.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    source["tools"]["status"] = "incomplete"
    source["tools"]["items"].pop()
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    source["tools"]["items"][0]["inputSchema"]["properties"]["limit"]["maximum"] = 20
    source["tools"]["items"].append({
        "name": "catalog_other", "inputSchema": {"type": "object"},
    })
    source["resource_templates"] = {
        "status": "incomplete", "items": [{"name": "Public entry", "uriTemplate": "catalog:{id}"}],
    }
    review = RunReview(model, ImportSource(model, source))
    assert review.status == "drift", "Confirmed changes and unknowns can coexist"
    assert {item.checkId for item in review.changes} == {
        "mcp.tool-input-schema-changed", "mcp.resource-template-added",
    }, "A partial inventory cannot establish absence"
    assert {item.section for item in review.unknowns if item.field == "membership"} == {
        "tools", "resource_templates",
    }, "The report lost incomplete coverage"


def test_RetryUsesIdenticalDerivedEvidenceAfterConcurrentModelCas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain a valid orphan diff on a CAS race and reuse it in a new review attempt.

    Args:
        tmp_path: Unique local workspace path.
        monkeypatch: Scoped simulation of one legitimate concurrent model save.
    """

    model = CreateModel(tmp_path / "work")
    source = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    baseline = ImportSource(model, source)
    ApproveFixture(model, baseline)
    source["tools"]["items"].pop()
    candidate = ImportSource(model, source)
    originalSave = LocalModelStore.Save

    def SaveAfterConcurrentWrite(
        store: LocalModelStore, state: ModelState, **options: int,
    ) -> ModelState:
        """Advance the model once before the prepared review's original CAS.

        Args:
            store: Selected workspace model.
            state: Pending verified review transition.
            options: Original model save keyword containing the pre-race revision.

        Returns:
            Original model save result if its CAS can succeed.
        """

        basis = store.Open()
        fact = next(
            item for item in basis.observations if item.Reference() == candidate.snapshotReference
        )
        competing, _ = basis.Apply(observations=(replace(fact, kind="test-concurrent-note"),))
        originalSave(store, competing, expected_revision=options["expected_revision"])

        return originalSave(store, state, expected_revision=options["expected_revision"])

    with monkeypatch.context() as race:
        race.setattr(LocalModelStore, "Save", SaveAfterConcurrentWrite)

        with pytest.raises(WorkspaceConflictError, match="revision changed"):
            RunReview(model, candidate)

    assert Findings(model.Open()) == (), "Losing the CAS must not commit model findings"
    records = model.root / "evidence" / "records"
    published = tuple(sorted(records.iterdir()))
    assert len(published) == 3, "The verified derived evidence was not retained for retry"
    retry = RunReview(model, candidate)
    assert retry.status == "drift", "Retry did not complete the same review"
    assert tuple(sorted(records.iterdir())) == published, "Retry duplicated derived evidence"
