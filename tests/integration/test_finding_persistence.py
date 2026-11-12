# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real workspace, immutable evidence, canonical finding, and revision integration."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState, NormalizedFinding
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceIntegrityError,
    EvidenceProvenance,
    LocalEvidenceStore,
)
from fuzzy1337.findings import (
    ApplyVerifiedFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceConfiguration,
    WorkspaceConflictError,
)


def Context(tmp_path: Path, workspace_id="synthetic"):
    """Create real owned storage and a first-party localhost subject without performing a scan."""

    root = tmp_path / workspace_id
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Finding integration"), workspace_id)
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance(
        "native", "run:subject", "2026-10-11T10:00:00Z", "scope:local", "target:local",
    )
    subject = SecurityObject(
        ObjectIdentity(workspace_id, ObjectKind.HOST, "127.0.0.1"), {}, (provenance,),
    )
    state, delta = initial.Apply(objects=(subject,))
    store.Save(state, expected_revision=delta.previous_revision)

    return store, state, subject


def Detection(store, subject, source_id="native", outcome=ExecutionState.SUCCEEDED):
    """Bind an SDK envelope explicitly to first-party identity and real acquisition evidence."""

    execution = AdapterExecution(outcome, 0 if outcome is ExecutionState.SUCCEEDED else 2, 0.1)
    evidence = LocalEvidenceStore(store.root / "evidence").Put(
        b'{"synthetic_tls_policy":"not-satisfied"}', "stdout", "application/json",
        EvidenceProvenance(
            store.Open().workspace_id, "scope:local", source_id, "1", "fixture-1",
            "2026-10-11T10:00:00Z", "2026-10-11T10:00:01Z", execution=execution,
        ),
    )
    envelope = NormalizedFinding(
        "provider-check", "provider-host", "Synthetic TLS policy",
        {"raw_severity": "provider-medium"},
    )
    provenance = ModelProvenance(
        source_id, evidence.evidence_id, "2026-10-11T10:00:01Z", "scope:local", "target:local",
        "fixture-1", (evidence.reference,), execution,
    )
    finding = Finding(
        subject.Reference(), "transport.test-policy", "tcp/443", envelope.summary,
        (provenance,), FindingSeverity.MEDIUM, 0.75,
    )

    return finding, evidence, envelope


@pytest.mark.parametrize("outcome", [ExecutionState.SUCCEEDED, ExecutionState.FAILED])
def test_DedupeEvidenceAndDispositionSurviveWorkspaceRelocation(tmp_path, outcome):
    """Acquisitions converge on one object and retain verified portable evidence and outcomes."""

    store, initial, subject = Context(tmp_path)
    workspaceBytes = (store.root / "workspace.json").read_bytes()
    first, evidence, envelope = Detection(store, subject, outcome=outcome)
    firstState, delta = ApplyVerifiedFindings(initial, (first,), store.root)
    store.Save(firstState, expected_revision=delta.previous_revision)
    second, _, _ = Detection(store, subject, source_id="other-provider", outcome=outcome)
    secondState, delta = ApplyVerifiedFindings(store.Open(), (second,), store.root)
    store.Save(secondState, expected_revision=delta.previous_revision)
    reference = secondState.Objects(ObjectKind.FINDING)[0].Reference()
    operator = ModelProvenance(
        "operator", "decision:one", "2026-10-11T10:01:00Z", "scope:local", "target:local",
    )
    triaged, delta = TransitionFinding(
        store.Open(), reference, FindingStatus.CONFIRMED, operator, "Local evidence reviewed",
    )
    store.Save(triaged, expected_revision=delta.previous_revision)
    snapshotBytes = (store.root / "state" / "model" / "model.json").read_bytes()
    movedRoot = tmp_path / "moved-workspace"
    shutil.move(str(store.root), movedRoot)
    movedStore = LocalModelStore(movedRoot)
    reopened = movedStore.Open()
    replayed, replayDelta = ApplyVerifiedFindings(reopened, (second,), movedRoot)
    movedStore.Save(replayed, expected_revision=replayDelta.previous_revision)
    finding = Findings(reopened)[0]
    acquisition = [record for record in finding.provenance if record.execution is not None]

    assert len(reopened.Objects(ObjectKind.FINDING)) == 1, "Provider dedupe created extra objects"
    assert finding.status is FindingStatus.CONFIRMED, "Relocation or replay lost operator triage"
    assert len(acquisition) == 2 and all(
        record.execution.state is outcome for record in acquisition
    ), (
        "Deduplication erased acquisitions or turned failed execution into success"
    )
    assert LocalEvidenceStore(movedRoot / "evidence").Read(evidence.reference) == (
        b'{"synthetic_tls_policy":"not-satisfied"}'
    ), "Portable finding evidence could not be integrity-verified after relocation"
    assert (movedRoot / "workspace.json").read_bytes() == workspaceBytes, (
        "Finding publication changed workspace metadata"
    )
    assert (movedRoot / "state" / "model" / "model.json").read_bytes() == snapshotBytes, (
        "Exact rediscovery rewrote canonical triaged state after relocation"
    )
    assert replayed == reopened and replayDelta.created == replayDelta.updated == (), (
        "Exact rediscovery changed findings or retained duplicate observations"
    )
    assert envelope.kind == "provider-check" and envelope.attributes["raw_severity"] == (
        "provider-medium"
    ), "First-party binding mutated the provider-neutral SDK envelope"


def test_VerifiedFindingReplayKeepsEndpointEvidenceSeparate(tmp_path):
    """Equal check and location keys retain separate evidence for separate endpoint subjects."""

    store, initial, host = Context(tmp_path)
    endpoints = tuple(
        SecurityObject(
            ObjectIdentity(initial.workspace_id, ObjectKind.ENDPOINT, endpointUrl),
            {}, host.provenance,
        )
        for endpointUrl in ("https://one.example.invalid/health", "https://two.example.invalid/health")
    )
    state, delta = initial.Apply(objects=endpoints)
    store.Save(state, expected_revision=delta.previous_revision)

    evidenceStore = LocalEvidenceStore(store.root / "evidence")
    firstPayload = b'{"fixture":"one","policy":"not-satisfied"}'
    secondPayload = b'{"fixture":"two","policy":"not-satisfied"}'
    detections = []
    expectedEvidence = {}

    for endpoint, payload in zip(endpoints, (firstPayload, secondPayload), strict=True):
        evidence = evidenceStore.Put(
            payload, "stdout", "application/json",
            EvidenceProvenance(
                initial.workspace_id, "scope:local", "native", "1", "fixture-1",
                "2026-10-11T10:00:00Z", "2026-10-11T10:00:01Z",
            ),
        )
        subjectReference = endpoint.Reference()
        provenance = ModelProvenance(
            "native", evidence.evidence_id, "2026-10-11T10:00:01Z", "scope:local",
            subjectReference, "fixture-1", (evidence.reference,),
        )
        detections.append(Finding(
            subjectReference, "transport.test-policy", "tcp/443", "Synthetic TLS policy",
            (provenance,), FindingSeverity.MEDIUM, 0.75,
        ))
        expectedEvidence[subjectReference] = (evidence.reference,)

    updated, delta = ApplyVerifiedFindings(store.Open(), tuple(detections), store.root)
    store.Save(updated, expected_revision=delta.previous_revision)
    copiedRoot = tmp_path / "copied-workspace"
    shutil.copytree(store.root, copiedRoot)
    copiedStore = LocalModelStore(copiedRoot)
    reopened = copiedStore.Open()
    copiedEvidence = LocalEvidenceStore(copiedRoot / "evidence")
    firstReference, secondReference = (
        expectedEvidence[endpoint.Reference()][0] for endpoint in endpoints
    )
    replayed, replayDelta = ApplyVerifiedFindings(
        reopened, tuple(reversed(detections)), copiedRoot,
    )

    assert copiedEvidence.Read(firstReference) == firstPayload
    assert copiedEvidence.Read(secondReference) == secondPayload

    assert len(reopened.Objects(ObjectKind.FINDING)) == 2, (
        "Distinct endpoints merged into one finding"
    )
    assert {
        item.subject_reference: tuple(
            reference
            for provenance in item.provenance
            for reference in provenance.evidence_references
        )
        for item in Findings(reopened)
    } == expectedEvidence, "Verified evidence was linked to a different endpoint"
    assert replayed == reopened and replayDelta.created == replayDelta.updated == (), (
        "Replay changed stable finding identities or attributed evidence"
    )

    copiedModel = copiedRoot / "state" / "model" / "model.json"
    snapshotBytes = copiedModel.read_bytes()
    (copiedRoot / "evidence" / secondReference.locator).write_bytes(
        b"x" * secondReference.size_bytes
    )

    with pytest.raises(EvidenceIntegrityError, match="raw evidence digest"):
        ApplyVerifiedFindings(reopened, tuple(detections), copiedRoot)

    assert copiedModel.read_bytes() == snapshotBytes, "Rejected replay changed the copied model"
    assert copiedEvidence.Read(firstReference) == firstPayload
    assert evidenceStore.Read(firstReference) == firstPayload
    assert evidenceStore.Read(secondReference) == secondPayload
    assert store.Open() == reopened, "Corrupting the copy changed the original workspace"


@pytest.mark.parametrize("failure", ["missing", "corrupt", "wrong-size"])
def test_VerifiedIngestionRejectsMissingOrCorruptEvidenceBeforeAnyModelChange(tmp_path, failure):
    """Verified ingestion must complete all byte checks before returning a proposed transition."""

    store, initial, subject = Context(tmp_path)
    finding, evidence, _ = Detection(store, subject)
    path = store.root / "evidence" / evidence.reference.locator

    if failure == "missing":
        path.unlink()

    elif failure == "corrupt":
        path.write_bytes(b"x" * evidence.reference.size_bytes)

    else:
        reference = replace(evidence.reference, size_bytes=evidence.reference.size_bytes + 1)
        finding = replace(finding, provenance=(replace(
            finding.provenance[0], evidence_references=(reference,),
        ),))

    with pytest.raises(EvidenceError):
        ApplyVerifiedFindings(initial, (finding,), store.root)

    assert store.Open() == initial and Findings(initial) == (), (
        "Failed evidence verification partially mutated persisted model state"
    )


def test_VerifiedBatchFailsAtomicallyAfterOneValidEvidenceCheck(tmp_path):
    """A later missing artifact cannot leave an earlier finding committed from the same batch."""

    store, initial, subject = Context(tmp_path)
    first, _, _ = Detection(store, subject)
    missingReference = replace(
        first.provenance[0].evidence_references[0], locator="blobs/sha256/" + "f" * 64,
        sha256="f" * 64,
    )
    second = replace(first, location_key="tcp/8443", provenance=(replace(
        first.provenance[0], evidence_references=(missingReference,),
    ),))
    snapshotBytes = (store.root / "state" / "model" / "model.json").read_bytes()

    with pytest.raises(EvidenceError):
        ApplyVerifiedFindings(initial, (first, second), store.root)

    assert (store.root / "state" / "model" / "model.json").read_bytes() == snapshotBytes, (
        "A rejected batch wrote part of its finding set"
    )


def test_VerifiedIngestionChecksWorkspaceOwnership(tmp_path):
    """A caller cannot use another workspace as the finding evidence authority."""

    store, initial, subject = Context(tmp_path)
    otherStore, _, _ = Context(tmp_path, "foreign")
    finding, _, _ = Detection(store, subject)

    with pytest.raises(ValueError, match="workspace"):
        ApplyVerifiedFindings(initial, (finding,), otherStore.root)

    assert store.Open() == initial, "Foreign evidence ownership changed the original workspace"


def test_DispositionReplayIsPortableAndPreservesLaterCanonicalState(tmp_path):
    """Reopened decision history prevents an old retry from overriding a newer disposition."""

    store, initial, subject = Context(tmp_path)
    finding, _, _ = Detection(store, subject)
    state, delta = ApplyVerifiedFindings(initial, (finding,), store.root)
    store.Save(state, expected_revision=delta.previous_revision)
    reference = state.Objects(ObjectKind.FINDING)[0].Reference()
    first = ModelProvenance(
        "operator", "decision:one", "2026-10-11T10:01:00Z", "scope:local", "target:local",
    )
    second = replace(first, run_reference="decision:two", observed_at="2026-10-11T10:02:00Z")

    for status, provenance, reason in (
        (FindingStatus.CONFIRMED, first, "First review"),
        (FindingStatus.OPEN, second, "Reopened for a later review"),
    ):
        state, delta = TransitionFinding(store.Open(), reference, status, provenance, reason)
        store.Save(state, expected_revision=delta.previous_revision)

    snapshotBytes = (store.root / "state" / "model" / "model.json").read_bytes()
    movedRoot = tmp_path / "moved-workspace"
    shutil.move(str(store.root), movedRoot)
    movedStore = LocalModelStore(movedRoot)
    reopened = movedStore.Open()
    replayed, delta = TransitionFinding(
        reopened, reference, FindingStatus.CONFIRMED, first, "First review",
    )
    movedStore.Save(replayed, expected_revision=delta.previous_revision)

    assert replayed == reopened and delta.created == delta.updated == (), (
        "Persisted decision replay changed a newer disposition after workspace relocation"
    )
    assert (movedRoot / "state" / "model" / "model.json").read_bytes() == snapshotBytes, (
        "Old decision retry rewrote the persisted snapshot"
    )
    decisions = [item for item in reopened.observations if item.kind == "finding-disposition"]
    assert len(decisions) == 2 and {item.provenance for item in decisions} == {first, second}, (
        "Canonical disposition history lost operator attribution or retained duplicate decisions"
    )


def test_VerifiedIngestionReadsSharedArtifactOnce(tmp_path, monkeypatch):
    """Dedupe reuses a verified raw artifact without weakening integrity or provenance checks."""

    store, initial, subject = Context(tmp_path)
    first, evidence, _ = Detection(store, subject)
    second = replace(first, location_key="tcp/8443")
    calls = []
    original = LocalEvidenceStore.Read

    def Read(self, reference):
        """Count the real immutable-evidence read rather than substituting a success stub."""

        calls.append(reference)

        return original(self, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    updated, _ = ApplyVerifiedFindings(initial, (first, second), store.root)

    assert calls == [evidence.reference], "One batch redundantly read the same raw artifact"
    assert len(Findings(updated)) == 2, "Distinct locations were merged by evidence digest"


def test_CompetingFindingProposalsUseExistingRevisionConflictBoundary(tmp_path):
    """Finding publication participates in the canonical model CAS instead of its own store."""

    store, initial, subject = Context(tmp_path)
    first, _, _ = Detection(store, subject)
    second = replace(first, location_key="tcp/8443")
    proposal, delta = ApplyVerifiedFindings(initial, (first,), store.root)
    staleProposal, staleDelta = ApplyVerifiedFindings(initial, (second,), store.root)
    store.Save(proposal, expected_revision=delta.previous_revision)

    with pytest.raises(WorkspaceConflictError):
        store.Save(staleProposal, expected_revision=staleDelta.previous_revision)

    assert store.Open() == proposal, "A stale finding proposal replaced newer canonical state"


def test_ModelReopenRejectsTamperedFindingFields(tmp_path):
    """Persisted finding schema is revalidated through the authoritative model loader."""

    store, initial, subject = Context(tmp_path)
    finding, _, _ = Detection(store, subject)
    updated, delta = ApplyVerifiedFindings(initial, (finding,), store.root)
    store.Save(updated, expected_revision=delta.previous_revision)
    path = store.root / "state" / "model" / "model.json"
    document = json.loads(path.read_text("utf-8"))
    entity = next(item for item in document["objects"] if item["identity"]["kind"] == "finding")
    entity["attributes"]["confidence"] = 1.1
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="confidence"):
        store.Open()


@pytest.mark.parametrize("state,findings", [(None, ()), ("actual", "all"),
                                          ("actual", ({},))])
def test_VerifiedIngestionRejectsUntypedInputs(tmp_path, state, findings):
    """The verified I/O boundary does not coerce generic objects into model/detection contracts."""

    store, initial, _ = Context(tmp_path)
    state = initial if state == "actual" else state

    with pytest.raises(ValueError):
        ApplyVerifiedFindings(state, findings, store.root)

    assert store.Open() == initial, "Rejected input changed canonical persisted state"
