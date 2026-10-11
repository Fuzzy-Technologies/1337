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
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
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
    workspace_bytes = (store.root / "workspace.json").read_bytes()
    first, evidence, envelope = Detection(store, subject, outcome=outcome)
    first_state, delta = ApplyVerifiedFindings(initial, (first,), store.root)
    store.Save(first_state, expected_revision=delta.previous_revision)
    second, _, _ = Detection(store, subject, source_id="other-provider", outcome=outcome)
    second_state, delta = ApplyVerifiedFindings(store.Open(), (second,), store.root)
    store.Save(second_state, expected_revision=delta.previous_revision)
    reference = second_state.Objects(ObjectKind.FINDING)[0].Reference()
    operator = ModelProvenance(
        "operator", "decision:one", "2026-10-11T10:01:00Z", "scope:local", "target:local",
    )
    triaged, delta = TransitionFinding(
        store.Open(), reference, FindingStatus.CONFIRMED, operator, "Local evidence reviewed",
    )
    store.Save(triaged, expected_revision=delta.previous_revision)
    snapshot_bytes = (store.root / "state" / "model" / "model.json").read_bytes()
    moved_root = tmp_path / "moved-workspace"
    shutil.move(str(store.root), moved_root)
    moved_store = LocalModelStore(moved_root)
    reopened = moved_store.Open()
    replayed, replay_delta = ApplyVerifiedFindings(reopened, (second,), moved_root)
    moved_store.Save(replayed, expected_revision=replay_delta.previous_revision)
    finding = Findings(reopened)[0]
    acquisition = [record for record in finding.provenance if record.execution is not None]

    assert len(reopened.Objects(ObjectKind.FINDING)) == 1, "Provider dedupe created extra objects"
    assert finding.status is FindingStatus.CONFIRMED, "Relocation or replay lost operator triage"
    assert len(acquisition) == 2 and all(
        record.execution.state is outcome for record in acquisition
    ), (
        "Deduplication erased acquisitions or turned failed execution into success"
    )
    assert LocalEvidenceStore(moved_root / "evidence").Read(evidence.reference) == (
        b'{"synthetic_tls_policy":"not-satisfied"}'
    ), "Portable finding evidence could not be integrity-verified after relocation"
    assert (moved_root / "workspace.json").read_bytes() == workspace_bytes, (
        "Finding publication changed workspace metadata"
    )
    assert (moved_root / "state" / "model" / "model.json").read_bytes() == snapshot_bytes, (
        "Exact rediscovery rewrote canonical triaged state after relocation"
    )
    assert replayed == reopened and replay_delta.created == replay_delta.updated == (), (
        "Exact rediscovery changed findings or retained duplicate observations"
    )
    assert envelope.kind == "provider-check" and envelope.attributes["raw_severity"] == (
        "provider-medium"
    ), "First-party binding mutated the provider-neutral SDK envelope"


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
    missing_reference = replace(
        first.provenance[0].evidence_references[0], locator="blobs/sha256/" + "f" * 64,
        sha256="f" * 64,
    )
    second = replace(first, location_key="tcp/8443", provenance=(replace(
        first.provenance[0], evidence_references=(missing_reference,),
    ),))
    snapshot_bytes = (store.root / "state" / "model" / "model.json").read_bytes()

    with pytest.raises(EvidenceError):
        ApplyVerifiedFindings(initial, (first, second), store.root)

    assert (store.root / "state" / "model" / "model.json").read_bytes() == snapshot_bytes, (
        "A rejected batch wrote part of its finding set"
    )


def test_VerifiedIngestionChecksWorkspaceOwnership(tmp_path):
    """A caller cannot use another workspace as the finding evidence authority."""

    store, initial, subject = Context(tmp_path)
    other_store, _, _ = Context(tmp_path, "foreign")
    finding, _, _ = Detection(store, subject)

    with pytest.raises(ValueError, match="workspace"):
        ApplyVerifiedFindings(initial, (finding,), other_store.root)

    assert store.Open() == initial, "Foreign evidence ownership changed the original workspace"


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
    stale_proposal, stale_delta = ApplyVerifiedFindings(initial, (second,), store.root)
    store.Save(proposal, expected_revision=delta.previous_revision)

    with pytest.raises(WorkspaceConflictError):
        store.Save(stale_proposal, expected_revision=stale_delta.previous_revision)

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
