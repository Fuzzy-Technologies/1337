# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real offline source/detector evidence, model persistence, triage preservation and replay."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace

import pytest

from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import (
    ApplyVerifiedFindings,
    Finding,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.intel_references import ReferenceSource, SourceOrigin
from fuzzy1337.intelligence import (
    ApplyVerifiedEnrichment,
    IntelligenceFeed,
    ParseIntelligenceSnapshot,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration, WorkspaceConflictError

CVE = "CVE-1900-9999"
AS_OF = "2026-10-12T13:00:00Z"


def Context(tmp_path, name="synthetic"):
    """Create one owned canonical finding and raw detection without contacting a scan target."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Intel integration"), name)
    store = LocalModelStore(root)
    initial = store.Create()
    context = ModelProvenance("synthetic", "run:subject", "2026-10-12T10:00:00Z",
                              "scope:local", "target:local")
    subject = SecurityObject(ObjectIdentity(name, ObjectKind.HOST, "127.0.0.1"), {}, (context,))
    state, delta = initial.Apply(objects=(subject,))
    store.Save(state, expected_revision=delta.previous_revision)
    detector = LocalEvidenceStore(root / "evidence").Put(
        b"Synthetic detection evidence", "stdout", "text/plain",
        EvidenceProvenance(name, "scope:local", "synthetic", "1", "fixture",
                           "2026-10-12T10:00:00Z", "2026-10-12T10:00:01Z"),
    )
    finding = Finding(
        subject.Reference(), "synthetic.check", "tcp/443", "Synthetic finding",
        (replace(context, run_reference=detector.evidence_id,
                 evidence_references=(detector.reference,)),), FindingSeverity.LOW, 0.25,
    )
    state, delta = ApplyVerifiedFindings(state, (finding,), root)
    store.Save(state, expected_revision=delta.previous_revision)
    provenance = ModelProvenance("intel", "run:enrichment", AS_OF, "scope:local", "target:local")

    return store, state, state.Objects(ObjectKind.FINDING)[0].Reference(), detector, provenance


def Source(store, score="0.125", role="intelligence-source"):
    """Persist a small synthetic FIRST-shaped artifact and bind the pure parser to real bytes."""

    raw = (
        "#model_version:synthetic-model-1,score_date:2026-10-12T00:00:00Z\n"
        f"cve,epss,percentile\n{CVE},{score},0.8\n"
    ).encode()
    evidence = LocalEvidenceStore(store.root / "evidence").Put(
        raw, role, "text/csv", EvidenceProvenance(
            store.Open().workspace_id, "scope:local", "synthetic-intel", "1", None,
            "2026-10-12T12:00:00Z", "2026-10-12T12:00:00Z",
        ),
    )
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/scores.csv",
        evidence.reference.sha256, "Apache-2.0 (synthetic fixture only)",
        "https://example.invalid/LICENSE", "2026-10-12T12:00:00Z", "synthetic-importer", "1",
    )

    return ParseIntelligenceSnapshot(
        raw, IntelligenceFeed.EPSS, "synthetic-model-1", source, evidence.reference,
    )


def Enrich(base_state, base_reference, base_snapshot, base_provenance, base_root, **changes):
    """Call the real verified consumer with explicit exact identifiers and a freshness budget."""

    options = {"state": base_state, "finding_reference": base_reference,
               "identifiers": (CVE, "CWE-89"), "snapshots": (base_snapshot,),
               "provenance": base_provenance, "workspace_root": base_root,
               "as_of": AS_OF, "max_age_seconds": 3600, **changes}

    return ApplyVerifiedEnrichment(**options)


def test_CvePublisherGmtTimestampSurvivesVerifiedReparseAndCanonicalPersistence(tmp_path):
    """Stored CVE bytes without a zone retain publisher GMT semantics without upgrading triage."""

    store, state, reference, _, provenance = Context(tmp_path)
    raw = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED", "dateUpdated": "2026-10-12T10:00:00"},
        "containers": {"cna": {"providerMetadata": {"orgId": "synthetic-cna"}}},
    }).encode()
    evidence = LocalEvidenceStore(store.root / "evidence").Put(
        raw, "intelligence-source", "application/json", EvidenceProvenance(
            state.workspace_id, "scope:local", "synthetic-intel", "1", None,
            "2026-10-12T12:00:00Z", "2026-10-12T12:00:00Z",
        ),
    )
    source = ReferenceSource(
        SourceOrigin.SYNTHETIC, "1337 synthetic fixture", "https://example.invalid/source.json",
        evidence.reference.sha256, "Apache-2.0 (synthetic fixture only)",
        "https://example.invalid/LICENSE", "2026-10-12T12:00:00Z", "synthetic-importer", "1",
    )
    snapshot = ParseIntelligenceSnapshot(
        raw, IntelligenceFeed.CVE, "synthetic-record-list-1", source, evidence.reference,
    )
    enriched, delta = Enrich(state, reference, snapshot, provenance, store.root, identifiers=(CVE,))
    observation = [item for item in enriched.observations if item.kind == "finding-intelligence"][0]
    assertion = observation.attributes["source_assertions"][0]

    assert assertion["record"]["effective_at"] == "2026-10-12T10:00:00.000000+00:00", (
        "CVE publisher GMT semantics changed during verified reparse"
    )
    assert enriched.Objects(ObjectKind.FINDING) == state.Objects(ObjectKind.FINDING), (
        "A source timestamp created a vulnerability claim or changed operator disposition"
    )
    assert assertion["association_state"] == "candidate" and assertion["review"] is None, (
        "Byte verification upgraded the explicit identifier association"
    )
    assert store.Open() == state, "Verification wrote a source proposal before caller publication"
    store.Save(enriched, expected_revision=delta.previous_revision)

    assert store.Open() == enriched, "Canonical persistence changed the source timestamp semantics"
    assert LocalEvidenceStore(store.root / "evidence").Read(snapshot.evidence) == raw, (
        "Timestamp normalization changed retained raw CVE bytes"
    )


def test_VerifiedIntelligenceKeepsDispositionAndEvidenceAcrossRelocationAndOldReplay(tmp_path):
    """Source observations preserve later operator triage across persistence and relocation."""

    store, state, reference, detector, provenance = Context(tmp_path)
    snapshot = Source(store)
    enriched, delta = Enrich(state, reference, snapshot, provenance, store.root)
    original = Finding.FromObject(state.Objects(ObjectKind.FINDING)[0])
    observed = [item for item in enriched.observations if item.kind == "finding-intelligence"][0]
    assertion = observed.attributes["source_assertions"][0]

    assert Finding.FromObject(enriched.Objects(ObjectKind.FINDING)[0]) == original, (
        "Catalog presence changed finding severity, confidence, remediation, or disposition"
    )
    assert assertion["record"]["data"]["probability"] == 0.125 and assertion["review"] is None, (
        "An EPSS score acquired an approval claim or was converted into a finding probability"
    )
    assert assertion["stale"] is True and assertion["age_seconds"] == 13 * 3600, (
        "EPSS staleness must use score date rather than recent artifact acquisition"
    )
    assert observed.attributes["unmatched_identifiers"] == ("CWE-89",), (
        "Absent classifications must remain unmatched rather than become negative security claims"
    )
    assert snapshot.evidence in observed.provenance.evidence_references, (
        "Canonical observation lost the raw source artifact reference"
    )
    store.Save(enriched, expected_revision=delta.previous_revision)
    operator = ModelProvenance("operator", "decision:later", "2026-10-12T14:00:00Z",
                               "scope:local", "target:local")
    triaged, delta = TransitionFinding(
        store.Open(), reference, FindingStatus.DISMISSED, operator, "Owner reviewed local evidence",
    )
    store.Save(triaged, expected_revision=delta.previous_revision)
    moved = tmp_path / "moved"
    shutil.move(str(store.root), moved)
    reopened = LocalModelStore(moved)
    prior_bytes = (moved / "state/model/model.json").read_bytes()
    replayed, delta = Enrich(reopened.Open(), reference, snapshot, provenance, moved)
    reopened.Save(replayed, expected_revision=delta.previous_revision)

    assert replayed == triaged and delta.created == delta.updated == (), (
        "Exact enrichment replay changed newer triage or created another interpretation"
    )
    assert (moved / "state/model/model.json").read_bytes() == prior_bytes, (
        "Replaying a portable source rewrote the authoritative finding/model snapshot"
    )
    assert LocalEvidenceStore(moved / "evidence").Read(detector.reference) == (
        b"Synthetic detection evidence"
    ), "Relocation lost verified detector evidence"


@pytest.mark.parametrize("artifact,failure", [
    ("detector", "missing"), ("detector", "corrupt"),
    ("source", "missing"), ("source", "corrupt"), ("source", "wrong-size"),
])
def test_ConsumerVerifiesEveryArtifactBeforeReturningAnyModelProposal(tmp_path, artifact, failure):
    """A broken source or detector artifact cannot yield partial successful enrichment."""

    store, state, reference, detector, provenance = Context(tmp_path)
    snapshot = Source(store)
    evidence = detector.reference if artifact == "detector" else snapshot.evidence
    path = store.root / "evidence" / evidence.locator

    if failure == "missing":
        path.unlink()

    elif failure == "corrupt":
        path.write_bytes(b"x" * evidence.size_bytes)

    else:
        snapshot = replace(snapshot, evidence=replace(evidence, size_bytes=evidence.size_bytes + 1))

    with pytest.raises(EvidenceError):
        Enrich(state, reference, snapshot, provenance, store.root)

    assert store.Open() == state, "Failed verification wrote part of a model transition"


def test_RehashedForgedParsedSnapshotCannotReplaceTheVerifiedSourceAssertion(tmp_path):
    """A caller can recompute public hashes but cannot use invented parsed scores at ingestion."""

    store, state, reference, _, provenance = Context(tmp_path)
    snapshot = Source(store)
    forged = replace(snapshot, records=(replace(
        snapshot.records[0], data={**snapshot.records[0].data, "probability": 0.99},
    ),))

    assert forged.Reference() != snapshot.Reference(), "Forged content retained the original hash"

    with pytest.raises(ValueError, match="verified source bytes"):
        Enrich(state, reference, forged, provenance, store.root)

    assert store.Open() == state, "A forged source interpretation reached canonical persistence"


@pytest.mark.parametrize("change", [
    {"state": "model"}, {"provenance": {}}, {"finding_reference": "object:" + "f" * 64},
    {"finding_reference": "relation:" + "f" * 64}, {"identifiers": "CVE"},
    {"identifiers": ()}, {"identifiers": (CVE, CVE)}, {"snapshots": ()},
    {"snapshots": ({},)}, {"max_age_seconds": True}, {"max_age_seconds": -1},
    {"as_of": "2026-10-12T12:59:59Z"},
])
def test_ConsumerRejectsUntypedUnattributedAmbiguousAndUnboundedInputs(tmp_path, change):
    """The verified boundary cannot infer associations, timestamps, or types from caller intent."""

    store, state, reference, _, provenance = Context(tmp_path)
    snapshot = Source(store)

    with pytest.raises(ValueError):
        Enrich(state, reference, snapshot, provenance, store.root, **change)

    assert store.Open() == state, "Rejected input changed persisted findings or observations"


def test_ConsumerRejectsForeignWorkspaceDuplicateSourcesAndFutureKnowledge(tmp_path):
    """The real boundary retains owned evidence, explicit chronology and source uniqueness."""

    store, state, reference, _, provenance = Context(tmp_path)
    other, _, _, _, _ = Context(tmp_path, "foreign")
    snapshot = Source(store)

    with pytest.raises(ValueError, match="workspace"):
        Enrich(state, reference, snapshot, provenance, other.root)

    with pytest.raises(ValueError, match="unique"):
        Enrich(state, reference, snapshot, provenance, store.root, snapshots=(snapshot, snapshot))

    future = replace(snapshot, source=replace(snapshot.source, acquired_at="2026-10-12T14:00:00Z"))

    with pytest.raises(ValueError, match="as-of"):
        Enrich(state, reference, future, provenance, store.root)


def test_IndependentSourceRevisionsAreRetainedAndUseTheCanonicalModelCas(tmp_path):
    """Fresh source interpretations remain attributable under the existing revision gate."""

    store, state, reference, _, provenance = Context(tmp_path)
    first = Source(store)
    second = Source(store, "0.5")
    proposal, delta = Enrich(state, reference, first, provenance, store.root)
    other, other_delta = Enrich(state, reference, second, provenance, store.root)
    store.Save(proposal, expected_revision=delta.previous_revision)

    with pytest.raises(WorkspaceConflictError):
        store.Save(other, expected_revision=other_delta.previous_revision)

    combined, delta = Enrich(store.Open(), reference, second, provenance, store.root)
    store.Save(combined, expected_revision=delta.previous_revision)

    observations = [
        item for item in store.Open().observations if item.kind == "finding-intelligence"
    ]

    assert len(observations) == 2, (
        "A source revision silently overwrote an earlier attributable catalog interpretation"
    )


def test_NonScoreCatalogFreshnessUsesAcquisitionAndUnmatchedIdsStayExplicit(tmp_path):
    """An old weakness assertion stays distinct from its recent verified acquisition time."""

    store, state, reference, _, provenance = Context(tmp_path)
    raw = (b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="synthetic-1" '
           b'Date="2020-01-01"><Weaknesses><Weakness ID="89" Name="Synthetic weakness" '
           b'Status="Stable"/></Weaknesses></Weakness_Catalog>')
    evidence = LocalEvidenceStore(store.root / "evidence").Put(
        raw, "intelligence-source", "application/xml", EvidenceProvenance(
            state.workspace_id, "scope:local", "synthetic-intel", "1", None,
            "2026-10-12T12:00:00Z", "2026-10-12T12:00:00Z",
        ),
    )
    source = replace(Source(store).source, artifact_sha256=evidence.reference.sha256)
    snapshot = ParseIntelligenceSnapshot(
        raw, IntelligenceFeed.CWE, "synthetic-1", source, evidence.reference,
    )
    enriched, _ = Enrich(state, reference, snapshot, provenance, store.root, max_age_seconds=3600)
    observation = [item for item in enriched.observations if item.kind == "finding-intelligence"][0]
    assertion = observation.attributes["source_assertions"][0]

    assert assertion["age_seconds"] == 3600 and assertion["stale"] is False, (
        "Non-score feed freshness must use verified source acquisition and an inclusive budget"
    )
    assert assertion["association_state"] == "candidate" and assertion["review"] is None, (
        "Source membership must not turn into an authenticated or approved finding association"
    )
    assert observation.attributes["unmatched_identifiers"] == (CVE,), (
        "Explicit identifiers must not match another family or be inferred from catalog text"
    )


def test_MultiSourceFailuresAndRecordBoundsRejectPartialProposals(tmp_path, monkeypatch):
    """All selected source assertions obey the same verification and observation-size contract."""

    store, state, reference, _, provenance = Context(tmp_path)
    first, second = Source(store), Source(store, "0.5")
    ordered = sorted((first, second), key=lambda snapshot: snapshot.Reference())
    last_path = store.root / "evidence" / ordered[-1].evidence.locator
    original = last_path.read_bytes()
    last_path.unlink()

    with pytest.raises(EvidenceError):
        Enrich(state, reference, first, provenance, store.root, snapshots=tuple(ordered))

    last_path.write_bytes(original)
    monkeypatch.setattr("fuzzy1337.intelligence.MAX_SELECTED_RECORDS", 1)

    with pytest.raises(ValueError, match="observation record bound"):
        Enrich(state, reference, first, provenance, store.root,
               identifiers=(CVE,), snapshots=(first, second))

    assert store.Open() == state, "A rejected multi-source proposal changed persisted model state"
