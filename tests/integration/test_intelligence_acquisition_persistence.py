# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Production import/sync API, immutable storage replay, and actual verified finding enrichment."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace

import pytest

from fuzzy1337 import intelligence_acquisition as acquisition
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingSeverity
from fuzzy1337.intel_references import SourceOrigin
from fuzzy1337.intelligence import ApplyVerifiedEnrichment, IntelligenceFeed
from fuzzy1337.intelligence_acquisition import (
    AcquireIntelligenceSnapshot,
    AcquisitionState,
    CisaKevSource,
    LoadAcquiredSnapshot,
    SnapshotRequest,
    SnapshotSource,
    SyncIntelligenceSnapshots,
    SyncState,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

CVE = "CVE-1900-9999"
RAW = (b"#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n"
       b"cve,epss,percentile\nCVE-1900-9999,0.2,0.8\n")


def Source():
    """Select owned synthetic EPSS-shaped bytes with explicit fixture-only licensing."""

    return SnapshotSource(
        IntelligenceFeed.EPSS, "synthetic-1", SourceOrigin.SYNTHETIC, "1337 synthetic fixture",
        "https://example.invalid/scores.csv", "Apache-2.0 (synthetic fixture only)",
        "https://example.invalid/LICENSE",
    )


def Context(tmp_path, name="owned"):
    """Persist an owned real finding and original detector artifact before source acquisition."""

    root = tmp_path / name
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Acquisition integration"), name)
    model = LocalModelStore(root)
    state = model.Create()
    provenance = ModelProvenance("synthetic", "run:detector", "2026-10-12T10:00:00Z",
                                 "scope:owned", "target:owned")
    subject = SecurityObject(ObjectIdentity(name, ObjectKind.HOST, "127.0.0.1"), {}, (provenance,))
    state, delta = state.Apply(objects=(subject,))
    model.Save(state, expected_revision=delta.previous_revision)
    detector = LocalEvidenceStore(root / "evidence").Put(
        b"Owned synthetic detector bytes", "stdout", "text/plain",
        EvidenceProvenance(name, "scope:owned", "synthetic-detector", "1", None,
                           "2026-10-12T10:00:00Z", "2026-10-12T10:00:01Z"),
    )
    finding = Finding(
        subject.Reference(), "synthetic.check", "tcp/443", "Owned synthetic finding",
        (replace(provenance, evidence_references=(detector.reference,)),), FindingSeverity.LOW, 0.2,
    )
    state, delta = ApplyVerifiedFindings(state, (finding,), root)
    model.Save(state, expected_revision=delta.previous_revision)

    return model, state.Objects(ObjectKind.FINDING)[0].Reference()


def FeedBody(feed):
    """Return tiny owned documents in each supported publisher-shaped format."""

    if feed is IntelligenceFeed.CVE:
        return json.dumps({
            "dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"cveId": CVE, "state": "PUBLISHED",
                            "dateUpdated": "2026-10-12T10:00:00Z"},
            "containers": {"cna": {"providerMetadata": {"orgId": "synthetic-cna"}}},
        }).encode()

    if feed is IntelligenceFeed.CWE:
        return (b'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="synthetic-1" '
                b'Date="2026-10-12"><Weaknesses><Weakness ID="89" Name="Synthetic weakness" '
                b'Status="Stable"/></Weaknesses></Weakness_Catalog>')

    if feed is IntelligenceFeed.KEV:
        return json.dumps({
            "catalogVersion": "synthetic-1", "dateReleased": "2026-10-12T10:00:00Z", "count": 1,
            "vulnerabilities": [{"cveID": CVE, "dateAdded": "2026-10-12",
                                 "dueDate": "2026-10-31", "vendorProject": "Synthetic",
                                 "product": "Owned fixture", "vulnerabilityName": "Synthetic",
                                 "requiredAction": "Review owned evidence",
                                 "knownRansomwareCampaignUse": "Unknown"}],
        }).encode()

    return RAW


@pytest.mark.parametrize("feed,media_type", [
    (IntelligenceFeed.CVE, "application/json"), (IntelligenceFeed.CWE, "application/xml"),
    (IntelligenceFeed.KEV, "application/json"), (IntelligenceFeed.EPSS, "text/csv"),
])
def test_AllSupportedLocalFormatsUseTheActualImportStorageAndReplayBoundary(
    tmp_path, feed, media_type,
):
    """Every claimed offline acquisition format publishes and replays its original exact source."""

    model, _ = Context(tmp_path)
    raw = FeedBody(feed)
    source = replace(Source(), feed=feed,
                     source_url=f"https://example.invalid/{feed.value}.data")
    outcome = AcquireIntelligenceSnapshot(
        model.root, SnapshotRequest(source, raw), scope_reference="scope:owned",
    )

    assert outcome.state is AcquisitionState.SUCCEEDED and outcome.snapshot_record is not None, (
        "A claimed local source format did not pass its actual production acquisition path"
    )
    replayed = LoadAcquiredSnapshot(model.root, outcome.snapshot_record.evidence_id)

    assert replayed.feed is feed and replayed.source.origin is SourceOrigin.SYNTHETIC, (
        "Replay changed source family or attributed a synthetic fixture to an official corpus"
    )
    assert replayed.evidence.media_type == media_type and LocalEvidenceStore(
        model.root / "evidence",
    ).Read(replayed.evidence) == raw, "Format dispatch changed original source bytes or media type"


def test_ProductionImportReplayAndVerifiedConsumerPreserveOriginalSourceAndFinding(
    tmp_path, monkeypatch,
):
    """The implemented API feeds the actual canonical consumer without changing owner triage."""

    model, finding_reference = Context(tmp_path)
    original_model = (model.root / "state/model/model.json").read_bytes()
    times = iter(("2026-10-13T10:00:00.000000+00:00", "2026-10-13T10:00:01.000000+00:00"))
    monkeypatch.setattr(acquisition, "AcquisitionTime", lambda: next(times))
    outcome = AcquireIntelligenceSnapshot(
        model.root, SnapshotRequest(Source(), RAW), scope_reference="scope:owned",
    )

    assert outcome.state is AcquisitionState.SUCCEEDED and outcome.snapshot_record is not None, (
        "Actual production import did not publish a replayable parsed source"
    )
    assert (model.root / "state/model/model.json").read_bytes() == original_model, (
        "Acquisition silently mutated the canonical finding/model state"
    )
    moved = tmp_path / "moved"
    shutil.move(str(model.root), moved)
    replayed = LoadAcquiredSnapshot(moved, outcome.snapshot_record.evidence_id)
    model = LocalModelStore(moved)
    state = model.Open()
    provenance = ModelProvenance("intel", "run:enrichment", "2026-10-13T11:00:00Z",
                                 "scope:owned", "target:owned")
    proposal, delta = ApplyVerifiedEnrichment(
        state, finding_reference, (CVE,), (replayed,), provenance, moved,
        as_of="2026-10-13T11:00:00Z", max_age_seconds=86400,
    )
    model.Save(proposal, expected_revision=delta.previous_revision)
    assertion = next(item for item in proposal.observations if item.kind == "finding-intelligence")

    assert replayed == outcome.snapshot and replayed.source.acquired_at == outcome.finished_at, (
        "Portable replay changed the receiver-observed acquisition or interpretation"
    )
    assert proposal.Objects(ObjectKind.FINDING) == state.Objects(ObjectKind.FINDING), (
        "Acquired reference metadata changed operator finding triage"
    )
    assert assertion.attributes["source_assertions"][0]["association_state"] == "candidate", (
        "Acquisition or byte integrity fabricated a reviewed source applicability claim"
    )
    assert LocalEvidenceStore(moved / "evidence").Read(replayed.evidence) == RAW, (
        "Stored source bytes changed during import, relocation, or consumer interpretation"
    )


@pytest.mark.parametrize("raw", [RAW + b"CVE-1900-9998,0.3,0.9\n", b"invalid CSV"])
def test_FreshAcquisitionsNeverOverwriteEarlierSnapshotOrEvidence(tmp_path, raw):
    """New revisions and refused bodies retain the earlier immutable accepted snapshot."""

    model, _ = Context(tmp_path)
    accepted = AcquireIntelligenceSnapshot(
        model.root, SnapshotRequest(Source(), RAW), scope_reference="scope:owned",
    )
    store = LocalEvidenceStore(model.root / "evidence")
    first = accepted.snapshot_record

    assert first is not None, "Baseline import did not publish the prior snapshot"
    before = store.Read(first.reference)
    following = AcquireIntelligenceSnapshot(
        model.root, SnapshotRequest(Source(), raw), scope_reference="scope:owned",
    )

    assert store.Read(first.reference) == before, "Later acquisition overwrote the prior revision"
    assert LoadAcquiredSnapshot(model.root, first.evidence_id) == accepted.snapshot, (
        "Later import replaced a prior source interpretation"
    )
    assert following.raw is not None and store.Read(following.raw.reference) == raw, (
        "New or refused acquisition lost its original attributable source bytes"
    )


@pytest.mark.parametrize("failure", ["missing-raw", "corrupt-raw", "foreign-owner", "partial"])
def test_ReplayRejectsBrokenForeignOrIncompleteArtifactsBeforeReturningASnapshot(tmp_path, failure):
    """Stored snapshot loading cannot silently promote partial or unverifiable source evidence."""

    model, _ = Context(tmp_path)
    request = SnapshotRequest(Source(), RAW, max_bytes=10) if failure == "partial" else (
        SnapshotRequest(Source(), RAW)
    )
    outcome = AcquireIntelligenceSnapshot(model.root, request, scope_reference="scope:owned")
    root = model.root
    record = outcome.raw if failure == "partial" else outcome.snapshot_record

    assert record is not None, "Controlled acquisition did not publish its expected test artifact"

    if failure == "foreign-owner":
        other, _ = Context(tmp_path, "foreign")
        shutil.copytree(model.root / "evidence", other.root / "evidence", dirs_exist_ok=True)
        root = other.root

    elif failure in ("missing-raw", "corrupt-raw"):
        path = root / "evidence" / outcome.raw.reference.locator

        if failure == "missing-raw":
            path.unlink()

        else:
            path.write_bytes(b"x" * len(RAW))

    with pytest.raises((EvidenceError, ValueError)):
        LoadAcquiredSnapshot(root, record.evidence_id)


@pytest.mark.parametrize("failure", ["partial-role", "forged-score"])
def test_ReplayRejectsRehashedNormalizedOrPartialSourceClaims(tmp_path, failure):
    """Public hashes cannot legitimize invented interpretations or incomplete source roles."""

    model, _ = Context(tmp_path)
    outcome = AcquireIntelligenceSnapshot(
        model.root, SnapshotRequest(Source(), RAW), scope_reference="scope:owned",
    )
    snapshot = outcome.snapshot

    assert snapshot is not None and outcome.snapshot_record is not None, (
        "Owned baseline import did not produce a complete source interpretation"
    )

    if failure == "partial-role":
        forged = replace(snapshot, evidence=replace(snapshot.evidence, role="intelligence-partial"))

    else:
        forged = replace(snapshot, records=(replace(
            snapshot.records[0], data={**snapshot.records[0].data, "probability": 0.99},
        ),))

    artifact = LocalEvidenceStore(model.root / "evidence").Put(
        forged.Serialize(), "intelligence-snapshot", "application/json",
        outcome.snapshot_record.provenance,
    )

    with pytest.raises(ValueError):
        LoadAcquiredSnapshot(model.root, artifact.evidence_id)


@pytest.mark.parametrize("state,body,status", [
    (AcquisitionState.TIMED_OUT, b"partial original bytes", 200),
    (AcquisitionState.REDIRECT_REJECTED, b"", 302),
    (AcquisitionState.TRANSPORT_FAILED, b"", None),
])
def test_ActualSyncApiRetainsOwnedTransportFailuresAlongsideSuccessfulImports(
    tmp_path, monkeypatch, state, body, status,
):
    """The public sync path reports partial success and retains captured incomplete evidence."""

    model, _ = Context(tmp_path)
    calls = []

    def Fetch(request):
        """Supply one deterministic owned remote transport result at the actual API boundary."""

        calls.append(request)

        return body, state, status

    monkeypatch.setattr(acquisition, "FetchRemoteBytes", Fetch)
    before = (model.root / "state/model/model.json").read_bytes()
    result = SyncIntelligenceSnapshots(
        model.root, (SnapshotRequest(Source(), RAW), SnapshotRequest(CisaKevSource("a" * 40, "x"))),
        scope_reference="scope:owned",
    )
    remote = result.outcomes[1]

    assert result.state is SyncState.PARTIAL and remote.state is state and len(calls) == 1, (
        "Actual sync hid a transport failure, retried implicitly, or reordered requested work"
    )
    assert not remote.body_complete and remote.snapshot is None and remote.receipt is not None, (
        "A refused or incomplete response received usable parsed snapshot semantics"
    )
    store = LocalEvidenceStore(model.root / "evidence")
    receipt = json.loads(store.Read(remote.receipt.reference))

    assert receipt["state"] == state.value and receipt["http_status"] == status, (
        "Persisted sync receipt lost its observed transport outcome"
    )
    assert (model.root / "state/model/model.json").read_bytes() == before, (
        "A failed sync partially modified canonical model state"
    )

    if body:
        assert remote.raw is not None and store.Read(remote.raw.reference) == body, (
            "Incomplete transport bytes were discarded, normalized, or replaced"
        )
