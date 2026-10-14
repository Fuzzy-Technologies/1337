# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual caller-byte acquisition, immutable records, reparse, refusal and relocation proof."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337 import ioc_artifacts as ioc
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.ioc_artifacts import (
    AcquireIocArtifact,
    IocLimits,
    IocRequest,
    IocSource,
    LoadIocArtifact,
    ReplayIocArtifact,
)
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

RAW = (b"ipv4\t192.0.2.7\r\nipv6\t2001:0DB8::1\ndns\tEXAMPLE.Invalid.\nsha256\t" + b"A" * 64
       + b"\ndns\texample.invalid\t2099-01-01T12:00:00+05:30\t+05:30\n")


@pytest.fixture
def ioc_workspace(tmp_path):
    """Create a real owned workspace and canonical empty model for mutation detection."""

    root = tmp_path / "w"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned IOC evidence"), "owned")
    LocalModelStore(root).Create()

    return root


def Request(raw=RAW, limits=IocLimits()):
    """Select synthetic bytes with explicit source/version/license and finite budgets."""

    source = IocSource("owned.synthetic", "fixture-1", r"C:\owned\case.tsv", "Apache-2.0",
                       "owned:LICENSE", hashlib.sha256(raw).hexdigest())

    return IocRequest(raw, source, limits)


def Denied(*args, **kwargs):
    """Fail if acquisition or historical replay attempts process or network activity."""

    raise AssertionError("Offline IOC acquisition/replay attempted process or network I/O")


def Acquired(root):
    """Require actual successful immutable publication through production acquisition."""

    acquired = AcquireIocArtifact(root, Request(), scope_reference="scope:owned")

    assert acquired.state == "succeeded" and acquired.snapshot_record is not None and (
        acquired.snapshot is not None
    ), "Owned actual acquisition did not publish an accepted replayable candidate snapshot"

    return acquired


def test_IntegrationActualAcquisitionAndReadOnlyRelocationReparsePreserveOriginals(
    ioc_workspace, tmp_path, monkeypatch,
):
    """Compose actual immutable publication and detached replay after workspace movement."""

    root = ioc_workspace
    workspace_before = (root / "workspace.json").read_bytes()
    model_before = (root / "state/model/model.json").read_bytes()
    times = iter(("2026-10-14T10:00:00.000000+00:00", "2026-10-14T10:00:01.000000+00:00"))
    monkeypatch.setattr(ioc, "AcquisitionClock", lambda: next(times))
    monkeypatch.setattr(socket, "socket", Denied)
    monkeypatch.setattr(socket, "getaddrinfo", Denied)
    monkeypatch.setattr(subprocess, "Popen", Denied)
    acquired = Acquired(root)
    store = LocalEvidenceStore(root / "evidence")

    assert store.Read(acquired.raw.reference) == RAW, (
        "Original receiver bytes were rewritten during candidate normalization"
    )
    assert all(store.Get(record.evidence_id) == record for record in (
        acquired.raw, acquired.receipt, acquired.snapshot_record
    )), "Actual acquisition did not retain its three original immutable owning manifests"
    envelope = json.loads(store.Read(acquired.receipt.reference))

    assert envelope["raw_evidence_id"] == acquired.raw.evidence_id and envelope["source"] == (
        Request().source.ToDict()
    ), "Acquisition receipt lost the exact original raw manifest or declared source/license pins"
    assert envelope["limits"] == Request().limits.ToDict() and envelope["provenance"] == (
        acquired.raw.provenance.ToDict()
    ), "Acquisition receipt replaced its finite budgets or receiver-observed provenance"
    assert acquired.raw.provenance.started_at == "2026-10-14T10:00:00.000000+00:00" and (
        acquired.raw.provenance.finished_at == "2026-10-14T10:00:01.000000+00:00"
    ), "Source-declared future observation replaced actual receiver acquisition clock readings"
    moved = tmp_path / "m"
    shutil.move(str(root), moved)
    files = tuple(path for path in (moved / "evidence").rglob("*") if path.is_file())
    original_bytes = {path.relative_to(moved): path.read_bytes() for path in files}

    try:
        for path in files:
            path.chmod(0o444)

        replayed = LoadIocArtifact(moved, acquired.snapshot_record.evidence_id)
        typed_replay = ReplayIocArtifact(moved, acquired.snapshot_record)

    finally:
        for path in files:
            path.chmod(0o600)

    assert replayed == acquired.snapshot == typed_replay, (
        "Reopening or relocating owning evidence changed independently reparsed candidate facts"
    )
    assert [item.normalized_token for item in replayed.candidates] == [
        "192.0.2.7", "2001:db8::1", "example.invalid", "a" * 64, "example.invalid"
    ], "Actual production acquisition/reparse differs from the supplied candidate oracle"
    assert replayed.candidates[-1].observed_at == "2099-01-01T12:00:00+05:30" and (
        replayed.candidates[-1].source_locator == r"C:\owned\case.tsv"
    ), "Detached replay read an original Windows locator or erased declared timestamp/timezone"
    assert (moved / "workspace.json").read_bytes() == workspace_before and (
        moved / "state/model/model.json"
    ).read_bytes() == model_before, "IOC acquisition or replay mutated workspace/Core model state"
    assert all((moved / path).read_bytes() == content
               for path, content in original_bytes.items()), (
        "Read-only replay rewrote original raw, acquisition or derived immutable evidence"
    )


@pytest.mark.parametrize("raw,state", [
    (b"", "parse-rejected"), (b"ipv4\t192.0.2.", "parse-rejected"),
    (b"dns\texample.invalid\nmalformed", "parse-rejected"),
    (b"invalid", "parse-rejected"),
])
def test_IntegrationMalformedAndPartialCallerBytesRetainTruthfulRefusal(ioc_workspace, raw, state):
    """Malformed/partial supplied data is retained by refusal without a usable snapshot."""

    acquired = AcquireIocArtifact(ioc_workspace, Request(raw), scope_reference="scope:owned")
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    receipt = json.loads(store.Read(acquired.receipt.reference))

    assert acquired.state == state and acquired.snapshot is None and (
        acquired.snapshot_record is None
    ), "Malformed or partial source bytes received a usable success snapshot"
    assert store.Read(acquired.raw.reference) == raw and receipt["state"] == state and (
        receipt["raw_evidence_id"] == acquired.raw.evidence_id
    ), "Parser refusal lost original byte identity or published untruthful terminal receipt facts"
    assert receipt["transport"] == "caller-supplied-bytes" and receipt["authentication"] == (
        "not-assessed"
    ), "Local supplied bytes were described as fetched or publisher-authenticated evidence"

    with pytest.raises(ValueError):
        LoadIocArtifact(ioc_workspace, acquired.receipt.evidence_id)


def test_IntegrationDigestRefusalRetainsActualBytesAndBothDeclaredAndObservedPins(ioc_workspace):
    """Mismatching pins cause truthful terminal refusal and retain original received evidence."""

    request = Request()
    source = replace(request.source, expected_sha256="b" * 64)
    acquired = AcquireIocArtifact(ioc_workspace, replace(request, source=source),
                                  scope_reference="scope:owned")
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    receipt = json.loads(store.Read(acquired.receipt.reference))

    assert acquired.state == "digest-rejected" and acquired.snapshot_record is None, (
        "Wrong explicit source digest was accepted as normalized evidence"
    )
    assert store.Read(acquired.raw.reference) == RAW and receipt["source"]["expected_sha256"] == (
        "b" * 64
    ), "Digest rejection lost actual raw bytes or silently repaired the caller-declared pin"


@pytest.mark.parametrize("changes", [
    {"source_id": "foreign"}, {"source_version": "99"}, {"tool_version": "99"},
    {"workspace_id": "foreign"}, {"scope_reference": "scope:foreign"},
    {"started_at": "2026-10-14T00:00:00Z"}, {"finished_at": "2099-01-01T00:00:00Z"},
])
def test_IntegrationRehashedSnapshotManifestCannotReplaceOriginalAcquisition(
    ioc_workspace, changes,
):
    """Rehashed manifests cannot borrow original bytes with altered source/time/owner facts."""

    acquired = Acquired(ioc_workspace)
    original = acquired.snapshot_record
    provenance = replace(original.provenance, **changes)
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    forged = store.Put(store.Read(original.reference), "ioc-snapshot", "application/json",
                       provenance)

    with pytest.raises(ValueError):
        LoadIocArtifact(ioc_workspace, forged.evidence_id)


@pytest.mark.parametrize("field,value", [
    ("family", "foreign-family"), ("profile", "foreign-profile"), ("parser_id", "foreign-parser"),
    ("parser_version", "99"), ("schema_version", True), ("raw_evidence_id", "sha256:wrong"),
    ("acquisition_evidence_id", "sha256:wrong"),
])
def test_IntegrationRehashedMetadataCannotReplaceOriginalFamilyOrParser(
    ioc_workspace, field, value,
):
    """All declared schema/family/profile/parser/original-manifest pins are consumer-owned facts."""

    acquired = Acquired(ioc_workspace)
    original = acquired.snapshot_record
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    data = json.loads(store.Read(original.reference))
    data[field] = value
    forged = store.Put(ioc.JsonBytes(data), "ioc-snapshot", "application/json", original.provenance)

    with pytest.raises(ValueError):
        LoadIocArtifact(ioc_workspace, forged.evidence_id)


@pytest.mark.parametrize("mutation", [
    "candidate", "locator", "timezone", "source", "license", "budget", "raw-substitution",
    "receipt-provenance", "receipt-state", "receipt-transport", "receipt-authentication",
])
def test_IntegrationRehashedSnapshotAndReceiptSubstitutionsFailOriginalReparse(
    ioc_workspace, mutation,
):
    """Rehashing cannot legitimize altered normalization, source, limits or acquisition."""

    acquired = Acquired(ioc_workspace)
    original = acquired.snapshot_record
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    data = json.loads(store.Read(original.reference))

    if mutation == "candidate":
        data["candidates"][0]["normalized_token"] = "192.0.2.8"

    elif mutation == "locator":
        data["candidates"][0]["byte_offset"] = 6

    elif mutation == "timezone":
        data["candidates"][-1]["observation_timezone"] = "Z"

    elif mutation == "source":
        data["source"]["source_version"] = "forged"

    elif mutation == "license":
        data["source"]["license_name"] = "forged"

    elif mutation == "budget":
        data["limits"]["max_items"] = 1

    elif mutation == "raw-substitution":
        substituted = store.Put(RAW, "ioc-source", "text/tab-separated-values",
                                replace(acquired.raw.provenance, scope_reference="scope:forged"))
        data["raw_evidence_id"] = substituted.evidence_id

    else:
        envelope = json.loads(store.Read(acquired.receipt.reference))

        if mutation == "receipt-provenance":
            envelope["provenance"]["finished_at"] = "2099-01-01T00:00:00.000000+00:00"

        elif mutation == "receipt-state":
            envelope["state"] = "parse-rejected"

        elif mutation == "receipt-transport":
            envelope["transport"] = "network"

        else:
            envelope["authentication"] = "verified"

        substitute = store.Put(ioc.JsonBytes(envelope), "ioc-acquisition", "application/json",
                               acquired.receipt.provenance)
        data["acquisition_evidence_id"] = substitute.evidence_id

    forged = store.Put(ioc.JsonBytes(data), "ioc-snapshot", "application/json", original.provenance)

    with pytest.raises(ValueError):
        LoadIocArtifact(ioc_workspace, forged.evidence_id)


@pytest.mark.parametrize("role", ["raw", "receipt", "snapshot_record"])
def test_IntegrationReplayRequiresEveryOriginalOwningManifest(ioc_workspace, role):
    """Surviving blobs do not replace missing original raw, acquisition or derived manifests."""

    acquired = Acquired(ioc_workspace)
    selected = getattr(acquired, role)
    path = ioc_workspace / "evidence/records" / (selected.evidence_id[7:] + ".json")
    path.unlink()

    assert (ioc_workspace / "evidence" / selected.reference.locator).is_file(), (
        "Missing-manifest oracle removed its blob instead of original acquisition attribution"
    )

    with pytest.raises(EvidenceError):
        LoadIocArtifact(ioc_workspace, acquired.snapshot_record.evidence_id)


@pytest.mark.parametrize("failure", ["corrupt-raw", "foreign-owner", "frozen-record"])
def test_IntegrationReplayRejectsCorruptForeignAndFrozenRecordFacts(
    ioc_workspace, tmp_path, failure,
):
    """Replay requires owning bytes/workspace and exact original typed acquisition facts."""

    acquired = Acquired(ioc_workspace)
    root = ioc_workspace
    record = acquired.snapshot_record

    if failure == "corrupt-raw":
        (root / "evidence" / acquired.raw.reference.locator).write_bytes(b"x" * len(RAW))

    elif failure == "foreign-owner":
        root = tmp_path / "f"
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Foreign owner"), "foreign")
        shutil.copytree(ioc_workspace / "evidence", root / "evidence", dirs_exist_ok=True)

    else:
        object.__setattr__(record.provenance, "scope_reference", "scope:forged")

    with pytest.raises((ValueError, EvidenceError)):
        ReplayIocArtifact(root, record)


def test_IntegrationRepeatedAcquisitionNeverOverwritesHistoricalSnapshot(ioc_workspace):
    """Successful or refused later input preserves the earlier exact immutable snapshot chain."""

    first = Acquired(ioc_workspace)
    store = LocalEvidenceStore(ioc_workspace / "evidence")
    original = store.Read(first.snapshot_record.reference)
    later = AcquireIocArtifact(ioc_workspace, Request(b"malformed"), scope_reference="scope:owned")

    assert later.state == "parse-rejected" and store.Read(first.snapshot_record.reference) == (
        original
    ), "A later refused acquisition overwrote earlier normalized evidence"
    assert LoadIocArtifact(ioc_workspace, first.snapshot_record.evidence_id) == first.snapshot, (
        "Earlier trusted acquisition cannot replay after a later source revision"
    )


def test_IntegrationStorageFailureNeverReturnsSuccess(ioc_workspace, monkeypatch):
    """Evidence-owner publication errors propagate honestly even if an orphan raw record remains."""

    original = ioc.IocEvidenceStore.Put

    def Put(store, data, role, media_type, provenance):
        """Refuse only receipt publication after the actual raw evidence owner succeeds."""

        if role == "ioc-acquisition":
            raise EvidenceError("Owned synthetic storage refusal")

        return original(store, data, role, media_type, provenance)

    monkeypatch.setattr(ioc.IocEvidenceStore, "Put", Put)

    with pytest.raises(EvidenceError, match="storage refusal"):
        AcquireIocArtifact(ioc_workspace, Request(), scope_reference="scope:owned")

    manifests = tuple((ioc_workspace / "evidence/records").glob("*.json"))

    assert len(manifests) == 1, "Storage failure hid publication state or falsely created a receipt"


def test_IntegrationBackwardAcquisitionClockFailsBeforeEvidencePublication(
    ioc_workspace, monkeypatch,
):
    """Acquisition clock disagreement cannot publish success or fabricated collection times."""

    times = iter(("2026-10-14T10:00:01.000000+00:00", "2026-10-14T10:00:00.000000+00:00"))
    monkeypatch.setattr(ioc, "AcquisitionClock", lambda: next(times))

    with pytest.raises(ValueError, match="finished_at"):
        AcquireIocArtifact(ioc_workspace, Request(), scope_reference="scope:owned")

    assert not tuple((ioc_workspace / "evidence").iterdir()), (
        "Invalid actual acquisition clock facts published orphaned or successful evidence"
    )
