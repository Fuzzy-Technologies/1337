# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual owned native wire crosses custody, model CAS and relocated replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import ExecutionAuthorization, InvocationDigest
from fuzzy1337.findings import Finding, FindingStatus
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.native_image_admission import (
    ApplyVerifiedNativeTrivyImages,
    VerifyNativeTrivyImageReplay,
)
from fuzzy1337.native_image_capture import (
    CaptureNativeTrivyOperation,
    NativeTrivyOperation,
    NativeTrivySelection,
)
from fuzzy1337.quickscan import VerifyWorkspaceEvidence
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(os.name == "nt", reason="owned fixture uses a POSIX shebang")]


def CapturePair(root: Path, archive: bytes):
    """Run actual owned subprocesses without claiming genuine Trivy accuracy."""

    workspace = LocalWorkspaceStore(root)
    workspace.Create(WorkspaceConfiguration("Owned native wire integration"), "native-wire")
    model = LocalModelStore(root).Create()
    fixture = Path(__file__).parents[1] / "fixtures/trivy/native_capture_wire.py"
    executable = root / "owned-native-wire"
    executable.write_text(f"#!{sys.executable}\n" + fixture.read_text(), encoding="utf-8")
    executable.chmod(0o700)
    (root / "owned.tar").write_bytes(archive)
    database = root / "trivy-cache" / "db"
    database.mkdir(parents=True)
    (database / "trivy.db").write_bytes(b"owned simulated database bytes")
    (database / "metadata.json").write_text(json.dumps({"Version": 2,
        "UpdatedAt": "2026-06-22T14:30:14Z"}))
    store = LocalEvidenceStore(root / "evidence")
    owner = "owner:owned-native-wire"
    selection = NativeTrivySelection(root, executable, "owned.tar", "trivy-cache",
        ArtifactReadConsent(owner, "read:owned-wire-integration"))
    captures = []

    for operation in (NativeTrivyOperation.VERSION, NativeTrivyOperation.SCAN):
        adapter = selection.Adapter(store, None if not captures else captures[0].observed_version)
        request = AdapterRequest("image.archive-vulnerabilities", "target:owned-native-wire",
            ImpactLevel.SAFE, {"archive": "owned.tar", "timeout_seconds": 3})
        invocation = adapter.PrepareVersionInvocation(request) if not captures else (
            adapter.PrepareInvocation(request))
        authority = ExecutionAuthorization("authorization:owned-wire-" + operation.value,
            "scope:owned-wire", "policy:owned-wire", InvocationDigest(invocation))
        capture = asyncio.run(CaptureNativeTrivyOperation(operation, selection, invocation,
            authority, store, model.workspace_id, owner,
            version_prerequisite=None if not captures else captures[0]))
        captures.append(capture)

    return model, store, captures[0], captures[1]


@pytest.mark.parametrize("archive,expected_finding", [
    (b"owned vulnerable fixture", True), (b"owned fixed fixture", False),
])
def test_ExecutedOwnedPairAdmitsPersistsReopensAndReplaysAfterMove(
    tmp_path, archive, expected_finding
):
    """Actual acquisitions compose into canonical saved assets/findings and portable replay."""

    root = tmp_path / "workspace"
    state, store, version, scan = CapturePair(root, archive)
    assert scan.outcome.execution.state is ExecutionState.SUCCEEDED and scan.refusal is None, (
        "Actual owned subprocess must complete before successful admission"
    )
    assert version.request.invocation.provider_version is None and (
        version.observed_version == "0.75.0"
    ), "Original VERSION invocation must remain unchanged after observed version parsing"
    updated, delta = ApplyVerifiedNativeTrivyImages(state, version, scan, root)
    saved = LocalModelStore(root).Save(updated, expected_revision=state.revision)
    finding_objects = tuple(item for item in saved.objects
                            if item.identity.kind is ObjectKind.FINDING)
    assert bool(finding_objects) is expected_finding, "Owned oracle must match finding state"
    assert saved == LocalModelStore(root).Open() and delta.revision == saved.revision, (
        "Canonical CAS persistence and independent reopening must agree"
    )
    records = (*version.records, *scan.records)
    workspace_store = LocalWorkspaceStore(root)
    workspace = workspace_store.Open()
    workspace_store.Save(replace(workspace,
        object_references=tuple(sorted(item.Reference() for item in saved.objects)),
        evidence_references=tuple(record.reference for record in records),
        evidence_record_references=tuple(record.evidence_id for record in records)))
    VerifyWorkspaceEvidence(workspace_store.Open(), store)

    if finding_objects:
        finding = Finding.FromObject(finding_objects[0])
        triaged = replace(finding, status=FindingStatus.CONFIRMED,
                          status_reason="Owned integration review")
        current, _ = saved.Apply(objects=(triaged.ToObject(saved.workspace_id),))
        saved = LocalModelStore(root).Save(current, expected_revision=saved.revision)
        repeated, repeated_delta = ApplyVerifiedNativeTrivyImages(saved, version, scan, root)
        assert repeated == saved and repeated_delta.revision == saved.revision, (
            "Native admission must preserve separately confirmed canonical finding triage"
        )

    original_replay = VerifyNativeTrivyImageReplay(records, root)

    for record in records:
        assert store.Get(record.evidence_id) == record, "Original manifest must reopen unchanged"
        assert hashlib.sha256(store.Read(record.reference)).hexdigest() == (
            record.reference.sha256
        ), (
            "Admission and saving must preserve the independently retained original stream bytes"
        )

    moved = tmp_path / "moved-workspace"
    shutil.copytree(root, moved)
    shutil.rmtree(root)
    assert LocalModelStore(moved).Open() == saved, "Relocation must retain saved identities"
    assert VerifyNativeTrivyImageReplay(records, moved) == original_replay, (
        "Portable replay must retain original VERSION/SCAN provenance without historical material"
    )
    VerifyWorkspaceEvidence(LocalWorkspaceStore(moved).Open(),
                            LocalEvidenceStore(moved / "evidence"))


def test_ActualFailedPartialScanRetainsRawAndRefusesModelAdmission(tmp_path):
    """Original nonzero partial output remains attributable and replayable without saved success."""

    root = tmp_path / "workspace"
    state, store, version, scan = CapturePair(root, b"owned failure fixture")
    assert scan.outcome.execution.state is ExecutionState.FAILED and (
        scan.outcome.execution.exit_code == 7
    ), "Actual owned failed subprocess must retain its original nonzero terminal state"
    assert scan.outcome.stdout == b'{"partial":' and scan.refusal == "execution-not-successful", (
        "Incomplete raw JSON must remain original failure rather than successful empty inventory"
    )
    replay = VerifyNativeTrivyImageReplay((*version.records, *scan.records), root)
    assert replay.scan_execution == scan.outcome.execution and (
        replay.scan_refusal == "execution-not-successful"
    ), "Replay must retain failed SCAN state without interpreting partial stdout"

    with pytest.raises(ValueError, match="successful"):
        ApplyVerifiedNativeTrivyImages(state, version, scan, root)

    assert LocalModelStore(root).Open() == state, "Failure must preserve saved model"

    for record in (*version.records, *scan.records):
        assert store.Get(record.evidence_id) == record, "Failure must retain immutable custody"

    assert not tuple(root.glob("native-image-*")), "Actual subprocess scratch must be cleaned"
