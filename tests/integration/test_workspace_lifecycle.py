# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real portable workspace lifecycle through independently decoded persisted documents."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration, WorkspaceLens


def test_WorkspaceLifecycleSurvivesReopenDerivedStateRemovalAndRelocation(tmp_path: Path):
    """Persist actual context, preserve raw artifacts, and reopen a moved portable workspace."""

    store = LocalWorkspaceStore(tmp_path / "original")
    configuration = WorkspaceConfiguration(
        "Synthetic investigation", WorkspaceLens.DFIR, "view:object-list", "report:summary"
    )
    initial = store.Create(configuration, "synthetic-investigation")
    raw_payload = b"Synthetic immutable raw evidence\n"
    digest = hashlib.sha256(raw_payload).hexdigest()
    locator = "blobs/sha256/" + digest
    artifact = store.root / "evidence" / locator
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(raw_payload)
    domain_marker = store.root / "state" / "domain-owner-fixture"
    domain_marker.write_bytes(b"independent owner fixture")
    reference = EvidenceReference("stdout", locator, digest, "text/plain", len(raw_payload))
    saved = store.Save(replace(
        initial,
        scope_references=("scope:synthetic-authorized-fixture",),
        object_references=("object:synthetic-service",),
        job_references=("job:fixture-record",),
        evidence_references=(reference,),
        evidence_record_references=("sha256:" + "a" * 64, "sha256:" + "b" * 64),
    ))
    document = json.loads((store.root / "workspace.json").read_text(encoding="utf-8"))

    assert document == {
        "schema_version": 1,
        "workspace_id": "synthetic-investigation",
        "revision": 1,
        "configuration": {
            "display_name": "Synthetic investigation", "selected_lens": "dfir",
            "view_reference": "view:object-list", "report_context_reference": "report:summary",
        },
        "scope_references": ["scope:synthetic-authorized-fixture"],
        "object_references": ["object:synthetic-service"],
        "job_references": ["job:fixture-record"],
        "evidence_record_references": ["sha256:" + "a" * 64, "sha256:" + "b" * 64],
        "evidence_references": [{
            "role": "stdout", "locator": locator, "sha256": digest,
            "media_type": "text/plain", "size_bytes": len(raw_payload),
        }],
    }, "The independently decoded document violates the initial workspace schema"

    for partition in ("cache", "indexes"):
        (store.root / partition).rmdir()

    assert LocalWorkspaceStore(store.root).Open() == saved, "Derived state was required to reopen"
    relocated_root = tmp_path / "relocated"
    store.root.rename(relocated_root)
    reopened = LocalWorkspaceStore(relocated_root).Open()

    assert reopened == saved, "Relocating the portable workspace lost authoritative context"
    assert (relocated_root / "evidence" / locator).read_bytes() == raw_payload, (
        "Workspace lifecycle mutated independently owned immutable evidence"
    )
    assert (relocated_root / "state" / "domain-owner-fixture").read_bytes() == (
        b"independent owner fixture"
    ), "Metadata lifecycle modified independently owned domain state"
    assert str(tmp_path) not in json.dumps(document), "Metadata contains machine-local paths"


def test_WorkspaceCanOpenWithoutUninitializedOwnedPartitions(tmp_path: Path):
    """Domain and evidence owners can initialize separately without blocking metadata reads."""

    store = LocalWorkspaceStore(tmp_path / "workspace")
    state = store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    (store.root / "evidence").rmdir()
    (store.root / "state").rmdir()

    assert store.Open() == state, "Absent evidence blocked authoritative state"
    assert store.Save(state).revision == 1, "An absent evidence partition blocked metadata updates"


def test_LocalWorkspaceUsesPrivateCreationPermissionsOnPosix(tmp_path: Path):
    """Keep created workspace metadata private without changing operator umask."""

    store = LocalWorkspaceStore(tmp_path / "workspace")
    store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")

    if os.name == "posix":
        assert stat.S_IMODE(store.root.stat().st_mode) & 0o077 == 0, (
            "Workspace creation exposed the directory to other users"
        )
        assert stat.S_IMODE((store.root / "workspace.json").stat().st_mode) & 0o077 == 0, (
            "Atomic metadata creation exposed the document to other users"
        )
