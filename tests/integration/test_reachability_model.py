# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prove reachability owning-read, relocation and pure query boundaries through real producers."""

from __future__ import annotations

import builtins
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import CanonicalModelJson, LocalModelStore
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReadReachabilityClaims,
    SearchReachabilityPaths,
)
from tests.contract.reachability_fixture import Fixture
from tests.contract.test_reachability_contract import Projection


def Bytes(root):
    """Capture isolated test-owned workspace contents before a claimed read-only operation.

    Args:
        root: Explicit synthetic owning workspace root.

    Returns:
        Relative file identities and exact original bytes.
    """

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_RealOwningProofReadsNeverWriteModelEvidenceScopeOrWorkspace(tmp_path):
    """Source acquisition precedes verification, which leaves all authoritative bytes intact."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    before = Bytes(fixture.root)
    projection = Projection(fixture, records)
    result = SearchReachabilityPaths(projection, fixture.model,
        fixture.objects["source"].Reference(), fixture.objects["event"].Reference())
    assert len(result.paths) == 3 and result.complete, "Real acquired proof lost oracle routes"
    assert Bytes(fixture.root) == before, "Proof projection or query mutated owned storage"
    assert LocalModelStore(fixture.root).Open() == fixture.model, "Canonical model changed"
    assert b"synthetic-private-source-value" not in repr(result).encode(), "Raw support repr leaked"
    assessment_refs = {CanonicalModelJson(record.reference) for record in records}
    retained_refs = {CanonicalModelJson(reference) for observation in fixture.model.observations
                     for reference in observation.provenance.evidence_references}
    assert not assessment_refs & retained_refs, (
        "Assessment artifact became its own circular model support proof"
    )


def test_ExactStoredModelAndProofReopenAfterRelocation(tmp_path):
    """Portable immutable identities survive moving the entire owner workspace together."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    original = Projection(fixture, records)
    moved = tmp_path / "relocated"
    fixture.root.rename(moved)
    fixture.root = moved
    fixture.model = LocalModelStore(moved).Open()
    assert Projection(fixture, records) == original, "Workspace path entered proof identity"
    store = LocalEvidenceStore(moved / "evidence")
    assert all(store.Get(record.evidence_id) == record for record in records), "Reopen failed"


def test_ProjectionAndSearchRemainPureWithoutNetworkFilesystemOrOwnerCalls(tmp_path, monkeypatch):
    """I/O tripwires surround public pure interfaces after the explicit owning verification read."""

    fixture = Fixture.Create(tmp_path / "workspace")
    version = ReachabilityModelVersion(**fixture.Version())
    claims = ReadReachabilityClaims(fixture.model, fixture.Phase("confirmed"),
        workspace_root=fixture.root, expected_model_version=version,
        context_reference=fixture.graph["context_reference"],
        scope_reference=fixture.graph["scope_reference"], at=fixture.graph["query_at"])
    refs = tuple(item.Reference() for item in fixture.relations.values())

    def Refuse(*args, **kwargs):
        """Fail any unadvertised filesystem, owner, transport or socket activity.

        Args:
            args: Unused attempted positional I/O arguments.
            kwargs: Unused attempted keyword I/O arguments.

        Raises:
            AssertionError: A pure interface attempted I/O.
        """

        raise AssertionError("pure reachability interfaces attempted I/O")

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", Refuse)
        guard.setattr(Path, "open", Refuse)
        guard.setattr(Path, "stat", Refuse)
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(LocalModelStore, "Open", Refuse)
        guard.setattr(LocalEvidenceStore, "Get", Refuse)
        guard.setattr(LocalEvidenceStore, "Read", Refuse)
        graph = ProjectReachability(fixture.model, refs, claims, expected_model_version=version)
        result = SearchReachabilityPaths(graph, fixture.model,
            fixture.objects["source"].Reference(), fixture.objects["event"].Reference())
    assert len(result.paths) == 3 and result.complete, "Pure oracle query changed under I/O guards"


def test_CurrentMeansOneOwnerReadRatherThanContinuousFilesystemFreshness(tmp_path):
    """Pure queries pin their read; a later supplied model requires new owning verification."""

    fixture = Fixture.Create(tmp_path / "workspace")
    graph = Projection(fixture, fixture.Phase("confirmed"))
    original = fixture.model
    entity = replace(original.objects[0], attributes={**original.objects[0].attributes,
                                                     "later_interpretation": True})
    changed, _ = original.Apply(objects=(entity,))
    later = LocalModelStore(fixture.root).Save(changed, expected_revision=original.revision)
    result = SearchReachabilityPaths(graph, original, fixture.objects["source"].Reference(),
                                     fixture.objects["event"].Reference())
    assert result.complete and len(result.paths) == 3, "Immutable one-read query lost its basis"
    with pytest.raises(ValueError):
        SearchReachabilityPaths(graph, later, fixture.objects["source"].Reference(),
                                fixture.objects["event"].Reference())
    with pytest.raises(ValueError):
        Projection(fixture, ())
