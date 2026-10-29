# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual captured-source verification, scope and existing-model persistence boundaries."""

from __future__ import annotations

import builtins
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.captured_web import ProjectCapturedWebFrontier, ReadCapturedWebFrontier
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind
from fuzzy1337.requests import (
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract.captured_web_fixture import Fixture, WorkspaceBytes


def Read(fixture):
    """Read actual independent synthetic evidence through the public owning consumer.

    Args:
        fixture: Explicit synthetic workspace with already acquired raw bytes.

    Returns:
        Full original-source frontier with exact current scope membership.
    """

    return ReadCapturedWebFrontier(fixture.root, fixture.source, fixture.capture,
                                  fixture.scope.scope_id, at=fixture.at)


def test_RealModelSaveReopenPreservesExistingRequestsAttributesAndSourceFacts(tmp_path):
    """Structural discovery uses actual owner interfaces and never drops existing templates."""

    fixture = Fixture.Create(tmp_path / "workspace")
    model_store = LocalModelStore(fixture.root)
    initial = model_store.Create()
    frontier = Read(fixture)
    alpha = frontier.entries[0].template
    prior = RequestTemplate(alpha.endpoint, (
        InjectionPoint(InjectionLocation.QUERY, "existing_field", ValueBinding("existing-input")),
    ))
    provenance = ModelProvenance("synthetic-existing", "run:earlier",
        fixture.capture.provenance.started_at, fixture.scope.Reference(),
        frontier.entries[0].target.Reference(), "old-parser-v2")
    old_object = ProjectRequests((prior,), provenance=(provenance,))
    old_object = replace(old_object, attributes={**old_object.attributes, "unrelated": "preserved"})
    seeded, _ = initial.Apply(objects=(old_object,))
    current = model_store.Save(seeded, expected_revision=initial.revision)
    projection = ProjectCapturedWebFrontier(frontier, existing=(old_object,))
    updated, delta = current.Apply(objects=projection.object_patches,
                                   observations=projection.observations)
    saved = model_store.Save(updated, expected_revision=current.revision)
    reopened = LocalModelStore(fixture.root).Open()
    assert reopened == saved, "Structural candidates did not survive actual model persistence"
    assert delta.revision > current.revision, "Real source interpretation produced no model delta"
    assert len(reopened.Objects(ObjectKind.ENDPOINT)) == 5, "Logical candidate identities changed"
    alpha_object = next(item for item in reopened.objects
                        if item.identity == alpha.endpoint.Identity())
    assert set(RequestsFromObject(alpha_object)) == {prior, alpha}, (
        "Complete request composition dropped the existing template"
    )
    assert alpha_object.attributes["unrelated"] == "preserved", "Unrelated data was overwritten"
    links = tuple(item for item in reopened.observations if item.kind == "web.lexical-link")
    assert len(links) == 5 and not reopened.relations, "Lexical input invented connectivity"
    assert all(item.provenance.target_reference == frontier.source_target.Reference()
               for item in links), "The candidate replaced the declared source acquisition target"
    assert all(item.provenance.provider_version == "fixture-collector-v3" for item in links), (
        "Original collector version was replaced with the format or parser version"
    )
    assert all(item.attributes["source_version"] == "synthetic-html-v7" for item in links), (
        "Exact original source format was not retained"
    )
    assert all(item.attributes["capture_manifest_id"] == fixture.capture.evidence_id
               for item in links), "Model attribution lost the exact immutable source manifest"
    assert all(item.provenance.execution is None for item in links), "Execution was invented"
    assert all(item.provenance.evidence_references == (fixture.capture.reference,)
               for item in links), (
        "Link interpretation lost the actual verified body reference"
    )
    assert all("status" not in item.attributes and "reachable" not in item.attributes
               for item in reopened.objects), "Lexical templates acquired observed network facts"
    repeated = ProjectCapturedWebFrontier(frontier, existing=reopened.Objects(ObjectKind.ENDPOINT))
    replayed, replay_delta = reopened.Apply(objects=repeated.object_patches,
                                            observations=repeated.observations)
    assert replayed == reopened and replay_delta.revision == reopened.revision, (
        "Exact source/projection replay changed attribution history"
    )


def test_SameBodyDifferentCollectionManifestRetainsDistinctOriginHistory(tmp_path):
    """Raw-content deduplication does not collapse separate collector/version attribution."""

    fixture = Fixture.Create(tmp_path / "workspace")
    model_store = LocalModelStore(fixture.root)
    initial = model_store.Create()
    first = Read(fixture)
    first_projection = ProjectCapturedWebFrontier(first)
    state, _ = initial.Apply(objects=first_projection.object_patches,
                            observations=first_projection.observations)
    evidence = LocalEvidenceStore(fixture.root / "evidence")
    second_record = evidence.Put(evidence.Read(fixture.capture.reference),
        "response-body", "text/html",
        replace(fixture.capture.provenance, source_version="synthetic-html-v8",
                tool_version="fixture-collector-v4"))
    second = Read(replace(fixture, capture=second_record))
    second_projection = ProjectCapturedWebFrontier(second,
                                                   existing=state.Objects(ObjectKind.ENDPOINT))
    combined, _ = state.Apply(objects=second_projection.object_patches,
                              observations=second_projection.observations)
    assert first.capture.reference == second.capture.reference, "Identical bytes lost blob identity"
    assert first.capture.evidence_id != second.capture.evidence_id, "Collector identity changed"
    assert len(combined.Objects(ObjectKind.ENDPOINT)) == 5, "Repeated source duplicated endpoints"
    links = tuple(item for item in combined.observations if item.kind == "web.lexical-link")
    assert len(links) == 10, "Different source manifests lost observation history"
    assert {item.attributes["source_version"] for item in links} == {
        "synthetic-html-v7", "synthetic-html-v8"
    }, "Separate source-format attribution was collapsed"


def test_VerificationHasNoTransportLaunchOrOwnerWrites(tmp_path, monkeypatch):
    """Capture verification reads the named owners but never fetches, executes or mutates them."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before = WorkspaceBytes(fixture.root)

    def Refuse(*args, **kwargs):
        """Fail any unadvertised traffic, subprocess or authoritative storage mutation."""

        raise AssertionError("offline captured-source verification attempted a side effect")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        guard.setattr(LocalWorkspaceStore, "Save", Refuse)
        guard.setattr(LocalScopeStore, "Save", Refuse)
        guard.setattr(LocalModelStore, "Save", Refuse)
        guard.setattr(LocalEvidenceStore, "Put", Refuse)
        frontier = Read(fixture)

    assert len(frontier.entries) == 5, "Source interpretation changed under side-effect guards"
    assert WorkspaceBytes(fixture.root) == before, "Verification changed authoritative bytes"


def test_ProjectionIsPureWithAllFilesystemAndTransportBoundariesDisabled(tmp_path, monkeypatch):
    """Prepared records project solely through existing in-memory request/model interfaces."""

    fixture = Fixture.Create(tmp_path / "workspace")
    frontier = Read(fixture)

    def Refuse(*args, **kwargs):
        """Tripwire every filesystem, transport, evidence-owner and scope-owner operation."""

        raise AssertionError("pure captured-source projection attempted I/O")

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", Refuse)
        guard.setattr(Path, "open", Refuse)
        guard.setattr(Path, "stat", Refuse)
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        guard.setattr(LocalEvidenceStore, "Get", Refuse)
        guard.setattr(LocalEvidenceStore, "Read", Refuse)
        guard.setattr(LocalScopeStore, "Open", Refuse)
        guard.setattr(LocalModelStore, "Open", Refuse)
        projection = ProjectCapturedWebFrontier(frontier)

    assert len(projection.object_patches) == len(projection.observations) == 5, (
        "Pure owner projection changed when I/O was unavailable"
    )


def test_PreparedScopeDigestIsHistoricalAndNewPreparationUsesChangedCurrentRules(tmp_path):
    """One-read membership is historical while a new owner read sees a later exclusion."""

    fixture = Fixture.Create(tmp_path / "workspace")
    prepared = Read(fixture)
    alpha_target = prepared.entries[0].target
    changed = replace(fixture.scope, exclusions=(alpha_target,))
    current = LocalScopeStore(fixture.root).Save(changed)
    later = Read(fixture)
    assert later.scope_revision == current.revision and (
        later.scope_sha256 != prepared.scope_sha256
    ), (
        "Full scope identity became a permanent revision-only grant"
    )
    assert alpha_target not in tuple(entry.target for entry in later.entries), (
        "A new source preparation ignored current exact target exclusions"
    )
    assert dict(later.exclusion_counts)["scope.excluded"] == 3, "Denied duplicate count changed"
    assert len(ProjectCapturedWebFrontier(prepared).object_patches) == 5, (
        "A pure historical description was relabeled as live authority"
    )


@pytest.mark.parametrize("shape", ["mutable", "null", "duplicate", "unrelated", "too-many"])
def test_ProjectionRefusesAmbiguousExistingEndpointCollections(tmp_path, shape):
    """Complete request composition requires explicit distinct owned candidate objects."""

    fixture = Fixture.Create(tmp_path / "workspace")
    frontier = Read(fixture)
    projection = ProjectCapturedWebFrontier(frontier)
    existing = projection.object_patches[0]

    if shape == "mutable":
        supplied = [existing]

    elif shape == "null":
        supplied = (None,)

    elif shape == "duplicate":
        supplied = (existing, existing)

    elif shape == "unrelated":
        supplied = (replace(existing, identity=fixture.source.endpoint.Identity()),)

    else:
        supplied = (existing,) * 257

    with pytest.raises(ValueError):
        ProjectCapturedWebFrontier(frontier, existing=supplied)
