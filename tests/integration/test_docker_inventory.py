# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify owned Docker import, model persistence, image correlation and reachability consumers."""

from __future__ import annotations

import socket
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337.docker_inventory import ApplyVerifiedDockerInspect
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import LocalModelStore, SecurityObject
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
    SearchReachabilityPaths,
)
from tests.docker_helpers import Acquire, OwnedContext, Payload


def Import(context, *, payload=None):
    """Acquire real original input and save the production import through the canonical owner.

    Args:
        context: Existing synthetic workspace/model/host/evidence owners.
        payload: Optional independent source document override.

    Returns:
        Exact saved model plus original raw evidence and explicit model attribution.
    """

    root, state, host, _ = context
    record, provenance = Acquire(context, payload)
    proposed, _ = ApplyVerifiedDockerInspect(state, record, provenance,
        host_reference=host.Reference(), workspace_root=root)
    saved = LocalModelStore(root).Save(proposed, expected_revision=state.revision)

    return saved, record, provenance


def test_PersistedSnapshotOriginalEvidenceAndExactReplaySurviveWorkspaceRelocation(tmp_path):
    """Actual save/reopen and evidence reads remain portable with path-independent identities."""

    context = OwnedContext(tmp_path / "workspace")
    root, _, host, original_evidence = context
    saved, record, provenance = Import(context)
    original = original_evidence.Read(record.reference)
    moved = tmp_path / "relocated"
    root.rename(moved)
    reopened = LocalModelStore(moved).Open()
    assert reopened == saved, "Workspace relocation changed canonical identity or provenance"
    store = LocalEvidenceStore(moved / "evidence")
    assert store.Get(record.evidence_id) == record, "Relocation lost owning raw manifest"
    assert store.Read(record.reference) == original, "Relocation changed original inspect bytes"
    before = {path.relative_to(moved): path.read_bytes()
              for path in moved.rglob("*") if path.is_file()}
    replayed, delta = ApplyVerifiedDockerInspect(reopened, record, provenance,
        host_reference=host.Reference(), workspace_root=moved)
    assert replayed == saved and not delta.created and not delta.updated, "Replay changed model"
    LocalModelStore(moved).Save(replayed, expected_revision=reopened.revision)
    after = {path.relative_to(moved): path.read_bytes()
             for path in moved.rglob("*") if path.is_file()}
    assert after == before, "Exact portable replay rewrote authoritative owner state"


def test_ConfigImageCorrelationPreservesPreviouslyImportedImageFacts(tmp_path):
    """Shared ImageIdentity joins an existing image and retains that source's original metadata."""

    context = OwnedContext(tmp_path / "workspace")
    root, state, host, evidence = context
    _, provenance = Acquire(context)
    image = SecurityObject(ImageIdentity("sha256:" + "d" * 64).Object(state.workspace_id),
        {"asset_type": "image", "digest": "sha256:" + "d" * 64, "digest_kind": "config",
         "previous_inventory_fact": "owned-image-scan-fact"},
        (replace(provenance, source_id="owned.image-inventory"),))
    updated, _ = state.Apply(objects=(image,))
    saved = LocalModelStore(root).Save(updated, expected_revision=state.revision)
    imported, _, _ = Import((root, saved, host, evidence))
    same = next(item for item in imported.objects if item.Reference() == image.Reference())
    assert same.attributes["previous_inventory_fact"] == "owned-image-scan-fact", (
        "Docker config correlation erased an earlier image inventory source fact"
    )
    assert {item.source_id for item in same.provenance} == {
        "inventory.docker-inspect", "owned.image-inventory"}, "Image provenance history was lost"
    assert all("previous_inventory_fact" not in item.attributes
               for item in imported.observations
               if item.provenance.source_id == "inventory.docker-inspect"), (
        "Docker evidence was falsely attributed as the source of older image metadata"
    )
    associations = [item for item in imported.relations
                    if item.attributes["association"] == "configured-image-use"]
    assert len(associations) == 2 and all(item.source_reference == image.Reference()
        for item in associations), "Containers did not correlate to the shared existing image"


def test_RefreshedDetectorEvidencePreservesExplicitOperatorTriage(tmp_path):
    """Real detector reimport adds evidence observations without reopening a dismissed condition."""

    context = OwnedContext(tmp_path / "workspace")
    root, _, host, evidence = context
    imported, record, provenance = Import(context)
    finding = next(item for item in Findings(imported)
                   if item.check_id == "docker.configured.privileged")
    reference = finding.ToObject(imported.workspace_id).Reference()
    decision = replace(provenance, source_id="owned.operator", run_reference="run:triage")
    triaged, _ = TransitionFinding(imported, reference, FindingStatus.DISMISSED,
                                  decision, "Owned fixture disposition")
    saved = LocalModelStore(root).Save(triaged, expected_revision=imported.revision)
    refreshed_record = evidence.Put(evidence.Read(record.reference), record.reference.role,
        record.reference.media_type, replace(record.provenance,
            started_at="2026-10-14T09:00:01Z", finished_at="2026-10-14T09:00:01Z"))
    refreshed_provenance = replace(provenance, observed_at="2026-10-14T09:00:01Z")
    refreshed, delta = ApplyVerifiedDockerInspect(saved, refreshed_record, refreshed_provenance,
        host_reference=host.Reference(), workspace_root=root)
    LocalModelStore(root).Save(refreshed, expected_revision=saved.revision)
    current = next(item for item in Findings(LocalModelStore(root).Open())
                   if item.Fingerprint() == finding.Fingerprint())
    assert current.status is FindingStatus.DISMISSED, "Detector refresh overwrote operator triage"
    assert current.status_reason == "Owned fixture disposition", "Triage attribution was discarded"
    assert delta.revision == saved.revision + 1, "Refresh did not use one canonical transition"
    assert len(refreshed.observations) > len(saved.observations), "Fresh evidence history omitted"


def test_ExistingReachabilityConsumesExplicitAssociationsAsUnassessedUnknown(tmp_path):
    """Configuration relationships never become confirmed reachability or physical attack paths."""

    context = OwnedContext(tmp_path / "workspace")
    root, _, _, _ = context
    model, _, _ = Import(context)
    version = ReachabilityModelVersion.FromModel(model)
    claims = ReadReachabilityClaims(model, (), workspace_root=root,
        expected_model_version=version, context_reference="owned-docker-configuration",
        scope_reference="scope:owned", at="2026-10-14T09:00:01Z")
    edge = next(item for item in model.relations
                if item.attributes["association"] == "reported-network-membership")
    projected = ProjectReachability(model, (edge.Reference(),), claims,
                                    expected_model_version=version)
    paths = SearchReachabilityPaths(projected, model, edge.source_reference, edge.target_reference)
    assert len(projected.transitions) == 1, "Explicit existing association was not consumed"
    assert not claims.claims and not projected.transitions[0].claims, "Importer invented claims"
    assert projected.transitions[0].state is ReachabilityState.UNKNOWN, (
        "Configuration membership was promoted into confirmed network reachability"
    )
    assert projected.transitions[0].reasons == ("unassessed",), "Unknown lost its specific reason"
    assert len(paths.paths) == 1 and paths.paths[0].state is ReachabilityState.UNKNOWN, (
        "Explicit configured edge became a confirmed physical path"
    )


def test_ImporterPerformsNoDockerSubprocessOrNetworkAccess(tmp_path, monkeypatch):
    """Owned evidence import works with transport and external execution tripwires enabled."""

    context = OwnedContext(tmp_path / "workspace")
    record, provenance = Acquire(context)

    def Refuse(*args, **kwargs):
        """Fail any attempted live socket or external process activity.

        Args:
            args: Attempted external operation arguments.
            kwargs: Attempted external operation options.
        """

        raise AssertionError("Owned offline inspect importer attempted live runtime access")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        state, _ = ApplyVerifiedDockerInspect(context[1], record, provenance,
            host_reference=context[2].Reference(), workspace_root=context[0])

    assert len(Findings(state)) == 6, "Offline real-owner import failed under live-access tripwires"


def test_ForeignWorkspaceAndNonHostTargetsNeverBorrowOwnerEvidence(tmp_path):
    """Valid source evidence cannot project objects into another workspace or image target."""

    context = OwnedContext(tmp_path / "workspace")
    record, provenance = Acquire(context)
    foreign = OwnedContext(tmp_path / "foreign", "foreign-workspace")

    with pytest.raises(ValueError):
        ApplyVerifiedDockerInspect(foreign[1], record,
            replace(provenance, target_reference=foreign[2].Reference()),
            host_reference=foreign[2].Reference(), workspace_root=foreign[0])

    with pytest.raises(ValueError):
        ApplyVerifiedDockerInspect(context[1], record, provenance,
            host_reference=context[2].Reference(), workspace_root=foreign[0])

    with pytest.raises(ValueError):
        ApplyVerifiedDockerInspect(context[1], record, provenance,
            host_reference=ImageIdentity("sha256:" + "d" * 64).Object(
                context[1].workspace_id).Reference(), workspace_root=context[0])


def test_MultipleDestinationsForOneResourcePreserveAllExplicitMountAssociations(tmp_path):
    """One canonical mount resource can retain two configured destinations without losing a fact."""

    context = OwnedContext(tmp_path / "workspace")
    payload = Payload()
    payload[0]["Mounts"].append({"Type": "volume", "Name": "owned-volume",
                                 "Destination": "/second-data", "RW": False})
    model, _, _ = Import(context, payload=payload)
    resource = next(item for item in model.objects
                    if item.attributes.get("volume_name") == "owned-volume")
    relation = next(item for item in model.relations
                    if item.target_reference == resource.Reference())
    actual = {(item["destination"], item["read_write"]) for item in relation.attributes["mounts"]}
    assert actual == {("/data", True), ("/second-data", False)}, (
        "Shared mount source caused a destination association to disappear"
    )
