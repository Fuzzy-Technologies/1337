# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual offline runtime handler persistence, portable replay, triage and JSON/SARIF consumers."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO

from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import LocalModelStore, ModelProvenance, Observation, SecurityObject
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
)
from fuzzy1337.report_commands import RunReportCommands
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.docker_helpers import Acquire
from tests.runtime_helpers import Arguments, Context, KubernetesContext, Run

TIME = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)


def test_PublicHandlerActualPortableReplayExportsOriginalEvidenceAndPreservedTriage(
    tmp_path, monkeypatch,
):
    """Actual owners survive relocation and export JSON/SARIF without live runtime activity."""

    context = Context(tmp_path)
    root, initial, host, evidence, source = context
    image = SecurityObject(ImageIdentity("sha256:" + "d" * 64).Object(initial.workspace_id),
        {"asset_type": "image", "digest": "sha256:" + "d" * 64, "digest_kind": "config",
         "prior_image_fact": "owned-existing-image"},
        (ModelProvenance("owned.image", "run:image", TIME.isoformat(),
                         "scope:owned", host.Reference()),))
    proposal, _ = initial.Apply(objects=(image,))
    LocalModelStore(root).Save(proposal, expected_revision=initial.revision)

    def Refuse(*args, **kwargs):
        """Fail if the command or report consumer attempts live transport/execution."""

        raise AssertionError("Offline runtime product attempted live socket or process access")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        status, imported = Run(Arguments(context), clock=lambda: TIME)

    assert status == 0 and imported["model_commit"] == "confirmed", "Actual owned handler failed"
    original = evidence.Get(imported["evidence_id"])
    assert evidence.Read(original.reference) == source.read_bytes(), "Original acquisition changed"
    saved = LocalModelStore(root).Open()
    correlated = next(item for item in saved.objects if item.Reference() == image.Reference())
    assert correlated.attributes["prior_image_fact"] == "owned-existing-image" and (
        {item.source_id for item in correlated.provenance} == {
            "owned.image", "inventory.docker-inspect",
        }
    ), "Product runtime correlation erased original image metadata/provenance"
    finding = next(item for item in Findings(saved)
                   if item.check_id == "docker.configured.privileged")
    decision = ModelProvenance("owned.operator", "decision:owned", TIME.isoformat(),
                               "scope:owned", host.Reference())
    triaged, _ = TransitionFinding(saved, finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED, decision, "Owned explicit runtime disposition")
    LocalModelStore(root).Save(triaged, expected_revision=saved.revision)
    refreshed_at = TIME + timedelta(seconds=1)
    status, refreshed = Run(Arguments(context), clock=lambda: refreshed_at)
    assert status == 0 and refreshed["evidence_id"] != original.evidence_id, (
        "Fresh source was not acquired"
    )
    expected = LocalModelStore(root).Open()
    disposed = next(item for item in Findings(expected)
                    if item.Fingerprint() == finding.Fingerprint())
    assert disposed.status is FindingStatus.DISMISSED and (
        disposed.status_reason == "Owned explicit runtime disposition"
    ), "Fresh detector acquisition overwrote existing operator triage"
    before = {path.relative_to(root): path.read_bytes()
              for path in root.rglob("*") if path.is_file()}
    moved = tmp_path / "moved"
    root.rename(moved)
    relocated = (moved, expected, host, evidence, source)

    def NoClock():
        """Reject new acquisition timestamps during retained original replay."""

        raise AssertionError("Retained replay fabricated a fresh local file acquisition")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        status, replayed = Run(Arguments(relocated, evidence_id=refreshed["evidence_id"]),
                               clock=NoClock)
        assert status == 0 and replayed["created"] == 0 and replayed["updated"] == 0, (
            "Retained relocated exact import was not a canonical no-op"
        )

        for report_format in ("json", "sarif"):
            destination = tmp_path / ("report." + report_format)
            output = StringIO()
            status = RunReportCommands(["export", str(moved), "--format", report_format,
                "--output", str(destination)], output, json_output=True)
            outcome = json.loads(output.getvalue())
            assert status == 0 and outcome["output_published"] is True, "Report export failed"
            document = json.loads(destination.read_bytes())

            if report_format == "json":
                assert document["summary"]["findings"] == 6, "Saved runtime JSON lost findings"

            else:
                results = document["runs"][0]["results"]
                assert len(results) == 5 and all(
                    item["ruleId"] != "docker.configured.privileged" for item in results
                ), "SARIF did not preserve the dismissed finding's existing export disposition"
                closed = document["runs"][0]["properties"]["closedFindings"]
                assert len(closed) == 1 and closed[0]["normalized"]["status"] == "dismissed", (
                    "SARIF lost the original dismissed finding context"
                )

            assert b"SYNTHETIC_PRIVATE_MARKER" not in destination.read_bytes(), "Raw source leaked"

    after = {path.relative_to(moved): path.read_bytes()
             for path in moved.rglob("*") if path.is_file()}
    assert before == after, "Exact replay or separate report export rewrote authoritative workspace"
    assert LocalModelStore(moved).Open() == expected, "Relocated consumer changed canonical model"
    version = ReachabilityModelVersion.FromModel(expected)
    claims = ReadReachabilityClaims(expected, (), workspace_root=moved,
        expected_model_version=version, context_reference="owned-runtime-import",
        scope_reference="scope:owned", at=(TIME + timedelta(seconds=2)).isoformat())
    edge = next(item for item in expected.relations
                if item.attributes.get("association") == "reported-network-membership")
    projected = ProjectReachability(expected, (edge.Reference(),), claims,
                                    expected_model_version=version)
    assert not claims.claims and projected.transitions[0].state is ReachabilityState.UNKNOWN, (
        "Configured offline source became a physical runtime reachability claim"
    )


def test_SameRawBytesWithDifferentOriginalManifestIdentityRemainDistinctOnReplay(tmp_path):
    """Equal raw references and attribution do not collapse different acquisition IDs."""

    context = Context(tmp_path)
    root, _, _, evidence, _ = context
    status, imported = Run(Arguments(context), clock=lambda: TIME)
    assert status == 0, "Initial original acquisition failed"
    original = evidence.Get(imported["evidence_id"])
    second = evidence.Put(evidence.Read(original.reference), "docker-inspect", "application/json",
        replace(original.provenance, started_at=(TIME - timedelta(seconds=1)).isoformat()))
    assert second.reference == original.reference and second.evidence_id != original.evidence_id, (
        "Independent acquisition did not create the intended same-content/different-manifest case"
    )
    status, outcome = Run(Arguments(context, evidence_id=second.evidence_id))
    assert status == 0 and outcome["model_revision"] == imported["model_revision"] + 1, (
        "Second original manifest identity was collapsed or caused multiple model revisions"
    )
    saved = LocalModelStore(root).Open()
    source_facts = {item.attributes["evidence_id"]: item for item in saved.observations
                    if item.kind == "runtime-import-source"}
    assert set(source_facts) == {original.evidence_id, second.evidence_id}, "Manifest IDs merged"
    assert source_facts[second.evidence_id].attributes["read_actor_reference"] is None and (
        source_facts[second.evidence_id].attributes["read_consent_reference"] is None
    ), "Externally acquired original record invented prior file read consent"
    workspace = LocalWorkspaceStore(root).Open()
    assert len(workspace.evidence_references) == 1 and (
        len(workspace.evidence_record_references) == 2
    ), (
        "Workspace confused content identity with original acquisition identity"
    )
    before = (root / "state/model/model.json").read_bytes()
    status, replayed = Run(Arguments(context, evidence_id=original.evidence_id))
    assert status == 0 and replayed["created"] == 0 and replayed["updated"] == 0, (
        "Original manifest could not replay after another same-byte acquisition"
    )
    assert (root / "state/model/model.json").read_bytes() == before, "Original replay rewrote model"


def test_KubernetesRuntimeAcquisitionAndRetainedReplayNeedNoLiveTransportOrNewReadAuthority(
    tmp_path, monkeypatch,
):
    """Actual handler acquisition, owner saves and exact replay work under live-access tripwires."""

    context = KubernetesContext(tmp_path)

    def Refuse(*args, **kwargs):
        """Fail any cluster/native access or new observation clock in retained replay."""

        raise AssertionError("Owned Kubernetes import attempted live access or fresh retained read")

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", Refuse)
        guard.setattr(socket, "create_connection", Refuse)
        guard.setattr(subprocess, "Popen", Refuse)
        status, outcome = Run(Arguments(context, profile="kubernetes-list"), clock=lambda: TIME)
        assert status == 0, "Actual Kubernetes handler failed without live access"
        before = {path.relative_to(context[0]): path.read_bytes()
                  for path in context[0].rglob("*") if path.is_file()}
        context[4].unlink()
        status, replay = Run(Arguments(context, profile="kubernetes-list",
            evidence_id=outcome["evidence_id"]), clock=Refuse)
        assert status == 0 and replay["created"] == replay["updated"] == 0, (
            "Retained original selection performed a fresh external acquisition"
        )

    assert before == {path.relative_to(context[0]): path.read_bytes()
                      for path in context[0].rglob("*") if path.is_file()}, (
        "Actual retained no-op changed authoritative owner bytes"
    )


def test_PreexistingDockerCustodyShapeReplaysWithoutMigrationOrSavedByteChanges(tmp_path):
    """Handwritten accepted Docker product custody remains compatible across shared helper reuse."""

    from fuzzy1337.docker_inventory import ApplyVerifiedDockerInspect

    context = Context(tmp_path)
    root, basis, host, _, _ = context
    record, provenance = Acquire(context[:4])
    proposed, _ = ApplyVerifiedDockerInspect(basis, record, provenance,
        host_reference=host.Reference(), workspace_root=root)
    original_fact = Observation("runtime-import-source", host.Reference(), {
        "profile": "docker-inspect", "evidence_id": record.evidence_id,
        "source_sha256": record.reference.sha256,
        "source_version": "owned-docker-container-inspect-v1",
        "read_actor_reference": "owner:legacy",
        "read_consent_reference": "consent:legacy",
    }, provenance)
    legacy, _ = proposed.Apply(observations=(original_fact,))
    legacy = replace(legacy, revision=proposed.revision)
    LocalModelStore(root).Save(legacy, expected_revision=basis.revision)
    workspace = LocalWorkspaceStore(root)
    workspace.Save(replace(workspace.Open(), scope_references=("scope:owned",),
        object_references=tuple(sorted(item.Reference() for item in legacy.objects)),
        evidence_references=(record.reference,), evidence_record_references=(record.evidence_id,)))
    before = {path.relative_to(root): path.read_bytes()
              for path in root.rglob("*") if path.is_file()}

    def NoClock():
        """Refuse a fabricated fresh acquisition during legacy original retained replay."""

        raise AssertionError("Legacy retained Docker replay acquired new source authority")

    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id), clock=NoClock)
    assert status == 0 and outcome["created"] == outcome["updated"] == 0, (
        "Existing accepted Docker custody required migration or reinterpretation"
    )
    after = {path.relative_to(root): path.read_bytes()
             for path in root.rglob("*") if path.is_file()}
    assert after == before and original_fact in LocalModelStore(root).Open().observations, (
        "Shared profiles changed original Docker attribute keys, host/run or read descriptions"
    )
