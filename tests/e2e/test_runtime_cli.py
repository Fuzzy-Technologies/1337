# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed console workflows over owned original runtime files and portable durable stores."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
)
from fuzzy1337.runtime_commands import RuntimeEvidenceStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.docker_helpers import FIXTURES, TIME
from tests.runtime_helpers import Arguments


def Console(parent, arguments):
    """Run the real installed console script with only explicitly supplied local selections."""

    executable = Path(sys.executable).parent / ("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(executable), *arguments], cwd=parent, check=False,
                            capture_output=True, text=True, timeout=30)
    assert not result.stderr, "Registered console emitted unexpected or unsafe diagnostics"

    return result.returncode, json.loads(result.stdout)


def ConsoleContext(parent, *, profile="docker-inspect"):
    """Create public workspace/scope and seed the explicit profile's existing owning anchor."""

    root = parent / "Owned Workspace"
    status, _ = Console(parent, ["workspace", "create", str(root), "--id", "runtime-console",
                                "--name", "Owned runtime console", "--json"])
    assert status == 0, "Actual console workspace creation failed"
    status, _ = Console(parent, ["scope", "create", str(root), "--id", "owned",
                                "--allow-ip", "192.0.2.1", "--json"])
    assert status == 0, "Actual console scope creation failed"
    store = LocalModelStore(root)
    basis = store.Open()

    if profile == "docker-inspect":
        provenance = ModelProvenance("synthetic.host", "run:host", TIME,
                                    "scope:owned", "host:owned")
        anchor = SecurityObject(ObjectIdentity(basis.workspace_id, ObjectKind.HOST, "192.0.2.1"),
                                {"fixture_kind": "owned-explicit-host"}, (provenance,))
        fixture = "docker-inspect.owned.v1.json"

    else:
        provenance = ModelProvenance("synthetic.cluster", "run:cluster", TIME,
                                    "scope:owned", "cluster:owned")
        anchor = SecurityObject(ObjectIdentity(basis.workspace_id, ObjectKind.ASSET,
            "kubernetes-cluster:owned-cluster"),
            {"asset_type": "kubernetes-cluster", "cluster_id": "owned-cluster"}, (provenance,))
        fixture = "kubernetes-list.owned.v1.json"

    proposed, _ = basis.Apply(objects=(anchor,))
    saved = store.Save(proposed, expected_revision=basis.revision)
    source = parent / "Owned Inspect.json"
    source.write_bytes((FIXTURES / fixture).read_bytes())

    return root, saved, anchor, RuntimeEvidenceStore(root / "evidence", profile=profile), source


def Import(parent, context, *, evidence_id=None, arguments=None, profile="docker-inspect"):
    """Invoke the assembled runtime namespace using current explicit owner revision pins."""

    selected = Arguments(context, evidence_id=evidence_id, profile=profile) if (
        arguments is None) else arguments

    return Console(parent, ["runtime", *selected, "--json"])


def test_InstalledRuntimeConsolePreservesOwnedOracleRelocationReplayTriageAndReports(tmp_path):
    """Actual public setup/import/export paths retain source custody and canonical SDK meanings."""

    context = ConsoleContext(tmp_path)
    root, basis, host, evidence, source = context
    original = source.read_bytes()
    status, outcome = Import(tmp_path, context)
    assert status == 0 and outcome["status"] == "succeeded", "Registered owned import failed"
    assert all(outcome[name] == "confirmed" for name in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "Actual console conflated the three independent owner acknowledgements"
    record = evidence.Get(outcome["evidence_id"])
    assert evidence.Read(record.reference) == original and (
        outcome["source_sha256"] == hashlib.sha256(original).hexdigest()
    ), "Actual console changed original acquisition bytes or their complete hash"
    assert record.provenance.tool_version is None and record.provenance.execution is None and (
        record.provenance.invocation_sha256 is None
    ), "Actual offline console fabricated provider detection or native execution"
    saved = LocalModelStore(root).Open()
    oracle = json.loads((FIXTURES / "docker-inspect.oracle.v1.json").read_bytes())
    assert {"objects": len(saved.objects), "relations": len(saved.relations),
            "observations": len(saved.observations), "findings": len(Findings(saved))} == {
        **oracle["counts"], "observations": 56,
    }, "Actual assembled console lost handwritten SDK facts or original manifest custody"
    checks = {item.check_id for item in Findings(saved)}
    assert {"tp": len(checks & set(oracle["expected_checks"])),
            "fp": len(checks - set(oracle["expected_checks"])),
            "fn": len(set(oracle["expected_checks"]) - checks),
            "tn": len(set(oracle["absent_checks"]) - checks)} == {
        "tp": 6, "fp": 0, "fn": 0, "tn": 3,
    }, "Actual runtime console failed the independent configured-condition oracle"
    assert saved.revision == basis.revision + 1 and outcome["workspace_revision"] == 1, (
        "Actual import silently changed caller model/workspace CAS bases"
    )
    unknown = next(item for item in saved.objects
                   if item.attributes.get("container_id") == oracle["unknown_container"])
    assert all(unknown.attributes[name] is None for name in oracle["unknown_fields"]), (
        "Actual console inferred safe defaults for unknown inspect facts"
    )
    finding = next(item for item in Findings(saved)
                   if item.check_id == "docker.configured.privileged")
    image = next(item for item in saved.objects
                 if item.attributes.get("digest") == "sha256:" + "d" * 64)
    image_fact = ModelProvenance("owned.image", "run:image", TIME, "scope:owned", host.Reference())
    preserved = replace(image, attributes={**image.attributes,
        "prior_image_fact": "owned-existing-image"}, provenance=(*image.provenance, image_fact))
    image_state, _ = saved.Apply(objects=(preserved,))
    saved = LocalModelStore(root).Save(image_state, expected_revision=saved.revision)
    decision = ModelProvenance("owned.operator", "decision:owned", TIME,
                               "scope:owned", host.Reference())
    triaged, _ = TransitionFinding(saved, finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED, decision, "Owned explicit runtime disposition")
    LocalModelStore(root).Save(triaged, expected_revision=saved.revision)
    status, refreshed = Import(tmp_path, context)
    assert status == 0 and refreshed["evidence_id"] != record.evidence_id, (
        "Same-byte actual acquisition collapsed distinct original manifest identities"
    )
    expected = LocalModelStore(root).Open()
    correlated = next(item for item in expected.objects if item.Reference() == image.Reference())
    assert correlated.attributes["prior_image_fact"] == "owned-existing-image" and (
        image_fact in correlated.provenance
    ), "Registered refresh erased prior image correlation metadata or provenance"
    disposed = next(item for item in Findings(expected)
                    if item.Fingerprint() == finding.Fingerprint())
    assert disposed.status is FindingStatus.DISMISSED and (
        disposed.status_reason == "Owned explicit runtime disposition"
    ), "Registered import overwrote the operator's saved triage"
    workspace = LocalWorkspaceStore(root).Open()
    assert set(workspace.evidence_record_references) == {
        record.evidence_id, refreshed["evidence_id"],
    } and len(workspace.evidence_references) == 1 and not workspace.job_references, (
        "Console confused raw content identity with original acquisition or invented a scan job"
    )
    before = {path.relative_to(root): path.read_bytes()
              for path in root.rglob("*") if path.is_file()}
    moved = tmp_path / "Moved Owned Workspace"
    root.rename(moved)
    relocated = (moved, expected, host, RuntimeEvidenceStore(moved / "evidence"), source)
    source.unlink()
    status, replay = Import(tmp_path, relocated, evidence_id=refreshed["evidence_id"])
    assert status == 0 and replay["created"] == replay["updated"] == 0 and (
        replay["model_revision"] == expected.revision
        and replay["workspace_revision"] == workspace.revision
    ), "Retained relocated console replay was not an exact owner-basis no-op"
    assert before == {path.relative_to(moved): path.read_bytes()
                      for path in moved.rglob("*") if path.is_file()}, (
        "Actual retained replay rewrote durable owner bytes"
    )
    status, _ = Console(tmp_path, ["workspace", "open", str(moved), "--json"])
    assert status == 0, "Public authoritative reopen failed after portable retained replay"
    version = ReachabilityModelVersion.FromModel(expected)
    claims = ReadReachabilityClaims(expected, (), workspace_root=moved,
        expected_model_version=version, context_reference="owned-runtime-console",
        scope_reference="scope:owned", at="2026-10-14T23:59:59Z")
    edge = next(item for item in expected.relations
                if item.attributes.get("association") == "reported-network-membership")
    projected = ProjectReachability(expected, (edge.Reference(),), claims,
                                    expected_model_version=version)
    assert not claims.claims and projected.transitions[0].state is ReachabilityState.UNKNOWN, (
        "Actual configured import fabricated physical runtime reachability evidence"
    )

    for report_format in ("json", "sarif"):
        destination = tmp_path / ("runtime-report." + report_format)
        status, exported = Console(tmp_path, ["report", "export", str(moved), "--format",
            report_format, "--output", str(destination), "--json"])
        assert status == 0 and exported["output_published"] is True, "Actual report export failed"
        document = json.loads(destination.read_bytes())

        if report_format == "json":
            assert document["model"] == expected.ToDict() and (
                document["summary"]["findings"] == 6
            ), (
                "Actual JSON consumer lost the exact portable saved runtime snapshot"
            )

        else:
            run = document["runs"][0]
            assert len(run["results"]) == 5 and len(run["properties"]["closedFindings"]) == 1, (
                "Actual SARIF consumer lost the existing dismissed-finding disposition"
            )

        assert b"SYNTHETIC_PRIVATE_MARKER" not in destination.read_bytes(), "Raw source leaked"


@pytest.mark.parametrize("mode,expected,failure", [
    ("no-consent", 2, "configuration"), ("stale-model", 4, "revision-conflict"),
    ("stale-workspace", 4, "workspace-conflict"), ("missing-file", 4, "acquisition"),
    ("malformed-json", 4, "normalization"), ("model-busy", 4, "model-busy"),
    ("workspace-busy", 4, "workspace-busy"),
    ("hardlink", 2, "configuration"), ("symlink", 4, "acquisition"),
])
@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
def test_InstalledRuntimeRefusalsPreserveActualIndependentOwnerTruth(
    tmp_path, mode, expected, failure, profile,
):
    """Actual setup, denied read, conflict and busy paths retain durable owner truth."""

    context = ConsoleContext(tmp_path, profile=profile)
    root, basis, _, _, source = context
    arguments = Arguments(context, profile=profile)
    lock = None

    if mode == "no-consent":
        index = arguments.index("--read-consent-reference")
        del arguments[index:index + 2]

    elif mode in {"stale-model", "stale-workspace"}:
        flag = "--expected-revision" if mode == "stale-model" else "--expected-workspace-revision"
        arguments[arguments.index(flag) + 1] = "99"

    elif mode == "missing-file":
        source.unlink()

    elif mode == "malformed-json":
        source.write_bytes(b'{"unconsumed":"SYNTHETIC_PRIVATE_MARKER"}')

    elif mode in {"hardlink", "symlink"}:
        selected = tmp_path / "Linked Inspect.json"

        try:
            if mode == "hardlink":
                os.link(source, selected)

            else:
                selected.symlink_to(source)

        except (OSError, NotImplementedError):
            pytest.skip("Physical source links are unavailable on this test host")

        arguments[arguments.index("--file") + 1] = str(selected)

    else:
        lock = root / "state/model/.write-lock" if mode == "model-busy" else root / ".write-lock"
        lock.mkdir()

    try:
        status, outcome = Import(tmp_path, context, arguments=arguments)
        assert status == expected and outcome["failure"] == failure, "Console refusal changed"
        assert LocalModelStore(root).Open().revision == basis.revision + int(
            mode == "workspace-busy"
        ) and LocalWorkspaceStore(root).Open().revision == 0, "Refused owner state was rolled back"
        assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Rejected source leaked"

        if lock is not None:
            owner = "model" if mode == "model-busy" else "workspace"
            assert lock.is_dir() and outcome[owner + "_commit"] == "not-committed", (
                "Actual busy refusal removed another owner's lock or guessed committed state"
            )

        else:
            assert outcome["acquisition_commit"] == (
                "confirmed" if mode == "malformed-json" else "not-attempted"
            ), "Actual refused source acquisition acknowledgement was guessed"

    finally:
        if lock is not None:
            lock.rmdir()


def test_InstalledKubernetesRuntimePreservesOracleTriagePortableReplayAndUnknownClaims(tmp_path):
    """Actual console custody and durable consumers retain configured Kubernetes meanings."""

    context = ConsoleContext(tmp_path, profile="kubernetes-list")
    root, basis, cluster, evidence, source = context
    original = source.read_bytes()
    status, imported = Import(tmp_path, context, profile="kubernetes-list")
    assert status == 0 and imported["command"] == "runtime.import.kubernetes-list", (
        "Installed console failed its explicit Kubernetes profile"
    )
    assert all(imported[name] == "confirmed" for name in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "Actual Kubernetes console lost independent acknowledgements"
    record = evidence.Get(imported["evidence_id"])
    assert evidence.Read(record.reference) == original and record.reference.sha256 == (
        hashlib.sha256(original).hexdigest()
    ), "Kubernetes console changed original file bytes or their complete hash"
    assert record.provenance.tool_version is None and record.provenance.execution is None, (
        "Explicit offline console fabricated native provider detection/execution"
    )
    saved = LocalModelStore(root).Open()
    oracle = json.loads((FIXTURES / "kubernetes-list.oracle.v1.json").read_bytes())
    assert {"objects": len(saved.objects), "relations": len(saved.relations),
            "findings": len(Findings(saved))} == oracle["counts"], "Console graph oracle changed"
    checks = {item.check_id for item in Findings(saved)}
    assert {"tp": len(checks & set(oracle["expected_checks"])),
            "fp": len(checks - set(oracle["expected_checks"])),
            "fn": len(set(oracle["expected_checks"]) - checks),
            "tn": len(set(oracle["absent_checks"]) - checks)} == {
        "tp": 3, "fp": 0, "fn": 0, "tn": 3,
    }, "Actual console lost the independent configured-condition oracle"
    facts = [item for item in saved.observations if item.kind == "runtime-import-source"]
    assert len(facts) == 1 and facts[0].subject_reference == cluster.Reference() and (
        facts[0].attributes["evidence_id"] == record.evidence_id
    ), "Original manifest identity was not bound to the explicitly declared cluster"
    assert saved.revision == basis.revision + 1 and imported["workspace_revision"] == 1, (
        "Kubernetes console used multiple model revisions or different owner bases"
    )
    finding = next(item for item in Findings(saved)
                   if item.check_id == "kubernetes.configured.privileged")
    decision = ModelProvenance("owned.operator", "decision:owned", TIME,
                               "scope:owned", cluster.Reference())
    triaged, _ = TransitionFinding(saved, finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED, decision, "Owned Kubernetes disposition")
    LocalModelStore(root).Save(triaged, expected_revision=saved.revision)
    status, refreshed = Import(tmp_path, context, profile="kubernetes-list")
    assert status == 0 and refreshed["evidence_id"] != record.evidence_id, (
        "Actual same-byte acquisitions collapsed their original manifest identities"
    )
    expected = LocalModelStore(root).Open()
    disposed = next(item for item in Findings(expected)
                    if item.Fingerprint() == finding.Fingerprint())
    assert disposed.status is FindingStatus.DISMISSED and (
        disposed.status_reason == "Owned Kubernetes disposition"
    ), "Fresh actual import overwrote saved operator triage"
    workspace = LocalWorkspaceStore(root).Open()
    assert set(workspace.evidence_record_references) == {
        record.evidence_id, refreshed["evidence_id"],
    } and len(workspace.evidence_references) == 1 and not workspace.job_references, (
        "Console confused manifest identity with raw content or fabricated an execution job"
    )
    before = {path.relative_to(root): path.read_bytes()
              for path in root.rglob("*") if path.is_file()}
    moved = tmp_path / "Moved Kubernetes Workspace"
    root.rename(moved)
    relocated = (moved, expected, cluster,
                 RuntimeEvidenceStore(moved / "evidence", profile="kubernetes-list"), source)
    source.unlink()

    for evidence_id in (refreshed["evidence_id"], record.evidence_id):
        status, replay = Import(tmp_path, relocated, evidence_id=evidence_id,
                                profile="kubernetes-list")
        assert status == 0 and replay["created"] == replay["updated"] == 0 and (
            replay["model_revision"] == expected.revision
            and replay["workspace_revision"] == workspace.revision
        ), "Portable retained Kubernetes replay was not an exact owner-basis no-op"

    assert before == {path.relative_to(moved): path.read_bytes()
                      for path in moved.rglob("*") if path.is_file()}, (
        "Actual retained Kubernetes replay changed authoritative owner bytes"
    )
    status, _ = Console(tmp_path, ["workspace", "open", str(moved), "--json"])
    assert status == 0, "Actual public reopen failed after retained portable import"
    version = ReachabilityModelVersion.FromModel(expected)
    claims = ReadReachabilityClaims(expected, (), workspace_root=moved,
        expected_model_version=version, context_reference="owned-kubernetes-console",
        scope_reference="scope:owned", at="2026-10-14T23:59:59Z")
    edge = next(item for item in expected.relations
                if item.attributes.get("association") == "nominal-role-reference")
    projected = ProjectReachability(expected, (edge.Reference(),), claims,
                                    expected_model_version=version)
    assert not claims.claims and projected.transitions[0].state is ReachabilityState.UNKNOWN, (
        "Actual console turned nominal RBAC into effective physical access"
    )
    resources = [item for item in expected.objects
                 if item.attributes.get("asset_type") == "kubernetes-resource"]
    assert all(item.attributes["effective_permissions"] is None for item in resources), (
        "Actual portable snapshot inferred effective authorization"
    )

    for report_format in ("json", "sarif"):
        destination = tmp_path / ("kubernetes-report." + report_format)
        status, exported = Console(tmp_path, ["report", "export", str(moved), "--format",
            report_format, "--output", str(destination), "--json"])
        assert status == 0 and exported["output_published"] is True, "Actual report export failed"
        document = json.loads(destination.read_bytes())

        if report_format == "json":
            assert document["model"] == expected.ToDict(), "JSON lost the exact saved snapshot"

        else:
            run = document["runs"][0]
            assert len(run["results"]) == 2 and len(run["properties"]["closedFindings"]) == 1, (
                "SARIF lost the existing configured-finding disposition"
            )

        assert b"owned-operator" not in destination.read_bytes(), "Raw Kubernetes identity leaked"
