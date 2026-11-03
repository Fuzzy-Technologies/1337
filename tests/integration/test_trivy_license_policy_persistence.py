# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent native occurrence oracles through real local workspace and evidence owners."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from copy import deepcopy
from dataclasses import replace

import pytest

from fuzzy1337 import trivy_license_policy as projection
from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.images import ApplyVerifiedTrivyImages, ImageIdentity, PackageIdentity
from fuzzy1337.license_policy import LicensePolicy
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.trivy_license_policy import EvaluateVerifiedTrivyLicenses
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

IMAGE = "sha256:" + "a" * 64
PURL = "pkg:pypi/owned-lib@1.0"


def Package(licenses=None):
    """Describe a synthetic exact native package; list states are selected by each oracle."""

    value = {"ID": "owned-1", "Name": "Owned_Lib", "Version": "1.0",
             "Identifier": {"PURL": PURL}}

    if licenses is not None:
        value["Licenses"] = licenses

    return value


def Payload(packages=None):
    """Build independent schema-2 input with an equal-byte manifest and ignored private bait."""

    return {"SchemaVersion": 2, "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE, "RepoDigests": ["owned.invalid/fixture@" + IMAGE],
                     "Env": ["IGNORED-PRIVATE"]},
        "Results": [{"Target": "IGNORED-PRIVATE", "Type": "python-pkg",
                     "Packages": [Package(["MIT"])] if packages is None else packages}]}


def Policy():
    """Provide explicit synthetic syntax preferences without an implicit legal decision."""

    return LicensePolicy("owned-review", ("MIT",), ("Apache-2.0",))


def Owned(tmp_path, payload=None, *, overrides=None, version="0.75.0-synthetic"):
    """Store explicitly synthetic native-format evidence without invoking a scanner."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned native policy fixture"), "owned")
    state = LocalModelStore(root).Create()
    store = LocalEvidenceStore(root / "evidence")
    execution = AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)
    invocation = AdapterInvocation("native.trivy",
        AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE,
                       {"archive": "owned.tar", "timeout_seconds": 1}),
        ("synthetic-fixture", "--input", "owned.tar"), 1, version)
    source = EvidenceProvenance("owned", "scope:owned", "native.trivy", "1", version,
        "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z", InvocationDigest(invocation), execution)

    if overrides:
        source = replace(source, **overrides)

    raw = CanonicalModelJson(Payload() if payload is None else payload)
    selected = tmp_path / "selected.json"
    selected.write_bytes(raw)
    records = (store.Put(raw, "stdout", "application/json", source),
        store.Put(b"synthetic fixture", "stderr", "text/plain", source),
        store.Put(CanonicalModelJson({"Version": version,
            "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z"}}),
            "provider-version", "application/json", replace(source, invocation_sha256=None,
                execution=None, started_at="2026-10-12T23:59:59Z",
                finished_at="2026-10-13T00:00:00Z")))
    report = AdapterReport(invocation, execution, tuple(item.reference for item in records))
    provenance = ModelProvenance("native.trivy", "run:synthetic-fixture", source.finished_at,
        "scope:owned", "target:owned", version, report.evidence, execution)

    return root, state, report, provenance, records, selected


def Evaluate(context):
    """Enter the new SDK using exact independently retained owning inputs."""

    root, state, report, provenance, records, _ = context

    return EvaluateVerifiedTrivyLicenses(state, report, provenance, records, root, Policy())


def Files(root):
    """Preserve all original workspace byte identities around each read-only operation."""

    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def Refuse(*args, **kwargs):
    """Trip on any storage publication, process or network side effect."""

    raise AssertionError("Read-only native license projection attempted a side effect.")


def test_OriginalCoordinatesDuplicatesKindsAndIndependentDecisions(tmp_path, monkeypatch):
    """Original strings and repeated PURLs remain separate without list or legal aggregation."""

    omitted = Package()
    null = Package()
    null["Licenses"] = None
    payload = Payload([Package(["MIT OR Apache-2.0", "Apache-2.0", "MIT", "MIT"]),
        Package(["LicenseRef-Owned", "MIT OR (", "Unconfigured"]), omitted, null, Package([])])
    payload["Results"].append(deepcopy(payload["Results"][0]))
    context = Owned(tmp_path, payload)
    root, state, report, provenance, records, _ = context
    before = Files(root)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    monkeypatch.setattr(socket, "socket", Refuse)
    monkeypatch.setattr(subprocess, "Popen", Refuse)
    result = Evaluate(context)
    rows = result["packages"]
    assert [(row["result_index"], row["package_index"]) for row in rows] == [
        (0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (1, 0), (1, 1), (1, 2), (1, 3), (1, 4),
    ], "Repeated source coordinates were reordered or deduplicated."
    assert [item["evaluation"]["status"] for item in rows[0]["assertions"]] == [
        "allow", "deny", "allow", "allow",
    ], "Independent sibling expression oracle differs."
    assert [item["license_index"] for item in rows[0]["assertions"]] == [0, 1, 2, 3], (
        "Duplicate original strings lost their source occurrence indices."
    )
    assert [item["evaluation"]["reason"] for item in rows[1]["assertions"]] == [
        "unsupported-expression", "unsupported-expression", "unconfigured-atoms",
    ], "Unknown syntax and unknown atoms lost separate meanings."
    assert [rows[index]["assertions"][0]["information_state"] for index in (2, 3, 4)] == [
        "omitted", "null", "empty",
    ], "Original omitted, null and empty states collapsed."
    assert result["image_reference"] == ImageIdentity(IMAGE).Object("owned").Reference() and (
        result["image_reference"] != ImageIdentity(IMAGE, "manifest").Object("owned").Reference()
    ), "Equal hash bytes borrowed manifest-domain identity."
    assert all(row["package_reference"] == PackageIdentity.FromPurl(PURL).Object(
        "owned").Reference() for row in rows), "Canonical source package identities differ."
    assert result["evidence_ids"] == {r.reference.role: r.evidence_id for r in records} and (
        result["source_sha256"] == records[0].reference.sha256
    ), "Exact source acquisition and digest identities were lost."
    assert result["provenance"] == json.loads(CanonicalModelJson(provenance)) and (
        result["policy"] == Policy().Description()
    ), "Original attribution or complete explicit policy was lost."
    assert result["execution"]["state"] == "succeeded" and result["invocation"][
        "adapter_id"
    ] == report.invocation.adapter_id, "Execution and invocation were not retained separately."
    assert b"IGNORED-PRIVATE" not in CanonicalModelJson(result), "Unselected raw fields leaked."
    assert all(item["source_role"] == "not-classified" for row in rows
        for item in row["assertions"]), "Native strings gained an inferred SPDX source role."
    assert "status" not in result and Files(root) == before, "Projection aggregated or wrote state."


@pytest.mark.parametrize("field", ["state", "report", "provenance", "records", "workspace_root",
                                  "policy"])
def test_ExactInputRefusalPrecedesEveryRead(tmp_path, monkeypatch, field):
    """Implicit types fail before workspace or evidence access."""

    root, state, report, provenance, records, _ = Owned(tmp_path)
    arguments = dict(state=state, report=report, provenance=provenance, records=records,
                     workspace_root=root, policy=Policy())
    arguments[field] = None
    monkeypatch.setattr(projection, "PreflightRecords", Refuse)

    with pytest.raises(ValueError, match="invalid-trivy-license-policy-input"):
        EvaluateVerifiedTrivyLicenses(**arguments)


@pytest.mark.parametrize("case", ["package", "vulnerability", "license", "schema", "type"])
def test_LaterOwnerInvalidInputRefusesWholeResult(tmp_path, case):
    """A valid first match cannot hide later owner-invalid inventory or source fields."""

    payload = Payload([Package(["MIT"]), Package(["MIT"])])
    native = payload["Results"][0]

    if case == "package":
        native["Packages"][1]["Version"] = "2.0"

    elif case == "vulnerability":
        native["Vulnerabilities"] = [{"PkgName": "absent", "InstalledVersion": "1.0"}]

    elif case == "license":
        native["Packages"][1]["Licenses"] = [""]

    elif case == "schema":
        payload["SchemaVersion"] = 1

    else:
        payload["ArtifactType"] = "filesystem"

    context = Owned(tmp_path, payload)
    before = Files(context[0])

    with pytest.raises(ValueError):
        Evaluate(context)

    assert Files(context[0]) == before, "Owner-invalid refusal modified saved evidence."


@pytest.mark.parametrize("field,value", [("scope_reference", "scope:other"),
    ("observed_at", "2026-10-13T00:00:02Z"), ("source_id", "other"),
    ("provider_version", "0.75.1"), ("evidence_references", ()),
    ("target_reference", "target:other")])
def test_SourceScopeTimeVersionAndManifestJoins(tmp_path, field, value):
    """Exact original attribution cannot be silently replaced or spliced."""

    root, state, report, provenance, records, _ = Owned(tmp_path)

    with pytest.raises(ValueError):
        EvaluateVerifiedTrivyLicenses(state, report, replace(provenance, **{field: value}),
                                     records, root, Policy())


def test_ManifestSubstitutionAndCorruptBytesRefuse(tmp_path):
    """Matching source-byte hashes cannot replace immutable acquisition identity or integrity."""

    context = Owned(tmp_path)
    root, state, report, provenance, records, _ = context
    changed = replace(records[0], provenance=replace(records[0].provenance, source_version="2"))

    with pytest.raises(EvidenceError):
        EvaluateVerifiedTrivyLicenses(state, report, provenance, (changed, *records[1:]), root,
                                     Policy())

    (root / "evidence" / records[0].reference.locator).write_bytes(b"corrupt")

    with pytest.raises(EvidenceError):
        Evaluate(context)


def test_RelocationAndDeletedInputRetainExactOfflineResult(tmp_path):
    """Only retained original evidence is needed after complete workspace relocation."""

    context = Owned(tmp_path)
    root, state, report, provenance, records, selected = context
    expected = Evaluate(context)
    selected.unlink()
    moved = tmp_path / "moved"
    shutil.move(root, moved)
    before = Files(moved)
    assert EvaluateVerifiedTrivyLicenses(LocalModelStore(moved).Open(), report, provenance,
        records, moved, Policy()) == expected, "Offline relocation changed original projection."
    assert Files(moved) == before and LocalModelStore(moved).Open() == state, (
        "Relocation projection rewrote original owners."
    )


def test_ForeignWorkspaceCannotBorrowOriginalEvidence(tmp_path):
    """Copied source bytes remain owned by their original workspace."""

    root, _, report, provenance, records, _ = Owned(tmp_path)
    foreign = tmp_path / "foreign"
    LocalWorkspaceStore(foreign).Create(WorkspaceConfiguration("Foreign"), "foreign")
    state = LocalModelStore(foreign).Create()
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)

    with pytest.raises(ValueError):
        EvaluateVerifiedTrivyLicenses(state, report, provenance, records, foreign, Policy())


def test_Global4097RowsRefuseAcrossValidArrays(tmp_path):
    """An unknown empty package counts once after 4096 original license occurrences."""

    context = Owned(tmp_path, Payload([Package(["MIT"] * 4096), Package([])]))
    root, state, report, provenance, records, _ = context
    ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    with pytest.raises(ValueError, match="trivy-license-policy-limit"):
        Evaluate(context)


def test_Exact4096RowsKeepAllOriginalIndices(tmp_path):
    """The inclusive occurrence ceiling retains all duplicate occurrences."""

    result = Evaluate(Owned(tmp_path, Payload([Package(["MIT"] * 4096)])))
    assert len(result["packages"][0]["assertions"]) == 4096 and result["packages"][0][
        "assertions"
    ][-1]["license_index"] == 4095, "Inclusive row limit truncated or rejected valid occurrences."


def test_ActualEscapedCanonicalOutputLimitRefuses(tmp_path):
    """Valid long original strings exceed the independent full-result ceiling."""

    context = Owned(tmp_path, Payload([Package(['"\\' * 1024] * 600)]))
    root, state, report, provenance, records, _ = context
    ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    with pytest.raises(ValueError, match="trivy-license-policy-limit"):
        Evaluate(context)


def test_EmptyPackagesYieldNoOverallVerdict(tmp_path):
    """An empty admitted inventory does not become a positive policy result."""

    result = Evaluate(Owned(tmp_path, Payload([])))
    assert result["packages"] == [] and "status" not in result, "Empty inventory became allow."
