# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verified SPDX joins existing native/CycloneDX identity, triage and portable model consumers."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.images import ApplyVerifiedCycloneDx, ApplyVerifiedTrivyImages, ImageIdentity
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ImageIdentity("sha256:" + "a" * 64)
PURL = "pkg:pypi/owned-lib@1.0"


def test_SpdxReusesOtherInventoryKeysPreservesTriageAndPortableRawProvenance(tmp_path):
    """Real persistence retains cross-source package history and owner disposition."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned SBOM integration"), "sbom-test")
    store = LocalEvidenceStore(root / "evidence")
    model = LocalModelStore(root)
    initial = model.Create()
    execution = AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)
    invocation = AdapterInvocation("native.trivy", AdapterRequest(
        "image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE,
        {"archive": "owned.tar", "timeout_seconds": 1},
    ), ("synthetic-trivy", "--input", "owned.tar"), 1, "0.75.0-synthetic")
    acquired = EvidenceProvenance("sbom-test", "scope:owned", "native.trivy", "1",
        invocation.provider_version, "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z",
        InvocationDigest(invocation), execution)
    native = {"SchemaVersion": 2, "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE.digest}, "Results": [{"Type": "python-pkg",
            "Packages": [{"Name": "Owned_Lib", "Version": "1.0", "Identifier": {"PURL": PURL},
                          "Licenses": ["MIT"]}], "Vulnerabilities": [{"PkgName": "Owned_Lib",
                "InstalledVersion": "1.0", "VulnerabilityID": "CVE-2099-0001",
                "Severity": "HIGH"}]}]}
    records = [store.Put(CanonicalModelJson(native), "stdout", "application/json", acquired),
               store.Put(b"synthetic owned scanner fixture", "stderr", "text/plain", acquired),
               store.Put(CanonicalModelJson({"Version": invocation.provider_version,
                   "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z"}}),
                   "provider-version", "application/json", EvidenceProvenance("sbom-test",
                       "scope:owned", "native.trivy", "1", invocation.provider_version,
                       "2026-10-12T23:59:59Z", "2026-10-13T00:00:00Z"))]
    report = AdapterReport(invocation, execution, tuple(item.reference for item in records))
    provenance = ModelProvenance("native.trivy", "run:native", acquired.finished_at,
        "scope:owned", "target:owned", invocation.provider_version, report.evidence, execution)
    state, _ = ApplyVerifiedTrivyImages(initial, report, provenance, tuple(records), root)
    state = model.Save(state, expected_revision=initial.revision)
    finding = Findings(state)[0]
    operator = ModelProvenance("operator", "decision:owned", "2026-10-13T01:00:00Z",
                               "scope:owned", "target:owned")
    decided, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
        FindingStatus.RESOLVED, operator, "Synthetic owner disposition")
    state = model.Save(decided, expected_revision=state.revision)

    cyclone = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "container", "hashes": [
            {"alg": "SHA-256", "content": IMAGE.digest[7:]}]}}, "components": [
            {"type": "library", "bom-ref": "owned-1", "name": "Owned_Lib", "version": "1.0",
             "purl": PURL, "licenses": [{"license": {"id": "MIT"}}]}]}
    cyclone_record = store.Put(CanonicalModelJson(cyclone), "sbom", "application/json",
        EvidenceProvenance("sbom-test", "scope:owned", "inventory.cyclonedx", "1", None,
                           "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z"))
    cyclone_context = ModelProvenance("inventory.cyclonedx", "run:cdx",
        cyclone_record.provenance.finished_at, "scope:owned", "target:owned",
        evidence_references=(cyclone_record.reference,))
    interpreted, _ = ApplyVerifiedCycloneDx(state, cyclone_record, cyclone_context, IMAGE, root)
    state = model.Save(interpreted, expected_revision=state.revision)

    raw = (ROOT / "tests/contract/fixtures/spdx.image.v2.3.json").read_bytes()
    record = store.Put(raw, "sbom", "application/json", EvidenceProvenance("sbom-test",
        "scope:owned", "inventory.spdx", "1", None,
        "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z"))
    spdx_context = ModelProvenance("inventory.spdx", "run:spdx", record.provenance.finished_at,
        "scope:owned", "target:owned", evidence_references=(record.reference,))
    interpreted, _ = ApplyVerifiedSpdx(state, record, spdx_context, IMAGE, root)
    state = model.Save(interpreted, expected_revision=state.revision)
    packages = [item for item in state.objects if item.attributes.get("asset_type") == "package"]
    assert len(packages) == 1 and {item.source_id for item in packages[0].provenance} == {
        "native.trivy", "inventory.cyclonedx", "inventory.spdx",
    }, "SPDX created a competing package truth store or lost another source"
    assert len(Findings(state)) == 1 and Findings(state)[0].status is FindingStatus.RESOLVED, (
        "Inventory changed the owner's prior finding disposition"
    )
    replayed, delta = ApplyVerifiedSpdx(state, record, spdx_context, IMAGE, root)
    assert replayed == state and not delta.created and not delta.updated, (
        "Exact replay changed state"
    )
    assert store.Read(record.reference) == raw, "SPDX raw evidence was modified"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(state.ToDict()), (
        "Private fields were persisted"
    )
    saved_bytes = (root / "state/model/model.json").read_bytes()
    moved = tmp_path / "relocated"
    root.rename(moved)
    assert LocalModelStore(moved).Open() == state, "Portable model consumer lost the source joins"
    assert (moved / "state/model/model.json").read_bytes() == saved_bytes, (
        "Relocation rewrote state"
    )
    assert LocalEvidenceStore(moved / "evidence").Read(record.reference) == raw, (
        "Relocation broke immutable source evidence"
    )
