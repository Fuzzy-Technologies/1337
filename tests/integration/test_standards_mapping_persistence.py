# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned workspace findings consume the actual reviewed pack without changing state or evidence."""

from __future__ import annotations

import json
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingStatus, TransitionFinding
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.standards_mapping import (
    BindFindingObjectMappings,
    MappingPack,
    ReviewedBaseline,
    StandardIdentity,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
@pytest.mark.parametrize("classifier,expected_ids", [
    (StandardIdentity("cwe", "4.20", "CWE-89"), {
        "sql-injection.top10", "sql-injection.asvs", "sql-injection.capec", "sql-injection.nist",
    }),
    (StandardIdentity("cwe", "4.20", "CWE-1427"), {"prompt-injection.atlas-context"}),
    (StandardIdentity("capec", "3.9", "CAPEC-66"), {"sql-injection.attack-context"}),
])
def test_PersistedFindingBindsReviewedContextWithoutPublishingClaimsOrChangingEvidence(
    tmp_path, classifier, expected_ids,
):
    """The real evidence/model APIs retain ownership while portable mappings stay advisory."""

    root = tmp_path / "owned-workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Mapping acceptance"), "synthetic")
    store = LocalModelStore(root)
    state = store.Create()
    provenance = ModelProvenance(
        "synthetic", "run:subject", "2026-10-13T17:00:00Z", "scope:owned", "target:owned",
    )
    subject = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"), {}, (provenance,),
    )
    state, delta = state.Apply(objects=(subject,))
    store.Save(state, expected_revision=delta.previous_revision)
    evidence_store = LocalEvidenceStore(root / "evidence")
    evidence = evidence_store.Put(
        b'{"synthetic_classification":"explicitly-supplied"}', "stdout", "application/json",
        EvidenceProvenance(
            "synthetic", "scope:owned", "synthetic", "1", None,
            "2026-10-13T17:00:00Z", "2026-10-13T17:00:01Z",
        ),
    )
    detection = Finding(
        subject.Reference(), "synthetic.explicit-classification", "owned-fixture",
        "Explicitly classified synthetic finding", (ModelProvenance(
            "synthetic", evidence.evidence_id, "2026-10-13T17:00:01Z",
            "scope:owned", "target:owned", evidence_references=(evidence.reference,),
        ),),
    )
    state, delta = ApplyVerifiedFindings(state, (detection,), root)
    store.Save(state, expected_revision=delta.previous_revision)
    state, delta = TransitionFinding(
        store.Open(), detection.ToObject("synthetic").Reference(), FindingStatus.DISMISSED,
        ModelProvenance(
            "synthetic-operator", "decision:synthetic-dismissal", "2026-10-13T17:00:02Z",
            "scope:owned", "target:owned",
        ), "Synthetic operator disposition",
    )
    store.Save(state, expected_revision=delta.previous_revision)
    model_path = root / "state" / "model" / "model.json"
    model_before = model_path.read_bytes()
    raw_before = evidence_store.Read(evidence.reference)
    entity = store.Open().Objects(ObjectKind.FINDING)[0]

    pack = MappingPack.FromBytes(ReviewedBaseline().ToBytes())
    bindings = BindFindingObjectMappings(pack, entity, classifier)
    portable = json.loads(CanonicalModelJson(bindings))

    assert {binding.mapping.mapping_id for binding in bindings} == expected_ids, (
        "The production finding consumer guessed a classifier, version, or transitive relation"
    )
    assert all(record["pack_reference"] == pack.Reference()
               and record["mapping"]["review"]["mapping_reference"] == binding.mapping.Reference()
               and record["mapping"]["review"]["decision_reference"] == (
                   binding.mapping.review.decision_reference
               ) for record, binding in zip(portable, bindings, strict=True)), (
        "Serialized finding context lost its exact mapping revision or external review decision"
    )
    assert model_path.read_bytes() == model_before, "Mapping context modified canonical model state"
    assert evidence_store.Read(evidence.reference) == raw_before, (
        "Mapping context rewrote raw evidence"
    )
    assert Finding.FromObject(entity).status is FindingStatus.DISMISSED, (
        "A reviewed standards relation overrode the independent operator disposition"
    )


@pytest.mark.integration
def test_WheelResourceSupportsIsolatedOfflineConsumer(tmp_path):
    """The exact baseline must survive wheel packaging and import outside the source tree."""

    output = tmp_path / "dist"
    built = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(output)],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=60,
    )
    assert built.returncode == 0, (
        "Reviewed-baseline wheel build failed: " + built.stdout + built.stderr
    )
    wheels = tuple(output.glob("*.whl"))
    assert len(wheels) == 1, "The bounded wheel build did not produce exactly one artifact"
    baseline = ReviewedBaseline()

    with zipfile.ZipFile(wheels[0]) as archive:
        payload = archive.read("fuzzy1337/data/standards_baseline_0_2_0.json")

    assert MappingPack.FromBytes(payload) == baseline, (
        "Wheel packaging omitted or changed accountable baseline provenance"
    )
    environment = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
    executable = scripts / ("python.exe" if sys.platform == "win32" else "python")
    installed = subprocess.run(
        [str(executable), "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
         str(wheels[0])],
        cwd=tmp_path, capture_output=True, text=True, check=False, timeout=60,
    )
    assert installed.returncode == 0, (
        "Offline clean-wheel installation failed: " + installed.stdout + installed.stderr
    )
    consumer = subprocess.run(
        [str(executable), "-I", "-c",
         "from fuzzy1337.standards_mapping import ReviewedBaseline; "
         "print(ReviewedBaseline().Reference())"],
        cwd=tmp_path, capture_output=True, text=True, check=False, timeout=30,
    )
    assert consumer.returncode == 0, "Isolated wheel resource failed: " + consumer.stderr
    assert consumer.stdout.strip() == baseline.Reference(), (
        "An isolated wheel consumer loaded another mapping or review revision"
    )
