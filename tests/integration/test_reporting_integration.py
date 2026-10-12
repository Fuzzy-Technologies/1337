# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned model/evidence storage consumed by deterministic side-effect-free report exports."""

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema.validators import validator_for

from fuzzy1337.adapters.contracts import AdapterExecution, ExecutionState
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingSeverity
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.reporting import (
    FindingReferences,
    ReportReference,
    ReportSnapshot,
    VerifyReportEvidence,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.test_reporting_contract import Validator

EXPORTERS = (RenderHtml, SerializeJson, SerializeSarif, SerializeJunit)


def Context(tmp_path: Path, workspace_id="synthetic"):
    """Create an owned workspace and failed synthetic acquisition with verifiable bytes."""

    root = tmp_path / workspace_id
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Report integration"), workspace_id)
    execution = AdapterExecution(ExecutionState.FAILED, 2, 0.1)
    raw = b"SYNTHETIC_RAW_ONLY_1337_REPORT_9c3ad34"
    evidence = LocalEvidenceStore(root / "evidence").Put(
        raw, "stdout", "text/plain", EvidenceProvenance(
            workspace_id, "scope:local", "synthetic", "1", "fixture-1",
            "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z", execution=execution,
        ),
    )
    provenance = ModelProvenance(
        "synthetic", evidence.evidence_id, "2026-10-13T00:00:01Z", "scope:local", "target:local",
        evidence_references=(evidence.reference,), execution=execution,
    )
    host = SecurityObject(
        ObjectIdentity(workspace_id, ObjectKind.HOST, "127.0.0.1"), {}, (provenance,),
    )
    store = LocalModelStore(root)
    initial = store.Create()
    state, delta = initial.Apply(objects=(host,))
    store.Save(state, expected_revision=delta.previous_revision)
    finding = Finding(
        host.Reference(), "synthetic.report-check", "tcp/443",
        "Synthetic retained interpretation", (provenance,), FindingSeverity.HIGH, 0.75,
    )
    state, delta = ApplyVerifiedFindings(state, (finding,), root)
    store.Save(state, expected_revision=delta.previous_revision)
    binding = FindingReferences(
        finding.ToObject(workspace_id).Reference(), (ReportReference("cwe", "CWE-89", "4.20"),),
        "Synthetic context only; no actual weakness match is asserted", provenance,
    )

    return root, ReportSnapshot(store.Open(), (binding,)), evidence, raw


def Files(root: Path):
    """Capture only bytes beneath this test's explicitly owned workspace."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_RealEvidenceVerificationFeedsAllFormatsWithoutWritingOrEmbeddingRawBytes(tmp_path):
    """Report verification preserves storage and the original failed acquisition outcome."""

    root, report, evidence, raw = Context(tmp_path)
    original = Files(root)
    checked = VerifyReportEvidence(report, root)
    document = json.loads(SerializeJson(checked))
    Validator().validate(document)

    assert document["evidence_integrity"]["unverified_count"] == 0, "Owned bytes stayed unverified"
    assert document["evidence_integrity"]["checked_references"] == [
        json.loads(SerializeJson(report))["evidence_integrity"]["linked_references"][0],
    ], "Verifier substituted another artifact identity"
    assert document["summary"]["failed_acquisitions"] == 1, "Execution failure became success"
    assert b"verified bytes" in RenderHtml(checked), "HTML lost checked byte integrity"
    assert b"not verified" in RenderHtml(report), "Pure report inherited a byte check"

    for exporter in EXPORTERS:
        output = exporter(checked)
        assert raw not in output, "Report embedded acquired raw content"
        assert str(root).encode("utf-8") not in output, "Report leaked a local installation path"

    assert Files(root) == original, "Report verification/export wrote workspace data"
    assert LocalEvidenceStore(root / "evidence").Read(evidence.reference) == raw, (
        "Report verification changed immutable artifact bytes"
    )


def test_VerifiedReportsStayByteIdenticalAfterWorkspaceRelocation(tmp_path):
    """Output binds logical snapshot/evidence identities rather than physical workspace paths."""

    root, report, _, _ = Context(tmp_path)
    checked = VerifyReportEvidence(report, root)
    before = [exporter(checked) for exporter in EXPORTERS]
    moved = tmp_path / "relocated workspace"
    shutil.move(str(root), moved)
    reopened = replace(report, state=LocalModelStore(moved).Open())
    relocated = VerifyReportEvidence(reopened, moved)

    assert [exporter(relocated) for exporter in EXPORTERS] == before, (
        "Moving an owned workspace changed a deterministic report"
    )


@pytest.mark.parametrize("failure", ["missing", "corrupt", "wrong-size", "symlink"])
def test_ReportIntegrityVerificationFailsClosedOnInvalidEvidence(tmp_path, failure):
    """Artifact failures never return a partially verified projection or rewrite source state."""

    root, report, evidence, _ = Context(tmp_path)
    model_bytes = (root / "state" / "model" / "model.json").read_bytes()
    artifact = root / "evidence" / evidence.reference.locator

    if failure == "missing":
        artifact.unlink()

    elif failure == "corrupt":
        artifact.write_bytes(b"x" * evidence.reference.size_bytes)

    elif failure == "symlink":
        target = root / "owned-synthetic-copy"
        target.write_bytes(artifact.read_bytes())
        artifact.unlink()

        try:
            artifact.symlink_to(target)

        except OSError:
            pytest.skip("Platform does not permit synthetic symlinks")

    else:
        modified = replace(evidence.reference, size_bytes=evidence.reference.size_bytes + 1)
        provenance = replace(
            report.reference_bindings[0].provenance, evidence_references=(modified,),
        )
        objects = tuple(replace(item, provenance=(provenance,)) for item in report.state.objects)
        state = replace(report.state, objects=objects, observations=())
        report = ReportSnapshot(state)

    with pytest.raises(EvidenceError):
        VerifyReportEvidence(report, root)

    assert report.ToDict()["evidence_integrity"]["checked_references"] == [], (
        "Failed verification mutated the original pure report"
    )
    assert (root / "state" / "model" / "model.json").read_bytes() == model_bytes, (
        "Failed report verification wrote source model state"
    )


def test_ReportVerificationRequiresTheActualOwningWorkspace(tmp_path):
    """The verifier cannot use another workspace as an artifact authority."""

    _, report, _, _ = Context(tmp_path)
    foreign, _, _, _ = Context(tmp_path, "foreign")

    with pytest.raises(ValueError, match="workspace"):
        VerifyReportEvidence(report, foreign)

    with pytest.raises(ValueError, match="ReportSnapshot"):
        VerifyReportEvidence({}, foreign)


def test_VerifierReadsSharedReferenceExactlyOnceAndNeverAuthorizesAScan(tmp_path, monkeypatch):
    """Real byte verification deduplicates references without changing model state."""

    root, report, evidence, _ = Context(tmp_path)
    calls = []
    original = LocalEvidenceStore.Read

    def Read(self, reference):
        """Observe actual integrity reads without replacing the evidence-store implementation."""

        calls.append(reference)

        return original(self, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    checked = VerifyReportEvidence(report, root)

    assert calls == [evidence.reference], "Shared evidence was checked repeatedly"
    assert checked.state is report.state, "Report verification forked canonical workspace state"


def test_GeneratedSarifValidatesAgainstPinnedOfficialSchema(tmp_path):
    """The actual report adapter matches the official offline SARIF 2.1.0 schema."""

    _, report, _, _ = Context(tmp_path)
    schema_path = (
        Path(__file__).parents[1] / "contract" / "fixtures" / "reporting"
        / "sarif-schema-2.1.0.json"
    )
    schema = json.loads(schema_path.read_text("utf-8"))
    assert hashlib.sha256(schema_path.read_bytes()).hexdigest() == (
        "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
    ), "Official SARIF schema content changed without provenance review"
    validator = validator_for(schema)(schema)
    validator.validate(json.loads(SerializeSarif(report)))
