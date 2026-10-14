# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual closed image CI producer, original paired proof, saved model and three publications."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from xml.etree import ElementTree

import pytest

import fuzzy1337.ci_commands as commands
import fuzzy1337.report_commands as report_commands
from fuzzy1337.adapters import AdapterExecution
from fuzzy1337.artifact_policy import ArtifactVersionProof, GovernedArtifactExecutor
from fuzzy1337.evidence import EvidenceRecord
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.image_evidence import ImageOperationCapture
from fuzzy1337.image_workflow import RunSyntheticImageScan
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.ci_helpers import ImageCiArguments, InvokeCi
from tests.image_helpers import ORACLE, CreateOwnedImage


@pytest.mark.parametrize("scenario,expected", [("success", 1), ("no_findings", 0)])
def test_ActualImagePairUsesIndependentOracleAndAllSavedSnapshotArtifacts(
    tmp_path, scenario, expected
):
    """Actual VERSION/SCAN and all real reports agree with the independent fixture oracle."""

    owned = CreateOwnedImage(tmp_path, scenario)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    saved = LocalModelStore(owned.root).Open()
    exported = json.loads((tmp_path / "ci.json").read_bytes())
    sarif = json.loads((tmp_path / "ci.sarif").read_bytes())
    junit = ElementTree.parse(tmp_path / "ci.xml").getroot()
    assert status == expected == outcome["exit_code"], (
        "Actual image criterion exit must match the independent zero-match high/open oracle"
    )
    assert outcome["scan"]["state"] == "completed" and saved.revision == 1, (
        "A violated predicate must retain actual completed image acquisition and saved state"
    )
    assert [item["operation"] for item in outcome["scan"]["operations"]] == ["version", "scan"], (
        "Actual independently acquired VERSION must precede prerequisite-bound SCAN"
    )
    assert outcome["criterion"]["selected_count"] == outcome["criterion"]["matched_count"] == (
        ORACLE["scenarios"][scenario]["proposed_findings"]
    ), "Only original current SCAN detections enter the explicit predicate"
    assert exported["model"] == saved.ToDict() and len(sarif["runs"][0]["results"]) == (
        expected
    ) and len(junit.findall("testcase")) == expected, (
        "All actual formats preserve the same complete saved model and retained findings"
    )
    properties = {item.attrib["name"]: item.attrib["value"] for item in
                  junit.findall("properties/property")}
    assert outcome["snapshot_sha256"] == exported["snapshot_sha256"] == (
        properties["snapshot_sha256"]
    ) == sarif["runs"][0]["properties"]["canonicalSnapshotSha256"], (
        "The original complete saved model digest must bind every actual artifact"
    )

    for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
        raw = (tmp_path / filename).read_bytes()
        report = outcome["reports"][name]
        assert report["status"] == "completed" and report["output_published"] is True and (
            report["report_sha256"] == hashlib.sha256(raw).hexdigest()
        ), "Artifact outcomes must describe independently read actually published bytes"

    assert "captures" not in outcome["scan"] and outcome["scan_completeness"] == (
        properties["scan_completeness"]
    ) == "not-assessed", "Hidden original proof never becomes detached authority or completeness"
    assert len(LocalWorkspaceStore(owned.root).Open().evidence_record_references) == 12, (
        "Both operations retain separate selection receipts and their six original execution roles"
    )


def test_ImageGatePreservesPriorTriageAndUnrelatedFullReportFacts(tmp_path):
    """Current original detections inherit dismissal and unrelated history stays outside gating."""

    owned = CreateOwnedImage(tmp_path)
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True))
    assert len(summary.captures) == 2 and all(type(item) is ImageOperationCapture
                                           for item in summary.captures), (
        "Original workflow exposes its actual immutable typed captures only in the internal object"
    )
    store = LocalModelStore(owned.root)
    original = store.Open()
    finding = Findings(original)[0]
    operator = replace(finding.provenance[0], source_id="operator.test", run_reference="run:triage",
                       execution=None)
    triaged, _ = TransitionFinding(original, finding.ToObject(original.workspace_id).Reference(),
        FindingStatus.DISMISSED, operator, "Owned prior image dismissal")
    store.Save(triaged, expected_revision=original.revision)
    unrelated = Finding(finding.subject_reference, "synthetic.unrelated", "position:other",
        "Owned unrelated high finding", (replace(operator, run_reference="run:unrelated"),),
        severity=FindingSeverity.HIGH)
    with_unrelated, _ = ApplyFindings(triaged, (unrelated,))
    store.Save(with_unrelated, expected_revision=triaged.revision)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    current = next(item for item in Findings(store.Open()) if item.check_id == finding.check_id)
    assert status == 0 and outcome["criterion"]["selected_count"] == 1 and (
        outcome["criterion"]["matched_count"] == 0
    ), "Current selection uses authoritative dismissal, without unrelated-history gate matches"
    assert current.status is FindingStatus.DISMISSED and current.status_reason == (
        "Owned prior image dismissal"
    ), "Repeated image execution must retain explicit saved operator triage"
    assert len(json.loads((tmp_path / "ci.json").read_bytes())["findings"]) == 2, (
        "Unrelated retained finding remains in the complete saved report"
    )


def test_ImageProcessedNoFindingSourceRetainsHistoricalDetectionsOutsideGate(tmp_path):
    """An original newly processed no-findings source neither gates nor resolves old detections."""

    owned = CreateOwnedImage(tmp_path)
    asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True))
    selected = CreateOwnedImage(tmp_path / "new source", "no_findings")
    owned = replace(owned, selection=replace(owned.selection,
        archive=selected.selection.archive, material=selected.selection.material))
    scopes = LocalScopeStore(owned.root)
    scope = scopes.Open("image-scope")
    scopes.Save(replace(scope, targets=selected.context.scope.targets,
                        allow=selected.context.scope.allow))
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    saved = LocalModelStore(owned.root).Open()
    assert status == 0 and outcome["criterion"]["selected_count"] == 0 and (
        outcome["criterion"]["matched_count"] == 0
    ), "Original processed no-findings proof may satisfy only the acknowledged current predicate"
    assert len(Findings(saved)) == 1 and Findings(saved)[0].status is FindingStatus.OPEN and (
        len(json.loads((tmp_path / "ci.json").read_bytes())["findings"]) == 1
    ), "Absent historical detections remain open complete report facts without implicit resolution"


@pytest.mark.parametrize("mode", ["no-approval", "owner", "revoked", "before-gate",
                                  "late-revocation"])
def test_ImageCurrentAuthorityRefusalCannotBecomeSatisfiedExit(tmp_path, monkeypatch, mode):
    """Current authority must survive acquisition, gating and the final publication barrier."""

    owned = CreateOwnedImage(tmp_path, "no_findings")
    arguments = ImageCiArguments(owned, tmp_path)

    def Revoke():
        """Revoke actual currently persisted scope consent without replacing original facts."""

        scopes = LocalScopeStore(owned.root)
        scope = scopes.Open("image-scope")
        scopes.Save(replace(scope, authorization=replace(scope.authorization,
            state=AuthorizationState.REVOKED)))

    if mode == "no-approval":
        arguments.remove("--approve-safe-image")

    elif mode == "owner":
        arguments[arguments.index("--owner") + 1] = "owner:foreign"

    elif mode == "revoked":
        Revoke()

    elif mode == "before-gate":
        original_input = commands.OpenReportInput

        def Open(root):
            """Reopen actual committed model before revoking current paired authority."""

            value = original_input(root)
            Revoke()

            return value

        monkeypatch.setattr(commands, "OpenReportInput", Open)

    else:
        original = commands.PublishReport

        def Publish(destination, payload):
            """Publish original artifact bytes before revoking after the last real output."""

            original(destination, payload)

            if destination.suffix == ".xml":
                Revoke()

        monkeypatch.setattr(commands, "PublishReport", Publish)

    status, outcome = InvokeCi(arguments)
    assert status == 3 and outcome["status"] == "failed", (
        "Actual authority refusal cannot be overridden by an empty source predicate"
    )

    if mode == "late-revocation":
        assert outcome["criterion"]["status"] == "satisfied" and all(
            item["status"] == "completed" for item in outcome["reports"].values()
        ), "Original evaluated/published facts remain truthful after a later authority refusal"

    elif mode == "before-gate":
        assert outcome["criterion"]["status"] == "indeterminate" and (
            outcome["scan"]["state"] == "completed"
            and outcome["reports"]["json"]["status"] == "completed"
            and not (tmp_path / "ci.sarif").exists()
        ), "A stale original grant is refused before predicate evaluation and additional outputs"

    else:
        assert outcome["criterion"]["status"] == "indeterminate" and not (
            tmp_path / "ci.json"
        ).exists(), "Earlier refusal never invents a criterion or artifact"


@pytest.mark.parametrize("kind", ["model", "workspace"])
@pytest.mark.parametrize("acknowledged", [False, True], ids=["before-save", "lost-ack"])
def test_ImageActualStorageFailureCannotPassPredicate(tmp_path, monkeypatch, kind, acknowledged):
    """Both actual storage owners retain truthful nonzero outcomes for missing acknowledgements."""

    owned = CreateOwnedImage(tmp_path)
    selected_store = LocalModelStore if kind == "model" else LocalWorkspaceStore
    original = selected_store.Save

    def Save(self, *args, **kwargs):
        """Fail before the real save or lose its acknowledgement after its durable operation."""

        if acknowledged:
            original(self, *args, **kwargs)

        raise OSError("Owned image storage acknowledgement failure")

    monkeypatch.setattr(selected_store, "Save", Save)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    assert status == 4 and outcome["criterion"]["status"] == "indeterminate" and (
        outcome["scan"]["state"] == "failed"
    ), "Lost storage acknowledgement cannot be converted into an evaluated successful gate"
    assert LocalModelStore(owned.root).Open().revision == (
        0 if kind == "model" and not acknowledged else 1
    ), "Read-back must retain actually durable model truth without fabricating rollback"
    assert not (tmp_path / "ci.json").exists(), "Failed owning job publishes no success artifacts"


@pytest.mark.parametrize("name", ["json", "sarif", "junit"])
def test_ImageActualLostPublicationAcknowledgementRetainsPartialArtifactTruth(
    tmp_path, monkeypatch, name
):
    """Actual publication keeps its confirmed original linked bytes while refusing success."""

    owned = CreateOwnedImage(tmp_path)
    filename = {"json": "ci.json", "sarif": "ci.sarif", "junit": "ci.xml"}[name]
    original = report_commands.os.link

    def Link(source, destination, *args, **kwargs):
        """Lose acknowledgement only after the actual complete image artifact is linked."""

        original(source, destination, *args, **kwargs)

        if destination.name == filename:
            raise OSError("Owned lost image report link acknowledgement")

    monkeypatch.setattr(report_commands.os, "link", Link)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    report = outcome["reports"][name]
    assert status == 4 and outcome["scan"]["state"] == "completed" and (
        report["status"] == "failed" and report["output_published"] is True
        and (tmp_path / filename).is_file()
    ), "Completed image scan and confirmed partial publication survive lost output acknowledgement"


@pytest.mark.parametrize("mode", ["reversed", "changed-version", "changed-scan", "missing-record",
    "foreign-capture", "foreign-record", "foreign-execution", "foreign-proof",
    "changed-record-schema", "missing-inventory", "missing-relation",
    "missing-detection", "changed-asset", "changed-finding", "unsaved-basis"])
def test_ImageOriginalPairAndSavedSourceProofCannotBeSubstituted(tmp_path, monkeypatch, mode):
    """Actual successful acquisition does not lend proof to foreign, changed or unsaved facts."""

    owned = CreateOwnedImage(tmp_path)
    original = commands.EvaluateImageCriterion
    forbidden_calls = []

    class ForeignCapture(ImageOperationCapture):
        """Alternative capture implementation whose serializer must not dispatch."""

        def Envelope(self):
            """Trip an unsafe alternative serializer at the original source boundary."""

            forbidden_calls.append("capture")

            raise AssertionError("Foreign capture serializer cannot execute")

    class ForeignRecord(EvidenceRecord):
        """Alternative original-acquisition implementation cannot borrow canonical identity."""

    class ForeignExecution(AdapterExecution):
        """Alternative equal-looking executor fact cannot enter canonical source comparison."""

    class ForeignProof(ArtifactVersionProof):
        """Alternative prerequisite implementation cannot enter the typed original pair."""

    def Gate(model, captures, records, root, **options):
        """Alter exactly one consumer input after the real scan, saves and original JSON output."""

        if mode == "reversed":
            captures = tuple(reversed(captures))

        elif mode in {"changed-version", "changed-scan"}:
            index = 0 if mode == "changed-version" else 1
            altered = replace(captures[index], finished_at="2099-10-14T10:00:00Z")
            captures = tuple(altered if position == index else item
                             for position, item in enumerate(captures))

        elif mode == "missing-record":
            records = records[:-1]

        elif mode == "foreign-capture":
            capture = captures[0]
            foreign = ForeignCapture(capture.outcome, capture.prepared, capture.stage,
                                     capture.started_at, capture.finished_at)
            captures = (foreign, captures[1])

        elif mode == "foreign-record":
            record = records[0]
            records = (ForeignRecord(record.reference, record.provenance, record.schema_version),
                       *records[1:])

        elif mode == "foreign-execution":
            execution = records[0].provenance.execution
            assert execution is not None, "Original image execution provenance is retained"
            object.__setattr__(records[0].provenance, "execution", ForeignExecution(
                execution.state, execution.exit_code, execution.duration_seconds))

        elif mode == "foreign-proof":
            proof = captures[1].prepared.version_proof
            assert proof is not None, "Actual SCAN retains its original VERSION prerequisite"
            object.__setattr__(captures[1].prepared, "version_proof", ForeignProof(
                proof.outcome, proof.prepared, proof.stage))

        elif mode == "changed-record-schema":
            object.__setattr__(records[0], "schema_version", True)

        else:
            if mode in {"missing-inventory", "missing-detection"}:
                kind = "image-inventory" if mode == "missing-inventory" else "finding-detection"
                model = replace(model, observations=tuple(item for item in model.observations
                                                         if item.kind != kind))

            elif mode == "missing-relation":
                relation = model.relations[0]
                model = replace(model, relations=tuple(item for item in model.relations
                                                      if item != relation))

            else:
                entity = next(item for item in model.objects if item.identity.kind is (
                    ObjectKind.FINDING if mode == "changed-finding" else ObjectKind.ASSET))
                attributes = dict(entity.attributes)
                attributes["summary" if mode == "changed-finding" else "asset_type"] = (
                    "Owned changed interpretation")
                altered = replace(entity, attributes=attributes)
                model = replace(model, objects=tuple(altered if item is entity else item
                                                    for item in model.objects))

            options["expected_snapshot_sha256"] = ReportSnapshot(model).SnapshotDigest()

            if mode != "unsaved-basis":
                store = LocalModelStore(owned.root)
                store.WriteState(store.ValidatePaths(), model)

        return original(model, captures, records, root, **options)

    monkeypatch.setattr(commands, "EvaluateImageCriterion", Gate)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    assert status == 4 and outcome["criterion"]["status"] == "indeterminate" and not (
        forbidden_calls
    ), "Foreign serializers, original pair substitution and missing current proof fail closed"
    assert outcome["reports"]["json"]["status"] == "completed" and not (
        tmp_path / "ci.sarif"
    ).exists(), "Source proof refusal retains original JSON and never publishes later formats"


def test_ImageActualCancellationPreservesOriginalPartialOperationTruth(tmp_path, monkeypatch):
    """Actual owned execution cancellation cannot become an empty satisfied image predicate."""

    owned = CreateOwnedImage(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **kwargs):
        """Request owned cancellation after the real operation returns its original raw result."""

        result = await original(self, *args, **kwargs)
        kwargs["cancellation"].set()

        return result

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    assert status == 130 and outcome["scan"]["state"] == "cancelled" and (
        outcome["criterion"]["status"] == "indeterminate"
    ), "Actual cancellation preserves its distinct terminal category without criterion fabrication"
    assert len(outcome["scan"]["operations"]) == 1 and not (tmp_path / "ci.json").exists(), (
        "Cancelled VERSION retains only original acquired facts and publishes no success artifacts"
    )


@pytest.mark.parametrize("mode", ["digest", "size"])
def test_ImagePublishedPayloadDigestRemainsSeparateFromCanonicalModelPin(
    tmp_path, monkeypatch, mode
):
    """Actual original JSON payload acknowledgement cannot be borrowed for changed export facts."""

    owned = CreateOwnedImage(tmp_path)
    original = commands.RunSyntheticImageScan

    async def Run(*args, **kwargs):
        """Run actual acquisition/saves/publication before altering one detached outcome."""

        summary = await original(*args, **kwargs)
        assert summary.report is not None, "Actual workflow must retain its JSON export outcome"
        report = replace(summary.report, report_sha256="f" * 64) if mode == "digest" else (
            replace(summary.report, size_bytes=1))

        return replace(summary, report=report)

    monkeypatch.setattr(commands, "RunSyntheticImageScan", Run)
    status, outcome = InvokeCi(ImageCiArguments(owned, tmp_path))
    exported = json.loads((tmp_path / "ci.json").read_bytes())
    assert status == 4 and outcome["failure"] == "json-export-proof" and (
        outcome["criterion"]["status"] == "indeterminate"
    ), "Full saved model pin cannot substitute for the independently acknowledged JSON payload"
    assert exported["snapshot_sha256"] == outcome["snapshot_sha256"] and not (
        tmp_path / "ci.sarif"
    ).exists(), "Original JSON survives, while inconsistent export facts refuse later outputs"
