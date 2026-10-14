# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual public CI handler, owned execution, durable source gate and report publication."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from xml.etree import ElementTree

import pytest
from configuration_helpers import CASES, CORPUS, ORACLE, LiveConfiguration

import fuzzy1337.ci_commands as commands
import fuzzy1337.configuration_workflow as workflow
import fuzzy1337.report_commands as report_commands
from fuzzy1337.artifact_inputs import ArtifactManifest
from fuzzy1337.artifact_policy import GovernedArtifactExecutor, PrepareArtifact
from fuzzy1337.ci_gate import CiFindingCriterion
from fuzzy1337.configuration_workflow import RunSyntheticConfigurationScan
from fuzzy1337.evidence import EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import ExecutionResources
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.model import LocalModelStore, ModelState
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConflictError
from tests.ci_helpers import CiArguments, InvokeCi


@pytest.mark.parametrize("case_id", list(CASES), ids=list(CASES))
def test_ActualCommandMatchesHandwrittenSourceOracleAndPublishesAllFormats(tmp_path, case_id):
    """Real SCAN/save/gate/export uses independent expected configuration positions and counts."""

    root, selection, _ = LiveConfiguration(tmp_path, case_id)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    expected = CASES[case_id]["expected_findings"]
    expected_status = 1 if expected else 0
    saved = LocalModelStore(root).Open()
    exported = json.loads((tmp_path / "ci.json").read_bytes())
    sarif = json.loads((tmp_path / "ci.sarif").read_bytes())
    junit = ElementTree.parse(tmp_path / "ci.xml").getroot()
    assert status == expected_status == outcome["exit_code"], (
        "Actual terminal exit must match the independently declared high/open zero-match oracle"
    )
    assert outcome["scan"]["state"] == "completed" and saved.revision == 1, (
        "Criterion violation must retain a completed actual scan and its durable saved revision"
    )
    criterion = outcome["criterion"]
    assert criterion["selected_count"] == criterion["matched_count"] == len(expected), (
        "Source-proven current detections must match independent expected counts"
    )
    assert exported["model"] == saved.ToDict() and exported["snapshot_sha256"] == (
        outcome["snapshot_sha256"]
    ), "JSON must project the exact saved complete model rather than count/revision heuristics"
    assert len(sarif["runs"][0]["results"]) == len(expected) and len(junit.findall("testcase")) == (
        len(expected)
    ), "All actual report formats must preserve the same retained finding facts"
    properties = {item.attrib["name"]: item.attrib["value"] for item in
                  junit.findall("properties/property")}
    assert properties["snapshot_sha256"] == outcome["snapshot_sha256"] == (
        sarif["runs"][0]["properties"]["canonicalSnapshotSha256"]
    ), "Every artifact must retain exactly the saved JSON's complete model digest"

    for name, filename in (("json", "ci.json"), ("sarif", "ci.sarif"), ("junit", "ci.xml")):
        raw = (tmp_path / filename).read_bytes()
        report = outcome["reports"][name]
        assert report["status"] == "completed" and report["output_published"] is True, (
            "Each requested artifact needs actual complete publication evidence"
        )
        assert report["report_sha256"] == hashlib.sha256(raw).hexdigest(), (
            "Reported artifact digest must match actual published original bytes"
        )
        assert ORACLE["raw_only_marker"].encode() not in raw and b"owned.invalid" not in raw, (
            "Private selected source bytes must remain raw-only evidence"
        )

    assert outcome["acknowledge_unassessed_completeness"] is True and (
        outcome["scope"] == "selected-profile-finding-predicate"
        and outcome["scan_completeness"] == properties["scan_completeness"] == "not-assessed"
    ), "Satisfied source predicate must remain distinct from global clean/completeness claims"


@pytest.mark.parametrize("option,value", [("--severity", "medium"), ("--max-matches", "1")])
def test_ActualCallerSelectedPredicateCanSatisfyWithRetainedHighFinding(tmp_path, option, value):
    """Caller selections determine criterion satisfaction without hiding the retained finding."""

    root, selection, _ = LiveConfiguration(tmp_path)
    arguments = CiArguments(root, selection, tmp_path)
    arguments[arguments.index(option) + 1] = value
    status, outcome = InvokeCi(arguments)
    assert status == 0 and outcome["criterion"]["selected_count"] == 1, (
        "Explicit label/count choices may satisfy while retaining the actual selected finding"
    )
    assert len(json.loads((tmp_path / "ci.json").read_bytes())["findings"]) == 1, (
        "Full reports must preserve findings independently from predicate satisfaction"
    )


def test_ActualPriorTriageIsAuthoritativeAndUnrelatedFindingsStayOutsideGate(tmp_path):
    """Fresh original detections preserve dismissal; unrelated saved findings remain in exports."""

    root, selection, _ = LiveConfiguration(tmp_path)
    asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test", selection,
                                            approve_safe_configuration=True))
    store = LocalModelStore(root)
    original = store.Open()
    finding = Findings(original)[0]
    operator = replace(finding.provenance[0], source_id="operator.test", run_reference="run:triage",
                       execution=None)
    triaged, _ = TransitionFinding(original, finding.ToObject(original.workspace_id).Reference(),
        FindingStatus.DISMISSED, operator, "Owned prior operator dismissal")
    store.Save(triaged, expected_revision=original.revision)
    unrelated = Finding(finding.subject_reference, "synthetic.unrelated", "position:other",
        "Owned unrelated high finding", (replace(operator, run_reference="run:unrelated"),),
        severity=FindingSeverity.HIGH)
    with_unrelated, _ = ApplyFindings(triaged, (unrelated,))
    store.Save(with_unrelated, expected_revision=triaged.revision)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    saved = store.Open()
    assert status == 0 and outcome["criterion"]["selected_count"] == 1 and (
        outcome["criterion"]["matched_count"] == 0
    ), "Only the current source detection enters the gate with its saved authoritative disposition"
    current = next(item for item in Findings(saved) if item.check_id == finding.check_id)
    assert current.status is FindingStatus.DISMISSED and current.status_reason == (
        "Owned prior operator dismissal"
    ), "New execution must preserve explicit saved triage"
    assert len(json.loads((tmp_path / "ci.json").read_bytes())["findings"]) == 2, (
        "Unrelated retained finding stays visible in complete snapshot exports"
    )


def test_NewNoFindingSourceDoesNotResolveOrGateHistoricalDetection(tmp_path):
    """A processed new source may yield zero selected detections while retaining older findings."""

    root, selection, _ = LiveConfiguration(tmp_path)
    asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test", selection,
                                            approve_safe_configuration=True))
    case = CASES["dockerfile.non-root-user"]
    selection.source.write_bytes((CORPUS / case["inputs"][0]["fixture"]).read_bytes())
    material = json.loads(selection.material.read_bytes())
    material["case_id"] = "dockerfile.non-root-user"
    selection.material.write_text(json.dumps(material))
    selected = selection.Stage(root / "selected-new-source")
    target = selected.input.manifest.Target()
    scopes = LocalScopeStore(root)
    scopes.Save(replace(scopes.Open("config-scope"), targets=(target,), allow=(target,)))
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    saved = LocalModelStore(root).Open()
    assert status == 0 and outcome["criterion"]["selected_count"] == 0, (
        "Proven processed new source with no detections may satisfy the acknowledged criterion"
    )
    assert len(Findings(saved)) == 1 and Findings(saved)[0].status is FindingStatus.OPEN, (
        "Absent historical detections cannot be resolved or enter a different source gate"
    )


@pytest.mark.parametrize("mode", ["no-approval", "foreign-owner", "revoked"])
def test_ActualAuthorityRefusalCannotProduceCriterionOrReports(tmp_path, mode):
    """Missing SAFE opt-in, changed recorded actor and revoked consent fail through real owners."""

    root, selection, _ = LiveConfiguration(tmp_path)
    arguments = CiArguments(root, selection, tmp_path)

    if mode == "no-approval":
        arguments.remove("--approve-safe-configuration")

    elif mode == "foreign-owner":
        arguments[arguments.index("--owner") + 1] = "owner:foreign"

    else:
        store = LocalScopeStore(root)
        scope = store.Open("config-scope")
        store.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

    status, outcome = InvokeCi(arguments)
    assert status == 3 and outcome["criterion"]["status"] == "indeterminate", (
        "Actual authority refusal must retain its nonzero terminal classification"
    )
    assert LocalModelStore(root).Open().revision == 0 and not (tmp_path / "ci.json").exists(), (
        "Denied launch has no saved findings or fabricated report publication"
    )


@pytest.mark.parametrize("mode", ["conflict", "model-lost-ack", "workspace-lost-ack"])
def test_ActualSaveUncertaintyCannotProduceCriterionSuccess(tmp_path, monkeypatch, mode):
    """Actual CAS/write acknowledgements retain saved revision uncertainty and never pass."""

    root, selection, _ = LiveConfiguration(tmp_path)
    owner = LocalWorkspaceStore if mode == "workspace-lost-ack" else LocalModelStore
    original = owner.Save

    def Save(self, *args, **kwargs):
        """Inject conflict or lose the acknowledgement after the actual owning save completes."""

        if mode == "conflict":
            raise WorkspaceConflictError("Owned CI conflict")

        original(self, *args, **kwargs)

        raise OSError("Owned lost acknowledgement")

    monkeypatch.setattr(owner, "Save", Save)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    expected_revision = 0 if mode == "conflict" else 1
    assert status == 4 and outcome["model_revision"] == expected_revision and (
        LocalModelStore(root).Open().revision == expected_revision
    ), "Storage failure retains reopened revision without treating lost acknowledgement as PASS"
    assert outcome["criterion"]["status"] == "indeterminate" and (
        outcome["scan"]["state"] == "failed"
    ), "A failed storage contract cannot claim an evaluated successful gate"


def test_ActualOutputLimitPreservesOriginalFailureAndEvidence(tmp_path, monkeypatch):
    """The reviewed worker's bounded truncated output fails without model/report fabrication."""

    root, selection, _ = LiveConfiguration(tmp_path)

    def Prepare(stage, workspace_root, **options):
        """Select a tighter owning resource cap before actual matching grant issuance."""

        return PrepareArtifact(stage, workspace_root, resources=ExecutionResources(
            max_stdout_bytes=3, max_stderr_bytes=16 * 1024), **options)

    monkeypatch.setattr(workflow, "PrepareArtifact", Prepare)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert status == 4 and outcome["failure"] == "output_limit", (
        "Actual output limit must retain its original failure classification"
    )
    assert len(LocalWorkspaceStore(root).Open().evidence_record_references) == 4 and (
        LocalModelStore(root).Open().revision == 0
    ), "Original bounded streams/source/receipt remain retained without model fabrication"


def test_ActualOwningCancellationCannotBecomeEmptySatisfiedGate(tmp_path, monkeypatch):
    """Cooperative cancellation after real execution preserves acquired originals and exit130."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **kwargs):
        """Request actual owned cancellation immediately after the real reviewed worker returns."""

        result = await original(self, *args, **kwargs)
        kwargs["cancellation"].set()

        return result

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert status == 130 and outcome["scan"]["state"] == "cancelled" and (
        outcome["criterion"]["status"] == "indeterminate"
    ), "Canonical cancellation must remain distinct from failed and satisfied criterion states"


@pytest.mark.parametrize("name", ["json", "sarif", "junit"])
def test_ActualLostReportLinkAcknowledgementRetainsPartialPublication(tmp_path, monkeypatch, name):
    """The real publication owner confirms lost acknowledgements by private physical identity."""

    root, selection, _ = LiveConfiguration(tmp_path)
    filename = {"json": "ci.json", "sarif": "ci.sarif", "junit": "ci.xml"}[name]
    original = report_commands.os.link

    def Link(source, destination, *args, **kwargs):
        """Lose one acknowledgement only after the actual complete artifact is linked."""

        original(source, destination, *args, **kwargs)

        if destination.name == filename:
            raise OSError("Owned lost report link acknowledgement")

    monkeypatch.setattr(report_commands.os, "link", Link)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    report = outcome["reports"][name]
    assert status == 4 and outcome["scan"]["state"] == "completed", (
        "Separate report uncertainty must not erase the actual completed scanner job"
    )
    assert report["status"] == "failed" and report["output_published"] is True and (
        (tmp_path / filename).is_file()
    ), "Lost-link acknowledgement retains confirmed original artifact publication without PASS"


def test_FinalFreshAuthorityBarrierRefusesAfterAllReportsPublish(tmp_path, monkeypatch):
    """Late revocation preserves complete artifacts and evaluated facts while refusing exit0."""

    root, selection, _ = LiveConfiguration(tmp_path, "dockerfile.non-root-user")
    original = commands.PublishReport

    def Publish(destination, payload):
        """Publish actual bytes, then revoke current consent after the last artifact."""

        original(destination, payload)

        if destination.suffix == ".xml":
            store = LocalScopeStore(root)
            scope = store.Open("config-scope")
            store.Save(replace(scope, authorization=replace(scope.authorization,
                                                           state=AuthorizationState.REVOKED)))

    monkeypatch.setattr(commands, "PublishReport", Publish)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert status == 3 and outcome["status"] == "failed" and (
        outcome["criterion"]["status"] == "satisfied"
    ), "Evaluated predicate truth cannot override the final current authority refusal"
    assert all(report["status"] == "completed" for report in outcome["reports"].values()), (
        "Actual completed artifact truth must survive a later current authority refusal"
    )


@pytest.mark.parametrize("mode", ["revision", "same-revision-content"])
def test_CompleteSavedBasisCannotBeSubstitutedAfterJsonExport(tmp_path, monkeypatch, mode):
    """The saved complete JSON digest rejects both newer snapshots and equal-revision content."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = commands.OpenReportInput

    def Open(selected_root):
        """Change the actual owned model before the CI consumer reopens the canonical report."""

        store = LocalModelStore(root)
        saved = store.Open()

        if mode == "revision":
            store.Save(replace(saved, revision=saved.revision + 1),
                       expected_revision=saved.revision)

        else:
            entity = next(item for item in saved.objects if item.identity.kind.value == "asset")
            altered = replace(entity, attributes=dict(entity.attributes, injected="owned-change"))
            store.WriteState(store.ValidatePaths(), replace(saved, objects=tuple(
                altered if item is entity else item for item in saved.objects)))

        return original(selected_root)

    monkeypatch.setattr(commands, "OpenReportInput", Open)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert status == 4 and outcome["failure"] == "input-changed" and (
        outcome["reports"]["json"]["status"] == "completed"
        and outcome["reports"]["sarif"]["status"] == "not-run"
    ), "Original JSON pin cannot silently substitute a changed basis for gate or later artifacts"


@pytest.mark.parametrize("mode", ["foreign-model", "foreign-criterion", "foreign-record",
    "foreign-manifest", "changed-capture", "foreign-provenance", "missing-inventory",
    "missing-detection", "changed-asset", "changed-finding", "unsaved-basis"])
def test_ActualPublicGateRejectsForeignTypesOriginalSubstitutionAndMissingProof(
    tmp_path, monkeypatch, mode
):
    """Actual execution cannot lend its receipts to changed typed inputs or missing source proof."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = commands.EvaluateConfigurationCriterion
    forbidden_calls = []
    reached_gate = []

    class ForeignModel(ModelState):
        """Hostile equivalent wrapper whose serializer must never be called."""

        def ToDict(self):
            """Record an unsafe foreign serializer dispatch for the independent test oracle."""

            forbidden_calls.append("model")

            raise AssertionError("Foreign serializer must be refused before dispatch")

    class ForeignCriterion(CiFindingCriterion):
        """Foreign criterion implementation cannot borrow the exact consumer contract."""

    class ForeignRecord(EvidenceRecord):
        """Foreign acquisition wrapper cannot borrow an original immutable owning manifest."""

    class ForeignManifest(ArtifactManifest):
        """Hostile selected-manifest wrapper whose serializer cannot enter original replay."""

        def ToDict(self):
            """Trip forbidden foreign method execution before the canonical owner is reached."""

            forbidden_calls.append("manifest")

            raise AssertionError("Foreign selected manifest must be refused before dispatch")

    def Gate(model, capture, records, selected_root, **options):
        """Inject one hostile public-boundary specimen after actual scan/JSON persistence."""

        if mode == "foreign-model":
            model = ForeignModel(model.workspace_id, model.revision, model.objects,
                                 model.relations, model.observations)

        elif mode == "foreign-criterion":
            criterion = options["criterion"]
            options["criterion"] = ForeignCriterion(criterion.severities, criterion.statuses,
                criterion.max_matches, criterion.acknowledge_unassessed_completeness)

        elif mode == "foreign-record":
            record = records[0]
            foreign = ForeignRecord(record.reference, record.provenance, record.schema_version)
            records = (foreign, *records[1:])

        elif mode == "foreign-manifest":
            manifest = capture.outcome.manifests[0]
            foreign = ForeignManifest(manifest.profile, manifest.role, manifest.files,
                                      manifest.schema_version)
            object.__setattr__(capture.outcome, "manifests",
                               (foreign, *capture.outcome.manifests[1:]))

        elif mode == "changed-capture":
            capture = replace(capture, finished_at="2099-10-14T10:00:00Z")

        elif mode == "foreign-provenance":
            store = LocalEvidenceStore(root / "evidence")
            record = records[0]
            foreign = store.Put(store.Read(record.reference), record.reference.role,
                record.reference.media_type, replace(record.provenance, source_id="foreign.test"))
            records = (foreign, *records[1:])

        else:
            if mode in {"missing-inventory", "missing-detection"}:
                missing_kind = "configuration-inventory" if mode == "missing-inventory" else (
                    "finding-detection")
                model = replace(model, observations=tuple(item for item in model.observations
                                                         if item.kind != missing_kind))

            else:
                entity = next(item for item in model.objects if item.identity.kind.value == (
                    "finding" if mode == "changed-finding" else "asset"))
                attributes = dict(entity.attributes)
                attributes["summary" if mode == "changed-finding" else "asset_type"] = (
                    "Owned changed interpretation")
                altered = replace(entity, attributes=attributes)
                model = replace(model, objects=tuple(altered if item is entity else item
                                                    for item in model.objects))

            options["expected_snapshot_sha256"] = ReportSnapshot(model).SnapshotDigest()

            if mode != "unsaved-basis":
                store = LocalModelStore(root)
                store.WriteState(store.ValidatePaths(), model)

        reached_gate.append(mode)

        return original(model, capture, records, selected_root, **options)

    monkeypatch.setattr(commands, "EvaluateConfigurationCriterion", Gate)
    status, outcome = InvokeCi(CiArguments(root, selection, tmp_path))
    assert reached_gate == [mode], (
        "The hostile specimen must reach the actual gate, without constructor-error false positives"
    )
    assert status == 4 and outcome["criterion"]["status"] == "indeterminate" and (
        outcome["scan"]["state"] == "completed"
    ), "Original successful execution cannot authorize a substituted or unproven gate input"
    assert not forbidden_calls and outcome["reports"]["json"]["status"] == "completed" and (
        not (tmp_path / "ci.sarif").exists()
    ), "Foreign methods must not dispatch, and failed proof cannot publish later report formats"


def test_ActualForeignAcquisitionRefusesBeforeAnyReaderOrAuthorityLookup(tmp_path, monkeypatch):
    """A correctly constructed equivalent foreign manifest fails at the actual typed gate."""

    root, selection, _ = LiveConfiguration(tmp_path)
    summary = asyncio.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.ExitCode() == 0 and len(summary.captures) == 1, (
        "The source boundary test requires actual accepted execution and durable original proof"
    )
    model = LocalModelStore(root).Open()
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    source = records[0]

    class ForeignRecord(EvidenceRecord):
        """A correctly initialized alternative implementation cannot borrow manifest authority."""

    foreign = ForeignRecord(source.reference, source.provenance, source.schema_version)
    assert foreign.evidence_id == source.evidence_id and foreign.ToDict() == source.ToDict(), (
        "Foreign specimen construction succeeds and preserves the same canonical manifest bytes"
    )
    altered = (foreign, *records[1:])
    criterion = CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True)
    pin = ReportSnapshot(model).SnapshotDigest()
    forbidden_calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip any owning read or fresh authority lookup after exact foreign type refusal."""

        forbidden_calls.append("reader-or-authority")

        raise AssertionError("Foreign acquisition reached a reader or authority boundary")

    monkeypatch.setattr(LocalModelStore, "Open", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Get", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    monkeypatch.setattr(GovernedArtifactExecutor, "ValidateAcceptanceFresh", Forbidden)

    with pytest.raises(ValueError, match="exact original acquisition contracts"):
        commands.EvaluateConfigurationCriterion(model, summary.captures[0], altered, root,
            expected_snapshot_sha256=pin, criterion=criterion, context_provider=Forbidden)

    assert not forbidden_calls, "Foreign acquisition is refused before storage or authority reads"
