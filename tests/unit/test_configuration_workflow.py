# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Isolated configuration consumers with process doubles and unchanged network guards."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from configuration_helpers import CASES, FAMILY, LiveConfiguration

from fuzzy1337.adapters import AdapterExecution, ExecutionState, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent
from fuzzy1337.configuration_evidence import (
    ApplyVerifiedSyntheticConfiguration,
    ConfigurationEvidenceStore,
    ConfigurationOperationCapture,
    VerifyFactory,
    VerifySyntheticConfigurationReplay,
)
from fuzzy1337.configuration_workflow import (
    ConfigurationScanSelection,
    RunSyntheticConfigurationScan,
    SyntheticConfigurationWorkflow,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobEventKind, JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.workspace import LocalWorkspaceStore


@pytest.fixture(scope="module")
def configuration_loop() -> Iterator[asyncio.Runner]:
    """Initialize owned loop resources before the unchanged per-test network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture
def process_double(monkeypatch):
    """Provide explicit terminal-process specimens without executing a tool or opening a socket."""

    settings = {"termination": ExecutionTermination.PROCESS_EXIT, "bad_wire": False}

    async def Execute(self, request, *, on_event=None, cancellation=None, pre_launch=None):
        """Exercise pre-launch checks and return explicitly declared isolated unit facts."""

        if pre_launch is not None:
            pre_launch(request)

        policy = json.loads(Path(request.invocation.argv[5]).read_bytes())
        case = CASES[policy["case_id"]]
        selected = case["inputs"][0]["logical_path"]
        source = (Path(request.invocation.argv[-1]) / selected).read_bytes()
        kind = "dockerfile" if policy["case_id"].startswith("dockerfile") else "kubernetes"
        wire = {"schema_version": 1, "provider_id": "synthetic.trivy",
            "provider_version": "0.75.0-synthetic", "fixture_id": FAMILY,
            "profile_id": case["profile_id"], "case_id": policy["case_id"],
            "scan_completeness": "not-assessed", "file_outcomes": [{"logical_path": selected,
                "sha256": hashlib.sha256(source).hexdigest(), "size_bytes": len(source),
                "configuration_type": kind, "document_count": None if kind == "dockerfile" else (
                    2 if policy["case_id"] == "kubernetes.second-document" else 1),
                "outcome": "processed"}],
            "findings": [dict(item, outcome="failed") for item in case["expected_findings"]]}
        stdout = b"{}" if settings["bad_wire"] else SerializeContract(wire).encode()
        termination = settings["termination"]
        succeeded = termination is ExecutionTermination.PROCESS_EXIT
        state = ExecutionState.SUCCEEDED if succeeded else (
            ExecutionState.TIMED_OUT if termination is ExecutionTermination.TIMEOUT else
            ExecutionState.CANCELLED)
        execution = AdapterExecution(state,
                                     0 if succeeded else None, 0.1)
        result = LocalExecutionResult(execution, termination, stdout, b"", (
            ExecutionEvent(0, ExecutionEventKind.COMPLETED, termination=termination),))

        if settings.get("cancel"):
            cancellation.set()

        return result

    monkeypatch.setattr(LocalExecutor, "Execute", Execute)

    return settings


def UnitCapture(tmp_path, loop):
    """Recover isolated unit originals without claiming functional scanner execution."""

    root, selection, context = LiveConfiguration(tmp_path)
    summary = loop.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test", selection,
        approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.COMPLETED, "Unit process specimen must compose"
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    policy = ImpactPolicy("synthetic-configuration-safe-v1", permissions=(CapabilityPermission(
        "config.dockerfile-misconfigurations", "synthetic.trivy",
        context.policy.permissions[0].maximum_impact),))

    return root, selection, summary, records, replace(context, policy=policy)


@pytest.mark.parametrize("case_id", list(CASES))
def test_IsolatedCanonicalCompositionCoversEveryClosedSourceType(
    tmp_path, configuration_loop, process_double, case_id
):
    """Declared independent specimens exercise consumers without establishing scanner acceptance."""

    root, selection, _ = LiveConfiguration(tmp_path, case_id)
    events = []
    summary = configuration_loop.run(RunSyntheticConfigurationScan(
        root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True, on_event=events.append))
    saved = LocalModelStore(root).Open()
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0, (
        "A complete accepted unit process specimen must save canonical state"
    )
    assert len(Findings(saved)) == len(CASES[case_id]["expected_findings"]), (
        "Consumer normalization must preserve independent declared specimen counts"
    )
    assert summary.ToDict()["workflow"] == "synthetic-configuration", (
        "Summary retains workflow identity"
    )
    assert len([item for item in events if item.kind is JobEventKind.MODEL_DELTA]) == 1, (
        "Only committed state may produce a successful delta"
    )


@pytest.mark.parametrize("configuration", [
    {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 61},
    {"timeout_seconds": 1.5}, {"approve_safe_configuration": 1}, {"report_format": "json"},
    {"report_output": Path("output.json")},
])
def test_InvalidWorkflowConfigurationDeniesBeforeStorage(
    tmp_path, configuration_loop, configuration, monkeypatch
):
    """No bound coercion or implicit report destination reaches current workspace storage."""

    selection = ConfigurationScanSelection(ArtifactProfile.SYNTHETIC_DOCKERFILE, "Dockerfile",
        tmp_path, tmp_path, tmp_path, tmp_path, ArtifactReadConsent("owner:test", "read:test"))

    def Forbidden(*_args, **_kwargs):
        """Trip any owning-store access before caller contract rejection."""

        raise AssertionError("Invalid workflow configuration reached storage")

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Forbidden)

    with pytest.raises(ValueError):
        configuration_loop.run(RunSyntheticConfigurationScan(tmp_path, "scope", "owner:test",
                                                             selection, **configuration))


@pytest.mark.parametrize("termination,code", [
    (ExecutionTermination.TIMEOUT, JobFailureCode.TIMEOUT),
    (ExecutionTermination.OUTPUT_LIMIT, JobFailureCode.OUTPUT_LIMIT),
    (ExecutionTermination.CANCELLATION, JobFailureCode.PROVIDER),
])
def test_IsolatedTerminalFailureRetainsFourOriginalAcquisitions(
    tmp_path, configuration_loop, process_double, termination, code
):
    """Declared terminal failure paths retain raw facts without successful state publication."""

    process_double["termination"] = termination
    root, selection, _ = LiveConfiguration(tmp_path)
    summary = configuration_loop.run(RunSyntheticConfigurationScan(
        root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.FAILED and summary.snapshot.failure.code is code, (
        "Actual terminal process category must remain distinct from successful normalization"
    )
    assert len(summary.snapshot.artifacts) == 4 and LocalModelStore(root).Open().revision == 0, (
        "Terminal failure must keep original facts without applying a model proposal"
    )
    records = tuple(item.evidence for item in summary.snapshot.artifacts)
    assert VerifySyntheticConfigurationReplay(records, root).acceptance.refusal is not None, (
        "Historical refusal remains available for failed process facts"
    )
    assert summary.ExitCode() == 4, "Declared terminal failure cannot return success"


@pytest.mark.parametrize("mode", ["bad_wire", "cancel", "no-approval", "foreign-owner"])
def test_IsolatedRefusalAndCancellationDoNotSaveModels(
    tmp_path, configuration_loop, process_double, mode
):
    """Explicit malformed output, cancellation and missing authority preserve truthful states."""

    process_double[mode] = True
    root, selection, _ = LiveConfiguration(tmp_path)
    summary = configuration_loop.run(RunSyntheticConfigurationScan(root, "config-scope",
        "owner:foreign" if mode == "foreign-owner" else "owner:test", selection,
        approve_safe_configuration=mode != "no-approval", report_format="json",
        report_output=tmp_path / "refused.json"))
    assert summary.snapshot.state is not JobState.COMPLETED, "Refused unit specimen cannot complete"
    assert LocalModelStore(root).Open().revision == 0 and summary.report.status == "not-run", (
        "A rejected scan has no model save or report publication"
    )
    assert summary.ExitCode() != 0, "Cancellation and missing authority must preserve failure exits"


@pytest.mark.parametrize("mode", ["model", "workspace", "workspace-read", "current-scope"])
def test_IsolatedStorageFailuresPreserveFailureClassification(
    tmp_path, configuration_loop, process_double, monkeypatch, mode
):
    """Real store boundary failures cannot publish a successful model delta."""

    root, selection, _ = LiveConfiguration(tmp_path)

    def Forbidden(*_args, **_kwargs):
        """Inject one deterministic owned storage failure without exposing source content."""

        raise OSError("Owned unavailable store")

    target, method = {"model": (LocalModelStore, "Save"),
        "workspace": (LocalWorkspaceStore, "Save"),
        "workspace-read": (SyntheticConfigurationWorkflow, "PersistReferences"),
        "current-scope": (SyntheticConfigurationWorkflow, "CurrentContext")}[mode]
    monkeypatch.setattr(target, method, Forbidden)
    summary = configuration_loop.run(RunSyntheticConfigurationScan(
        root, "config-scope", "owner:test",
        selection, approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.FAILED, "Unavailable owning storage must fail the job"
    assert summary.first_model_update_seconds is None, "Storage failure cannot publish a delta"


@pytest.mark.parametrize("role", ["configuration-stdout", "configuration-stderr",
                                  "configuration-receipt", "configuration-source"])
def test_IsolatedActualRoleBudgetsPrecedeEagerStoreAllocation(
    tmp_path, configuration_loop, process_double, role
):
    """Each role enforces its declared media and byte bounds before original raw allocation."""

    root, _, summary, records, _ = UnitCapture(tmp_path, configuration_loop)
    record = next(item for item in records if item.reference.role == role)
    store = ConfigurationEvidenceStore(root / "evidence")

    for changed in (replace(record.reference, media_type="application/foreign"),
                    replace(record.reference, size_bytes=10**9),
                    replace(record.reference, role="foreign")):
        with pytest.raises(ValueError):
            store.Read(changed)

    assert summary.snapshot.state is JobState.COMPLETED, "Budget probes cannot alter success"


@pytest.mark.parametrize("value", [(), [], (None,), (None, None, None, None)])
def test_OriginalRecordCollectionShapeFailsBeforeOwningReads(tmp_path, value):
    """Missing, untyped or caller-list collections cannot masquerade as four original records."""

    with pytest.raises(ValueError):
        VerifySyntheticConfigurationReplay(value, tmp_path)


@pytest.mark.parametrize("mutation", ["field", "wire", "duplicate", "source", "provenance"])
def test_IsolatedHostileRecordsCannotProduceModelProposal(
    tmp_path, configuration_loop, process_double, mutation
):
    """Re-acquisition and typed facts cannot admit malformed wire or foreign provenance."""

    root, _, summary, records, context = UnitCapture(tmp_path, configuration_loop)
    store = LocalEvidenceStore(root / "evidence")
    selected = next(item for item in records if item.reference.role == (
        "configuration-source" if mutation == "source" else "configuration-stdout"))
    raw = store.Read(selected.reference)
    provenance = selected.provenance

    if mutation == "source":
        payload = raw + b"changed"

    elif mutation == "provenance":
        payload = raw
        provenance = replace(provenance, source_id="native.trivy")

    elif mutation == "duplicate":
        payload = b'{"schema_version":1,"schema_version":1}'

    else:
        wire = json.loads(raw)

        if mutation == "field":
            wire["extra"] = "foreign"

        else:
            wire["findings"][0]["start_line"] += 1

        payload = SerializeContract(wire).encode()

    altered = store.Put(payload, selected.reference.role, selected.reference.media_type, provenance)
    replacements = tuple(altered if item is selected else item for item in records)

    with pytest.raises(ValueError):
        ApplyVerifiedSyntheticConfiguration(LocalModelStore(root).Open(), summary.captures[0],
            replacements, root, context_provider=lambda: context)


@pytest.mark.parametrize("mutation", ["partitions", "lease", "root", "role", "consent",
    "identities", "file-order", "file-size", "invocation", "environment", "version"])
def test_IsolatedDetachedFactoryGrammarRejectsRehashedFields(
    tmp_path, configuration_loop, process_double, mutation
):
    """Updating unkeyed recorded digests never bypasses the original closed factory grammar."""

    from fuzzy1337.policy import Digest

    root, _, summary, _, _ = UnitCapture(tmp_path, configuration_loop)
    envelope = copy.deepcopy(summary.captures[0].Envelope())
    stage = envelope["stage_payload"]
    prepared = envelope["prepared_payload"]

    if mutation == "partitions":
        stage["partitions"] = []

    elif mutation == "lease":
        stage["lease"] = "foreign"

    elif mutation == "root":
        stage["root"] = prepared["workspace_root"]

    elif mutation == "role":
        stage["partitions"][0]["manifest"]["role"] = "material"

    elif mutation == "consent":
        stage["partitions"][0]["consent"]["record_ref"] = ""

    elif mutation == "identities":
        stage["partitions"][0]["identities"] = []

    elif mutation == "file-order":
        stage["partitions"][0]["identities"][0][0] = "foreign"

    elif mutation == "file-size":
        stage["partitions"][0]["identities"][0][1][2] += 1

    elif mutation == "invocation":
        prepared["invocation"]["argv"].append("--foreign")

    elif mutation == "environment":
        prepared["environment"]["PATH"] = "/foreign"

    else:
        prepared["version_run_id"] = "run:borrowed"

    envelope["artifact_metadata"]["grant"]["plan"]["request_sha256"] = Digest(prepared)
    envelope["artifact_metadata"]["grant"]["plan"]["stage_sha256"] = Digest(stage)

    with pytest.raises(ValueError):
        VerifyFactory(envelope)

    assert LocalModelStore(root).Open().revision == 1, "Read-only probes cannot mutate saved state"


@pytest.mark.parametrize("report_format", ["json", "sarif", "invalid"])
def test_IsolatedRequestedReportTruthIsSeparateFromCompletedJob(
    tmp_path, configuration_loop, process_double, report_format
):
    """Canonical report serialization/publication truth never changes the actual completed job."""

    root, selection, _ = LiveConfiguration(tmp_path)
    output = tmp_path / ("owned-report." + report_format)
    summary = configuration_loop.run(RunSyntheticConfigurationScan(root, "config-scope",
        "owner:test", selection, approve_safe_configuration=True, report_format=report_format,
        report_output=output))
    assert summary.snapshot.state is JobState.COMPLETED, "Separate export cannot undo scan"

    if report_format == "invalid":
        assert summary.report.status == "failed" and summary.ExitCode() == 4, (
            "Invalid export format is an explicit separate failure"
        )

    else:
        assert summary.report.status == "completed" and output.is_file() and (
            summary.ExitCode() == 0
        ), (
            "Successful report must be actually published from the saved model"
        )


@pytest.mark.parametrize("scenario", ["exists", "render", "interrupted", "changed", "limit"])
def test_IsolatedReportPublicationFailureKeepsActualModelTruth(
    tmp_path, configuration_loop, process_double, monkeypatch, scenario
):
    """Existing canonical report owner failures retain phase and publication outcome truth."""

    import fuzzy1337.configuration_workflow as workflow

    root, _, summary, _, _ = UnitCapture(tmp_path, configuration_loop)
    output = tmp_path / "refused-report.json"
    model = LocalModelStore(root).Open()

    if scenario == "exists":
        output.write_bytes(b"preserved owned output")

    elif scenario in {"render", "interrupted"}:
        def Render(*_args, **_kwargs):
            """Inject explicit render interruption or failure without output mutation."""

            if scenario == "interrupted":
                raise KeyboardInterrupt

            raise ValueError("Owned rendering refusal")

        monkeypatch.setattr(workflow, "SerializeJson", Render)

    elif scenario == "changed":
        model = replace(model, revision=model.revision + 1)

    else:
        monkeypatch.setattr(workflow, "MAX_REPORT_BYTES", 1)

    report = workflow.ExportConfigurationReport(root, model, "json", output)
    altered = replace(summary, report=report)
    assert report.status == "failed" and altered.ExitCode() in {4, 130}, (
        "Separate export failure must preserve a nonzero truthful exit"
    )
    assert summary.snapshot.state is JobState.COMPLETED, "Original completed job remains unchanged"


@pytest.mark.parametrize("field,value", [
    ("profile", ArtifactProfile.IMAGE), ("profile", "synthetic.dockerfile-offline.v1"),
    ("source", Path("relative")), ("executable", "absolute-text"), ("read_consent", None),
])
def test_SelectionRejectsImplicitOrForeignProfileInputs(tmp_path, field, value):
    """Typed selection does not discover paths or coerce a native/image/string source profile."""

    values = {"profile": ArtifactProfile.SYNTHETIC_DOCKERFILE, "logical_path": "Dockerfile",
        "source": tmp_path, "executable": tmp_path, "producer": tmp_path,
        "material": tmp_path, "read_consent": ArtifactReadConsent("owner:test", "read:test")}
    values[field] = value

    with pytest.raises(ValueError):
        ConfigurationScanSelection(**values)


@pytest.mark.parametrize("change", ["outcome", "prepared", "stage", "time"])
def test_CaptureConstructorRejectsForeignTypesAndInvalidChronology(
    tmp_path, configuration_loop, process_double, change
):
    """Capture fields retain exact original SDK types and a real increasing collection window."""

    _, _, summary, _, _ = UnitCapture(tmp_path, configuration_loop)
    capture = summary.captures[0]
    values = {"outcome": capture.outcome, "prepared": capture.prepared,
        "stage": capture.stage, "started_at": capture.started_at,
        "finished_at": capture.finished_at}
    values["finished_at" if change == "time" else change] = (
        capture.started_at if change == "time" else None)

    with pytest.raises(ValueError):
        ConfigurationOperationCapture(**values)


def test_IsolatedPresentationFailureCancelsAndDrainsOwningJob(
    tmp_path, configuration_loop, process_double
):
    """A failing event sink propagates after canonical cancellation and owning-job cleanup."""

    root, selection, _ = LiveConfiguration(tmp_path)

    def Observe(_event):
        """Reject event presentation without pretending the owning scan succeeded."""

        raise RuntimeError("Owned presentation failure")

    with pytest.raises(RuntimeError, match="presentation"):
        configuration_loop.run(RunSyntheticConfigurationScan(root, "config-scope", "owner:test",
            selection, approve_safe_configuration=True, on_event=Observe))

    assert not configuration_loop.get_loop().is_closed(), "Owned loop remains usable"


def test_IsolatedCallerCancellationReturnsTruthfulTerminalSummary(
    tmp_path, configuration_loop, process_double
):
    """Parent presentation cancellation preserves already completed owning-job facts."""

    root, selection, _ = LiveConfiguration(tmp_path)
    requested = False

    def Observe(_event):
        """Request one parent cancellation without forcing an invented provider outcome."""

        nonlocal requested

        if not requested:
            requested = True
            asyncio.current_task().cancel()

    summary = configuration_loop.run(RunSyntheticConfigurationScan(root, "config-scope",
        "owner:test", selection, approve_safe_configuration=True, on_event=Observe))
    assert requested and summary.snapshot.state is JobState.COMPLETED, (
        "Completed owning jobs retain original completion after presentation cancellation"
    )
    assert not summary.snapshot.cancellation_requested and (
        LocalModelStore(root).Open().revision == 1
    ), (
        "Presentation cancellation cannot invent a late job cancellation or erase committed state"
    )
