# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual configuration CLI collection, durable reopening, replay and failure outcomes."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest
from configuration_helpers import CASES, ORACLE, LiveConfiguration

from fuzzy1337 import configuration_workflow
from fuzzy1337.artifact_inputs import ArtifactProfile
from fuzzy1337.artifact_policy import GovernedArtifactExecutor
from fuzzy1337.cli import Main
from fuzzy1337.configuration_evidence import VerifySyntheticConfigurationReplay
from fuzzy1337.configuration_workflow import ConfigurationScanSelection
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import ExecutionResources
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConflictError


def ConfigurationCliArguments(root: Path, selection: ConfigurationScanSelection,
                              *, approval: bool = True) -> list[str]:
    """Select exact reviewed source/runtime/worker/material and consent through the product."""

    source_type = "dockerfile" if selection.profile is ArtifactProfile.SYNTHETIC_DOCKERFILE else (
        "kubernetes")
    arguments = ["scan", "config", str(root), "--profile", "synthetic", "--type", source_type,
        "--logical-path", selection.logical_path, "--source", str(selection.source),
        "--scope", "config-scope", "--owner", "owner:test",
        "--executable", str(selection.executable), "--producer", str(selection.producer),
        "--material", str(selection.material),
        "--read-consent-reference", selection.read_consent.record_ref]

    if approval:
        arguments.append("--approve-safe-configuration")

    return arguments


def Console(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the actual installed module entry in an owned process with bounded cleanup."""

    return subprocess.run([sys.executable, "-m", "fuzzy1337", *arguments],
                          text=True, capture_output=True, timeout=60, check=False)


@pytest.mark.parametrize("case_id,report_format", [
    ("dockerfile.root-user", "sarif"), ("dockerfile.non-root-user", "json"),
    ("kubernetes.privileged-container", "sarif"),
    ("kubernetes.non-privileged-container", "json"), ("kubernetes.second-document", "sarif"),
], ids=["root", "nonroot", "privileged", "safe", "second-doc"])
def test_ActualConsoleCreatesScopeCollectsEveryReviewedCaseReopensAndReplays(
    tmp_path, case_id, report_format
):
    """Public subprocess commands drive real worker execution into durable canonical state."""

    _, selection, context = LiveConfiguration(tmp_path, case_id)
    root = tmp_path / "CLI workspace with spaces"
    created = Console(["workspace", "create", str(root), "--id", "cli-config", "--name", "Config"])
    assert created.returncode == 0 and not created.stderr, "CLI creates the explicit workspace"
    authority = context.scope.authorization
    scoped = Console(["scope", "create", str(root), "--id", "config-scope", "--allow-artifact",
        context.scope.targets[0].value, "--grant-consent", "--owner", authority.authority_reference,
        "--consent-reference", authority.record_reference, "--valid-from", authority.valid_from,
        "--valid-until", authority.valid_until])
    assert scoped.returncode == 0 and not scoped.stderr, "CLI records exact manifest authority"
    output = tmp_path / ("configuration report." + report_format)
    completed = Console([*ConfigurationCliArguments(root, selection), "--events-json",
        "--report-format", report_format, "--report-output", str(output)])
    assert completed.returncode == 0 and not completed.stderr, (
        "Actual closed subprocess CLI must complete execution, durable saves and requested export"
    )
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    summary = messages[-1]["summary"]
    assert messages[-1]["type"] == "summary" and (
        [message["event"] for message in messages[:-1]] == summary["events"]
    ), "Streamed events must preserve exact canonical identity before one terminal summary"
    assert summary["workflow"] == "synthetic-configuration" and (
        summary["source_id"] == "synthetic.trivy" and summary["state"] == "completed"
    ), "CLI must identify the actual closed synthetic workflow"
    assert summary["scan_completeness"] == "not-assessed", (
        "Reviewed source execution must not imply native configuration scan completeness"
    )
    assert [operation["operation"] for operation in summary["operations"]] == ["scan"], (
        "Configuration summary must retain the original SCAN-only SDK outcome"
    )
    model = LocalModelStore(root).Open()
    workspace = LocalWorkspaceStore(root).Open()
    findings = Findings(model)
    expected = CASES[case_id]["expected_findings"]
    assert model.revision == summary["model_revision"] == 1 and len(findings) == len(expected), (
        "CLI summary and independent fixture detection count must match saved canonical state"
    )

    for finding, oracle in zip(findings, expected, strict=True):
        assert json.loads(finding.location_key) == {key: oracle[key] for key in (
            "start_line", "end_line", "document_index", "resource_selector")}, (
            "Exact source line/document/resource coordinates must survive CLI normalization"
        )

    assets = model.Objects(ObjectKind.ASSET)
    assert len(assets) == 1 and assets[0].identity.key.startswith("synthetic:configuration:"), (
        "Configuration assets remain in the reviewed synthetic source family"
    )
    store = LocalEvidenceStore(root / "evidence")
    records = tuple(store.Get(record_id) for record_id in workspace.evidence_record_references)
    assert len(records) == 4 and {record.reference.role for record in records} == {
        "configuration-stdout", "configuration-stderr", "configuration-receipt",
        "configuration-source",
    }, "Reopened CLI workspace must retain all original four acquisition roles"
    replay = VerifySyntheticConfigurationReplay(records, root)
    assert replay.acceptance.refusal is None, "Replay must retain original SDK acceptance"
    assert summary["report"]["status"] == "completed" and summary["report"]["output_published"], (
        "Requested export must confirm actual publication separately from scan completion"
    )
    report = json.loads(output.read_bytes())

    if report_format == "json":
        assert report["model"] == model.ToDict() and (
            report["scan_completeness"] == "not-assessed"
        ), (
            "JSON projects exact durable canonical model without a clean-scan claim"
        )

    else:
        assert len(report["runs"][0]["results"]) == len(expected), (
            "SARIF must preserve the independent reviewed source detection count"
        )

    assert ORACLE["raw_only_marker"] not in output.read_text(encoding="utf-8"), (
        "Private selected source text must remain raw evidence rather than a report field"
    )
    reopened = Console(["workspace", "open", str(root), "--json"])
    assert reopened.returncode == 0 and not reopened.stderr, "CLI reopens all saved acquisitions"
    document = json.loads(reopened.stdout)
    assert document["model_revision"] == 1 and document["verified_evidence_records"] == 4, (
        "Read-only CLI reopen verifies exact saved model and evidence counts"
    )


@pytest.mark.parametrize("refusal", ["approval", "owner", "revoked", "source", "material", "type"])
def test_ActualConfigurationCliRefusalCannotLaunchOrCommit(tmp_path, capsys, refusal):
    """A CLI flag or read consent cannot replace current authority or closed source selection."""

    root, selection, _ = LiveConfiguration(tmp_path)
    arguments = ConfigurationCliArguments(root, selection, approval=refusal != "approval")

    if refusal == "owner":
        arguments.extend(("--owner", "owner:foreign"))

    elif refusal == "revoked":
        store = LocalScopeStore(root)
        scope = store.Open("config-scope")
        store.Save(replace(scope, authorization=replace(scope.authorization,
                                                       state=AuthorizationState.REVOKED)))

    elif refusal == "source":
        selection.source.write_bytes(b"unreviewed synthetic source")

    elif refusal == "material":
        selection.material.write_bytes(b"{}")

    elif refusal == "type":
        arguments.extend(("--type", "kubernetes"))

    assert Main([*arguments, "--json"]) == 3, "Pre-launch refusal remains authorization denial"
    summary = json.loads(capsys.readouterr().out)
    assert summary["state"] == "failed" and summary["operations"] == [] and (
        summary["job"]["artifacts"] == [] and summary["model_revision"] == 0
    ), "Pre-launch refusal cannot fabricate process, acquisition or saved model success"
    assert LocalModelStore(root).Open().revision == 0, "Denied CLI cannot change the original model"


def test_ForegroundConfigurationShellUsesExactQuotedInputsAndProtectedHistory(tmp_path):
    """Foreground shell reuses the CLI with spaces and cannot retain sensitive selection text."""

    root, selection, _ = LiveConfiguration(tmp_path, "dockerfile.non-root-user")
    source = tmp_path / "selected source with spaces"
    source.write_bytes(selection.source.read_bytes())
    selection = replace(selection, source=source)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    assert not shell.onecmd(shlex.join(ConfigurationCliArguments(root, selection))), (
        "Foreground config shell must stay available after actual scan completion"
    )
    assert "Synthetic Configuration Scan completed" in output.getvalue(), (
        "Human output identifies the actual synthetic configuration workflow"
    )
    assert LocalModelStore(root).Open().revision == 1, "Shell uses the governed persistence owner"
    assert list(shell._history) == ["scan"] and shell.lastcmd == "scan", (
        "Selected source and consent values cannot enter replay or shell history"
    )


def test_ActualConfigurationCliCancellationRetainsOriginalFourRecords(
    tmp_path, capsys, monkeypatch
):
    """Cooperative cancellation after the real worker keeps its facts without model publication."""

    root, selection, _ = LiveConfiguration(tmp_path)
    original = GovernedArtifactExecutor.Execute

    async def Execute(self, *args, **options):
        """Use actual governed execution, then request owning cancellation before publication."""

        outcome = await original(self, *args, **options)
        options["cancellation"].set()

        return outcome

    monkeypatch.setattr(GovernedArtifactExecutor, "Execute", Execute)
    assert Main([*ConfigurationCliArguments(root, selection), "--json"]) == 130, (
        "Actual cancellation must remain the workflow's terminal interruption status"
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["state"] == "cancelled" and summary["model_revision"] == 0 and (
        len(summary["job"]["artifacts"]) == 4 and len(summary["operations"]) == 1
    ), "Cancellation retains the actual run and original acquisitions without committing a model"
    assert not any(event["kind"] == "model_delta" for event in summary["events"]), (
        "Cancelled CLI cannot publish a successful model delta"
    )


def test_ActualConfigurationCliOutputOverflowRetainsBoundedProcessFacts(
    tmp_path, capsys, monkeypatch
):
    """Actual unchanged worker overflow cannot become complete wire or a successful CLI scan."""

    from fuzzy1337.artifact_policy import PrepareArtifact

    root, selection, _ = LiveConfiguration(tmp_path)

    def Prepare(stage, workspace_root, **options):
        """Tighten actual matching canonical resources before the original grant is created."""

        return PrepareArtifact(stage, workspace_root,
            resources=ExecutionResources(max_stdout_bytes=3, max_stderr_bytes=16 * 1024), **options)

    monkeypatch.setattr(configuration_workflow, "PrepareArtifact", Prepare)
    assert Main([*ConfigurationCliArguments(root, selection), "--json"]) == 4, (
        "Real bounded process overflow remains a failed scan command"
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["job"]["failure"]["code"] == "output_limit" and (
        summary["operations"][0]["termination"] == "output_limit"
    ), "Original executor overflow classification must survive CLI presentation"
    assert summary["model_revision"] == 0 and len(summary["job"]["artifacts"]) == 4, (
        "Overflow retains original acquisitions while denying configuration model application"
    )
    workspace = LocalWorkspaceStore(root).Open()
    store = LocalEvidenceStore(root / "evidence")
    records = tuple(store.Get(record_id) for record_id in workspace.evidence_record_references)
    replay = VerifySyntheticConfigurationReplay(records, root)
    assert replay.acceptance.refusal is not None, "Replay retains the original refused overflow run"
    stdout = next(record for record in records if record.reference.role == "configuration-stdout")
    assert len(store.Read(stdout.reference)) == 3, "Evidence retains the actual bounded prefix"


@pytest.mark.parametrize("failure", ["model-conflict", "model-lost-ack", "workspace-lost-ack"])
def test_ActualConfigurationCliStorageFailureReportsRealCommittedRevision(
    tmp_path, capsys, monkeypatch, failure
):
    """Lost acknowledgements and CAS refusal retain real process/model truth with failed job."""

    root, selection, _ = LiveConfiguration(tmp_path)
    store_type = LocalWorkspaceStore if failure == "workspace-lost-ack" else LocalModelStore
    original = store_type.Save

    def Save(self, *args, **options):
        """Exercise original durable CAS save before losing its caller acknowledgement."""

        if failure == "model-conflict":
            raise WorkspaceConflictError("Owned synthetic conflict")

        original(self, *args, **options)

        raise OSError("Owned synthetic lost acknowledgement")

    monkeypatch.setattr(store_type, "Save", Save)
    output = tmp_path / "not-run.json"
    assert Main([*ConfigurationCliArguments(root, selection), "--json", "--report-format", "json",
        "--report-output", str(output)]) == 4, "Failed durable job retains storage failure status"
    summary = json.loads(capsys.readouterr().out)
    assert summary["state"] == "failed" and summary["job"]["failure"]["code"] == "storage", (
        "Storage acknowledgement failure cannot become successful scan publication"
    )
    assert summary["model_revision"] == LocalModelStore(root).Open().revision == (
        0 if failure == "model-conflict" else 1
    ), "CLI must reopen and expose the actual durable model revision after failed acknowledgement"
    assert len(summary["operations"]) == 1 and len(summary["job"]["artifacts"]) == 4, (
        "Storage failure cannot erase the actual completed worker or original acquired records"
    )
    assert not any(event["kind"] == "model_delta" for event in summary["events"]), (
        "Failed durable job cannot emit a successful model publication event"
    )
    assert summary["report"]["status"] == "not-run" and not output.exists(), (
        "Requested export remains separate and cannot run after failed job completion"
    )


@pytest.mark.parametrize("failure", ["existing", "lost-ack"])
def test_ActualConfigurationCliExportFailurePreservesCompletedScanAndPublicationFacts(
    tmp_path, capsys, monkeypatch, failure
):
    """Report no-clobber and lost publication acknowledgement leave durable scanner facts intact."""

    root, selection, _ = LiveConfiguration(tmp_path)
    output = tmp_path / "report.json"

    if failure == "existing":
        output.write_bytes(b"owned original report")

    else:
        original = configuration_workflow.PublishReport

        def Publish(destination, payload):
            """Publish complete bytes before reporting a confirmed acknowledgement failure."""

            original(destination, payload)

            raise ReportFailure("publication", published=True)

        monkeypatch.setattr(configuration_workflow, "PublishReport", Publish)

    assert Main([*ConfigurationCliArguments(root, selection), "--events-json", "--report-format",
        "json", "--report-output", str(output)]) == 4, "Requested export failure stays nonzero"
    messages = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    summary = messages[-1]["summary"]
    assert summary["state"] == "completed" and summary["model_revision"] == 1, (
        "Report failure must preserve the actual completed scan and saved canonical model"
    )
    assert summary["report"]["status"] == "failed" and (
        summary["report"]["output_published"] is (failure == "lost-ack")
    ), "Confirmed actual publication remains distinct from existing-destination refusal"

    if failure == "existing":
        assert output.read_bytes() == b"owned original report", "Existing report remains untouched"

    else:
        assert json.loads(output.read_bytes())["model"] == LocalModelStore(root).Open().ToDict(), (
            "Lost publication acknowledgement retains the complete actually saved report"
        )
