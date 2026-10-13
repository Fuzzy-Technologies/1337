# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""User-level closed synthetic image collection, durable reopening and separate export failures."""

from __future__ import annotations

import asyncio
import json
import shlex
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.image_workflow import RunSyntheticImageScan
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.synthetic_images import VerifySyntheticTrivyImageReplay
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.image_helpers import CreateOwnedImage, OwnedImage


def test_OperatorCanCollectReopenVerifyAndExportClosedSyntheticImageInventory(tmp_path):
    """Drive the assembled SDK workflow over an owned no-findings fixture and reopen it."""

    owned = CreateOwnedImage(tmp_path, "no_findings")
    output = tmp_path / "inventory.json"
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, report_format="json", report_output=output))
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0, (
        "User workflow completes only after actual governed operations, durable saves and export"
    )
    reopened = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    store = LocalEvidenceStore(owned.root / "evidence")
    roles = {"provider-version", "provider-version-stderr", "stdout", "stderr",
        "artifact-version-receipt", "artifact-scan-receipt"}
    acquisitions = tuple(store.Get(record_id) for record_id in workspace.evidence_record_references)
    records = tuple(item for item in acquisitions if item.reference.role in roles)
    original = VerifySyntheticTrivyImageReplay(records, owned.root)
    report = json.loads(output.read_bytes())
    assert len(records) == 6 and original.provenance.source_id == "synthetic.trivy", (
        "A reopened workspace retains exact original synthetic operation provenance"
    )
    assert not Findings(reopened) and report["scan_completeness"] == "not-assessed", (
        "No Findings remains explicit inventory without a clean-scan or completeness claim"
    )
    assert report["model"] == reopened.ToDict() and summary.model_revision == reopened.revision, (
        "User report and terminal summary describe the exact durable reopened model"
    )


def ImageCliArguments(owned: OwnedImage, *, root: Path | None = None,
                      approval: bool = True) -> list[str]:
    """Select the exact reviewed image sources and read consent through the public CLI."""

    selection = owned.selection
    arguments = ["scan", "image", str(root or owned.root), "--profile", "synthetic",
        "--scope", "image-scope", "--owner", "owner:image-test",
        "--archive", str(selection.archive), "--executable", str(selection.executable),
        "--producer", str(selection.producer), "--material", str(selection.material),
        "--read-consent-reference", selection.read_consent.record_ref]

    if approval:
        arguments.append("--approve-safe-image")

    return arguments


@pytest.mark.parametrize("scenario,report_format,finding_count", [
    ("success", "sarif", 1), ("no_findings", "json", 0),
])
def test_CliCreatesArtifactScopeCollectsReopensAndExports(
    tmp_path, capsys, scenario, report_format, finding_count
):
    """Run public CLI workspace/scope/image commands with actual two-phase owned execution."""

    owned = CreateOwnedImage(tmp_path, scenario)
    root = tmp_path / "CLI workspace with spaces"
    assert Main(["workspace", "create", str(root), "--id", "cli-images", "--name", "Images"]) == 0
    capsys.readouterr()
    authority = owned.context.scope.authorization
    assert Main(["scope", "create", str(root), "--id", "image-scope", "--allow-artifact",
        owned.context.scope.targets[0].value, "--grant-consent", "--owner",
        authority.authority_reference, "--consent-reference", authority.record_reference,
        "--valid-from", authority.valid_from, "--valid-until", authority.valid_until]) == 0
    capsys.readouterr()
    destination = tmp_path / ("report." + report_format)
    assert Main([*ImageCliArguments(owned, root=root), "--json", "--report-format", report_format,
        "--report-output", str(destination)]) == 0, "CLI succeeds after actual durable saves"
    summary = json.loads(capsys.readouterr().out)
    assert summary["workflow"] == "synthetic-image" and summary["source_id"] == "synthetic.trivy"
    assert summary["state"] == "completed" and summary["scan_completeness"] == "not-assessed"
    assert [item["operation"] for item in summary["operations"]] == ["version", "scan"], (
        "Observed independent VERSION precedes original prerequisite-bound SCAN"
    )
    model = LocalModelStore(root).Open()
    assert len(Findings(model)) == finding_count and summary["model_revision"] == model.revision
    assert summary["report"]["output_published"] and summary["report"]["status"] == "completed"
    report = json.loads(destination.read_bytes())

    if report_format == "json":
        assert report["model"] == model.ToDict() and report["scan_completeness"] == "not-assessed"

    else:
        assert len(report["runs"][0]["results"]) == finding_count, (
            "SARIF preserves fixture findings"
        )

    assert Main(["workspace", "open", str(root), "--json"]) == 0
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["model_revision"] == summary["model_revision"], "Reopen uses committed state"
    assert reopened["verified_evidence_records"] == 12, (
        "All selected and six operation roles persist"
    )


@pytest.mark.parametrize("refusal", ["approval", "owner", "scope", "archive"])
def test_CliDenialPreservesEmptyModelAndNoNativeInterpretation(tmp_path, capsys, refusal):
    """CLI approvals never replace current authority, scope membership or closed producer inputs."""

    owned = CreateOwnedImage(tmp_path)
    arguments = ImageCliArguments(owned, approval=refusal != "approval")

    if refusal == "owner":
        arguments.extend(("--owner", "owner:other"))

    elif refusal == "scope":
        scope = LocalScopeStore(owned.root).Open("image-scope")
        LocalScopeStore(owned.root).Save(replace(scope, authorization=replace(scope.authorization,
            state=AuthorizationState.REVOKED)))

    elif refusal == "archive":
        arguments.extend(("--archive", str(tmp_path / "missing-image.tar")))

    result = Main([*arguments, "--json"])
    summary = json.loads(capsys.readouterr().out)
    assert result in (3, 4) and summary["state"] == "failed", "Denial retains nonzero exit status"
    assert summary["operations"] == [] and summary["model_revision"] == 0, (
        "Refused workflow launches neither operation and commits no interpreted model"
    )
    assert not Findings(LocalModelStore(owned.root).Open()), "No fixture becomes a native Finding"


def test_CliEventStreamKeepsTerminalSummaryAndSeparateReportFailure(tmp_path, capsys):
    """A valid saved synthetic scan remains completed when no-clobber report publication fails."""

    owned = CreateOwnedImage(tmp_path)
    destination = tmp_path / "existing.json"
    destination.write_bytes(b"existing owned report")
    assert Main([*ImageCliArguments(owned), "--events-json", "--report-format", "json",
        "--report-output", str(destination)]) == 4
    messages = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    summary = messages[-1]["summary"]
    events = [item["event"] for item in messages[:-1]]
    assert events == summary["events"] and messages[-1]["type"] == "summary", (
        "Streaming preserves exact original events before one truthful terminal summary"
    )
    assert summary["state"] == "completed" and summary["model_revision"] > 0, (
        "Separate report refusal cannot erase the actual completed scan/model commit"
    )
    assert summary["report"]["status"] == "failed" and not summary["report"]["output_published"]
    assert destination.read_bytes() == b"existing owned report", "Publication never clobbers a file"


def test_ForegroundShellUsesSameExplicitSyntheticImageCli(tmp_path):
    """Shell dispatch reuses the existing namespace, selected files and governed image workflow."""

    from io import StringIO

    owned = CreateOwnedImage(tmp_path, "no_findings")
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    assert not shell.onecmd(shlex.join(ImageCliArguments(owned))), "Foreground shell stays alive"
    assert "Synthetic Image Scan completed" in output.getvalue(), "Human output names synthetic run"
    assert LocalModelStore(owned.root).Open().revision > 0, "Shell commits through same model owner"
