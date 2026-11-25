# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Shared installed-CLI bundles and opt-in GitHub upload selection without remote execution."""

from __future__ import annotations

import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path

import pytest
import yaml

from fuzzy1337 import cli, retained_report_ci
from tests.contract.report_export_fixture import Context, DenyExecution, Files
from tests.unit.test_gitlab_retained_report import RunTemplate

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "docs/examples/ci/github-retained-report/action.yml"


def Action():
    """Read the exact opt-in composite instead of reproducing its shell implementation."""

    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def RunAction(project: Path, monkeypatch, *, source: str = "saved", key: str = "owned"):
    """Execute the actual isolated bootstrap while denying all provider process/network access."""

    monkeypatch.chdir(project)
    monkeypatch.setenv("REPORT_PROJECT", str(project))
    monkeypatch.setenv("REPORT_RUN", "456")
    monkeypatch.setenv("REPORT_ATTEMPT", "2")
    monkeypatch.setenv("REPORT_KEY", key)
    monkeypatch.setenv("F1337_SAVED_WORKSPACE", source)
    DenyExecution(monkeypatch)
    step, = [step for step in Action()["runs"]["steps"] if step.get("id") == "export"]
    header, program = step["run"].split("\n", 1)
    assert header == "python3 -I - <<'PY'", "Import the installed helper through isolated Python"
    program, closing = program.rsplit("\nPY", 1)
    assert not closing.strip(), "The sample must contain no extra shell commands"

    try:
        exec(compile(program, str(ACTION), "exec"), {"__name__": "__main__"})

    except SystemExit as error:
        return error.code

    raise AssertionError("The exact bootstrap must preserve its helper's terminal status")


def test_GithubSampleIsOptInAndUploadsOnlyAfterSuccessfulOfflineExport():
    """Keep the action inert until explicitly used and grant no repository mutation authority."""

    action = Action()
    assert action["runs"]["using"] == "composite" and "on" not in action, (
        "Providing the sample must create no workflow or automatic job"
    )
    export, upload = action["runs"]["steps"]
    demo = yaml.safe_load((ROOT / "docs/examples/ci/github-actions.yml").read_text())
    original, = [step for step in demo["jobs"]["local-demo"]["steps"] if "uses" in step]
    assert upload["uses"] == original["uses"], "Reuse the exact reviewed artifact action pin"
    assert upload["if"] == "${{ success() && steps.export.outcome == 'success' }}", (
        "Failed or cancelled export must never upload even an older complete bundle"
    )
    assert (upload["with"]["overwrite"] is False
            and upload["with"]["if-no-files-found"] == "error"), (
        "Hosted artifact collisions and missing bundles must fail instead of pretending success"
    )
    assert set(action["inputs"]) == {"saved_workspace", "report_key"}, (
        "The caller provides only existing saved input and its unique artifact namespace"
    )
    assert all(item["required"] for item in action["inputs"].values()), (
        "Do not invent a default workspace or ambiguous artifact selection"
    )
    assert export["working-directory"] == "${{ github.workspace }}", (
        "A caller's run-directory default must not redirect the owned artifact namespace"
    )
    assert "${{" not in export["run"] and "GITHUB_TOKEN" not in str(action), (
        "Pass data only through quoted environment boundaries; request no repository write token"
    )
    assert set(upload["with"]) == {
        "name", "path", "if-no-files-found", "overwrite", "retention-days",
    }, "The sample must perform one ordinary artifact upload without code-scanning or publishing"


def test_GitlabAndGithubPublishIdenticalCanonicalBundleAndRepeatWithoutSourceWrites(
    tmp_path, monkeypatch,
):
    """Both standalone templates use the same accepted exports over one actual saved store."""

    source, records = Context(tmp_path, workspace_id="saved")
    original = Files(source)
    assert RunTemplate(tmp_path, monkeypatch) == 0, "Preserve standalone GitLab template use"
    assert RunAction(tmp_path, monkeypatch) == 0, "The explicit GitHub action must export offline"
    github = tmp_path / "1337-retained-report-456-2-owned"
    gitlab = tmp_path / "1337-retained-report-123"
    first = Files(github)
    assert first == Files(gitlab), "Platforms must preserve canonical report and receipt bytes"
    assert set(first) == {
        "report.json", "report.junit.xml", "json-export.json", "junit-export.json",
    }, (
        "One bundle must preserve both original reports and their unchanged CLI receipt contracts"
    )
    assert RunAction(tmp_path, monkeypatch) == 0, "A repeated local invocation may export again"
    assert Files(github) == first, "Repeat export of unchanged source must be byte-identical"
    assert Files(source) == original, "Both platforms must preserve saved input bytes"
    retired, = tmp_path.glob(".1337-retired-*/bundle")
    assert Files(retired) == first, "Keep older results outside the one selected artifact path"


@pytest.mark.parametrize("sourceName", ["missing", "", ".", "../outside",
                                        "1337-retained-report-456-2-owned"])
def test_GithubSourceRefusalAfterSuccessLeavesNoUploadSelection(tmp_path, monkeypatch, sourceName):
    """Configuration refusals cannot select an older bundle even before a CLI invocation."""

    source, records = Context(tmp_path, workspace_id="saved")
    assert RunAction(tmp_path, monkeypatch) == 0, "Establish a real previous successful bundle"
    original = Files(source)
    assert RunAction(tmp_path, monkeypatch, source=sourceName) != 0, "Refuse invalid saved source"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), (
        "No prior report may remain at the exact upload selection after refusal"
    )
    assert Files(source) == original, "Source refusal must not rewrite independently saved facts"


@pytest.mark.parametrize("alteration", ["json-bytes", "json-receipt", "junit-bytes"])
def test_AlteredStagedOutputOrReceiptDuringSecondExportRefusesWholeBundle(
    tmp_path, monkeypatch, alteration,
):
    """Recheck original acknowledgements after both real exports before publishing either."""

    source, records = Context(tmp_path, workspace_id="saved")
    original = Files(source)
    actualMain = cli.Main

    def AlterAfterJunit(arguments):
        """Alter already staged bytes after the actual second CLI command acknowledges success."""

        status = actualMain(arguments)

        if arguments[arguments.index("--format") + 1] == "junit":
            destination = Path(arguments[arguments.index("--output") + 1])
            name = {"json-bytes": "report.json", "json-receipt": "json-export.json",
                    "junit-bytes": "report.junit.xml"}[alteration]
            selected = destination.parent / name
            content = selected.read_bytes()
            selected.write_bytes(bytes([content[0] ^ 1]) + content[1:])

        return status

    monkeypatch.setattr(cli, "Main", AlterAfterJunit)
    assert RunAction(tmp_path, monkeypatch) == 4, "Altered staged bytes must fail visibly"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), (
        "Do not publish a pair whose acknowledged original bytes have changed"
    )
    assert not list(tmp_path.glob(".1337-report-*")), "Remove unpublished staging after refusal"
    assert Files(source) == original, "Staged-output refusal must preserve all retained input facts"


@pytest.mark.parametrize("field,value", [
    ("command", "other"), ("schema_version", True), ("status", "failed"),
    ("output_published", False), ("format", "html"), ("failure", "integrity"),
    ("scan_completeness", "complete"), ("model_revision", -1),
    ("verified_retained_acquisitions", True), ("checked_model_evidence_references", "1"),
    ("snapshot_sha256", "unknown"), ("report_sha256", "wrong"), ("size_bytes", -1),
    ("size_bytes", True), ("size_bytes", 32 * 1024 * 1024 + 1),
])
def test_InvalidActualCliReceiptNeverPublishesAClaimedSuccessfulBundle(
    tmp_path, monkeypatch, field, value,
):
    """Reject failed/ambiguous acknowledgements rather than treating process exit zero as proof."""

    Context(tmp_path, workspace_id="saved")
    actualMain = cli.Main

    def WrongReceipt(arguments):
        """Retain actual saved export while changing one original completion acknowledgement."""

        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            status = actualMain(arguments)

        outcome = json.loads(output.getvalue())
        outcome[field] = value
        print(json.dumps(outcome))

        return status

    monkeypatch.setattr(cli, "Main", WrongReceipt)
    assert RunAction(tmp_path, monkeypatch) == 4, "Malformed CLI acknowledgements must fail closed"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), (
        "A process success with an invalid receipt is not a completed report bundle"
    )


@pytest.mark.parametrize("status", [2, 3, 4, 130])
def test_OriginalCliFailureStatusIsPreservedWithoutPublishing(tmp_path, monkeypatch, status):
    """Export refusal/denial/failure/cancellation must never become a finding-threshold pass."""

    Context(tmp_path, workspace_id="saved")
    monkeypatch.setattr(cli, "Main", lambda arguments: status)
    assert RunAction(tmp_path, monkeypatch) == status, "Preserve the actual failing CLI status"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), (
        "No failed CLI result may become a selected upload bundle"
    )


def test_InterruptionAfterFirstStagedExportRemovesPrivatePartialOutput(tmp_path, monkeypatch):
    """A real acknowledged first projection is still private when the second command interrupts."""

    Context(tmp_path, workspace_id="saved")
    actualMain = cli.Main

    def InterruptJunit(arguments):
        """Interrupt only the second command after one actual JSON export has completed."""

        if arguments[arguments.index("--format") + 1] == "junit":
            raise KeyboardInterrupt

        return actualMain(arguments)

    monkeypatch.setattr(cli, "Main", InterruptJunit)
    assert RunAction(tmp_path, monkeypatch) == 130, "Interruption must remain a non-success outcome"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), "Publish no partial report"
    assert not list(tmp_path.glob(".1337-report-*")), "Interrupted staging must be cleaned"


def test_MissingPackagedHelperAfterSuccessCannotExposeAnOlderUpload(tmp_path, monkeypatch):
    """The small bootstrap must retire output before importing even the shared packaged helper."""

    Context(tmp_path, workspace_id="saved")
    assert RunAction(tmp_path, monkeypatch) == 0, "Establish an actual older complete bundle"
    actualImport = builtins.__import__

    def RefuseHelper(name, *arguments, **options):
        """Simulate an old/missing wheel without blocking the platform bootstrap's stdlib."""

        if name == "fuzzy1337.retained_report_ci":
            raise ModuleNotFoundError("Owned missing shared helper")

        return actualImport(name, *arguments, **options)

    monkeypatch.setattr(builtins, "__import__", RefuseHelper)
    assert RunAction(tmp_path, monkeypatch) == 4, "A missing installed helper must fail visibly"
    assert not (tmp_path / "1337-retained-report-456-2-owned").exists(), (
        "Do not expose stale output even when the installed package cannot be imported"
    )


@pytest.mark.parametrize("key", ["", "../escape", "with space", "x" * 65, "--option"])
def test_UnsafeArtifactKeyCannotRedirectAnyOutputNamespace(tmp_path, monkeypatch, key):
    """Untrusted caller input must remain data and cannot alter filesystem or upload scope."""

    source, records = Context(tmp_path, workspace_id="saved")
    original = Files(source)
    assert RunAction(tmp_path, monkeypatch, key=key) == 4, "Require a bounded alphanumeric-led key"
    assert not list(tmp_path.glob("1337-retained-report-*")), "Create no output on invalid identity"
    assert Files(source) == original, "Invalid namespace input must leave saved source unchanged"


def test_DirectSharedOwnerRefusesUnsafeNamespaceAndIncorrectWorkingDirectory(tmp_path, monkeypatch):
    """The Internal owner independently bounds output even without a platform bootstrap."""

    monkeypatch.chdir(tmp_path)
    assert retained_report_ci.Main(tmp_path, "../escape", "saved") == 4, (
        "A direct caller must not escape the reserved output namespace"
    )
    nested = tmp_path / "nested"
    nested.mkdir()
    assert retained_report_ci.Main(nested, "owned", "saved") == 4, (
        "Do not infer or silently change the caller's working directory"
    )


@pytest.mark.skipif(os.name == "nt", reason="The fixture owns a POSIX symbolic link")
def test_ReportVerificationRejectsNonregularStaging(tmp_path):
    """Receipt digests cannot make a directory or symbolic link a supported staged report."""

    payload = b"owned"
    receipt = {"size_bytes": len(payload), "report_sha256": hashlib.sha256(payload).hexdigest()}
    regular = tmp_path / "regular"
    regular.write_bytes(payload)
    link = tmp_path / "link"
    link.symlink_to(regular)

    for selected in (tmp_path, link):
        with pytest.raises(ValueError):
            retained_report_ci.VerifyReport(selected, receipt)


@pytest.mark.skipif(os.name == "nt", reason="The fixture owns POSIX symbolic links")
@pytest.mark.parametrize("filename", ["json-export.json", "junit-export.json"])
def test_SubstitutedReceiptSymlinkCannotPublishOrReadAnExternalSource(
    tmp_path, monkeypatch, filename,
):
    """Matching receipt bytes behind a substituted link must not become an accepted artifact."""

    project = tmp_path / "project"
    project.mkdir()
    source, records = Context(project, workspace_id="saved")
    outside = tmp_path / "outside-receipt.json"
    original = Files(source)
    actualMain = cli.Main
    expectedContents = []

    def SubstituteReceipt(arguments):
        """Replace one acknowledged receipt path with a link after the actual second export."""

        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            status = actualMain(arguments)

        receipt = output.getvalue()
        print(receipt, end="")

        if arguments[arguments.index("--format") + 1] == "junit":
            staging = Path(arguments[arguments.index("--output") + 1]).parent
            selected = staging / filename
            data = selected.read_bytes() if selected.exists() else receipt.encode("utf-8")
            outside.write_bytes(data)
            expectedContents.append(data)

            if selected.exists():
                selected.unlink()

            selected.symlink_to(outside)

        return status

    monkeypatch.setattr(cli, "Main", SubstituteReceipt)
    assert RunAction(project, monkeypatch) == 4, "Receipt links must fail even with matching bytes"
    assert outside.read_bytes() == expectedContents[0], "Preserve the independent receipt target"
    assert not (project / "1337-retained-report-456-2-owned").exists(), (
        "No completed bundle may contain a symlink selected as an original receipt"
    )
    assert Files(source) == original, "Link substitution refusal must preserve saved source facts"


@pytest.mark.skipif(os.name == "nt", reason="The fixture owns POSIX symbolic links")
def test_PrecreatedReceiptLinkCannotRedirectTheInitialReceiptWrite(tmp_path, monkeypatch):
    """The exporter must create a new receipt exclusively rather than following a staged link."""

    project = tmp_path / "project"
    project.mkdir()
    source, records = Context(project, workspace_id="saved")
    outside = tmp_path / "owned-external-marker"
    outside.write_bytes(b"Owned unchanged external marker")
    original = Files(source)
    actualMain = cli.Main

    def PlantReceiptLink(arguments):
        """Place a link at the still-uncreated receipt name after real report publication."""

        status = actualMain(arguments)
        staging = Path(arguments[arguments.index("--output") + 1]).parent
        (staging / "json-export.json").symlink_to(outside)

        return status

    monkeypatch.setattr(cli, "Main", PlantReceiptLink)
    assert RunAction(project, monkeypatch) == 4, "Refuse receipt destination occupancy before write"
    assert outside.read_bytes() == b"Owned unchanged external marker", (
        "Exclusive receipt creation must not overwrite a link target outside the project"
    )
    assert not (project / "1337-retained-report-456-2-owned").exists(), "Refuse redirected receipt"
    assert Files(source) == original, "A refused receipt destination must not change saved source"
