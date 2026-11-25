# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the copyable GitLab job against real retained stores without providers."""

from __future__ import annotations

import builtins
import json
from dataclasses import replace
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml

from fuzzy1337 import cli
from fuzzy1337.findings import ApplyVerifiedFindings, Finding, FindingSeverity
from fuzzy1337.model import LocalModelStore, ObjectKind
from tests.contract.report_export_fixture import Context, DenyExecution, Files, OutcomeValidator
from tests.contract.test_reporting_contract import Validator

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docs/examples/ci/gitlab-retained-report.yml"


def Job():
    """Read the actual copyable hidden job rather than a mirrored implementation."""

    return yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))[".1337-retained-report"]


def RunTemplate(project: Path, monkeypatch, *, jobId: str = "123", source: str | None = "saved"):
    """Execute the actual inline Python with process and network operations forbidden."""

    monkeypatch.chdir(project)
    monkeypatch.setenv("CI_PROJECT_DIR", str(project))
    monkeypatch.setenv("CI_JOB_ID", jobId)

    if source is None:
        monkeypatch.delenv("F1337_SAVED_WORKSPACE", raising=False)

    else:
        monkeypatch.setenv("F1337_SAVED_WORKSPACE", source)

    DenyExecution(monkeypatch)
    shell, = Job()["script"]
    header, program = shell.split("\n", 1)
    assert header == "python3 -I - <<'PY'", "Use only the installed isolated Python CLI runtime"
    program, closing = program.rsplit("\nPY", 1)
    assert not closing.strip(), "The reusable job must not hide additional shell commands"

    try:
        exec(compile(program, str(TEMPLATE), "exec"), {"__name__": "__main__"})

    except SystemExit as error:
        return error.code

    return 0


def test_IncludeIsInertAndOnlyTheMatchedBundleIsSelected():
    """Require explicit job opt-in without scanners, default setup or an implicit gate."""

    template = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
    assert list(template) == [".1337-retained-report"], "Including the file must schedule no job"
    job = Job()
    assert job["inherit"] == {"default": False}, "Do not inherit active project setup or services"
    assert "rules" not in job and "allow_failure" not in job, (
        "The caller chooses scheduling; export errors must retain their failing status"
    )
    assert job["artifacts"]["paths"] == ['1337-retained-report-$CI_JOB_ID/'], (
        "Download only the complete bundle for this exact GitLab job"
    )
    assert job["artifacts"]["reports"] == {
        "junit": '1337-retained-report-$CI_JOB_ID/report.junit.xml',
    }, "Offer the existing finding adapter through GitLab's supported JUnit report field"


def test_RealRetainedFindingsExportRepeatablyWithUnknownsAndSourceFailures(
    tmp_path, monkeypatch,
):
    """Keep all saved facts while GitLab receives only active failures and closed skips."""

    source, records = Context(tmp_path, workspace_id="saved")
    model = LocalModelStore(source).Open()
    host, = model.Objects(ObjectKind.HOST)
    unknown = Finding(host.Reference(), "synthetic.unknown", "unknown/location",
        "Retained severity was not classified", host.provenance, FindingSeverity.UNKNOWN, 0.0)
    model, delta = ApplyVerifiedFindings(model, (unknown,), source)
    LocalModelStore(source).Save(model, expected_revision=delta.previous_revision)
    original = Files(source)
    assert RunTemplate(tmp_path, monkeypatch) == 0, "Real saved findings must export offline"
    bundle = tmp_path / "1337-retained-report-123"
    document = json.loads((bundle / "report.json").read_bytes())
    Validator().validate(document)
    assert document["model"] == model.ToDict(), "Preserve the complete canonical saved model"
    assert document["scan_completeness"] == "not-assessed", "Do not invent scan completeness"
    assert document["summary"]["failed_execution_records"] == 1, (
        "Successful projection must retain the original failed source execution"
    )
    assert document["summary"]["finding_severities"]["unknown"] == 1, (
        "An unclassified severity must remain unknown without a GitLab severity conversion"
    )
    suite = ElementTree.fromstring((bundle / "report.junit.xml").read_bytes())
    assert (suite.attrib["tests"], suite.attrib["failures"], suite.attrib["skipped"]) == (
        "5", "3", "2",
    ), "Only active saved dispositions become failures; closed dispositions remain skipped"
    cases = suite.findall("testcase")
    fingerprints = {item["normalized"]["fingerprint"] for item in document["findings"]}
    assert {case.attrib["name"] for case in cases} == fingerprints, (
        "Use real canonical fingerprints for unique GitLab case names"
    )
    assert all("file" not in case.attrib and "time" not in case.attrib for case in cases), (
        "Do not fabricate file bindings or test execution durations"
    )
    outcomes = [json.loads((bundle / f"{name}-export.json").read_bytes())
                for name in ("json", "junit")]

    for outcome in outcomes:
        OutcomeValidator().validate(outcome)
        assert outcome["snapshot_sha256"] == document["snapshot_sha256"], (
            "Both retained CLI receipts must identify the exact exported canonical snapshot"
        )
        assert outcome["verified_retained_acquisitions"] == len(records), (
            "Verify even retained acquisitions unused by the current model"
        )

    first = Files(bundle)
    assert RunTemplate(tmp_path, monkeypatch) == 0, "A repeated export may publish a fresh bundle"
    assert Files(bundle) == first, "Unchanged saved input must produce identical reports/receipts"
    assert Files(source) == original, "Offline export must not change any saved workspace bytes"
    retired, = tmp_path.glob(".1337-retired-*/bundle")
    assert Files(retired) == first, "Preserve the superseded bundle outside artifact selection"


@pytest.mark.parametrize("failure", ["missing", "corrupt", "missing-variable"])
def test_RefusalAfterSuccessCannotUploadStaleOrPartialReports(tmp_path, monkeypatch, failure):
    """Remove previous same-job selection before missing/corrupt-source refusal."""

    source, records = Context(tmp_path, workspace_id="saved")
    assert RunTemplate(tmp_path, monkeypatch) == 0, "Establish an actual older successful bundle"
    bundle = tmp_path / "1337-retained-report-123"
    first = Files(bundle)
    selected = "missing" if failure == "missing" else "saved"

    if failure == "corrupt":
        evidence = source / "evidence" / records[-1].reference.locator
        assert evidence.is_file(), "Corrupt the actual retained unused acquisition blob"
        evidence.write_bytes(b"owned corrupted evidence")

    if failure == "missing-variable":
        selected = None

    original = Files(source)
    assert RunTemplate(tmp_path, monkeypatch, source=selected) != 0, (
        "Configuration and saved-evidence integrity errors must fail the export job"
    )
    assert not bundle.exists(), "No older or partial report may remain at GitLab's upload path"
    assert not list(tmp_path.glob(".1337-report-*")), "Ordinary failures must clean staging"
    retired, = tmp_path.glob(".1337-retired-*/bundle")
    assert Files(retired) == first, "Do not overwrite or delete the old bundle while retiring it"
    assert Files(source) == original, "Even refused export must leave source facts unchanged"


@pytest.mark.parametrize("selection", [".", "1337-retained-report-123",
                                       "1337-retained-report-123/inside", "../outside"])
def test_InvalidSourceSelectionAfterSuccessCannotLeaveUploadableStaleXml(
    tmp_path, monkeypatch, selection,
):
    """Retire exclusively owned output even when the selected source overlaps or escapes."""

    source, records = Context(tmp_path, workspace_id="saved")
    assert RunTemplate(tmp_path, monkeypatch) == 0, "Establish an actual prior successful bundle"
    bundle = tmp_path / "1337-retained-report-123"
    first = Files(bundle)
    original = Files(source)
    assert RunTemplate(tmp_path, monkeypatch, source=selection) == 4, (
        "Invalid source placement must fail without executing any provider"
    )
    assert not bundle.exists(), "Even configuration refusal must remove stale XML from selection"
    retired, = tmp_path.glob(".1337-retired-*/bundle")
    assert Files(retired) == first, "Retiring the reserved namespace must preserve its exact bytes"
    assert Files(source) == original, "The independent saved workspace must remain unchanged"



def test_SnapshotChangeBetweenExportsRefusesWholeBundle(tmp_path, monkeypatch):
    """Simulate a concurrent retained model save through its actual local model store."""

    source, records = Context(tmp_path, workspace_id="saved")
    actualMain = cli.Main

    def ChangeAfterJson(arguments):
        """Persist an actual changed model between the two foreground CLI invocations."""

        status = actualMain(arguments)

        if arguments[arguments.index("--format") + 1] == "json":
            store = LocalModelStore(source)
            model = store.Open()
            host, = model.Objects(ObjectKind.HOST)
            changed = replace(host, attributes={**host.attributes, "concurrent": True})
            updated, delta = model.Apply(objects=(changed,))
            store.Save(updated, expected_revision=delta.previous_revision)

        return status

    monkeypatch.setattr(cli, "Main", ChangeAfterJson)
    assert RunTemplate(tmp_path, monkeypatch) == 4, "Different retained snapshots cannot be paired"
    assert not (tmp_path / "1337-retained-report-123").exists(), (
        "A mismatched pair must not become a downloadable or GitLab-parsed report"
    )


def test_EmptySnapshotCreatesZeroCasesWithoutInventedSecurityPass(tmp_path, monkeypatch):
    """Expose an empty saved model honestly through the unchanged accepted JUnit adapter."""

    Context(tmp_path, workspace_id="saved", findings=False)
    assert RunTemplate(tmp_path, monkeypatch) == 0, "A retained empty snapshot may be exported"
    suite = ElementTree.fromstring(
        (tmp_path / "1337-retained-report-123/report.junit.xml").read_bytes())
    assert suite.attrib["tests"] == "0" and not suite.findall("testcase"), (
        "No findings must remain zero cases rather than a fabricated successful security test"
    )


def test_SecondCliFailureCannotPublishTheSuccessfulFirstProjection(tmp_path, monkeypatch):
    """Keep the first report private when the second real CLI invocation fails."""

    Context(tmp_path, workspace_id="saved")
    actualMain = cli.Main

    def FailAfterJunit(arguments):
        """Return an export failure after real serialization to exercise bundle publication."""

        status = actualMain(arguments)

        return 4 if arguments[arguments.index("--format") + 1] == "junit" else status

    monkeypatch.setattr(cli, "Main", FailAfterJunit)
    assert RunTemplate(tmp_path, monkeypatch) == 4, "Propagate the second export's failure"
    assert not (tmp_path / "1337-retained-report-123").exists(), (
        "A successful JSON export alone must not publish a partial artifact bundle"
    )
    assert not list(tmp_path.glob(".1337-report-*")), "Remove unpublished staging on CLI failure"


def test_GitlabIndividualJunitLimitRefusesOtherwiseValidExport(tmp_path, monkeypatch):
    """Enforce GitLab's smaller XML limit before publishing a valid product-sized report."""

    from fuzzy1337 import report_commands

    Context(tmp_path, workspace_id="saved")
    actualSerializer = report_commands.SerializeJunit

    def LargeJunit(report):
        """Pad a genuine XML projection within the CLI bound but above GitLab's limit."""

        return actualSerializer(report) + b" " * 30_000_000

    monkeypatch.setattr(report_commands, "SerializeJunit", LargeJunit)
    assert RunTemplate(tmp_path, monkeypatch) == 4, "Oversized GitLab reports must fail visibly"
    assert not (tmp_path / "1337-retained-report-123").exists(), (
        "Do not publish JSON with an XML report GitLab refuses to parse"
    )


@pytest.mark.parametrize("failure", ["resolution", "product-import"])
def test_InputResolutionOrProductImportFailureCannotLeaveOldSelectedXml(
    tmp_path, monkeypatch, failure,
):
    """Retire prior output before either input traversal or importing the installed CLI."""

    source, records = Context(tmp_path, workspace_id="saved")
    assert RunTemplate(tmp_path, monkeypatch) == 0, "Establish an actual older successful export"
    bundle = tmp_path / "1337-retained-report-123"
    first = Files(bundle)
    original = Files(source)
    actualResolve = Path.resolve
    actualImport = builtins.__import__

    def RefuseResolution(path, *arguments, **options):
        """Simulate a filesystem resolution error only for the selected saved source."""

        if path == source:
            raise OSError("Owned source resolution failure")

        return actualResolve(path, *arguments, **options)

    def RefuseProductImport(name, *arguments, **options):
        """Simulate an unavailable installed CLI without blocking the harness runtime."""

        if name == "fuzzy1337.cli":
            raise ModuleNotFoundError("Owned missing installed product")

        return actualImport(name, *arguments, **options)

    if failure == "resolution":
        monkeypatch.setattr(Path, "resolve", RefuseResolution)

    else:
        monkeypatch.setattr(builtins, "__import__", RefuseProductImport)

    assert RunTemplate(tmp_path, monkeypatch) == 4, "Refuse unavailable input or installed product"
    assert not bundle.exists(), "Refusal before CLI execution must still prevent stale JUnit upload"
    retired, = tmp_path.glob(".1337-retired-*/bundle")
    assert Files(retired) == first, "Preserve old output outside the runner's report selection"
    assert Files(source) == original, "Infrastructure refusal must not rewrite the saved workspace"
