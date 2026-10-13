# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real product report export over owned stores, with no provider process or target contact."""

from __future__ import annotations

import hashlib
import json
import shutil
from io import StringIO

import pytest

from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
)
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.shell import InteractiveShell
from tests.contract.report_export_fixture import (
    Context,
    DenyExecution,
    Files,
    OutcomeValidator,
    Run,
)
from tests.contract.test_reporting_contract import Validator


@pytest.mark.parametrize("format_name", ["json", "sarif"])
def test_ProductCliExportsExactSavedSnapshotAndPreservesAllSourceTruth(
    tmp_path, monkeypatch, capsys, format_name,
):
    """Exercise Main dispatch with retained failures/dispositions and no provider operations."""

    root, records = Context(tmp_path)
    original = Files(root)
    model = LocalModelStore(root).Open()
    destination = tmp_path / f"selected.{format_name}"
    DenyExecution(monkeypatch)
    status = Main(["report", "export", str(root), "--format", format_name,
                   "--output", str(destination), "--json"])
    outcome = json.loads(capsys.readouterr().out)
    OutcomeValidator().validate(outcome)
    document = json.loads(destination.read_bytes())
    assert status == 0 and outcome["status"] == "completed", "The explicit export must complete."
    assert outcome["snapshot_sha256"] == ReportSnapshot(model).SnapshotDigest(), (
        "The command must export the exact saved model, not a detached or newly created state."
    )
    assert outcome["model_revision"] == model.revision, "Saved revision must remain explicit."
    assert outcome["report_sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest(), (
        "Terminal metadata must describe the complete selected output bytes."
    )
    assert outcome["verified_retained_acquisitions"] == 2, (
        "Older failed acquisitions unused by the model must still be verified and retained."
    )
    assert outcome["checked_model_evidence_references"] == 1, "Keep distinct read counts honest."

    if format_name == "json":
        Validator().validate(document)
        assert document["model"] == model.ToDict(), "Export must preserve every canonical field."
        assert document["summary"]["failed_execution_records"] == 1, (
            "A successful export must retain the source execution failure."
        )
        assert document["summary"]["finding_statuses"] == {
            "open": 1, "confirmed": 1, "dismissed": 1, "resolved": 1,
        }, "The reader must not reopen or dismiss operator findings."
        assert document["evidence_integrity"]["unverified_count"] == 0, (
            "Every actually linked model reference must undergo the accepted verifier."
        )

    else:
        assert document["version"] == "2.1.0", "Preserve the accepted SARIF version."
        assert len(document["runs"][0]["results"]) == 2, (
            "Only open and confirmed retained findings may become active SARIF results."
        )

    assert Files(root) == original, "Report export must not write any source workspace state."
    assert str(root).encode() not in destination.read_bytes(), "Do not embed local source paths."

    for record in records:
        assert LocalEvidenceStore(root / "evidence").Read(record.reference) not in (
            destination.read_bytes()
        ), "Reports must retain links without embedding raw acquired content."



def test_SelectedWorkspaceRelocationPreservesReportBytes(tmp_path):
    """Report identity follows the stored logical workspace rather than its physical path."""

    root, _ = Context(tmp_path)
    first = tmp_path / "before.json"
    assert Run(root, first)[0] == 0, "The original owned workspace must export."
    moved = tmp_path / "relocated source with spaces"
    shutil.move(str(root), moved)
    second = tmp_path / "after.json"
    assert Run(moved, second)[0] == 0, "The relocated owned workspace must remain readable."
    assert second.read_bytes() == first.read_bytes(), "Relocation must not change report bytes."



def test_ForegroundShellExportsExplicitWorkspaceAndRetainsNoArguments(tmp_path, monkeypatch):
    """Shell context supplies no implicit source; history/lastcmd retain no report arguments."""

    root, _ = Context(tmp_path)
    destination = tmp_path / "shell report.json"
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    DenyExecution(monkeypatch)
    line = f'report export "{root}" --format json --output "{destination}" --json'
    assert not shell.onecmd(line), (
        "Foreground report export must not exit the workbench."
    )
    outcome = json.loads(output.getvalue())
    assert outcome["status"] == "completed", "Shell must use the actual product consumer."
    assert shell.lastcmd == "report", "Empty-line replay cannot retain a prior export argument."
    shell.onecmd("report export absent --format 'synthetic-secret-argument'")
    shell.onecmd("history")
    assert "synthetic-secret-argument" not in output.getvalue(), (
        "Rejected argv must stay unretained."
    )
    assert output.getvalue().splitlines()[-2:] == ["report", "report"], (
        "Product history must retain only its explicit namespace."
    )


@pytest.mark.parametrize("prefix", ["report;", "report--format=", "report/", "REPORT:",
                                    "report; '"])
def test_ActualRejectedReportDispatchCannotLeakMalformedArgumentsOrReplayThem(
    monkeypatch, capsys, prefix,
):
    """The real report command keeps punctuation, missing-space and quoting failures unretained."""

    DenyExecution(monkeypatch)
    marker = "synthetic-private-argument"
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    assert not shell.onecmd(prefix + " " + marker), "Rejected report input cannot exit the shell."
    assert shell.lastcmd == "report", "The parsed namespace alone must become replay state."
    shell.onecmd("")
    shell.onecmd("history")
    terminal = capsys.readouterr()
    assert marker not in output.getvalue() + terminal.out + terminal.err, (
        "Neither actual command diagnostics nor history/replay may expose rejected report values."
    )
    assert output.getvalue().splitlines()[-2:] == ["report", "report"], (
        "Empty-line replay must not redispatch original report arguments."
    )
