# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify selected persisted business declarations through their real immutable storage owners."""

import json
import shlex
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import business_commands as commands
from fuzzy1337 import business_events
from fuzzy1337.cli import Main
from fuzzy1337.model import LocalModelStore
from fuzzy1337.report_commands import BoundedReportEvidenceStore
from fuzzy1337.shell import InteractiveShell
from tests.business_inspection_helpers import Arguments, Files, Owned, Run
from tests.contract.report_export_fixture import DenyExecution


def Refuse(*arguments, **options):
    """Reject writes, route analysis or active execution outside the inspection contract."""

    raise AssertionError("Read-only business inspection attempted an unrelated operation")


@pytest.mark.parametrize("count", [1, 2, 16])
def test_RelocatedInspectionReturnsOnlyVerifiedCanonicalDeclarationRecords(
    tmp_path, monkeypatch, count,
):
    """Operators reopen one original declaration with exact saved assets and primary provenance."""

    root, record, model, support = Owned(tmp_path, count=count)
    moved = tmp_path / "relocated business workspace"
    root.rename(moved)
    before = Files(tmp_path)
    DenyExecution(monkeypatch)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalModelStore, "Create", Refuse)
    monkeypatch.setattr(business_events, "AnalyzeReachabilityPaths", Refuse)
    status, result = Run(Arguments(moved, record, model))
    assert status == 0 and result["status"] == "completed", (
        "The operator must be able to inspect a relocated retained declaration"
    )
    inspected = result["inspection"]
    expected = model.ToDict()
    declaration, = [item for item in expected["objects"]
                    if item["attributes"].get("asset_type") == "business-event-definition"]
    assets = [item for item in expected["objects"] if item != declaration]
    assert inspected["declaration"] == declaration and inspected["critical_assets"] == assets, (
        "Return unchanged current canonical records rather than inferred criticality or risk"
    )
    assert inspected["memberships"] == expected["relations"], (
        "Memberships must retain their exact descriptive semantics and original provenance"
    )
    assert inspected["definition_record"] == record.ToDict() and inspected[
        "definition_evidence_id"
    ] == record.evidence_id, "The original selected acquisition manifest must remain explicit"
    assert inspected["checked_model_evidence_references"] == 2, (
        "Verify both original definition and inventory bytes selected by model provenance"
    )
    assert inspected["semantics"] == "declared-unacceptable-outcome", (
        "An owner declaration must not become an observed incident"
    )
    assert result["core_mutation"] == "none" and result["evidence_commit"] == "not-attempted", (
        "Inspection must grant no persistence or assessment authority"
    )
    assert Run(Arguments(moved, record, model)) == (status, result), (
        "Repeated inspection must introduce no new facts or observation clock"
    )
    assert Files(tmp_path) == before, "Read-only inspection must preserve every saved fixture byte"


@pytest.mark.parametrize("fault", [
    "not-persisted", "declaration", "membership", "definition-bytes", "asset-evidence",
    "definition-missing", "asset-missing", "scope", "revision", "snapshot",
])
def test_ChangedOrUnpersistedFactsRefuseWithoutPartialOperatorRecords(
    tmp_path, monkeypatch, fault,
):
    """Retain exact source, membership, support bytes and independently selected pins."""

    root, record, model, support = Owned(tmp_path, persisted=fault != "not-persisted")

    if fault in {"declaration", "membership"}:
        if fault == "declaration":
            declaration = next(item for item in model.objects
                if item.attributes.get("asset_type") == "business-event-definition")
            altered = replace(declaration,
                attributes={**declaration.attributes, "owner_reference": "synthetic.forged-owner"})
            changed, delta = model.Apply(objects=(altered,))

        else:
            link = model.relations[0]
            altered = replace(link, provenance=(replace(link.provenance[0],
                                                       source_id="synthetic.forged-owner"),))
            changed, delta = model.Apply(relations=(altered,))

        model = LocalModelStore(root).Save(changed, expected_revision=delta.previous_revision)

    elif fault in {"definition-bytes", "asset-evidence", "definition-missing", "asset-missing"}:
        selected = record if fault.startswith("definition") else support
        path = root / "evidence" / selected.reference.locator

        if fault.endswith("missing"):
            path.unlink()

        else:
            path.write_bytes(b"Owned corrupt source")

    arguments = Arguments(root, record, model)

    if fault == "scope":
        arguments[arguments.index("--scope-reference") + 1] = "scope:foreign"

    elif fault == "revision":
        arguments[arguments.index("--expected-revision") + 1] = str(model.revision - 1)

    elif fault == "snapshot":
        arguments[-1] = "0" * 64

    before = Files(tmp_path)
    DenyExecution(monkeypatch)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, result = Run(arguments)
    assert status == 4 and result["status"] == "failed" and result["failure"] == "integrity", (
        "Unverified or unpersisted business facts must refuse the whole inspection"
    )
    assert "inspection" not in result and "synthetic.forged-owner" not in json.dumps(result), (
        "A refusal must publish no partial declaration, owner text or asset list"
    )
    assert Files(tmp_path) == before, "Refusal must not repair or rewrite source facts"


@pytest.mark.parametrize("arguments", [
    [], ["inspect"], ["inspect", "private-path", "--bad"],
    ["inspect", "private-path", "--definition", "private-value",
     "--scope-reference", "scope:owned", "--expected-revision", "0",
     "--expected-snapshot-sha256", "a" * 64],
])
def test_ConfigurationRefusesBeforeOwningStorageReads(monkeypatch, arguments):
    """Incomplete grammar and noncanonical pins cannot open local state or reflect input values."""

    monkeypatch.setattr(commands, "InspectBusinessEvent", Refuse)
    status, result = Run(arguments)
    assert status == 2 and result["failure"] == "configuration", (
        "Invalid selections must fail before any owning read"
    )
    assert "inspection" not in result and "private-" not in json.dumps(result), (
        "Fixed diagnostics must not echo rejected filenames or values"
    )


@pytest.mark.parametrize("arguments", [["--help"], ["inspect", "--help"]])
def test_HelpDoesNotOpenAWorkspace(monkeypatch, arguments):
    """Base help explains the explicit saved-input selection without reading model or evidence."""

    monkeypatch.setattr(commands, "InspectBusinessEvent", Refuse)
    status, text = Run(arguments, human=True)
    assert status == 0 and "--expected-snapshot-sha256" in text, (
        "Help must expose the complete current model pin"
    )


def test_ChangedModelDuringSupportVerificationRefusesTheFinalProjection(tmp_path, monkeypatch):
    """A cooperating save between original and support reads cannot become a mixed-basis result."""

    root, record, model, support = Owned(tmp_path)
    actual = BoundedReportEvidenceStore.Read
    calls = []

    def ChangeAfterRead(store, reference):
        """Persist one deliberate concurrent update only after a real supporting-byte read."""

        result = actual(store, reference)
        calls.append(reference)

        if len(calls) == 1:
            selected = LocalModelStore(root)
            current = selected.Open()
            asset = next(item for item in current.objects
                         if item.attributes.get("asset_type") == "business-service")
            changed, delta = current.Apply(objects=(replace(asset, attributes={
                **asset.attributes, "concurrent": True,
            }),))
            selected.Save(changed, expected_revision=delta.previous_revision)

        return result

    monkeypatch.setattr(BoundedReportEvidenceStore, "Read", ChangeAfterRead)
    status, result = Run(Arguments(root, record, model))
    assert status == 4 and "inspection" not in result, (
        "The final owning read must refuse a source model that changed during verification"
    )


@pytest.mark.parametrize("failure,expected", [(OSError, 4), (KeyboardInterrupt, 130)])
def test_InterruptedOrFailedSupportReadEmitsNoPartialInspection(
    tmp_path, monkeypatch, failure, expected,
):
    """A late support failure cannot expose earlier verified owner facts as a complete outcome."""

    root, record, model, support = Owned(tmp_path)
    before = Files(tmp_path)

    def Failed(store, reference):
        """Refuse the selected support read with a value that must not reach terminal output."""

        raise failure("PRIVATE_FAILURE")

    monkeypatch.setattr(BoundedReportEvidenceStore, "Read", Failed)
    status, result = Run(Arguments(root, record, model))
    assert status == expected and "inspection" not in result, (
        "Support failure and cancellation must withhold every data-bearing inspection field"
    )
    assert "PRIVATE_FAILURE" not in json.dumps(result), "Do not expose raw exception text"
    assert Files(tmp_path) == before, "A late refusal must leave saved owner facts untouched"


def test_ConsoleDispatchAndShellRetainTheSameRecordsAndPrivateHistory(tmp_path, capsys):
    """Generic command transports preserve model context and canonical inspection semantics."""

    root, record, model, support = Owned(tmp_path)
    arguments = Arguments(root, record, model)
    before = Files(tmp_path)
    assert Main(["business", *arguments, "--json"]) == 0, (
        "The product CLI must expose the retained business operation"
    )
    expected = json.loads(capsys.readouterr().out)
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    basis = shell.State
    shell.onecmd(shlex.join(["business", *arguments, "--json"]))
    assert json.loads(output.getvalue()) == expected and shell.State == basis, (
        "Shell presentation context must neither change inputs nor alter verified records"
    )
    assert list(shell._history) == ["business"] and shell.lastcmd == "business", (
        "Private workspace and original-definition arguments must not enter shell replay history"
    )
    status, text = Run(arguments, human=True)
    assert status == 0 and "Owner-declared unacceptable outcome" in text, (
        "The operator must see that critical membership belongs to the supplied owner scenario"
    )
    assert "Billing service disruption" in text and "billing:0" in text, (
        "Text output must present the actual saved title and critical Assets"
    )
    assert Files(tmp_path) == before, "Both operator transports must preserve every retained byte"
