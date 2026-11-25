# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Detached verified candidate presentation without new ingestion or Core semantics."""

import base64
import hashlib
import json
import shutil
from io import StringIO

import pytest

from fuzzy1337 import ioc_bundle as bundles
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.ioc_commands import RunIocCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract.report_export_fixture import DenyExecution
from tests.ioc_cli_helpers import (
    BundleVerifyArguments,
    ExportArguments,
    Files,
    ImportArguments,
    Owned,
    Run,
)


def test_DetachedExportRetainsExactSnapshotAndDefaultOutcomeAfterWorkspaceDeletion(
    tmp_path, monkeypatch,
):
    """Expose the existing DTO only after source-free verification and explicit machine opt-in."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Acquire the original selected evidence before testing detached consumption"
    store = LocalEvidenceStore(root / "evidence")
    expected = json.loads(store.Read(store.Get(imported["snapshot_id"]).reference))
    destination = tmp_path / "received bundle.json"
    status, transferred = Run(ExportArguments(root, imported, destination))
    assert status == 0, "Export the actual original chain through the product owner"
    shutil.rmtree(root)
    source.unlink()
    before = Files(tmp_path)
    DenyExecution(monkeypatch)

    def Denied(*arguments, **options):
        """Reject hidden workspace reopening, acquisition or model writes during detached reads."""

        raise AssertionError("Detached export must read only its independently pinned file")

    monkeypatch.setattr(bundles, "LoadIocArtifact", Denied)
    monkeypatch.setattr(LocalWorkspaceStore, "Open", Denied)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Denied)
    monkeypatch.setattr(LocalModelStore, "Create", Denied)
    monkeypatch.setattr(LocalModelStore, "Save", Denied)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Denied)
    arguments = BundleVerifyArguments(destination, transferred)
    status, summary = Run(arguments)
    assert status == 0 and "candidate_export" not in summary, (
        "Default detached verification must retain its existing data-free terminal outcome"
    )
    status, result = Run([*arguments, "--export-candidates"])
    assert status == 0 and result["candidate_export"] == expected, (
        "Export must preserve every original candidate, coordinate, timestamp and attribution field"
    )
    summaryOnly = dict(result)
    del summaryOnly["candidate_export"]
    assert summaryOnly == summary, "Explicit export must not change the existing outcome DTO"
    assert result["evidence_commit"] == "not-attempted" and result["core_mutation"] == "none", (
        "Detached presentation must not become acquisition or a Core interpretation"
    )
    assert result["output_published"] is False, "Stdout presentation must create no output file"
    assert Run([*arguments, "--export-candidates"]) == (status, result), (
        "Repeated verified presentation must preserve the original facts without a new clock"
    )
    assert Run(arguments) == (0, summary), "Omitting the option must restore the unchanged summary"
    assert Files(tmp_path) == before, "Detached verification must leave every saved file unchanged"


@pytest.mark.parametrize("role", [0, 1, 2], ids=("raw", "receipt", "snapshot"))
def test_CorruptDetachedRoleCannotEmitCandidatesEvenWithARehashedTransfer(tmp_path, role):
    """Every original role must pass verification before the optional data-bearing field exists."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Acquire actual originals for the corrupt detached-role oracle"
    destination = tmp_path / "received.json"
    status, transferred = Run(ExportArguments(root, imported, destination))
    assert status == 0, "Export the complete original transfer before altering a selected role"
    document = json.loads(destination.read_bytes())
    payload = base64.b64decode(document["records"][role]["payload_base64"])
    document["records"][role]["payload_base64"] = base64.b64encode(
        bytes([payload[0] ^ 1]) + payload[1:]).decode()
    changed = bundles.JsonBytes(document)
    destination.write_bytes(changed)
    selected = {**transferred, "bundle_sha256": hashlib.sha256(changed).hexdigest()}
    shutil.rmtree(root)
    source.unlink()
    before = Files(tmp_path)
    status, refused = Run([*BundleVerifyArguments(destination, selected), "--export-candidates"])
    assert status == 4 and refused["failure"] == "integrity", (
        "Rehashing the wrapper must not admit a changed original acquisition role"
    )
    assert "candidate_export" not in refused, "Integrity refusal must emit no candidate DTO"
    assert "EXAMPLE.Invalid." not in json.dumps(refused), "Refusal must not disclose tokens"
    assert Files(tmp_path) == before, "Refusal must not rewrite its selected source"


@pytest.mark.parametrize("mode", ["text-verify", "mixed-match", "export-bundle"])
def test_DetachedCandidateExportRejectsInvalidCombinationsBeforeFileAccess(
    tmp_path, monkeypatch, mode,
):
    """Explicit machine disclosure belongs only to detached verification."""

    def Denied(*arguments, **options):
        """Reject any selected-file or original evidence read after invalid option combinations."""

        raise AssertionError("Invalid detached export options must fail before reading evidence")

    monkeypatch.setattr(bundles, "SelectedPath", Denied)
    monkeypatch.setattr(bundles, "ReadArtifactFile", Denied)
    monkeypatch.setattr(bundles, "VerifyIocBundle", Denied)
    receipt = "sha256:" + "a" * 64
    arguments = ["ioc", "verify-bundle", str(tmp_path / "absent.json"), "--receipt", receipt,
                 "--expected-sha256", "b" * 64, "--export-candidates"]
    machine = mode != "text-verify"

    if mode == "mixed-match":
        arguments.extend(("--match", "dns", "untrusted.invalid"))

    elif mode == "export-bundle":
        arguments = ["ioc", "export-bundle", str(tmp_path), "--snapshot", "sha256:" + "b" * 64,
                     "--receipt", receipt, "--include-originals",
                     "--output", str(tmp_path / "absent.json"), "--export-candidates"]

    output = StringIO()
    assert RunIocCommands(arguments, output, json_output=machine) == 2, (
        "Unsupported detached disclosure selections must fail with configuration status"
    )
    assert "configuration" in output.getvalue() and "candidate_export" not in output.getvalue(), (
        "Invalid selections must not produce a candidate field or a partial data-bearing result"
    )
    assert "untrusted.invalid" not in output.getvalue(), "Refusal must not reflect rejected data"
    assert not list(tmp_path.iterdir()), "Invalid selections must create no files or workspace"


def test_ValidDifferentAcquisitionCannotChooseItsOwnReceiptForDetachedExport(tmp_path):
    """A self-consistent replacement transfer still cannot replace the independent original pin."""

    root, source = Owned(tmp_path)
    status, original = Run(ImportArguments(root, source))
    assert status == 0, "Acquire the independently selected original receipt first"
    arguments = ImportArguments(root, source)
    arguments[arguments.index("--license-name") + 1] = "other-declaration"
    status, alternative = Run(arguments)
    assert status == 0, "The replacement must be an actual valid independently recorded acquisition"
    destination = tmp_path / "alternative.json"
    status, transferred = Run(ExportArguments(root, alternative, destination))
    assert status == 0, "Export the real alternative chain for the independent-pin negative case"
    selected = {**transferred, "receipt_id": original["receipt_id"]}
    before = Files(tmp_path)
    status, refused = Run([*BundleVerifyArguments(destination, selected), "--export-candidates"])
    assert status == 4 and "candidate_export" not in refused, (
        "A candidate transfer cannot supply its own trusted receipt when disclosing candidates"
    )
    assert Files(tmp_path) == before, "Independent-pin refusal must preserve every original chain"
