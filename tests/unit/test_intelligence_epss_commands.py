# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local selected EPSS command preflight, truthful acknowledgements and safe presentation."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import intelligence_acquisition
from fuzzy1337 import intelligence_epss_commands as commands
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intelligence_commands import RunIntelCommands
from fuzzy1337.model import LocalModelStore
from tests.e2e.test_intelligence_cli import Files
from tests.e2e.test_intelligence_epss_cli import Body, ImportArguments, Selection
from tests.integration.test_intelligence_acquisition_persistence import Context


def Run(arguments: list[str], *, human: bool = False) -> tuple[int, dict | str]:
    """Exercise actual parent namespace dispatch while measuring the local CLI implementation."""

    output = StringIO()
    status = RunIntelCommands(arguments, output, json_output=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())


def Imported(tmp_path: Path) -> tuple[Path, dict]:
    """Acquire actual original gzip and fully acknowledged custody through the parent router."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    status, outcome = Run(ImportArguments(model.root, source))
    assert status == 0 and isinstance(outcome, dict), "Selected EPSS fixture acquisition failed."

    return model.root, outcome


@pytest.mark.parametrize("arguments", [
    [], ["remote", "untrusted-value"], ["apply", "untrusted-value"], ["apply", "--help"],
    ["import", "untrusted-value"], ["inspect", "untrusted-value"],
    ["inspect", "untrusted-value", "--selection", "untrusted-value", "--receipt"],
])
def test_InvalidGrammarUsesFixedDiagnostics(arguments):
    """Unsupported or incomplete grammar never echoes source values or filesystem paths."""

    status, outcome = Run(["epss", *arguments])
    assert status == 2 and outcome["failure"] == "configuration", (
        "Invalid selected EPSS grammar escaped the configuration failure boundary."
    )
    assert "untrusted-value" not in json.dumps(outcome), "Rejected arguments leaked into output."


@pytest.mark.parametrize("action,expected", [(None, "import,inspect"), ("import", "--terms-url"),
                                             ("inspect", "--selection")])
def test_HelpUsesCallerStreamWithoutOpeningWorkspace(action, expected):
    """Help explains explicit action selection without source reads or local workspace access."""

    arguments = ["epss", "--help"] if action is None else ["epss", action, "--help"]
    status, human = Run(arguments, human=True)
    assert status == 0 and expected in human, "Selected action help omitted its required options."


@pytest.mark.parametrize("case", ["identifier", "duplicate-id", "many-ids", "many-terms",
                                  "duplicate-terms", "scope", "origin", "url", "date",
                                  "limit-zero", "limit-large", "limit-type", "abbreviation",
                                  "duplicate-scalar", "pin", "workspace-path"])
def test_InvalidSourceConfigurationRefusesBeforeFileRead(tmp_path, monkeypatch, case):
    """Every caller source, selection and budget constraint is checked before original bytes."""

    model, _ = Context(tmp_path)
    source = tmp_path / "untrusted-value.csv.gz"
    arguments = ImportArguments(model.root, source)

    if case == "duplicate-id":
        arguments.extend(["--identifier", "CVE-1900-9999"])

    elif case == "many-ids":
        for index in range(63):
            arguments.extend(["--identifier", f"CVE-1900-{10000 + index}"])

    elif case in ("many-terms", "duplicate-terms"):
        urls = ["https://example.invalid/terms"] if case == "duplicate-terms" else [
            f"https://example.invalid/terms{index}" for index in range(3)
        ]

        for url in urls:
            arguments.extend(["--terms-url", url])

    elif case == "duplicate-scalar":
        arguments.extend(["--publisher", "untrusted-value"])

    elif case == "abbreviation":
        arguments[arguments.index("--publisher")] = "--pub"

    elif case == "workspace-path":
        arguments[2] = "../untrusted-value"

    else:
        option, value = {
            "identifier": ("--identifier", "CWE-89"), "scope": ("--scope", ""),
            "origin": ("--origin", "untrusted-value"),
            "url": ("--source-url", "https://example.invalid/scores?untrusted-value=1"),
            "date": ("--score-date", "2026-13-01"), "limit-zero": ("--max-bytes", "0"),
            "limit-large": ("--max-bytes", "4194305"),
            "limit-type": ("--max-bytes", "untrusted-value"),
            "pin": ("--expected-sha256", "untrusted-value"),
        }[case]

        if option in arguments:
            arguments[arguments.index(option) + 1] = value

        else:
            arguments.extend([option, value])

    def RefuseRead(*args):
        """Trip if invalid configuration reaches the original selected source reader."""

        raise AssertionError("Invalid EPSS source configuration reached the input reader.")

    monkeypatch.setattr(commands, "ReadLocalIntel", RefuseRead)
    before = Files(model.root)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", (
        "Invalid source configuration passed the original-byte preflight boundary."
    )
    assert "untrusted-value" not in json.dumps(outcome) and Files(model.root) == before, (
        "Rejected source configuration leaked a value or changed owning state."
    )


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "missing"])
def test_OriginalInputUsesOwningPhysicalFileChecks(tmp_path, kind):
    """Local source selection refuses links and nonphysical files without publishing evidence."""

    model, _ = Context(tmp_path)
    original = tmp_path / "original.csv.gz"
    original.write_bytes(Body())
    source = tmp_path / "untrusted-value.csv.gz"

    if kind == "symlink":
        source.symlink_to(original)

    elif kind == "hardlink":
        os.link(original, source)

    elif kind == "directory":
        source.mkdir()

    before = Files(model.root)
    status, outcome = Run(ImportArguments(model.root, source))
    assert status == 2 and outcome["failure"] == "configuration", (
        "Observed nonphysical input crossed the shared singly-linked-file boundary."
    )
    assert Files(model.root) == before and "untrusted-value" not in json.dumps(outcome), (
        "Rejected physical source input published evidence or disclosed its filename."
    )


def test_ActualImportInspectAndHumanPresentationRetainTermsTimeAndUnknowns(tmp_path):
    """The local namespace exposes every selected source assertion and independent unknowns."""

    root, imported = Imported(tmp_path)
    before = Files(root)
    status, inspected = Run(Selection(root, imported))
    assert status == 0 and inspected["selection"] == imported["selection"], (
        "Actual read-only replay changed persisted selected source assertions."
    )
    assert Files(root) == before and inspected["model_commit"] == "not-attempted", (
        "Selected EPSS inspection changed owning files or entered a model save."
    )
    status, human = Run(Selection(root, imported), human=True)
    assert status == 0 and all(value in human for value in (
        "intel.epss.inspect: succeeded", "CVE-1900-9999", "CVE-1900-8888", "2e-1",
        "https://example.invalid/terms", "https://example.invalid/attribution", "synthetic-1",
        "2026-10-12", "next 30 days", "not assessed", "not been evaluated",
        imported["selection_id"], imported["receipt_id"], imported["raw_id"],
    )), "Human source presentation omitted source assertions, terms, time, unknowns or custody."
    assert "cve,epss" not in human, "Human selected inspection printed the original source body."


@pytest.mark.parametrize("stage", ["raw", "selection", "receipt"])
@pytest.mark.parametrize("committed", [False, True])
def test_PublicationLossNeverBecomesFalseCompleteCustody(tmp_path, monkeypatch, stage, committed):
    """Actual publication refusal or lost acknowledgement retains independently observed facts."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    original = LocalEvidenceStore.Put
    role = {"raw": "epss-gzip-source", "selection": "epss-selected-snapshot",
            "receipt": "epss-selection-acquisition"}[stage]

    def Put(owner, data, selected_role, media_type, provenance):
        """Optionally publish the actual immutable artifact before losing its acknowledgement."""

        if selected_role != role:
            return original(owner, data, selected_role, media_type, provenance)

        if committed:
            original(owner, data, selected_role, media_type, provenance)

        raise EvidenceError("untrusted-value publication failure")

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    before_model = model.Open()
    status, outcome = Run(ImportArguments(model.root, source))
    assert status == 4 and outcome["status"] == "failed" and outcome[
        "acquisition_state"
    ] == "storage-failed", "A publication acknowledgement loss became successful local custody."
    assert outcome[stage + "_ack"] == "unknown" and outcome[stage + "_id"] is None, (
        "The CLI inferred an unacknowledged immutable artifact handle."
    )
    assert "selection" not in outcome and "source" not in outcome, (
        "Incomplete custody exposed usable selected source output."
    )
    if stage != "raw":
        assert outcome["raw_ack"] == "confirmed" and outcome["raw_id"] is not None, (
            "A later storage failure discarded already acknowledged original custody."
        )

    if stage == "receipt":
        assert outcome["selection_ack"] == "confirmed" and outcome["selection_id"] is not None, (
            "Receipt failure erased the independently acknowledged selected artifact."
        )

    assert "untrusted-value" not in json.dumps(outcome) and model.Open() == before_model, (
        "Storage failure leaked exception details or changed authoritative model state."
    )


@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_UnreturnedAcquisitionCannotClaimKnownPublicationState(tmp_path, monkeypatch, failure):
    """A missing terminal SDK result is uncertain and never reconstructed as complete custody."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())

    def Acquire(*args, **kwargs):
        """Represent an interrupted acquisition that supplies no terminal publication facts."""

        raise failure("untrusted-value")

    monkeypatch.setattr(commands, "AcquireLocalEpssSelection", Acquire)
    status, outcome = Run(ImportArguments(model.root, source))
    assert status == (130 if failure is KeyboardInterrupt else 4) and outcome[
        "status"
    ] == "failed", "Unreturned SDK acquisition became CLI success."
    assert all(outcome[key] == "unknown" for key in ("raw_ack", "selection_ack", "receipt_ack")), (
        "CLI guessed publication rollback without a terminal SDK acknowledgement."
    )
    assert "untrusted-value" not in json.dumps(outcome), "Interrupted acquisition leaked content."


def test_SucceededStateWithoutAcknowledgedReceiptStillRefusesUsableSelection(tmp_path, monkeypatch):
    """Success is the complete actual SDK result, never only its terminal state enum."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    original = commands.AcquireLocalEpssSelection

    def Acquire(*args, **kwargs):
        """Preserve actual artifact writes while removing the receipt acknowledgement."""

        acquired = original(*args, **kwargs)

        return replace(acquired, receipt=None, receipt_ack=commands.EpssAcknowledgement.UNKNOWN)

    monkeypatch.setattr(commands, "AcquireLocalEpssSelection", Acquire)
    status, outcome = Run(ImportArguments(model.root, source))
    assert status == 4 and outcome["receipt_ack"] == "unknown" and "selection" not in outcome, (
        "An SDK succeeded label bypassed the complete receipt acknowledgement requirement."
    )


def test_InspectionIntegrityFailureDoesNotExposeUnverifiedSelection(tmp_path):
    """An absent selected manifest is a fixed integrity failure without source or model writes."""

    root, imported = Imported(tmp_path)
    arguments = Selection(root, dict(imported, selection_id="sha256:" + "0" * 64))
    before = Files(root)
    status, outcome = Run(arguments, human=True)
    assert status == 4 and "integrity" in outcome and "CVE-1900-9999" not in outcome, (
        "Failed exact selected custody presented unverified source assertions."
    )
    assert Files(root) == before, "Failed selection inspection changed retained state."


def test_LocalNamespaceNeverFetchesOrSavesAndAcceptsInclusiveSelectionBounds(tmp_path, monkeypatch):
    """Actual local import and replay remain offline and read-only for all 64 selected IDs."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    arguments = ImportArguments(model.root, source)

    for index in range(62):
        arguments.extend(["--identifier", f"CVE-1900-{10000 + index}"])

    for index in range(2):
        arguments.extend(["--terms-url", f"https://example.invalid/additional{index}"])

    def Refuse(*args, **kwargs):
        """Trip on any attempted remote acquisition or authoritative model mutation."""

        raise AssertionError("Local EPSS entered remote acquisition or a model save.")

    monkeypatch.setattr(intelligence_acquisition, "FetchRemoteBytes", Refuse)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, imported = Run(arguments)
    assert status == 0 and len(imported["selection"]["requested_ids"]) == 64 and len(
        imported["source"]["terms_urls"]
    ) == 4, "The inclusive 64-CVE or four-terms bound was reduced or truncated."
    status, inspected = Run(Selection(model.root, imported))
    assert status == 0 and len(inspected["selection"]["unmatched_ids"]) == 63, (
        "Offline exact replay enlarged matches or silently dropped unmatched selected CVEs."
    )


def test_HumanMatchedOnlyImportEscapesDeclaredPublisherControls(tmp_path):
    """Terminal formatting escapes directional metadata and handles an entirely matched scope."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    arguments = ImportArguments(model.root, source)
    selected = arguments.index("CVE-1900-8888")
    del arguments[selected - 1:selected + 1]
    arguments[arguments.index("--publisher") + 1] = "Owned fixture\u202e"
    status, human = Run(arguments, human=True)
    assert status == 0 and "\\u202e" in human and "\u202e" not in human, (
        "Declared source metadata could activate terminal directional formatting."
    )
    assert "Not present" not in human and "CVE-1900-9999" in human, (
        "A wholly matched selected source manufactured unmatched identifiers."
    )
