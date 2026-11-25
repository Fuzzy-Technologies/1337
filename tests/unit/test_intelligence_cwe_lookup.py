# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify on-demand CWE lookup against exact saved original custody without writes."""

from __future__ import annotations

import hashlib
import json
import shlex
from io import StringIO

import pytest

from fuzzy1337 import intelligence_cwe_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.shell import InteractiveShell
from tests.contract.test_intelligence_cwe_commands_contract import Run
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry


def Saved(parent, version="5.0"):
    """Save one real owned catalog while selecting only a different original Weakness."""

    model, _ = Context(parent)
    raw = Archive(Catalog(b"<Weaknesses>" + Entry("79", name="Original selection")
        + Entry("20", name="New source name é 😀")
        + b"</Weaknesses><Views>" + Entry("1000", kind="View") + b"</Views>",
        version), version)
    source = parent / "original.zip"
    source.write_bytes(raw)
    status, original = Run(["import", str(model.root), str(source), "--catalog-version", version,
        "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--identifier", "CWE-79",
        "--scope", "scope:owned"])
    assert status == 0, "The original owned catalog must enter genuine local product custody."

    return model, source, raw, original


def Lookup(root, original):
    """Select new explicit IDs against the original immutable selection and receipt pair."""

    return ["lookup", str(root), "--selection", original["selection_id"],
        "--receipt", original["receipt_id"], "--identifier", "CWE-9999999",
        "--identifier", "CWE-20", "--identifier", "CWE-1000"]


@pytest.mark.parametrize("version", ["5.0", "4.21"])
def test_NewIdsUseTheSameSavedOriginalAndKeepEveryOwningByte(tmp_path, monkeypatch, version):
    """A deleted input and relocated workspace still answer new IDs from the original ZIP."""

    model, source, raw, original = Saved(tmp_path, version)
    moved = tmp_path / "moved workspace"
    model.root.rename(moved)
    source.unlink()
    before = Files(moved)

    def Forbidden(*arguments, **options):
        """Refuse new acquisition, source-file access and owning persistence during lookup."""

        raise AssertionError("Read-only CWE lookup attempted acquisition or persistence.")

    monkeypatch.setattr(commands, "AcquireLocalCweSelection", Forbidden)
    monkeypatch.setattr(commands, "ReadLocalIntel", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Forbidden)
    monkeypatch.setattr(LocalModelStore, "Save", Forbidden)
    status, result = Run(Lookup(moved, original))
    assert status == 0 and result["profile"] == "cwe-local-original-lookup-cli", (
        "The new action must expose its distinct read-only terminal family."
    )
    assert result["selection"] == original["selection"] and result[
        "selection_reference"
    ] == original["selection_reference"], "Lookup replaced the original verified saved selection."
    assert result["source"] == original["source"] and result["source_sha256"] == hashlib.sha256(
        raw
    ).hexdigest(), "Lookup lost its exact original version, notice or byte identity."
    lookup = result["lookup"]
    selected = lookup["selection"]
    assert lookup["persistence"] == "not-attempted" and lookup[
        "selection_reference"
    ].startswith("cwe-selection:"), "An ephemeral content reference impersonated stored custody."
    assert selected["requested_ids"] == ["CWE-1000", "CWE-20", "CWE-9999999"], (
        "Explicit new IDs were not sorted canonically."
    )
    assert selected["matched_ids"] == ["CWE-20"] and selected["records"][0]["name"] == (
        "New source name é 😀"
    ), "A newly requested Weakness was filtered through the original selection."
    assert selected["unsupported_entries"] == [{"identifier": "CWE-1000", "source_kind": "View"}], (
        "Known unsupported source kinds were relabeled as Weakness or absent."
    )
    assert selected["unmatched_ids"] == ["CWE-9999999"], "An absent ID acquired a source assertion."
    assert selected["catalog_version"] == version and selected["raw_sha256"] == result[
        "source_sha256"
    ], "The lookup silently selected another catalog or original."
    assert result["ack_basis"] == "verified-present" and result[
        "model_commit"
    ] == "not-attempted", (
        "Lookup invented a new publication or model acknowledgement."
    )
    assert Files(moved) == before, "Lookup changed original custody or saved owner bytes."
    status, human = Run(Lookup(moved, original), human=True)
    assert status == 0 and "Original saved selection (verified; unchanged)" in human and (
        "On-demand lookup (not stored; content reference only)" in human
    ), "Human output merged original and on-demand selections."
    assert "unsupported source kind View" in human and "CWE-9999999" in human, (
        "Human output hid unsupported or absent IDs."
    )
    assert Files(moved) == before, "Human lookup changed owning state."


@pytest.mark.parametrize("fault", ["duplicate", "many", "identifier", "root", "scalar", "override"])
def test_InvalidLookupRefusesBeforeAnyOwningPathOrRead(tmp_path, monkeypatch, fault):
    """New selection and immutable-root grammar precede every filesystem boundary."""

    original = {"selection_id": "sha256:" + "a" * 64, "receipt_id": "sha256:" + "b" * 64}
    arguments = Lookup(tmp_path, original)

    if fault == "duplicate":
        arguments += ["--identifier", "CWE-20"]

    elif fault == "many":
        arguments += [item for index in range(62)
                      for item in ("--identifier", "CWE-" + str(index + 2000))]

    elif fault == "identifier":
        arguments[arguments.index("CWE-20")] = "CVE-2024-3094"

    elif fault == "root":
        arguments[arguments.index("--receipt") + 1] = "not-a-manifest"

    elif fault == "scalar":
        arguments += ["--selection=" + original["selection_id"]]

    else:
        arguments += ["--catalog-version", "4.21"]

    def Forbidden(*values, **options):
        """Trip if malformed lookup configuration reaches any owning storage boundary."""

        raise AssertionError("Malformed CWE lookup reached storage.")

    monkeypatch.setattr(commands, "IntelPath", Forbidden)
    monkeypatch.setattr(commands, "LoadAcquiredCweSelection", Forbidden)
    status, result = Run(arguments)
    assert status == 2 and result["failure"] == "configuration" and "lookup" not in result, (
        "Invalid lookup configuration reached custody or produced usable assertions."
    )


@pytest.mark.parametrize("fault", ["raw", "selection", "receipt", "mixed"])
def test_CorruptOrMixedOriginalRefusesBeforeAnyLookupProjection(tmp_path, monkeypatch, fault):
    """Stored corruption and unrelated receipt roots cannot produce newly selected assertions."""

    model, source, raw, original = Saved(tmp_path)
    arguments = Lookup(model.root, original)
    evidence = LocalEvidenceStore(model.root / "evidence")

    if fault == "mixed":
        status, other = Run(["import", str(model.root), str(source), "--catalog-version", "5.0",
            "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--identifier", "CWE-20",
            "--scope", "scope:other"])
        assert status == 0, "An independent original acquisition must precede the mixed-root probe."
        arguments[arguments.index("--receipt") + 1] = other["receipt_id"]

    else:
        record = evidence.Get(original[{"raw": "raw_id", "selection": "selection_id",
                                        "receipt": "receipt_id"}[fault]])
        path = model.root / "evidence" / record.reference.locator
        originalBytes = path.read_bytes()
        path.write_bytes(bytes([originalBytes[0] ^ 1]) + originalBytes[1:])

    source.unlink()
    before = Files(model.root)

    def Forbidden(*values, **options):
        """Trip if failed original custody reaches the on-demand parser."""

        raise AssertionError("Unverified original reached CWE lookup.")

    monkeypatch.setattr(commands, "LookupCweOriginal", Forbidden)
    status, result = Run(arguments)
    assert status == 4 and result["failure"] == "integrity" and all(
        name not in result for name in ("source", "selection", "selection_reference", "lookup")
    ), "A damaged or mixed original emitted partial source assertions."
    assert Files(model.root) == before, "Integrity refusal changed saved owner bytes."


def test_ActualModuleAndShellRoutingKeepLookupReadOnlyAndArgumentsPrivate(tmp_path, capsys):
    """Ordinary dispatch reaches lookup without changing context or the saved selection."""

    model, source, _, original = Saved(tmp_path)
    source.unlink()
    arguments = Lookup(model.root, original)
    before = Files(model.root)
    assert Main(["intel", "cwe", *arguments, "--json"]) == 0, (
        "Ordinary module dispatch refused the verified saved-original lookup."
    )
    expected = json.loads(capsys.readouterr().out)
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd("intel cwe " + shlex.join([*arguments, "--json"]))
    assert json.loads(output.getvalue()) == expected and list(shell._history) == ["intel"], (
        "Shell lookup changed results or retained private source selection arguments."
    )
    assert Files(model.root) == before, "Actual dispatch wrote to the saved workspace."


def test_PresentationRefusalNeverLeavesUsableLookupContent(tmp_path, monkeypatch):
    """A bounded failed fallback preserves original custody handles without on-demand assertions."""

    model, _, _, original = Saved(tmp_path)
    monkeypatch.setattr(commands, "MAX_TERMINAL_BYTES", 100)
    status, result = Run(Lookup(model.root, original))
    assert status == 4 and result["failure"] == "presentation-limit" and "lookup" not in result, (
        "A partial lookup escaped the terminal ceiling."
    )
    assert result["raw_id"] == original["raw_id"] and result["ack_basis"] == "verified-present", (
        "Presentation failure erased the verified original custody basis."
    )


def test_LookupShortWriteIsOneFailedAttemptWithoutAutomaticReplay(tmp_path):
    """A caller-owned incomplete stream cannot receive a false successful lookup result."""

    model, _, _, original = Saved(tmp_path)

    class ShortOutput:
        """Count actual write attempts and deliberately truncate the response."""

        calls = 0

        def Write(self, text):
            """Report an incomplete write once without leaking source content."""

            self.calls += 1

            return len(text) - 1

        write = Write

    output = ShortOutput()

    with pytest.raises(OSError, match="not written completely"):
        commands.RunCweIntelCommands(Lookup(model.root, original), output, json_output=True)

    assert output.calls == 1, "Lookup silently retried a truncated terminal response."


def test_LookupHelpIsStorageIndependentAndInspectStillRejectsReplacementIds(monkeypatch):
    """The additive action does not broaden the accepted exact-inspection grammar."""

    def Forbidden(*values, **options):
        """Trip any storage access while requesting exact help or invalid inspect replacement."""

        raise AssertionError("Lookup help or rejected inspect arguments reached storage.")

    monkeypatch.setattr(commands, "IntelPath", Forbidden)
    status, human = Run(["lookup", "--help"], human=True)
    assert status == 0 and "--identifier" in human, "New action help required stored custody."
    status, result = Run(["inspect", "unused", "--selection", "sha256:" + "a" * 64,
        "--receipt", "sha256:" + "b" * 64, "--identifier", "CWE-20"])
    assert status == 2 and "lookup" not in result, (
        "Exact inspect silently acquired lookup semantics."
    )
