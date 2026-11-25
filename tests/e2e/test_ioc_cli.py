# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed IOC console imports, independent-anchor replay and refusal output."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from tests.ioc_cli_helpers import RAW, Files, ImportArguments, InspectArguments, Owned


def Console(arguments: list[str]) -> tuple[int, dict]:
    """Invoke the real installed entry point in a separate process with bounded output handling."""

    executable = Path(sys.executable).with_name("1337.exe" if sys.platform == "win32" else "1337")
    result = subprocess.run([str(executable), "trace", *arguments, "--json"],
                            capture_output=True, text=True, timeout=15, check=False)
    assert not result.stderr, "IOC console reflected arguments or leaked a traceback"
    outcome = json.loads(result.stdout)
    assert outcome["exit_code"] == result.returncode, "IOC console exit and machine facts differ"

    return result.returncode, outcome


def test_InstalledConsoleImportsAndReopensRelocatedOriginalEvidence(tmp_path):
    """The shipped console performs actual immutable acquisition and source-free anchored replay."""

    root, source = Owned(tmp_path)
    core = {key: value for key, value in Files(root).items() if key in (
        "workspace.json", "state/model/model.json")}
    status, imported = Console(ImportArguments(root, source))
    assert status == 0 and imported["candidate_count"] == 5 and imported["evidence_commit"] == (
        "confirmed"
    ), "Installed IOC console did not perform accepted acquisition"
    store = LocalEvidenceStore(root / "evidence")
    assert store.Read(store.Get(imported["raw_id"]).reference) == RAW, (
        "Installed IOC console changed supplied original bytes"
    )
    moved = tmp_path / "relocated workspace"
    shutil.move(root, moved)
    source.unlink()
    before = Files(moved)
    status, inspected = Console(InspectArguments(moved, imported))
    assert status == 0 and inspected["candidate_count"] == 5 and inspected["raw_id"] == (
        imported["raw_id"]
    ), "Installed IOC inspect depended on the vanished original physical file"
    assert Files(moved) == before and all(before[key] == value for key, value in core.items()), (
        "Installed IOC import/inspect mutated Core or read-only relocated evidence"
    )


def test_InstalledConsoleExportsVerifiedCandidatesAfterSourceRemoval(tmp_path):
    """Export original occurrences and provenance for an offline consumer through the console."""

    root, source = Owned(tmp_path)
    status, imported = Console(ImportArguments(root, source))
    assert status == 0, "Candidate export fixture did not acquire its original evidence"
    moved = tmp_path / "relocated export workspace"
    root.rename(moved)
    source.unlink()
    before = Files(moved)
    arguments = [*InspectArguments(moved, imported), "--export-candidates"]
    status, result = Console(arguments)
    assert status == 0 and result["evidence_commit"] == "not-attempted", (
        "Candidate export failed or attempted to publish additional evidence"
    )
    exported = result["candidate_export"]
    assert exported["schema_version"] == 1 and exported["profile"] == "ascii-ioc-tsv-v1"
    assert exported["parser_id"] == "ioc-artifacts" and exported["parser_version"] == "1"
    assert exported["raw_evidence_id"] == imported["raw_id"] and exported[
        "acquisition_evidence_id"
    ] == imported["receipt_id"], "Export lost its independently selected original evidence pins"
    assert exported["source"]["source_id"] == "owned.synthetic" and exported[
        "source"
    ]["source_version"] == "fixture-1", "Export changed its original declared source identity"
    candidates = exported["candidates"]
    assert [item["normalized_token"] for item in candidates] == [
        "192.0.2.7", "2001:db8::1", "example.invalid", "a" * 64, "example.invalid"
    ], "Export changed canonical values or collapsed repeated original occurrences"
    assert [item["line_number"] for item in candidates] == [1, 2, 3, 4, 5]
    assert candidates[2]["raw_token"] == "EXAMPLE.Invalid."
    assert candidates[-1]["observed_at"] == "2099-01-01T12:00:00+05:30"
    assert candidates[-1]["observation_timezone"] == "+05:30"
    assert candidates[-1]["observed_at_utc"] == "2099-01-01T06:30:00.000000+00:00"
    assert candidates[0]["observed_at"] is None, "Export invented a source observation time"

    for item in candidates:
        start = item["byte_offset"]
        end = start + item["byte_length"]
        assert RAW[start:end].decode("ascii") == item["raw_token"], (
            "Export coordinates no longer recover each exact token from retained original bytes"
        )

    store = LocalEvidenceStore(moved / "evidence")
    original = json.loads(store.Read(store.Get(imported["snapshot_id"]).reference))
    assert exported == original, "Export rewrote the verified original derived snapshot contract"
    assert result["started_at"] == imported["started_at"] and result["finished_at"] == (
        imported["finished_at"]
    ), "Export replaced the acquisition clock with the replay clock"
    assert result["publisher_authentication"] == "not-assessed" and result["core_mutation"] == (
        "none"
    ), "Export promoted candidates into authenticated sources or model mutations"
    assert Console(arguments) == (status, result), "Repeated read-only export changed its facts"
    assert Files(moved) == before, "Installed candidate export changed retained workspace files"


@pytest.mark.parametrize("raw", [b"bad-source", b""], ids=("malformed", "empty"))
def test_InstalledConsolePreservesRefusedOriginalsAndSafeTerminalTruth(tmp_path, raw):
    """Malformed actual input retains both originals without returning source content or success."""

    root, source = Owned(tmp_path, raw)
    status, result = Console(ImportArguments(root, source, raw))
    assert status == 4 and result["acquisition_state"] == "parse-rejected" and result[
        "evidence_commit"
    ] == "confirmed" and result["snapshot_id"] is None, (
        "Installed IOC console disguised a parser refusal or lost its original evidence"
    )
    assert LocalEvidenceStore(root / "evidence").Read(LocalEvidenceStore(root / "evidence").Get(
        result["raw_id"]
    ).reference) == raw, "Installed console refusal discarded supplied original bytes"


def test_InstalledConsoleRequiresReceiptAndRejectsMetadataOverrides(tmp_path):
    """Real argument routing cannot turn untrusted snapshot metadata into its own trust anchor."""

    root, source = Owned(tmp_path)
    status, result = Console(ImportArguments(root, source))
    assert status == 0, "Installed owned IOC fixture import failed"
    before = Files(root)
    status, rejected = Console(["ioc", "inspect", str(root), "--snapshot", result["snapshot_id"]])
    assert status == 2 and Files(root) == before, "Installed inspect inferred its original receipt"
    status, rejected = Console([*InspectArguments(root, result), "--source-version",
                               "secret-marker"])
    assert status == 2 and "secret-marker" not in str(rejected) and Files(root) == before, (
        "Installed inspect accepted metadata overrides or exposed rejected argument values"
    )


@pytest.mark.parametrize("export", [False, True], ids=("summary", "candidate-export"))
@pytest.mark.parametrize("key", ["raw_id", "receipt_id", "snapshot_id"])
def test_InstalledConsoleRejectsAnyCorruptOriginalChainRole(tmp_path, key, export):
    """Each original owning evidence role is checked through the assembled console route."""

    root, source = Owned(tmp_path)
    status, result = Console(ImportArguments(root, source))
    assert status == 0, "Installed owned IOC fixture import failed"
    record = LocalEvidenceStore(root / "evidence").Get(result[key])
    (root / "evidence" / record.reference.locator).write_bytes(b"corrupted")
    before = Files(root)
    arguments = InspectArguments(root, result)

    if export:
        arguments.append("--export-candidates")

    status, rejected = Console(arguments)
    assert status == 4 and rejected["failure"] == "integrity" and Files(root) == before, (
        "Installed IOC inspect ignored original role corruption or wrote owning evidence"
    )
    assert "candidate_export" not in rejected and all(token not in str(rejected) for token in (
        "EXAMPLE.Invalid.", "192.0.2.7", "opaque.tsv"
    )), "Integrity failure emitted unverified candidate data or declared source metadata"
