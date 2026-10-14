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


@pytest.mark.parametrize("key", ["raw_id", "receipt_id", "snapshot_id"])
def test_InstalledConsoleRejectsAnyCorruptOriginalChainRole(tmp_path, key):
    """Each original owning evidence role is checked through the assembled console route."""

    root, source = Owned(tmp_path)
    status, result = Console(ImportArguments(root, source))
    assert status == 0, "Installed owned IOC fixture import failed"
    record = LocalEvidenceStore(root / "evidence").Get(result[key])
    (root / "evidence" / record.reference.locator).write_bytes(b"corrupted")
    before = Files(root)
    status, rejected = Console(InspectArguments(root, result))
    assert status == 4 and rejected["failure"] == "integrity" and Files(root) == before, (
        "Installed IOC inspect ignored original role corruption or wrote owning evidence"
    )
