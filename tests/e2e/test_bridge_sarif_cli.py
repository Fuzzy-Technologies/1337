# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed external SARIF intake, copied original custody and zero source-URI side effects."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sarif_helpers import (
    SHA256,
    Document,
    Files,
    Golden,
    ImportArguments,
    InspectArguments,
    Raw,
)


def Console(parent, arguments, expected=0):
    """Invoke the actual installed console with explicit local selections and fixed exit checks."""

    console = Path(sys.executable).parent / ("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(console), *arguments, "--json"], cwd=parent, capture_output=True,
                            text=True, timeout=30, check=False)
    assert result.returncode == expected and not result.stderr, (
        "The installed saved-report console must preserve its exact exit and bounded diagnostics"
    )

    return json.loads(result.stdout)


GUARDED = r"""
"Run the installed source-only inspector with all external actions denied."

import os
import sys
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore


def Denied(*arguments, **options):
    "Reject owning persistence during original verification."

    raise AssertionError("Read-only SARIF inspection attempted persistence")


def Guard(event, arguments):
    "Keep declared SARIF locators inert and all physical actions read-only."

    if event in {"socket.__new__", "socket.connect", "socket.connect_ex",
                 "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.exec"}:
        raise AssertionError("Saved SARIF inspection attempted an external action")

    if event == "open":
        path, mode, flags = arguments

        if "simple-example.js" in str(path) or "schemastore" in str(path):
            raise AssertionError("Saved SARIF metadata became a file read")

        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError("Saved SARIF inspection attempted a file write")


LocalEvidenceStore.Put = Denied
LocalModelStore.Save = Denied
LocalWorkspaceStore.Save = Denied
sys.addaudithook(Guard)
raise SystemExit(Main(sys.argv[1:]))
"""


def test_InstalledSarifImportPreservesExternalFactsAfterSourceDeletionAndCopiedReplay(tmp_path):
    """Use external ESLint bytes through installed intake and copied original replay."""

    root = tmp_path / "owned workspace"
    Console(tmp_path, ["workspace", "create", str(root), "--id", "sarif-console",
                      "--name", "Owned saved SARIF"])
    Console(tmp_path, ["scope", "create", str(root), "--id", "owned",
                      "--allow-ip", "192.0.2.1"])
    source = tmp_path / "external ESLint.sarif"
    raw = Raw()
    source.write_bytes(raw)
    beforeModel = LocalModelStore(root).Open()
    beforeWorkspace = LocalWorkspaceStore(root).Open()
    imported = Console(tmp_path, ["bridge", *ImportArguments(root, source)])
    assert imported["projection"] == Golden() and imported["source_sha256"] == SHA256, (
        "The real external report must retain its independent source-field and original-byte oracle"
    )
    assert imported["original_commit"] == imported["receipt_commit"] == "confirmed", (
        "A successful import must return both independent immutable publication handles"
    )
    assert imported["model_commit"] == imported["workspace_commit"] == "not-attempted", (
        "Source-report intake must not claim a canonical model/workspace update"
    )
    evidence = LocalEvidenceStore(root / "evidence")
    original = evidence.Get(imported["original_id"])
    assert evidence.Read(original.reference) == raw and original.reference.sha256 == (
        hashlib.sha256(raw).hexdigest()
    ), "The evidence owner must retain exact original external bytes"
    assert original.provenance.tool_version is None and original.provenance.execution is None and (
        original.provenance.invocation_sha256 is None
    ), "The report's declared tool cannot become a locally observed tool execution"
    assert LocalModelStore(root).Open() == beforeModel and LocalWorkspaceStore(root).Open() == (
        beforeWorkspace
    ), "Imported source assertions must not silently change canonical owners"
    changed = Document()
    changed["runs"][0]["results"][0]["message"]["text"] = "Another owned report assertion."
    alternate = json.dumps(changed).encode("utf-8")
    source.write_bytes(alternate)
    other = Console(tmp_path, ["bridge", *ImportArguments(
        root, source, hashlib.sha256(alternate).hexdigest())])
    copied = tmp_path / "copied workspace"
    shutil.copytree(root, copied)
    shutil.rmtree(root)
    source.unlink()
    before = Files(copied)
    arguments = ["bridge", *InspectArguments(copied, imported)]
    inspected = Console(tmp_path, arguments)
    assert inspected["projection"] == Golden() and inspected["ack_basis"] == "verified-present", (
        "Copied original/receipt/SHA verification must preserve source facts without the input file"
    )
    assert Console(tmp_path, arguments) == inspected and Files(copied) == before, (
        "Repeated inspection must preserve every saved byte and original source fact"
    )
    guarded = subprocess.run([sys.executable, "-I", "-B", "-c", GUARDED, *arguments, "--json"],
        cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert guarded.returncode == 0 and not guarded.stderr and json.loads(
        guarded.stdout
    ) == inspected, "Installed inspection must survive denied network/source reads/writes/execution"
    assert Files(copied) == before, "Guarded inspection cannot mutate original custody"
    mixed = list(arguments)
    mixed[mixed.index("--receipt") + 1] = other["receipt_id"]
    refused = Console(tmp_path, mixed, expected=4)
    assert "projection" not in refused and Files(copied) == before, (
        "A different legitimate receipt cannot supply source authority for the selected original"
    )
    wrong = list(arguments)
    wrong[-1] = "a" * 64
    refused = Console(tmp_path, wrong, expected=4)
    assert "projection" not in refused and Files(copied) == before, (
        "A wrong external original-byte pin must fail without partial source assertions"
    )
    blob = copied / "evidence" / original.reference.locator
    blob.write_bytes(b"corrupt retained external report")
    corrupted = Files(copied)
    refused = Console(tmp_path, arguments, expected=4)
    assert "projection" not in refused and Files(copied) == corrupted, (
        "Corrupt original bytes must refuse rather than restore content from a source URI"
    )
    assert LocalModelStore(copied).Open() == beforeModel, (
        "Even retained corruption cannot create targets, canonical findings or model changes"
    )
