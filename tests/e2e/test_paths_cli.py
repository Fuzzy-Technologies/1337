# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed path console over selected snapshots and immutable source attestations."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.contract.reachability_fixture import Fixture
from tests.integration.test_path_command_workflow import Selected
from tests.path_command_helpers import Files, SmallArguments, SmallGraph, Value


def Console(arguments):
    """Run the installed console through ordinary root routing without direct handler access."""

    executable = Path(sys.executable).with_name("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(executable), "paths", *arguments, "--json"],
                            capture_output=True, text=True, check=False, timeout=15)
    assert not result.stderr, "Path console emitted source content or an unhandled traceback"
    document = json.loads(result.stdout)
    assert result.returncode == document["exit_code"], "Path console and terminal status disagree"

    return result.returncode, document


def test_InstalledUnassessedGraphKeepsKnownCountsAndIndependentTruncation(tmp_path):
    """The console traverses actual stores and preserves the independent small graph oracle."""

    context = SmallGraph(tmp_path)
    before = Files(context[0])
    status, result = Console(SmallArguments(context))
    assert status == 0 and len(result["analysis"]["search"]["paths"]) == 2 and len(
        result["analysis"]["cuts"]["verified"]
    ) == 2, "Installed path analysis lost its known original graph/cut oracle"
    status, bounded = Console(Value(SmallArguments(context), "--max-depth", "1"))
    assert status == 0 and not bounded["analysis"]["search"]["complete"] and bounded[
        "analysis"
    ]["cuts"]["complete"], "Installed console merged independent search/cut truncation"
    assert Files(context[0]) == before, "Installed path command wrote authoritative owner state"


def test_InstalledOriginalAttestationsReplayAfterRelocationWithoutWrites(tmp_path):
    """Console admission consumes retained source manifests and survives relocation."""

    fixture = Fixture.Create(tmp_path / "owned original workspace")
    records = fixture.Phase("remediation")
    before = Files(fixture.root)
    status, original = Console(Selected(fixture, records))
    assert status == 0 and any(path["state"] == "BLOCKED"
        for path in original["analysis"]["search"]["paths"]), (
        "Installed source admission lost the original named barrier outcome"
    )
    moved = tmp_path / "moved workspace"
    shutil.move(fixture.root, moved)
    fixture.root = moved
    status, replayed = Console(Selected(fixture, records))
    assert status == 0 and replayed == original and Files(moved) == before, (
        "Installed original path replay changed after relocation or wrote evidence"
    )
    assert "synthetic-private-source-value" not in str(replayed) and "_seal" not in str(replayed), (
        "Installed path DTO leaked raw witnesses or private SDK seals"
    )


def test_InstalledExpectedPinAndMissingAssessmentGrammarCannotInventDefaults(tmp_path):
    """The console refuses substituted model pins and omitted explicit no-assessment selection."""

    context = SmallGraph(tmp_path)
    before = Files(context[0])
    status, result = Console(Value(SmallArguments(context), "--expected-snapshot-sha256", "a" * 64))
    assert status == 4 and result["analysis"] is None, (
        "Installed console accepted changed model pin"
    )
    arguments = SmallArguments(context)
    arguments.remove("--no-assessments")
    status, result = Console(arguments)
    assert status == 2 and Files(context[0]) == before, "Installed console inferred proof selection"
