# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual console pair workflows; an explicit fresh-wheel console can own installed acceptance."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tests.contract.reachability_fixture import Fixture
from tests.contract.test_path_comparison_contract import OriginalArguments, PairArguments
from tests.path_command_helpers import Files, Value


def Console(arguments):
    """Invoke product dispatch, removing checkout imports for an explicit installed console."""

    selected = os.environ.get("FUZZY1337_PATH_COMPARISON_CONSOLE")
    executable = Path(selected) if selected else Path(sys.executable).with_name(
        "1337.exe" if os.name == "nt" else "1337")
    environment = dict(os.environ)

    if selected:
        environment.pop("PYTHONPATH", None)

    result = subprocess.run([str(executable), "paths", *arguments], env=environment,
                            capture_output=True, text=True, check=False, timeout=20)
    assert not result.stderr, "Console pair exposed a traceback or original argument diagnostic."

    return result


def test_ActualConsoleRetainsBothOriginalsExactDownloadsAndPortableReplay(tmp_path):
    """Actual console output preserves original graphs without saved owner changes."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before, after = fixture.Phase("confirmed"), fixture.Phase("remediation")
    arguments = PairArguments(fixture, before, after)
    retained = Files(fixture.root)
    original_before = Console([*OriginalArguments(fixture, before), "--json"])
    original_after = Console([*OriginalArguments(fixture, after), "--json"])
    machine = Console([*arguments, "--json"])
    rendered = Console([*arguments, "--html"])
    assert original_before.returncode == original_after.returncode == machine.returncode == (
        rendered.returncode
    ) == 0, "Actual console comparison failed its original owning interface."
    result = json.loads(machine.stdout)
    assert result["before"] == json.loads(original_before.stdout) and result["after"] == json.loads(
        original_after.stdout,
    ), "Console pair differs from independent original machine outcomes."
    download = re.search(r'download="path-comparison.json" href="data:application/json;'
                         r'base64,([^"]+)"', rendered.stdout).group(1)
    assert base64.b64decode(download).decode() == machine.stdout, (
        "Actual static download differs byte-for-byte from machine stdout."
    )
    moved = tmp_path / "relocated"
    shutil.move(fixture.root, moved)
    fixture.root = moved
    relocated = Console([*PairArguments(fixture, before, after), "--json"])
    assert relocated.returncode == 0 and relocated.stdout == machine.stdout and Files(moved) == (
        retained
    ), "Installed-capable pair changed source state after owning workspace relocation."


def test_ActualConsoleRejectsOtherStateChangeAndStalePinWithoutPartialOutput(tmp_path):
    """Actual product refusals remain bounded failed pairs, and zero change remains valid."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before, after = fixture.Phase("confirmed"), fixture.Phase("likely")
    refused = Console([*PairArguments(fixture, before, after), "--json"])
    result = json.loads(refused.stdout)
    assert refused.returncode == 4 and result["before"] is result["after"] is None, (
        "Actual unrelated state change exposed a successful partial pair."
    )
    stale = Console([*Value(PairArguments(fixture, before, before),
                            "--expected-snapshot-sha256", "0" * 64), "--html"])
    assert stale.returncode == 4 and "<!doctype" not in stale.stdout, (
        "Actual stale pin generated a successful static artifact."
    )
    equal = Console([*PairArguments(fixture, before, before), "--json"])
    assert equal.returncode == 0 and not json.loads(equal.stdout)["observed_state_change"], (
        "Actual zero-change pair failed or became a causal state transition."
    )
