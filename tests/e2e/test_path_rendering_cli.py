# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed console renders the same verified selected graph without durable owner changes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from tests.contract.reachability_fixture import Fixture
from tests.integration.test_path_command_workflow import Selected
from tests.path_command_helpers import Files


def Console(arguments):
    """Invoke the real installed entry point with caller-selected presentation arguments."""

    executable = Path(sys.executable).with_name("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(executable), "paths", *arguments], capture_output=True,
                            text=True, check=False, timeout=15)
    assert not result.stderr, "Installed renderer exposed a traceback or source diagnostic"

    return result


def test_InstalledHtmlRetainsActualOriginalBarrierAndExactMachineOutput(tmp_path):
    """The installed command consumes original proof and preserves the independent JSON contract."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("remediation")
    arguments = Selected(fixture, records)
    before = Files(fixture.root)
    ordinary = Console([*arguments, "--json"])
    rendered = Console([*arguments, "--html"])
    selected = re.search(r'<script id="analysis-json" type="application/json">(.*?)</script>',
                         rendered.stdout, re.DOTALL)
    assert ordinary.returncode == rendered.returncode == 0 and selected is not None, (
        "Installed selected-graph renderer failed original source admission"
    )
    assert json.loads(selected.group(1)) == json.loads(ordinary.stdout), (
        "Installed HTML changed original machine-readable states/provenance/completeness"
    )
    assert "BLOCKED" in rendered.stdout and (
        "synthetic-private-source-value" not in rendered.stdout
    ), (
        "Installed rendered graph lost its original barrier or exposed raw witnesses"
    )
    refused = Console([*arguments, "--html", "--json"])
    assert refused.returncode == 2 and "<!doctype" not in refused.stdout, (
        "Conflicting presentation modes produced partial successful HTML"
    )
    assert Files(fixture.root) == before, "Installed renderer mutated authoritative owner bytes"
