# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real console inspection of relocated saved declarations without active workflows or writes."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.business_inspection_helpers import Arguments, Files, Owned


def Console(parent, arguments, expected=0):
    """Run the selected environment's console with external activity denied by an owned guard."""

    guard = parent / "guard"
    guard.mkdir(exist_ok=True)
    loaded = guard / "loaded"
    (guard / "sitecustomize.py").write_text('''
"""Refuse active execution while the operator reopens already retained business facts."""
import sys
from pathlib import Path
Path(''' + repr(str(loaded)) + ''').write_text('loaded', encoding='ascii')
def Audit(event, arguments):
    if event.startswith('socket.') or event in {
        'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'os.forkpty',
    }:
        raise AssertionError('Business inspection attempted external activity')
sys.addaudithook(Audit)
''', encoding="utf-8")
    executable = Path(sys.executable).with_name("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(executable), "business", *arguments],
        cwd=parent, env={**os.environ, "PYTHONPATH": str(guard),
                        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "ascii:strict"},
        capture_output=True, text=True, timeout=20, check=False)
    assert loaded.read_text(encoding="ascii") == "loaded", "The activity guard must actually load"
    assert result.returncode == expected and not result.stderr, (
        "Console inspection must retain its original status without an exception traceback"
    )

    return result.stdout


def test_ConsoleReopensExactOwnerDeclarationAfterRelocationWithoutWriting(tmp_path):
    """An operator reads a durable scenario and its critical Assets through the actual console."""

    root, record, model, support = Owned(tmp_path)
    moved = tmp_path / "relocated saved business workspace"
    root.rename(moved)
    before = Files(moved)
    arguments = Arguments(moved, record, model)
    raw = Console(tmp_path, [*arguments, "--json"])
    result = json.loads(raw)
    assert result["status"] == "completed" and result["core_mutation"] == "none", (
        "The installed operator path must reopen the already persisted declaration"
    )
    inspected = result["inspection"]
    assert inspected["definition_evidence_id"] == record.evidence_id, (
        "Keep the independently selected primary source identity"
    )
    assert len(inspected["critical_assets"]) == len(inspected["memberships"]) == 2, (
        "Present both actually persisted critical Assets and their descriptive membership"
    )
    assert inspected["declaration"]["attributes"]["owner_reference"] == (
        "owner:synthetic-billing"
    ), "Preserve the original owner-supplied attribution without authenticating a human"
    assert Console(tmp_path, [*arguments, "--json"]) == raw, (
        "A repeated read must retain identical facts and complete model pins"
    )
    human = Console(tmp_path, arguments)
    assert "Owner-declared unacceptable outcome" in human and "billing:0" in human, (
        "Ordinary terminal output must explain the owner scenario and its retained Assets"
    )
    assert Files(moved) == before, "Console reads must change no model, evidence or workspace bytes"


@pytest.mark.parametrize("fault", ["support", "snapshot"])
def test_ConsoleRefusesUnverifiedFactsWithoutPublishingADeclaration(tmp_path, fault):
    """A bad complete pin or corrupt original support must remain an integrity refusal."""

    root, record, model, support = Owned(tmp_path)
    arguments = Arguments(root, record, model)

    if fault == "support":
        (root / "evidence" / support.reference.locator).write_bytes(b"Owned corrupted support")

    else:
        arguments[-1] = "0" * 64

    before = Files(root)
    result = json.loads(Console(tmp_path, [*arguments, "--json"], expected=4))
    assert result["status"] == "failed" and "inspection" not in result, (
        "A failed original or model verification must emit no partial declaration or Asset list"
    )
    assert "Billing service disruption" not in json.dumps(result), (
        "Unverified source text must not escape through refusal output"
    )
    assert Files(root) == before, "Refusal must not repair or mutate saved source facts"
