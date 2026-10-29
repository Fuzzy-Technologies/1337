# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed SBOM console acquisition, preserved custody, relocation and safe refusal."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sbom_helpers import Arguments, Context, OwnedSbom, Value


def Console(arguments, parent):
    """Run the installed actual entry point with one explicit owning source selection."""

    executable = shutil.which("1337")
    assert executable is not None, "The locked installation must expose the actual product console"
    result = subprocess.run([executable, "sbom", *arguments, "--json"], cwd=parent,
                            capture_output=True, check=False, text=True, timeout=30)
    assert result.stderr == "", "The actual console must preserve safe terminal diagnostics"

    return result.returncode, json.loads(result.stdout)


@pytest.mark.parametrize("digest_kind", ["config", "manifest"])
def test_InstalledConsoleSavesOriginalOwnedGraphAndReplaysAfterRelocation(tmp_path, digest_kind):
    """Operators can import through the real console and replay their original moved custody."""

    owned = Context(tmp_path)
    original_raw = owned.source.read_bytes()
    status, outcome = Console(Arguments(owned, digest_kind=digest_kind), tmp_path)
    assert status == 0 and outcome["model_revision"] == outcome["workspace_revision"] == 1, (
        "Actual product acquisition must acknowledge one model transition and workspace CAS save"
    )
    record = LocalEvidenceStore(owned.root / "evidence").Get(outcome["evidence_id"])
    assert LocalEvidenceStore(owned.root / "evidence").Read(record.reference) == original_raw, (
        "The installed console must preserve complete original bytes and actual immutable custody"
    )
    model = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    moved = tmp_path / "moved console workspace"
    owned.root.rename(moved)
    relocated = OwnedSbom(moved, owned.source)
    status, replay = Console(Arguments(relocated, evidence_id=record.evidence_id,
                                      digest_kind=digest_kind), tmp_path)
    assert status == 0 and replay["created"] == replay["updated"] == 0 and (
        LocalModelStore(moved).Open() == model and LocalWorkspaceStore(moved).Open() == workspace
    ), "Actual installed replay must keep original context and both saved owners unchanged"


@pytest.mark.parametrize("mode,expected", [("missing-kind", 2), ("checksum", 4),
                                         ("changed-kind", 4)])
def test_InstalledConsoleRefusesImplicitOrChangedImageSemantics(tmp_path, mode, expected):
    """No console selection derives digest kind or replaces an original known image context."""

    owned = Context(tmp_path)

    if mode == "changed-kind":
        status, original = Console(Arguments(owned), tmp_path)
        assert status == 0, "Original console custody must precede changed-context replay"
        arguments = Arguments(owned, evidence_id=original["evidence_id"], digest_kind="manifest")

    else:
        arguments = Arguments(owned)

        if mode == "missing-kind":
            position = arguments.index("--image-digest-kind")
            del arguments[position:position + 2]

        else:
            arguments = Value(arguments, "--image-digest", "sha256:" + "b" * 64)

    status, outcome = Console(arguments, tmp_path)
    assert status == expected and outcome["status"] == "failed", (
        "Actual console must preserve fixed invalid/setup or source-context refusal categories"
    )
    assert outcome["model_commit"] == outcome["workspace_commit"] == "not-attempted", (
        "Refused source/image semantics cannot fabricate owning model or workspace acknowledgement"
    )
