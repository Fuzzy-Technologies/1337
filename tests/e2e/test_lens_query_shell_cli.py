# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed shell replays explicit saved LensQuery files without changing retained inputs."""

import json
import shlex
import shutil
import subprocess

import pytest

from fuzzy1337.lenses import LensQuery, ResolveLens
from fuzzy1337.model import CanonicalModelJson, ObjectKind
from tests.integration.test_lenses_integration import Files, Workspace


def Console(parent, commands):
    """Drive saved-model viewing through the installed shell outside the checkout."""

    executable = shutil.which("1337")
    assert executable is not None, "Saved lens acceptance requires the installed product console"
    result = subprocess.run([executable, "shell"], input="\n".join([*commands, "quit", ""]),
                            cwd=parent, capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 0 and not result.stderr, (
        "The shell transport must exit normally after reporting any per-command refusal"
    )
    documents = []

    for line in result.stdout.splitlines():
        content = line.removeprefix("1337> ").strip()

        if content.startswith("{"):
            documents.append(json.loads(content))

    return result.stdout, documents


def test_InstalledShellReplaysLiteralQueryAndRestoresDefaultWithoutWriting(tmp_path):
    """Operators can select a saved filter with spaces and uppercase paths on an existing model."""

    root, state = Workspace(tmp_path)
    query = LensQuery(object_kinds=(ObjectKind.ASSET,), key_contains="BUILD",
                      attributes_match={"version": "1"}, include_observations=False)
    path = tmp_path / "Saved Inventory Query.JSON"
    path.write_bytes(CanonicalModelJson(query.ToDict()))
    before = Files(tmp_path)
    output, documents = Console(tmp_path, [f"model {root}",
        f"view model --query {shlex.quote(str(path))} --json", "view model --json",
        f"view model --query {shlex.quote(str(path))}"])
    lens = ResolveLens("pentest")
    assert documents == [lens.Project(state, query), lens.Project(state)], (
        "Installed replay and unfiltered output must exactly match the existing SDK contract"
    )
    assert "asset: build:synthetic" in output, "Installed terminal rows must honor the same query"
    assert Files(tmp_path) == before, "Installed replay must preserve all saved and query bytes"


@pytest.mark.parametrize("contents", [None, b"{", b'{"handler":"inert"}'])
def test_InstalledShellRefusesSelectedQueryWithoutFallbackOrWrites(tmp_path, contents):
    """Invalid query files fail one command without guessing or losing the bound snapshot."""

    root, state = Workspace(tmp_path)
    path = tmp_path / "Saved Query.JSON"

    if contents is not None:
        path.write_bytes(contents)

    before = Files(tmp_path)
    output, documents = Console(tmp_path, [f"model {root}",
        f"view model --query {shlex.quote(str(path))} --json", "view model --json"])
    assert "Could not open lens query:" in output, "Selected query failures must be visible"
    assert documents == [ResolveLens("pentest").Project(state)], (
        "Refusal must emit no projection and the next default view must retain the bound model"
    )
    assert Files(tmp_path) == before, "Refusals must preserve all saved bytes and create no file"
