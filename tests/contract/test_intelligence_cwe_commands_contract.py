# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Local CWE terminal profile, strict forwarded grammar and immutable-root preflight."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from fuzzy1337 import intelligence_cwe_commands as commands
from fuzzy1337.intelligence_commands import RunIntelCommands
from fuzzy1337.workspace import LocalWorkspaceStore


def Run(arguments, *, human=False):
    """Exercise actual namespace enrollment and capture one terminal response."""

    output = StringIO()
    status = RunIntelCommands(["cwe", *arguments], output, json_output=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())


@pytest.mark.parametrize("arguments", [
    [], ["bogus", "--help"], ["import", "extra", "--help"], ["--help", "import"],
    ["import", "--help", "--help"], ["https", "fetch"], ["apply"],
])
def test_ForwardedGrammarRejectsNonexactHelpAndUnsupportedActions(arguments):
    """The adapter rejects only grammar still observable after global normalization."""

    status, result = Run(arguments)
    assert status == 2 and result["failure"] == "configuration", "Invalid forwarded grammar passed"
    assert result["profile"] == "cwe-local-selected-cli", "Legacy terminal profile was reused"


@pytest.mark.parametrize("arguments", [["--help"], ["-h"], ["import", "--help"],
    ["import", "-h"], ["inspect", "--help"], ["inspect", "-h"]])
def test_ExactForwardedHelpNeedsNoWorkspace(arguments, monkeypatch):
    """Every documented adapter help form is storage-independent."""

    def Refuse(*args, **kwargs):
        """Trip if help enters an owning workspace."""

        raise AssertionError("Help opened storage")

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Refuse)
    status, result = Run(arguments, human=True)
    assert status == 0 and "usage:" in result, "Exact adapter help failed"


@pytest.mark.parametrize("field,value", [("selection", "sha256:" + "A" * 64),
    ("selection", "sha256:" + "a" * 63), ("selection", "a" * 64),
    ("receipt", "sha256:" + "a" * 64 + "\n"), ("receipt", "unknown")])
def test_RootSyntaxFailsBeforeAnyOwningRead(field, value, monkeypatch):
    """Both manifest roots are configuration inputs before the frozen SDK opens storage."""

    def Refuse(*args, **kwargs):
        """Trip if malformed root syntax crosses preflight."""

        raise AssertionError("Malformed root reached storage")

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Refuse)
    monkeypatch.setattr(commands, "LoadAcquiredCweSelection", Refuse)
    roots = {"selection": "sha256:" + "a" * 64, "receipt": "sha256:" + "b" * 64}
    roots[field] = value
    status, result = Run(["inspect", "untrusted", "--selection", roots["selection"],
                          "--receipt", roots["receipt"]])
    assert status == 2 and result["failure"] == "configuration", "Malformed root was integrity"
    assert result["raw_ack"] == "not-attempted", "Invalid root invented acknowledgement"
