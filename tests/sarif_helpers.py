# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned local saved-SARIF fixtures and real storage, without executing a producer."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path

from fuzzy1337.bridge_commands import RunBridgeCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURES = Path(__file__).parent / "contract/fixtures/sarif"
SHA256 = "d50cd7b2dc4ef6890c4ee5c905a2591fde69e8f5fee0e4c99dfceab0d947294d"


def Raw():
    """Return exact original external sample bytes without running the named analyzer."""

    return (FIXTURES / "external-eslint.sarif").read_bytes()


def Golden():
    """Read the independent handwritten source-fact oracle."""

    return json.loads((FIXTURES / "external-eslint.golden.json").read_bytes())


def Document():
    """Return a detached copy of the official sample for one explicit source mutation."""

    return json.loads(Raw())


def Owned(parent):
    """Create real existing workspace/scope/model owners and one caller-owned report."""

    root = parent / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned saved SARIF"), "sarif-owned")
    LocalScopeStore(root).Create(ScopeSnapshot("owned", "sarif-owned"))
    LocalModelStore(root).Create()
    source = parent / "external.sarif"
    source.write_bytes(Raw())

    return root, source


def ImportArguments(root, source, pin=SHA256):
    """Declare every required local selection without deriving authority from SARIF content."""

    return ["sarif", "import", str(root), str(source), "--scope", "owned",
            "--owner", "operator:owned", "--read-consent-reference", "consent:owned",
            "--expected-sha256", pin]


def InspectArguments(root, imported, pin=SHA256):
    """Select the original/receipt pair and independent original-byte pin."""

    return ["sarif", "inspect", str(root), "--original", imported["original_id"],
            "--receipt", imported["receipt_id"], "--expected-sha256", pin]


def Run(arguments, *, human=False, clock=None):
    """Call the owning command and capture its one complete terminal response."""

    output = StringIO()
    options = {} if clock is None else {"clock": clock}
    status = RunBridgeCommands(arguments, output, jsonOutput=not human, **options)

    return status, output.getvalue() if human else json.loads(output.getvalue())


def Files(root):
    """Compare actual saved owner bytes independently from deserialized objects."""

    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}
