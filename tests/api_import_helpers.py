# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual owned workspace/source/scope setup for the original GraphQL product handler."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from fuzzy1337.api_commands import RunApiCommands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURE = Path(__file__).parent / "contract/fixtures/graphql_introspection.owned.json"
ENDPOINT = "http://127.0.0.1:8080/graphql"
TIME = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)


def Context(parent: Path):
    """Create real portable owners, exact pre-existing scope and one original synthetic file."""

    root = parent / "ws"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned GraphQL"), "api-owned")
    basis = LocalModelStore(root).Create()
    target = Target(TargetKind.URL, ENDPOINT)
    scope = ScopeSnapshot(
        "owned",
        basis.workspace_id,
        ScopeAuthorization(AuthorizationState.GRANTED, "actor:owned", "consent:endpoint"),
        targets=(target,),
        allow=(target,),
    )
    LocalScopeStore(root).Create(scope)
    source = parent / "introspection.json"
    source.write_bytes(FIXTURE.read_bytes())

    return root, basis, scope, LocalEvidenceStore(root / "evidence"), source


def Arguments(context, *, evidence_id: str | None = None):
    """Select the actual current independent revisions and explicit original source context."""

    root, _, _, _, source = context
    arguments = [
        "import",
        "graphql-introspection",
        str(root),
        "--endpoint",
        ENDPOINT,
        "--scope",
        "owned",
        "--run",
        "run:owned-graphql",
        "--expected-revision",
        str(LocalModelStore(root).Open().revision),
        "--expected-workspace-revision",
        str(LocalWorkspaceStore(root).Open().revision),
    ]

    if evidence_id is None:
        arguments.extend(
            [
                "--file",
                str(source),
                "--owner",
                "actor:owned",
                "--read-consent-reference",
                "consent:original",
            ]
        )

    else:
        arguments.extend(["--evidence", evidence_id])

    return arguments


def Run(arguments, *, clock=lambda: TIME, json_output: bool = True):
    """Exercise the actual handler, retaining only its terminal original-source acknowledgement."""

    output = StringIO()
    status = RunApiCommands(arguments, output, json_output=json_output, clock=clock)

    return status, json.loads(output.getvalue()) if json_output else output.getvalue()


def Value(arguments, name, value):
    """Replace one explicit caller selection without altering other independent context."""

    modified = list(arguments)
    modified[modified.index(name) + 1] = str(value)

    return modified


def Imported(parent: Path):
    """Acquire and commit through the real handler and actual store owners."""

    context = Context(parent)
    status, outcome = Run(Arguments(context))
    assert status == 0, f"Original GraphQL product setup failed: {outcome['failure']}"

    return context, outcome


def Files(root: Path):
    """Capture actual portable owner bytes for exact no-op and refusal comparisons."""

    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
