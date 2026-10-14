# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned original-input and actual-store setup for the offline runtime product handler."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.docker_helpers import FIXTURES, OwnedContext


def Context(parent: Path):
    """Create actual workspace/model/HOST/scope owners and one independently authored input file."""

    root, state, host, evidence = OwnedContext(parent / "ws", "runtime-test")
    LocalScopeStore(root).Create(ScopeSnapshot("owned", state.workspace_id))
    source = parent / "inspect.json"
    source.write_bytes((FIXTURES / "docker-inspect.owned.v1.json").read_bytes())

    return root, state, host, evidence, source


def Arguments(context, *, evidence_id: str | None = None):
    """Declare current exact owner bases and explicit consent or original retained selection."""

    root, _, host, _, source = context
    arguments = ["import", "docker-inspect", str(root), "--host", host.Reference(),
        "--scope", "owned", "--run", "run:owned-inspect", "--expected-revision",
        str(LocalModelStore(root).Open().revision), "--expected-workspace-revision",
        str(LocalWorkspaceStore(root).Open().revision)]

    if evidence_id is None:
        arguments.extend(["--file", str(source), "--owner", "owner:owned",
                          "--read-consent-reference", "consent:owned-input"])

    else:
        arguments.extend(["--evidence", evidence_id])

    return arguments


def Run(arguments, *, json_output: bool = True, clock=None):
    """Exercise the real command handler and decode its single original terminal summary."""

    from fuzzy1337.runtime_commands import RunRuntimeCommands

    output = StringIO()
    options = {"json_output": json_output}

    if clock is not None:
        options["clock"] = clock

    status = RunRuntimeCommands(arguments, output, **options)

    return status, json.loads(output.getvalue()) if json_output else output.getvalue()
