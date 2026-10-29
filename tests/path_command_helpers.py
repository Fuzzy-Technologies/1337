# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent owned graph producers and explicit path-command invocation helpers."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path

from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.path_commands import RunPathCommands
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def SmallGraph(parent: Path):
    """Produce two literal paths sharing only a pivot and source/pivot edge through real owners."""

    root = parent / "Owned Path Workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned selected graph"), "paths-owned")
    store = LocalModelStore(root)
    initial = store.Create()
    provenance = ModelProvenance("owned.graph", "run:owned", "2026-10-14T00:00:00Z",
                                "scope:owned", "target:owned")
    objects = {name: SecurityObject(ObjectIdentity(initial.workspace_id, ObjectKind.ASSET,
        "owned-path:" + name), provenance=(provenance,))
        for name in ("source", "pivot", "left", "right", "target", "isolated")}
    coordinates = (("source", "pivot"), ("pivot", "left"), ("pivot", "right"),
                   ("left", "target"), ("right", "target"))
    relations = {source + "-" + target: Relation(RelationKind.RELATED_TO,
        objects[source].Reference(), objects[target].Reference(), provenance=(provenance,))
        for source, target in coordinates}
    changed, _ = initial.Apply(objects=tuple(objects.values()), relations=tuple(relations.values()))
    model = store.Save(changed, expected_revision=initial.revision)

    return root, model, objects, relations


def Arguments(root, model, source, target, relations, *, assessments=(), context="owned:paths",
              scope="scope:owned", at="2026-10-14T01:00:00Z"):
    """Select every input and resource bound without deriving an execution or confidence default."""

    arguments = ["analyze", str(root), "--expected-revision", str(model.revision),
        "--expected-snapshot-sha256",
        hashlib.sha256(CanonicalModelJson(model.ToDict())).hexdigest(),
        "--source", source, "--target", target, "--context", context, "--scope-reference", scope,
        "--as-of", at, "--max-age-seconds", "3600", "--max-depth", "16",
        "--max-paths", "64", "--max-work", "4096", "--max-frontier", "1024",
        "--max-cut-work", "100000"]

    for reference in relations:
        arguments.extend(("--transition", reference))

    if assessments:
        for identity in assessments:
            arguments.extend(("--assessment", identity))

    else:
        arguments.append("--no-assessments")

    return arguments


def SmallArguments(context):
    """Select the independent small graph's two complete source-to-target candidates."""

    root, model, objects, relations = context

    return Arguments(root, model, objects["source"].Reference(), objects["target"].Reference(),
                     (item.Reference() for item in relations.values()))


def Run(arguments):
    """Run the real handler and require one terminal outcome with matching process status."""

    output = StringIO()
    status = RunPathCommands(arguments, output, json_output=True)
    document = json.loads(output.getvalue())
    assert document["exit_code"] == status, "Path command status and terminal DTO disagree"

    return status, document


def Value(arguments, name, value):
    """Replace one explicit selected field while keeping the independent producer fixed."""

    selected = list(arguments)
    selected[selected.index(name) + 1] = value

    return selected


def Files(root):
    """Snapshot only the owned workspace bytes for exact no-write assertions."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}
