# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real portable workspace/model/evidence consumed by read-only shell and SDK lenses."""

import json
from io import StringIO
from pathlib import Path

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.lenses import LENS_CATALOG
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def Workspace(tmp_path: Path):
    """Store attributable synthetic host and build facts alongside actual local evidence bytes."""

    root = tmp_path / "workspace with spaces"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Local lens integration"), "synthetic")
    evidence = LocalEvidenceStore(root / "evidence").Put(
        b"synthetic observation", "stdout", "text/plain",
        EvidenceProvenance(
            "synthetic", "scope:local", "synthetic-adapter", "1", "fixture-1",
            "2026-10-11T10:00:00Z", "2026-10-11T10:00:01Z",
        ),
    )
    provenance = ModelProvenance(
        "native", "run:local", "2026-10-11T10:00:01Z", "scope:local", "target:" + "a" * 64,
        evidence_references=(evidence.reference,),
    )
    host = SecurityObject(ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
                          {"state": "reported"}, (provenance,))
    asset = SecurityObject(ObjectIdentity("synthetic", ObjectKind.ASSET, "build:synthetic"),
                           {"version": "1"}, (provenance,))
    store = LocalModelStore(root)
    initial = store.Create()
    state, delta = initial.Apply(objects=(host, asset))
    store.Save(state, expected_revision=delta.previous_revision)

    return root, state


def Files(root: Path) -> dict[str, bytes]:
    """Capture only files created within this isolated test workspace."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_AllLensShellViewsUsePersistedCanonicalObjectsWithoutWritingAnything(tmp_path):
    """Actual shell reads preserve workspace, evidence, provenance, object IDs, and revisions."""

    root, state = Workspace(tmp_path)
    original = Files(root)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd(f"model {root}")
    assert output.getvalue().strip() == f"Loaded model: synthetic at revision {state.revision}", (
        'Lens views changed persisted canonical state.'
    )

    for lens in LENS_CATALOG:
        shell.onecmd(f"lens {lens.identifier} --json")
        shell.onecmd("view model --json")
        actual = json.loads(output.getvalue().splitlines()[-1])
        assert actual == lens.Project(state), (
            'Lens views changed persisted canonical state.'
        )
        assert set(actual["object_references"]) <= {item.Reference() for item in state.objects}, (
            'Lens views changed persisted canonical state.'
        )

    assert Files(root) == original, (
        'Lens views changed persisted canonical state.'
    )
    reopened = LocalModelStore(root).Open()
    assert CanonicalModelJson(reopened.ToDict()) == CanonicalModelJson(state.ToDict()), (
        'Lens views changed persisted canonical state.'
    )


def test_TerminalLensSwitchesRenderDifferentActualSlicesAndKeepSelectedObject(tmp_path):
    """Human views show observed surface versus build inventory from the same loaded revision."""

    root, state = Workspace(tmp_path)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd(f"model {root}")
    selected = state.objects[0].Reference()
    shell.onecmd(f"select {selected}")
    shell.onecmd("view model")
    first = output.getvalue()
    assert "host: 127.0.0.1" in first, (
        'Lens switch changed the expected slice or selected object.'
    )
    assert "asset: build:synthetic" not in first, (
        'Lens switch changed the expected slice or selected object.'
    )
    output.seek(0)
    output.truncate()
    shell.onecmd("lens devsecops")
    second = output.getvalue()

    assert "DevSecOps: synthetic at revision 1" in second, (
        'Lens switch changed the expected slice or selected object.'
    )
    assert "asset: build:synthetic" in second, (
        'Lens switch changed the expected slice or selected object.'
    )
    assert "host: 127.0.0.1" not in second, (
        'Lens switch changed the expected slice or selected object.'
    )
    assert shell.State.selected_object == selected, (
        'Lens switch changed the expected slice or selected object.'
    )
    assert LocalModelStore(root).Open() == state, (
        'Lens switch changed the expected slice or selected object.'
    )


def test_CorruptPersistedModelCannotReplaceThePreviousView(tmp_path):
    """Unsafe/corrupt state is diagnosed without displaying guessed security objects."""

    root, state = Workspace(tmp_path)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.BindModel(state)
    (root / "state/model/model.json").write_text('{"schema_version": 999}', encoding="utf-8")
    shell.onecmd(f"model {root}")
    assert output.getvalue().startswith("Could not open model:"), (
        'Lens contract failed: corrupt persisted model cannot replace the previous view.'
    )
    shell.onecmd("view model --json")

    assert json.loads(output.getvalue().splitlines()[-1])["revision"] == state.revision, (
        'Lens contract failed: corrupt persisted model cannot replace the previous view.'
    )
