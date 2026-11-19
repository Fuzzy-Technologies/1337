# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check offline persistence of a declared attack-path scenario asset."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzy1337.model import (
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

SCENARIO_PATH = (
    Path(__file__).resolve().parents[2] / "labs/targets/attack-path-mini/scenario.v1.json"
)


def test_ReopeningAndReapplyingSeedPreservesSingleAsset(tmp_path: Path) -> None:
    """Repeat one static declaration through the real store and preserve its attribution."""

    scenario = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    declaration = next(
        asset for asset in scenario["assets"] if asset["id"] == "asset.business-event"
    )
    scenarioId = scenario["scenario"]["id"]
    scenarioVersion = scenario["scenario"]["version"]
    root = tmp_path / "workspace"
    workspaceStore = LocalWorkspaceStore(root)
    workspace = workspaceStore.Create(WorkspaceConfiguration("Offline seed replay"), scenarioId)
    modelStore = LocalModelStore(root)
    empty = modelStore.Create()
    identity = ObjectIdentity(workspace.workspace_id, ObjectKind.ASSET, declaration["id"])
    reference = identity.Reference()
    provenance = ModelProvenance(
        scenarioId, f"seed:{scenarioId}:v{scenarioVersion}", "2026-01-01T00:00:00Z",
        "scope:scenario-seed", reference,
    )
    seed = SecurityObject(identity, {
        "name": declaration["name"], "provenance": declaration["provenance"],
    }, (provenance,))
    applied, _ = empty.Apply(objects=(seed,))
    first = modelStore.Save(applied, expected_revision=empty.revision)

    replayStore = LocalModelStore(root)
    persisted = replayStore.Open()
    replayed, delta = persisted.Apply(objects=(seed,))
    saved = replayStore.Save(replayed, expected_revision=persisted.revision)
    reopened = LocalModelStore(root).Open()

    assert first.revision == empty.revision + 1, "Initial seed must create one revision"
    assert delta == ModelDelta(first.revision, first.revision), "Seed replay changed the model"
    assert first == persisted == replayed == saved == reopened, "Persisted state changed on replay"
    assert reopened.Objects() == (seed,), "Seed replay must leave one Asset and no Finding"
    storedAsset = reopened.Objects(ObjectKind.ASSET)[0]
    assert storedAsset.Reference() == reference and storedAsset.attributes["provenance"] == "seeded"
    assert reopened.observations == (
        Observation("object-update", reference, seed.attributes, provenance),
    ), "Seed replay duplicated attribution"
    assert reopened.relations == ()
    assert storedAsset.provenance[0].evidence_references == ()
    assert storedAsset.provenance[0].execution is None
    assert workspaceStore.Open() == workspace, "Seed replay changed workspace attribution"
    assert tuple((root / "evidence").iterdir()) == (), "Seed replay acquired evidence"
