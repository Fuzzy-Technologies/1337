# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked original Save return/lost-ACK/cancellation observations without real stores or jobs."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from fuzzy1337 import model, owned_response_workflow, workspace
from tests.contract import owned_content_response_sdk_consumer as consumer


@pytest.fixture(scope="module")
def observer_runner():
    """Initialize loop resources before the unchanged unit network guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.mark.parametrize("failure", [None, "model", "workspace", "cancelled"])
def test_SaveObserversReturnOriginalObjectsRetainFailuresAndRestoreOwners(
    failure, monkeypatch, tmp_path, observer_runner,
):
    """Only explicit store doubles execute; acknowledged and uncertain returns remain distinct."""

    model_proposal = SimpleNamespace(ToDict=lambda: {"revision": 5})
    model_return = SimpleNamespace(ToDict=lambda: {"revision": 5})
    workspace_proposal = SimpleNamespace(revision=8, ToDict=lambda: {"revision": 8})
    workspace_return = SimpleNamespace(ToDict=lambda: {"revision": 9})

    def ModelSave(store, proposal, *, expected_revision):
        """Observe the exact original model inputs and return a distinct original object."""

        assert proposal is model_proposal and expected_revision == 4, (
            "Observed model Save must receive the original model proposal and selected CAS basis."
        )

        if failure == "model":
            raise OSError("synthetic lost model acknowledgement")

        return model_return

    def WorkspaceSave(store, proposal):
        """Keep actual proposal/returned revisions distinct without performing storage work."""

        assert proposal is workspace_proposal and proposal.revision == 8, (
            "Observed workspace Save must receive its original proposal and revision."
        )

        if failure == "workspace":
            raise OSError("synthetic lost workspace acknowledgement")

        return workspace_return

    async def Capture(*args, **kwargs):
        """Exercise only the installed-boundary doubles; no SDK, executor or policy is invoked."""

        assert model.LocalModelStore.Save(None, model_proposal, expected_revision=4) is (
            model_return), (
            "The model observer must return the original model acknowledgement object unchanged."
        )
        assert workspace.LocalWorkspaceStore.Save(None, workspace_proposal) is workspace_return, (
            "The workspace observer must return the original workspace acknowledgement object "
            "unchanged."
        )

        if failure == "cancelled":
            raise asyncio.CancelledError

        return SimpleNamespace(ToDict=lambda: {"state": "mock-only"})

    monkeypatch.setattr(model.LocalModelStore, "Save", ModelSave)
    monkeypatch.setattr(workspace.LocalWorkspaceStore, "Save", WorkspaceSave)
    monkeypatch.setattr(owned_response_workflow, "RunOwnedContentResponseCapture", Capture)
    config = {"workspace": str(tmp_path / "workspace"), "scope_id": "scope:unit",
        "url": "http://127.0.0.1:32123/research/content", "owner_reference": "actor:unit",
        "policy": str(tmp_path / "policy.json"), "approve_safe_content_response_capture": True,
        "retain_response": True}
    operation = consumer.Capture(config, tmp_path / "observations", enabled=True)

    if failure:
        with pytest.raises(asyncio.CancelledError if failure == "cancelled" else OSError):
            observer_runner.run(operation)

    else:
        assert observer_runner.run(operation) == {"state": "mock-only"}, (
            "The observed operation must return its actual controlled result without replacement."
        )

    assert model.LocalModelStore.Save is ModelSave and workspace.LocalWorkspaceStore.Save is (
        WorkspaceSave), "Original owners must be restored before observations are serialized"
    document = json.loads((tmp_path / "observations/capture.json").read_bytes())
    saves = document["store_saves"]
    assert len(saves) == (1 if failure == "model" else 2), (
        "A failed model Save must stop before workspace Save while other cases retain both "
        "attempts."
    )
    assert saves[0]["expected_revision"] == 4 and saves[0]["proposal"] == {"revision": 5}, (
        "The model Save trace must preserve its exact original CAS basis and proposal."
    )
    assert saves[0]["returned"] == (None if failure == "model" else {"revision": 5}), (
        "The model Save trace must distinguish a lost ACK from the original returned revision."
    )
    assert saves[0]["exception_type"] == ("OSError" if failure == "model" else None), (
        "The model Save trace must retain the injected failure type only when the model Save "
        "fails."
    )

    if len(saves) == 2:
        assert saves[1]["expected_revision"] == 8 and saves[1]["proposal"] == {"revision": 8}, (
            "The workspace Save trace must preserve its exact original CAS basis and proposal."
        )
        assert saves[1]["returned"] == (None if failure == "workspace" else {"revision": 9}), (
            "The workspace Save trace must distinguish a lost ACK from the original returned "
            "revision."
        )
        assert saves[1]["exception_type"] == ("OSError" if failure == "workspace" else None), (
            "The workspace Save trace must retain the injected failure type only when workspace "
            "Save fails."
        )
