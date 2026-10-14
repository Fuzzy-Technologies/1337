# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual portable original GraphQL custody replay and honest independent storage outcomes."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from fuzzy1337 import api_commands as commands
from fuzzy1337.evidence import EvidenceProvenance
from fuzzy1337.model import LocalModelStore
from fuzzy1337.report_commands import OpenReportInput
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError
from tests.api_import_helpers import TIME, Arguments, Files, Imported, Run, Value


def test_RelocationRetainedReplayAndExactNoopPreserveEveryOwnerByte(tmp_path):
    """Known original custody survives movement and does not depend on the removed external file."""

    context, first = Imported(tmp_path)
    root, basis, scope, evidence, source = context
    before = Files(root)
    source.unlink()
    moved = tmp_path / "moved"
    root.rename(moved)
    relocated = moved, basis, scope, evidence, source
    status, replay = Run(Arguments(relocated, evidence_id=first["evidence_id"]))
    assert status == 0 and replay["created"] == replay["updated"] == 0, (
        "Retained replay changed graph"
    )
    assert Files(moved) == before, "Exact original replay rewrote portable owner bytes"
    assert OpenReportInput(moved).report.state == LocalModelStore(moved).Open(), (
        "Actual relocated report owner failed source evidence verification"
    )


def test_SameOriginalBytesDifferentAcquisitionsKeepDistinctManifestCustody(tmp_path):
    """Raw deduplication never collapses independent acquisition identity or read context."""

    context, first = Imported(tmp_path)
    status, second = Run(Arguments(context), clock=lambda: TIME + timedelta(seconds=2))
    assert (
        status == 0
        and first["source_sha256"] == second["source_sha256"]
        and (first["evidence_id"] != second["evidence_id"])
    ), "Independent original acquisitions were collapsed to the source digest"
    model = LocalModelStore(context[0]).Open()
    facts = [item for item in model.observations if item.kind == "api-import-source"]
    assert {item.attributes["evidence_id"] for item in facts} == {
        first["evidence_id"],
        second["evidence_id"],
    }, "Canonical model lost one acquisition's original custody"
    assert len(model.objects) == 1, "Equivalent source acquisitions duplicated Endpoint identities"
    before = Files(context[0])

    for selected in (first, second):
        status, replay = Run(Arguments(context, evidence_id=selected["evidence_id"]))
        assert status == 0 and replay["created"] == replay["updated"] == 0, (
            "Original replay changed facts"
        )
        assert Files(context[0]) == before, "Original independent replay rewrote stored bytes"


@pytest.mark.parametrize("owner", ["acquisition", "model", "workspace"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("interrupt", [False, True])
def test_LostAcknowledgementBeforeOrAfterRealOwnerCommitRemainsUnknown(
    tmp_path,
    monkeypatch,
    owner,
    after,
    interrupt,
):
    """An owner can commit and then lose acknowledgement without rollback or guessed success."""

    from tests.api_import_helpers import Context

    context = Context(tmp_path)
    storage = {
        "acquisition": commands.ApiEvidenceStore,
        "model": LocalModelStore,
        "workspace": LocalWorkspaceStore,
    }[owner]
    name = "Put" if owner == "acquisition" else "Save"
    original = getattr(storage, name)

    def Save(self, *args, **kwargs):
        """Optionally call the actual storage owner before simulating acknowledgement loss."""

        if after:
            original(self, *args, **kwargs)

        if interrupt:
            raise KeyboardInterrupt

        raise OSError("PRIVATE_STORAGE_MARKER")

    monkeypatch.setattr(storage, name, Save)
    status, outcome = Run(Arguments(context))
    assert status == (130 if interrupt else 4) and outcome[owner + "_commit"] == "unknown", (
        "Lost acknowledgement became guessed committed/not-committed state"
    )
    assert "PRIVATE_STORAGE_MARKER" not in str(outcome), "Storage diagnostic escaped summary"
    model, workspace = LocalModelStore(context[0]).Open(), LocalWorkspaceStore(context[0]).Open()
    assert model.revision == (1 if owner == "workspace" or owner == "model" and after else 0), (
        "Observed actual model commit truth differed from the owner boundary"
    )
    assert workspace.revision == (1 if owner == "workspace" and after else 0), (
        "Observed actual workspace commit truth differed from the owner boundary"
    )
    if owner != "acquisition":
        assert outcome["acquisition_commit"] == "confirmed", (
            "Earlier confirmed acquisition was lost"
        )

    if owner == "workspace":
        assert outcome["model_commit"] == "confirmed", "Earlier confirmed model was lost"


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("error", [WorkspaceBusyError, WorkspaceConflictError])
def test_KnownStorageBusyAndConflictRemainDistinctFromUnknownCommit(
    tmp_path,
    monkeypatch,
    owner,
    error,
):
    """A cooperating-writer rejection carries the existing owner's known not-committed outcome."""

    from tests.api_import_helpers import Context

    context = Context(tmp_path)

    def Save(*args, **kwargs):
        """Report the existing storage owner's explicit lock/revision refusal."""

        raise error("PRIVATE_STORAGE_MARKER")

    monkeypatch.setattr(LocalModelStore if owner == "model" else LocalWorkspaceStore, "Save", Save)
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome[owner + "_commit"] == "not-committed", (
        "Known refusal became unknown"
    )
    assert outcome["failure"] == owner + (
        "-busy" if error is WorkspaceBusyError else "-conflict"
    ), "Known independent storage refusal lost its owner/category"


def test_ModelCommittedWorkspaceLostAckCanRepairOnlyKnownOriginalCustody(tmp_path, monkeypatch):
    """Retained replay can finish references after an actual model commit without re-reading a
    file.
    """

    from tests.api_import_helpers import Context

    context = Context(tmp_path)
    original = LocalWorkspaceStore.Save

    def Fail(*args, **kwargs):
        """Lose the workspace acknowledgement before its real CAS publication."""

        raise OSError("owned simulated failure")

    monkeypatch.setattr(LocalWorkspaceStore, "Save", Fail)
    status, first = Run(Arguments(context))
    assert status == 4 and first["model_commit"] == "confirmed", (
        "Required prior model commit missing"
    )
    monkeypatch.setattr(LocalWorkspaceStore, "Save", original)
    context[4].unlink()
    status, replay = Run(Arguments(context, evidence_id=first["evidence_id"]))
    assert status == 0 and replay["model_revision"] == 1 and replay["workspace_revision"] == 1, (
        "Known original custody did not repair independently missing workspace references"
    )


@pytest.mark.parametrize("same_source", [False, True])
def test_SelectedGraphQlPreflightPreservesUnrelatedLargerEvidenceAndExactReplay(
    tmp_path, same_source,
):
    """Selected source bounds do not cap unrelated retained evidence under its existing owner."""

    context, first = Imported(tmp_path)
    root, _, scope, evidence, _ = context

    if same_source:
        provenance = evidence.Get(first["evidence_id"]).provenance

    else:
        provenance = EvidenceProvenance("api-owned", scope.Reference(), "owned.unrelated", "1",
            None, TIME.isoformat(), TIME.isoformat())

    unrelated = evidence.Put(b"owned unrelated evidence\n" * 25000, "stdout", "text/plain",
                             provenance)
    assert unrelated.reference.size_bytes > 512 * 1024, "Unrelated fixture was too small"
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace,
        evidence_references=tuple(sorted((*workspace.evidence_references, unrelated.reference),
                                        key=lambda item: (item.locator, item.role))),
        evidence_record_references=tuple(sorted((*workspace.evidence_record_references,
                                                unrelated.evidence_id)))))
    before = Files(root)

    for identity in (None, first["evidence_id"]):
        status, outcome = Run(Arguments(context, evidence_id=identity))
        assert status == 0 and outcome["created"] == outcome["updated"] == 0, "Replay was blocked"
        assert Files(root) == before, "Preflight rewrote unrelated evidence or no-op owner bytes"


def test_FileModeKnownOriginalPreflightPreservesEachAcquisitionScope(tmp_path):
    """A valid older GraphQL original retains its own scope when the new import selects another."""

    context, first = Imported(tmp_path)
    root, basis, scope, evidence, source = context
    another_scope = replace(scope, scope_id="another")
    LocalScopeStore(root).Create(another_scope)
    status, second = Run(Value(Arguments(context), "--scope", "another"),
                         clock=lambda: TIME + timedelta(seconds=2))
    assert status == 0 and second["evidence_id"] != first["evidence_id"], (
        "Known original inherited the new selection's different scope"
    )
    other = root, basis, another_scope, evidence, source
    before = Files(root)

    for selected, selected_scope in ((first, "owned"), (second, "another")):
        status, outcome = Run(Value(Arguments(other, evidence_id=selected["evidence_id"]),
                                    "--scope", selected_scope))
        assert status == 0 and outcome["created"] == outcome["updated"] == 0, (
            "Known originals under different scopes did not replay independently"
        )
        assert Files(root) == before, "Different-scope preflight rewrote owner bytes"
