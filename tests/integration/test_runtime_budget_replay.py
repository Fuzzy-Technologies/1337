# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Runtime original budget preflight preserves larger unrelated evidence and lost-ACK repair."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337 import runtime_commands as commands
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.runtime_helpers import Arguments, Context, KubernetesContext, Run
from tests.unit.test_runtime_input_budget import TIME, Imported, RefuseRead


def Files(root):
    """Capture actual portable owner bytes without depending on their previous physical path."""

    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
@pytest.mark.parametrize("original_metadata", [False, True])
def test_UnrelatedLargerEvidenceKeepsGenericBoundsAndBytewiseRuntimeReplay(
    tmp_path, profile, original_metadata,
):
    """The fixed one-MiB runtime ceiling applies to known runtime originals, not other evidence."""

    context, first = Imported(tmp_path, profile)
    root, state, _, evidence, _ = context
    unrelated = evidence.Put(
        b"owned unrelated larger evidence\n" * 40000,
        "stdout",
        "text/plain",
        evidence.Get(first["evidence_id"]).provenance if original_metadata else EvidenceProvenance(
            state.workspace_id,
            "scope:owned",
            "owned.unrelated",
            "1",
            None,
            TIME.isoformat(),
            TIME.isoformat(),
        ),
    )
    assert unrelated.reference.size_bytes > 1024 * 1024, "Unrelated fixture was too small"
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(
        replace(
            workspace,
            evidence_references=tuple(
                sorted(
                    (*workspace.evidence_references, unrelated.reference),
                    key=lambda item: (item.locator, item.role),
                )
            ),
            evidence_record_references=tuple(
                sorted((*workspace.evidence_record_references, unrelated.evidence_id))
            ),
        )
    )
    before = Files(root)
    status, outcome = Run(Arguments(context, profile=profile, evidence_id=first["evidence_id"]))
    assert status == 0 and outcome["created"] == outcome["updated"] == 0, (
        "Unrelated evidence blocked replay"
    )
    assert Files(root) == before, "Runtime preflight rewrote unrelated evidence or no-op bytes"


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
def test_LegacyNullReadCustodyRemainsExactBytewiseReplay(tmp_path, profile):
    """Unchanged six-field validation retains legacy SDK custody with both read references null."""

    context, first = Imported(tmp_path, profile)
    root = context[0]
    model = LocalModelStore(root).Open()
    observations = tuple(replace(item, attributes={**item.attributes,
        "read_actor_reference": None, "read_consent_reference": None})
        if item.kind == "runtime-import-source" else item for item in model.observations)
    legacy = replace(model, revision=model.revision + 1, observations=observations)
    LocalModelStore(root).Save(legacy, expected_revision=model.revision)
    before = Files(root)
    status, outcome = Run(Arguments(context, profile=profile, evidence_id=first["evidence_id"]))
    assert status == 0 and outcome["created"] == outcome["updated"] == 0, "Null-read replay changed"
    assert Files(root) == before, "Legacy null-read custody required migration or owner rewrite"


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
@pytest.mark.parametrize("grown", [False, True])
def test_ModelCustodyAfterLostWorkspaceAckRetainsBudgetAndRepair(
    tmp_path, monkeypatch, profile, grown
):
    """Model-only manifest identity is preflighted before raw reading and permits honest repair."""

    context = Context(tmp_path) if profile == "docker-inspect" else KubernetesContext(tmp_path)
    root = context[0]

    def Fail(*args, **kwargs):
        """Lose the workspace acknowledgement before its actual publication."""

        raise OSError("owned simulated lost acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(LocalWorkspaceStore, "Save", Fail)
        status, first = Run(Arguments(context, profile=profile), clock=lambda: TIME)

    assert (
        status == 4
        and first["model_commit"] == "confirmed"
        and (first["workspace_commit"] == "unknown")
    ), "Required model-confirmed/workspace-lost-ACK state was not actually created"
    assert not LocalWorkspaceStore(root).Open().evidence_record_references, (
        "Workspace unexpectedly saved"
    )
    record = context[3].Get(first["evidence_id"])

    if grown:
        reference = record.reference
        alias = EvidenceReference(
            "a-runtime-alias",
            reference.locator,
            reference.sha256,
            "application/json",
            1024 * 1024 + 1,
        )
        workspace = LocalWorkspaceStore(root).Open()
        LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))
        (root / "evidence" / reference.locator).write_bytes(b"x" * (1024 * 1024 + 1))
        before = LocalModelStore(root).Open()
        monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
        monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
        status, outcome = Run(Arguments(context, profile=profile, evidence_id=record.evidence_id))
        assert status == 4 and outcome["failure"] == "integrity", (
            "Model-only known original read raw"
        )
        assert LocalModelStore(root).Open() == before, "Lost-ACK budget guard rewrote model truth"

    else:
        before = LocalModelStore(root).Open()
        context[4].unlink()
        status, outcome = Run(Arguments(context, profile=profile, evidence_id=record.evidence_id))
        assert status == 0 and outcome["model_revision"] == before.revision, (
            "Repair changed saved model"
        )
        assert record.evidence_id in LocalWorkspaceStore(root).Open().evidence_record_references, (
            "Known model custody could not finish workspace references after lost acknowledgement"
        )
