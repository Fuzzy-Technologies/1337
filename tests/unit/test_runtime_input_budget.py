# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Known original runtime budget refusals before either mode reaches generic raw verification."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from fuzzy1337 import runtime_commands as commands
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.runtime_helpers import Arguments, Context, KubernetesContext, Run

TIME = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)


def Imported(parent, profile):
    """Create real owners and successfully import an original fixture before testing its bounds."""

    context = Context(parent) if profile == "docker-inspect" else KubernetesContext(parent)
    status, first = Run(Arguments(context, profile=profile), clock=lambda: TIME)
    assert status == 0, "Original runtime setup did not actually acquire and save"

    return context, first


def RefuseRead(*args, **kwargs):
    """Fail explicitly if a refused known original reaches generic or selected raw consumers."""

    pytest.fail("Known runtime budget refusal reached raw reading")


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
@pytest.mark.parametrize("retained", [False, True])
def test_GrownOriginalOtherRoleAliasRefusesBeforeEveryRawRead(
    tmp_path,
    monkeypatch,
    profile,
    retained,
):
    """Both profiles and modes refuse grown originals and larger aliases before generic Read."""

    context, first = Imported(tmp_path, profile)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    reference = record.reference
    alias = EvidenceReference(
        "a-runtime-alias", reference.locator, reference.sha256, "application/json", 1024 * 1024 + 1
    )
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))
    (root / "evidence" / reference.locator).write_bytes(b"x" * (1024 * 1024 + 1))
    before = LocalModelStore(root).Open()
    workspace_before = (root / "workspace.json").read_bytes()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedInspect", RefuseRead)
    status, outcome = Run(
        Arguments(context, profile=profile, evidence_id=record.evidence_id if retained else None),
        clock=lambda: TIME,
    )
    assert status == 4 and outcome["failure"] == "integrity", "Known original reached raw access"
    assert outcome["acquisition_commit"] == "not-attempted", "Refusal acquired original bytes"
    assert LocalModelStore(root).Open() == before, "Budget refusal changed saved model truth"
    assert (root / "workspace.json").read_bytes() == workspace_before, (
        "Budget refusal saved workspace"
    )


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
@pytest.mark.parametrize("known_by", ["manifest-only", "raw-reference", "custody-only"])
def test_FileModePreflightsEveryKnownOriginalBeforeGenericRead(
    tmp_path,
    monkeypatch,
    profile,
    known_by,
):
    """Manifest IDs and model provenance/custody retain the original budget boundary."""

    context, first = Imported(tmp_path, profile)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    reference = record.reference
    model = LocalModelStore(root).Open()

    if known_by == "manifest-only":
        changed = replace(context[1], revision=model.revision + 1)
        LocalModelStore(root).Save(changed, expected_revision=model.revision)

    elif known_by == "raw-reference":
        changed = replace(
            model,
            revision=model.revision + 1,
            observations=tuple(
                item for item in model.observations if item.kind != "runtime-import-source"
            ),
        )
        LocalModelStore(root).Save(changed, expected_revision=model.revision)

    alias = EvidenceReference(
        "a-runtime-alias", reference.locator, reference.sha256, "application/json", 1024 * 1024 + 1
    )
    workspace = LocalWorkspaceStore(root).Open()
    object_references = tuple(item.Reference() for item in LocalModelStore(root).Open().objects)
    LocalWorkspaceStore(root).Save(
        replace(
            workspace,
            object_references=object_references,
            evidence_references=(alias,),
            evidence_record_references=(record.evidence_id,) if known_by == "manifest-only" else (),
        )
    )
    (root / "evidence" / reference.locator).write_bytes(b"x" * (1024 * 1024 + 1))
    before = LocalModelStore(root).Open()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Arguments(context, profile=profile), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "integrity", (
        "Known-by path bypassed original bound"
    )
    assert LocalModelStore(root).Open() == before, (
        "Budget scan adopted or rewrote known source data"
    )


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
def test_KnownOriginalsKeepTheirOwnScopesAndRetainedBytewiseNoop(tmp_path, profile):
    """Another selected attribution scope never replaces an older original's own context."""

    context, first = Imported(tmp_path, profile)
    root = context[0]
    scope = LocalScopeStore(root).Open("owned")
    LocalScopeStore(root).Create(replace(scope, scope_id="another"))
    arguments = Arguments(context, profile=profile)
    arguments[arguments.index("--scope") + 1] = "another"
    status, second = Run(arguments, clock=lambda: TIME + timedelta(seconds=2))
    assert status == 0 and second["evidence_id"] != first["evidence_id"], (
        "Older original inherited the newly selected scope"
    )
    before = {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }

    for selected, scope_id in ((first, "owned"), (second, "another")):
        arguments = Arguments(context, profile=profile, evidence_id=selected["evidence_id"])
        arguments[arguments.index("--scope") + 1] = scope_id
        status, outcome = Run(arguments)
        assert status == 0 and outcome["created"] == outcome["updated"] == 0, (
            "Old scope replay failed"
        )
        assert before == {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }, "Known original replay rewrote owner bytes"


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
def test_SamePhysicalLocatorWrongShaAliasRefusesBeforeGenericRead(tmp_path, monkeypatch, profile):
    """Alias hash substitution cannot hide a known original physical file from budget admission."""

    context, first = Imported(tmp_path, profile)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    reference = record.reference
    other_sha = "b" * 64 if reference.sha256 != "b" * 64 else "c" * 64
    alias = EvidenceReference("a-runtime-alias", reference.locator, other_sha,
                              reference.media_type, reference.size_bytes)
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))
    before = LocalModelStore(root).Open()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Arguments(context, profile=profile), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "integrity", "Physical alias reached generic read"
    assert outcome["acquisition_commit"] == "not-attempted", "Physical alias acquired source"
    assert LocalModelStore(root).Open() == before, "Physical alias guard changed model truth"


@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("repair_context", [False, True])
def test_KnownCustodyCannotReclassifyWrongRoleOriginalAsUnrelatedEvidence(
    tmp_path, monkeypatch, profile, retained, repair_context,
):
    """Custody binds its old profile before role classification in normal and lost-ACK contexts."""

    if repair_context:
        context = Context(tmp_path) if profile == "docker-inspect" else KubernetesContext(tmp_path)

        def Fail(*args, **kwargs):
            """Create an actual model-confirmed/workspace-lost-ACK original acquisition."""

            raise OSError("owned workspace acknowledgement loss")

        with monkeypatch.context() as patch:
            patch.setattr(LocalWorkspaceStore, "Save", Fail)
            status, first = Run(Arguments(context, profile=profile), clock=lambda: TIME)

        assert status == 4 and first["model_commit"] == "confirmed", "Repair setup did not commit"
        assert first["workspace_commit"] == "unknown", "Repair acknowledgement was not unknown"

    else:
        context, first = Imported(tmp_path, profile)

    root = context[0]
    evidence = LocalEvidenceStore(root / "evidence")
    record = evidence.Get(first["evidence_id"])
    wrong_role = evidence.Put(b"x" * (1024 * 1024 + 1), "stdout", "application/json",
                              record.provenance)
    model = LocalModelStore(root).Open()
    original_fact = next(item for item in model.observations
                         if item.kind == "runtime-import-source")
    wrong = replace(original_fact,
        attributes={**original_fact.attributes, "evidence_id": wrong_role.evidence_id,
                    "source_sha256": wrong_role.reference.sha256},
        provenance=replace(original_fact.provenance, evidence_references=(wrong_role.reference,)))
    changed, _ = model.Apply(observations=(wrong,))
    saved = LocalModelStore(root).Save(changed, expected_revision=model.revision)
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(wrong_role.reference,),
        evidence_record_references=() if repair_context else workspace.evidence_record_references))
    workspace_before = (root / "workspace.json").read_bytes()
    reads = []

    def RawRead(self, reference):
        """Record an actual generic owning Read before failing the violated pre-read boundary."""

        reads.append((reference.role, reference.size_bytes))
        pytest.fail("Custody-declared wrong-role original reached actual raw Read")

    monkeypatch.setattr(LocalEvidenceStore, "Read", RawRead)
    arguments = Arguments(context, profile=profile,
                          evidence_id=record.evidence_id if retained else None)
    status, outcome = Run(arguments, clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "integrity", "Custody role substitution passed"
    assert not reads and outcome["acquisition_commit"] == "not-attempted", "Wrong-role raw read"
    assert LocalModelStore(root).Open() == saved, "Custody budget validation rewrote model facts"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Custody guard saved state"
