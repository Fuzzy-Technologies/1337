# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual local-export orchestration over explicitly inert command results and socket metadata."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337 import local_image_workflow as product
from fuzzy1337.adapters import ExecutionState
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.jobs import JobFailureCode, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.scope import AuthorizationState, LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.unit.test_local_image_archive import CONFIG_ID, OriginalArchive
from tests.unit.test_local_image_material import SelectedMaterial as SelectedMaterial
from tests.unit.test_local_image_policy import NOW, InertResult
from tests.unit.test_local_image_policy import OriginalOperation as OriginalOperation


@pytest.fixture(scope="module")
def export_runner():
    """Create event-loop resources before the unchanged per-test networking refusal guard."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.fixture(name="export_case")
def ExportCase(original_operation, monkeypatch):
    """Keep actual policy, evidence, workspace and executor-entry checks, replacing process only."""

    _, prepared, context = original_operation
    selection = prepared.observer.selection
    calls = []
    control = {"failure": None}

    async def Execute(self, request, **options):
        """Supply clearly inert command results after the actual mandatory prelaunch callback."""

        assert options["own_descendants"] is True, (
            "The product must request the accepted Linux descendant cleanup boundary."
        )
        options["pre_launch"](request)
        operation = request.invocation.request.parameters["operation"]
        calls.append(operation)
        raw = OriginalArchive() if operation == "export" else json.dumps(
            {"Os": "linux", "Id": CONFIG_ID}).encode()
        if control["failure"] == "missing" and operation == "inspect":
            return InertResult(b"missing local image", state=ExecutionState.FAILED, code=1)
        if control["failure"] == "reassigned" and operation == "recheck":
            raw = json.dumps({"Os": "linux", "Id": "sha256:" + "a" * 64}).encode()
        if control["failure"] == "malformed" and operation == "export":
            raw = b"not a Docker-save archive"
        if control["failure"] == "revoked" and operation == "export":
            store = LocalScopeStore(selection.workspace_root)
            original = store.Open(context.scope.scope_id)
            store.Save(replace(original, authorization=replace(original.authorization,
                state=AuthorizationState.REVOKED)))
        if control["failure"] == "cancelled" and operation == "export":
            options["cancellation"].set()
        return InertResult(raw)

    monkeypatch.setattr(product.LocalExecutor, "Execute", Execute)
    return selection, context, calls, control


def RunExport(export_runner, case, **kwargs):
    """Run the real product API against one exact explicitly approved inert fixture."""

    selection, context, _, _ = case
    return export_runner.run(product.ExportLocalImage(selection, context.scope.scope_id,
        context.owner_ref, lambda: context.policy, approve_local_image=True,
        clock=lambda: NOW, **kwargs))


def test_ExportPublishesSeparateArchivePinPreservingModelAndEvidence(export_runner, export_case):
    """Three original commands produce an archive, never an implicit scope or model scan."""

    selection, context, calls, _ = export_case
    root = selection.workspace_root
    before = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    summary = RunExport(export_runner, export_case)
    assert summary.snapshot.state is JobState.COMPLETED and summary.workspace_acknowledged, (
        "A completed export must have a confirmed original workspace CAS acknowledgement."
    )
    assert calls == ["inspect", "export", "recheck"], (
        "One local reference must resolve, save by immutable config ID and recheck once."
    )
    assert summary.archive_pin is not None and summary.archive_pin.image_config_id == CONFIG_ID, (
        "The returned selected config must match actual retained archive config bytes."
    )
    assert (root / summary.archive_relative_path).read_bytes() == OriginalArchive(), (
        "The separately scoped archive must preserve the complete original stdout bytes."
    )
    after = LocalWorkspaceStore(root).Open()
    assert after.revision == before.revision + 1 and LocalModelStore(root).Open() == model, (
        "Export must preserve the model and acknowledge one workspace metadata transition."
    )
    assert len(summary.snapshot.artifacts) == 9 and len(after.evidence_record_references) == 9, (
        "Each actual command must retain original stdout, stderr and receipt before acceptance."
    )
    store = LocalEvidenceStore(root / "evidence")
    for artifact in summary.snapshot.artifacts:
        assert store.Get(artifact.evidence.evidence_id) == artifact.evidence, (
            "Every original job artifact must reopen with its unchanged canonical evidence ID."
        )
    scope = LocalScopeStore(root).Open(context.scope.scope_id)
    assert scope.targets == (selection.Target(),), (
        "An export must never silently register or authorize the produced archive target."
    )
    rendered = summary.ToDict()
    assert rendered["archive_scan_requires_separate_scope"] is True and (
        rendered["archive_sha256"] != CONFIG_ID.removeprefix("sha256:")
    ), "Archive byte identity and selected config identity must remain separate."


@pytest.mark.parametrize("selected_material", [True], indirect=True, ids=["portable-posix-model"])
def test_PortableLogicalExportPreservesOriginalStateAndAuthority(export_runner, export_case):
    """Declared mode/fsync projections exercise orchestration without a socket or process claim."""

    selection, _, commands, _ = export_case
    summary = RunExport(export_runner, export_case)
    assert summary.ExitCode() == 0 and commands == ["inspect", "export", "recheck"], (
        "Portable logical projections must still traverse the actual original authority owner."
    )
    saved = LocalWorkspaceStore(selection.workspace_root).Open()
    assert len(saved.evidence_record_references) == 9, (
        "Portable logical publication must retain the same nine acknowledged original acquisitions."
    )


@pytest.mark.parametrize("failure,expected_calls", (
    ("missing", ["inspect"]),
    ("malformed", ["inspect", "export"]),
    ("reassigned", ["inspect", "export", "recheck"]),
    ("revoked", ["inspect", "export"]),
    ("cancelled", ["inspect", "export"]),
))
def test_FailedExportRetainsOriginalEvidenceWithoutAcceptedArchive(
    export_runner, export_case, failure, expected_calls,
):
    """Failed interpretation, authority or cancellation keeps original acquisitions explicit."""

    selection, _, calls, control = export_case
    control["failure"] = failure
    before = LocalModelStore(selection.workspace_root).Open()
    summary = RunExport(export_runner, export_case)
    assert summary.snapshot.state in {JobState.FAILED, JobState.CANCELLED}, (
        "A refused phase must not become a completed local export."
    )
    assert calls == expected_calls and summary.archive_pin is None and (
        summary.archive_relative_path is None
    ), "Refused original phases must stop forward work and expose no accepted archive."
    assert len(summary.snapshot.artifacts) == len(calls) * 3 and (
        LocalModelStore(selection.workspace_root).Open() == before
    ), "Actual failed-command evidence must survive without any model mutation."
    assert summary.workspace_acknowledged, "Failed-job evidence CAS must report its actual result."


def test_ExportApprovalRefusesBeforeSelectedReads(export_runner, export_case, monkeypatch):
    """Neither descriptor planning nor an absent opt-in may start material observation."""

    selection, context, calls, _ = export_case

    def Unexpected(*args):
        """Detect an unauthorized selected-material read without running any command."""

        pytest.fail("Unapproved local export must not observe selected material")

    monkeypatch.setattr(product.LocalImageMaterialObserver, "Observe", Unexpected)
    plan = product.PlanLocalImageExport(selection).ToDict()
    assert plan["execution_authorized"] is False, (
        "Pure planning must never issue execution authority."
    )
    with pytest.raises(ValueError, match="explicit approval"):
        export_runner.run(product.ExportLocalImage(selection, context.scope.scope_id,
            context.owner_ref, lambda: context.policy))
    assert calls == [], "Absent explicit approval must never enter the executor."


def test_ArchiveNoClobberPreservesPreexistingBytes(export_runner, export_case, monkeypatch):
    """An existing destination denies completion and retains its original caller bytes."""

    selection, _, _, _ = export_case
    original = Path.open

    def Open(path, mode="r", *args, **kwargs):
        """Create a competing archive immediately before the private config setup returns."""

        stream = original(path, mode, *args, **kwargs)
        if path.name == "config.json" and mode == "xb":
            archive = path.parent.parent.parent / "image.tar"
            with original(archive, "xb") as owned:
                owned.write(b"preexisting caller bytes")
        return stream

    monkeypatch.setattr(Path, "open", Open)
    summary = RunExport(export_runner, export_case)
    archives = tuple(selection.workspace_root.glob("local-image-export-*/image.tar"))
    assert summary.snapshot.state is JobState.FAILED and summary.archive_pin is None, (
        "An existing archive destination must deny accepted publication."
    )
    assert len(archives) == 1 and archives[0].read_bytes() == b"preexisting caller bytes", (
        "Exclusive archive publication must never replace existing caller content."
    )


@pytest.mark.parametrize("boundary", ("claim", "scope", "archive", "acknowledgement"))
def test_FinalPublicationRefusalsDoNotExposeAcceptedPins(
    export_runner, export_case, monkeypatch, boundary,
):
    """Original completed results cannot bypass final custody, authority, bytes or CAS truth."""

    selection, context, calls, _ = export_case
    original = product.ValidateCompletedLocalExport
    save = LocalWorkspaceStore.Save
    checks = []

    def Validate(*args, **kwargs):
        """Change one controlled final boundary before delegating every actual original check."""

        checks.append(True)
        if len(checks) == 1 and boundary == "claim":
            path = next((selection.workspace_root / "local-image-export-claims").glob(
                "*.launch.json"))
            path.unlink()
        if len(checks) == 1 and boundary == "scope":
            store = LocalScopeStore(selection.workspace_root)
            prior = store.Open(context.scope.scope_id)
            store.Save(replace(prior, authorization=replace(prior.authorization,
                state=AuthorizationState.REVOKED)))
        if len(checks) == 2 and boundary == "archive":
            archive = next(selection.workspace_root.glob("local-image-export-*/image.tar"))
            archive.write_bytes(b"changed after complete export")
        return original(*args, **kwargs)

    def Save(store, state):
        """Simulate one uncertain acknowledgement after the actual immutable workspace save."""

        result = save(store, state)
        if boundary == "acknowledgement":
            raise OSError("Explicit inert uncertain CAS acknowledgement")
        return result

    monkeypatch.setattr(product, "ValidateCompletedLocalExport", Validate)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Save)
    summary = RunExport(export_runner, export_case)
    assert calls == ["inspect", "export", "recheck"] and (
        summary.snapshot.state is JobState.FAILED
    ), (
        "Final publication alone was changed; all original acquisitions must remain factual."
    )
    assert summary.archive_pin is None and summary.archive_relative_path is None and (
        len(summary.snapshot.artifacts) == 9
    ), "A final refusal must preserve original evidence while withholding accepted archive claims."
    if boundary == "acknowledgement":
        assert not summary.workspace_acknowledged, (
            "An uncertain save response must never be upgraded to a confirmed acknowledgement."
        )


@pytest.mark.parametrize("failure", ("suppressed", "wrong-write", "lost-ack", "stale-ack",
                                     "wrong-ack", "untyped-ack"))
def test_ExactWorkspaceAcknowledgementRequiresTheOriginalProposalAndRevision(
    export_runner, export_case, monkeypatch, failure,
):
    """Unconfirmed saves cannot publish successful archive acknowledgements."""

    selection, _, commands, _ = export_case
    root = selection.workspace_root
    before = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    original_save = LocalWorkspaceStore.Save
    writes = []

    class EqualityImpostor:
        """An explicitly untyped inert return value cannot supply a storage acknowledgement."""

        def __eq__(self, other):
            """Model a permissive equality response without claiming any actual saved state."""

            return True

    def Save(store, proposal):
        """Change one actual save/return boundary while retaining factual partial-write state."""

        writes.append(proposal)

        if failure == "suppressed":
            return store.Open()

        if failure == "wrong-write":
            return original_save(store, replace(proposal, evidence_references=(),
                evidence_record_references=(), scope_references=(), job_references=()))

        saved = original_save(store, proposal)

        if failure == "lost-ack":
            return None

        if failure == "stale-ack":
            return before

        if failure == "wrong-ack":
            return replace(saved, revision=saved.revision + 1)

        return EqualityImpostor()

    monkeypatch.setattr(LocalWorkspaceStore, "Save", Save)
    summary = RunExport(export_runner, export_case)
    assert summary.snapshot.state is JobState.FAILED and summary.snapshot.failure.code is (
        JobFailureCode.STORAGE
    ), "Only the exact original typed proposal at the next revision may acknowledge publication."
    assert commands == ["inspect", "export", "recheck"] and len(writes) == 1, (
        "Original provider phases must remain factual and an uncertain save must never be retried."
    )
    assert not summary.workspace_acknowledged and summary.archive_pin is None and (
        summary.archive_relative_path is None
    ), "Unacknowledged storage must withhold every accepted archive/pin publication."
    after = LocalWorkspaceStore(root).Open()
    assert after.revision == before.revision + int(failure != "suppressed"), (
        "Actual partial writes remain visible even when their acknowledgement is refused."
    )
    assert len(summary.snapshot.artifacts) == 9 and LocalModelStore(root).Open() == model, (
        "Failed persistence must retain original acquisitions and never mutate the model."
    )
    evidence = LocalEvidenceStore(root / "evidence")

    for artifact in summary.snapshot.artifacts:
        assert evidence.Get(artifact.evidence.evidence_id) == artifact.evidence, (
            "Unacknowledged publication must preserve every original evidence record."
        )
