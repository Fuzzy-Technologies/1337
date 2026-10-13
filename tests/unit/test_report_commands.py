# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded report consumer failure contracts over owned local source and output bytes."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337 import report_commands as commands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.report_export_fixture import (
    Context,
    DenyExecution,
    Files,
    OutcomeValidator,
    Run,
)
from tests.contract.test_reporting_contract import Validator


def test_EmptyWorkspaceExportsWithoutScopeOrCleanScanClaim(tmp_path, monkeypatch):
    """No findings and no acquisitions remain an empty snapshot with unassessed completeness."""

    root = tmp_path / "empty"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Empty snapshot"), "empty")
    LocalModelStore(root).Create()
    before = Files(root)
    DenyExecution(monkeypatch)
    destination = tmp_path / "empty.json"
    status, outcome = Run(root, destination)
    document = json.loads(destination.read_bytes())
    assert status == 0 and outcome["model_revision"] == 0, "An empty saved model is exportable."
    assert document["summary"]["findings"] == 0 and document["scan_completeness"] == (
        "not-assessed"
    ), "An empty report must not become a clean scan or successful check."
    assert Files(root) == before, "Empty export must not initialize scopes or acquire evidence."



@pytest.mark.parametrize("authorization", [
    ScopeAuthorization(AuthorizationState.REVOKED),
    ScopeAuthorization(AuthorizationState.GRANTED, "operator:original", "consent:historic",
                       "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z"),
])
def test_HistoricalScopeMetadataNeverBecomesCurrentExecutionApproval(tmp_path, authorization):
    """Valid owning context may be revoked/expired while original source attribution stays exact."""

    root, _ = Context(tmp_path)
    scope = LocalScopeStore(root).Open("local")
    LocalScopeStore(root).Save(replace(scope, authorization=authorization))
    before = Files(root)
    destination = tmp_path / "historical.json"
    status, _ = Run(root, destination)
    assert status == 0, "Historical report reading must not demand or synthesize a new scan grant."
    assert Files(root) == before, "Current scope lookup must not substitute acquisition provenance."



@pytest.mark.parametrize("failure", [
    "missing", "corrupt", "foreign", "manifest", "scope", "foreign-scope", "corrupt-scope",
])
def test_AnyRetainedEvidenceOrOwningContextFailurePreventsOutput(tmp_path, failure):
    """An older unused acquisition cannot silently disappear or migrate between workspaces."""

    root, records = Context(tmp_path)
    store = LocalEvidenceStore(root / "evidence")
    unused = records[1]

    if failure == "missing":
        (root / "evidence" / unused.reference.locator).unlink()

    elif failure == "corrupt":
        (root / "evidence" / unused.reference.locator).write_bytes(
            b"x" * unused.reference.size_bytes,
        )

    elif failure == "foreign":
        foreign = store.Put(b"owned foreign synthetic record", "stdout", "text/plain",
                            replace(unused.provenance, workspace_id="foreign"))
        workspace = LocalWorkspaceStore(root).Open()
        LocalWorkspaceStore(root).Save(replace(workspace,
            evidence_record_references=(*workspace.evidence_record_references, foreign.evidence_id),
        ))

    elif failure == "manifest":
        (root / "evidence" / "records" / (unused.evidence_id[7:] + ".json")).write_bytes(b"{}")

    elif failure == "scope":
        (root / "state" / "scopes" / "local.json").unlink()

    elif failure == "foreign-scope":
        scope_path = root / "state" / "scopes" / "local.json"
        scope_data = json.loads(scope_path.read_bytes())
        scope_data["workspace_id"] = "foreign"
        scope_path.write_text(json.dumps(scope_data))

    else:
        (root / "state" / "scopes" / "local.json").write_bytes(b"{}")

    before = Files(root)
    destination = tmp_path / "rejected.json"
    status, result = Run(root, destination)
    assert status == 4 and result["failure"] == "integrity", "Invalid retained input must fail."
    assert not destination.exists() and not result["output_published"], (
        "Integrity failure cannot publish a partly verified report."
    )
    assert Files(root) == before, "The reader must not repair, remove or rewrite rejected source."



@pytest.mark.parametrize("change", ["model", "workspace"])
def test_ChangedSavedInputIsRejectedWithoutSubstitutingNewRevision(tmp_path, monkeypatch, change):
    """A renderer-triggered cooperative write cannot silently replace the selected snapshot."""

    root, _ = Context(tmp_path)
    serialize = commands.SerializeJson

    def SerializeThenChange(report):
        """Simulate an owner save after projection verification but before publication."""

        payload = serialize(report)

        if change == "model":
            model = LocalModelStore(root).Open()
            host = SecurityObject(
                ObjectIdentity(model.workspace_id, ObjectKind.HOST, "127.0.0.2"),
                provenance=model.Objects(ObjectKind.HOST)[0].provenance,
            )
            updated, delta = model.Apply(objects=(host,))
            LocalModelStore(root).Save(updated, expected_revision=delta.previous_revision)

        else:
            workspace = LocalWorkspaceStore(root).Open()
            LocalWorkspaceStore(root).Save(replace(workspace,
                configuration=WorkspaceConfiguration("Cooperatively changed")))

        return payload

    monkeypatch.setattr(commands, "SerializeJson", SerializeThenChange)
    destination = tmp_path / "stale.json"
    status, outcome = Run(root, destination)
    assert status == 4 and outcome["failure"] == "input-changed", (
        "The command must disclose changed source rather than exporting another revision."
    )
    assert not destination.exists(), "Changed input must not publish output."



def test_ExistingOutputAndConcurrentCreatorAreNeverClobbered(tmp_path, monkeypatch):
    """The no-clobber publication boundary preserves both preexisting and racing selected files."""

    root, _ = Context(tmp_path)
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"owned preexisting report")
    assert Run(root, existing)[0] == 2, "An existing selected output is invalid configuration."
    assert existing.read_bytes() == b"owned preexisting report", "Do not overwrite existing data."
    destination = tmp_path / "racing.json"
    link = os.link

    def ConcurrentCreation(source, target):
        """Create a legitimate competing destination immediately before atomic publication."""

        Path(target).write_bytes(b"owned concurrent creator")

        return link(source, target)

    monkeypatch.setattr(commands.os, "link", ConcurrentCreation)
    status, outcome = Run(root, destination)
    assert status == 4 and not outcome["output_published"], "A lost publication race must fail."
    assert destination.read_bytes() == b"owned concurrent creator", "Never remove competing data."
    assert not list(tmp_path.glob(".1337-report-*.pending")), "The exporter owns temporary cleanup."



@pytest.mark.parametrize("failure", ["write-sync", "link", "parent-sync", "cleanup"])
def test_AtomicPublicationFailuresPreserveCompleteOutputTruth(tmp_path, monkeypatch, failure):
    """Post-link failure remains failed while its complete committed output survives unchanged."""

    root, _ = Context(tmp_path)
    destination = tmp_path / "atomic.json"
    before = Files(root)
    published = failure in {"parent-sync", "cleanup"}

    def Denied(*arguments, **options):
        """Inject a finite filesystem failure without changing or fabricating an acquisition."""

        raise OSError("synthetic sensitive-path diagnostic must not escape")

    if failure == "write-sync":
        monkeypatch.setattr(commands.os, "fsync", Denied)

    elif failure == "link":
        monkeypatch.setattr(commands.os, "link", Denied)

    elif failure == "parent-sync":
        monkeypatch.setattr(commands, "SyncStorageDirectory", Denied)

    else:
        unlink = Path.unlink

        def DenyOwnedCleanup(path, **options):
            """Fail only exporter-owned temporary cleanup, preserving the committed destination."""

            if path.name.startswith(".1337-report-"):
                raise OSError("owned synthetic cleanup failure")

            return unlink(path, **options)

        monkeypatch.setattr(Path, "unlink", DenyOwnedCleanup)

    status, outcome = Run(root, destination)
    assert status == 4 and outcome["failure"] == "publication", "Storage failure must stay failed."
    assert outcome["output_published"] is published, "Preserve the exact confirmed link outcome."
    assert destination.exists() is published, "Publish only complete outputs, never partial bytes."
    assert Files(root) == before, "Export failure must not alter the source workspace."

    if published:
        Validator().validate(json.loads(destination.read_bytes()))
        assert hashlib.sha256(destination.read_bytes()).hexdigest() == outcome["report_sha256"], (
            "A post-link error must not change or remove its complete output."
        )

    if failure == "cleanup":
        monkeypatch.setattr(Path, "unlink", unlink)

        for path in tmp_path.glob(".1337-report-*.pending"):
            path.unlink()



@pytest.mark.parametrize("limit,value", [
    ("MAX_EXPORT_ACQUISITIONS", 1), ("MAX_EXPORT_BLOBS", 1),
    ("MAX_EXPORT_BLOB_BYTES", 1), ("MAX_EXPORT_EVIDENCE_BYTES", 40),
    ("MAX_EXPORT_SCOPES", 0), ("MAX_REPORT_BYTES", 1),
])
def test_ConsumerQuotasRejectBeforeAnyReportPublication(tmp_path, monkeypatch, limit, value):
    """Enforce real manifest/blob/context and output bounds without changing source ownership."""

    root, _ = Context(tmp_path)
    before = Files(root)
    monkeypatch.setattr(commands, limit, value)
    destination = tmp_path / "over-budget.json"
    status, result = Run(root, destination)
    assert status == 4 and result["failure"] == "limit", "Fixed quotas must fail explicitly."
    assert not destination.exists(), "Over-budget export must not publish even an empty report."
    assert Files(root) == before, "The quota consumer must not truncate source evidence."



def test_ActualOversizedStoredBlobIsRejectedBeforeOwningRead(tmp_path, monkeypatch):
    """A false declared length cannot make the owner load larger stored bytes before rejection."""

    root, records = Context(tmp_path)
    (root / "evidence" / records[0].reference.locator).write_bytes(b"x" * 256)
    owner_read = LocalEvidenceStore.Read
    reads = []

    def ObserveRead(store, reference):
        """Observe owning raw-read entry without replacing its integrity implementation."""

        reads.append(reference)

        return owner_read(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", ObserveRead)
    monkeypatch.setattr(commands, "MAX_EXPORT_BLOB_BYTES", 128)
    destination = tmp_path / "oversized.json"
    status, _ = Run(root, destination)
    assert status == 4 and not reads, "Actual raw sizes must be checked before owning body reads."
    assert not destination.exists(), "The oversized stored blob must not produce a report."



def test_SecondReportVerifierPathRejectsBlobGrowthBeforeOpeningRawBytes(tmp_path, monkeypatch):
    """Owner size checks retain the approved resource ceiling in the subsequent verifier path."""

    root, records = Context(tmp_path)
    artifact = root / "evidence" / records[0].reference.locator
    verify = commands.VerifyReportEvidence
    opening = Path.open
    changed = False

    def GrowBeforeVerification(report, workspace_root):
        """Change only the owned artifact between preflight and the real report verifier."""

        nonlocal changed
        artifact.write_bytes(b"x" * 256)
        changed = True

        return verify(report, workspace_root)

    def ObserveOpen(path, *arguments, **options):
        """A stored-size mismatch must fail on metadata before a second bulk-read file open."""

        if changed and path == artifact:
            raise AssertionError("Second verification must reject oversized bytes before opening.")

        return opening(path, *arguments, **options)

    monkeypatch.setattr(commands, "VerifyReportEvidence", GrowBeforeVerification)
    monkeypatch.setattr(Path, "open", ObserveOpen)
    destination = tmp_path / "changed-evidence.json"
    status, result = Run(root, destination)
    assert status == 4 and result["failure"] == "integrity", (
        "The owning second verifier must preserve its declared-size ceiling."
    )
    assert not destination.exists(), "A failing second verification cannot publish output."



@pytest.mark.parametrize("failure", ["missing-parent", "inside-workspace", "traversal", "control"])
def test_OnlyExplicitNewSafeOutputPathsAreAccepted(tmp_path, failure):
    """Invalid publication configuration cannot mutate source partitions or create directories."""

    root, _ = Context(tmp_path)
    destinations = {
        "missing-parent": tmp_path / "not-created" / "report.json",
        "inside-workspace": root / "derived.json",
        "traversal": tmp_path / "not-created" / ".." / "report.json",
        "control": tmp_path / "report\n.json",
    }
    before = Files(root)
    status, outcome = Run(root, destinations[failure])
    assert status == 2 and outcome["failure"] == "configuration", (
        "Unsafe or implicit output configuration must remain a setup failure."
    )
    assert Files(root) == before and not (tmp_path / "not-created").exists(), (
        "The exporter must create only its explicitly selected new output file."
    )



@pytest.mark.parametrize("phase", ["before-link", "after-link"])
def test_InterruptedPublicationOwnsCleanupAndReportsConfirmedCommit(tmp_path, monkeypatch, phase):
    """Ctrl+C never exposes partial output or erases a complete already published report."""

    root, _ = Context(tmp_path)

    def Interrupt(*arguments, **options):
        """Interrupt one explicitly chosen filesystem boundary, not a provider process."""

        raise KeyboardInterrupt

    if phase == "before-link":
        monkeypatch.setattr(commands.os, "link", Interrupt)

    else:
        monkeypatch.setattr(commands, "SyncStorageDirectory", Interrupt)

    destination = tmp_path / "interrupted.json"
    status, outcome = Run(root, destination)
    assert status == 130 and outcome["failure"] == "interrupted", (
        "Interruption must remain explicit after owned cleanup."
    )
    assert outcome["output_published"] is (phase == "after-link"), (
        "An interruption cannot invent or erase a confirmed link commit."
    )
    assert destination.exists() is (phase == "after-link"), "Output must be complete or absent."
    assert not list(tmp_path.glob(".1337-report-*.pending")), (
        "Interrupted export owns its temp file."
    )



@pytest.mark.parametrize("location", ["source-root", "output-parent", "blob"])
def test_ObservedLinkedPathsAreRejectedWithoutFollowingThem(tmp_path, location):
    """Both source owners and selected output reject test-owned symbolic path aliases."""

    root, records = Context(tmp_path)
    source = root
    destination = tmp_path / "physical.json"

    try:
        if location == "source-root":
            source = tmp_path / "source-alias"
            source.symlink_to(root, target_is_directory=True)

        elif location == "output-parent":
            parent = tmp_path / "output-alias"
            parent.symlink_to(tmp_path, target_is_directory=True)
            destination = parent / "physical.json"

        else:
            blob = root / "evidence" / records[0].reference.locator
            target = tmp_path / "owned-blob-bytes"
            blob.rename(target)
            blob.symlink_to(target)

    except OSError:
        pytest.skip("This platform cannot create the owned symlink regression fixture.")

    status, outcome = Run(source, destination)
    assert status == (4 if location == "blob" else 2), "Observed links must fail before output."
    assert not (tmp_path / "physical.json").exists() and not outcome["output_published"], (
        "An observed alias cannot publish a report or silently traverse another partition."
    )



def test_HardLinkedEvidenceCannotBecomeAnOwnedReportInput(tmp_path):
    """A second physical owner of raw input violates this consumer's immutable-read contract."""

    root, records = Context(tmp_path)
    os.link(root / "evidence" / records[0].reference.locator, tmp_path / "second-owner")
    destination = tmp_path / "hardlink.json"
    status, outcome = Run(root, destination)
    assert status == 4 and outcome["failure"] == "integrity", (
        "Retained input with another physical link must not pass the read-only ownership check."
    )
    assert not destination.exists(), "Unsafe physical evidence ownership cannot produce output."



def test_AcquisitionOnlyAndModelOnlyReferencesShareTheSameReadQuotas(tmp_path, monkeypatch):
    """Removing a direct workspace link cannot bypass budgets on owning Get or report reads."""

    root, records = Context(tmp_path)
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=()))
    monkeypatch.setattr(commands, "MAX_EXPORT_BLOB_BYTES", records[0].reference.size_bytes - 1)
    destination = tmp_path / "acquisition-only.json"
    status, outcome = Run(root, destination)
    assert status == 4 and outcome["failure"] == "limit", (
        "Get must quota-check raw bytes even without a direct workspace reference."
    )
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_record_references=()))
    destination = tmp_path / "model-only.json"
    status, outcome = Run(root, destination)
    assert status == 4 and outcome["failure"] == "limit", (
        "Report-linked bytes must remain bounded even without a retained acquisition pointer."
    )
    assert not destination.exists(), "Both source paths must fail before publication."



@pytest.mark.parametrize("arguments", [
    [], ["export", "synthetic-private-path"],
    ["export", "absent", "--format", "synthetic-secret-format", "--output", "new"],
    ["export", "absent", "--format", "json", "--output", "new", "--raw-secret-flag"],
])
def test_InvalidArgumentDiagnosticsRetainOnlyFixedCategories(arguments):
    """Rejected values and unknown options stay out of terminal diagnostics in both modes."""

    for json_output in (False, True):
        output = StringIO()
        status = commands.RunReportCommands(arguments, output, json_output=json_output)
        assert status == 2, "Invalid command grammar must remain a configuration exit."
        assert "synthetic-" not in output.getvalue() and "secret" not in output.getvalue(), (
            "Argparse must not echo private rejected argument values or flags."
        )

        if json_output:
            OutcomeValidator().validate(json.loads(output.getvalue()))



def test_ExplicitHelpAndHumanSuccessDoNotReadImplicitWorkspace(tmp_path, monkeypatch):
    """Help is local grammar; concise human success keeps the same unassessed source semantics."""

    DenyExecution(monkeypatch)
    output = StringIO()
    assert commands.RunReportCommands(["--help"], output) == 0, "Help needs no source or target."
    assert "--output" in output.getvalue() and "--format" in output.getvalue(), (
        "Required explicit output arguments must be discoverable."
    )
    root, _ = Context(tmp_path, findings=False)
    output = StringIO()
    destination = tmp_path / "human.json"
    status = commands.RunReportCommands(
        ["export", str(root), "--format", "json", "--output", str(destination)], output,
    )
    assert status == 0 and "scan completeness was not assessed" in output.getvalue(), (
        "Export success must not be presented as a clean scan or provider success."
    )



@pytest.mark.parametrize("error,category,status", [
    (ValueError("synthetic-private-render-path"), "rendering", 4),
    (RuntimeError("synthetic-private-internal-detail"), "internal", 4),
    (KeyboardInterrupt(), "interrupted", 130),
])
def test_RenderingFailuresAndInterruptionCannotPublishOrExposeExceptionText(
    tmp_path, monkeypatch, error, category, status,
):
    """Presentation errors retain their actual failure class without raw exception diagnostics."""

    root, _ = Context(tmp_path)

    def FailedRenderer(report):
        """Fail the actual post-verification renderer at an owned deterministic boundary."""

        raise error

    monkeypatch.setattr(commands, "SerializeJson", FailedRenderer)
    destination = tmp_path / "render-error.json"
    observed, outcome = Run(root, destination)
    assert observed == status and outcome["failure"] == category, (
        "The terminal result must preserve rendering, unexpected error or interruption truth."
    )
    assert "private" not in json.dumps(outcome) and not destination.exists(), (
        "A failed renderer cannot publish output or expose raw error text."
    )


def test_RepeatedInterruptionDuringCleanupPreservesConfirmedPublication(tmp_path, monkeypatch):
    """Repeated Ctrl+C cannot turn an already linked complete output into unpublished state."""

    root, _ = Context(tmp_path)
    unlink = Path.unlink

    def InterruptedCleanup(path, **options):
        """Interrupt every attempt to unlink only the explicitly owned temporary output."""

        if path.name.startswith(".1337-report-"):
            raise KeyboardInterrupt

        return unlink(path, **options)

    monkeypatch.setattr(Path, "unlink", InterruptedCleanup)
    destination = tmp_path / "repeated-interruption.json"
    status, outcome = Run(root, destination)
    assert status == 130 and outcome["output_published"], (
        "Repeated cleanup interruption must preserve the confirmed complete link commit."
    )
    assert outcome["failure"] == "interrupted" and destination.exists(), (
        "An interrupted owned cleanup must remain explicit without removing committed output."
    )
    monkeypatch.setattr(Path, "unlink", unlink)

    for path in tmp_path.glob(".1337-report-*.pending"):
        path.unlink()
