# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic workspace validation, concurrency, and write-failure boundaries."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.workspace import (
    MAX_STATE_BYTES,
    LocalWorkspaceStore,
    WorkspaceBusyError,
    WorkspaceConfiguration,
    WorkspaceConflictError,
    WorkspaceLens,
    WorkspaceState,
    WorkspaceStore,
)


def CreateStore(tmp_path: Path) -> tuple[LocalWorkspaceStore, WorkspaceState]:
    """Create an isolated real store and its initial authoritative snapshot."""

    store = LocalWorkspaceStore(tmp_path / "workspace")
    state = store.Create(WorkspaceConfiguration("Synthetic investigation"), "synthetic-case")

    return store, state


def WriteDocument(store: LocalWorkspaceStore, document: object) -> None:
    """Write a deliberately malformed fixture without calling the product serializer."""

    (store.root / "workspace.json").write_text(json.dumps(document), encoding="utf-8")


@pytest.mark.parametrize("lens", list(WorkspaceLens))
def test_ConfigurationRoundTripsEachInitialLens(lens):
    """Preserve each declared lens and opaque view/report references exactly."""

    configuration = WorkspaceConfiguration("Synthetic", lens, "view:selected", "report:local")
    decoded = WorkspaceConfiguration.FromDict(configuration.ToDict())

    assert decoded == configuration, "Configuration decoding lost a lens or context reference"

    with pytest.raises(FrozenInstanceError):
        configuration.display_name = "changed"


@pytest.mark.parametrize("field_name,value", [
    ("workspace_id", "UPPER"), ("workspace_id", ""), ("workspace_id", 1),
    ("revision", True), ("revision", -1), ("revision", 1.0),
    ("configuration", {}), ("scope_references", "scope"),
    ("object_references", ("object", "object")), ("job_references", ("bad\nreference",)),
    ("scope_references", (3,)), ("evidence_references", "evidence"),
    ("evidence_references", ({},)), ("evidence_record_references", "not-a-list"),
    ("evidence_record_references", ("bad",)),
    ("evidence_record_references", ("sha256:" + "a" * 64,) * 2),
])
def test_StateRejectsMalformedRuntimeMetadata(field_name, value):
    """Reject invalid typed metadata before any store operation is possible."""

    arguments = {"workspace_id": "synthetic", "configuration": WorkspaceConfiguration("Synthetic")}
    arguments[field_name] = value

    with pytest.raises(ValueError):
        WorkspaceState(**arguments)


@pytest.mark.parametrize("field_name,value", [
    ("display_name", ""), ("display_name", 7), ("display_name", "bad\rname"),
    ("selected_lens", "pentest"), ("selected_lens", None),
    ("view_reference", "bad\x00reference"), ("report_context_reference", False),
])
def test_ConfigurationRejectsImplicitTypesAndInvalidReferences(field_name, value):
    """Keep lens selection and opaque references explicit rather than coercing strings."""

    arguments = {"display_name": "Synthetic"}
    arguments[field_name] = value

    with pytest.raises(ValueError):
        WorkspaceConfiguration(**arguments)


@pytest.mark.parametrize("field_name,value", [
    ("schema_version", 2), ("schema_version", True), ("schema_version", "1"),
    ("revision", False), ("revision", -1), ("workspace_id", None),
    ("scope_references", "all"), ("scope_references", ["same", "same"]),
    ("job_references", [False]), ("evidence_references", {}),
    ("object_references", ["bad\nreference"]), ("configuration", []),
    ("evidence_record_references", ["sha256:" + "A" * 64]),
    ("evidence_record_references", ["sha256:" + "a" * 63]),
    ("evidence_record_references", ["a" * 64]),
    ("evidence_record_references", ["sha256:" + "a" * 64] * 2),
])
def test_OpenRejectsInvalidDocumentFields(tmp_path, field_name, value):
    """Fail closed when a persisted document violates schema or reference contracts."""

    store, state = CreateStore(tmp_path)
    document = state.ToDict()
    document[field_name] = value
    WriteDocument(store, document)

    with pytest.raises(ValueError):
        store.Open()


@pytest.mark.parametrize("mutation", ["unknown", "missing", "not-object"])
def test_OpenRejectsNonExactDocumentObjects(tmp_path, mutation):
    """Never ignore undeclared fields or silently recover missing authoritative fields."""

    store, state = CreateStore(tmp_path)
    document = state.ToDict()

    if mutation == "unknown":
        document["extra"] = "unrecognized"

    elif mutation == "missing":
        del document["revision"]

    else:
        document = []

    WriteDocument(store, document)

    with pytest.raises(ValueError):
        store.Open()


@pytest.mark.parametrize("field_name,value", [
    ("selected_lens", "unrecognized"), ("selected_lens", 5),
    ("view_reference", []), ("report_context_reference", 1), ("display_name", ""),
])
def test_OpenRejectsMalformedConfiguration(tmp_path, field_name, value):
    """Do not interpret unknown lens names or wrong configuration types as defaults."""

    store, state = CreateStore(tmp_path)
    document = state.ToDict()
    document["configuration"][field_name] = value
    WriteDocument(store, document)

    with pytest.raises(ValueError):
        store.Open()


@pytest.mark.parametrize("payload", [
    b'{"schema_version":1,"schema_version":1}', b'{"revision":NaN}',
    b'{"revision":Infinity}', b"[]", b"not-json", b"\xff", b"\xef\xbb\xbf{}",
    b"[" * 2000 + b"]" * 2000,
])
def test_OpenRejectsAmbiguousOrCorruptJson(tmp_path, payload):
    """Reject duplicate keys, non-standard numbers, invalid encodings, and malformed JSON."""

    store, _ = CreateStore(tmp_path)
    (store.root / "workspace.json").write_bytes(payload)

    with pytest.raises(ValueError):
        store.Open()


@pytest.mark.parametrize("field_name,value", [
    ("role", "UPPER"), ("locator", "../outside"), ("locator", "/outside"),
    ("locator", "a\\b"), ("locator", "."), ("locator", "a//b"), ("locator", "a/./b"),
    ("locator", "file:outside"), ("sha256", "bad"), ("sha256", 7),
    ("media_type", ""), ("size_bytes", True), ("size_bytes", -1),
])
def test_OpenRejectsCorruptEvidenceReferences(tmp_path, field_name, value):
    """Validate evidence integrity metadata and reject unsafe partition-relative locators."""

    store, state = CreateStore(tmp_path)
    reference = {
        "role": "stdout", "locator": "blobs/sha256/" + "a" * 64,
        "sha256": "a" * 64, "media_type": "text/plain", "size_bytes": 1,
    }
    reference[field_name] = value
    document = state.ToDict()
    document["evidence_references"] = [reference]
    WriteDocument(store, document)

    with pytest.raises(ValueError):
        store.Open()


def test_StateRejectsDuplicateEvidenceIdentity(tmp_path):
    """Prevent ambiguous roles from repeating the same immutable evidence locator."""

    _, state = CreateStore(tmp_path)
    reference = EvidenceReference("stdout", "blobs/sha256/" + "a" * 64, "a" * 64, "text/plain", 1)

    with pytest.raises(ValueError, match="unique"):
        replace(state, evidence_references=(reference, reference))


def test_OpenRejectsOversizedAuthoritativeState(tmp_path):
    """Bound metadata reads independently from the size of evidence artifacts."""

    store, _ = CreateStore(tmp_path)
    (store.root / "workspace.json").write_bytes(b" " * (MAX_STATE_BYTES + 1))

    with pytest.raises(ValueError, match="size limit"):
        store.Open()


def test_SaveRejectsOversizedStateWithoutLosingOldSnapshot(tmp_path):
    """Validate the proposed metadata size before writing or replacing authoritative state."""

    store, state = CreateStore(tmp_path)
    oversized = replace(state, configuration=WorkspaceConfiguration("x" * MAX_STATE_BYTES))

    with pytest.raises(ValueError, match="size limit"):
        store.Save(oversized)

    assert store.Open() == state, "Oversized save replaced the previous valid snapshot"
    assert not (store.root / ".write-lock").exists(), "Oversized save leaked its writer lock"


@pytest.mark.parametrize("kind", ["revision", "identity"])
def test_SaveRejectsLostUpdatesAndIdentityChanges(tmp_path, kind):
    """Keep immutable workspace identity and reject stale cooperating writers."""

    store, state = CreateStore(tmp_path)
    committed = store.Save(replace(state, job_references=("job:first",)))
    proposal = state if kind == "revision" else replace(committed, workspace_id="another-case")

    with pytest.raises(WorkspaceConflictError):
        store.Save(proposal)

    assert store.Open() == committed, "A rejected save modified current state"
    assert committed.revision == 1, "A successful save did not increment its revision exactly once"
    assert not (store.root / ".write-lock").exists(), "Conflict rejection leaked writer ownership"


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_AbandonedWriterLockRemainsExplicitAndReadable(tmp_path, kind):
    """Do not steal an existing lock or prevent readers from opening completed state."""

    store, state = CreateStore(tmp_path)
    lock_path = store.root / ".write-lock"

    if kind == "directory":
        lock_path.mkdir()

    elif kind == "file":
        lock_path.write_text("operator-owned", encoding="utf-8")

    else:
        lock_path.symlink_to(tmp_path / "missing")

    with pytest.raises(WorkspaceBusyError):
        store.Save(state)

    assert store.Open() == state, "A writer lock incorrectly blocked reading a complete snapshot"
    assert lock_path.exists() or lock_path.is_symlink(), "Save stole an existing writer lock"


def test_CooperatingConcurrentWritersCannotLoseAnUpdate(tmp_path, monkeypatch):
    """Hold one real writer at commit and deterministically deny a competing writer."""

    store, state = CreateStore(tmp_path)
    entered = Event()
    release = Event()
    original_write = LocalWorkspaceStore.WriteState

    def ControlledWrite(self, proposal):
        """Hold a single writer while its owned lock protects the old snapshot."""

        entered.set()

        if not release.wait(timeout=5):
            raise RuntimeError("controlled writer was never released")

        original_write(self, proposal)

    monkeypatch.setattr(LocalWorkspaceStore, "WriteState", ControlledWrite)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(store.Save, replace(state, job_references=("job:writer",)))

        try:
            assert entered.wait(timeout=5), "The controlled writer never acquired ownership"
            assert store.Open() == state, "Readers observed incomplete state during a held writer"

            with pytest.raises(WorkspaceBusyError):
                store.Save(replace(state, job_references=("job:competing",)))

        finally:
            release.set()

        committed = future.result(timeout=5)

    assert store.Open() == committed, "The completed writer's snapshot was lost"

    with pytest.raises(WorkspaceConflictError):
        store.Save(state)


def test_FailedReplacementPreservesStateAndCleansOwnership(tmp_path, monkeypatch):
    """Clean temporary files and locks when a commit fails before replacement."""

    store, state = CreateStore(tmp_path)

    def RejectReplacement(source, destination):
        """Simulate a local filesystem failure without changing the old state."""

        raise OSError("synthetic replacement failure")

    monkeypatch.setattr(os, "replace", RejectReplacement)

    with pytest.raises(OSError, match="synthetic replacement failure"):
        store.Save(replace(state, job_references=("job:failed",)))

    assert store.Open() == state, "A failed replacement changed authoritative state"
    assert not list(store.root.glob(".workspace-*.json")), "Replacement failure leaked a file"
    assert not (store.root / ".write-lock").exists(), "Failed replacement leaked its writer lock"


def test_FileSyncFailureCleansTemporaryFilesBeforeCommit(tmp_path, monkeypatch):
    """Do not replace authoritative state when its new file could not be synchronized."""

    store, state = CreateStore(tmp_path)

    def RejectSync(descriptor):
        """Fail the first synchronization before an atomic replacement can occur."""

        raise OSError("synthetic synchronization failure")

    monkeypatch.setattr(os, "fsync", RejectSync)

    with pytest.raises(OSError, match="synthetic synchronization failure"):
        store.Save(state)

    assert store.Open() == state, "Failed file synchronization replaced authoritative state"
    assert not list(store.root.glob(".workspace-*.json")), "Synchronization failure leaked a file"
    assert not (store.root / ".write-lock").exists(), "Synchronization failure leaked a lock"


@pytest.mark.skipif(os.name != "posix", reason="Directory synchronization is a POSIX contract")
def test_PostReplacementSyncFailureRequiresReopening(tmp_path, monkeypatch):
    """Expose failure after replacement without pretending the old revision is still current."""

    store, state = CreateStore(tmp_path)
    original_sync = os.fsync
    calls = 0

    def RejectDirectorySync(descriptor):
        """Synchronize the file but fail the next directory synchronization."""

        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError("synthetic directory synchronization failure")

        original_sync(descriptor)

    monkeypatch.setattr(os, "fsync", RejectDirectorySync)

    with pytest.raises(OSError, match="synthetic directory synchronization failure"):
        store.Save(replace(state, job_references=("job:committed",)))

    reopened = store.Open()
    assert reopened.revision == 1, "The post-replacement failure unexpectedly lost the new revision"
    assert reopened.job_references == ("job:committed",), "Reopening did not reveal committed state"
    assert not (store.root / ".write-lock").exists(), "Post-replacement failure leaked ownership"


@pytest.mark.parametrize("partition", ["state", "evidence", "cache", "indexes", "workspace.json"])
@pytest.mark.parametrize("kind", ["symlink", "wrong-type"])
def test_OpenAndSaveRejectUnsafeStoragePaths(tmp_path, partition, kind):
    """Reject symlinked or invalid partition/state paths without following their contents."""

    store, state = CreateStore(tmp_path)
    path = store.root / partition

    if path.is_dir():
        path.rmdir()

    else:
        path.unlink()

    if kind == "symlink":
        path.symlink_to(tmp_path / "outside")

    elif partition == "workspace.json":
        path.mkdir()

    else:
        path.write_text("invalid partition", encoding="utf-8")

    with pytest.raises(ValueError):
        store.Open()

    with pytest.raises(ValueError):
        store.Save(state)


def test_SymlinkedRootAndAncestorAreRejected(tmp_path):
    """Reject both direct and ancestor links before creating or opening a workspace."""

    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "link"
    link.symlink_to(actual, target_is_directory=True)

    for root in (link, link / "workspace"):
        store = LocalWorkspaceStore(root)

        with pytest.raises(ValueError, match="symlinks"):
            store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")

        with pytest.raises(ValueError, match="symlinks"):
            store.Open()

    assert not list(actual.iterdir()), "Ancestor symlink rejection wrote outside the root"


@pytest.mark.parametrize("root", [Path("/"), Path("parent/../workspace"), "workspace"])
def test_ConstructionRejectsUnsafeLexicalRoots(root):
    """Reject filesystem roots, traversal, and implicit path coercion without mutation."""

    with pytest.raises(ValueError):
        LocalWorkspaceStore(root)


def test_ConstructionAndMissingWorkspaceFailWithoutImplicitCreation(tmp_path):
    """Constructing a store does not create files and Open does not initialize state."""

    root = tmp_path / "missing"
    store = LocalWorkspaceStore(root)

    with pytest.raises(ValueError, match="existing directory"):
        store.Open()

    with pytest.raises(ValueError, match="WorkspaceState"):
        store.Save({})

    assert not root.exists(), "Constructing or reading a store implicitly initialized its root"
    assert isinstance(store, WorkspaceStore), "The backend does not implement WorkspaceStore"


def test_CreateDoesNotOverwriteAnExistingWorkspace(tmp_path):
    """Preserve the previous authoritative identity when creation collides with an existing root."""

    store, state = CreateStore(tmp_path)

    with pytest.raises(FileExistsError):
        store.Create(WorkspaceConfiguration("Another"), "another")

    assert store.Open() == state, "Create replaced an existing workspace or reset its identity"


def test_FailedCreateLeavesAnExplicitlyIncompleteRoot(tmp_path, monkeypatch):
    """Keep an interrupted initialization detectable instead of reporting a valid workspace."""

    store = LocalWorkspaceStore(tmp_path / "workspace")

    def RejectWrite(self, state):
        """Fail initial persistence after private partitions have been initialized."""

        raise OSError("synthetic create failure")

    monkeypatch.setattr(LocalWorkspaceStore, "WriteState", RejectWrite)

    with pytest.raises(OSError, match="synthetic create failure"):
        store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")

    with pytest.raises(FileNotFoundError):
        store.Open()

    assert store.root.is_dir(), "Failed creation did not leave its explicitly incomplete root"


@pytest.mark.parametrize("evidence", [None, [None], [{"role": "stdout"}]])
def test_OpenRejectsIncompleteEvidenceObjects(tmp_path, evidence):
    """Do not infer missing integrity fields or accept non-object evidence records."""

    store, state = CreateStore(tmp_path)
    document = state.ToDict()
    document["evidence_references"] = evidence
    WriteDocument(store, document)

    with pytest.raises(ValueError):
        store.Open()


def test_ReparsePointMetadataIsRejectedWithoutFollowingIt(tmp_path, monkeypatch):
    """Exercise Windows reparse-point detection with deterministic non-following metadata."""

    store, _ = CreateStore(tmp_path)
    original_lstat = Path.lstat
    state_path = store.root / "workspace.json"

    def SimulateReparse(self, *args, **kwargs):
        """Represent an observed reparse file using the platform-independent attribute flag."""

        metadata = original_lstat(self, *args, **kwargs)

        if self == state_path:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)

        return metadata

    monkeypatch.setattr(Path, "lstat", SimulateReparse)

    with pytest.raises(ValueError, match="reparse points"):
        store.Open()


def test_RootMustBeADirectoryWithoutReplacingAnExistingFile(tmp_path):
    """Reject an existing regular file used as a root and preserve its bytes."""

    root = tmp_path / "existing-file"
    root.write_bytes(b"operator-owned")
    store = LocalWorkspaceStore(root)

    with pytest.raises(ValueError, match="directories"):
        store.Create(WorkspaceConfiguration("Synthetic"), "synthetic")

    assert root.read_bytes() == b"operator-owned", "Invalid root handling replaced an existing file"
