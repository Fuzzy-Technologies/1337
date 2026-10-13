# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned selected-file capture, physical-path denial and observed snapshot invariants."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import artifact_inputs as inputs
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactSelection,
    ArtifactSnapshot,
    ArtifactStage,
)


@pytest.fixture
def selected(tmp_path):
    """Select only owned finite fixture bytes and the explicitly trusted runtime."""

    root = tmp_path.resolve()
    source = root / "selected.tar"
    source.write_bytes(b"owned-selected-archive")

    return root, source, ArtifactReadConsent("owner:test", "consent:selected-files")


def Stage(selected):
    """Capture a fresh owned stage without issuing any scan grant."""

    root, source, consent = selected

    return ArtifactStage.Create(
        root / "stage",
        ArtifactProfile.SYNTHETIC_IMAGE,
        consent,
        (ArtifactSelection("image.tar", source),),
        ArtifactSelection("executable", Path(sys.executable).resolve()),
        "0.75.0-synthetic",
    )


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "a\\b",
        "a:b",
        "a//b",
        "a/../b",
        "a.",
        "a ",
        "CON",
        "prn.txt",
        "a/LPT9.yaml",
        "ümlaut",
        "x" * 241,
        "/".join(["x"] * 17),
        "a\nsecret",
        "a\x00b",
    ],
    ids=[
        "empty",
        "dot",
        "parent",
        "traversal",
        "absolute",
        "backslash",
        "colon",
        "empty-component",
        "parent-component",
        "trailing-dot",
        "trailing-space",
        "device",
        "device-extension",
        "nested-device",
        "non-ascii",
        "long-name",
        "deep-path",
        "newline",
        "nul",
    ],
)
def test_PortableNamesFailClosedWithoutReads(name, selected):
    """Unsafe names cannot become paths even when their source is selected."""

    _, source, _ = selected

    with pytest.raises(ValueError):
        ArtifactSelection(name, source)


@pytest.mark.parametrize(
    "records",
    [
        ("x", "X"),
        ("a", "a/b"),
        ("Folder/a", "folder/b"),
        ("x", "x"),
    ],
)
def test_ManifestRejectsCaseAndFileDirectoryCollisions(records):
    """Portable snapshot identities cannot vary between supported filesystems."""

    with pytest.raises(ValueError):
        ArtifactManifest(
            ArtifactProfile.SYNTHETIC_IMAGE,
            ArtifactRole.INPUT,
            tuple(ArtifactFile(name, 0, "0" * 64) for name in records),
        )


def test_CaptureOnlySelectedBytesAndIgnoreLaterOriginalMutation(selected):
    """Snapshot approval binds captured bytes rather than a mutable original path."""

    _, source, _ = selected
    stage = Stage(selected)
    target = stage.input.manifest.Target()
    source.write_bytes(b"changed-original-after-capture")
    stage.Verify()

    assert (stage.root / "input/image.tar").read_bytes() == b"owned-selected-archive", (
        "Original mutation altered the selected snapshot"
    )
    assert stage.input.manifest.Target() == target, "Original path affected manifest identity"
    assert stage.material.manifest.files == (), "Implicit material was selected"


@pytest.mark.parametrize("mutation", ["bytes", "extra-file", "extra-directory", "root-file"])
def test_ClosedStageRejectsObservedMaterialChanges(selected, mutation):
    """Missing/unlisted/material mutation never preserves observed integrity."""

    stage = Stage(selected)

    if mutation == "bytes":
        path = stage.root / "input/image.tar"
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        path.write_bytes(b"owned-change")

    elif mutation == "extra-file":
        (stage.root / "material/unlisted.db").write_bytes(b"owned-extra")

    elif mutation == "extra-directory":
        (stage.root / "input/unlisted").mkdir()

    else:
        (stage.root / "unlisted").write_bytes(b"owned-extra")

    with pytest.raises(ValueError):
        stage.Verify()


def test_ScratchStartsEmptyAndIsObservedOnlyAfterRun(selected):
    """Allowed scratch writes are measured afterward, never reused as approved input."""

    stage = Stage(selected)
    (stage.root / "scratch/output.txt").write_bytes(b"owned-output")

    with pytest.raises(ValueError):
        stage.Verify()

    stage.Verify(after_run=True)


def test_PhysicalHardlinkAndSymlinkAreRejected(selected):
    """Singly selected names do not authorize linked external bytes."""

    root, source, consent = selected
    alias = root / "hardlink"
    os.link(source, alias)

    with pytest.raises(ValueError):
        ArtifactSnapshot.Capture(
            root / "bad",
            ArtifactProfile.SYNTHETIC_IMAGE,
            ArtifactRole.INPUT,
            (ArtifactSelection("image.tar", alias),),
            consent,
        )


def test_ReparseAndSpecialMetadataAreRejected(selected, monkeypatch):
    """Portable non-following guards deny Windows reparse points and special files."""

    root, source, consent = selected
    real = inputs.StoragePathInfo

    def Special(path):
        """Expose an owned selected path as a special file without creating a device."""

        if path == source:
            return os.stat_result((stat.S_IFIFO | stat.S_IRUSR, 1, 1, 1, 0, 0, 0, 0, 0, 0))

        return real(path)

    monkeypatch.setattr(inputs, "StoragePathInfo", Special)

    with pytest.raises(ValueError):
        ArtifactSnapshot.Capture(
            root / "bad",
            ArtifactProfile.SYNTHETIC_IMAGE,
            ArtifactRole.INPUT,
            (ArtifactSelection("image.tar", source),),
            consent,
        )


def test_ExplicitReadConsentRequiredBeforeCapture(selected):
    """Absent actor/read consent cannot read selected bytes or create a successful snapshot."""

    root, source, _ = selected

    with pytest.raises(ValueError):
        ArtifactSnapshot.Capture(
            root / "bad",
            ArtifactProfile.SYNTHETIC_IMAGE,
            ArtifactRole.INPUT,
            (ArtifactSelection("image.tar", source),),
            None,
        )

    assert not (root / "bad").exists(), "Missing read authority created a capture partition"


def test_FiniteFilesAndBytesCheckedBeforeCapture(selected, monkeypatch):
    """Small injected limits prove the same production bounded-copy contract cheaply."""

    root, source, consent = selected
    monkeypatch.setattr(inputs, "MAX_ARTIFACT_FILE_BYTES", 4)

    with pytest.raises(ValueError):
        ArtifactSnapshot.Capture(
            root / "bad",
            ArtifactProfile.SYNTHETIC_IMAGE,
            ArtifactRole.INPUT,
            (ArtifactSelection("image.tar", source),),
            consent,
        )


@pytest.mark.parametrize(
    "field,value",
    [("size_bytes", True), ("size_bytes", -1), ("sha256", "A" * 64), ("sha256", None)],
)
def test_ExactFileMetadataRejectsMalformedTypes(field, value):
    """Invalid length/hash fields cannot enter a manifest."""

    values = {"name": "image.tar", "size_bytes": 0, "sha256": "0" * 64, field: value}

    with pytest.raises(ValueError):
        ArtifactFile(**values)


def test_ScannerRoleCannotAuthorizeInputAndRelocationKeepsIdentity(selected):
    """Role separation and content-based relocation keep digest semantics explicit."""

    root, source, consent = selected
    stage = Stage(selected)
    other = ArtifactSnapshot.Capture(
        root / "relocated",
        ArtifactProfile.SYNTHETIC_IMAGE,
        ArtifactRole.INPUT,
        (ArtifactSelection("image.tar", source),),
        consent,
    )

    assert other.manifest.Digest() == stage.input.manifest.Digest(), (
        "Absolute physical location entered content identity"
    )

    with pytest.raises(ValueError):
        replace(other.manifest, role=ArtifactRole.SCANNER).Target()

    assert other.manifest.Digest() != hashlib.sha256(source.read_bytes()).hexdigest(), (
        "Archive SHA was confused with the profile manifest digest"
    )


def test_AllPartitionsShareOneCombinedStageBudget(selected, monkeypatch):
    """The reviewer's16→24-byte case denies before creating or copying a stage."""

    root, source, consent = selected
    source.write_bytes(b"x" * 10)
    executable = root / "owned-executable"
    executable.write_bytes(b"x" * 4)
    material = root / "owned-material"
    material.write_bytes(b"x" * 10)
    monkeypatch.setattr(inputs, "MAX_ARTIFACT_TOTAL_BYTES", 16)

    with pytest.raises(ValueError):
        ArtifactStage.Create(
            root / "too-large",
            ArtifactProfile.IMAGE,
            consent,
            (ArtifactSelection("image.tar", source),),
            ArtifactSelection("executable", executable),
            "0.75.0",
            material=(ArtifactSelection("db/trivy.db", material),),
        )

    assert not (root / "too-large").exists(), "Combined overflow copied material before denial"


def test_ChangingSourceDuringStreamingCannotProduceSnapshot(selected):
    """An owned concurrent file mutation is detected after the exact selected read."""

    _, source, _ = selected

    class MutatingDestination:
        """Replace only this fixture's source while its read is active."""

        def Write(self, chunk):
            """Mutate the owned source at the bounded-copy callback boundary."""

            source.write_bytes(b"owned-mutation")

        write = Write

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar", MutatingDestination())


def test_SnapshotPhysicalReplacementAndUnexpectedDirectoryAreDenied(selected):
    """Observed partition replacement cannot keep a prior physical lease."""

    stage = Stage(selected)

    with pytest.raises(ValueError):
        replace(stage.input, directory_identity=(-1, -1)).Verify()

    with pytest.raises(ValueError):
        replace(stage, root_identity=(-1, -1)).Verify()


def test_LinkAndReparseObservationsFailBeforeReading(selected, monkeypatch):
    """Non-following metadata guards reject both portable observed link forms."""

    from types import SimpleNamespace

    _, source, _ = selected
    original = Path.lstat

    for metadata in (
        SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0),
        SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400),
    ):

        def Metadata(path, *, _observed=metadata):
            """Expose only the owned selected path as linked metadata."""

            return _observed if path == source else original(path)

        monkeypatch.setattr(Path, "lstat", Metadata)

        with pytest.raises(ValueError):
            inputs.ReadArtifactFile(source, "image.tar")


def test_InventoryRejectsOversizedClosedWorldAndUnsafePaths(selected, monkeypatch):
    """Owned enumeration stops at finite file counts and rejects unsafe path types."""

    root, _, _ = selected
    partition = root / "inventory"
    partition.mkdir()
    (partition / "a").write_bytes(b"owned")
    (partition / "b").write_bytes(b"owned")
    monkeypatch.setattr(inputs, "MAX_ARTIFACT_FILES", 1)

    with pytest.raises(ValueError):
        inputs.ArtifactInventory(partition)

    for path in (Path("relative"), root / "absent", root / "inventory/../inventory"):
        with pytest.raises(ValueError):
            inputs.ArtifactPathInfo(path)


def test_ScratchAggregateOverflowRejectedBeforeReadingScratchBytes(selected, monkeypatch):
    """Post-run observation remains bounded even when the owned scratch exceeded its quota."""

    root, source, consent = selected
    source.write_bytes(b"x")
    executable = root / "owned-executable"
    executable.write_bytes(b"xxxx")
    stage = ArtifactStage.Create(
        root / "small-stage",
        ArtifactProfile.IMAGE,
        consent,
        (ArtifactSelection("image.tar", source),),
        ArtifactSelection("executable", executable),
        "0.75.0",
    )
    (stage.root / "scratch/a").write_bytes(b"x" * 10)
    (stage.root / "scratch/b").write_bytes(b"x" * 10)
    monkeypatch.setattr(inputs, "MAX_ARTIFACT_TOTAL_BYTES", 16)
    actual_read = inputs.ReadArtifactFile
    scratch_reads = []

    def Read(path, name, *args, **options):
        """Observe only whether the bounded checker reads this owned oversized scratch."""

        if path.parent == stage.root / "scratch":
            scratch_reads.append(path)

        return actual_read(path, name, *args, **options)

    monkeypatch.setattr(inputs, "ReadArtifactFile", Read)

    with pytest.raises(ValueError):
        stage.Verify(after_run=True)

    assert not scratch_reads, "Oversized scratch was fully read before aggregate denial"


def test_UnboundedIteratorsAreRejectedWithoutConsumption(selected):
    """A typed finite-list boundary does not consume arbitrary caller generators."""

    root, source, consent = selected

    def Unsupported():
        """Fail if a bounded constructor tries to expand an untrusted iterator."""

        raise AssertionError("Unbounded iterable must never be consumed")
        yield ArtifactSelection("image.tar", source)

    with pytest.raises(ValueError):
        ArtifactSnapshot.Capture(
            root / "invalid", ArtifactProfile.IMAGE, ArtifactRole.INPUT, Unsupported(), consent
        )

    with pytest.raises(ValueError):
        ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT, Unsupported())

    assert not (root / "invalid").exists(), "Invalid sequence triggered filesystem capture"


def test_CapturedObservationRecordsFreezeCallerCollections(selected):
    """Frozen snapshot/stage records never retain mutable caller identity-list aliases."""

    stage = Stage(selected)
    observations = [[name, list(identity)] for name, identity in stage.input.identities]
    directory = list(stage.input.directory_identity)
    snapshot = replace(stage.input, identities=observations, directory_identity=directory)
    observations[0][1][0] = -1
    directory[0] = -1

    assert snapshot.identities == stage.input.identities, "Caller changed snapshot observations"
    assert snapshot.directory_identity == stage.input.directory_identity, (
        "Caller changed partition ID"
    )
    snapshot.Verify()


def ObservedInfo(info, **changes):
    """Copy only actual observed metadata fields into a finite owned test observation."""

    fields = {
        name: getattr(info, name)
        for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink"
        )
    }
    fields.update(changes)

    return SimpleNamespace(**fields)


@pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows"])
def test_CtimeViewDifferenceIsLimitedToWindowsAndStillHashesExactBytes(
    selected, monkeypatch, windows
):
    """Creation versus change-time semantics do not remove original-path or same-method checks."""

    _, source, _ = selected
    actual_handle = inputs.ArtifactHandleInfo

    def Handle(descriptor):
        """Expose only the documented creation/change-time API discrepancy."""

        info = actual_handle(descriptor)

        return ObservedInfo(info, st_ctime_ns=info.st_ctime_ns + 1)

    monkeypatch.setattr(inputs, "_WINDOWS_STAT_VIEWS", windows)
    monkeypatch.setattr(inputs, "ArtifactHandleInfo", Handle)

    if windows:
        record = inputs.ReadArtifactFile(source, "image.tar")

        assert record.sha256 == hashlib.sha256(source.read_bytes()).hexdigest(), (
            "Wrong bytes accepted"
        )

    else:
        with pytest.raises(ValueError):
            inputs.ReadArtifactFile(source, "image.tar")


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns"])
def test_CommonOriginalPathIdentityCannotBeNormalizedAway(selected, monkeypatch, field):
    """Different device/inode/content observations refuse even in the Windows ctime branch."""

    _, source, _ = selected
    actual_handle = inputs.ArtifactHandleInfo

    def Handle(descriptor):
        """Alter exactly one otherwise valid opened-file observation."""

        info = actual_handle(descriptor)

        return ObservedInfo(info, **{field: getattr(info, field) + 1})

    monkeypatch.setattr(inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(inputs, "ArtifactHandleInfo", Handle)
    destination = io.BytesIO()

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar", destination)

    assert not destination.getvalue(), "Unbound original file bytes were copied"


@pytest.mark.parametrize("which", ["both", "witness"])
def test_WrongHandlesCannotRelabelOriginalPathAndAllDescriptorsClose(selected, monkeypatch, which):
    """A path observing A cannot accept handles for B, even when both handles agree on B."""

    root, source, _ = selected
    other = root / "other"
    other.write_bytes(b"b" * len(source.read_bytes()))
    source_info = source.stat()
    os.utime(other, ns=(source_info.st_atime_ns, source_info.st_mtime_ns))
    actual_open = os.open
    opened = []

    def Open(path, *args, **options):
        """Expose owned B during selected opens while all guarded path observations remain A."""

        selected_path = path

        if path == source:
            if which == "both" or opened:
                selected_path = other

            descriptor = actual_open(selected_path, *args, **options)
            opened.append(descriptor)

            return descriptor

        return actual_open(path, *args, **options)

    monkeypatch.setattr(inputs.os, "open", Open)
    monkeypatch.setattr(inputs, "_WINDOWS_STAT_VIEWS", True)
    destination = io.BytesIO()

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar", destination)

    assert not destination.getvalue(), "Agreeing wrong handles replaced the original selected file"
    assert source.read_bytes() == b"owned-selected-archive", "The original owned path changed"

    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_FullHandleMutationChecksRemainActiveAcrossWindowsViews(selected, monkeypatch, field):
    """Every handle identity field remains checked after actual bounded bytes are read."""

    _, source, _ = selected
    actual_handle = inputs.ArtifactHandleInfo
    changed = False

    def Handle(descriptor):
        """Expose a handle-only change after the owned copy callback."""

        info = actual_handle(descriptor)

        return ObservedInfo(info, **({field: getattr(info, field) + 1} if changed else {}))

    class Destination:
        """Advance only owned simulated metadata after one bounded copied chunk."""

        def Write(self, chunk):
            """Retain read progress without mutating any unrelated path."""

            nonlocal changed
            changed = True

        write = Write

    monkeypatch.setattr(inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(inputs, "ArtifactHandleInfo", Handle)

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar", Destination())

    assert changed, "The handle after-read boundary was not exercised"


@pytest.mark.parametrize("phase", [2, 3, 4], ids=["first-open", "witness-open", "after-read"])
def test_FullPathMetadataRemainsCheckedAtEveryReadBoundary(selected, monkeypatch, phase):
    """Original path change-time stays checked within its own API at all three boundaries."""

    _, source, _ = selected
    actual_path = inputs.ArtifactPathInfo
    calls = 0

    def Info(path, **options):
        """Change only this selected path's own metadata at one deterministic boundary."""

        nonlocal calls
        info = actual_path(path, **options)

        if path == source:
            calls += 1

            if calls == phase:
                return ObservedInfo(info, st_ctime_ns=info.st_ctime_ns + 1)

        return info

    monkeypatch.setattr(inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(inputs, "ArtifactPathInfo", Info)

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar")

    assert calls == phase, "The selected path's requested boundary was not reached"


@pytest.mark.parametrize("mutation", ["type", "links", "zero-id", "reparse", "reparse-tag"])
def test_OpenedHandleMustRetainRegularUniqueNonReparseIdentity(selected, monkeypatch, mutation):
    """A path's earlier validation cannot validate unsafe or unavailable opened-handle metadata."""

    _, source, _ = selected
    actual_fstat = os.fstat

    with source.open("rb") as stream:
        descriptor = stream.fileno()
        info = actual_fstat(descriptor)
        changes = {
            "type": {"st_mode": stat.S_IFIFO},
            "links": {"st_nlink": 2},
            "zero-id": {"st_ino": 0},
            "reparse": {"st_file_attributes": 0x400},
            "reparse-tag": {"st_reparse_tag": 1},
        }[mutation]

        def Fstat(selected_descriptor):
            """Expose an unsafe observation for only this explicit owned handle."""

            if selected_descriptor == descriptor:
                return ObservedInfo(info, **changes)

            return actual_fstat(selected_descriptor)

        monkeypatch.setattr(inputs.os, "fstat", Fstat)

        with pytest.raises(ValueError):
            inputs.ArtifactHandleInfo(descriptor)


def test_ActualOpenedFileBoundIsCheckedBeforeAnyCopy(selected, monkeypatch):
    """A stale smaller path observation cannot defer an excessive actual-handle bound to reading."""

    _, source, _ = selected
    actual_handle = inputs.ArtifactHandleInfo

    def Handle(descriptor):
        """Expose only a larger actual opened-file length."""

        return ObservedInfo(actual_handle(descriptor), st_size=inputs.MAX_ARTIFACT_FILE_BYTES + 1)

    monkeypatch.setattr(inputs, "ArtifactHandleInfo", Handle)
    destination = io.BytesIO()

    with pytest.raises(ValueError):
        inputs.ReadArtifactFile(source, "image.tar", destination)

    assert not destination.getvalue(), "An oversized opened file reached the snapshot stream"
