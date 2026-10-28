# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Configuration material mechanics with tiny deterministic files, not native product proof."""

from __future__ import annotations

import hashlib
import io
import json
import os
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import native_configuration_material_worker as worker
from fuzzy1337.artifact_inputs import (
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactSnapshot,
    ArtifactStage,
    PhysicalIdentity,
)
from fuzzy1337.native_configuration import NativeConfigurationSelection


@pytest.fixture
def owned_material(tmp_path, monkeypatch):
    """Use a tiny explicit pin double for worker mechanics, never native admission."""

    source = tmp_path / "source"
    source.write_bytes(b"FROM scratch\nUSER 12345\n# independent ordinary source\n")
    executable = tmp_path / "selected-tool"
    executable.write_bytes(b"inert test bytes; this file must never execute\n")
    monkeypatch.setattr(worker, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256",
                        hashlib.sha256(executable.read_bytes()).hexdigest())

    return NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile", source,
        executable, ArtifactReadConsent("owner:mechanics", "read:tiny-files"))


def StageRoot(tmp_path):
    """Return an absent fixed-shape test stage beneath the explicit owned workspace."""

    return tmp_path / ("native-configuration-stage-" + "a" * 32)


def Control(tmp_path, selection, action="create", stage=None):
    """Create exact private metadata without issuing observer material proof."""

    directory = tmp_path / ("native-configuration-read-" + "b" * 32)
    directory.mkdir(mode=0o700)
    directory_identity = directory.stat()
    workspace_identity = tmp_path.stat()

    return directory, {"schema_version": 1, "action": action, "nonce": "c" * 32,
        "operation_reference": "operation:material", "workspace_id": "workspace:material",
        "owner_reference": selection.read_consent.actor_ref, "workspace_root": str(tmp_path),
        "workspace_identity": [workspace_identity.st_dev, workspace_identity.st_ino],
        "directory_identity": [directory_identity.st_dev, directory_identity.st_ino],
        "selection": worker.SelectionPayload(selection), "stage_root": str(StageRoot(tmp_path)),
        "stage": stage}


def test_SnapshotCompositionPassesActualRoleAdmissionLimits(tmp_path, owned_material, monkeypatch):
    """The limits reach streaming Capture rather than depending on a prior metadata check."""

    captures = []
    original_capture = ArtifactSnapshot.Capture

    def Capture(*args, **kwargs):
        """Observe the real bounded capture API while preserving actual guarded file copying."""

        captures.append((args[2], kwargs.get("max_total_bytes")))

        return original_capture(*args, **kwargs)

    def Forbidden(*args, **kwargs):
        """Reject accidental calls to the globally bounded stage or snapshot verifier."""

        pytest.fail("Configuration material must compose only explicitly bounded primitive reads")

    monkeypatch.setattr(ArtifactSnapshot, "Capture", Capture)
    monkeypatch.setattr(ArtifactStage, "Create", Forbidden)
    monkeypatch.setattr(ArtifactStage, "Verify", Forbidden)
    monkeypatch.setattr(ArtifactSnapshot, "Verify", Forbidden)
    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    assert captures == [(ArtifactRole.INPUT, 4096), (ArtifactRole.SCANNER, 256 * 1024**2),
                        (ArtifactRole.MATERIAL, 0)], (
        "Every copied role must receive its actual configuration streaming admission budget"
    )
    assert stage.input.manifest.files[0].sha256 == hashlib.sha256(
        owned_material.source.read_bytes()).hexdigest(), (
        "The manifest must describe the exact chunks copied into the staged source"
    )


def test_VerificationNeverReopensOriginalSource(tmp_path, owned_material, monkeypatch):
    """After snapshot capture only staged source bytes and both executable locations are read."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    owned_material.source.unlink()
    reads = []
    original_read = worker.ReadArtifactFile

    def Read(path, name, destination=None, *, max_bytes):
        """Retain each real bounded read and reject any original-source reopen."""

        assert path != owned_material.source, "Captured original source must never be reopened"
        reads.append((path, max_bytes))

        return original_read(path, name, destination, max_bytes=max_bytes)

    monkeypatch.setattr(worker, "ReadArtifactFile", Read)
    worker.VerifyStage(stage, owned_material)
    assert reads == [(stage.input.directory / "Dockerfile", 4096),
        (stage.scanner.directory / "executable", 256 * 1024**2),
        (owned_material.executable, 256 * 1024**2)], (
        "Verification must preserve explicit source/scanner admission limits at every read"
    )


def test_SourceUtf8ComesFromTheSameVerifiedCappedBytes(tmp_path, owned_material, monkeypatch):
    """Malformed copied UTF-8 refuses without a second source read after hash verification."""

    owned_material.source.write_bytes(b"\xff")

    def Forbidden(*args, **kwargs):
        """Refuse a convenience read that would bypass bounded guarded verifier bytes."""

        pytest.fail("UTF-8 must decode only the exact bounded verifier-returned bytes")

    monkeypatch.setattr(Path, "read_bytes", Forbidden)

    with pytest.raises(UnicodeDecodeError):
        worker.CreateStage(StageRoot(tmp_path), owned_material)


@pytest.mark.parametrize("mutation", ["source", "copy", "executable", "extra", "scratch"])
def test_ChangedOrExpandedMaterialRefuses(tmp_path, owned_material, mutation):
    """Physical replacement, changed selected bytes and unselected files cannot retain proof."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)

    if mutation == "source":
        target = stage.input.directory / "Dockerfile"

    elif mutation == "copy":
        target = stage.scanner.directory / "executable"

    elif mutation == "executable":
        target = owned_material.executable

    else:
        target = stage.root / ("scratch" if mutation == "scratch" else "material") / "unknown"

    if target.exists():
        target.chmod(0o600)

    target.write_bytes(b"different")

    with pytest.raises(ValueError):
        worker.VerifyStage(stage, owned_material)


def test_InitialSourceCapAndSupportedScannerPinAreEnforced(tmp_path, owned_material):
    """Oversized source and a different candidate both refuse before a usable stage exists."""

    owned_material.source.write_bytes(b"x" * 4097)

    with pytest.raises(ValueError):
        worker.CreateStage(StageRoot(tmp_path), owned_material)

    owned_material.source.write_bytes(b"FROM scratch\n")
    owned_material.executable.write_bytes(b"not the admitted candidate")

    with pytest.raises(ValueError):
        worker.CreateStage(tmp_path / ("native-configuration-stage-" + "d" * 32), owned_material)


def test_StageWireRoundtripPreservesExactPhysicalAndManifestFacts(tmp_path, owned_material):
    """Detached stage syntax reconstructs descriptive facts without issuing observer proof."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    detached = json.loads(worker.CanonicalControl(worker.StagePayload(stage)))
    restored = worker.StageFromPayload(detached, owned_material, stage.root)
    assert restored == stage, "The private stage roundtrip must retain exact original associations"
    worker.VerifyStage(restored, owned_material)

    with pytest.raises(ValueError):
        worker.StageFromPayload({**detached, "unexpected": True}, owned_material, stage.root)

    detached["partitions"]["input"]["manifest"]["role"] = "scanner"

    with pytest.raises(ValueError):
        worker.StageFromPayload(detached, owned_material, stage.root)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1} ',
                                 b" " * 65537, b"[]", b"\xff"])
def test_PrivateControlRequiresStrictBoundedCanonicalJson(raw):
    """Duplicate, nonfinite, malformed or noncanonical control cannot describe selected reads."""

    with pytest.raises(ValueError):
        worker.ParseControl(raw)


def test_PrivateRequestBindsOriginalPathDigestIdentityAndParents(tmp_path, owned_material):
    """The child reads only the original exclusive owner request beneath its exact workspace."""

    directory, control = Control(tmp_path, owned_material)
    raw = worker.CanonicalControl(control)
    path = directory / "request.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    digest = hashlib.sha256(raw).hexdigest()
    identity = PhysicalIdentity(path.stat())
    assert worker.ReadControl(path, digest, identity) == control, (
        "The exact private request must retain its original hash and physical parent binding"
    )

    with pytest.raises(ValueError):
        worker.ReadControl(path, "0" * 64, identity)

    path.chmod(0o644)

    with pytest.raises(ValueError):
        worker.ReadControl(path, digest, PhysicalIdentity(path.stat()))


def test_ActualOverlimitReadChunkIsRefusedBeforeHashOrCopy(tmp_path, monkeypatch):
    """A concurrent-growth double can read one 64-KiB chunk, but none is admitted past 4 KiB."""

    source = tmp_path / "growing"
    source.write_bytes(b"x")
    original_fdopen = os.fdopen
    opened = 0
    requested = []

    def Read(maximum):
        """Supply one bounded overlimit buffer after real descriptor metadata checks."""

        requested.append(maximum)

        return b"x" * maximum

    def Open(*args, **kwargs):
        """Replace only the selected read stream, retaining the independent witness handle."""

        nonlocal opened
        stream = original_fdopen(*args, **kwargs)
        opened += 1

        if opened != 1:
            return stream

        simulated = MagicMock()
        simulated.__enter__.return_value = simulated
        simulated.__exit__.side_effect = lambda *unused: stream.close()
        simulated.fileno.side_effect = stream.fileno
        simulated.read.side_effect = Read

        return simulated

    monkeypatch.setattr(artifact_inputs.os, "fdopen", Open)
    destination = io.BytesIO()

    with pytest.raises(ValueError, match="grew beyond"):
        artifact_inputs.ReadArtifactFile(source, "source", destination, max_bytes=4096)

    assert requested == [64 * 1024] and destination.getvalue() == b"", (
        "One bounded overlimit read may occur, but those bytes must not be copied or admitted"
    )


def test_StagePayloadCannotBroadenManifestSizeWithoutPhysicalAgreement(tmp_path, owned_material):
    """A typed descriptive stage cannot bypass the admitted input and scanner bounds."""

    stage = worker.CreateStage(StageRoot(tmp_path), owned_material)
    file = replace(stage.input.manifest.files[0], size_bytes=4097)
    snapshot = replace(stage.input, manifest=replace(stage.input.manifest, files=(file,)))

    with pytest.raises(ValueError):
        worker.CheckStageMetadata(replace(stage, input=snapshot), owned_material)
