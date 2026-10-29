# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Selected Docker metadata proofs over real inert bytes and a labeled Unix-socket mode view."""

import hashlib
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import local_image_material as material
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.local_image_material import LocalImageMaterialObserver
from fuzzy1337.local_image_reference import LocalImageSelection
from fuzzy1337.scan_commands import CreateWorkspace

LINUX = pytest.mark.skipif(sys.platform != "linux", reason="Owned Unix socket proof requires Linux")


@pytest.fixture(name="selected_material")
def SelectedMaterial(tmp_path, monkeypatch):
    """Own inert bytes and model only the selected leaf's Unix-socket kind without networking.

    Args:
        tmp_path: Isolated pytest root; no Docker or external endpoint is contacted.
        monkeypatch: Restore the exact selected-leaf synthetic metadata after this test.

    Returns:
        Typed selection, observer and explicit socket-mode view with real inode/change time.
    """

    root = tmp_path / "workspace"
    CreateWorkspace(root, "local-image-material", "Owned selected material")
    executable = tmp_path / "selected-docker"
    executable.write_bytes(b"inert selected bytes; never executed")
    executable.chmod(0o700)
    endpoint = tmp_path / "docker.sock"
    endpoint.write_bytes(b"inert selected socket metadata; no socket is opened")
    original = Path.lstat

    def Lstat(path):
        """Project only the selected ordinary leaf's kind while retaining its other real facts."""

        observed = original(path)

        if path == endpoint and stat.S_ISREG(observed.st_mode):
            return SimpleNamespace(st_mode=stat.S_IFSOCK | stat.S_IMODE(observed.st_mode),
                st_dev=observed.st_dev, st_ino=observed.st_ino, st_uid=observed.st_uid,
                st_gid=observed.st_gid, st_ctime_ns=observed.st_ctime_ns)

        return observed

    monkeypatch.setattr(Path, "lstat", Lstat)
    selection = LocalImageSelection(root, "owned:local", executable,
        ArtifactReadConsent("actor:local", "read:local"), endpoint)
    observer = LocalImageMaterialObserver(selection, "actor:local", "operation:local")

    return selection, observer, original


@LINUX
def test_SelectedFileBytesAndLabeledSocketViewRemainIndependent(selected_material):
    """Real file bytes and inode facts remain distinct from the explicitly synthetic socket kind."""

    selection, observer, _ = selected_material
    proof = observer.Observe()
    assert proof.executable.sha256 == (
        hashlib.sha256(selection.executable.read_bytes()).hexdigest()
    ), (
        "Original selected Docker bytes must retain their actual independent SHA-256."
    )
    assert proof.socket_identity[1] == selection.socket_path.lstat().st_ino, (
        "The exact selected socket inode must remain separate from executable byte identity."
    )
    observer.CheckCurrent(proof)


@LINUX
def test_UnselectedOrdinaryEndpointStillFailsTheRealSocketGuard(selected_material):
    """The fixture cannot turn another ordinary file into a supported local socket endpoint."""

    selection, _, _ = selected_material
    endpoint = selection.socket_path.with_name("ordinary-file")
    endpoint.write_bytes(b"not a Unix socket")
    other = replace(selection, socket_path=endpoint)

    with pytest.raises(ValueError, match="physical Unix socket"):
        material.SocketIdentity(other)

    assert stat.S_ISREG(os.lstat(endpoint).st_mode), (
        "The negative endpoint must remain an actual ordinary file, not modeled socket metadata."
    )


@LINUX
def test_ReconstructedProofCannotBorrowTheOriginalIssuer(selected_material):
    """Value-equivalent dataclass construction never revives an original issued material proof."""

    _, observer, _ = selected_material
    proof = observer.Observe()

    with pytest.raises(ValueError, match="original issuer-owned"):
        observer.CheckCurrent(replace(proof))


@LINUX
@pytest.mark.parametrize("fault", ["binary", "socket", "nonexecutable"])
def test_SelectedMaterialMutationRefusesCurrentProof(selected_material, fault):
    """Cheap final checks reject changed bytes/permissions and a replacement socket identity."""

    selection, observer, _ = selected_material
    proof = observer.Observe()

    if fault == "binary":
        selection.executable.write_bytes(b"changed inert selected bytes")

    elif fault == "nonexecutable":
        selection.executable.chmod(0o600)

    else:
        selection.socket_path.unlink()
        selection.socket_path.write_bytes(b"not the original Unix socket")

    with pytest.raises(ValueError):
        observer.CheckCurrent(proof)


@LINUX
def test_IndependentObserverCannotAcceptAnotherOriginalProof(selected_material):
    """A matching selection and operation do not establish original observer object identity."""

    selection, observer, _ = selected_material
    proof = observer.Observe()
    other = LocalImageMaterialObserver(selection, "actor:local", "operation:local")

    with pytest.raises(ValueError, match="original issuer-owned"):
        other.CheckCurrent(proof)


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_UnsupportedMaterialObservationRefusesBeforeAnySelectedPathRead(
    tmp_path, monkeypatch, platform,
):
    """The Linux-only metadata profile cannot become an implicit alternate runtime."""

    selection = LocalImageSelection(tmp_path / "absent", "owned:local", tmp_path / "absent-docker",
        ArtifactReadConsent("actor:local", "read:local"), tmp_path / "absent.sock")
    observer = LocalImageMaterialObserver(selection, "actor:local", "operation:local")
    monkeypatch.setattr(material, "sys", SimpleNamespace(platform=platform))

    with pytest.raises(ValueError, match="requires Linux"):
        observer.Observe()

    assert list(tmp_path.iterdir()) == [], (
        "Unsupported observation must refuse without creating or reading a selected material path."
    )


def test_ChangedReadConsentActorRefusesBeforeMaterialReads(tmp_path):
    """A reference declaration never substitutes for the explicitly executing read actor."""

    selection = LocalImageSelection(tmp_path / "absent", "owned:local", tmp_path / "absent-docker",
        ArtifactReadConsent("actor:other", "read:local"), tmp_path / "absent.sock")

    with pytest.raises(ValueError, match="read-consent actor"):
        LocalImageMaterialObserver(selection, "actor:local", "operation:local")

    assert list(tmp_path.iterdir()) == [], "Rejected read ownership must create no material state."
