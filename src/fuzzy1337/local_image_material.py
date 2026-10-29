# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal exact-owner observations for explicitly selected Docker bytes and Unix socket."""

from __future__ import annotations

import stat
import sys
from dataclasses import dataclass

from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity
from fuzzy1337.executors.contracts import RequireReference
from fuzzy1337.local_image_reference import LocalImageSelection
from fuzzy1337.native_image_capture import NativeFileFact, SelectedFile
from fuzzy1337.workspace import LocalWorkspaceStore

MAX_DOCKER_EXECUTABLE_BYTES = 64 * 1024 * 1024


def SocketIdentity(selection: LocalImageSelection) -> tuple[int, int, int, int, int, int]:
    """Observe the selected physical Unix socket without reading it or contacting a daemon.

    Args:
        selection: Exact declared endpoint; parent aliases and a non-socket leaf refuse.

    Returns:
        Original device, inode, mode, owner, group and change-time observations.

    Raises:
        ValueError: The selected endpoint lacks supported Linux socket identity.
        OSError: Its explicit physical path cannot be inspected.
    """

    if sys.platform != "linux":
        raise ValueError("local image material requires Linux socket ownership")

    ArtifactPathInfo(selection.socket_path.parent, directory=True)
    info = selection.socket_path.lstat()

    if not stat.S_ISSOCK(info.st_mode) or info.st_ino == 0:
        raise ValueError("local image endpoint must be an explicit physical Unix socket")

    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_ctime_ns


@dataclass(frozen=True, slots=True, eq=False)
class LocalImageMaterialProof:
    """Original issued observations; a value-equivalent reconstruction supplies no authority."""

    executable: NativeFileFact
    socket_identity: tuple[int, int, int, int, int, int]
    workspace_identity: tuple[int, int]
    workspace_id: str
    owner_reference: str
    operation_reference: str


class LocalImageMaterialObserver:
    """Bind selected reads to one original issuer and operation without launching a process.

    Args:
        selection: Explicit trusted Docker, Unix socket and owning workspace declarations.
        owner_reference: Executing actor matching the independently supplied read consent.
        operation_reference: Exact whole-export correlation identity, never a grant.
    """

    def __init__(self, selection: LocalImageSelection, owner_reference: str,
                 operation_reference: str) -> None:
        """Validate pure declarations and retain no proof before an actual observation."""

        if type(selection) is not LocalImageSelection or (
            selection.read_consent.actor_ref != owner_reference
        ):
            raise ValueError("local image material requires its exact selected read-consent actor")

        RequireReference(owner_reference, "local image owner")
        RequireReference(operation_reference, "local image operation")
        self.selection = selection
        self.owner_reference = owner_reference
        self.operation_reference = operation_reference
        self._issued: list[LocalImageMaterialProof] = []

    def Observe(self) -> LocalImageMaterialProof:
        """Read only the declared executable under a byte ceiling and observe its exact endpoint.

        Returns:
            An issuer-retained original proof after full before/open/after file checks.

        Raises:
            ValueError: Platform, ownership, executable or selected physical identities refuse.
            OSError: Explicit material cannot be read or inspected safely.

        These bounded local filesystem reads have soft timing; they establish no
        hostile-writer exclusion or real-time deadline and contact no daemon.
        """

        socket_identity = SocketIdentity(self.selection)
        root = ArtifactPathInfo(self.selection.workspace_root, directory=True)
        workspace = LocalWorkspaceStore(self.selection.workspace_root).Open()
        info = ArtifactPathInfo(self.selection.executable)

        if not info.st_mode & 0o111 or not 0 < info.st_size <= MAX_DOCKER_EXECUTABLE_BYTES:
            raise ValueError("local image Docker executable must be bounded and executable")

        executable = SelectedFile(self.selection.executable, "docker-executable",
                                  MAX_DOCKER_EXECUTABLE_BYTES)
        proof = LocalImageMaterialProof(executable, socket_identity, (root.st_dev, root.st_ino),
            workspace.workspace_id, self.owner_reference, self.operation_reference)
        self._issued.append(proof)
        self.CheckCurrent(proof)

        return proof

    def CheckCurrent(self, proof: LocalImageMaterialProof) -> None:
        """Recheck original proof identity and cheap selected metadata without rehashing a binary.

        Args:
            proof: Exact object previously issued by this observer for this operation.

        Raises:
            ValueError: A reconstructed, changed, unrelated or stale material proof refuses.
            OSError: Current explicit selected material cannot be safely inspected.
        """

        if type(proof) is not LocalImageMaterialProof or not any(
            issued is proof for issued in self._issued
        ):
            raise ValueError("local image material requires its original issuer-owned proof")

        root = ArtifactPathInfo(self.selection.workspace_root, directory=True)
        workspace = LocalWorkspaceStore(self.selection.workspace_root).Open()
        executable = ArtifactPathInfo(self.selection.executable)

        if proof.owner_reference != self.owner_reference or (
            proof.operation_reference != self.operation_reference
            or self.selection.read_consent.actor_ref != self.owner_reference
            or proof.workspace_id != workspace.workspace_id
            or proof.workspace_identity != (root.st_dev, root.st_ino)
            or proof.socket_identity != SocketIdentity(self.selection)
            or proof.executable.path != str(self.selection.executable)
            or proof.executable.physical_identity != PhysicalIdentity(executable)
            or not executable.st_mode & 0o111
        ):
            raise ValueError("local image selected material or owner identity changed")
