# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit local Docker reference declarations and fixed read-only recipes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.executors import CapabilityDescriptor, ExecutionResources
from fuzzy1337.policy import Digest
from fuzzy1337.scope import Target, TargetKind

LOCAL_IMAGE_SOURCE = "native.docker-local"
LOCAL_IMAGE_PROFILE = "docker-local-reference.v1"
LOCAL_IMAGE_CAPABILITY = CapabilityDescriptor(
    "image.local-reference-export", LOCAL_IMAGE_SOURCE, ImpactLevel.SAFE,
    required_privileges=("local-docker-read",))
LOCAL_IMAGE_ARCHIVE_BYTES = 64 * 1024 * 1024
LOCAL_IMAGE_INSPECT_BYTES = 1024 * 1024
LOCAL_IMAGE_STDERR_BYTES = 64 * 1024
DEFAULT_DOCKER_SOCKET = Path("/run/docker.sock")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_NAME_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def ImageConfigId(value: str) -> str:
    """Require the full selected Docker config identity, never a tag or shortened ID.

    Args:
        value: Explicit algorithm-prefixed lowercase SHA-256 config identity.

    Returns:
        The unchanged complete config identity.

    Raises:
        ValueError: The input has no exact full config-ID representation.
    """

    if type(value) is not str or _IMAGE_ID.fullmatch(value) is None:
        raise ValueError("local image requires an exact SHA-256 config identity")

    return value


def LocalImageReference(value: str) -> str:
    """Validate an unchanged local repository/tag or full config ID without resolving it.

    Args:
        value: Exact local reference with an explicit tag, or full SHA-256 image ID.

    Returns:
        Unchanged bounded reference; no implicit latest tag or registry contact.

    Raises:
        ValueError: The reference is ambiguous, malformed or unsupported.
    """

    if type(value) is not str or not 1 <= len(value) <= 255:
        raise ValueError("local image reference must be bounded text")

    if value.startswith("sha256:"):
        return ImageConfigId(value)

    name, separator, tag = value.rpartition(":")

    if not separator or _TAG.fullmatch(tag) is None or "@" in name:
        raise ValueError("local image name requires an explicit supported tag")

    components = name.split("/")

    if ":" in components[0]:
        domain, _, port = components[0].rpartition(":")

        if len(components) < 2 or not port.isascii() or not port.isdigit() or (
            not 1 <= int(port) <= 65535
        ):
            raise ValueError("local image reference has an invalid registry-name port")

        components[0] = domain

    if any(_NAME_COMPONENT.fullmatch(component) is None for component in components):
        raise ValueError("local image reference has an invalid name component")

    return value


def SelectedPath(path: Path) -> None:
    """Validate explicit local path syntax without resolving links or reading the filesystem.

    Args:
        path: Absolute selected workspace, trusted executable or Unix-socket path.

    Raises:
        ValueError: The path is relative, traversing, oversized or contains controls.
    """

    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts or (
        len(str(path)) > 4096 or any(ord(character) < 32 or ord(character) == 127
                                  for character in str(path))
    ):
        raise ValueError("local image requires explicit absolute path syntax")


class LocalImageOperation(StrEnum):
    """Closed read-only Docker operations; the export always selects an immutable ID."""

    INSPECT = "inspect"
    EXPORT = "export"
    RECHECK = "recheck"


@dataclass(frozen=True, slots=True)
class LocalImageSelection:
    """Explicit owning workspace, reference, trusted Docker and local endpoint; no reads."""

    workspace_root: Path
    reference: str
    executable: Path
    read_consent: ArtifactReadConsent
    socket_path: Path = DEFAULT_DOCKER_SOCKET

    def __post_init__(self) -> None:
        """Reject malformed declarations before filesystem reads or Docker discovery."""

        for path in (self.workspace_root, self.executable, self.socket_path):
            SelectedPath(path)

        LocalImageReference(self.reference)

        if type(self.read_consent) is not ArtifactReadConsent or (
            len({self.workspace_root, self.executable, self.socket_path}) != 3
        ):
            raise ValueError("local image requires distinct selections and explicit read consent")

    def Manifest(self) -> dict[str, object]:
        """Describe this source reference independently of future archive or image bytes.

        Returns:
            Closed schema-one source descriptor, not an archive ArtifactManifest.
        """

        return {"schema_version": 1, "profile": LOCAL_IMAGE_PROFILE,
                "reference": self.reference, "docker_executable": str(self.executable),
                "endpoint": "unix://" + str(self.socket_path)}

    def Target(self) -> Target:
        """Return only the source-descriptor scope target, without registering permission.

        Returns:
            Existing ARTIFACT-kind identity for canonical descriptor bytes.
        """

        return Target(TargetKind.ARTIFACT, "manifest-sha256:" + Digest(self.Manifest()))


def PrepareLocalImageInvocation(selection: LocalImageSelection, operation: LocalImageOperation,
                                config_directory: Path, *, image_id: str | None = None,
) -> AdapterInvocation:
    """Describe a fixed local inspect/save recipe without proving material or granting launch.

    Args:
        selection: Explicit exact reference, endpoint, executable and owning workspace.
        operation: Closed inspect, immutable export or reference recheck.
        config_directory: Explicit private config path beneath the owning workspace.
        image_id: Required only for export, from later verified original inspect.

    Returns:
        Exact descriptive invocation with fixed bounds and no inherited Docker context.

    Raises:
        ValueError: Operation, output selection or immutable export identity is unsupported.
    """

    if type(selection) is not LocalImageSelection or type(operation) is not LocalImageOperation:
        raise ValueError("local image recipe requires exact selection and operation types")

    SelectedPath(config_directory)

    if not config_directory.is_relative_to(selection.workspace_root) or (
        config_directory == selection.workspace_root
    ):
        raise ValueError("local image config must be beneath its owning workspace")

    suffix: tuple[str, ...]

    if operation is LocalImageOperation.EXPORT:
        argument = ImageConfigId(image_id) if image_id is not None else ImageConfigId("")
        suffix = ("image", "save", argument)

    else:
        if image_id is not None:
            raise ValueError("local image inspect cannot substitute an export config ID")

        suffix = ("image", "inspect", "--format", "{{json .}}", selection.reference)

    request = AdapterRequest(LOCAL_IMAGE_CAPABILITY.identifier, selection.Target().Reference(),
        ImpactLevel.SAFE, {"operation": operation.value, "reference": selection.reference,
                          "image_id": image_id})
    argv = (str(selection.executable), "--host", "unix://" + str(selection.socket_path),
            "--config", str(config_directory), *suffix)

    return AdapterInvocation(LOCAL_IMAGE_SOURCE, request, argv,
                             timeout_seconds=30 if operation is LocalImageOperation.EXPORT else 10)


def LocalImageResources(operation: LocalImageOperation) -> ExecutionResources:
    """Keep exported bytes under stdout limits rather than unbounded daemon-written files.

    Args:
        operation: Exact closed Docker read operation.

    Returns:
        Fixed output bounds; these are not an operating-system or daemon sandbox.
    """

    if type(operation) is not LocalImageOperation:
        raise ValueError("local image resources require an exact operation")

    return ExecutionResources(
        LOCAL_IMAGE_ARCHIVE_BYTES if operation is LocalImageOperation.EXPORT
        else LOCAL_IMAGE_INSPECT_BYTES, LOCAL_IMAGE_STDERR_BYTES)
