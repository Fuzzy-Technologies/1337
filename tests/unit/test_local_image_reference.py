# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure local image-reference declarations; no socket, process or selected file is read."""

from pathlib import Path

import pytest

from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)
from fuzzy1337.local_image_reference import (
    LOCAL_IMAGE_ARCHIVE_BYTES,
    LOCAL_IMAGE_CAPABILITY,
    LOCAL_IMAGE_INSPECT_BYTES,
    LOCAL_IMAGE_STDERR_BYTES,
    ImageConfigId,
    LocalImageOperation,
    LocalImageReference,
    LocalImageResources,
    LocalImageSelection,
    PrepareLocalImageInvocation,
)
from fuzzy1337.policy import Digest

IMAGE = "sha256:" + "a" * 64


def Selection(root: Path, reference: str = "owned/image:local") -> LocalImageSelection:
    """Declare explicit files and endpoint without requiring any to exist.

    Args:
        root: Synthetic absolute owning workspace path.
        reference: Exact bounded local name/tag or full image config ID.

    Returns:
        Pure typed local selection; no runtime or authority is established.
    """

    return LocalImageSelection(root, reference, root.parent / "selected-docker",
        ArtifactReadConsent("actor:local", "consent:local"), root.parent / "docker.sock")


@pytest.mark.parametrize("reference", [
    "owned/image:local", "localhost:5000/owned/image:V1.0", "registry.test/a-b/c__d:x_y", IMAGE,
])
def test_ExplicitLocalReferencesPreserveTheirOriginalSpelling(reference):
    """Validation neither rewrites tags nor looks up a registry-qualified local name."""

    assert LocalImageReference(reference) == reference, (
        "A valid explicit local reference must remain byte-for-byte unchanged."
    )


@pytest.mark.parametrize("reference", [
    "", "image", "latest", "-image:tag", "../image:tag", "a//image:tag", "Image:tag",
    "a:tag\n", "a:tag extra", "a:--tag", "a:", "a@sha256:" + "a" * 64,
    "sha256:short", "sha256:" + "A" * 64, "https://registry.test/image:tag",
    "localhost:0/image:tag", "localhost:65536/image:tag", "a:" + "x" * 129,
    "a/" * 128 + "a:tag",
])
def test_AmbiguousOrImplicitReferencesRefuseBeforeDiscovery(reference):
    """Missing tags, options, URLs, traversal, shortened IDs and unsupported names fail closed."""

    with pytest.raises(ValueError):
        LocalImageReference(reference)


def test_SelectionAndDescriptorNeedNoFilesystemOrDocker(tmp_path, monkeypatch):
    """Explicit declarations stay pure even when every selected-file metadata read is forbidden."""

    def Forbidden(*arguments, **options):
        """Refuse a selected-path metadata read during pure declaration."""

        raise AssertionError("Pure reference declaration cannot read selected filesystem metadata")

    monkeypatch.setattr(Path, "stat", Forbidden)
    monkeypatch.setattr(Path, "lstat", Forbidden)
    selected = Selection(tmp_path / "workspace")
    manifest = selected.Manifest()
    assert manifest == {"schema_version": 1, "profile": "docker-local-reference.v1",
        "reference": "owned/image:local", "docker_executable": str(selected.executable),
        "endpoint": "unix://" + str(selected.socket_path)}, (
        "The closed descriptor must bind exact reference, executable and selected local endpoint."
    )
    assert selected.Target().value == "manifest-sha256:" + Digest(manifest), (
        "Reference scope must identify its descriptor without inventing archive or image bytes."
    )


def test_ReferenceDescriptorCannotAliasTheExportedArchiveTarget(tmp_path):
    """Source-reference permission never becomes permission for an archive created later."""

    selected = Selection(tmp_path / "workspace")
    archive = ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT,
        (ArtifactFile("image.tar", 3, "a" * 64),))
    assert selected.Target() != archive.Target(), (
        "The export descriptor and native archive must retain distinct registered scope targets."
    )


@pytest.mark.parametrize("operation", list(LocalImageOperation))
def test_FixedRecipesCannotPullOrSaveByMutableReference(tmp_path, operation):
    """Pure fixed argv selects the explicit socket and save-by-ID without ambient contexts."""

    selected = Selection(tmp_path / "workspace")
    config = selected.workspace_root / "private" / "docker-config"
    invocation = PrepareLocalImageInvocation(selected, operation, config,
        image_id=IMAGE if operation is LocalImageOperation.EXPORT else None)
    prefix = (str(selected.executable), "--host", "unix://" + str(selected.socket_path),
              "--config", str(config))
    suffix = ("image", "save", IMAGE) if operation is LocalImageOperation.EXPORT else (
        "image", "inspect", "--format", "{{json .}}", selected.reference)
    assert invocation.argv == (*prefix, *suffix), (
        "Local read argv must be exact; export may use only the resolved immutable config ID."
    )
    assert invocation.request.target_reference == selected.Target().Reference() and (
        invocation.request.capability == LOCAL_IMAGE_CAPABILITY.identifier
    ), "Recipe metadata must preserve the source-descriptor capability and target."
    assert invocation.timeout_seconds == (30 if operation is LocalImageOperation.EXPORT else 10), (
        "Export and inspect must keep their separate fixed process deadlines."
    )
    resources = LocalImageResources(operation)
    assert resources.max_stdout_bytes == (
        LOCAL_IMAGE_ARCHIVE_BYTES if operation is LocalImageOperation.EXPORT
        else LOCAL_IMAGE_INSPECT_BYTES
    ) and resources.max_stderr_bytes == LOCAL_IMAGE_STDERR_BYTES, (
        "Raw archive/inspect bytes and stderr must remain under explicit distinct ceilings."
    )


@pytest.mark.parametrize("fault", ["missing-id", "tag-id", "inspect-id", "outside-config"])
def test_InvalidRecipeDeclarationsCannotDescribeExecutableWork(tmp_path, fault):
    """A typed operation does not accept inferred IDs, mutable exports or external config paths."""

    selected = Selection(tmp_path / "workspace")
    operation = LocalImageOperation.EXPORT
    image_id = IMAGE
    config = selected.workspace_root / "private"

    if fault == "missing-id":
        image_id = None

    elif fault == "tag-id":
        image_id = selected.reference

    elif fault == "inspect-id":
        operation = LocalImageOperation.INSPECT

    else:
        config = selected.workspace_root.parent / "unowned"

    with pytest.raises(ValueError):
        PrepareLocalImageInvocation(selected, operation, config, image_id=image_id)


def test_ConfigIdentityNeverAcceptsTagsOrShortenedValues():
    """Config identity grammar remains narrower than user-facing tagged local references."""

    assert ImageConfigId(IMAGE) == IMAGE, "A complete config digest must retain its exact identity."

    with pytest.raises(ValueError):
        ImageConfigId("owned/image:local")
