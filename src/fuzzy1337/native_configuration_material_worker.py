# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed private configuration snapshot reader; never executes the selected scanner."""

from __future__ import annotations

import io
import os
import platform
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, cast

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import (
    ArtifactManifest,
    ArtifactPathInfo,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactSelection,
    ArtifactSnapshot,
    ArtifactStage,
    PhysicalIdentity,
    ReadArtifactFile,
)
from fuzzy1337.executors.local import LocalExecutionError
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.native_configuration import (
    MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES,
    MAX_NATIVE_CONFIGURATION_SOURCE_BYTES,
    NATIVE_CONFIGURATION_EXECUTABLE_SHA256,
    NATIVE_CONFIGURATION_PLATFORM,
    NATIVE_CONFIGURATION_VERSION,
    ConfigurationManifest,
    ConfigurationPath,
    NativeConfigurationSelection,
)

CONTROL_BYTES = 64 * 1024
_NONCE = re.compile(r"[a-f0-9]{32}")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_CONTROL_FIELDS = {"schema_version", "action", "nonce", "operation_reference", "workspace_id",
    "owner_reference", "workspace_root", "workspace_identity", "directory_identity",
    "selection", "stage_root", "stage"}


def CanonicalControl(value: object) -> bytes:
    """Encode only finite internal control with an inclusive 64-KiB ceiling."""

    raw = SerializeContract(value).encode("utf-8")

    if len(raw) > CONTROL_BYTES:
        raise ValueError("configuration material control exceeds its bound")

    return raw


def ParseControl(raw: bytes) -> dict[str, Any]:
    """Require bounded duplicate-free exact canonical JSON without selected contents."""

    value = ParseJson(raw, CONTROL_BYTES)

    if raw != CanonicalControl(value):
        raise ValueError("configuration material control is not canonical")

    return value


def Text(value: object) -> str:
    """Require bounded single-line non-secret private references and path declarations."""

    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(
        character in value for character in ("\x00", "\n", "\r")
    ):
        raise ValueError("configuration material text is invalid")

    return value


def Identity(value: object, length: int = 5) -> tuple[int, ...]:
    """Validate complete finite private physical identities without normalizing them."""

    if not isinstance(value, (list, tuple)) or len(value) != length or any(
        type(item) is not int or item < 0 for item in value
    ):
        raise ValueError("configuration material physical identity is invalid")

    return tuple(value)


def RequirePlatform() -> None:
    """Refuse unproved platform or descendant ownership before selected material reads."""

    if (sys.platform, platform.machine()) != NATIVE_CONFIGURATION_PLATFORM:
        raise ValueError("configuration material platform is unsupported")

    try:
        RequireLinuxOwnership()

    except LocalExecutionError:
        raise ValueError("configuration material ownership is unsupported") from None


def SelectionPayload(selection: NativeConfigurationSelection) -> dict[str, object]:
    """Detach the exact syntax-only selection and explicit selected-read consent."""

    return {"profile": selection.profile.value, "logical_path": selection.logical_path,
        "source": str(selection.source), "executable": str(selection.executable),
        "read_consent": {"actor_ref": selection.read_consent.actor_ref,
                         "record_ref": selection.read_consent.record_ref}}


def SelectionFromControl(value: dict[str, Any]) -> NativeConfigurationSelection:
    """Validate exact private request fields and same-owner selected read authority."""

    if set(value) != _CONTROL_FIELDS or type(value["schema_version"]) is not int or (
        value["schema_version"] != 1 or value["action"] not in {"create", "verify"}
    ) or not isinstance(value["nonce"], str) or not _NONCE.fullmatch(value["nonce"]):
        raise ValueError("configuration material request schema differs")

    for key in ("operation_reference", "workspace_id", "owner_reference", "workspace_root",
                "stage_root"):
        Text(value[key])

    root = Path(value["workspace_root"])
    stage_root = Path(value["stage_root"])
    ConfigurationPath(root)
    ConfigurationPath(stage_root)
    Identity(value["workspace_identity"], 2)
    Identity(value["directory_identity"], 2)

    if stage_root.parent != root or not re.fullmatch(
        r"native-configuration-stage-[a-f0-9]{32}", stage_root.name
    ) or (value["action"] == "create") != (value["stage"] is None):
        raise ValueError("configuration material stage association differs")

    selected = value["selection"]

    if type(selected) is not dict or set(selected) != {
        "profile", "logical_path", "source", "executable", "read_consent"
    }:
        raise ValueError("configuration material selection fields differ")

    consent = selected["read_consent"]

    if type(consent) is not dict or set(consent) != {"actor_ref", "record_ref"} or (
        Text(consent["actor_ref"]) != value["owner_reference"]
    ):
        raise ValueError("configuration material read consent belongs to another owner")

    return NativeConfigurationSelection(ArtifactProfile(selected["profile"]),
        selected["logical_path"], Path(Text(selected["source"])),
        Path(Text(selected["executable"])),
        ArtifactReadConsent(consent["actor_ref"], Text(consent["record_ref"])))


def StagePayload(stage: ArtifactStage) -> dict[str, object]:
    """Describe exact original snapshots and physical facts without copying selected bodies."""

    partitions = {}

    for snapshot in (stage.input, stage.scanner, stage.material):
        partitions[snapshot.manifest.role.value] = {"manifest": snapshot.manifest.ToDict(),
            "identities": snapshot.identities, "directory_identity": snapshot.directory_identity}

    return {"lease_id": stage.lease_id, "root_identity": stage.root_identity,
        "executable_identity": stage.executable_identity, "partitions": partitions}


def StageFromPayload(value: object, selection: NativeConfigurationSelection,
                     stage_root: Path) -> ArtifactStage:
    """Decode only the original fixed stage shape without selected-file content reads."""

    if type(value) is not dict or set(value) != {
        "lease_id", "root_identity", "executable_identity", "partitions"
    } or type(value["partitions"]) is not dict or set(value["partitions"]) != {
        "input", "scanner", "material"
    }:
        raise ValueError("configuration material stage fields differ")

    snapshots = []

    for role in (ArtifactRole.INPUT, ArtifactRole.SCANNER, ArtifactRole.MATERIAL):
        partition = value["partitions"][role.value]

        if type(partition) is not dict or set(partition) != {
            "manifest", "identities", "directory_identity"
        }:
            raise ValueError("configuration material partition fields differ")

        manifest = ArtifactManifest.FromDict(partition["manifest"])

        if manifest.profile is not selection.profile or manifest.role is not role:
            raise ValueError("configuration material manifest domain differs")

        snapshots.append(ArtifactSnapshot(manifest, stage_root / role.value,
            selection.read_consent, partition["identities"], partition["directory_identity"]))

    return ArtifactStage(stage_root, value["lease_id"], snapshots[0], snapshots[1], snapshots[2],
        selection.executable,
        cast(tuple[int, int, int, int, int], Identity(value["executable_identity"])),
        NATIVE_CONFIGURATION_VERSION, cast(tuple[int, int], Identity(value["root_identity"], 2)))


def ExactChildren(directory: Path, expected: set[str]) -> None:
    """Refuse unexpected directory entries after at most one excess metadata entry."""

    names: set[str] = set()

    with os.scandir(directory) as children:
        for child in children:
            if child.name not in expected or child.name in names:
                raise ValueError("configuration material contains unselected entries")

            names.add(child.name)

    if names != expected:
        raise ValueError("configuration material selected entries are missing")


def CheckStageMetadata(stage: ArtifactStage, selection: NativeConfigurationSelection) -> None:
    """Check only fixed finite no-follow identities and tree shape, never selected contents."""

    ConfigurationManifest(selection, stage.input.manifest)
    root = ArtifactPathInfo(stage.root, directory=True)

    if (root.st_dev, root.st_ino) != stage.root_identity or (
        stage.executable != selection.executable or stage.version != NATIVE_CONFIGURATION_VERSION
        or PhysicalIdentity(ArtifactPathInfo(stage.executable)) != stage.executable_identity
    ):
        raise ValueError("configuration material root or selected executable changed")

    ExactChildren(stage.root, {"input", "scanner", "material", "scratch"})

    for snapshot, role, names in (
        (stage.input, ArtifactRole.INPUT, {selection.logical_path}),
        (stage.scanner, ArtifactRole.SCANNER, {"executable"}),
        (stage.material, ArtifactRole.MATERIAL, set()),
    ):
        directory = ArtifactPathInfo(snapshot.directory, directory=True)

        if snapshot.directory != stage.root / role.value or (
            snapshot.manifest.profile is not selection.profile or snapshot.manifest.role is not role
            or snapshot.consent != selection.read_consent
            or {record.name for record in snapshot.manifest.files} != names
            or (directory.st_dev, directory.st_ino) != snapshot.directory_identity
        ):
            raise ValueError("configuration material partition association changed")

        ExactChildren(snapshot.directory, names)

        for name, identity in snapshot.identities:
            if PhysicalIdentity(ArtifactPathInfo(snapshot.directory / name)) != identity:
                raise ValueError("configuration material staged physical identity changed")

    ArtifactPathInfo(stage.root / "scratch", directory=True)
    ExactChildren(stage.root / "scratch", set())
    scanner = stage.scanner.manifest.files[0]

    if not 1 <= scanner.size_bytes <= MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES or (
        scanner.sha256 != NATIVE_CONFIGURATION_EXECUTABLE_SHA256
    ):
        raise ValueError("configuration material executable differs from the supported candidate")


def VerifyStage(stage: ArtifactStage, selection: NativeConfigurationSelection) -> None:
    """Verify copied bytes with per-role admission limits and decode the exact verified source."""

    CheckStageMetadata(stage, selection)
    source_bytes = io.BytesIO()
    source = ReadArtifactFile(stage.input.directory / selection.logical_path,
        selection.logical_path, source_bytes, max_bytes=MAX_NATIVE_CONFIGURATION_SOURCE_BYTES)
    scanner = ReadArtifactFile(stage.scanner.directory / "executable", "executable",
                               max_bytes=MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES)
    original = ReadArtifactFile(stage.executable, "executable",
                                max_bytes=MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES)

    if (source,) != stage.input.manifest.files or (
        (scanner,) != stage.scanner.manifest.files or original != scanner
    ):
        raise ValueError("configuration material copied bytes differ from original manifests")

    source_bytes.getvalue().decode("utf-8")
    CheckStageMetadata(stage, selection)


def CreateStage(stage_root: Path, selection: NativeConfigurationSelection) -> ArtifactStage:
    """Compose bounded actual streaming copies rather than broader global stage capture."""

    executable_identity = PhysicalIdentity(ArtifactPathInfo(selection.executable))
    stage_root.mkdir(mode=0o700)
    source = ArtifactSnapshot.Capture(stage_root / "input", selection.profile, ArtifactRole.INPUT,
        (ArtifactSelection(selection.logical_path, selection.source),), selection.read_consent,
        max_total_bytes=MAX_NATIVE_CONFIGURATION_SOURCE_BYTES)
    scanner = ArtifactSnapshot.Capture(stage_root / "scanner", selection.profile,
        ArtifactRole.SCANNER, (ArtifactSelection("executable", selection.executable),),
        selection.read_consent, max_total_bytes=MAX_NATIVE_CONFIGURATION_EXECUTABLE_BYTES)
    material = ArtifactSnapshot.Capture(stage_root / "material", selection.profile,
        ArtifactRole.MATERIAL, (), selection.read_consent, max_total_bytes=0)
    (stage_root / "scratch").mkdir(mode=0o700)
    root = ArtifactPathInfo(stage_root, directory=True)
    stage = ArtifactStage(stage_root, uuid.uuid4().hex, source, scanner, material,
        selection.executable, executable_identity, NATIVE_CONFIGURATION_VERSION,
        (root.st_dev, root.st_ino))
    VerifyStage(stage, selection)

    return stage


def ReadControl(path: Path, digest: str, identity: tuple[int, ...]) -> dict[str, Any]:
    """Read exact private control through existing bounded before/open/after path guards."""

    if path.name != "request.json" or not _DIGEST.fullmatch(digest):
        raise ValueError("configuration material private request differs")

    before = ArtifactPathInfo(path)
    directory = ArtifactPathInfo(path.parent, directory=True)

    if PhysicalIdentity(before) != identity or stat.S_IMODE(before.st_mode) != 0o600 or (
        stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise ValueError("configuration material private ownership differs")

    contents = io.BytesIO()
    record = ReadArtifactFile(path, "request.json", contents, max_bytes=CONTROL_BYTES)

    if record.sha256 != digest or PhysicalIdentity(ArtifactPathInfo(path)) != identity:
        raise ValueError("configuration material private request changed")

    value = ParseControl(contents.getvalue())
    SelectionFromControl(value)
    root = Path(value["workspace_root"])
    workspace = ArtifactPathInfo(root, directory=True)

    if path.parent.parent != root or not re.fullmatch(
        r"native-configuration-read-[a-f0-9]{32}", path.parent.name
    ) or (directory.st_dev, directory.st_ino) != Identity(value["directory_identity"], 2) or (
        (workspace.st_dev, workspace.st_ino) != Identity(value["workspace_identity"], 2)
    ):
        raise ValueError("configuration material private parent association differs")

    return value


def ObserveControl(value: dict[str, Any], digest: str,
                   request_identity: tuple[int, ...]) -> bytes:
    """Create or verify only the read-authorized fixed selected snapshots inside this child."""

    RequirePlatform()
    selection = SelectionFromControl(value)
    stage_root = Path(value["stage_root"])

    if value["action"] == "create":
        stage = CreateStage(stage_root, selection)

    else:
        stage = StageFromPayload(value["stage"], selection, stage_root)
        VerifyStage(stage, selection)

    return CanonicalControl({"schema_version": 1, "control": value,
        "request_sha256": digest, "request_identity": request_identity,
        "stage": StagePayload(stage)})


def Main(argv: list[str] | None = None) -> int:
    """Run only the fixed installed reader; all refusals use a bounded sanitized diagnostic."""

    arguments = sys.argv[1:] if argv is None else argv

    try:
        RequirePlatform()

        if len(arguments) != 3:
            raise ValueError("configuration material reader requires fixed control arguments")

        identity = Identity([int(item) for item in arguments[2].split(",")])
        path = Path(arguments[0])
        value = ReadControl(path, arguments[1], identity)
        raw = ObserveControl(value, arguments[1], identity)
        ReadControl(path, arguments[1], identity)
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()

        return 0

    except (OSError, ValueError, TypeError, KeyError):
        sys.stderr.write("native-configuration-material-refused\n")

        return 2


if __name__ == "__main__":
    raise SystemExit(Main())
