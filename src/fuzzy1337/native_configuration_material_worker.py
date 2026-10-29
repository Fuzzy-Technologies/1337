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
    """Encode only finite internal control with an inclusive 64-KiB ceiling.

    Args:
        value: Internal contract value supported by the strict JSON serializer.

    Returns:
        Deterministic compact UTF-8 JSON bytes with sorted keys, at most 65536 bytes.

    Raises:
        ValueError: The value is outside the finite JSON contract or exceeds the byte limit.
    """

    raw = SerializeContract(value).encode("utf-8")

    if len(raw) > CONTROL_BYTES:
        raise ValueError("configuration material control exceeds its bound")

    return raw


def ParseControl(raw: bytes) -> dict[str, Any]:
    """Require bounded duplicate-free exact canonical JSON without selected contents.

    Args:
        raw: Complete private JSON object bytes, at most 65536 bytes including encoding.

    Returns:
        Decoded object only when reserialization exactly matches the original bytes.
        Request/response field semantics require their separate validators.

    Raises:
        ValueError: Encoding, JSON shape, duplicate keys, finite/structural limits or
            canonical byte equality fails.
    """

    value = ParseJson(raw, CONTROL_BYTES)

    if raw != CanonicalControl(value):
        raise ValueError("configuration material control is not canonical")

    return value


def Text(value: object) -> str:
    """Require bounded single-line non-secret private references and path declarations.

    Args:
        value: Caller-supplied non-secret reference or path text; secrets are not detected.

    Returns:
        Original string of 1 through 4096 characters without NUL or line breaks.

    Raises:
        ValueError: The value is not a string or violates the length/character bounds.
    """

    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(
        character in value for character in ("\x00", "\n", "\r")
    ):
        raise ValueError("configuration material text is invalid")

    return value


def Identity(value: object, length: int = 5) -> tuple[int, ...]:
    """Validate complete finite private physical identities without normalizing them.

    Args:
        value: List or tuple containing only nonnegative exact integers, excluding bool.
        length: Required number of identity components; defaults to five for files,
            while callers use two for device/inode directory identities.

    Returns:
        Tuple preserving every validated component in its original order.

    Raises:
        ValueError: Container type, component count or integer domain is invalid.
    """

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
    """Detach the exact syntax-only selection and explicit selected-read consent.

    Args:
        selection: Native profile, logical source name, paths and explicit read consent.

    Returns:
        New descriptive dictionary with the profile value, paths and consent references.
        No selected file is read and no provider authority is issued.
    """

    return {"profile": selection.profile.value, "logical_path": selection.logical_path,
        "source": str(selection.source), "executable": str(selection.executable),
        "read_consent": {"actor_ref": selection.read_consent.actor_ref,
                         "record_ref": selection.read_consent.record_ref}}


def SelectionFromControl(value: dict[str, Any]) -> NativeConfigurationSelection:
    """Validate exact private request fields and same-owner selected read authority.

    Args:
        value: Decoded schema-one create/verify request with the fixed field set,
            generated stage path, physical identity declarations and owner consent.

    Returns:
        Syntax-validated native selection whose consent actor equals the declared owner.
        This validates declarations without reading source or executing the scanner.

    Raises:
        ValueError: Schema, nonce, bounded text, paths, identities, profile or consent differs.
        TypeError: Malformed nested values cannot be interpreted as the required fields.
    """

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


def StagePayload(stage: ArtifactStage, *,
                 scratch_identity: tuple[int, ...] | None = None) -> dict[str, object]:
    """Describe original facts, refusing a changed expected scratch before serialization.

    Args:
        stage: Original stage whose manifests and recorded physical identities are described.
        scratch_identity: Expected scratch device/inode tuple, or None to record the
            current directory identity. A supplied identity must match exactly.

    Returns:
        Detached lease, root, scratch, executable and partition metadata. This does
        not verify copied file contents or issue a parent observer's material proof.

    Raises:
        ValueError: Scratch physical path guards fail or its expected identity changed.
        OSError: Scratch directory metadata cannot be observed.
    """

    partitions = {}

    for snapshot in (stage.input, stage.scanner, stage.material):
        partitions[snapshot.manifest.role.value] = {"manifest": snapshot.manifest.ToDict(),
            "identities": snapshot.identities, "directory_identity": snapshot.directory_identity}

    scratch = ArtifactPathInfo(stage.root / "scratch", directory=True)
    observed_scratch_identity = scratch.st_dev, scratch.st_ino

    if scratch_identity is None:
        scratch_identity = observed_scratch_identity

    elif observed_scratch_identity != scratch_identity:
        raise ValueError("configuration material scratch identity changed")

    return {"lease_id": stage.lease_id, "root_identity": stage.root_identity,
        "scratch_identity": scratch_identity,
        "executable_identity": stage.executable_identity, "partitions": partitions}


def StageFromPayload(value: object, selection: NativeConfigurationSelection,
                     stage_root: Path) -> ArtifactStage:
    """Decode only the original fixed stage shape without selected-file content reads.

    Args:
        value: Fixed stage payload containing three partition manifests and identities.
        selection: Original native selection supplying profile, executable and read consent.
        stage_root: Generated stage root already associated with the original request.

    Returns:
        Reconstructed stage with matching scratch identity and declared partition
        domains. Content verification and original parent proof issuance remain separate.

    Raises:
        ValueError: Payload shape, identities, manifest domain or scratch association fails.
        OSError: Scratch metadata cannot be observed.
    """

    if type(value) is not dict or set(value) != {
        "lease_id", "root_identity", "scratch_identity", "executable_identity", "partitions"
    } or type(value["partitions"]) is not dict or set(value["partitions"]) != {
        "input", "scanner", "material"
    }:
        raise ValueError("configuration material stage fields differ")

    scratch = ArtifactPathInfo(stage_root / "scratch", directory=True)

    if (scratch.st_dev, scratch.st_ino) != Identity(value["scratch_identity"], 2):
        raise ValueError("configuration material scratch identity changed")

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
    """Refuse unexpected directory entries after at most one excess metadata entry.

    Args:
        directory: Directory to enumerate for exact immediate child names, without recursion.
        expected: Complete allowed child-name set; empty requires an empty directory.

    Raises:
        ValueError: An unexpected/duplicate entry appears or an expected entry is missing.
        OSError: Directory entries cannot be enumerated.
    """

    names: set[str] = set()

    with os.scandir(directory) as children:
        for child in children:
            if child.name not in expected or child.name in names:
                raise ValueError("configuration material contains unselected entries")

            names.add(child.name)

    if names != expected:
        raise ValueError("configuration material selected entries are missing")


def CheckStageMetadata(stage: ArtifactStage, selection: NativeConfigurationSelection) -> None:
    """Check only fixed finite no-follow identities and tree shape, never selected contents.

    Args:
        stage: Stage with original root, selected executable and partition identities.
        selection: Original selected input, native profile and explicit read consent.

    Raises:
        ValueError: Manifest, association, physical identity, exact child set or candidate
            executable pin differs. Declared scanner size must be 1 byte through 256 MiB.
        OSError: Required directory/file metadata cannot be observed.
    """

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
    """Verify copied bytes with per-role admission limits and decode the exact verified source.

    Args:
        stage: Original stage whose copied input/scanner and selected executable are reread.
        selection: Original profile, logical name and selected executable association.

    Raises:
        ValueError: Metadata, manifests, content hashes, UTF-8 or bounded reads fail.
            Input admission is capped at 4096 bytes and executable admission at 256 MiB.
        OSError: Required metadata or bounded file reads fail.

    UTF-8 is decoded from the same copied source bytes used for manifest agreement.
    The original selected source is not reopened and the scanner is never executed.
    """

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
    """Compose bounded actual streaming copies rather than broader global stage capture.

    Args:
        stage_root: New generated stage path; creation is exclusive and uses mode 0700.
        selection: Explicit read-authorized source and pinned native executable selection.

    Returns:
        Verified stage with captured input, scanner, empty material and empty scratch.
        Streaming admission caps are 4096 source bytes, 256 MiB executable bytes and
        zero material bytes; no provider process is launched.

    Raises:
        ValueError: Read consent, streaming limits, UTF-8, pin or stage verification fails.
        OSError: Stage creation, copying or metadata observation fails. A partial tree
            is retained on failure for the owning observer to assess.
    """

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
    """Read exact private control through existing bounded before/open/after path guards.

    Args:
        path: Original request.json in the generated mode-0700 private request directory.
        digest: Expected lowercase SHA-256 hex digest of the canonical request bytes.
        identity: Original request file's physical identity, requiring unchanged mode 0600.

    Returns:
        Canonical request object after a read capped at 65536 bytes, matching digest,
        physical file guards, selected consent and private/workspace associations.

    Raises:
        ValueError: Request name, digest, bytes, identity, permissions or association differs.
        OSError: Physical metadata or bounded private control reading fails.
    """

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
    """Create or verify only the read-authorized fixed selected snapshots inside this child.

    Args:
        value: Original canonical request already read through private control guards.
        digest: Original request's lowercase SHA-256 hex digest echoed in the response.
        request_identity: Original physical request identity echoed for parent comparison.

    Returns:
        Canonical response bytes capped at 65536 bytes, binding original control and
        request identity to created or reverified stage metadata. This child response
        cannot itself issue the parent observer's material proof.

    Raises:
        ValueError: Platform ownership, request, bounded material or response validation fails.
        OSError: Selected capture, verification or stage metadata observation fails.
    """

    RequirePlatform()
    selection = SelectionFromControl(value)
    stage_root = Path(value["stage_root"])
    scratch_identity = None

    if value["action"] == "create":
        stage = CreateStage(stage_root, selection)

    else:
        stage = StageFromPayload(value["stage"], selection, stage_root)
        scratch_identity = Identity(value["stage"]["scratch_identity"], 2)
        VerifyStage(stage, selection)

    return CanonicalControl({"schema_version": 1, "control": value,
        "request_sha256": digest, "request_identity": request_identity,
        "stage": StagePayload(stage, scratch_identity=scratch_identity)})


def Main(argv: list[str] | None = None) -> int:
    """Run only the fixed installed reader; all refusals use a bounded sanitized diagnostic.

    Args:
        argv: Three explicit arguments: request path, SHA-256 digest and comma-separated
            physical identity integers. None reads process arguments after the executable.

    Returns:
        Zero after rechecking unchanged control and writing the bounded canonical
        response to stdout; two after a handled I/O, validation, type or key refusal,
        with the fixed sanitized refusal line on stderr. No scanner is executed.
    """

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
