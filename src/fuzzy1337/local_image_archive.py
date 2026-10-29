# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded original Docker inspect and Docker-save config binding, without extraction."""

from __future__ import annotations

import hashlib
import io
import json
import math
import tarfile
from dataclasses import dataclass

from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactName,
    ArtifactProfile,
    ArtifactRole,
)
from fuzzy1337.local_image_reference import (
    LOCAL_IMAGE_ARCHIVE_BYTES,
    LOCAL_IMAGE_INSPECT_BYTES,
    ImageConfigId,
)


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys before a later value can replace original identity facts.

    Args:
        pairs: Original ordered object members from the bounded JSON decoder.

    Returns:
        One unambiguous object.

    Raises:
        ValueError: The original object repeats a key.
    """

    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("local image JSON cannot repeat object keys")

        result[key] = value

    return result


def RejectConstant(value: str) -> None:
    """Refuse non-JSON numeric constants without echoing selected material.

    Args:
        value: Decoder-supplied nonfinite token, never retained in diagnostics.

    Raises:
        ValueError: A forbidden JSON constant was present.
    """

    raise ValueError("local image JSON cannot contain nonfinite constants")


def FiniteNumber(value: str) -> float:
    """Refuse float overflow even when the original numeric token is legal JSON syntax.

    Args:
        value: Original JSON fractional/exponent token.

    Returns:
        Finite decoded number; source bytes remain independently retained.

    Raises:
        ValueError: Numeric conversion overflows to a nonfinite value.
    """

    number = float(value)

    if not math.isfinite(number):
        raise ValueError("local image JSON number exceeds finite representation")

    return number


def JsonDocument(raw: bytes, maximum: int) -> object:
    """Decode one bounded strict UTF-8 original without last-key-wins behavior.

    Args:
        raw: Complete retained original JSON bytes.
        maximum: Inclusive ceiling for this fixed original role.

    Returns:
        Decoded original value; caller validates its exact selected semantics.

    Raises:
        ValueError: Bytes, encoding, size, syntax or nesting cannot be accepted.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("local image JSON bytes exceed their original bound")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueObject,
                          parse_constant=RejectConstant, parse_float=FiniteNumber)

    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("local image original JSON is invalid") from error


def InspectConfigId(raw: bytes) -> str:
    """Read the exact local inspect ID without inferring an image identity from mutable tags.

    Args:
        raw: Original fixed ``image inspect --format {{json .}}`` stdout.

    Returns:
        Full config digest for the one observed Linux image.

    Raises:
        ValueError: The original response lacks one supported image identity.
    """

    value = JsonDocument(raw, LOCAL_IMAGE_INSPECT_BYTES)

    if type(value) is not dict or value.get("Os") != "linux" or type(value.get("Id")) is not str:
        raise ValueError("local image inspect requires one explicit Linux image identity")

    return ImageConfigId(value["Id"])


@dataclass(frozen=True, slots=True)
class LocalImageArchivePin:
    """Distinct complete archive byte identity and original config identity; no scan authority."""

    image_config_id: str
    archive_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Keep descriptive archive/config identities valid without granting execution."""

        ImageConfigId(self.image_config_id)

        if type(self.archive_sha256) is not str or type(self.size_bytes) is not int or (
            not 0 < self.size_bytes <= LOCAL_IMAGE_ARCHIVE_BYTES
        ):
            raise ValueError("local image archive pin requires bounded original identities")

        ImageConfigId("sha256:" + self.archive_sha256)

    def Manifest(self) -> ArtifactManifest:
        """Describe only the complete accepted tar for separately registered archive scope.

        Returns:
            The existing unchanged native IMAGE/INPUT manifest for ``image.tar``.
        """

        return ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT,
            (ArtifactFile("image.tar", self.size_bytes, self.archive_sha256),))


def VerifyDockerSave(raw: bytes, expected_config_id: str) -> LocalImageArchivePin:
    """Bind one complete bounded Docker-save archive to the original inspected config bytes.

    Args:
        raw: Complete successful bounded export stdout, not a truncated stream prefix.
        expected_config_id: Original inspected full SHA-256 config ID.

    Returns:
        Separate archive/config facts suitable for a later independent native archive plan.

    Raises:
        ValueError: Archive shape, members, manifest, config bytes or limits refuse.
    """

    ImageConfigId(expected_config_id)

    if type(raw) is not bytes or not 0 < len(raw) <= LOCAL_IMAGE_ARCHIVE_BYTES:
        raise ValueError("local image archive bytes exceed their original bound")

    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}

            for member in archive:
                name = ArtifactName(member.name.rstrip("/") if member.isdir() else member.name)

                if name in members or len(members) >= 1024 or (
                    not (member.isreg() or member.isdir())
                    or member.size < 0 or member.size > LOCAL_IMAGE_ARCHIVE_BYTES
                ):
                    raise ValueError("local image tar requires unique bounded ordinary members")

                members[name] = member

            tail = raw[archive.offset:]

            if len(raw) % 512 or len(tail) < 1024 or any(tail):
                raise ValueError("local image tar requires a complete zero-terminated original")

            def Read(name: str, maximum: int) -> bytes:
                """Read only a selected bounded ordinary member, never extract a filesystem path.

                Args:
                    name: Exact validated member identity selected by the Docker-save manifest.
                    maximum: Inclusive limit for original manifest or config bytes.

                Returns:
                    Complete member bytes within their declared size.

                Raises:
                    ValueError: The selected member is absent, linked, oversized or truncated.
                """

                member = members.get(name)

                if member is None or not member.isreg() or not 0 < member.size <= maximum:
                    raise ValueError("local image tar selected member is absent or unsupported")

                stream = archive.extractfile(member)

                if stream is None:
                    raise ValueError("local image tar selected member cannot be read")

                with stream:
                    content = stream.read(maximum + 1)

                if len(content) != member.size or len(content) > maximum:
                    raise ValueError("local image tar selected member is truncated or oversized")

                return content

            manifest = JsonDocument(Read("manifest.json", 64 * 1024), 64 * 1024)

            if type(manifest) is not list or len(manifest) != 1 or type(manifest[0]) is not dict:
                raise ValueError("local image tar requires one Docker-save image manifest")

            config_name = manifest[0].get("Config")

            if type(config_name) is not str:
                raise ValueError("local image tar manifest lacks its explicit config member")

            config = Read(ArtifactName(config_name), 1024 * 1024)
            observed_id = "sha256:" + hashlib.sha256(config).hexdigest()

            if observed_id != expected_config_id:
                raise ValueError("local image archive config differs from original inspect")

            return LocalImageArchivePin(observed_id, hashlib.sha256(raw).hexdigest(), len(raw))

    except (tarfile.TarError, KeyError, OSError, OverflowError) as error:
        raise ValueError("local image original Docker-save archive is invalid") from error
