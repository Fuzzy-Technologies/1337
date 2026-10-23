# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed private four-file observation worker; never executes an optional scanner."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import (
    ArtifactHandleInfo,
    ArtifactPathInfo,
    ArtifactReadConsent,
    PhysicalIdentity,
)
from fuzzy1337.native_image_capture import NativeTrivySelection

CONTROL_MAX_BYTES = 64 * 1024
ROLE_BOUNDS = (("archive", 512 * 1024**2), ("executable", 256 * 1024**2),
               ("database", 2 * 1024**3), ("database-metadata", 16 * 1024))
_DIGEST = re.compile(r"[a-f0-9]{64}")
_NONCE = re.compile(r"[a-f0-9]{32}")
_REQUEST_FIELDS = {"schema_version", "nonce", "operation_reference", "workspace_id",
    "owner_reference", "read_consent", "selection", "directory_identity", "workspace_identity",
    "roles"}


def CanonicalControl(value: object) -> bytes:
    """Serialize finite private JSON with its fixed inclusive byte ceiling.

    Args:
        value: Internally selected private request or result fields.

    Returns:
        Canonical UTF-8 bytes, without a trailing line separator.

    Raises:
        ValueError: Serialization exceeds the private control budget.
    """

    raw = SerializeContract(value).encode("utf-8")

    if len(raw) > CONTROL_MAX_BYTES:
        raise ValueError("native material control exceeds its byte bound")

    return raw


def ParseControl(raw: bytes) -> dict[str, object]:
    """Reject duplicate, oversized or noncanonical private control JSON.

    Args:
        raw: Exact captured private control bytes.

    Returns:
        Detached strict canonical object.
    """

    value = ParseJson(raw, CONTROL_MAX_BYTES)

    if CanonicalControl(value) != raw:
        raise ValueError("native material control must be canonical")

    return value


def RequireText(value: object) -> str:
    """Require finite nonempty private references or selected path text.

    Args:
        value: Explicit typed private field, never discovered content.

    Returns:
        Unchanged bounded single-line text.
    """

    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(
        character in value for character in ("\x00", "\n", "\r")
    ):
        raise ValueError("native material text must be bounded and single-line")

    return value


def ControlIdentity(value: object, length: int = 5) -> tuple[int, ...]:
    """Validate exact finite physical identity components from private control.

    Args:
        value: Ordered original integer metadata.
        length: Fixed directory or regular-file identity length.

    Returns:
        Unchanged immutable physical metadata.
    """

    if not isinstance(value, (list, tuple)) or len(value) != length or any(
        type(item) is not int or item < 0 for item in value
    ):
        raise ValueError("native material physical identity is invalid")

    return cast(tuple[int, ...], tuple(value))


def SelectionFromControl(value: dict[str, object]) -> NativeTrivySelection:
    """Admit only the fixed selection and explicit matching read-consent actor.

    Args:
        value: Already bounded canonical private request.

    Returns:
        The unchanged native four-file selection, without selected content reads.
    """

    if set(value) != _REQUEST_FIELDS or type(value["schema_version"]) is not int or (
        value["schema_version"] != 1
    ) or not isinstance(value["nonce"], str) or not _NONCE.fullmatch(value["nonce"]):
        raise ValueError("native material request schema is invalid")

    for key in ("operation_reference", "workspace_id", "owner_reference"):
        RequireText(value[key])

    ControlIdentity(value["directory_identity"], 2)
    ControlIdentity(value["workspace_identity"], 2)

    if value["roles"] != [list(role) for role in ROLE_BOUNDS]:
        raise ValueError("native material roles or limits differ from the fixed profile")

    consent = value["read_consent"]
    selection = value["selection"]

    if not isinstance(consent, dict) or set(consent) != {"actor_ref", "record_ref"} or (
        not isinstance(selection, dict) or set(selection) != {
            "workspace_root", "executable", "archive", "cache_directory"}
    ):
        raise ValueError("native material selection or consent fields are invalid")

    actor = RequireText(consent["actor_ref"])

    if actor != value["owner_reference"]:
        raise ValueError("native material read consent belongs to another owner")

    return NativeTrivySelection(Path(RequireText(selection["workspace_root"])),
        Path(RequireText(selection["executable"])), RequireText(selection["archive"]),
        RequireText(selection["cache_directory"]),
        ArtifactReadConsent(actor, RequireText(consent["record_ref"])))


def ReadControl(path: Path, digest: str, identity: tuple[int, ...]) -> dict[str, object]:
    """Read only the fixed private request with exact physical and digest binding.

    Args:
        path: Observer-created request.json in its private operation directory.
        digest: Parent-observed canonical request SHA256.
        identity: Parent-observed original request physical identity.

    Returns:
        Exact bounded canonical request after before/open/after checks.
    """

    if path.name != "request.json" or not _DIGEST.fullmatch(digest):
        raise ValueError("native material request association is invalid")

    before = ArtifactPathInfo(path)
    directory = ArtifactPathInfo(path.parent, directory=True)

    if stat.S_IMODE(before.st_mode) != 0o600 or stat.S_IMODE(directory.st_mode) != 0o700 or (
        before.st_size > CONTROL_MAX_BYTES or PhysicalIdentity(before) != identity
    ):
        raise ValueError("native material private request identity differs")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

    with os.fdopen(os.open(path, flags), "rb") as source:
        if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != identity:
            raise ValueError("native material private request changed at open")

        raw = source.read(CONTROL_MAX_BYTES + 1)

        if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != identity:
            raise ValueError("native material private request changed during read")

    if PhysicalIdentity(ArtifactPathInfo(path)) != identity or (
        hashlib.sha256(raw).hexdigest() != digest
    ):
        raise ValueError("native material private request changed after read")

    value = ParseControl(raw)
    selected = SelectionFromControl(value)

    if path.parent.parent != selected.workspace_root or not path.parent.name.startswith(
        "native-material-"
    ) or (directory.st_dev, directory.st_ino) != ControlIdentity(value["directory_identity"], 2):
        raise ValueError("native material private directory association differs")

    root = ArtifactPathInfo(selected.workspace_root, directory=True)

    if (root.st_dev, root.st_ino) != ControlIdentity(value["workspace_identity"], 2):
        raise ValueError("native material workspace parent identity differs")

    return value


def StrictMetadata(raw: bytes) -> dict[str, object]:
    """Parse bounded schema-two database metadata without a freshness assertion.

    Args:
        raw: Exact selected metadata bytes, not scanner output.

    Returns:
        Detached strict JSON metadata with a timezone-bearing update time.
    """

    value = ParseJson(raw, 16 * 1024)

    if type(value.get("Version")) is not int or value["Version"] != 2 or (
        not isinstance(value.get("UpdatedAt"), str)
    ):
        raise ValueError("native material metadata requires schema two and update time")

    updated = datetime.fromisoformat(cast(str, value["UpdatedAt"]))

    if updated.tzinfo is None or updated.utcoffset() is None:
        raise ValueError("native material metadata time requires an explicit timezone")

    return value


def ObserveControl(value: dict[str, object], digest: str,
                   request_identity: tuple[int, ...]) -> bytes:
    """Observe only the four original selected files inside the owned worker.

    Args:
        value: Exact verified private request.
        digest: Parent-bound original request digest.
        request_identity: Parent-bound original request physical metadata.

    Returns:
        Bounded canonical original facts and strict metadata, never file bodies.
    """

    selection = SelectionFromControl(value)
    facts = selection.Material()
    metadata_fact = facts[-1]
    metadata: dict[str, object] | None = None

    if metadata_fact.sha256 is not None:
        path = Path(metadata_fact.path)
        before = PhysicalIdentity(ArtifactPathInfo(path))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

        with os.fdopen(os.open(path, flags), "rb") as source:
            if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != before:
                raise ValueError("native material metadata changed at open")

            raw = source.read(16 * 1024 + 1)

            if PhysicalIdentity(ArtifactHandleInfo(source.fileno())) != before:
                raise ValueError("native material metadata changed during read")

        if before != metadata_fact.physical_identity or (
            PhysicalIdentity(ArtifactPathInfo(path)) != before or
            hashlib.sha256(raw).hexdigest() != metadata_fact.sha256
        ):
            raise ValueError("native material metadata changed after observation")

        metadata = StrictMetadata(raw)

    return CanonicalControl({"schema_version": 1, "request_sha256": digest,
        "request_identity": request_identity, "nonce": value["nonce"],
        "operation_reference": value["operation_reference"],
        "workspace_id": value["workspace_id"], "owner_reference": value["owner_reference"],
        "read_consent": value["read_consent"], "selection": value["selection"],
        "directory_identity": value["directory_identity"],
        "workspace_identity": value["workspace_identity"], "facts": facts, "metadata": metadata})


def Main(argv: list[str] | None = None) -> int:
    """Run the fixed installed private worker without executing selected files.

    Args:
        argv: Fixed request path, SHA256 and comma-separated physical identity.

    Returns:
        Zero for a complete private observation; two for a bounded fixed refusal.
    """

    arguments = sys.argv[1:] if argv is None else argv

    try:
        if len(arguments) != 3 or sys.platform != "linux":
            raise ValueError("native material worker requires the fixed Linux profile")

        identity = ControlIdentity([int(item) for item in arguments[2].split(",")])
        value = ReadControl(Path(arguments[0]), arguments[1], identity)
        raw = ObserveControl(value, arguments[1], identity)
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()

        return 0

    except (OSError, ValueError, TypeError, KeyError):
        sys.stderr.write("native-material-observation-refused\n")

        return 2


if __name__ == "__main__":
    raise SystemExit(Main())
