# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify a requested passive CI batch against an immutable reviewed diff manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

MAX_BYTES = 1024 * 1024
MAX_FILES = 512
REQUEST_PREFIX = "feature/passive-batch-"
HEX = re.compile(r"[0-9a-f]{40}\Z")
HEADER = re.compile(
    rb":(000000|100644) (000000|100644) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMD])\Z"
)
PIN = re.compile(rb'^  PASSIVE_POLICY_COMMIT: "([0-9a-f]{40})"$', re.MULTILINE)
PIN_PATH = ".github/workflows/passive-acceptance-routing.yml"


def Changes(payload: bytes) -> list[dict[str, str]]:
    """Require a complete bounded raw NUL diff with full object IDs and regular-file joins.

    Args:
        payload: Complete original output of the declared full-object raw Git diff.

    Returns:
        Ordered exact regular-file changes, without executing candidate contents.
    """

    if not 0 < len(payload) <= MAX_BYTES:
        raise ValueError("diff byte limit")

    parts = payload.split(b"\0")

    if parts[-1] != b"" or len(parts) % 2 != 1 or not 1 <= len(parts) // 2 <= MAX_FILES:
        raise ValueError("diff framing or count")

    result = []
    seen: set[str] = set()

    for index in range(0, len(parts) - 1, 2):
        header = HEADER.fullmatch(parts[index])

        if header is None:
            raise ValueError("diff header")

        oldMode, newMode, oldHash, newHash, status = header.groups()
        zero = b"0" * 40

        if not (
            (status == b"M" and oldMode == newMode == b"100644"
             and oldHash != zero and newHash != zero and oldHash != newHash)
            or (status == b"A" and oldMode == b"000000" and oldHash == zero
                and newMode == b"100644" and newHash != zero)
            or (status == b"D" and oldMode == b"100644" and oldHash != zero
                and newMode == b"000000" and newHash == zero)
        ):
            raise ValueError("diff object join")

        path = parts[index + 1].decode("utf-8", "strict")

        if path in seen or not path or path.startswith("/") or any(
            part in ("", ".", "..") for part in path.split("/")
        ) or any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ValueError("diff path")

        seen.add(path)
        result.append({"path": path, "old_mode": oldMode.decode(), "new_mode": newMode.decode(),
                       "old_blob": oldHash.decode(), "new_blob": newHash.decode()})

    return result


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject repeated manifest members instead of adopting a last-writer interpretation.

    Args:
        pairs: Original JSON object members in their input order.

    Returns:
        Detached object after every member name is verified unique.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest member")

        result[key] = value

    return result


def NormalizedWorkflow(payload: bytes, policy: str) -> bytes:
    """Normalize only the sole policy commit literal in the shared routing workflow.

    Args:
        payload: Exact candidate routing-workflow blob bytes.
        policy: Actual immutable policy commit used by the isolated loader.

    Returns:
        Original bytes with only the one policy commit value replaced by forty zeros.
    """

    if len(payload) > MAX_BYTES:
        raise ValueError("routing blob byte limit")

    matches = list(PIN.finditer(payload))

    if len(matches) != 1 or matches[0][1].decode() != policy:
        raise ValueError("routing policy pin")

    return PIN.sub(b'  PASSIVE_POLICY_COMMIT: "' + b"0" * 40 + b'"', payload)


def Profile(
    payload: bytes, manifest: bytes, *, event: str, base: str, head: str, commit: str,
    policy: str, read: Callable[[str], bytes],
) -> str:
    """Preserve ordinary/master routing and certify only one exact independently reviewed batch.

    Args:
        payload: Complete bounded raw Git diff of the actual base and proposed head.
        manifest: Policy bytes from the independently reviewed immutable policy commit.
        event: Original GitHub event name.
        base: Actual PR base branch, independent from the request branch.
        head: Actual head branch; its prefix only requests verification.
        commit: Exact original PR base commit.
        policy: Immutable policy checkout commit used by the loader.
        read: Bounded exact Git-blob reader for the sole normalized workflow exception.

    Returns:
        Full for ordinary work, passive for the exact reviewed batch, otherwise hold.
    """

    if event != "pull_request" or base != "develop" or not head.startswith(REQUEST_PREFIX):
        return "full"

    try:
        if not HEX.fullmatch(commit) or not HEX.fullmatch(policy) or not (
            0 < len(manifest) <= MAX_BYTES
        ):
            raise ValueError("manifest input bounds")

        expected = json.loads(manifest, object_pairs_hook=UniqueObject)

        if not isinstance(expected, dict) or set(expected) != {
            "schema_version", "base_commit", "head_ref", "changes",
        } or type(expected["schema_version"]) is not int or expected["schema_version"] != 1 or (
            expected["base_commit"] != commit or expected["head_ref"] != head
        ):
            raise ValueError("manifest selection")

        actual = Changes(payload)
        selected = expected["changes"]

        if not isinstance(selected, list) or len(selected) != len(actual):
            raise ValueError("manifest inventory")

        for observed, record in zip(actual, selected, strict=True):
            if not isinstance(record, dict):
                raise ValueError("manifest record")

            if record == observed:
                continue

            if set(record) != set(observed) | {"normalized_sha256"} or (
                record["path"] != PIN_PATH or record["new_blob"] is not None
                or observed["new_mode"] != "100644"
                or any(record[key] != observed[key] for key in observed if key != "new_blob")
                or not isinstance(record["normalized_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["normalized_sha256"])
            ):
                raise ValueError("manifest content")

            normalized = NormalizedWorkflow(read(observed["new_blob"]), policy)

            if hashlib.sha256(normalized).hexdigest() != record["normalized_sha256"]:
                raise ValueError("workflow content")

    except (ValueError, UnicodeError, OSError, RecursionError, subprocess.SubprocessError):
        return "hold"

    return "passive"


def Main() -> int:
    """Read trusted manifest and bounded raw diff, then emit one fixed GitHub routing output.

    Returns:
        Zero after reporting the explicit full, passive or held profile.
    """

    parser = argparse.ArgumentParser()

    for name in ("event", "base", "head-ref", "base-commit", "policy-commit", "manifest"):
        parser.add_argument("--" + name, required=True)

    options = parser.parse_args()
    payload = sys.stdin.buffer.read(MAX_BYTES + 1)

    def ReadBlob(reference: str) -> bytes:
        """Read an exact Git blob without checking out or executing candidate code.

        Args:
            reference: Full validated candidate object identifier from the complete raw diff.

        Returns:
            Exact original blob bytes after the metadata byte ceiling is verified.
        """

        size = subprocess.run(["git", "--no-replace-objects", "cat-file", "-s", reference],
                              check=True, capture_output=True, timeout=10).stdout

        if not size.strip().isdigit() or not 0 < int(size) <= MAX_BYTES:
            raise ValueError("routing blob byte limit")

        return subprocess.run(["git", "--no-replace-objects", "cat-file", "blob", reference],
                              check=True,
                              capture_output=True, timeout=10).stdout

    try:
        with Path(options.manifest).open("rb") as stream:
            manifest = stream.read(MAX_BYTES + 1)

    except OSError:
        manifest = b""

    profile = Profile(payload, manifest, event=options.event, base=options.base,
                      head=options.head_ref, commit=options.base_commit,
                      policy=options.policy_commit, read=ReadBlob)
    print(f"profile={profile}")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
