# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal closed owned artifact lifecycle oracle; no scanner or finding verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import time
from pathlib import Path
from typing import NoReturn


def FixtureFields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate policy fields instead of selecting one ambiguous mode.

    Args:
        pairs: Decoded JSON object fields in source order.

    Returns:
        Exact unique fields; duplicate names raise ValueError.
    """

    fields: dict[str, object] = {}

    for name, value in pairs:
        if name in fields:
            raise ValueError("fixture policy contains duplicate fields")

        fields[name] = value

    return fields


def RejectFixtureConstant(value: str) -> NoReturn:
    """Reject non-JSON numerical constants without reflecting their input spelling.

    Args:
        value: Unsupported decoder constant; never interpreted as a lifecycle mode.

    Returns:
        Never returns; malformed policy raises ValueError.
    """

    raise ValueError("fixture policy contains a non-JSON constant")


def ParseFixturePolicy(payload: bytes) -> str:
    """Parse only bounded strict UTF-8 JSON with exact version and closed lifecycle mode.

    Args:
        payload: At most 4,096 explicitly selected immutable policy bytes.

    Returns:
        One finite typed lifecycle mode; malformed material raises ValueError.
    """

    if not isinstance(payload, bytes) or len(payload) > 4096:
        raise ValueError("fixture policy is oversized or not byte content")

    try:
        policy = json.loads(payload.decode("utf-8"), object_pairs_hook=FixtureFields,
                            parse_constant=RejectFixtureConstant)

    except (UnicodeError, ValueError) as error:
        raise ValueError("fixture policy requires strict UTF-8 JSON") from error

    if not isinstance(policy, dict) or set(policy) != {"schema_version", "fixture_id", "mode"}:
        raise ValueError("fixture policy fields are invalid")

    if (
        type(policy["schema_version"]) is not int or policy["schema_version"] != 1
        or policy["fixture_id"] != "owned-artifact-lifecycle-v1"
    ):
        raise ValueError("fixture policy version or identity is unsupported")

    mode = policy["mode"]

    if not isinstance(mode, str) or mode not in {
        "success", "failure", "wait", "overflow", "mutate", "scratch",
    }:
        raise ValueError("fixture policy mode is unsupported")

    return mode


def Main() -> int:
    """Exercise bounded synthetic lifecycle modes through the fixed profile wire.

    Returns:
        Zero for synthetic lifecycle completion, seven for the owned failure mode.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-policy", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("command", choices=("image", "config"))
    parser.add_argument("--input")
    parser.add_argument("--cache-backend", choices=("memory",), required=True)
    parser.add_argument("--format", choices=("json",), required=True)
    parser.add_argument("--scanners", choices=("vuln",))
    parser.add_argument("--misconfig-scanners", choices=("dockerfile", "kubernetes"))
    parser.add_argument("--ignorefile", required=True)
    parser.add_argument("--exit-code", choices=("0",), required=True)
    parser.add_argument("--timeout", required=True)

    for flag in (
        "disable-telemetry",
        "offline-scan",
        "skip-db-update",
        "skip-java-db-update",
        "skip-check-update",
        "skip-version-check",
        "skip-vex-repo-update",
        "list-all-pkgs",
        "no-progress",
    ):
        parser.add_argument("--" + flag, action="store_true")

    parser.add_argument("target", nargs="?")
    arguments = parser.parse_args()
    try:
        with Path(arguments.fixture_policy).open("rb") as stream:
            mode = ParseFixturePolicy(stream.read(4097))

    except ValueError:
        return 7

    selected = (
        [Path(arguments.input)]
        if arguments.command == "image"
        else sorted(Path(arguments.target).rglob("*"))
    )
    files = [path for path in selected if path.is_file()]

    if mode == "wait":
        print("owned-ready", flush=True)
        time.sleep(60)

    if mode == "overflow":
        print("x" * 65536, flush=True)

    if mode == "mutate":
        files[0].chmod(stat.S_IRUSR | stat.S_IWUSR)
        files[0].write_bytes(b"owned-postlaunch-mutation")

    if mode == "scratch":
        Path("scratch-output.txt").write_bytes(b"owned-scratch")

    if mode == "failure":
        print("owned-partial-output", flush=True)
        print("owned-failure", file=sys.stderr, flush=True)

        return 7

    payload = {
        "fixture_id": "owned-artifact-lifecycle-v1",
        "state": "synthetic-completion",
        "provider_version": "0.75.0-synthetic",
        "files": [
            {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in files
        ],
    }
    print(json.dumps(payload, sort_keys=True), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
