# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned IOC command inputs and actual-store helpers, without authority or discovery defaults."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path

from fuzzy1337.ioc_commands import RunIocCommands
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

RAW = (b"ipv4\t192.0.2.7\r\nipv6\t2001:0DB8::1\ndns\tEXAMPLE.Invalid.\nsha256\t" + b"A" * 64
       + b"\ndns\texample.invalid\t2099-01-01T12:00:00+05:30\t+05:30\n")


def Owned(tmp_path: Path, raw: bytes = RAW) -> tuple[Path, Path]:
    """Create real isolated workspace/model and an explicitly supplied synthetic source file."""

    root = tmp_path / "owned workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned IOC CLI"), "owned")
    LocalModelStore(root).Create()
    source = tmp_path / "owned candidate.tsv"
    source.write_bytes(raw)

    return root, source


def ImportArguments(root: Path, source: Path, raw: bytes = RAW) -> list[str]:
    """Select one physical file, independent opaque attribution, exact pin and read references."""

    return ["ioc", "import", str(root), "--file", str(source), "--source-id", "owned.synthetic",
        "--source-version", "fixture-1", "--source-locator", r"C:\owned\opaque.tsv",
        "--license-name", "Apache-2.0", "--license-locator", "owned:LICENSE",
        "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--scope", "scope:owned",
        "--owner", "owner:fixture", "--read-consent-reference", "read:owned-non-secret"]


def InspectArguments(root: Path, result: dict) -> list[str]:
    """Require independently retained original receipt and snapshot manifest pins."""

    return ["ioc", "inspect", str(root), "--snapshot", result["snapshot_id"],
            "--receipt", result["receipt_id"]]


def Run(arguments: list[str]) -> tuple[int, dict]:
    """Execute the actual handler over real owners and require one safe terminal JSON outcome."""

    output = StringIO()
    status = RunIocCommands(arguments, output, json_output=True)
    result = json.loads(output.getvalue())
    assert result["exit_code"] == status, "IOC command process and structured status disagree"

    return status, result


def Files(root: Path) -> dict[str, bytes]:
    """Capture only this owned test workspace's files for exact no-write assertions."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}
