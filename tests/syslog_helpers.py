# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten inert RFC messages and actual-owner selections for saved-syslog tests."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.syslog_artifacts import SyslogSource
from fuzzy1337.syslog_commands import RunSyslogCommands
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIRST = (b'<13>1 2026-11-25T10:15:30.123456+05:30 h app 42 ID '
         b'[x@32473 a="one" a="two" e="x\\]y\\"z\\\\"] \xef\xbb\xbfcaf\xc3\xa9')
SECOND = b"<0>1 - - - - - -"
THIRD = b"<191>1 2026-11-25T04:45:30.123456Z h app - ID - "
ORIGINAL = FIRST + b"\r\n" + SECOND + b"\n" + THIRD
CONSENT = ArtifactReadConsent("actor:synthetic", "read:synthetic")


def Source(payload: bytes = ORIGINAL, framing: str = "lines") -> SyslogSource:
    """Select an independent checksum and declared source distinct from the parser."""

    return SyslogSource("fixture.syslog", "export-7", "opaque:offline",
                        hashlib.sha256(payload).hexdigest(), framing)


def Owned(parent: Path, payload: bytes = ORIGINAL) -> tuple[Path, Path]:
    """Create an actual empty workspace and independent original file without Core or scope."""

    root = parent / "owned"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Saved log fixture"), "owned-log")
    source = parent / "original.log"
    source.write_bytes(payload)

    return root, source


def Files(root: Path) -> dict[str, bytes]:
    """Capture every ordinary owning file to prove later read-only byte preservation."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def ImportArguments(root: Path, path: Path, payload: bytes = ORIGINAL,
                    framing: str = "lines") -> list[str]:
    """Require every source/file/read selection explicitly without authority defaults."""

    return ["import", str(root), "--file", str(path), "--source-id", "fixture.syslog",
        "--source-version", "export-7", "--source-locator", "opaque:offline",
        "--expected-sha256", hashlib.sha256(payload).hexdigest(), "--framing", framing,
        "--scope", "collection:fixture", "--owner", CONSENT.actor_ref,
        "--read-consent-reference", CONSENT.record_ref]


def InspectArguments(root: Path, result: dict) -> list[str]:
    """Retain the original receipt and source checksum independently of candidate metadata."""

    return ["inspect", str(root), "--receipt", result["receipt_id"],
            "--expected-sha256", result["source_sha256"]]


def Run(arguments: list[str], *, machine: bool = True) -> tuple[int, dict | str]:
    """Run the real handler and decode only its completed finite terminal envelope."""

    output = StringIO()
    status = RunSyslogCommands(arguments, output, jsonOutput=machine)

    return status, json.loads(output.getvalue()) if machine else output.getvalue()
