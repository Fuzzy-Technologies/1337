# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit IOC artifact commands over unchanged local acquisition and replay owners."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Never, TextIO

from fuzzy1337.artifact_inputs import (
    ArtifactHandleInfo,
    ArtifactPathInfo,
    ArtifactReadConsent,
    MatchesArtifactReadIdentity,
    PhysicalIdentity,
)
from fuzzy1337.evidence import EvidenceError, EvidenceRecord
from fuzzy1337.ioc_artifacts import (
    AcquireIocArtifact,
    Header,
    Identity,
    IocAcquisition,
    IocEvidenceStore,
    IocLimits,
    IocRequest,
    IocSnapshot,
    IocSource,
    LoadIocArtifact,
    Metadata,
    OriginalRecord,
    ParseIocArtifact,
    RequestPin,
    Text,
)
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("IocParser", "RunIocCommands")


class IocFailure(RuntimeError):
    """Retain only a trusted diagnostic category and truthful terminal status."""

    def __init__(self, category: str, status: int = 4) -> None:
        """Exclude rejected arguments, physical filenames and original bytes from diagnostics."""

        super().__init__(category)
        self.category = category
        self.status = status


class IocArgumentParser(argparse.ArgumentParser):
    """Suppress framework diagnostics that can reflect untrusted material or metadata."""

    def Error(self, message: str) -> Never:
        """Reject malformed grammar without rendering the supplied untrusted text.

        Args:
            message: Unretained framework diagnostic, which may contain source selections.

        Returns:
            Never returns; the handler receives only a fixed configuration failure.
        """

        raise IocFailure("configuration", 2)

    error = Error


def IocParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare the closed product grammar without reading files, scope or evidence.

    Args:
        action: Optional import/inspect help selection after the explicit ioc namespace.

    Returns:
        Complete trace parser, or its selected known action's parser.
    """

    parser = IocArgumentParser(prog="1337 trace", add_help=False)
    parser.add_argument("profile", choices=("ioc",))
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IocArgumentParser)
    importer = actions.add_parser("import", add_help=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("--file", type=Path, required=True)

    for name in ("source-id", "source-version", "source-locator", "license-name",
                 "license-locator", "expected-sha256", "scope", "owner",
                 "read-consent-reference"):
        importer.add_argument("--" + name, required=True)

    for name, default in IocLimits().ToDict().items():
        importer.add_argument("--" + name.replace("_", "-"), type=int, default=default)

    inspector = actions.add_parser("inspect", add_help=False)
    inspector.add_argument("workspace", type=Path)
    inspector.add_argument("--snapshot", required=True)
    inspector.add_argument("--receipt", required=True)

    return actions.choices[action] if action in actions.choices else parser


def SelectedPath(path: Path) -> Path:
    """Require one bounded absolute physical selection without traversal or control characters.

    Args:
        path: Explicit workspace or source file, never a discovered or source-declared locator.

    Returns:
        Original absolute lexical path; owning guards check physical ancestors before access.
    """

    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts or (
        len(str(path).encode("utf-8")) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in str(path))
    ):
        raise IocFailure("configuration", 2)

    return path


def ReadOwnedIoc(path: Path, consent: ArtifactReadConsent, max_bytes: int) -> bytes:
    """Read one explicitly consented stable singly linked file within the closed IOC ceiling.

    Args:
        path: Absolute explicitly selected source, with observed physical parents.
        consent: Exact existing selected-file read references, not an assessment grant.
        max_bytes: Positive caller ceiling at most the unchanged SDK's 64 KiB maximum.

    Returns:
        Original bytes after full same-view and platform-aware cross-view identity checks.
        This detects observed replacement/mutation; it is not hostile-writer OS isolation.
    """

    if type(consent) is not ArtifactReadConsent:
        raise IocFailure("configuration", 2)

    ArtifactReadConsent(consent.actor_ref, consent.record_ref)

    if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024:
        raise IocFailure("configuration", 2)

    selected = SelectedPath(path)
    before = ArtifactPathInfo(selected)

    if before.st_ino == 0 or before.st_size > max_bytes:
        raise IocFailure("selected-file", 2)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(selected, flags)

    try:
        stream = os.fdopen(descriptor, "rb", closefd=False)

    except BaseException:
        os.close(descriptor)

        raise

    try:
        with stream:
            opened = ArtifactHandleInfo(stream.fileno())

            if not MatchesArtifactReadIdentity(before, opened) or opened.st_size > max_bytes:
                raise IocFailure("selected-file", 2)

            payload = stream.read(max_bytes + 1)
            finished = ArtifactHandleInfo(stream.fileno())

    finally:
        os.close(descriptor)

    after = ArtifactPathInfo(selected)

    if len(payload) > max_bytes or len(payload) != before.st_size or (
        PhysicalIdentity(before) != PhysicalIdentity(after)
        or PhysicalIdentity(opened) != PhysicalIdentity(finished)
        or not MatchesArtifactReadIdentity(after, finished)
    ):
        raise IocFailure("selected-file", 2)

    return payload


def VerifiedAcquisition(root: Path, acquired: IocAcquisition,
                        request: IocRequest, scope: str) -> None:
    """Verify every original typed owning record before describing acquisition as confirmed.

    Args:
        root: Existing physical owning workspace.
        acquired: Exact unchanged SDK terminal result; no foreign wrapper is accepted.
        request: Exact original typed payload/source/budget selection.
        scope: Explicit collection attribution, never execution authorization.

    Raises:
        ValueError: Record type, original provenance, receipt, state or successful reparse differs.
        EvidenceError: Original immutable records or bytes cannot be verified.
    """

    if type(acquired) is not IocAcquisition or type(request) is not IocRequest:
        raise ValueError("IOC command requires exact original acquisition and request types")

    IocRequest(request.payload, request.source, request.limits)

    if type(acquired.state) is not str or acquired.state not in (
        "succeeded", "parse-rejected", "digest-rejected"
    ) or any(type(record) is not EvidenceRecord for record in (acquired.raw, acquired.receipt)):
        raise ValueError("IOC command requires original terminal records and state")

    workspace_id = LocalWorkspaceStore(root).Open().workspace_id
    store = IocEvidenceStore(root / "evidence", request.limits.max_bytes)
    raw = OriginalRecord(acquired.raw, workspace_id, store, "ioc-source")
    receipt = Header(Metadata(OriginalRecord(acquired.receipt, workspace_id, store,
        "ioc-acquisition"), 8192), {"state", "transport", "authentication", "raw_evidence_id",
            "source", "limits", "provenance", "request_sha256"})

    if raw != request.payload or acquired.raw.provenance != acquired.receipt.provenance or (
        acquired.raw.provenance.scope_reference != scope
        or receipt["state"] != acquired.state
        or receipt["transport"] != "caller-supplied-bytes"
        or receipt["authentication"] != "not-assessed"
        or receipt["raw_evidence_id"] != acquired.raw.evidence_id
        or receipt["source"] != request.source.ToDict()
        or receipt["limits"] != request.limits.ToDict()
        or receipt["provenance"] != acquired.receipt.provenance.ToDict()
        or receipt["request_sha256"] != RequestPin(request.source, request.limits)
    ):
        raise ValueError("IOC command terminal result differs from its original acquisition")

    if acquired.state == "succeeded":
        if type(acquired.snapshot_record) is not EvidenceRecord or (
            type(acquired.snapshot) is not IocSnapshot
        ):
            raise ValueError("IOC command success requires exact original snapshot types")

        acquired.snapshot.Serialize()
        verified = LoadIocArtifact(root, acquired.snapshot_record.evidence_id,
                                   acquired.receipt.evidence_id)

        if type(verified) is not IocSnapshot or (
            verified.Serialize() != acquired.snapshot.Serialize()
        ):
            raise ValueError("IOC command snapshot differs from original replay")

        OriginalRecord(acquired.snapshot_record, workspace_id, store, "ioc-snapshot")

    else:
        if acquired.snapshot is not None or acquired.snapshot_record is not None:
            raise ValueError("IOC command refused acquisition cannot supply a usable snapshot")

        expected_state = "digest-rejected"

        if acquired.raw.reference.sha256 == request.source.expected_sha256:
            expected_state = "parse-rejected"

            try:
                ParseIocArtifact(raw, request.source, request.limits)

            except ValueError:
                pass

            else:
                raise ValueError("IOC refusal contradicts independently reparsed original bytes")

        if acquired.state != expected_state:
            raise ValueError("IOC refusal contradicts the original declared and observed digest")


def RunIocCommands(arguments: Sequence[str], output: TextIO, *, json_output: bool = False) -> int:
    """Import explicit non-secret local bytes or inspect an independently anchored snapshot.

    Args:
        arguments: Explicit ioc namespace, action, owning workspace and selected inputs.
        output: Caller-owned presentation stream; untrusted error messages are never copied.
        json_output: Render safe counts and confirmed identifiers, never original source bodies.

    Returns:
        Zero on verified success, two for invalid selections, four for acquisition/integrity
        failure or unknown evidence acknowledgement, and 130 for interruption. Core and
        workspace state are never saved; refused acquisition retains its original raw/receipt.
    """

    parser = IocParser()

    if "--help" in arguments or "-h" in arguments:
        action = arguments[1] if len(arguments) > 1 and arguments[0] == "ioc" else None
        IocParser(action).print_help(file=output)

        return 0

    outcome: dict[str, object] = {"schema_version": 1, "command": "trace.ioc", "status": "failed",
        "failure": None, "acquisition_state": None, "evidence_commit": "not-attempted",
        "raw_id": None, "receipt_id": None, "snapshot_id": None, "candidate_count": None,
        "received_bytes": None, "source_sha256": None, "read_consent": "not-applicable",
        "started_at": None, "finished_at": None,
        "publisher_authentication": "not-assessed",
        "core_mutation": "none"}
    status = 4
    phase = "configuration"

    try:
        options = parser.parse_args(arguments)
        outcome["command"] = "trace.ioc." + options.action
        root = SelectedPath(options.workspace)

        if options.action == "import":
            source = IocSource(options.source_id, options.source_version, options.source_locator,
                options.license_name, options.license_locator, options.expected_sha256)
            limits = IocLimits(options.max_bytes, options.max_lines, options.max_items,
                               options.max_line_bytes, options.max_token_bytes)
            scope = Text(options.scope, "scope")
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
            phase = "workspace"
            ArtifactPathInfo(root, directory=True)
            LocalWorkspaceStore(root).Open()
            phase = "selected-file"
            payload = ReadOwnedIoc(options.file, consent, limits.max_bytes)
            request = IocRequest(payload, source, limits)
            phase = "acquisition"
            outcome["evidence_commit"] = "unknown"
            acquired = AcquireIocArtifact(root, request, scope_reference=scope)
            VerifiedAcquisition(root, acquired, request, scope)
            outcome.update({"acquisition_state": acquired.state, "evidence_commit": "confirmed",
                "raw_id": acquired.raw.evidence_id, "receipt_id": acquired.receipt.evidence_id,
                "snapshot_id": None if acquired.snapshot_record is None else (
                    acquired.snapshot_record.evidence_id),
                "received_bytes": acquired.raw.reference.size_bytes,
                "source_sha256": acquired.raw.reference.sha256,
                "started_at": acquired.raw.provenance.started_at,
                "finished_at": acquired.raw.provenance.finished_at,
                "read_consent": "explicit-selected-file"})

            if acquired.state != "succeeded":
                raise IocFailure(acquired.state)

            snapshot = acquired.snapshot

        else:
            Identity(options.snapshot)
            Identity(options.receipt)
            phase = "integrity"
            ArtifactPathInfo(root, directory=True)
            snapshot = LoadIocArtifact(root, options.snapshot, options.receipt)
            outcome.update({"snapshot_id": options.snapshot, "receipt_id": options.receipt})

        if type(snapshot) is not IocSnapshot:
            raise IocFailure("integrity")

        snapshot.Serialize()
        store = IocEvidenceStore(root / "evidence", snapshot.limits.max_bytes)
        record = store.Get(snapshot.raw_evidence_id)
        OriginalRecord(record, LocalWorkspaceStore(root).Open().workspace_id, store, "ioc-source")
        outcome.update({"status": "completed", "raw_id": snapshot.raw_evidence_id,
            "acquisition_state": "succeeded", "candidate_count": len(snapshot.candidates),
            "source_sha256": record.reference.sha256, "received_bytes": record.reference.size_bytes,
            "started_at": record.provenance.started_at,
            "finished_at": record.provenance.finished_at})
        status = 0

    except IocFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except (OSError, EvidenceError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase in ("configuration", "selected-file") else 4

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    outcome["exit_code"] = status

    if json_output:
        output.write(json.dumps(outcome, sort_keys=True, allow_nan=False) + "\n")

    else:
        output.write("IOC artifact " + str(outcome["status"]) + " (exit " + str(status) + ").\n")

        if status == 0:
            output.write(str(outcome["candidate_count"]) + " supplied candidates; "
                         "publisher authentication and maliciousness are not assessed.\n")

    output.flush()

    return status
