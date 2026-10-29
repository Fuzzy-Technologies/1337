# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded offline product report export; internal consumers of the existing owning stores."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Never, TextIO

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import (
    CheckStorageEntry,
    EvidenceError,
    EvidenceIntegrityError,
    LocalEvidenceStore,
)
from fuzzy1337.model import LocalModelStore, Relation, SecurityObject
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.reporting import MAX_REPORT_BYTES, ReportSnapshot, VerifyReportEvidence
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    StoragePathInfo,
    SyncStorageDirectory,
    WorkspaceState,
)

MAX_EXPORT_ACQUISITIONS = 1024
MAX_EXPORT_BLOBS = 1024
MAX_EXPORT_BLOB_BYTES = 32 * 1024 * 1024
MAX_EXPORT_EVIDENCE_BYTES = 128 * 1024 * 1024
MAX_EXPORT_SCOPES = 256


class ReportFailure(RuntimeError):
    """Carry a fixed consumer diagnostic without rejected arguments or exception text."""

    def __init__(self, kind: str, status: int = 4, *, published: bool = False) -> None:
        """Retain a trusted category and confirmed publication state for terminal presentation.

        Args:
            kind: Fixed diagnostic category, never rejected arguments or exception text.
            status: Command exit status for this failure.
            published: Whether the selected complete output was already atomically linked.
        """

        super().__init__(kind)
        self.kind = kind
        self.status = status
        self.published = published


class ReportArgumentParser(argparse.ArgumentParser):
    """Preserve argparse grammar while replacing diagnostics that echo rejected argument values."""

    def Error(self, message: str) -> Never:
        """Reject configuration with a fixed category; the framework message stays unretained.

        Args:
            message: Unretained argparse diagnostic that may contain rejected argument values.

        Returns:
            Never returns; configuration fails without rendering framework diagnostic text.
        """

        raise ReportFailure("configuration", 2)

    # argparse requires its callback spelling; authored methods retain house-style names.
    error = Error


class BoundedReportEvidenceStore(LocalEvidenceStore):
    """Add only consumer read quotas; ownership, parsing and byte integrity remain in the store."""

    def __init__(self, root: Path) -> None:
        """Retain one existing owning store and an invocation-local distinct-byte budget.

        Args:
            root: Existing physical workspace evidence root.
        """

        super().__init__(root)
        self.seen: dict[str, int] = {}

    def Check(self, reference: EvidenceReference) -> None:
        """Bound actual stored bytes before any owning raw read, without following input links.

        Args:
            reference: Owned canonical content reference whose actual stored size is checked.
        """

        if reference.locator != f"blobs/sha256/{reference.sha256}":
            raise EvidenceIntegrityError("report evidence must use its canonical content address")

        path = self.StoragePath(("blobs", "sha256", reference.sha256))
        metadata = CheckStorageEntry(path, directory=False)

        if metadata.st_nlink != 1 or metadata.st_size != reference.size_bytes:
            raise EvidenceIntegrityError("report evidence size or physical ownership differs")

        if metadata.st_size > MAX_EXPORT_BLOB_BYTES:
            raise ReportFailure("limit")

        proposed = {**self.seen, reference.sha256: metadata.st_size}

        if len(proposed) > MAX_EXPORT_BLOBS or sum(proposed.values()) > MAX_EXPORT_EVIDENCE_BYTES:
            raise ReportFailure("limit")

        self.seen = proposed

    def Read(self, reference: EvidenceReference) -> bytes:
        """Apply quotas to direct reads and the owner's Get path before delegating verification.

        Args:
            reference: Owned reference reached directly or through an acquisition manifest.

        Returns:
            Original bytes after the existing owner verifies their exact length and digest.
        """

        self.Check(reference)

        return super().Read(reference)


@dataclass(frozen=True, slots=True)
class ReportInput:
    """Pin one owner-read workspace/model projection without another authoritative store."""

    workspace: WorkspaceState
    report: ReportSnapshot


def OpenReportInput(root: Path) -> ReportInput:
    """Reopen retained acquisitions/context before verifying the exact saved model projection.

    Args:
        root: Explicit existing physical workspace selected for this invocation.

    Returns:
        Owner-read workspace and byte-verified report of its exact saved model.
    """

    workspace = LocalWorkspaceStore(root).Open()
    state = LocalModelStore(root).Open()
    report = ReportSnapshot(state)
    evidence = BoundedReportEvidenceStore(root / "evidence")
    scopes = set(workspace.scope_references)

    if len(workspace.evidence_record_references) > MAX_EXPORT_ACQUISITIONS:
        raise ReportFailure("limit")

    for reference in workspace.evidence_references:
        evidence.Read(reference)

    for record_id in workspace.evidence_record_references:
        record = evidence.Get(record_id)

        if record.provenance.workspace_id != workspace.workspace_id:
            raise EvidenceIntegrityError("report acquisition belongs to a different workspace")

        scopes.add(record.provenance.scope_reference)

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)

    for entity in entities:
        scopes.update(record.scope_reference for record in entity.provenance)

    scopes.update(item.provenance.scope_reference for item in state.observations)

    if len(scopes) > MAX_EXPORT_SCOPES:
        raise ReportFailure("limit")

    scope_store = LocalScopeStore(root)

    for scope_reference in sorted(scopes):
        if not scope_reference.startswith("scope:"):
            raise ValueError("report scope must name an existing workspace-local scope")

        scope_store.Open(scope_reference[6:])

    for reference in report.EvidenceReferences():
        evidence.Check(reference)

    # The immutable references are quota-checked before this owner's second read path.
    # Its own size check also rejects growth before loading bytes, without claiming live freshness.
    verified = VerifyReportEvidence(report, root)

    return ReportInput(workspace, verified)


def RequireReportPath(path: Path) -> Path:
    """Accept one finite explicit path without traversal or control-bearing components.

    Args:
        path: Explicit input or output path, never inferred from shell context.

    Returns:
        Absolute selected path after configuration validation.
    """

    value = str(path)

    if ".." in path.parts or len(value.encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ReportFailure("configuration", 2)

    return path.absolute()


def ReportOutputPath(destination: Path, root: Path) -> Path:
    """Require a new selected output in an existing physical parent outside the source workspace.

    Args:
        destination: Explicit new output filename whose physical parent already exists.
        root: Selected workspace boundary in which derived output is forbidden.

    Returns:
        Validated absolute destination without creating or replacing any file.
    """

    destination = RequireReportPath(destination)
    source_metadata = StoragePathInfo(root)

    if (
        source_metadata is None or not stat.S_ISDIR(source_metadata.st_mode)
        or source_metadata.st_ino <= 0 or destination.is_relative_to(root)
    ):
        raise ReportFailure("configuration", 2)

    for directory in (*reversed(destination.parent.parents), destination.parent):
        metadata = StoragePathInfo(directory)

        if (
            metadata is None or not stat.S_ISDIR(metadata.st_mode) or metadata.st_ino <= 0
            or os.path.samestat(source_metadata, metadata)
        ):
            raise ReportFailure("configuration", 2)

    if StoragePathInfo(destination) is not None:
        raise ReportFailure("configuration", 2)

    return destination


def ConfirmReportPublication(destination: Path, owned_metadata: os.stat_result | None) -> bool:
    """Confirm a lost link acknowledgement using only the original private file's identity.

    Args:
        destination: Selected output inspected without following links or reparse points.
        owned_metadata: Original fstat identity of the completely written private file.

    Returns:
        True only for the same physical regular file and size; equal foreign bytes do not count.
        Missing, unsafe or unreadable metadata cannot confirm a publication.
    """

    if owned_metadata is None or owned_metadata.st_ino <= 0:
        return False

    try:
        observed = StoragePathInfo(destination)

    except (OSError, ValueError):
        return False

    return (
        observed is not None and stat.S_ISREG(observed.st_mode)
        and os.path.samestat(owned_metadata, observed)
        and owned_metadata.st_size == observed.st_size
    )


def CheckReportSnapshot(root: Path, original: ReportInput) -> None:
    """Compare once before publication rather than substituting a newer saved model or scope.

    Args:
        root: Explicit existing workspace reopened through its owners.
        original: Previously owner-read workspace/model projection selected for export.
    """

    workspace = LocalWorkspaceStore(root).Open()
    state = LocalModelStore(root).Open()

    if workspace != original.workspace or ReportSnapshot(state).SnapshotDigest() != (
        original.report.SnapshotDigest()
    ):
        raise ReportFailure("input-changed")


def PublishReport(destination: Path, payload: bytes) -> None:
    """Publish complete selected bytes without clobbering, retaining post-link failure truth.

    Args:
        destination: Validated new selected file in an existing physical parent.
        payload: Complete bounded report bytes serialized before publication.
    """

    temporary: Path | None = None
    published = False
    owned_metadata: os.stat_result | None = None

    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".1337-report-", suffix=".pending",
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)

            if stream.write(payload) != len(payload):
                raise OSError("report temporary write was incomplete")

            stream.flush()
            os.fsync(stream.fileno())
            owned_metadata = os.fstat(stream.fileno())

        os.link(temporary, destination)
        published = True
        temporary.unlink()
        temporary = None
        SyncStorageDirectory(destination.parent)

    except KeyboardInterrupt as error:
        if not published:
            published = ConfirmReportPublication(destination, owned_metadata)

        raise ReportFailure("interrupted", 130, published=published) from error

    except OSError as error:
        if not published:
            published = ConfirmReportPublication(destination, owned_metadata)

        raise ReportFailure("publication", published=published) from error

    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)

            except KeyboardInterrupt as error:
                raise ReportFailure("interrupted", 130, published=published) from error

            except OSError as error:
                raise ReportFailure("publication", published=published) from error


def ReportParser() -> argparse.ArgumentParser:
    """Declare one explicit export command; output format and new filename are always required.

    Returns:
        Parser that rejects invalid configuration without retaining rejected arguments.
    """

    parser = ReportArgumentParser(prog="1337 report", add_help=False)
    parser.add_argument("action", choices=("export",))
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--format", choices=("json", "sarif", "html", "junit"), required=True)
    parser.add_argument("--output", type=Path, required=True)

    return parser


def RunReportCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Export the saved model using existing owners and render only a safe command outcome.

    Args:
        arguments: Explicit product action, existing workspace, format and new output path.
        output: Caller-owned terminal stream; report bytes go only to the selected output file.
        json_output: Emit a schema-v1 outcome instead of concise human presentation.

    Returns:
        Zero for completed export, two for invalid configuration, or four for read/render/publish
        failure, or 130 for interruption. Source outcomes never control export status.
    """

    parser = ReportParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "report.export", "status": "failed",
        "format": None, "model_revision": None, "snapshot_sha256": None,
        "report_sha256": None, "size_bytes": None, "output_published": False,
        "scan_completeness": "not-assessed", "verified_retained_acquisitions": None,
        "checked_model_evidence_references": None, "failure": None,
    }
    status = 4
    phase = "integrity"

    try:
        options = parser.parse_args(arguments)
        outcome["format"] = options.format
        phase = "configuration"
        root = RequireReportPath(options.workspace)
        metadata = StoragePathInfo(root)

        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            raise ReportFailure("configuration", 2)

        phase = "configuration"
        destination = ReportOutputPath(options.output, root)
        phase = "integrity"
        original = OpenReportInput(root)
        outcome.update({
            "model_revision": original.report.state.revision,
            "snapshot_sha256": original.report.SnapshotDigest(),
            "verified_retained_acquisitions": len(original.workspace.evidence_record_references),
            "checked_model_evidence_references": len(original.report.EvidenceReferences()),
        })
        phase = "rendering"

        if options.format == "html":
            payload = RenderHtml(original.report)

        elif options.format == "junit":
            payload = SerializeJunit(original.report)

        else:
            payload = SerializeJson(original.report) if options.format == "json" else (
                SerializeSarif(original.report)
            )

        if len(payload) > MAX_REPORT_BYTES:
            raise ReportFailure("limit")

        outcome.update({"report_sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload)})
        phase = "integrity"
        CheckReportSnapshot(root, original)
        phase = "publication"
        PublishReport(destination, payload)
        outcome.update({"status": "completed", "output_published": True})
        status = 0

    except ReportFailure as error:
        outcome.update({"failure": error.kind, "output_published": error.published})
        status = error.status

    except (EvidenceError, OSError, ValueError, TypeError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except Exception:
        outcome["failure"] = "internal"
        status = 4

    if json_output:
        output.write(json.dumps(outcome, sort_keys=True, allow_nan=False) + "\n")

    elif status:
        output.write(f"Report export failed: {outcome['failure']}.\n")

    else:
        output.write(f"Exported {str(outcome['format']).upper()} report from model revision "
                     f"{outcome['model_revision']}; scan completeness was not assessed.\n")

    output.flush()

    return status
