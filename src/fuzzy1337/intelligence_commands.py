# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit local intelligence commands over owning evidence and model stores."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Never, TextIO

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.evidence import (
    CheckStorageEntry,
    EvidenceError,
    EvidenceRecord,
    LocalEvidenceStore,
    RejectManifestConstant,
    UniqueManifestObject,
)
from fuzzy1337.intel_references import SourceOrigin
from fuzzy1337.intelligence import (
    MAX_SOURCE_BYTES,
    ApplyVerifiedEnrichment,
    IntelligenceFeed,
    IntelligenceSnapshot,
    IntelligenceTime,
)
from fuzzy1337.intelligence_acquisition import (
    IMPORTER_ID,
    IMPORTER_VERSION,
    AcquireIntelligenceSnapshot,
    AcquisitionOutcome,
    AcquisitionState,
    LoadAcquiredSnapshot,
    SnapshotRequest,
    SnapshotSource,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError

MAX_RECEIPT_BYTES = 32 * 1024


class IntelFailure(RuntimeError):
    """Carry fixed diagnostics without retaining source bytes or rejected argument values."""

    def __init__(self, category: str, status: int = 4) -> None:
        """Keep only the trusted failure category and process status."""

        super().__init__(category)
        self.category = category
        self.status = status


class IntelArgumentParser(argparse.ArgumentParser):
    """Replace framework errors that can echo filenames, metadata, or rejected values."""

    def Error(self, message: str) -> Never:
        """Reject invalid grammar without rendering the untrusted framework message.

        Args:
            message: Unretained argparse diagnostic that may contain rejected values.

        Returns:
            Never returns; the caller receives the fixed configuration failure.
        """

        raise IntelFailure("configuration", 2)

    error = Error


class BoundedIntelEvidenceStore(LocalEvidenceStore):
    """Bound selected receipt/source/snapshot reads before the owning store loads bytes."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Enforce consumer byte ceilings while preserving the owner's address/hash checks.

        Args:
            reference: Explicit immutable receipt, source, or snapshot content reference.

        Returns:
            Original verified bytes within 32 KiB for receipts or 16 MiB for other selections.
        """

        limit = MAX_RECEIPT_BYTES if reference.role == "intelligence-acquisition" else (
            MAX_SOURCE_BYTES
        )

        if reference.size_bytes > limit:
            raise IntelFailure("limit")

        return super().Read(reference)


def IntelPath(path: Path) -> Path:
    """Validate a finite explicit physical path without following observed links.

    Args:
        path: Explicit workspace or input filename, never inferred from shell context.

    Returns:
        Absolute lexical path after its physical parents pass owning storage checks.
    """

    value = str(path)

    if ".." in path.parts or len(value.encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise IntelFailure("configuration", 2)

    selected = path.absolute()

    for parent in reversed(selected.parents):
        CheckStorageEntry(parent, directory=True)

    return selected


def ReadLocalIntel(path: Path, max_bytes: int) -> bytes:
    """Read one selected regular singly-linked file with one overflow byte for the receipt.

    Args:
        path: Explicit input file with observed physical parents and one owning link.
        max_bytes: Validated positive acquisition ceiling, no greater than 16 MiB.

    Returns:
        At most max_bytes plus one original byte; acquisition retains bounded overflow honestly.
    """

    selected = IntelPath(path)
    metadata = CheckStorageEntry(selected, directory=False)

    if metadata.st_nlink != 1:
        raise IntelFailure("configuration", 2)

    with selected.open("rb") as stream:
        return stream.read(max_bytes + 1)


def VerifiedIntelSelection(
    root: Path, snapshot_id: str, receipt_id: str,
) -> tuple[IntelligenceSnapshot, EvidenceRecord, EvidenceRecord]:
    """Reopen exact local terminal/source/snapshot records and reparse original source bytes.

    Args:
        root: Explicit existing owning workspace.
        snapshot_id: Exact intelligence-snapshot acquisition-manifest identifier.
        receipt_id: Exact successful local terminal receipt with common receiver provenance.

    Returns:
        Verified original snapshot, raw acquisition record, and selected terminal receipt.
    """

    owner = LocalWorkspaceStore(root).Open()
    store = BoundedIntelEvidenceStore(root / "evidence")
    snapshot_record = store.Get(snapshot_id)
    receipt = store.Get(receipt_id)

    if (
        receipt.reference.role != "intelligence-acquisition"
        or receipt.reference.media_type != "application/json"
        or receipt.provenance != snapshot_record.provenance
        or receipt.provenance.workspace_id != owner.workspace_id
        or receipt.provenance.source_id != IMPORTER_ID
        or receipt.provenance.source_version != IMPORTER_VERSION
    ):
        raise IntelFailure("integrity")

    document = json.loads(
        store.Read(receipt.reference), object_pairs_hook=UniqueManifestObject,
        parse_constant=RejectManifestConstant,
    )

    if not isinstance(document, dict):
        raise IntelFailure("integrity")

    limits = document.get("limits")
    source_fields = document.get("source")

    if not isinstance(limits, dict) or not isinstance(source_fields, dict):
        raise IntelFailure("integrity")

    # Preflight both bounded manifests before the existing loader's owning reparse path.
    bounded_snapshot = IntelligenceSnapshot.Deserialize(store.Read(snapshot_record.reference))
    raw_record = store.Get(EvidenceRecord(
        bounded_snapshot.evidence, snapshot_record.provenance,
    ).evidence_id)
    snapshot = LoadAcquiredSnapshot(root, snapshot_id)
    source = SnapshotSource(
        snapshot.feed, snapshot.catalog_version, snapshot.source.origin, snapshot.source.publisher,
        snapshot.source.source_url, snapshot.source.license_name, snapshot.source.license_url,
        source_fields.get("expected_sha256"),
    )
    max_bytes = limits.get("max_bytes")
    timeout_seconds = limits.get("receiver_timeout_seconds")

    if type(max_bytes) is not int or not isinstance(timeout_seconds, (int, float)):
        raise IntelFailure("integrity")

    request = SnapshotRequest(
        source, b"", max_bytes=max_bytes, timeout_seconds=timeout_seconds,
    )

    if raw_record.reference.size_bytes > request.max_bytes or (
        source.expected_sha256 is not None
        and source.expected_sha256 != snapshot.evidence.sha256
    ):
        raise IntelFailure("integrity")

    expected = AcquisitionOutcome(
        AcquisitionState.SUCCEEDED, source, receipt.provenance.started_at,
        receipt.provenance.finished_at, raw_record.reference.size_bytes, True, None,
        "local-bytes", request.max_bytes, request.timeout_seconds,
        raw_record, snapshot, snapshot_record,
    )

    if CanonicalModelJson(document) != CanonicalModelJson(expected.ToDict()):
        raise IntelFailure("integrity")

    return snapshot, raw_record, receipt


def IntelParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare explicit offline import, verified inspection, and one finding's enrichment.

    Args:
        action: Optional known action whose parser is requested for focused help.

    Returns:
        Complete namespace parser, or the known action parser; errors never echo rejected values.
    """

    parser = IntelArgumentParser(prog="1337 intel", add_help=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    importer = actions.add_parser("import", add_help=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("file", type=Path)
    importer.add_argument("--feed", choices=tuple(item.value for item in IntelligenceFeed),
                          required=True)
    importer.add_argument("--catalog-version", required=True)
    importer.add_argument("--origin", choices=tuple(item.value for item in SourceOrigin),
                          required=True)

    for name in ("publisher", "source-url", "license-name", "license-url", "scope"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--expected-sha256")
    importer.add_argument("--max-bytes", type=int, default=MAX_SOURCE_BYTES)

    for name in ("inspect", "apply"):
        selected = actions.add_parser(name, add_help=False)
        selected.add_argument("workspace", type=Path)
        selected.add_argument("--snapshot", required=True)
        selected.add_argument("--receipt", required=True)

        if name == "apply":
            selected.add_argument("--finding", required=True)
            selected.add_argument("--identifier", action="append", required=True)
            selected.add_argument("--expected-revision", type=int, required=True)
            selected.add_argument("--as-of", required=True)
            selected.add_argument("--max-age-seconds", type=int, required=True)
            selected.add_argument("--scope", required=True)
            selected.add_argument("--run", required=True)

    return actions.choices[action] if action in actions.choices else parser


def RunIntelCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute only explicit local selections and print bounded summaries without source bodies.

    Args:
        arguments: Explicit action and its workspace, source or immutable selection arguments.
        output: Caller-owned output stream.
        json_output: Emit the experimental schema-v1 terminal outcome.

    Returns:
        Zero on success, two for configuration rejection, four for failed import/integrity/save,
        or 130 for interruption. A failed save may have committed; the outcome states uncertainty.
    """

    parser = IntelParser()

    if "--help" in arguments or "-h" in arguments:
        IntelParser(arguments[0] if arguments else None).print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "intel", "status": "failed", "failure": None,
        "acquisition_state": None, "snapshot_id": None, "receipt_id": None, "raw_id": None,
        "feed": None, "catalog_version": None, "record_count": None, "source_sha256": None,
        "received_bytes": None, "started_at": None, "finished_at": None,
        "model_revision": None, "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed",
    }
    status = 4
    phase = "configuration"

    try:
        options = parser.parse_args(arguments)
        outcome["command"] = "intel." + options.action
        root = IntelPath(options.workspace)
        phase = "integrity"
        LocalWorkspaceStore(root).Open()

        if options.action == "import":
            phase = "configuration"
            source = SnapshotSource(
                IntelligenceFeed(options.feed), options.catalog_version,
                SourceOrigin(options.origin),
                options.publisher, options.source_url, options.license_name, options.license_url,
                options.expected_sha256,
            )
            request = SnapshotRequest(source, b"", max_bytes=options.max_bytes)
            payload = ReadLocalIntel(options.file, request.max_bytes)
            request = SnapshotRequest(source, payload, max_bytes=request.max_bytes)
            phase = "acquisition"
            acquired = AcquireIntelligenceSnapshot(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value,
                "snapshot_id": (acquired.snapshot_record.evidence_id
                                if acquired.snapshot_record is not None else None),
                "receipt_id": (acquired.receipt.evidence_id
                               if acquired.receipt is not None else None),
                "raw_id": acquired.raw.evidence_id if acquired.raw is not None else None,
                "received_bytes": acquired.received_bytes,
                "started_at": acquired.started_at, "finished_at": acquired.finished_at,
            })

            if acquired.state is not AcquisitionState.SUCCEEDED or acquired.snapshot is None:
                raise IntelFailure("acquisition")

            snapshot = acquired.snapshot

        else:
            snapshot, raw, receipt = VerifiedIntelSelection(root, options.snapshot, options.receipt)
            outcome.update({"snapshot_id": options.snapshot, "receipt_id": receipt.evidence_id,
                            "raw_id": raw.evidence_id, "received_bytes": raw.reference.size_bytes,
                            "started_at": receipt.provenance.started_at,
                            "finished_at": receipt.provenance.finished_at})

        outcome.update({"feed": snapshot.feed.value, "catalog_version": snapshot.catalog_version,
                        "record_count": len(snapshot.records),
                        "source_sha256": snapshot.evidence.sha256})

        if options.action == "apply":
            model = LocalModelStore(root)
            state = model.Open()

            if state.revision != options.expected_revision:
                raise IntelFailure("revision-conflict")

            provenance = ModelProvenance(
                "intelligence-local-cli", options.run, IntelligenceTime(options.as_of),
                options.scope, options.finding, evidence_references=(receipt.reference,),
            )
            proposed, delta = ApplyVerifiedEnrichment(
                state, options.finding, tuple(options.identifier), (snapshot,), provenance, root,
                as_of=options.as_of, max_age_seconds=options.max_age_seconds,
            )
            outcome["model_commit"] = "unknown"
            saved = model.Save(proposed, expected_revision=delta.previous_revision)
            outcome["model_commit"] = "confirmed"
            outcome["model_revision"] = saved.revision

        outcome["status"] = "succeeded"
        status = 0

    except IntelFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except WorkspaceConflictError:
        outcome["failure"] = "revision-conflict"
        outcome["model_commit"] = "not-committed"

    except WorkspaceBusyError:
        outcome["failure"] = "model-busy"
        outcome["model_commit"] = "not-committed"

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except (EvidenceError, OSError, ValueError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    if json_output:
        output.write(CanonicalModelJson(outcome).decode("utf-8") + "\n")

    else:
        output.write(f"{outcome['command']}: {outcome['status']}\n")

        for name in ("snapshot_id", "receipt_id", "raw_id", "model_revision", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {outcome[name]}\n")

    return status
