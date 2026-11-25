# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compose explicit retained local intelligence selections into one verified finding proposal."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO, cast

from fuzzy1337.adapters.contracts import EvidenceReference, JsonValue
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceError,
    EvidenceRecord,
    ParseEvidenceManifest,
)
from fuzzy1337.intelligence import (
    MAX_SOURCE_BYTES,
    ApplyVerifiedEnrichment,
    IntelligenceSnapshot,
    IntelligenceTime,
)
from fuzzy1337.intelligence_acquisition import IMPORTER_ID, IMPORTER_VERSION
from fuzzy1337.intelligence_commands import (
    MAX_INSPECTION_BYTES,
    MAX_RECEIPT_BYTES,
    BoundedIntelEvidenceStore,
    IntelArgumentParser,
    IntelFailure,
    IntelIdentifiers,
    IntelPath,
    VerifiedIntelSelection,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError

__all__ = ["RunIntelSetCommands"]

MAX_SET_SOURCES = 16
MAX_SET_SNAPSHOT_BYTES = MAX_SOURCE_BYTES
MAX_SET_RAW_BYTES = MAX_SOURCE_BYTES
MAX_SET_RECEIPT_BYTES = MAX_SET_SOURCES * MAX_RECEIPT_BYTES
MAX_SET_OUTPUT_BYTES = 2 * MAX_INSPECTION_BYTES


def SetParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare explicit multiple-source operations without reading any local owner.

    Args:
        action: Optional exact known action for help discovery.

    Returns:
        Closed complete parser or its selected action parser.
    """

    parser = IntelArgumentParser(prog="1337 intel", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)

    for name in ("preview-set", "apply-set"):
        selected = actions.add_parser(name, add_help=False, allow_abbrev=False)
        selected.add_argument("workspace", type=Path)
        selected.add_argument("--selection", action="append", nargs=2, required=True,
                              metavar=("SNAPSHOT", "RECEIPT"))
        selected.add_argument("--finding", required=True)
        selected.add_argument("--identifier", action="append", required=True)
        selected.add_argument("--expected-revision", type=int, required=True)
        selected.add_argument("--as-of", required=True)
        selected.add_argument("--max-age-seconds", type=int, required=True)
        selected.add_argument("--scope", required=True)
        selected.add_argument("--run", required=True)

    return actions.choices[action] if action in actions.choices else parser


def SetSelections(values: list[list[str]]) -> tuple[tuple[str, str], ...]:
    """Validate the complete explicit set before accessing any selected storage.

    Args:
        values: Caller-supplied original snapshot/receipt manifest pairs.

    Returns:
        Two to sixteen unique snapshot roots and unique receipt roots, in caller order.
    """

    if not 2 <= len(values) <= MAX_SET_SOURCES:
        raise IntelFailure("configuration", 2)

    if any(len(pair) != 2 or any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
                                for item in pair) for pair in values):
        raise IntelFailure("configuration", 2)

    selections = tuple((pair[0], pair[1]) for pair in values)

    if len({pair[0] for pair in selections}) != len(selections) or (
        len({pair[1] for pair in selections}) != len(selections)
    ):
        raise IntelFailure("configuration", 2)

    return selections


def SetManifest(store: BoundedIntelEvidenceStore, identity: str) -> EvidenceRecord:
    """Read only canonical selected manifest metadata, without triggering its eager blob read.

    Args:
        store: Existing bounded evidence owner within the explicit workspace.
        identity: Already syntax-validated original manifest ID.

    Returns:
        Exact hash-bound manifest; its body is not trusted or read by this preflight.
    """

    payload = store.ReadStoredBytes(("records", identity[7:] + ".json"),
                                   EVIDENCE_MANIFEST_MAX_BYTES)
    record = ParseEvidenceManifest(payload)

    if record.evidence_id != identity:
        raise IntelFailure("integrity")

    return record


def PreflightSet(root: Path, selections: tuple[tuple[str, str], ...]) -> None:
    """Bound total selected snapshots, receipts and originals before original-source reads.

    Args:
        root: Explicit owning workspace with its unchanged local evidence partition.
        selections: Complete validated original local snapshot/receipt pair selection.

    Returns:
        None after manifest identity, local roles and aggregate allocation ceilings pass.
        No preflight record supplies a usable result or substitutes for original verification.
    """

    owner = LocalWorkspaceStore(root).Open()
    store = BoundedIntelEvidenceStore(root / "evidence")
    records: list[EvidenceRecord] = []
    snapshotBytes = 0
    receiptBytes = 0

    for snapshotId, receiptId in selections:
        snapshot = SetManifest(store, snapshotId)
        receipt = SetManifest(store, receiptId)

        if snapshot.reference.role != "intelligence-snapshot" or (
            snapshot.reference.media_type != "application/json"
            or receipt.reference.role != "intelligence-acquisition"
            or receipt.reference.media_type != "application/json"
            or receipt.reference.size_bytes > MAX_RECEIPT_BYTES
            or snapshot.provenance != receipt.provenance
            or receipt.provenance.workspace_id != owner.workspace_id
            or receipt.provenance.source_id != IMPORTER_ID
            or receipt.provenance.source_version != IMPORTER_VERSION
        ):
            raise IntelFailure("integrity")

        snapshotBytes += snapshot.reference.size_bytes
        receiptBytes += receipt.reference.size_bytes

        if snapshotBytes > MAX_SET_SNAPSHOT_BYTES or receiptBytes > MAX_SET_RECEIPT_BYTES:
            raise IntelFailure("selection-limit")

        records.append(snapshot)

    rawBytes = 0

    for record in records:
        snapshotValue = IntelligenceSnapshot.Deserialize(store.Read(record.reference))
        rawBytes += snapshotValue.evidence.size_bytes

        if rawBytes > MAX_SET_RAW_BYTES:
            raise IntelFailure("selection-limit")


def SetRender(outcome: dict[str, object], machine: bool) -> str:
    """Prepare a complete escaped terminal response before one checked write.

    Args:
        outcome: Trusted staged set result; failed results contain no selections or proposal.
        machine: Render the distinct terminal JSON profile instead of human metadata.

    Returns:
        Complete bounded ASCII-safe text, with no silent result truncation.
    """

    text = json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    if not machine:
        text = ("Intelligence source set " + str(outcome["status"]) + " (exit "
                + str(outcome["exit_code"]) + ").\n" + text)

    if len(text.encode("ascii")) > MAX_SET_OUTPUT_BYTES:
        raise IntelFailure("presentation-limit")

    return text


def RunIntelSetCommands(arguments: Sequence[str], output: TextIO, *,
                        jsonOutput: bool = False) -> int:
    """Verify all selected local originals and propose or save one combined candidate observation.

    Args:
        arguments: Explicit set action, original pairs, finding, revision and interpretation basis.
        output: Caller-owned terminal; rejected values and exception text are never reflected.
        jsonOutput: Present the bounded experimental original-set envelope as ASCII-safe JSON.

    Returns:
        Zero on complete success, two on invalid selection, four on verification/save/output
        refusal and 130 on interruption. Preview never saves; apply calls the existing CAS once.
        Any save uncertainty remains explicit, with no automatic retry or rollback claim.
    """

    selections = list(arguments)

    if len(selections) == 2 and selections[0] in ("preview-set", "apply-set") and (
        selections[1] in ("--help", "-h")
    ):
        SetParser(selections[0]).print_help(file=output)

        return 0

    outcome: dict[str, object] = {"schema_version": 1, "profile": "local-intelligence-set-cli-v1",
        "command": "intel.source-set", "status": "failed", "failure": None,
        "model_revision": None, "model_commit": "not-attempted",
        "evidence_commit": "not-attempted", "target_applicability": "not-evaluated",
        "publisher_authentication": "not-assessed"}
    status = 4
    phase = "configuration"
    details: list[dict[str, object]] = []
    preview: dict[str, object] | None = None

    try:
        options = SetParser().parse_args(arguments)
        selected = SetSelections(options.selection)
        identifiers = IntelIdentifiers(options.identifier)
        observed = IntelligenceTime(options.as_of)

        if options.expected_revision < 0 or not 0 <= options.max_age_seconds <= 10 * 365 * 86400:
            raise IntelFailure("configuration", 2)

        provenance = ModelProvenance("intelligence-local-cli", options.run, observed,
            options.scope, options.finding)
        root = IntelPath(options.workspace)
        phase = "integrity"
        PreflightSet(root, selected)
        snapshots: list[IntelligenceSnapshot] = []
        receipts: list[EvidenceReference] = []

        for snapshotId, receiptId in selected:
            snapshot, raw, receipt = VerifiedIntelSelection(root, snapshotId, receiptId)
            snapshots.append(snapshot)
            receipts.append(receipt.reference)
            details.append({"snapshot_id": snapshotId, "receipt_id": receiptId,
                "raw_id": raw.evidence_id, "snapshot_reference": snapshot.Reference(),
                "feed": snapshot.feed.value, "catalog_version": snapshot.catalog_version,
                "source_sha256": raw.reference.sha256, "received_bytes": raw.reference.size_bytes,
                "record_count": len(snapshot.records)})

        model = LocalModelStore(root)
        state = model.Open()
        outcome["command"] = "intel." + options.action
        outcome["model_revision"] = state.revision

        if state.revision != options.expected_revision:
            raise IntelFailure("revision-conflict")

        provenance = ModelProvenance(provenance.source_id, provenance.run_reference,
            provenance.observed_at, provenance.scope_reference, provenance.target_reference,
            evidence_references=tuple(receipts))
        proposed, delta = ApplyVerifiedEnrichment(state, options.finding, identifiers,
            tuple(snapshots), provenance, root, as_of=observed,
            max_age_seconds=options.max_age_seconds)
        preview = {"profile_version": 1, "finding_reference": options.finding,
            "proposed_revision": proposed.revision, "already_applied": not delta.created,
            "observations": [
                {"reference": item.Reference(), **cast(dict[str, object], JsonValue(item))}
                for item in proposed.observations if item.Reference() in delta.created
            ], "target_applicability": "not-evaluated"}

        if len(CanonicalModelJson(preview)) > MAX_INSPECTION_BYTES:
            raise IntelFailure("inspection-limit")

        # Bound even apply's complete successful presentation before the irreversible CAS attempt.
        success = {**outcome, "status": "succeeded", "exit_code": 0,
                   "selections": details, "preview": preview,
                   "model_revision": proposed.revision if options.action == "apply-set" else (
                       state.revision),
                   "model_commit": "confirmed" if options.action == "apply-set" else (
                       "not-attempted")}
        SetRender(success, jsonOutput)

        if options.action == "apply-set":
            outcome["model_commit"] = "unknown"
            outcome["model_revision"] = None
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

    except (EvidenceError, OSError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    if status == 0:
        outcome["selections"] = details
        outcome["preview"] = preview

    else:
        outcome["status"] = "failed"

    outcome["exit_code"] = status

    try:
        rendered = SetRender(outcome, jsonOutput)

    except KeyboardInterrupt:
        outcome.pop("selections", None)
        outcome.pop("preview", None)
        outcome.update({"status": "failed", "failure": "interrupted", "exit_code": 130})
        status = 130
        rendered = json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    except (IntelFailure, ValueError, TypeError, OverflowError, RecursionError):
        outcome.pop("selections", None)
        outcome.pop("preview", None)
        outcome.update({"status": "failed", "failure": "presentation-limit", "exit_code": 4})
        status = 4
        rendered = json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    try:
        written = output.write(rendered)

        if written != len(rendered):
            return 4

        output.flush()

    except KeyboardInterrupt:
        return 130

    except (OSError, ValueError):
        return 4

    return status
