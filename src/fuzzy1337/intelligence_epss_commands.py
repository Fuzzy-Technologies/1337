# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit local EPSS selection commands with separate custody and output profiles."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO, cast

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.intel_references import RequireReferenceText, SourceOrigin
from fuzzy1337.intelligence_commands import (
    IntelArgumentParser,
    IntelDisplay,
    IntelFailure,
    IntelPath,
    ReadLocalIntel,
)
from fuzzy1337.intelligence_epss_acquisition import (
    AcquireLocalEpssSelection,
    EpssAcknowledgement,
    EpssAcquiredSelection,
    EpssAcquisitionOutcome,
    EpssAcquisitionState,
    EpssLocalRequest,
    EpssLocalSource,
    LoadAcquiredEpssSelection,
)
from fuzzy1337.intelligence_epss_selection import MAX_COMPRESSED_BYTES, RequestedIds
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore


def EpssIntelParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare only explicit offline import and exact read-only selection inspection.

    Args:
        action: Optional known action for focused help without opening a workspace.

    Returns:
        Namespace or action parser; invalid grammar never echoes rejected source values.
    """

    parser = IntelArgumentParser(prog="1337 intel epss", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    importer = actions.add_parser("import", add_help=False, allow_abbrev=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("file", type=Path)
    importer.add_argument("--identifier", action="append", required=True)
    importer.add_argument("--terms-url", action="append", required=True)
    importer.add_argument("--origin", choices=tuple(item.value for item in SourceOrigin),
                          required=True)

    for name in ("model-version", "score-date", "publisher", "source-url", "license-name",
                 "license-url", "scope"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--expected-sha256")
    importer.add_argument("--max-bytes", type=int, default=MAX_COMPRESSED_BYTES)
    selected = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    selected.add_argument("workspace", type=Path)
    selected.add_argument("--selection", required=True)
    selected.add_argument("--receipt", required=True)

    return actions.choices[action] if action in actions.choices else parser


def EpssArguments(arguments: Sequence[str]) -> None:
    """Reject ambiguous repeated scalar options before parsing or any local reads.

    Args:
        arguments: Explicit namespace arguments; only identifiers and terms may repeat.
    """

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--") and name not in ("--identifier", "--terms-url"):
            if name in seen:
                raise IntelFailure("configuration", 2)

            seen.add(name)


def EpssCustodyComplete(acquired: EpssAcquisitionOutcome) -> bool:
    """Require complete bytes and independently acknowledged handles before usable success.

    Args:
        acquired: Actual SDK terminal result, including uncertain storage publication facts.

    Returns:
        Whether every required artifact and its acknowledgement was returned successfully.
    """

    return (
        acquired.state is EpssAcquisitionState.SUCCEEDED and acquired.body_complete
        and acquired.raw_ack is EpssAcknowledgement.CONFIRMED
        and acquired.selection_ack is EpssAcknowledgement.CONFIRMED
        and acquired.receipt_ack is EpssAcknowledgement.CONFIRMED
        and acquired.raw is not None and acquired.envelope is not None
        and acquired.selection_record is not None and acquired.receipt is not None
    )


def WriteEpssDetails(envelope: EpssAcquiredSelection, output: TextIO) -> None:
    """Present all selected assertions, explicit source terms and unmatched IDs safely.

    Args:
        envelope: Verified or fully acknowledged acquired source selection.
        output: Caller-owned human-readable output stream.
    """

    source = envelope.source
    selected = envelope.selection
    output.write("Source assertions; target applicability has not been evaluated.\n")
    output.write("EPSS predicts exploitation of the CVE in the next 30 days.\n")
    output.write("Publisher authentication: not assessed.\n")
    output.write(f"Origin (declared): {IntelDisplay(source.origin.value)}\n")
    output.write(f"Publisher (declared): {IntelDisplay(source.publisher)}\n")
    output.write(f"Source: {IntelDisplay(source.source_url)}\n")
    output.write(f"License (declared): {IntelDisplay(source.license_name)}; "
                 f"{IntelDisplay(source.license_url)}\n")

    for url in source.terms_urls:
        output.write(f"Terms (declared): {IntelDisplay(url)}\n")

    output.write(f"Source model: {IntelDisplay(selected.model_version)}; "
                 f"score date: {IntelDisplay(selected.score_date)}; "
                 f"effective at: {IntelDisplay(selected.effective_at)}\n")

    for record in selected.records:
        output.write(f"{IntelDisplay(record.identifier)}: source probability "
                     f"{IntelDisplay(record.probability)}; "
                     f"percentile {IntelDisplay(record.percentile)}\n")

    if selected.unmatched_ids:
        output.write("Not present in this selected source: "
                     + ", ".join(selected.unmatched_ids) + "\n")


def RunEpssIntelCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute bounded local selected EPSS acquisition or verified immutable inspection.

    Args:
        arguments: Explicit import or inspect action with its source or exact custody handles.
        output: Caller-owned terminal stream.
        json_output: Emit the separate schema-one/profile-one local EPSS terminal outcome.

    Returns:
        Zero for acknowledged complete import or verified inspection, two for configuration,
        four for acquisition/integrity failure, or 130 for interruption. No model is saved.
    """

    if arguments and arguments[0] in ("import", "inspect", "--help", "-h") and (
        "--help" in arguments or "-h" in arguments
    ):
        EpssIntelParser(arguments[0] if arguments else None).print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "epss-local-selected-cli",
        "command": "intel.epss", "status": "failed", "failure": None,
        "acquisition_state": None, "raw_id": None, "selection_id": None, "receipt_id": None,
        "raw_ack": "not-attempted", "selection_ack": "not-attempted",
        "receipt_ack": "not-attempted", "received_bytes": None, "body_complete": None,
        "started_at": None, "finished_at": None, "source_sha256": None,
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "target_applicability": "not-evaluated",
    }
    status = 4
    phase = "configuration"
    envelope: EpssAcquiredSelection | None = None

    try:
        EpssArguments(arguments)
        options = EpssIntelParser().parse_args(arguments)
        outcome["command"] = "intel.epss." + options.action
        root = IntelPath(options.workspace)

        if options.action == "import":
            identifiers = RequestedIds(options.identifier)
            source = EpssLocalSource(
                SourceOrigin(options.origin), options.publisher, options.source_url,
                options.license_name, options.license_url, tuple(sorted(options.terms_url)),
                options.model_version, options.score_date, options.expected_sha256,
            )
            request = EpssLocalRequest(source, b"", identifiers, options.max_bytes)
            RequireReferenceText(options.scope, "scope_reference")
            phase = "integrity"
            LocalWorkspaceStore(root).Open()
            phase = "configuration"
            payload = ReadLocalIntel(options.file, request.max_bytes)
            request = EpssLocalRequest(source, payload, identifiers, request.max_bytes)
            phase = "acquisition"
            outcome.update({"raw_ack": "unknown", "selection_ack": "unknown",
                            "receipt_ack": "unknown"})
            acquired = AcquireLocalEpssSelection(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value,
                "raw_id": acquired.raw.evidence_id if acquired.raw is not None else None,
                "selection_id": (acquired.selection_record.evidence_id
                                 if acquired.selection_record is not None else None),
                "receipt_id": (acquired.receipt.evidence_id
                               if acquired.receipt is not None else None),
                "raw_ack": acquired.raw_ack.value, "selection_ack": acquired.selection_ack.value,
                "receipt_ack": acquired.receipt_ack.value,
                "received_bytes": acquired.received_bytes, "body_complete": acquired.body_complete,
                "started_at": acquired.started_at, "finished_at": acquired.finished_at,
            })

            if not EpssCustodyComplete(acquired):
                raise IntelFailure("acquisition")

            envelope = acquired.envelope

        else:
            phase = "integrity"
            envelope = LoadAcquiredEpssSelection(root, options.selection, options.receipt)
            outcome.update({
                "acquisition_state": "succeeded", "selection_id": options.selection,
                "receipt_id": options.receipt, "raw_id": envelope.raw.evidence_id,
                "raw_ack": "confirmed", "selection_ack": "confirmed", "receipt_ack": "confirmed",
                "received_bytes": envelope.raw.reference.size_bytes, "body_complete": True,
                "started_at": envelope.raw.provenance.started_at,
                "finished_at": envelope.raw.provenance.finished_at,
            })

        if envelope is None:
            raise IntelFailure("acquisition")

        outcome.update({
            "source_sha256": envelope.raw.reference.sha256,
            "selection_reference": envelope.Reference(),
            "source": envelope.source.ToDict(), "selection": envelope.selection.ToDict(),
            "status": "succeeded",
        })
        status = 0

    except IntelFailure as error:
        outcome["failure"] = error.category
        status = error.status

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

        for name in ("acquisition_state", "raw_ack", "selection_ack", "receipt_ack", "raw_id",
                     "selection_id", "receipt_id", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {outcome[name]}\n")

        if outcome["status"] == "succeeded":
            WriteEpssDetails(cast(EpssAcquiredSelection, envelope), output)

    return status
