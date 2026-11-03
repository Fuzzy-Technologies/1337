# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit pinned EPSS HTTPS commands with separate custody and offline inspection."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.intel_references import RequireReferenceText
from fuzzy1337.intelligence_epss_selection import MAX_COMPRESSED_BYTES, RequestedIds
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore

if TYPE_CHECKING:
    from fuzzy1337.intelligence_epss_remote import EpssHttpsOutcome, EpssHttpsSelection


def EpssHttpsParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare only pinned fetch and exact offline inspection without option abbreviations.

    Args:
        action: Optional known action for bounded help without storage or network access.

    Returns:
        Parser rejecting unsupported options through the fixed runtime diagnostic boundary.
    """

    from fuzzy1337.runtime_commands import RuntimeArgumentParser

    parser = RuntimeArgumentParser(prog="1337 intel epss https", add_help=False,
                                   allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True,
                                   parser_class=RuntimeArgumentParser)
    fetch = actions.add_parser("fetch", add_help=False, allow_abbrev=False)
    fetch.add_argument("workspace", type=Path)

    for name in ("commit", "score-date", "model-version", "expected-sha256", "scope"):
        fetch.add_argument("--" + name, required=True)

    fetch.add_argument("--identifier", action="append", required=True)
    fetch.add_argument("--max-bytes", type=int, default=MAX_COMPRESSED_BYTES)
    fetch.add_argument("--timeout-seconds", type=float, default=15.0)
    inspect = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspect.add_argument("workspace", type=Path)
    inspect.add_argument("--selection", required=True)
    inspect.add_argument("--receipt", required=True)

    return actions.choices[action] if action in actions.choices else parser


def EpssHttpsArguments(arguments: Sequence[str]) -> None:
    """Reject repeated scalar flags before parsing, storage access or network acquisition.

    Args:
        arguments: Explicit HTTPS namespace arguments; only identifier flags may repeat.
    """

    from fuzzy1337.runtime_commands import RuntimeFailure

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--") and name != "--identifier":
            if name in seen:
                raise RuntimeFailure("configuration", 2)

            seen.add(name)


def EpssHttpsCustodyComplete(acquired: EpssHttpsOutcome) -> bool:
    """Require observed complete HTTP 200 and every independently acknowledged artifact.

    Args:
        acquired: Actual SDK terminal result with independent transport and custody facts.

    Returns:
        Whether all observed network facts, publication acknowledgements and handles succeed.
    """

    from fuzzy1337.intelligence_epss_remote import EpssHttpsAcknowledgement, EpssHttpsState

    return (
        acquired.state is EpssHttpsState.SUCCEEDED and acquired.http_status == 200
        and acquired.receive_state == "succeeded" and acquired.body_complete
        and acquired.raw_ack is EpssHttpsAcknowledgement.CONFIRMED
        and acquired.selection_ack is EpssHttpsAcknowledgement.CONFIRMED
        and acquired.receipt_ack is EpssHttpsAcknowledgement.CONFIRMED
        and acquired.raw is not None and acquired.envelope is not None
        and acquired.selection_record is not None and acquired.receipt is not None
    )


def WriteEpssHttpsDetails(envelope: EpssHttpsSelection, output: TextIO) -> None:
    """Present bounded source assertions and FIRST attribution without authentication claims.

    Args:
        envelope: Verified or fully acknowledged immutable HTTPS source selection.
        output: Caller-owned human-readable output stream.
    """

    from fuzzy1337.intelligence_commands import IntelDisplay

    source = envelope.source.ToDict()
    selected = envelope.selection
    output.write("Source assertions; target applicability has not been evaluated.\n")
    output.write("EPSS predicts exploitation of the CVE in the next 30 days.\n")
    output.write("Publisher authentication: not assessed. Data license: not established.\n")

    for name in ("publisher", "source_url", "data_url", "attribution_url"):
        output.write(f"{name}: {IntelDisplay(str(source[name]))}\n")

    output.write("Terms: https://www.first.org/about/policies/terms\n")
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


def RunEpssHttpsCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute pinned HTTPS fetch or read-only exact remote custody inspection.

    Args:
        arguments: Fetch pins, CVEs and scope, or exact selection and receipt roots.
        output: Caller-owned terminal stream; rejected values are never echoed.
        json_output: Emit the separate versioned HTTPS terminal profile.

    Returns:
        Zero for complete acknowledged fetch or verified inspection, two for invalid
        configuration, four for acquisition/integrity failure, or 130 for interruption.
        No model state is saved and inspection never starts a receiver.
    """

    from fuzzy1337.intelligence_commands import IntelDisplay, IntelFailure, IntelPath
    from fuzzy1337.intelligence_epss_remote import (
        AcquireHttpsEpssSelection,
        EpssHttpsRequest,
        EpssHttpsSource,
        LoadHttpsEpssSelection,
    )
    from fuzzy1337.runtime_commands import RuntimeFailure

    if list(arguments) in (["--help"], ["-h"], ["fetch", "--help"], ["fetch", "-h"],
                           ["inspect", "--help"], ["inspect", "-h"]):
        EpssHttpsParser(arguments[0]).print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "epss-https-selected-cli",
        "command": "intel.epss.https", "status": "failed", "failure": None,
        "transport": "https", "acquisition_state": None, "receive_state": None,
        "http_status": None, "raw_id": None, "selection_id": None, "receipt_id": None,
        "raw_ack": "not-attempted", "selection_ack": "not-attempted",
        "receipt_ack": "not-attempted", "received_bytes": None, "body_complete": None,
        "started_at": None, "finished_at": None, "source_sha256": None,
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "target_applicability": "not-evaluated",
    }
    status = 4
    phase = "configuration"
    envelope: EpssHttpsSelection | None = None

    try:
        EpssHttpsArguments(arguments)
        options = EpssHttpsParser().parse_args(arguments)
        outcome["command"] = "intel.epss.https." + options.action
        root = IntelPath(options.workspace)

        if options.action == "fetch":
            source = EpssHttpsSource(options.commit, options.score_date, options.model_version,
                                    options.expected_sha256)
            request = EpssHttpsRequest(source, RequestedIds(options.identifier), options.max_bytes,
                                      options.timeout_seconds)
            RequireReferenceText(options.scope, "scope_reference")
            phase = "integrity"
            LocalWorkspaceStore(root).Open()
            phase = "acquisition"
            outcome.update({"raw_ack": "unknown", "selection_ack": "unknown",
                            "receipt_ack": "unknown"})
            acquired = AcquireHttpsEpssSelection(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value, "receive_state": acquired.receive_state,
                "http_status": acquired.http_status,
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

            if not EpssHttpsCustodyComplete(acquired):
                raise IntelFailure("acquisition")

            envelope = acquired.envelope

        else:
            phase = "integrity"
            envelope = LoadHttpsEpssSelection(root, options.selection, options.receipt)
            outcome.update({
                "acquisition_state": "succeeded", "receive_state": "succeeded", "http_status": 200,
                "selection_id": options.selection, "receipt_id": options.receipt,
                "raw_id": envelope.raw.evidence_id,
                "raw_ack": "confirmed", "selection_ack": "confirmed", "receipt_ack": "confirmed",
                "received_bytes": envelope.raw.reference.size_bytes, "body_complete": True,
                "started_at": envelope.raw.provenance.started_at,
                "finished_at": envelope.raw.provenance.finished_at,
            })

        if envelope is None:
            raise IntelFailure("acquisition")

        outcome.update({
            "source_sha256": envelope.raw.reference.sha256,
            "selection_reference": envelope.Reference(), "source": envelope.source.ToDict(),
            "selection": envelope.selection.ToDict(), "status": "succeeded",
        })
        status = 0

    except (IntelFailure, RuntimeFailure) as error:
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

        for name in ("acquisition_state", "receive_state", "http_status", "received_bytes",
                     "body_complete", "raw_ack", "selection_ack", "receipt_ack", "raw_id",
                     "selection_id", "receipt_id", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {IntelDisplay(str(outcome[name]))}\n")

        if outcome["status"] == "succeeded" and envelope is not None:
            WriteEpssHttpsDetails(envelope, output)

    return status
