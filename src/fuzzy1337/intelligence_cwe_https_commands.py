# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental fixed-source CWE HTTPS acquisition and read-only exact-root inspection."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, cast

from fuzzy1337.intel_references import RequireReferenceText
from fuzzy1337.intelligence_commands import (
    IntelArgumentParser,
    IntelDisplay,
    IntelFailure,
    IntelPath,
)
from fuzzy1337.intelligence_cwe_selection import MAX_REQUESTED_IDS, RequestedIds
from fuzzy1337.intelligence_cwe_zip import MAX_ZIP_BYTES
from fuzzy1337.workspace import LocalWorkspaceStore

if TYPE_CHECKING:
    from fuzzy1337.intelligence_cwe_commands import CweTerminalBuffer
    from fuzzy1337.intelligence_cwe_remote import CweHttpsOutcome, CweHttpsSelection

__all__ = ("RunCweHttpsCommands",)

MAX_TERMINAL_BYTES = 2 * 1024 * 1024
MAX_FALLBACK_BYTES = 64 * 1024


def CweHttpsParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare closed fetch and inspect grammar without importing the remote SDK."""

    parser = IntelArgumentParser(prog="1337 intel cwe https", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    fetch = actions.add_parser("fetch", add_help=False, allow_abbrev=False)
    fetch.add_argument("workspace", type=Path)
    fetch.add_argument("--catalog-version", choices=("5.0", "4.21"), required=True)
    fetch.add_argument("--expected-sha256", required=True)
    fetch.add_argument("--identifier", action="append", required=True)
    fetch.add_argument("--scope", required=True)
    fetch.add_argument("--max-bytes", type=int, default=MAX_ZIP_BYTES)
    fetch.add_argument("--timeout-seconds", type=float, default=15.0)
    inspect = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspect.add_argument("workspace", type=Path)
    inspect.add_argument("--selection", required=True)
    inspect.add_argument("--receipt", required=True)

    return actions.choices[action] if action in actions.choices else parser


def CweHttpsCustodyComplete(acquired: CweHttpsOutcome) -> bool:
    """Require complete HTTPS reception and all separately acknowledged SDK handles."""

    from fuzzy1337.intelligence_cwe_remote import CweHttpsAcknowledgement, CweHttpsState

    return (
        acquired.state is CweHttpsState.SUCCEEDED and acquired.receive_state == "succeeded"
        and acquired.http_status == 200 and acquired.body_complete
        and acquired.raw_ack is CweHttpsAcknowledgement.CONFIRMED
        and acquired.selection_ack is CweHttpsAcknowledgement.CONFIRMED
        and acquired.receipt_ack is CweHttpsAcknowledgement.CONFIRMED
        and acquired.raw is not None and acquired.envelope is not None
        and acquired.selection_record is not None and acquired.receipt is not None
    )


def WriteCweHttpsDetails(envelope: CweHttpsSelection, output: CweTerminalBuffer) -> None:
    """Present full HTTPS source notice and distinct selected source assertions."""

    from fuzzy1337.intelligence_cwe_commands import WriteCweMetadata

    output.Write("CWE source assertions. Target applicability and risk have not been evaluated.\n")
    output.Write("Legal rights, notice applicability and publisher authentication: unassessed.\n")
    source = envelope.source.ToDict()
    notice = cast(dict[str, object], source.pop("notice_bundle"))
    WriteCweMetadata(source, output, "Source")
    WriteCweMetadata({key: value for key, value in notice.items() if key != "text"}, output,
                     "Captured notice")
    output.Write("Complete captured notice text:\n")

    for line in cast(str, notice["text"]).splitlines():
        output.Write(IntelDisplay(line) + "\n")

    selected = envelope.selection
    output.Write(f"Catalog {IntelDisplay(selected.catalog_version)}, "
                 f"schema {IntelDisplay(selected.cwe_schema_version)}, "
                 f"date {IntelDisplay(selected.catalog_date)} (day precision)\n")
    output.Write(f"Original ZIP member: {IntelDisplay(selected.member_name)}\n")

    for record in selected.records:
        output.Write(f"{IntelDisplay(record.identifier)}: Weakness, "
                     f"{IntelDisplay(record.name)}, source status {IntelDisplay(record.status)}\n")

    for entry in selected.unsupported_entries:
        output.Write(f"{IntelDisplay(entry.identifier)}: unsupported source kind "
                     f"{IntelDisplay(entry.source_kind)}\n")

    if selected.unmatched_ids:
        output.Write("Not present in this selected source: "
                     + ", ".join(selected.unmatched_ids) + "\n")


def CweHttpsTerminal(
    outcome: dict[str, object], envelope: CweHttpsSelection | None, *,
    json_output: bool, maximum: int,
) -> str:
    """Stage one portable terminal document within its actual escaped byte limit."""

    from fuzzy1337.intelligence_cwe_commands import CweTerminalBuffer

    output = CweTerminalBuffer(maximum)

    if json_output:
        encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False)

        for part in encoder.iterencode(outcome):
            output.Write(part)

        output.Write("\n")

        return output.Text()

    output.Write(f"{outcome['command']}: {outcome['status']}\n")

    for name in ("transport", "transport_profile", "acquisition_state", "receive_state",
                 "http_status", "ack_basis", "raw_ack", "selection_ack", "receipt_ack", "raw_id",
                 "selection_id", "receipt_id", "source_sha256", "body_complete", "received_bytes",
                 "started_at", "finished_at", "limits", "failure"):
        if outcome[name] is not None:
            output.Write(f"{name}: {IntelDisplay(outcome[name])}\n")

    if outcome["ack_basis"] == "verified-present":
        output.Write("HTTP facts describe the original acquisition verified offline.\n")

    if outcome["status"] == "succeeded" and envelope is not None:
        WriteCweHttpsDetails(envelope, output)

    return output.Text()


def ClearCweHttpsSelection(outcome: dict[str, object]) -> None:
    """Retain custody diagnostics while withholding all usable assertions on failure."""

    for name in ("source", "selection", "selection_reference"):
        outcome.pop(name, None)

    outcome["status"] = "failed"


def RunCweHttpsCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute fixed-source HTTPS acquisition or exact read-only custody inspection.

    Args:
        arguments: Forwarded namespace arguments after global help and JSON normalization.
        output: Caller-owned stdout for one complete bounded terminal document.
        json_output: Select the schema-one/profile-one machine-readable outcome.

    Returns:
        Zero for complete custody or exact help, two for configuration, four for acquisition,
        integrity or presentation refusal, and 130 for interruption.
    """

    if list(arguments) in (["--help"], ["-h"], ["fetch", "--help"], ["fetch", "-h"],
                           ["inspect", "--help"], ["inspect", "-h"]):
        help_output = StringIO()
        CweHttpsParser(arguments[0]).print_help(file=help_output)
        help_text = help_output.getvalue()

        if output.write(help_text) != len(help_text):
            raise OSError("Incomplete CWE HTTPS terminal write")

        return 0

    from fuzzy1337.intelligence_cwe_commands import CweArguments, CweRoot

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "cwe-https-selected-cli",
        "command": "intel.cwe.https", "status": "failed", "failure": None,
        "transport": "https", "transport_profile": "cwe-https-zip-identity-v1",
        "acquisition_state": None, "receive_state": None, "http_status": None,
        "raw_id": None, "selection_id": None, "receipt_id": None, "raw_ack": "not-attempted",
        "selection_ack": "not-attempted", "receipt_ack": "not-attempted",
        "ack_basis": "not-attempted", "received_bytes": None, "body_complete": None,
        "started_at": None, "finished_at": None, "source_sha256": None, "limits": None,
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "legal_rights": "not-assessed", "notice_applicability": "not-assessed",
        "target_applicability": "not-evaluated",
    }
    status = 4
    phase = "configuration"
    envelope = None

    try:
        CweArguments(arguments)
        options = CweHttpsParser().parse_args(arguments)
        outcome["command"] = "intel.cwe.https." + options.action

        if options.action == "fetch":
            if not 1 <= len(options.identifier) <= MAX_REQUESTED_IDS:
                raise IntelFailure("configuration", 2)

            identifiers = RequestedIds(tuple(sorted(options.identifier)))
            RequireReferenceText(options.scope, "scope_reference")

            from fuzzy1337.intelligence_cwe_remote import (
                AcquireHttpsCweSelection,
                CweHttpsRequest,
                CweHttpsSource,
            )

            source = CweHttpsSource(options.catalog_version, options.expected_sha256)
            request = CweHttpsRequest(source, identifiers, options.max_bytes,
                                      options.timeout_seconds)
            outcome["limits"] = {"max_zip_bytes": request.max_bytes,
                                 "timeout_seconds": request.timeout_seconds}
            root = IntelPath(options.workspace)
            phase = "integrity"
            LocalWorkspaceStore(root).Open()
            phase = "acquisition"
            outcome.update({"raw_ack": "unknown", "selection_ack": "unknown",
                            "receipt_ack": "unknown", "ack_basis": "unreturned"})
            acquired = AcquireHttpsCweSelection(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value, "ack_basis": "sdk-returned",
                "receive_state": acquired.receive_state, "http_status": acquired.http_status,
                "raw_id": acquired.raw.evidence_id if acquired.raw is not None else None,
                "selection_id": (acquired.selection_record.evidence_id
                                 if acquired.selection_record is not None else None),
                "receipt_id": (acquired.receipt.evidence_id
                               if acquired.receipt is not None else None),
                "raw_ack": acquired.raw_ack.value, "selection_ack": acquired.selection_ack.value,
                "receipt_ack": acquired.receipt_ack.value,
                "received_bytes": acquired.received_bytes,
                "body_complete": acquired.body_complete, "started_at": acquired.started_at,
                "finished_at": acquired.finished_at,
                "source_sha256": (acquired.raw.reference.sha256
                                  if acquired.raw is not None else None),
            })

            if not CweHttpsCustodyComplete(acquired):
                raise IntelFailure("acquisition")

            envelope = acquired.envelope

        else:
            CweRoot(options.selection)
            CweRoot(options.receipt)
            root = IntelPath(options.workspace)
            phase = "integrity"

            from fuzzy1337.intelligence_cwe_remote import LoadHttpsCweSelection

            envelope = LoadHttpsCweSelection(root, options.selection, options.receipt)
            outcome.update({
                "acquisition_state": "succeeded", "ack_basis": "verified-present",
                "receive_state": "succeeded", "http_status": 200,
                "raw_id": envelope.raw.evidence_id, "selection_id": options.selection,
                "receipt_id": options.receipt, "raw_ack": "confirmed",
                "selection_ack": "confirmed", "receipt_ack": "confirmed",
                "received_bytes": envelope.raw.reference.size_bytes, "body_complete": True,
                "started_at": envelope.raw.provenance.started_at,
                "finished_at": envelope.raw.provenance.finished_at,
                "source_sha256": envelope.raw.reference.sha256,
                "limits": {"max_zip_bytes": envelope.max_bytes,
                           "timeout_seconds": envelope.timeout_seconds},
            })

        if envelope is None:
            raise IntelFailure("acquisition")

        outcome.update({"source": envelope.source.ToDict(),
                        "selection": envelope.selection.ToDict(),
                        "selection_reference": envelope.Reference(), "status": "succeeded"})
        status = 0

    except IntelFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except (RuntimeError, OSError, ValueError, TypeError, OverflowError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    if status != 0:
        ClearCweHttpsSelection(outcome)
        envelope = None

    try:
        text = CweHttpsTerminal(outcome, envelope, json_output=json_output,
                                maximum=MAX_TERMINAL_BYTES)

    except (KeyboardInterrupt, ValueError, TypeError, OverflowError, RecursionError) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        ClearCweHttpsSelection(outcome)
        outcome["failure"] = "interrupted" if interrupted else "presentation-limit"
        status = 130 if interrupted else 4
        text = CweHttpsTerminal(outcome, None, json_output=json_output, maximum=MAX_FALLBACK_BYTES)

    if output.write(text) != len(text):
        raise OSError("Incomplete CWE HTTPS terminal write")

    return status
