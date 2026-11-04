# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded local CWE import and exact-root inspection over unchanged SDK custody."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TextIO, cast

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.intel_references import RequireReferenceDigest, RequireReferenceText
from fuzzy1337.intelligence_commands import (
    IntelArgumentParser,
    IntelDisplay,
    IntelFailure,
    IntelPath,
    ReadLocalIntel,
)
from fuzzy1337.intelligence_cwe_acquisition import (
    AcquireLocalCweSelection,
    CweAcknowledgement,
    CweAcquiredSelection,
    CweAcquisitionOutcome,
    CweAcquisitionState,
    CweLocalRequest,
    CweLocalSource,
    LoadAcquiredCweSelection,
)
from fuzzy1337.intelligence_cwe_selection import MAX_REQUESTED_IDS, RequestedIds
from fuzzy1337.intelligence_cwe_zip import MAX_ZIP_BYTES
from fuzzy1337.workspace import LocalWorkspaceStore

MAX_TERMINAL_BYTES = 2 * 1024 * 1024
MAX_FALLBACK_BYTES = 64 * 1024


class CweTerminalBuffer:
    """Stage portable ASCII output within its UTF-8 byte ceiling before publishing text."""

    def __init__(self, maximum: int) -> None:
        """Initialize a profile-controlled finite terminal staging buffer.

        Args:
            maximum: Independent actual UTF-8 terminal byte ceiling.
        """

        self.maximum = maximum
        self.payload = bytearray()

    def Write(self, text: str) -> None:
        """Append text after portable non-ASCII escaping and check the complete byte expansion.

        Args:
            text: Next formatted human or ASCII-escaped JSON fragment; source bytes are unchanged.
        """

        encoded = text.encode("ascii", errors="backslashreplace")

        if len(self.payload) + len(encoded) > self.maximum:
            raise ValueError("CWE terminal output exceeds its byte profile")

        self.payload.extend(encoded)

    def Text(self) -> str:
        """Return the complete bounded staged text without writing the caller stream.

        Returns:
            Complete staged UTF-8 text admitted within the buffer's byte ceiling.
        """

        return self.payload.decode("ascii")


def CweIntelParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare local import and immutable inspection after inherited global flag normalization.

    Args:
        action: Optional exact known action for storage-independent focused help.

    Returns:
        Strict parser with fixed nonleaking diagnostics and no option abbreviation.
    """

    parser = IntelArgumentParser(prog="1337 intel cwe", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    importer = actions.add_parser("import", add_help=False, allow_abbrev=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("file", type=Path)
    importer.add_argument("--catalog-version", choices=("5.0", "4.21"), required=True)
    importer.add_argument("--expected-sha256", required=True)
    importer.add_argument("--identifier", action="append", required=True)
    importer.add_argument("--scope", required=True)
    importer.add_argument("--max-bytes", type=int, default=MAX_ZIP_BYTES)
    inspect = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspect.add_argument("workspace", type=Path)
    inspect.add_argument("--selection", required=True)
    inspect.add_argument("--receipt", required=True)

    return actions.choices[action] if action in actions.choices else parser


def CweArguments(arguments: Sequence[str]) -> None:
    """Reject repeated forwarded scalar options without deduplicating identifiers.

    Args:
        arguments: Adapter-visible arguments after global help and JSON normalization.
    """

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--") and name != "--identifier":
            if name in seen:
                raise IntelFailure("configuration", 2)

            seen.add(name)


def CweRoot(value: str) -> None:
    """Validate immutable manifest syntax before workspace or evidence reads.

    Args:
        value: Exact selection or receipt root, never an outer semantic reference.
    """

    if not value.startswith("sha256:"):
        raise ValueError("CWE inspection requires an immutable manifest identity")

    RequireReferenceDigest(value[7:])


def CweCustodyComplete(acquired: CweAcquisitionOutcome) -> bool:
    """Require actual complete SDK state, handles and three independently confirmed ACKs.

    Args:
        acquired: Actual returned immutable SDK outcome, not a serialized status label.

    Returns:
        Whether complete original bytes and every publication acknowledgement are available.
    """

    return (
        acquired.state is CweAcquisitionState.SUCCEEDED and acquired.body_complete
        and acquired.raw_ack is CweAcknowledgement.CONFIRMED
        and acquired.selection_ack is CweAcknowledgement.CONFIRMED
        and acquired.receipt_ack is CweAcknowledgement.CONFIRMED
        and acquired.raw is not None and acquired.envelope is not None
        and acquired.selection_record is not None and acquired.receipt is not None
    )


def WriteCweMetadata(value: dict[str, object], output: CweTerminalBuffer, prefix: str) -> None:
    """Stage every fixed source/notice metadata leaf readably without interpreting its content.

    Args:
        value: Detached metadata from the exact SDK source and fixed notice bundle.
        output: Finite terminal staging buffer.
        prefix: Profile-controlled human label extended by trusted metadata field names.
    """

    for key, item in sorted(value.items()):
        label = prefix + "." + key

        if isinstance(item, dict):
            WriteCweMetadata(item, output, label)

        elif isinstance(item, list):
            for entry in item:
                output.Write(f"{label}: {IntelDisplay(entry)}\n")

        else:
            output.Write(f"{label}: {IntelDisplay(item)}\n")


def WriteCweDetails(envelope: CweAcquiredSelection, output: CweTerminalBuffer) -> None:
    """Stage readable complete notices, source facts and three distinct selected partitions.

    Args:
        envelope: Fully acknowledged or verified-present immutable custody.
        output: Finite staging buffer, never the caller's live stdout.
    """

    output.Write("CWE source assertions; target applicability and risk have not been evaluated.\n")
    output.Write("Legal rights, notice applicability and publisher authentication: not assessed.\n")
    source = envelope.source.ToDict()
    notice = cast(dict[str, object], source.pop("notice_bundle"))
    WriteCweMetadata(source, output, "Source")
    WriteCweMetadata({key: value for key, value in notice.items() if key != "text"}, output,
                     "Captured notice")
    output.Write("Complete captured notice text (retained in source/envelope/receipt):\n")

    for line in cast(str, notice["text"]).splitlines():
        output.Write(IntelDisplay(line) + "\n")

    selected = envelope.selection
    output.Write(f"Catalog: {IntelDisplay(selected.catalog_version)}; schema: "
                 f"{IntelDisplay(selected.cwe_schema_version)}; date: "
                 f"{IntelDisplay(selected.catalog_date)} (day precision)\n")
    output.Write(f"Original ZIP member: {IntelDisplay(selected.member_name)}\n")

    for record in selected.records:
        output.Write(f"{IntelDisplay(record.identifier)}: Weakness; "
                     f"{IntelDisplay(record.name)}; source status {IntelDisplay(record.status)}\n")

    for entry in selected.unsupported_entries:
        output.Write(f"{IntelDisplay(entry.identifier)}: unsupported source kind "
                     f"{IntelDisplay(entry.source_kind)}\n")

    if selected.unmatched_ids:
        output.Write("Not present in this selected source: "
                     + ", ".join(selected.unmatched_ids) + "\n")


def CweTerminal(
    outcome: dict[str, object], envelope: CweAcquiredSelection | None, *,
    json_output: bool, maximum: int,
) -> str:
    """Stage complete JSON or escaped human output within its own UTF-8 byte ceiling.

    Args:
        outcome: Actual terminal facts; usable selected content appears only on success.
        envelope: Fully acknowledged or verified selected content for human presentation.
        json_output: Select lossless ASCII-escaped JSON rather than human lines.
        maximum: Separate terminal budget, including human formatting and escaping.

    Returns:
        Complete bounded text, including the final JSON framing newline.
    """

    output = CweTerminalBuffer(maximum)

    if json_output:
        encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False)

        for part in encoder.iterencode(outcome):
            output.Write(part)

        output.Write("\n")

        return output.Text()

    output.Write(f"{outcome['command']}: {outcome['status']}\n")

    for name in ("acquisition_state", "ack_basis", "raw_ack", "selection_ack", "receipt_ack",
                 "raw_id", "selection_id", "receipt_id", "source_sha256", "body_complete",
                 "received_bytes", "failure"):
        if outcome[name] is not None:
            output.Write(f"{name}: {IntelDisplay(outcome[name])}\n")

    if outcome["status"] == "succeeded" and envelope is not None:
        WriteCweDetails(envelope, output)

    return output.Text()


def RunCweIntelCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute local selected import or verified inspection with bounded truthful terminal output.

    Args:
        arguments: Forwarded local namespace arguments after inherited global normalization.
        output: Caller-owned stdout; selected text is staged before a single write.
        json_output: Emit the distinct schema-one/profile-one terminal outcome.

    Returns:
        Zero for exact help or complete custody, two for configuration, four for acquisition,
        integrity or presentation refusal, and 130 for interruption. No model is saved.
    """

    if list(arguments) in (["--help"], ["-h"], ["import", "--help"], ["import", "-h"],
                           ["inspect", "--help"], ["inspect", "-h"]):
        helpOutput = StringIO()
        CweIntelParser(arguments[0]).print_help(file=helpOutput)
        output.write(helpOutput.getvalue())

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "cwe-local-selected-cli",
        "command": "intel.cwe", "status": "failed", "failure": None,
        "transport": "local-bytes", "acquisition_state": None, "raw_id": None,
        "selection_id": None, "receipt_id": None, "raw_ack": "not-attempted",
        "selection_ack": "not-attempted", "receipt_ack": "not-attempted",
        "ack_basis": "not-attempted", "received_bytes": None, "body_complete": None,
        "started_at": None, "finished_at": None, "source_sha256": None,
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "legal_rights": "not-assessed", "notice_applicability": "not-assessed",
        "target_applicability": "not-evaluated",
    }
    status = 4
    phase = "configuration"
    envelope = None

    try:
        CweArguments(arguments)
        options = CweIntelParser().parse_args(arguments)
        outcome["command"] = "intel.cwe." + options.action

        if options.action == "import":
            if not 1 <= len(options.identifier) <= MAX_REQUESTED_IDS:
                raise IntelFailure("configuration", 2)

            identifiers = RequestedIds(tuple(sorted(options.identifier)))
            source = CweLocalSource(options.catalog_version, options.expected_sha256)
            request = CweLocalRequest(source, b"", identifiers, options.max_bytes)
            RequireReferenceText(options.scope, "scope_reference")
            root = IntelPath(options.workspace)
            phase = "integrity"
            LocalWorkspaceStore(root).Open()
            phase = "configuration"
            payload = ReadLocalIntel(options.file, request.max_bytes)
            request = CweLocalRequest(source, payload, identifiers, request.max_bytes)
            phase = "acquisition"
            outcome.update({"raw_ack": "unknown", "selection_ack": "unknown",
                            "receipt_ack": "unknown", "ack_basis": "unreturned"})
            acquired = AcquireLocalCweSelection(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value, "ack_basis": "sdk-returned",
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

            if not CweCustodyComplete(acquired):
                raise IntelFailure("acquisition")

            envelope = acquired.envelope

        else:
            CweRoot(options.selection)
            CweRoot(options.receipt)
            root = IntelPath(options.workspace)
            phase = "integrity"
            envelope = LoadAcquiredCweSelection(root, options.selection, options.receipt)
            outcome.update({
                "acquisition_state": "succeeded", "ack_basis": "verified-present",
                "raw_id": envelope.raw.evidence_id, "selection_id": options.selection,
                "receipt_id": options.receipt, "raw_ack": "confirmed",
                "selection_ack": "confirmed", "receipt_ack": "confirmed",
                "received_bytes": envelope.raw.reference.size_bytes, "body_complete": True,
                "started_at": envelope.raw.provenance.started_at,
                "finished_at": envelope.raw.provenance.finished_at,
                "source_sha256": envelope.raw.reference.sha256,
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

    except (EvidenceError, OSError, ValueError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    if status != 0:
        outcome = {key: value for key, value in outcome.items()
                   if key not in ("source", "selection", "selection_reference")}
        outcome["status"] = "failed"

    try:
        text = CweTerminal(outcome, envelope, json_output=json_output, maximum=MAX_TERMINAL_BYTES)

    except (KeyboardInterrupt, ValueError, OverflowError, RecursionError) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        outcome = {key: value for key, value in outcome.items()
                   if key not in ("source", "selection", "selection_reference")}
        outcome.update({"status": "failed", "failure": "interrupted" if interrupted
                                                      else "presentation-limit"})
        status = 130 if interrupted else 4
        text = CweTerminal(outcome, None, json_output=json_output, maximum=MAX_FALLBACK_BYTES)

    output.write(text)

    return status
