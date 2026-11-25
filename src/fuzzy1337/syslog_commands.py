# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Present owned saved-syslog imports and independently anchored offline records."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Never, TextIO

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.syslog_artifacts import (
    ImportSavedSyslogFile,
    LoadSavedSyslog,
    SyslogAcquisition,
    SyslogSource,
)

__all__ = ["RunSyslogCommands"]

MAX_SYSLOG_OUTPUT_BYTES = 8 * 1024 * 1024


class SyslogArguments(argparse.ArgumentParser):
    """Keep rejected selections out of framework diagnostics."""

    def Error(self, message: str) -> Never:
        """Raise a fixed error without copying rejected source strings.

        Args:
            message: Discarded framework diagnostic.

        Returns:
            Never returns.
        """

        raise ValueError("Saved syslog command selection is invalid")

    error = Error


def SyslogParser(action: str | None = None) -> argparse.ArgumentParser:
    """Build file-only command help without opening any source or store.

    Args:
        action: Optional known action selected only for help.

    Returns:
        Complete parser or the selected action parser.
    """

    parser = SyslogArguments(prog="1337 trace syslog", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=SyslogArguments)
    importer = actions.add_parser("import", add_help=False, allow_abbrev=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("--file", type=Path, required=True)

    for name in ("source-id", "source-version", "source-locator", "expected-sha256",
                 "scope", "owner", "read-consent-reference"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--framing", choices=("single", "lines"), required=True)
    importer.add_argument("--source-tool-version")
    inspector = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspector.add_argument("workspace", type=Path)
    inspector.add_argument("--receipt", required=True)
    inspector.add_argument("--expected-sha256", required=True)
    inspector.add_argument("--export-records", action="store_true",
                           help="include verified SD parameter values with --json; never MSG text")

    return actions.choices[action] if action in actions.choices else parser


def DescribeSyslog(acquired: SyslogAcquisition) -> dict[str, object]:
    """Detach truthful acknowledgements and provenance without exposing a message body.

    Args:
        acquired: Exact first-party immutable acquisition or verified-present replay.

    Returns:
        Bounded safe metadata; neither a source declaration nor read declaration authenticates.
    """

    if type(acquired) is not SyslogAcquisition:
        raise ValueError("Saved syslog result type is invalid")

    return {"acquisition_state": acquired.state, "source": acquired.source.ToDict(),
        "source_sha256": acquired.sourceSha256,
        "raw_id": None if acquired.raw is None else acquired.raw.evidence_id,
        "receipt_id": None if acquired.receipt is None else acquired.receipt.evidence_id,
        "raw_ack": acquired.rawAck, "receipt_ack": acquired.receiptAck,
        "ack_basis": acquired.ackBasis,
        "provenance": None if acquired.raw is None else acquired.raw.provenance.ToDict(),
        "read_declaration": None if acquired.readConsent is None else {
            "actor_reference": acquired.readConsent.actor_ref,
            "consent_reference": acquired.readConsent.record_ref},
        "publisher_authentication": "not-assessed", "core_mutation": "none"}


def VisibleSyslogRecords(document: bytes, *, exportValues: bool) -> list[dict[str, object]]:
    """Preserve verified coordinates and NILs while making SD value exposure explicit.

    Args:
        document: Original loader-verified canonical parser bytes.
        exportValues: Include ordered decoded SD values only for explicit JSON export.

    Returns:
        Source-order records with no arbitrary MSG content, including for explicit exports.
    """

    records: list[dict[str, object]] = json.loads(document)["records"]

    if not exportValues:
        for record in records:
            elements = record["structured_data"]

            if isinstance(elements, list):
                for element in elements:
                    for parameter in element["parameters"]:
                        parameter.pop("value")

    return records


def RenderSyslog(outcome: dict[str, object], machine: bool) -> str:
    """Stage bounded ASCII-safe terminal text before the single presentation write.

    Args:
        outcome: Completed trusted envelope, with records attached only after full verification.
        machine: Render the closed CLI envelope instead of human metadata and record lines.

    Returns:
        Complete finite escaped text; no terminal control from source values is interpreted.
    """

    if machine:
        text = json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    else:
        text = "Saved syslog " + str(outcome["status"]) + " (exit " + str(
            outcome["exit_code"]) + ").\n"
        metadata = {key: value for key, value in outcome.items() if key != "records"}
        text += json.dumps(metadata, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

        records = outcome.get("records", [])

        if not isinstance(records, list):
            raise ValueError("Saved syslog presentation records are invalid")

        for record in records:
            text += json.dumps(record, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    if len(text.encode("ascii")) > MAX_SYSLOG_OUTPUT_BYTES:
        raise ValueError("Saved syslog presentation exceeds its profile")

    return text


def RunSyslogCommands(arguments: Sequence[str], output: TextIO, *,
                      jsonOutput: bool = False) -> int:
    """Import a saved file or reparse an independently pinned retained original offline.

    Args:
        arguments: Explicit import or inspect action and all original selections.
        output: Caller-owned terminal; messages and rejected arguments are never reflected.
        jsonOutput: Render safe metadata; inspect --export-records additionally reveals SD values.

    Returns:
        Zero on complete verified success, two for invalid local selections, four for
        parsing/storage/integrity refusal or presentation failure, and 130 on interruption.
        Unknown storage acknowledgements remain unknown; no Core or workspace model is saved.
    """

    selections = list(arguments)

    if selections and selections[0] in ("import", "inspect") and selections[1:] in (
        ["--help"], ["-h"],
    ) or selections in (["--help"], ["-h"]):
        action = arguments[0] if arguments and arguments[0] in ("import", "inspect") else None
        SyslogParser(action).print_help(file=output)

        return 0

    outcome: dict[str, object] = {"schema_version": 1, "profile": "saved-syslog-cli-v1",
        "command": "trace.syslog", "status": "failed", "failure": None,
        "raw_ack": "not-attempted", "receipt_ack": "not-attempted",
        "raw_id": None, "receipt_id": None, "record_count": None,
        "publisher_authentication": "not-assessed", "core_mutation": "none"}
    status = 4
    phase = "configuration"
    acquired = None

    try:
        options = SyslogParser().parse_args(arguments)
        outcome["command"] = "trace.syslog." + options.action

        if options.action == "import":
            source = SyslogSource(options.source_id, options.source_version,
                options.source_locator, options.expected_sha256, options.framing,
                options.source_tool_version)
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
            phase = "selected-file"
            acquired = ImportSavedSyslogFile(options.workspace, options.file, source,
                                             scopeReference=options.scope, consent=consent)
            outcome.update(DescribeSyslog(acquired))

            if acquired.state in ("succeeded", "parse-rejected"):
                phase = "integrity"

                if acquired.receipt is None:
                    raise ValueError("Saved syslog import has no original receipt")

                verified = LoadSavedSyslog(options.workspace, acquired.receipt.evidence_id,
                                            source.expectedSha256)

                if verified.source != source or verified.document != acquired.document or (
                    verified.raw != acquired.raw or verified.receipt != acquired.receipt
                    or verified.readConsent != consent or verified.state != acquired.state
                    or verified.raw is None or verified.raw.provenance.scope_reference
                    != options.scope
                ):
                    raise ValueError("Saved syslog import differs from verified original")

        else:
            if options.export_records and not jsonOutput:
                raise ValueError("Saved syslog record export requires JSON output")

            phase = "integrity"
            acquired = LoadSavedSyslog(options.workspace, options.receipt, options.expected_sha256)
            outcome.update(DescribeSyslog(acquired))

        if acquired.state == "succeeded" and acquired.document is not None:
            records = VisibleSyslogRecords(acquired.document, exportValues=(
                options.action == "inspect" and options.export_records))
            outcome["record_count"] = len(records)

            if options.action == "inspect":
                outcome["records"] = records

            outcome["status"] = "completed"
            status = 0

        else:
            outcome["failure"] = acquired.state
            status = 130 if acquired.state == "interrupted" else 4

    except (OSError, EvidenceError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        outcome.pop("records", None)
        status = 2 if phase in ("configuration", "selected-file") else 4

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        outcome.pop("records", None)
        status = 130

    if status != 0:
        outcome["status"] = "failed"
        outcome["record_count"] = None
        outcome.pop("records", None)

    outcome["exit_code"] = status

    try:
        rendered = RenderSyslog(outcome, jsonOutput)

    except KeyboardInterrupt:
        outcome.pop("records", None)
        outcome.update({"status": "failed", "failure": "interrupted",
                        "record_count": None, "exit_code": 130})
        status = 130
        rendered = RenderSyslog(outcome, jsonOutput)

    except (ValueError, TypeError, OverflowError, RecursionError):
        outcome.pop("records", None)
        outcome.update({"status": "failed", "failure": "presentation",
                        "record_count": None, "exit_code": 4})
        status = 4
        rendered = RenderSyslog(outcome, jsonOutput)

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
