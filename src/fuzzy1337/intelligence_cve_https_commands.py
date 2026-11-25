# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit pinned CVE HTTPS commands with separate custody and offline inspection."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from fuzzy1337.evidence import EvidenceError, RequireEvidenceDigest
from fuzzy1337.intel_references import RequireReferenceText
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore

if TYPE_CHECKING:
    from fuzzy1337.intelligence_cve_remote import CveHttpsOutcome, CveHttpsSelection

MAX_SAVED_SET_TERMINAL_BYTES = 8 * 1024 * 1024


def CveHttpsParser(action: str | None = None) -> argparse.ArgumentParser:
    """Declare only pinned fetch and exact offline inspection without option abbreviations.

    Args:
        action: Optional known action for bounded help without storage or network access.

    Returns:
        Parser rejecting unsupported options through the fixed runtime diagnostic boundary.
    """

    from fuzzy1337.runtime_commands import RuntimeArgumentParser

    parser = RuntimeArgumentParser(prog="1337 intel cve https", add_help=False,
                                   allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True,
                                   parser_class=RuntimeArgumentParser)
    fetch = actions.add_parser("fetch", add_help=False, allow_abbrev=False)
    fetch.add_argument("workspace", type=Path)

    for name in ("commit", "identifier", "expected-sha256", "scope"):
        fetch.add_argument("--" + name, required=True)

    fetch.add_argument("--max-bytes", type=int, default=1024 * 1024)
    fetch.add_argument("--timeout-seconds", type=float, default=15.0)
    inspect = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspect.add_argument("workspace", type=Path)
    inspect.add_argument("--selection", required=True)
    inspect.add_argument("--receipt", required=True)
    savedSet = actions.add_parser("inspect-set", add_help=False, allow_abbrev=False)
    savedSet.add_argument("workspace", type=Path)
    savedSet.add_argument("--member", nargs=2, action="append", required=True,
                         metavar=("SELECTION", "RECEIPT"),
                         help="repeat for two to four saved members in caller order")

    return actions.choices[action] if action in actions.choices else parser


def CveHttpsArguments(arguments: Sequence[str]) -> None:
    """Reject repeated scalar flags before parsing, storage access or network acquisition.

    Args:
        arguments: Explicit HTTPS arguments; only inspect-set member pairs may repeat.
    """

    from fuzzy1337.runtime_commands import RuntimeFailure

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--"):
            if name in seen and not (list(arguments[:1]) == ["inspect-set"] and name == "--member"):
                raise RuntimeFailure("configuration", 2)

            seen.add(name)


def CveSavedSetMembers(values: Sequence[Sequence[str]]) -> tuple[tuple[str, str], ...]:
    """Validate every bounded independent manifest pair before any owning storage read.

    Args:
        values: Explicit pairs in caller order, with no implicit discovery or set identity.

    Returns:
        Two to four distinct selection/receipt pairs using canonical evidence identities.
    """

    if not 2 <= len(values) <= 4:
        raise ValueError("Saved CVE inspection requires two to four explicit manifest pairs")

    members = tuple((selection, receipt) for selection, receipt in values)
    identities = tuple(identity for pair in members for identity in pair)

    for identity in identities:
        if not identity.startswith("sha256:"):
            raise ValueError("Saved CVE inspection requires exact evidence manifest identities")

        RequireEvidenceDigest(identity[7:])

    if len(set(identities)) != len(identities):
        raise ValueError("Saved CVE inspection requires independent manifest pairs")

    return members


def CveSavedSetTerminal(outcome: dict[str, object], *, jsonOutput: bool) -> str:
    """Stage the complete portable terminal projection before a single caller-stream write.

    Args:
        outcome: Fully verified members or a fixed refusal without positive assertions.
        jsonOutput: Whether the caller requested the separate machine-readable profile.

    Returns:
        Bounded ASCII text retaining source Unicode through JSON or terminal escaping.
    """

    from fuzzy1337.intelligence_commands import IntelDisplay

    if jsonOutput:
        text = json.dumps(outcome, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"), sort_keys=True) + "\n"

    else:
        text = f"{outcome['command']}: {outcome['status']}\n"
        text += "Saved source assertions; applicability and risk are not evaluated.\n"
        text += "Publisher authentication: not assessed. No persisted set identity is asserted.\n"
        text += IntelDisplay(outcome) + "\n"
        text = text.encode("ascii", errors="backslashreplace").decode("ascii")

    if len(text) > MAX_SAVED_SET_TERMINAL_BYTES:
        raise ValueError("Saved CVE set terminal projection exceeds its byte ceiling")

    return text


def RunCveSavedSetInspection(
    arguments: Sequence[str], output: TextIO, *, jsonOutput: bool = False,
) -> int:
    """Verify an explicit saved selection through independent original loaders without writes.

    Args:
        arguments: Inspect-set action, physical workspace and two to four explicit member pairs.
        output: Caller-owned terminal stream receiving one complete bounded result.
        jsonOutput: Emit the separate Experimental saved-set terminal profile.

    Returns:
        Zero after every original member verifies, two for configuration, four for integrity
        or presentation refusal, or 130 for interruption. No acquisition or model action runs.
    """

    from fuzzy1337.intelligence_commands import IntelFailure, IntelPath
    from fuzzy1337.intelligence_cve_remote import LoadHttpsCveSelection
    from fuzzy1337.runtime_commands import RuntimeFailure

    if list(arguments) in (["inspect-set", "--help"], ["inspect-set", "-h"]):
        CveHttpsParser("inspect-set").print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "cve-https-saved-set-cli",
        "command": "intel.cve.https.inspect-set", "status": "failed", "failure": None,
        "members": [], "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed", "target_applicability": "not-evaluated",
        "risk_assessment": "not-evaluated",
    }
    status = 4
    phase = "configuration"

    try:
        CveHttpsArguments(arguments)
        options = CveHttpsParser().parse_args(arguments)
        pairs = CveSavedSetMembers(options.member)
        root = IntelPath(options.workspace)
        phase = "integrity"
        verified = tuple(LoadHttpsCveSelection(root, selection, receipt)
                         for selection, receipt in pairs)

        if len({envelope.source.commit for envelope in verified}) != 1 or (
            len({envelope.source.identifier for envelope in verified}) != len(verified)
        ) or len({envelope.raw.provenance.workspace_id for envelope in verified}) != 1:
            raise ValueError("Saved CVE members require one source commit, owner and distinct CVEs")

        outcome["members"] = [{
            "selection_id": selection, "receipt_id": receipt,
            "raw_id": envelope.raw.evidence_id, "source_sha256": envelope.raw.reference.sha256,
            "selection_reference": envelope.Reference(), "source": envelope.source.ToDict(),
            "snapshot": {**envelope.snapshot.Content(), "reference": envelope.snapshot.Reference()},
            "provenance": envelope.raw.provenance.ToDict(),
        } for (selection, receipt), envelope in zip(pairs, verified, strict=True)]
        outcome["status"] = "succeeded"
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

    if status != 0:
        outcome.update({"members": [], "status": "failed"})

    try:
        text = CveSavedSetTerminal(outcome, jsonOutput=jsonOutput)

    except (KeyboardInterrupt, ValueError, OverflowError, RecursionError) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        outcome.update({"members": [], "status": "failed",
                        "failure": "interrupted" if interrupted else "presentation-limit"})
        status = 130 if interrupted else 4
        text = CveSavedSetTerminal(outcome, jsonOutput=jsonOutput)

    if output.write(text) != len(text):
        raise OSError("Incomplete saved CVE set terminal write")

    return status


def CveHttpsCustodyComplete(acquired: CveHttpsOutcome) -> bool:
    """Require observed complete HTTP 200 and every independently acknowledged artifact.

    Args:
        acquired: Actual SDK terminal result with independent transport and custody facts.

    Returns:
        Whether all observed network facts, publication acknowledgements and handles succeed.
    """

    from fuzzy1337.intelligence_cve_remote import CveHttpsAcknowledgement, CveHttpsState

    return (
        acquired.state is CveHttpsState.SUCCEEDED and acquired.http_status == 200
        and acquired.receive_state == "succeeded" and acquired.body_complete
        and acquired.raw_ack is CveHttpsAcknowledgement.CONFIRMED
        and acquired.snapshot_ack is CveHttpsAcknowledgement.CONFIRMED
        and acquired.receipt_ack is CveHttpsAcknowledgement.CONFIRMED
        and acquired.raw is not None and acquired.envelope is not None
        and acquired.snapshot_record is not None and acquired.receipt is not None
    )


def WriteCveHttpsDetails(envelope: CveHttpsSelection, output: TextIO) -> None:
    """Present bounded CVE source assertions and notices without risk or applicability claims.

    Args:
        envelope: Verified or fully acknowledged immutable HTTPS source selection.
        output: Caller-owned human-readable output stream.
    """

    from fuzzy1337.intelligence_commands import IntelDisplay

    output.write("CVE source assertions; target applicability and risk have not been evaluated.\n")
    output.write("Selected source profile: CVE JSON 5.2, PUBLISHED records only.\n")
    output.write("Publisher authentication: not assessed.\n")
    output.write(f"Source notices: {IntelDisplay(envelope.source.ToDict())}\n")

    for record in envelope.snapshot.records:
        output.write(f"{IntelDisplay(record.identifier)}: source state "
                     f"{IntelDisplay(record.data['state'])}; "
                     f"effective at: {IntelDisplay(record.effective_at)}\n")
        output.write(f"Source assertions: {IntelDisplay(record.ToDict())}\n")


def RunCveHttpsCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute pinned HTTPS fetch or read-only exact remote custody inspection.

    Args:
        arguments: Exact source pins, one canonical CVE and scope, or selection and receipt roots.
        output: Caller-owned terminal stream; rejected values are never echoed.
        json_output: Emit the versioned HTTPS profile, escaping Unicode for narrow output codecs.

    Returns:
        Zero for complete acknowledged fetch or verified inspection, two for invalid
        configuration, four for acquisition/integrity failure, or 130 for interruption.
        No model state is saved and inspection never starts a receiver.
    """

    from fuzzy1337.intelligence_commands import IntelDisplay, IntelFailure, IntelPath
    from fuzzy1337.intelligence_cve_remote import (
        AcquireHttpsCveSelection,
        CveHttpsRequest,
        CveHttpsSource,
        LoadHttpsCveSelection,
    )
    from fuzzy1337.runtime_commands import RuntimeFailure

    if list(arguments[:1]) == ["inspect-set"]:
        return RunCveSavedSetInspection(arguments, output, jsonOutput=json_output)

    if list(arguments) in (["--help"], ["-h"], ["fetch", "--help"], ["fetch", "-h"],
                           ["inspect", "--help"], ["inspect", "-h"]):
        CveHttpsParser(arguments[0]).print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile_version": 1, "profile": "cve-https-selected-cli",
        "command": "intel.cve.https", "status": "failed", "failure": None,
        "transport": "https", "acquisition_state": None, "receive_state": None,
        "http_status": None, "raw_id": None, "selection_id": None, "receipt_id": None,
        "raw_ack": "not-attempted", "selection_ack": "not-attempted",
        "receipt_ack": "not-attempted", "received_bytes": None, "body_complete": None,
        "started_at": None, "finished_at": None, "source_sha256": None,
        "model_commit": "not-attempted", "publisher_authentication": "not-assessed",
        "target_applicability": "not-evaluated", "risk_assessment": "not-evaluated",
    }
    status = 4
    phase = "configuration"
    envelope: CveHttpsSelection | None = None

    try:
        CveHttpsArguments(arguments)
        options = CveHttpsParser().parse_args(arguments)
        outcome["command"] = "intel.cve.https." + options.action
        root = IntelPath(options.workspace)

        if options.action == "fetch":
            source = CveHttpsSource(options.commit, options.identifier, options.expected_sha256)
            request = CveHttpsRequest(source, options.max_bytes, options.timeout_seconds)
            RequireReferenceText(options.scope, "scope_reference")
            phase = "integrity"
            LocalWorkspaceStore(root).Open()
            phase = "acquisition"
            outcome.update({"raw_ack": "unknown", "selection_ack": "unknown",
                            "receipt_ack": "unknown"})
            acquired = AcquireHttpsCveSelection(root, request, scope_reference=options.scope)
            outcome.update({
                "acquisition_state": acquired.state.value, "receive_state": acquired.receive_state,
                "http_status": acquired.http_status,
                "raw_id": acquired.raw.evidence_id if acquired.raw is not None else None,
                "selection_id": (acquired.snapshot_record.evidence_id
                                 if acquired.snapshot_record is not None else None),
                "receipt_id": (acquired.receipt.evidence_id
                               if acquired.receipt is not None else None),
                "raw_ack": acquired.raw_ack.value, "selection_ack": acquired.snapshot_ack.value,
                "receipt_ack": acquired.receipt_ack.value,
                "received_bytes": acquired.received_bytes, "body_complete": acquired.body_complete,
                "started_at": acquired.started_at, "finished_at": acquired.finished_at,
            })

            if not CveHttpsCustodyComplete(acquired):
                raise IntelFailure("acquisition")

            envelope = acquired.envelope

        else:
            phase = "integrity"
            envelope = LoadHttpsCveSelection(root, options.selection, options.receipt)
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
            "snapshot": {**envelope.snapshot.Content(), "reference": envelope.snapshot.Reference()},
            "status": "succeeded",
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
        text = CanonicalModelJson(outcome).decode("utf-8") + "\n"
        encoding = getattr(output, "encoding", None)

        try:
            if encoding:
                text.encode(encoding)

        except UnicodeEncodeError:
            text = json.dumps(outcome, ensure_ascii=True, allow_nan=False,
                              sort_keys=True, separators=(",", ":")) + "\n"

        output.write(text)

    else:
        output.write(f"{outcome['command']}: {outcome['status']}\n")

        for name in ("acquisition_state", "receive_state", "http_status", "received_bytes",
                     "body_complete", "raw_ack", "selection_ack", "receipt_ack", "raw_id",
                     "selection_id", "receipt_id", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {IntelDisplay(str(outcome[name]))}\n")

        if outcome["status"] == "succeeded" and envelope is not None:
            WriteCveHttpsDetails(envelope, output)

    return status
