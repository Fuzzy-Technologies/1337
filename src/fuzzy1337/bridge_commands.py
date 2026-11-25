# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal IMPORT-only saved SARIF command over existing physical-file and evidence owners."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable, Sequence
from datetime import datetime
from io import BytesIO, StringIO
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.artifact_inputs import ArtifactReadConsent, ReadArtifactFile
from fuzzy1337.bridge_sarif import (
    MAX_RECEIPT_BYTES,
    MAX_SOURCE_BYTES,
    RAW_MEDIA,
    RAW_ROLE,
    RECEIPT_ROLE,
    SOURCE_ID,
    SOURCE_VERSION,
    JsonBytes,
    LoadSavedSarif,
    ParseSarif,
    ReceiptContent,
)
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    LocalEvidenceStore,
    RequireEvidenceDigest,
)
from fuzzy1337.intelligence_commands import IntelArgumentParser, IntelFailure, IntelPath
from fuzzy1337.policy import UtcNow
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ()

MAX_TERMINAL_BYTES = 2 * 1024 * 1024


def BridgeParser(topic: tuple[str, ...] = ()) -> argparse.ArgumentParser:
    """Declare only explicit saved-report intake and independently anchored retained inspection.

    Args:
        topic: Exact optional help path, without reading any source or workspace.

    Returns:
        Strict non-abbreviating parser with fixed diagnostics and no execution actions.
    """

    parser = IntelArgumentParser(prog="1337 bridge", add_help=False, allow_abbrev=False)
    profiles = parser.add_subparsers(dest="profile", required=True,
                                     parser_class=IntelArgumentParser)
    sarif = profiles.add_parser("sarif", add_help=False, allow_abbrev=False)
    actions = sarif.add_subparsers(dest="action", required=True, parser_class=IntelArgumentParser)
    importer = actions.add_parser("import", add_help=False, allow_abbrev=False)
    importer.add_argument("workspace", type=Path)
    importer.add_argument("file", type=Path)
    importer.add_argument("--scope", required=True)
    importer.add_argument("--owner", required=True)
    importer.add_argument("--read-consent-reference", required=True)
    importer.add_argument("--expected-sha256", required=True)
    inspect = actions.add_parser("inspect", add_help=False, allow_abbrev=False)
    inspect.add_argument("workspace", type=Path)
    inspect.add_argument("--original", required=True)
    inspect.add_argument("--receipt", required=True)
    inspect.add_argument("--expected-sha256", required=True)

    if topic == ("sarif",):
        return sarif

    if len(topic) == 2 and topic[0] == "sarif" and topic[1] in actions.choices:
        return actions.choices[topic[1]]

    return parser


def BridgeArguments(arguments: Sequence[str]) -> None:
    """Refuse repeated scalar options before paths or owning stores are touched.

    Args:
        arguments: Forwarded tokens after the shared CLI's global help/JSON normalization.
    """

    seen: set[str] = set()

    for value in arguments:
        name = value.split("=", 1)[0]

        if name.startswith("--"):
            if name in seen:
                raise IntelFailure("configuration", 2)

            seen.add(name)


def BridgeRoot(value: str) -> None:
    """Validate an explicit immutable root's grammar without opening its workspace.

    Args:
        value: Independently selected original or receipt manifest identifier.
    """

    if not value.startswith("sha256:"):
        raise ValueError("SARIF inspection requires exact manifest roots")

    RequireEvidenceDigest(value[7:])


def BridgeTerminal(outcome: dict[str, object], jsonOutput: bool) -> str:
    """Stage complete portable output without interpreting source URI or Markdown strings.

    Args:
        outcome: Actual command facts, with a projection only after complete verification.
        jsonOutput: Select a machine document rather than a labelled source-assertion display.

    Returns:
        One complete ASCII-safe text value within the actual terminal byte budget.
    """

    body = json.dumps(outcome, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":") if jsonOutput else None,
                      indent=None if jsonOutput else 2, allow_nan=False)
    prefix = "" if jsonOutput else "Saved SARIF source assertions; no canonical Findings or risk.\n"
    text = prefix + body + "\n"

    if len(text.encode("utf-8")) > MAX_TERMINAL_BYTES:
        raise ValueError("SARIF terminal output exceeds its byte profile")

    return text


def RunBridgeCommands(
    arguments: Sequence[str], output: TextIO, *, jsonOutput: bool = False,
    clock: Callable[[], datetime] = UtcNow,
) -> int:
    """Import one owned file or inspect exact retained SARIF custody without running an analyzer.

    Args:
        arguments: Explicit local profile/action and caller-owned source or original receipt pins.
        output: Caller-owned terminal stream; no partial source projection is written.
        jsonOutput: Emit the distinct version-one source-assertion outcome.
        clock: Actual local file-copy observation clock, unused during retained inspection.

    Returns:
        Zero for help or complete verified custody; two for configuration, four for integrity,
        parsing, storage or presentation refusal, and 130 for interruption.
    """

    selected = list(arguments)

    if selected and selected[-1] in ("--help", "-h") and tuple(selected[:-1]) in (
        (), ("sarif",), ("sarif", "import"), ("sarif", "inspect"),
    ):
        helpOutput = StringIO()
        BridgeParser(tuple(selected[:-1])).print_help(file=helpOutput)
        text = helpOutput.getvalue()

        if output.write(text) != len(text):
            raise OSError("SARIF help output was not written completely")

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "profile": "bridge-sarif-source-cli-v1", "command": "bridge.sarif",
        "status": "failed", "failure": None, "original_id": None, "receipt_id": None,
        "source_sha256": None, "source_bytes": None, "original_commit": "not-attempted",
        "receipt_commit": "not-attempted", "ack_basis": "not-attempted",
        "model_commit": "not-attempted", "workspace_commit": "not-attempted",
        "canonical_findings": "not-created", "risk": "not-evaluated",
        "publisher_authentication": "not-assessed", "scan_completeness": "not-assessed",
    }
    status = 4
    phase = "configuration"

    try:
        BridgeArguments(arguments)
        options = BridgeParser().parse_args(arguments)
        RequireEvidenceDigest(options.expected_sha256)
        outcome["command"] = "bridge.sarif." + options.action

        if options.action == "import":
            RequireIdentifier(options.scope, "scope")
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
            root = IntelPath(options.workspace)
            phase = "integrity"
            workspace = LocalWorkspaceStore(root).Open()
            scope = LocalScopeStore(root).Open(options.scope)

            if scope.workspace_id != workspace.workspace_id:
                raise ValueError("SARIF selected scope belongs to another workspace")

            phase = "source"
            selectedFile = options.file.absolute()
            buffer = BytesIO()
            startedAt = clock().isoformat()
            observed = ReadArtifactFile(selectedFile, "original.sarif", buffer,
                                        max_bytes=MAX_SOURCE_BYTES)
            finishedAt = clock().isoformat()
            raw = buffer.getvalue()

            if observed.sha256 != options.expected_sha256 or (
                hashlib.sha256(raw).hexdigest() != options.expected_sha256
            ):
                raise ValueError("SARIF selected original does not match its byte pin")

            phase = "parse"
            projection = ParseSarif(raw)
            provenance = EvidenceProvenance(workspace.workspace_id, "scope:" + options.scope,
                SOURCE_ID, SOURCE_VERSION, None, startedAt, finishedAt)
            store = LocalEvidenceStore(root / "evidence")
            phase = "storage"
            outcome.update({"original_commit": "unknown", "ack_basis": "publication-attempted"})
            original = store.Put(raw, RAW_ROLE, RAW_MEDIA, provenance)
            outcome.update({"original_commit": "confirmed", "original_id": original.evidence_id,
                            "source_sha256": original.reference.sha256,
                            "source_bytes": original.reference.size_bytes})
            receiptPayload = JsonBytes(ReceiptContent(original, consent, projection))

            if len(receiptPayload) > MAX_RECEIPT_BYTES:
                raise ValueError("SARIF receipt exceeds its byte profile")

            outcome["receipt_commit"] = "unknown"
            receipt = store.Put(receiptPayload, RECEIPT_ROLE, "application/json", provenance)
            outcome.update({"receipt_commit": "confirmed", "receipt_id": receipt.evidence_id,
                            "ack_basis": "owner-returned"})

        else:
            BridgeRoot(options.original)
            BridgeRoot(options.receipt)
            root = IntelPath(options.workspace)
            phase = "integrity"
            projection, original, receipt = LoadSavedSarif(
                root, options.original, options.receipt, options.expected_sha256,
            )
            outcome.update({"original_commit": "confirmed", "receipt_commit": "confirmed",
                "original_id": original.evidence_id, "receipt_id": receipt.evidence_id,
                "source_sha256": original.reference.sha256,
                "source_bytes": original.reference.size_bytes, "ack_basis": "verified-present"})

        outcome["projection"] = projection
        outcome["status"] = "succeeded"
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
        outcome.pop("projection", None)
        outcome["status"] = "failed"

    try:
        text = BridgeTerminal(outcome, jsonOutput)

    except (KeyboardInterrupt, ValueError, OverflowError, RecursionError) as error:
        outcome.pop("projection", None)
        outcome.update({"status": "failed", "failure": "interrupted" if isinstance(
            error, KeyboardInterrupt) else "presentation-limit"})
        status = 130 if isinstance(error, KeyboardInterrupt) else 4
        text = json.dumps(outcome, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n"

    if output.write(text) != len(text):
        raise OSError("SARIF command output was not written completely")

    return status
