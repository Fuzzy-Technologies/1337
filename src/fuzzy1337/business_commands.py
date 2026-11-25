# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal read-only inspection of retained owner-declared outcomes and critical Assets."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO, cast

from fuzzy1337.business_events import (
    ApplyBusinessEvent,
    DefinitionEvidenceStore,
    ReadBusinessEventDefinition,
    Representation,
    Text,
)
from fuzzy1337.evidence import EvidenceError, RequireEvidenceDigest
from fuzzy1337.model import LocalModelStore
from fuzzy1337.reachability import ReachabilityModelVersion
from fuzzy1337.report_commands import BoundedReportEvidenceStore, ReportFailure
from fuzzy1337.runtime_commands import RuntimeArgumentParser, RuntimeFailure, RuntimePath


def BusinessParser() -> argparse.ArgumentParser:
    """Declare one explicit retained definition and its complete saved-model selection.

    Returns:
        Fixed-diagnostic parser without discovery, acquisition or implicit scope selection.
    """

    parser = RuntimeArgumentParser(prog="1337 business", add_help=False, allow_abbrev=False)
    parser.add_argument("action", choices=("inspect",))
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--definition", required=True)
    parser.add_argument("--scope-reference", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-snapshot-sha256", required=True)

    return parser


def InspectBusinessEvent(
    root: Path, identity: str, scope: str, revision: int, digest: str,
) -> dict[str, object]:
    """Verify one already persisted declaration and return existing canonical record shapes.

    Args:
        root: Explicit existing physical owning workspace.
        identity: Independently selected original definition manifest identity.
        scope: Original declaration attribution, not an execution grant.
        revision: Independently selected current model revision.
        digest: Complete canonical model SHA-256 selected with that revision.

    Returns:
        Original definition manifest, current declaration, critical Assets and memberships,
        with their unchanged canonical provenance and exact model pin.

    Raises:
        ValueError: Original definition, model selection or persisted representation disagrees.
        EvidenceError: Selected original or referenced model evidence cannot be verified.
        OSError: The existing owning storage cannot be read.
        ReportFailure: Selected evidence exceeds the existing report consumer's read budgets.
    """

    model = LocalModelStore(root).Open()
    version = ReachabilityModelVersion.FromModel(model)

    if version.revision != revision or version.snapshot_sha256 != digest:
        raise ValueError("The saved model differs from its independently selected complete pin")

    record = DefinitionEvidenceStore(root / "evidence").Get(identity)
    definition = ReadBusinessEventDefinition(model, record, workspace_root=root,
        expected_model_version=version, scope_reference=scope)
    repeated, delta = ApplyBusinessEvent(definition, model)

    if repeated != model or delta.created or delta.updated:
        raise ValueError("Inspection requires an exact persisted declaration and membership")

    declaration, links = Representation(definition)
    entities = {item.Reference(): item for item in model.objects}
    assets = tuple(entities[reference] for reference in definition.critical_asset_references)
    references = dict.fromkeys(
        reference for entity in (declaration, *assets, *links)
        for provenance in entity.provenance for reference in provenance.evidence_references
    )
    evidence = BoundedReportEvidenceStore(root / "evidence")

    for reference in references:
        evidence.Read(reference)

    # Reuse the source owner again after support reads; no writer lock is claimed.
    if ReadBusinessEventDefinition(model, record, workspace_root=root,
        expected_model_version=version, scope_reference=scope) != definition:
        raise ValueError("The original declaration changed during inspection")

    document = model.ToDict()
    objects = {item["reference"]: item for item in cast(list[dict[str, Any]], document["objects"])}
    relations = {item["reference"]: item
                 for item in cast(list[dict[str, Any]], document["relations"])}

    return {
        "model_version": {
            "schema_version": version.schema_version, "workspace_id": version.workspace_id,
            "revision": version.revision, "snapshot_sha256": version.snapshot_sha256,
        },
        "definition_reference": definition.definition_reference,
        "definition_evidence_id": record.evidence_id,
        "definition_record": record.ToDict(),
        "declaration": objects[declaration.Reference()],
        "critical_assets": [objects[item.Reference()] for item in assets],
        "memberships": [relations[reference] for reference in
                        sorted(item.Reference() for item in links)],
        "checked_model_evidence_references": len(references),
        "semantics": "declared-unacceptable-outcome",
    }


def RunBusinessCommands(
    arguments: Sequence[str], output: TextIO, *, machine: bool = False,
) -> int:
    """Inspect retained owner declarations without scoring, analysis or storage writes.

    Args:
        arguments: Exact inspect action, workspace, definition, scope and complete model pins.
        output: Caller-owned terminal stream; selected declaration facts may be sensitive.
        machine: Emit a version-one terminal envelope containing canonical stored records.

    Returns:
        Zero after complete inspection, two for configuration, four for integrity/read refusal,
        or 130 for interruption. Failed outcomes contain no partial inspection records.
    """

    if list(arguments) in (["--help"], ["-h"], ["inspect", "--help"], ["inspect", "-h"]):
        BusinessParser().print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "business.inspect", "status": "failed",
        "failure": None, "core_mutation": "none", "evidence_commit": "not-attempted",
    }
    status = 4
    phase = "configuration"
    inspected: dict[str, object] | None = None

    try:
        seen: set[str] = set()

        for argument in arguments:
            flag = argument.split("=", 1)[0]

            if flag.startswith("--"):
                if flag in seen:
                    raise RuntimeFailure("configuration", 2)

                seen.add(flag)

        options = BusinessParser().parse_args(arguments)

        if not options.definition.startswith("sha256:") or options.expected_revision < 0:
            raise RuntimeFailure("configuration", 2)

        RequireEvidenceDigest(options.definition[7:])
        RequireEvidenceDigest(options.expected_snapshot_sha256)
        Text(options.scope_reference, 4096)
        root = RuntimePath(options.workspace)
        phase = "integrity"
        inspected = InspectBusinessEvent(root, options.definition, options.scope_reference,
            options.expected_revision, options.expected_snapshot_sha256)
        status = 0

    except RuntimeFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except ReportFailure as error:
        outcome["failure"] = error.kind
        status = error.status

    except (EvidenceError, OSError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    outcome["exit_code"] = status

    if status == 0 and inspected is not None:
        outcome.update({"status": "completed", "inspection": inspected})

    if machine:
        text = json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    else:
        text = f"business.inspect: {outcome['status']} (exit {status}).\n"

        if status == 0 and inspected is not None:
            declaration = cast(dict[str, Any], inspected["declaration"])
            fields = declaration["attributes"]
            text += "Owner-declared unacceptable outcome; declared critical-asset membership.\n"

            for label, field in (("Title", "title"), ("Declared outcome", "unacceptable_outcome"),
                                 ("Supplied owner reference", "owner_reference")):
                text += f"{label}: {json.dumps(fields[field], ensure_ascii=True)}\n"

            text += "Critical Assets recorded in the selected saved model:\n"

            for asset in cast(list[dict[str, Any]], inspected["critical_assets"]):
                text += (f"  {json.dumps(asset['identity']['key'], ensure_ascii=True)} "
                         f"({asset['reference']})\n")

            text += f"Original definition manifest: {inspected['definition_evidence_id']}\n"
            text += "The original definition records an owner-declared scenario.\n"

        else:
            text += f"Failure category: {outcome['failure']}.\n"

    if output.write(text) != len(text):
        raise OSError("Incomplete business inspection terminal write")

    return status
