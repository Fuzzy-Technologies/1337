# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit local-reference export namespace, independent of archive scan consent."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.artifact_policy import ArtifactDeniedError
from fuzzy1337.jobs import JobEvent
from fuzzy1337.local_image_reference import DEFAULT_DOCKER_SOCKET, LocalImageSelection, SelectedPath
from fuzzy1337.local_image_workflow import ExportLocalImage, PlanLocalImageExport
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.workspace import LocalWorkspaceStore


def ExplicitLocalPath(value: str) -> Path:
    """Reject ambiguous selected path spelling before normalization or filesystem reads.

    Args:
        value: Exact absolute operator-selected trusted executable or socket path.

    Returns:
        Unmodified canonical lexical Path without resolving filesystem aliases.
    """

    path = Path(value)
    SelectedPath(path)
    if str(path) != value:
        raise ValueError("local image path spelling must be explicit and canonical")
    return path


def LocalImageParser() -> argparse.ArgumentParser:
    """Build a closed export-only grammar with explicit plan and execution alternatives.

    Returns:
        Parser without a scanner, registry operation or implicit Docker discovery option.
    """

    parser = argparse.ArgumentParser(prog="1337 image")
    actions = parser.add_subparsers(dest="action", required=True)
    export = actions.add_parser("export-local", help="Export a governed local image reference.")
    export.add_argument("workspace", type=Path)
    export.add_argument("--reference", required=True)
    export.add_argument("--owner", required=True)
    export.add_argument("--executable", required=True)
    export.add_argument("--socket", default=str(DEFAULT_DOCKER_SOCKET))
    export.add_argument("--read-consent-reference", required=True)
    export.add_argument("--scope")
    export.add_argument("--policy", type=Path)
    export.add_argument("--plan", action="store_true")
    export.add_argument("--approve-local-image", action="store_true")
    export.add_argument("--events-json", action="store_true")
    return parser


def RunLocalImageCommands(argv: Sequence[str], output: TextIO, *, json_output: bool = False) -> int:
    """Dispatch pure source planning or one explicitly approved local export job.

    Args:
        argv: Explicit arguments after the image namespace.
        output: Caller-owned text stream for stable diagnostics and factual summaries.
        json_output: Select detached machine-readable plan or outcome.

    Returns:
        Zero completed, two invalid, three denied, four failed, or 130 cancelled.
    """

    parser = LocalImageParser()
    arguments = parser.parse_args(argv)

    def Write(value: object) -> None:
        """Write one complete detached JSON line without raw daemon or policy diagnostics.

        Args:
            value: Original typed plan, event or bounded outcome facts.
        """

        output.write(SerializeContract(value) + "\n")
        output.flush()

    try:
        if arguments.plan:
            if arguments.scope is not None or arguments.policy is not None or (
                arguments.approve_local_image or arguments.events_json
            ):
                raise ValueError("pure local source plan excludes execution authority arguments")
        elif not arguments.scope or arguments.policy is None or not arguments.approve_local_image:
            raise ValueError("local image export requires scope, policy and explicit approval")
        root = LocalWorkspaceStore(arguments.workspace).root
        selection = LocalImageSelection(root, arguments.reference,
            ExplicitLocalPath(arguments.executable),
            ArtifactReadConsent(arguments.owner, arguments.read_consent_reference),
            ExplicitLocalPath(arguments.socket))
        if arguments.plan:
            document = PlanLocalImageExport(selection).ToDict()
            if json_output:
                Write(document)
            else:
                output.write("Local source plan; execution is not authorized.\n")
                output.write(json.dumps(document, indent=2) + "\n")
            return 0

        def Policy() -> ImpactPolicy:
            """Reread the explicitly selected policy without deriving permissions from approval.

            Returns:
                Current canonical typed policy from the operator-selected file.
            """

            return ReadNucleiPolicy(arguments.policy)

        def Event(event: JobEvent) -> None:
            """Present original ordered job events only when explicitly requested.

            Args:
                event: Unchanged canonical job event without raw daemon output.
            """

            if arguments.events_json:
                Write({"schema_version": 1, "type": "event", "event": event})

        summary = asyncio.run(ExportLocalImage(selection, str(arguments.scope), arguments.owner,
            Policy, approve_local_image=True, on_event=Event))
        if json_output or arguments.events_json:
            Write(summary.ToDict())
        else:
            output.write("Local image export: " + summary.snapshot.state.value + "\n")
            if summary.archive_relative_path is not None:
                output.write("Archive: " + summary.archive_relative_path + "\n")
                output.write("Register and approve its archive target before scanning.\n")
        return summary.ExitCode()
    except ArtifactDeniedError:
        Write({"schema_version": 1, "state": "failed", "failure": {"code": "authorization"}})
        return 3
    except (ValueError, OSError):
        Write({"schema_version": 1, "state": "failed",
               "failure": {"code": "invalid_configuration"}})
        return 2
    except KeyboardInterrupt:
        Write({"schema_version": 1, "state": "cancelled", "failure": {"code": "interrupted"}})
        return 130
