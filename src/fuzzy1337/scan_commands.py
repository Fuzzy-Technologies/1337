# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit workspace, consent and bounded endpoint or closed synthetic product commands."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO
from urllib.parse import urlsplit

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent
from fuzzy1337.configuration_workflow import (
    ConfigurationScanSelection,
    ConfigurationScanSummary,
    RunSyntheticConfigurationScan,
)
from fuzzy1337.discovery import DiscoveryLimits
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.image_workflow import ImageScanSelection, ImageScanSummary, RunSyntheticImageScan
from fuzzy1337.jobs import JobEvent, JobEventKind
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.nucleiscan import (
    NucleiAuthorityDeniedError,
    NucleiScanLimits,
    NucleiScanSummary,
    NucleiUnavailableError,
    PlanNucleiScan,
    ReadNucleiPolicy,
    ReadNucleiProfile,
    RunNucleiScan,
)
from fuzzy1337.policy import ImpactPolicy, PolicyConfirmation, PolicyDeniedError
from fuzzy1337.quickscan import QuickScanSummary, RunQuickScan, VerifyWorkspaceEvidence
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    WorkspaceBusyError,
    WorkspaceConfiguration,
    WorkspaceConflictError,
)


class ProductArgumentParser(argparse.ArgumentParser):
    """Keep rejected product arguments out of diagnostic output as well as shell history."""

    def Error(self, message: str) -> NoReturn:
        """Reject malformed arguments without reflecting unknown credential-bearing values.

        Args:
            message: Untrusted argparse diagnostic, deliberately excluded from output.

        Returns:
            This callback never returns; invalid arguments terminate command parsing.

        Raises:
            SystemExit: Usage and a generic actionable diagnostic exit with status two.
        """

        super().error("Invalid command arguments; use --help for explicit required inputs.")

    # argparse owns this callback name; implementation keeps project method naming.
    error = Error


def Endpoint(value: str) -> Target:
    """Accept only explicit literal-IP HTTP(S) paths without credential-bearing URL fields.

    Args:
        value: Operator-selected non-secret endpoint literal.

    Returns:
        Canonical typed URL target; no name resolution or network request occurs.

    Raises:
        ValueError: The URL contains a hostname, query, fragment or credential field.
    """

    parsed = urlsplit(value)

    if (
        parsed.query or parsed.fragment
        or parsed.username is not None or parsed.password is not None
    ):
        raise ValueError("discovery URL must not contain queries, fragments or credentials")

    ipaddress.ip_address(parsed.hostname or "")

    return Target(TargetKind.URL, value)


def WriteJson(output: TextIO, document: object) -> None:
    """Write one complete strict JSON line with immediate presentation flushing.

    Args:
        output: Operator output stream.
        document: Detached machine-readable fields without raw evidence contents.
    """

    output.write(json.dumps(document, sort_keys=True, allow_nan=False) + "\n")
    output.flush()


def CreateWorkspace(path: Path, workspace_id: str, display_name: str) -> dict[str, object]:
    """Initialize existing workspace/model stores without authorizing or contacting targets.

    Args:
        path: New workspace root beneath an existing operator-owned parent.
        workspace_id: Durable lowercase workspace identifier.
        display_name: Non-secret display metadata.

    Returns:
        Created authoritative metadata with initialized empty model.
    """

    store = LocalWorkspaceStore(path)
    state = store.Create(WorkspaceConfiguration(display_name), workspace_id)
    LocalModelStore(store.root).Create()

    return state.ToDict()


def OpenWorkspace(path: Path) -> dict[str, object]:
    """Reopen and verify the existing shared model and every retained evidence acquisition.

    Args:
        path: Existing operator-owned workspace root.

    Returns:
        Detached authoritative metadata and finite model/evidence counts.

    Raises:
        ValueError: Evidence belongs to another workspace or integrity is inconsistent.
        EvidenceError: An acquisition or raw content cannot be independently verified.
    """

    store = LocalWorkspaceStore(path)
    workspace = store.Open()
    model = LocalModelStore(store.root).Open()
    evidence = LocalEvidenceStore(store.root / "evidence")

    VerifyWorkspaceEvidence(workspace, evidence)

    return {
        "schema_version": 1,
        "workspace": workspace.ToDict(),
        "model_revision": model.revision,
        "object_counts": {kind.value: len(model.Objects(kind)) for kind in ObjectKind},
        "relation_count": len(model.relations),
        "verified_evidence_records": len(workspace.evidence_record_references),
    }


def CreateScope(path: Path, arguments: argparse.Namespace) -> dict[str, object]:
    """Record supplied targets/rules and explicit consent without inferring any approval.

    Args:
        path: Existing initialized workspace root.
        arguments: Parsed finite targets, actor, consent and validity fields.

    Returns:
        Created scope document, including unknown consent when no grant was supplied.
    """

    workspace_store = LocalWorkspaceStore(path)
    workspace = workspace_store.Open()
    targets = tuple(Endpoint(value) for value in arguments.allow_url) + tuple(
        Target(TargetKind.IP, value) for value in arguments.allow_ip
    ) + tuple(
        Target(TargetKind.ARTIFACT, value) for value in arguments.allow_artifact
    )
    exclusions = tuple(Endpoint(value) for value in arguments.exclude_url) + tuple(
        Target(TargetKind.IP, value) for value in arguments.exclude_ip
    ) + tuple(
        Target(TargetKind.ARTIFACT, value) for value in arguments.exclude_artifact
    )

    if not targets or len(targets) + len(exclusions) > 64:
        raise ValueError("scope must supply between one and 64 explicit rules")

    authorization = ScopeAuthorization(
        AuthorizationState.GRANTED if arguments.grant_consent else AuthorizationState.UNKNOWN,
        arguments.owner, arguments.consent_reference, arguments.valid_from, arguments.valid_until,
    )

    snapshot = ScopeSnapshot(
        arguments.id, workspace.workspace_id, authorization, targets=targets, allow=targets,
        exclusions=exclusions,
    )

    snapshot = LocalScopeStore(workspace_store.root).Create(snapshot)

    return snapshot.ToDict()


def CommandParser(command: str) -> argparse.ArgumentParser:
    """Build only the selected namespace's explicit local product commands.

    Args:
        command: Canonical workspace, scope or scan namespace.

    Returns:
        Finite parser which never dispatches a scanner by itself.
    """

    parser = ProductArgumentParser(prog=f"1337 {command}")
    actions = parser.add_subparsers(dest="action", required=True)

    if command == "workspace":
        create = actions.add_parser("create", help="Create a workspace and empty shared model.")
        create.add_argument("path", type=Path)
        create.add_argument("--id", required=True)
        create.add_argument("--name", required=True)
        actions.add_parser("open", help="Verify retained workspace/model/evidence.").add_argument(
            "path", type=Path,
        )

    elif command == "scope":
        create = actions.add_parser("create", help="Record explicit rules and operator consent.")
        create.add_argument("path", type=Path)
        create.add_argument("--id", required=True)
        create.add_argument("--allow-url", action="append", default=[])
        create.add_argument("--allow-ip", action="append", default=[])
        create.add_argument("--allow-artifact", action="append", default=[],
                            help="Explicit manifest-sha256:<lowercase-sha256> artifact target.")
        create.add_argument("--exclude-url", action="append", default=[])
        create.add_argument("--exclude-ip", action="append", default=[])
        create.add_argument("--exclude-artifact", action="append", default=[])
        create.add_argument("--grant-consent", action="store_true")
        create.add_argument("--owner")
        create.add_argument("--consent-reference")
        create.add_argument("--valid-from")
        create.add_argument("--valid-until")

    elif command == "scan":
        quick = actions.add_parser("quick", help="Run bounded approved SAFE endpoint discovery.")
        quick.add_argument("path", type=Path)
        quick.add_argument("--scope", required=True)
        quick.add_argument("--owner", required=True)
        quick.add_argument("--target", action="append", required=True)
        quick.add_argument("--approve-safe-http", action="store_true")
        quick.add_argument("--max-endpoints", type=int, default=8)
        quick.add_argument("--request-timeout", type=float, default=3.0)
        quick.add_argument("--interval", type=float, default=0.2)
        quick.add_argument("--timeout", type=float, default=30.0)
        quick.add_argument("--events-json", action="store_true")
        nuclei = actions.add_parser("nuclei", help="Plan/run one reviewed STANDARD Nuclei profile.")
        nuclei.add_argument("path", type=Path)
        nuclei.add_argument("--scope", required=True)
        nuclei.add_argument("--owner", required=True)
        nuclei.add_argument("--target", required=True)
        nuclei.add_argument("--profile", type=Path, required=True)
        nuclei.add_argument("--policy", type=Path, required=True)
        nuclei.add_argument("--executable", required=True)
        nuclei.add_argument("--timeout", type=int, default=30)
        nuclei.add_argument("--rate-limit", type=int, default=2)
        nuclei.add_argument("--plan", action="store_true")
        nuclei.add_argument("--confirm-plan")
        nuclei.add_argument("--confirmation-reference")
        nuclei.add_argument("--events-json", action="store_true")
        image = actions.add_parser("image", help="Run the closed synthetic image workflow.")
        image.add_argument("path", type=Path)
        image.add_argument("--profile", choices=("synthetic",), required=True,
                           help="Explicitly select synthetic fixture interpretation.")
        image.add_argument("--scope", required=True)
        image.add_argument("--owner", required=True)
        image.add_argument("--archive", type=Path, required=True)
        image.add_argument("--executable", type=Path, required=True,
                           help="Absolute selected current trusted CPython executable.")
        image.add_argument("--producer", type=Path, required=True,
                           help="Absolute selected reviewed first-party image worker.")
        image.add_argument("--material", type=Path, required=True,
                           help="Absolute selected synthetic material policy.")
        image.add_argument("--read-consent-reference", required=True)
        image.add_argument("--approve-safe-image", action="store_true")
        image.add_argument("--timeout", type=int, default=30)
        image.add_argument("--report-format", choices=("json", "sarif"))
        image.add_argument("--report-output", type=Path)
        image.add_argument("--events-json", action="store_true")
        config = actions.add_parser("config",
                                    help="Run the closed synthetic configuration workflow.")
        config.add_argument("path", type=Path)
        config.add_argument("--profile", choices=("synthetic",), required=True,
                            help="Explicitly select reviewed synthetic source interpretation.")
        config.add_argument("--type", choices=("dockerfile", "kubernetes"), required=True,
                            help="Select the closed Dockerfile or Kubernetes source profile.")
        config.add_argument("--logical-path", required=True,
                            help="Exact selected source name in the reviewed input manifest.")
        config.add_argument("--source", type=Path, required=True,
                            help="Absolute selected reviewed synthetic source file.")
        config.add_argument("--scope", required=True)
        config.add_argument("--owner", required=True)
        config.add_argument("--executable", type=Path, required=True,
                            help="Absolute selected current trusted CPython executable.")
        config.add_argument("--producer", type=Path, required=True,
                            help="Absolute selected reviewed first-party configuration worker.")
        config.add_argument("--material", type=Path, required=True,
                            help="Absolute selected synthetic material policy.")
        config.add_argument("--read-consent-reference", required=True)
        config.add_argument("--approve-safe-configuration", action="store_true")
        config.add_argument("--timeout", type=int, default=30)
        config.add_argument("--report-format", choices=("json", "sarif"))
        config.add_argument("--report-output", type=Path)
        config.add_argument("--events-json", action="store_true")

    else:
        raise ValueError("unsupported local command namespace")

    return parser


def RunCommands(
    command: str, argv: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Execute local product commands with explicit safe machine and human output.

    Args:
        command: workspace, scope or scan namespace.
        argv: Namespace arguments excluding global --json.
        output: Explicit presentation stream, shared by CLI and foreground shell.
        json_output: Emit one JSON summary; scan --events-json emits a separate JSON-line stream.

    Returns:
        Zero for success, two for invalid inputs, three for denied scan, four for failure,
        or 130 for cancelled execution.

    Raises:
        SystemExit: Command parsing rejects missing or ambiguous arguments or prints help.
    """

    parser = CommandParser(command)
    arguments = parser.parse_args(argv)

    if command == "scope" and arguments.grant_consent and not all((
        arguments.owner, arguments.consent_reference, arguments.valid_from, arguments.valid_until,
    )):
        parser.error("--grant-consent requires owner, consent reference and both validity bounds")

    if command == "scan" and arguments.events_json and json_output:
        parser.error("choose --json or --events-json")

    if command == "scan" and arguments.action in {"image", "config"} and (
        (arguments.report_format is None) != (arguments.report_output is None)
    ):
        parser.error("supply both report format and new output destination")

    if command == "scan" and arguments.action == "nuclei":
        if bool(arguments.confirm_plan) != bool(arguments.confirmation_reference):
            parser.error("supply both exact plan digest and confirmation record reference")

        if arguments.plan and (arguments.confirm_plan or arguments.events_json):
            parser.error("planning is read-only and emits one exact plan document")

    try:
        if command == "workspace":
            document = (CreateWorkspace(arguments.path, arguments.id, arguments.name)
                        if arguments.action == "create" else OpenWorkspace(arguments.path))

        elif command == "scope":
            document = CreateScope(arguments.path, arguments)

        else:
            if arguments.action == "nuclei":
                profile = ReadNucleiProfile(arguments.profile)
                nuclei_limits = NucleiScanLimits(arguments.timeout, arguments.rate_limit)
                target = Endpoint(arguments.target)

                def ReadPolicy() -> ImpactPolicy:
                    """Reread the selected strict local policy at every authority boundary."""

                    return ReadNucleiPolicy(arguments.policy)

                if arguments.plan:
                    plan = PlanNucleiScan(arguments.path, arguments.scope, target, arguments.owner,
                                         profile, arguments.executable, ReadPolicy,
                                         limits=nuclei_limits)
                    WriteJson(output, plan.ToDict())

                    return 0

            def OnEvent(event: JobEvent) -> None:
                """Stream actual ordered status or structured events without raw process output."""

                if arguments.events_json:
                    WriteJson(output, {"schema_version": 1, "type": "event",
                                       "event": json.loads(SerializeContract(event))})

                elif not json_output and event.kind in (
                    JobEventKind.STATE, JobEventKind.MODEL_DELTA, JobEventKind.PROGRESS,
                ):
                    output.write(
                        f"{event.sequence} {event.kind.value}: {SerializeContract(event.data)}\n"
                    )

                    output.flush()

            if arguments.action == "nuclei":
                summary: (NucleiScanSummary | QuickScanSummary | ImageScanSummary
                          | ConfigurationScanSummary) = asyncio.run(
                    RunNucleiScan(
                        arguments.path, arguments.scope, target, arguments.owner, profile,
                        arguments.executable, ReadPolicy,
                        confirmation=PolicyConfirmation(arguments.confirm_plan,
                            arguments.confirmation_reference) if arguments.confirm_plan else None,
                        limits=nuclei_limits, on_event=OnEvent,
                    )
                )

            elif arguments.action == "image":
                selection = ImageScanSelection(arguments.archive, arguments.executable,
                    arguments.producer, arguments.material,
                    ArtifactReadConsent(arguments.owner, arguments.read_consent_reference))
                summary = asyncio.run(RunSyntheticImageScan(
                    arguments.path, arguments.scope, arguments.owner, selection,
                    approve_safe_image=arguments.approve_safe_image,
                    timeout_seconds=arguments.timeout, on_event=OnEvent,
                    report_format=arguments.report_format, report_output=arguments.report_output,
                ))

            elif arguments.action == "config":
                configuration_selection = ConfigurationScanSelection(
                    ArtifactProfile.SYNTHETIC_DOCKERFILE if arguments.type == "dockerfile" else
                    ArtifactProfile.SYNTHETIC_KUBERNETES, arguments.logical_path,
                    arguments.source, arguments.executable, arguments.producer, arguments.material,
                    ArtifactReadConsent(arguments.owner, arguments.read_consent_reference))
                summary = asyncio.run(RunSyntheticConfigurationScan(
                    arguments.path, arguments.scope, arguments.owner, configuration_selection,
                    approve_safe_configuration=arguments.approve_safe_configuration,
                    timeout_seconds=arguments.timeout, on_event=OnEvent,
                    report_format=arguments.report_format, report_output=arguments.report_output,
                ))

            else:
                summary = asyncio.run(RunQuickScan(
                    arguments.path, arguments.scope,
                    tuple(Endpoint(value) for value in arguments.target), arguments.owner,
                    approve_safe_http=arguments.approve_safe_http,
                    limits=DiscoveryLimits(
                        max_endpoints=arguments.max_endpoints,
                        request_timeout_seconds=arguments.request_timeout,
                        interval_seconds=arguments.interval, timeout_seconds=arguments.timeout,
                    ),
                    on_event=OnEvent,
                ))

            document = summary.ToDict()

            if arguments.events_json:
                WriteJson(output, {"schema_version": 1, "type": "summary", "summary": document})

            elif json_output:
                WriteJson(output, document)

            else:
                label = {"nuclei": "Nuclei Scan", "image": "Synthetic Image Scan",
                         "config": "Synthetic Configuration Scan",
                         "quick": "Quick Scan"}[arguments.action]
                output.write(f"{label} {summary.snapshot.state.value}; "
                             f"model revision {summary.model_revision}; "
                             f"evidence records {len(summary.snapshot.artifacts)}\n")

                output.flush()

            return summary.ExitCode()

    except (NucleiAuthorityDeniedError, PolicyDeniedError):
        WriteJson(output, {"schema_version": 1, "state": "failed",
                           "failure": {"code": "authorization",
                                       "message": "Current scan authority denied execution"}})

        return 3

    except NucleiUnavailableError:
        WriteJson(output, {"schema_version": 1, "state": "failed",
                           "failure": {"code": "provider",
                                       "message": "Selected Nuclei provider is unavailable"}})

        return 4

    except ValueError:
        WriteJson(output, {"schema_version": 1, "state": "failed",
                           "failure": {"code": "invalid_configuration",
                                       "message": "Invalid local command inputs or state"}})

        return 2

    except (OSError, EvidenceError, WorkspaceBusyError, WorkspaceConflictError):
        WriteJson(output, {"schema_version": 1, "state": "failed",
                           "failure": {"code": "storage",
                                       "message": "Could not open, verify or save local state"}})

        return 4

    if json_output:
        WriteJson(output, document)

    else:
        output.write(f"{command} {arguments.action}: succeeded\n")
        output.flush()

    return 0
