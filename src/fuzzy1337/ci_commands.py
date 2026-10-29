# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit governed CI profiles with selected predicates and saved-snapshot report artifacts."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import math
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    GovernedArtifactExecutor,
    ProfileCapability,
)
from fuzzy1337.ci_gate import (
    CiFindingCriterion,
    EvaluateConfigurationCriterion,
    EvaluateImageCriterion,
    EvaluateNativeImageCriterion,
)
from fuzzy1337.configuration_evidence import ConfigurationOperationCapture
from fuzzy1337.configuration_workflow import (
    ConfigurationReportOutcome,
    ConfigurationScanSelection,
    ConfigurationScanSummary,
    RunSyntheticConfigurationScan,
)
from fuzzy1337.evidence import EvidenceError, EvidenceRecord
from fuzzy1337.findings import FindingSeverity, FindingStatus
from fuzzy1337.image_evidence import ImageOperationCapture
from fuzzy1337.image_workflow import (
    ImageReportOutcome,
    ImageScanSelection,
    ImageScanSummary,
    RunSyntheticImageScan,
)
from fuzzy1337.jobs import (
    JobArtifact,
    JobFailure,
    JobFailureCode,
    JobSnapshot,
    JobSpec,
    JobState,
)
from fuzzy1337.native_image_capture import NativeTrivyOperationCapture, NativeTrivySelection
from fuzzy1337.native_image_workflow import (
    NativeImageAcceptance,
    NativeImageScanSummary,
    ScanNativeImage,
    ValidateSelection,
)
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, RequireDigest
from fuzzy1337.report_commands import (
    CheckReportSnapshot,
    OpenReportInput,
    PublishReport,
    ReportArgumentParser,
    ReportFailure,
    ReportOutputPath,
    RequireReportPath,
)
from fuzzy1337.report_formats import SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.scan_commands import WriteJson
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import StoragePathInfo

__all__ = ["CiParser", "RunCiCommands"]


def CiParser() -> argparse.ArgumentParser:
    """Declare explicit governed CI profiles without launching or discovering a scanner.

    Returns:
        Parser requiring selected source, policy, predicate, acknowledgement and all artifacts.
        Invalid arguments use a fixed diagnostic category without rejected-value reflection.
    """

    parser = ReportArgumentParser(prog="1337 ci", add_help=False)
    parser.add_argument("action", choices=("scan",))
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--profile", choices=("synthetic-dockerfile", "synthetic-kubernetes",
                                             "synthetic-image", "native-trivy"), required=True)
    parser.add_argument("--logical-path")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--archive")
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--material", type=Path)
    parser.add_argument("--cache-directory")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--read-consent-reference", required=True)
    parser.add_argument("--approve-safe-configuration", action="store_true")
    parser.add_argument("--approve-safe-image", action="store_true")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--severity", choices=tuple(item.value for item in FindingSeverity),
                        action="append", required=True)
    parser.add_argument("--status", choices=tuple(item.value for item in FindingStatus),
                        action="append", required=True)
    parser.add_argument("--max-matches", type=int, required=True)
    parser.add_argument("--acknowledge-unassessed-completeness", action="store_true")
    parser.add_argument("--report-json", type=Path, required=True)
    parser.add_argument("--report-sarif", type=Path, required=True)
    parser.add_argument("--report-junit", type=Path, required=True)

    return parser


def RequireSummary(
    summary: ConfigurationScanSummary | ImageScanSummary | NativeImageScanSummary,
) -> None:
    """Refuse foreign wrappers and uncertain terminal facts before presentation or gating.

    Args:
        summary: Candidate actual closed workflow result; no external summary is trusted.

    Raises:
        ValueError: Exact owning record types, terminal state or finite fields are unsupported.
    """

    if type(summary) not in {
        ConfigurationScanSummary, ImageScanSummary, NativeImageScanSummary
    } or type(summary.snapshot) is not JobSnapshot:
        raise ValueError("CI requires the exact owning workflow summary")

    snapshot = summary.snapshot
    capture_type = NativeTrivyOperationCapture if type(summary) is NativeImageScanSummary else (
        ImageOperationCapture if type(summary) is ImageScanSummary else
        ConfigurationOperationCapture)
    report_type = ConfigurationReportOutcome if type(summary) is ConfigurationScanSummary else (
        ImageReportOutcome)

    if type(snapshot.spec) is not JobSpec or type(snapshot.state) is not JobState or (
        snapshot.state not in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
        or type(snapshot.schema_version) is not int or snapshot.schema_version != 1
        or type(snapshot.cancellation_requested) is not bool
        or type(snapshot.artifacts) is not tuple
        or any(type(item) is not JobArtifact or type(item.evidence) is not EvidenceRecord
               or item.job_id != snapshot.spec.job_id
               or item.workspace_id != snapshot.spec.workspace_id for item in snapshot.artifacts)
        or type(summary.captures) is not tuple
        or any(type(item) is not capture_type for item in summary.captures)
        or summary.report is not None and type(summary.report) is not report_type
        or snapshot.failure is not None and type(snapshot.failure) is not JobFailure
        or snapshot.state is JobState.COMPLETED and (
            snapshot.failure is not None or snapshot.cancellation_requested)
        or type(summary.model_revision) is not int or summary.model_revision < 0
    ):
        raise ValueError("CI workflow terminal facts use an unsupported contract")

    snapshot.spec.__post_init__()

    if type(summary) is NativeImageScanSummary and (
        type(summary.custody_uncertain) is not bool
        or type(summary.retained_records) is not tuple
        or any(type(item) is not EvidenceRecord for item in summary.retained_records)
        or summary.acceptance is not None and type(summary.acceptance) is not NativeImageAcceptance
    ):
        raise ValueError("CI native summary requires exact acquisition and acceptance contracts")

    if snapshot.failure is not None:
        if type(snapshot.failure.code) is not JobFailureCode:
            raise ValueError("CI failure requires an exact owning failure code")

        snapshot.failure.__post_init__()

    if summary.report is not None:
        report = summary.report

        if type(report.status) is not str or (
            report.status not in {"completed", "failed", "not-run"}
        ) or (
            report.format != "json" or type(report.output_published) is not bool
            or report.model_revision is not None and (
                type(report.model_revision) is not int or report.model_revision < 0)
            or report.size_bytes is not None and (
                type(report.size_bytes) is not int or report.size_bytes < 0)
        ):
            raise ValueError("CI report facts require exact owning field types")

        for digest in (report.snapshot_sha256, report.report_sha256):
            if digest is not None:
                if type(digest) is not str:
                    raise ValueError("CI report digests require exact strings")

                RequireDigest(digest)

    for duration in (summary.duration_seconds, summary.first_model_update_seconds):
        if duration is not None and (type(duration) not in {int, float}
                                    or not math.isfinite(duration) or duration < 0):
            raise ValueError("CI workflow timing facts must be finite and nonnegative")


def ArtifactOutcome(report: ConfigurationReportOutcome | ImageReportOutcome) -> dict[str, object]:
    """Detach the existing report owner's actual outcome without source paths or evidence bytes.

    Args:
        report: Original workflow JSON publication result, separate from original job facts.

    Returns:
        Per-artifact status, digest, byte count, confirmed publication and safe failure category.
    """

    return {"status": report.status, "model_revision": report.model_revision,
        "snapshot_sha256": report.snapshot_sha256, "report_sha256": report.report_sha256,
        "size_bytes": report.size_bytes, "output_published": report.output_published,
        "failure": report.failure}


def RunCiCommands(
    arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
) -> int:
    """Run an existing owned workflow, explicit predicate and three actual exports.

    Args:
        arguments: Explicit CI scan arguments without the global JSON presentation option.
        output: Caller-owned terminal stream; reports go only to selected new output files.
        json_output: Emit one safe schema-one command outcome instead of concise human text.

    Returns:
        Zero for acknowledged criterion satisfaction, one for criterion violation, two for invalid
        configuration, three for authority refusal, four for failed/uncertain execution, proof,
        storage or export, and 130 for cancellation/interruption. Zero never claims global clean
        state or discovery completeness. Partial artifact publication retains per-file truth.
    """

    parser = CiParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    empty_report: dict[str, object] = {
        "status": "not-run", "model_revision": None, "snapshot_sha256": None,
        "report_sha256": None, "size_bytes": None, "output_published": False, "failure": None}
    reports = {name: dict(empty_report) for name in ("json", "sarif", "junit")}
    outcome: dict[str, object] = {"schema_version": 1, "command": "ci.scan", "status": "failed",
        "scope": "selected-profile-finding-predicate", "scan_completeness": "not-assessed",
        "acknowledge_unassessed_completeness": False, "policy": None,
        "criterion": {"status": "indeterminate"}, "scan": None, "reports": reports,
        "model_revision": None, "snapshot_sha256": None, "failure": None, "exit_code": 4}
    status = 4
    phase = "configuration"
    publishing: str | None = None

    try:
        options = parser.parse_args(arguments)
        criterion = CiFindingCriterion(tuple(FindingSeverity(item) for item in options.severity),
            tuple(FindingStatus(item) for item in options.status), options.max_matches,
            options.acknowledge_unassessed_completeness)
        outcome["policy"] = criterion.ToDict()
        outcome["acknowledge_unassessed_completeness"] = True

        if type(options.timeout) is not int or not 1 <= options.timeout <= 60:
            raise ReportFailure("configuration", 2)

        native = options.profile == "native-trivy"
        image = options.profile == "synthetic-image"

        if native:
            if options.archive is None or options.cache_directory is None or (
                options.policy is None or not options.policy.is_absolute()
                or options.producer is not None or options.material is not None
                or options.source is not None or options.logical_path is not None
                or options.approve_safe_configuration
            ):
                raise ReportFailure("configuration", 2)

        elif options.producer is None or options.material is None or (
            options.cache_directory is not None or options.policy is not None
        ):
            raise ReportFailure("configuration", 2)

        if image and (options.archive is None or options.source is not None or (
            options.logical_path is not None or options.approve_safe_configuration
        )) or not image and not native and (options.source is None or (
            options.logical_path is None or options.archive is not None
            or options.approve_safe_image
        )):
            raise ReportFailure("configuration", 2)

        consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
        profile = ArtifactProfile.IMAGE if native else (
            ArtifactProfile.SYNTHETIC_IMAGE if image else ArtifactProfile.SYNTHETIC_DOCKERFILE
            if options.profile == "synthetic-dockerfile" else ArtifactProfile.SYNTHETIC_KUBERNETES)
        configuration_selection = None
        image_selection = None

        if not native:
            assert options.producer is not None and options.material is not None, (
                "Synthetic preflight requires its explicit producer and material"
            )

            if image:
                image_selection = ImageScanSelection(Path(options.archive), options.executable,
                    options.producer, options.material, consent)

            else:
                configuration_selection = ConfigurationScanSelection(profile,
                    options.logical_path, options.source, options.executable, options.producer,
                    options.material, consent)

        root = RequireReportPath(options.workspace)
        metadata = StoragePathInfo(root)

        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            raise ReportFailure("configuration", 2)

        native_selection = None

        if native:
            assert options.cache_directory is not None, "Native preflight requires explicit cache"
            native_selection = NativeTrivySelection(root, options.executable, options.archive,
                options.cache_directory, consent)
            ValidateSelection(root, options.owner, native_selection, options.timeout)

        destinations = {name: ReportOutputPath(getattr(options, "report_" + name), root)
                        for name in reports}

        if len(set(destinations.values())) != 3:
            raise ReportFailure("configuration", 2)

        phase = "scan"
        summary: ConfigurationScanSummary | ImageScanSummary | NativeImageScanSummary

        if native_selection is not None:
            def NativePolicy() -> ImpactPolicy:
                """Reopen the explicit strict policy at every original native authority check."""

                return ReadNucleiPolicy(options.policy)

            summary = asyncio.run(ScanNativeImage(root, options.scope, options.owner,
                native_selection, NativePolicy, approve_safe_image=options.approve_safe_image,
                timeout_seconds=options.timeout, report_format="json",
                report_output=destinations["json"]))

        elif image_selection is not None:
            summary = asyncio.run(RunSyntheticImageScan(root, options.scope, options.owner,
                image_selection, approve_safe_image=options.approve_safe_image,
                timeout_seconds=options.timeout, report_format="json",
                report_output=destinations["json"]))

        else:
            assert configuration_selection is not None, "Explicit profile selects configuration"
            summary = asyncio.run(RunSyntheticConfigurationScan(root, options.scope, options.owner,
                configuration_selection,
                approve_safe_configuration=options.approve_safe_configuration,
                timeout_seconds=options.timeout, report_format="json",
                report_output=destinations["json"]))

        RequireSummary(summary)

        expected_summary = NativeImageScanSummary if native else (
            ImageScanSummary if image else ConfigurationScanSummary)

        if type(summary) is not expected_summary:
            raise ReportFailure("scan-proof")

        outcome["scan"] = summary.ToDict()
        outcome["model_revision"] = summary.model_revision

        if summary.report is not None:
            reports["json"] = ArtifactOutcome(summary.report)
            outcome["snapshot_sha256"] = summary.report.snapshot_sha256

        status = summary.ExitCode()

        if status != 0:
            failure = summary.snapshot.failure
            raise ReportFailure(failure.code.value if failure is not None else (
                "cancelled" if status == 130 else "json-export"), status)

        if summary.report is None or summary.report.format != "json" or (
            summary.report.status != "completed" or summary.report.output_published is not True
            or type(summary.report.model_revision) is not int
            or summary.report.model_revision != summary.model_revision
            or type(summary.report.snapshot_sha256) is not str
            or len(summary.captures) != (2 if image or native else 1)
            or len(summary.snapshot.artifacts) != (6 if native else 12 if image else 4)
            or type(summary) is NativeImageScanSummary and (
                summary.custody_uncertain or summary.acceptance is None
                or len(summary.retained_records) != 6
                or tuple(item.evidence for item in summary.snapshot.artifacts) != (
                    summary.retained_records))
        ):
            raise ReportFailure("scan-proof")

        RequireDigest(summary.report.snapshot_sha256)
        phase = "gate-integrity"
        original = OpenReportInput(root)

        if original.report.SnapshotDigest() != summary.report.snapshot_sha256 or (
            original.report.state.revision != summary.model_revision
        ):
            raise ReportFailure("input-changed")

        original_json = SerializeJson(original.report)

        if len(original_json) != summary.report.size_bytes or (
            hashlib.sha256(original_json).hexdigest() != summary.report.report_sha256
        ):
            raise ReportFailure("json-export-proof")

        if not native:
            capability = ProfileCapability(profile)
            policy = ImpactPolicy("synthetic-image-safe-v1" if image else (
                "synthetic-configuration-safe-v1"), permissions=(CapabilityPermission(
                capability.identifier, capability.adapter_id, ImpactLevel.SAFE),))

        def CurrentContext() -> ArtifactPolicyContext:
            """Reopen current same-store scope/owner facts without issuing execution permission.

            Returns:
                Exact current context for the original grant's fresh acceptance checks.

            Raises:
                ArtifactDeniedError: Current recorded authority no longer matches the caller.
                OSError: Current owning scope storage cannot be read.
            """

            scope = LocalScopeStore(root).Open(options.scope)

            if scope.authorization.authority_reference != options.owner:
                raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

            return ArtifactPolicyContext(scope, policy, options.owner)

        if type(summary) is NativeImageScanSummary:
            assert summary.acceptance is not None, "Native success retains original acceptance"
            result = EvaluateNativeImageCriterion(original.report.state, summary.captures,
                summary.retained_records, root,
                expected_snapshot_sha256=summary.report.snapshot_sha256, criterion=criterion,
                acceptance=summary.acceptance)

        elif type(summary) is ImageScanSummary:
            roles = {"provider-version", "provider-version-stderr", "artifact-version-receipt",
                     "stdout", "stderr", "artifact-scan-receipt"}
            records = tuple(item.evidence for item in summary.snapshot.artifacts
                            if item.evidence.reference.role in roles)
            result = EvaluateImageCriterion(original.report.state, summary.captures, records, root,
                expected_snapshot_sha256=summary.report.snapshot_sha256, criterion=criterion,
                context_provider=CurrentContext)

        elif type(summary) is ConfigurationScanSummary:
            result = EvaluateConfigurationCriterion(original.report.state, summary.captures[0],
                tuple(item.evidence for item in summary.snapshot.artifacts), root,
                expected_snapshot_sha256=summary.report.snapshot_sha256, criterion=criterion,
                context_provider=CurrentContext)

        outcome["criterion"] = result.ToDict()
        phase = "rendering"
        payloads = {"sarif": SerializeSarif(original.report),
                    "junit": SerializeJunit(original.report)}

        for name, payload in payloads.items():
            reports[name].update({"model_revision": original.report.state.revision,
                "snapshot_sha256": original.report.SnapshotDigest(),
                "report_sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)})

        for name, payload in payloads.items():
            phase = "gate-integrity"
            CheckReportSnapshot(root, original)
            phase = "publication"
            publishing = name
            PublishReport(destinations[name], payload)
            reports[name].update({"status": "completed", "output_published": True})
            publishing = None

        phase = "gate-integrity"
        CheckReportSnapshot(root, original)
        executor = GovernedArtifactExecutor(root)

        if type(summary) is NativeImageScanSummary:
            assert summary.acceptance is not None, "Native success retains original acceptance"
            summary.acceptance.Validate(summary.captures, root)

        elif type(summary) is ImageScanSummary:
            version, scan = summary.captures
            executor.ValidatePairAcceptanceFresh((version.outcome, version.prepared, version.stage),
                (scan.outcome, scan.prepared, scan.stage), CurrentContext)

        elif type(summary) is ConfigurationScanSummary:
            capture = summary.captures[0]
            executor.ValidateAcceptanceFresh(capture.outcome, capture.prepared, capture.stage,
                                             CurrentContext)
        status = 0 if result.satisfied else 1
        outcome["status"] = "criterion-satisfied" if result.satisfied else "criterion-violated"

    except ReportFailure as error:
        status = error.status
        outcome["failure"] = error.kind

        if publishing is not None:
            reports[publishing].update({"status": "failed", "failure": error.kind,
                                       "output_published": error.published})

    except ArtifactDeniedError as error:
        status = 4 if error.reason is ArtifactDenialReason.STORAGE else 3
        outcome["failure"] = "storage" if status == 4 else "authorization"

    except (EvidenceError, OSError, ValueError, TypeError, RecursionError):
        status = 2 if phase == "configuration" else 4
        outcome["failure"] = phase

    except KeyboardInterrupt:
        status = 130
        outcome["failure"] = "interrupted"

    except Exception:
        status = 4
        outcome["failure"] = "internal"

    outcome["exit_code"] = status

    if json_output:
        WriteJson(output, outcome)

    else:
        output.write(f"CI scan {outcome['status']} (exit {status}); selected finding predicate; "
                     "global scan completeness was not assessed.\n")
        output.flush()

    return status
