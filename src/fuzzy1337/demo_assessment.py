# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compose a real 1337Scope Git HEAD check and offline reports on a closed owned fixture."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import (
    AdapterExecution,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.adapters.native_web import ParseNativeWebRecord
from fuzzy1337.demo import (
    DemoFailure,
    EvidenceIndex,
    OwnedDemoTarget,
    RequireNewDemoRoot,
    SaveDemoArtifact,
)
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.findings import Findings, FindingSeverity, FindingStatus
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.native_web import NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.report_commands import (
    CheckReportSnapshot,
    OpenReportInput,
    ReportFailure,
    RunReportCommands,
)
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.scope import Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ["AssessmentDemoPlan", "RunAssessmentDemo"]

ASSESSMENT_WORKSPACE_ID = "demo-assessment"
ASSESSMENT_SCOPE_ID = "owned-assessment"
ASSESSMENT_OWNER = "operator:owned-assessment-demo"


def AssessmentDemoPlan() -> dict[str, object]:
    """Describe the complete closed STANDARD plan without touching any path or resource.

    Returns:
        A detached schema-one plan whose opt-in covers only two command-owned local GETs.
    """

    return {
        "schema_version": 1, "command": "demo.assessment", "bind_host": "127.0.0.1",
        "port_selection": "ephemeral", "routes": ["/.git/HEAD", "/fixed/.git/HEAD"],
        "capabilities": [NATIVE_WEB_CAPABILITY], "impact": "standard", "max_requests": 2,
        "request_timeout_seconds": 2, "scan_timeout_seconds": 10,
        "consent_validity_seconds": 120, "check": "git-head-exposure",
        "outputs": ["workspace", "policy.json", "exposed-plan.json", "exposed-scan.json",
                    "fixed-plan.json", "fixed-scan.json", "assessment-checks.json",
                    "workspace-open.json", "reports/model.json", "reports/model.html",
                    "reports/model.sarif", "evidence-index.json", "target.json",
                    "demo-summary.json"],
        "limitations": ["one native metadata-exposure predicate", "different-endpoint control",
                        "no resolution or remediation verdict", "no attack paths",
                        "no CVE applicability assessment", "no external targets or scanners"],
    }


def ReadAssessmentExecution(
    workspace: Path, url: str, scan: dict[str, object], *, matched: bool,
) -> tuple[str, tuple[EvidenceReference, ...], AdapterExecution]:
    """Reopen original registered worker evidence and bind it to the actual selected job.

    Args:
        workspace: The new composition-owned workspace, never an operator-selected source.
        url: The exact command-owned exposed or fixed endpoint used for this invocation.
        scan: The original successful product command receipt.
        matched: The fixed known-answer expectation for this endpoint.

    Returns:
        The original job reference, two verified material references and actual execution.

    Raises:
        DemoFailure: Job, source evidence or the fixed positive/negative observation differs.
    """

    job = scan.get("job")

    if (scan.get("state") != "completed" or scan.get("check_id") != "native.git-head-exposure"
            or not isinstance(job, dict) or job.get("state") != "completed"):
        raise DemoFailure("assessment")

    spec = job.get("spec")
    artifacts = job.get("artifacts")

    if (not isinstance(spec, dict) or not isinstance(spec.get("job_id"), str)
            or spec.get("provider_id") != NATIVE_WEB_PROVIDER_ID
            or spec.get("workspace_id") != ASSESSMENT_WORKSPACE_ID
            or spec.get("owner_reference") != ASSESSMENT_OWNER
            or spec.get("scope_reference") != "scope:" + ASSESSMENT_SCOPE_ID
            or not isinstance(artifacts, list) or len(artifacts) != 2):
        raise DemoFailure("assessment")

    job_id = spec["job_id"]
    saved = LocalWorkspaceStore(workspace).Open()
    evidence = LocalEvidenceStore(workspace / "evidence")
    references = []
    stdout: bytes | None = None
    execution: AdapterExecution | None = None

    for artifact in artifacts:
        if (not isinstance(artifact, dict) or artifact.get("job_id") != job_id
                or artifact.get("workspace_id") != ASSESSMENT_WORKSPACE_ID):
            raise DemoFailure("assessment")

        metadata = artifact.get("evidence")

        if not isinstance(metadata, dict) or not isinstance(metadata.get("evidence_id"), str):
            raise DemoFailure("assessment")

        identity = metadata["evidence_id"]

        if identity not in saved.evidence_record_references:
            raise DemoFailure("assessment")

        record = evidence.Get(identity)
        provenance = record.provenance

        if ({"evidence_id": record.evidence_id, **record.ToDict()} != metadata
                or provenance.workspace_id != ASSESSMENT_WORKSPACE_ID
                or provenance.scope_reference != "scope:" + ASSESSMENT_SCOPE_ID
                or provenance.source_id != NATIVE_WEB_PROVIDER_ID
                or provenance.source_version != "1" or provenance.tool_version != "1"
                or provenance.execution is None
                or provenance.execution.state is not ExecutionState.SUCCEEDED
                or provenance.execution.exit_code != 0
                or execution is not None and provenance.execution != execution):
            raise DemoFailure("assessment")

        execution = provenance.execution
        payload = evidence.Read(record.reference)
        references.append(record.reference)

        if record.reference.role == "stdout":
            stdout = payload

        elif record.reference.role != "stderr" or payload != b"":
            raise DemoFailure("assessment")

    if stdout is None or execution is None or {item.role for item in references} != {
        "stdout", "stderr"
    }:
        raise DemoFailure("assessment")

    response = ParseNativeWebRecord(stdout, url)
    body = b"ref: refs/heads/main\n" if matched else b"Not Found\n"

    if (response.get("matched") is not matched or response.get("status") != (
        200 if matched else 404) or response.get("body_bytes") != len(body)
            or response.get("body_sha256") != hashlib.sha256(body).hexdigest()):
        raise DemoFailure("assessment")

    return job_id, tuple(references), execution


def ReadAssessmentFinding(
    workspace: Path, exposed_url: str, exposed_scan: dict[str, object],
) -> dict[str, object]:
    """Bind the saved original LOW Finding to its endpoint, job and verified original evidence.

    Args:
        workspace: The workspace acquired by the real native check composition.
        exposed_url: The exact command-owned exposed endpoint, never the fixed control.
        exposed_scan: The original successful exposed endpoint command receipt.

    Returns:
        The canonical object reference and detached normalized Finding attributes.

    Raises:
        DemoFailure: The actual native check did not preserve the finite Finding invariant.
    """

    job_id, references, execution = ReadAssessmentExecution(
        workspace, exposed_url, exposed_scan, matched=True,
    )
    model = LocalModelStore(workspace).Open()
    findings = Findings(model)

    if len(findings) != 1:
        raise DemoFailure("assessment")

    finding = findings[0]

    if (finding.check_id != "native.git-head-exposure"
            or finding.severity is not FindingSeverity.LOW
            or finding.status is not FindingStatus.OPEN or finding.location_key != exposed_url
            or len(finding.provenance) != 1):
        raise DemoFailure("assessment")

    subjects = [item for item in model.Objects(ObjectKind.ENDPOINT)
                if item.Reference() == finding.subject_reference]

    if (len(subjects) != 1 or subjects[0].identity.key != exposed_url
            or dict(subjects[0].attributes).get("url") != exposed_url):
        raise DemoFailure("assessment")

    provenance = finding.provenance[0]

    if (provenance.run_reference != job_id or provenance.source_id != NATIVE_WEB_PROVIDER_ID
            or provenance.scope_reference != "scope:" + ASSESSMENT_SCOPE_ID
            or provenance.target_reference != Target(TargetKind.URL, exposed_url).Reference()
            or provenance.provider_version != "1" or provenance.execution != execution
            or set(provenance.evidence_references) != set(references)
            or subjects[0].provenance != finding.provenance):
        raise DemoFailure("assessment")

    return {"reference": model.Objects(ObjectKind.FINDING)[0].Reference(),
            "normalized": finding.ToAttributes(), "provenance": JsonValue(finding.provenance)}


def RunAssessmentDemo(
    path: Path, output: TextIO, *, approve_standard_http: bool = False,
    json_output: bool = False,
) -> int:
    """Execute the closed real-finding workflow with separate actual plan confirmations.

    Args:
        path: A new output root beneath an existing physical parent.
        output: Caller-owned presentation; evidence retains original worker metadata, not bodies.
        approve_standard_http: Exact explicit opt-in to this fixed owned STANDARD check plan.
        json_output: Emit a single strict JSON outcome rather than concise human presentation.

    Returns:
        Zero for verified completion, 2 for configuration, 3 for approval/policy denial,
        4 for execution/storage/invariant/cleanup failure, or 130 for interruption.
    """

    artifacts: list[str] = []
    commands: list[dict[str, object]] = []
    outcome: dict[str, object] = {
        "schema_version": 1, "command": "demo.assessment", "state": "denied",
        "exit_status": 3, "plan": AssessmentDemoPlan(), "phase": "approval",
        "failure": "approval_required", "artifacts": artifacts, "commands": commands,
        "target_teardown_completed": None, "duration_seconds": 0.0,
    }
    root: Path | None = None
    target: OwnedDemoTarget | None = None
    phase = "configuration"
    started = time.monotonic()

    def Invoke(namespace: str, arguments: list[str], filename: str) -> dict[str, object]:
        """Retain the original product command receipt and its actual failure before stopping."""

        assert root is not None, "Product commands require the newly acquired owned demo root."
        captured = StringIO()
        status = RunCommands(namespace, arguments, captured, json_output=True)
        document = json.loads(captured.getvalue())

        if not isinstance(document, dict):
            raise DemoFailure("receipt")

        command = namespace + "." + arguments[0] + (".plan" if "--plan" in arguments else "")
        commands.append({"command": command, "exit_status": status, "outcome": document})
        SaveDemoArtifact(root, filename, document, artifacts)

        if status:
            raise DemoFailure(phase, status)

        return document

    try:
        if type(approve_standard_http) is not bool:
            raise DemoFailure("configuration", 2)

        if approve_standard_http:
            selected = RequireNewDemoRoot(path)
            selected.mkdir(mode=0o700)
            root = selected
            (root / "reports").mkdir(mode=0o700)
            target = OwnedDemoTarget(assessment=True)
            phase = "target"
            target.Start()
            urls = target.Urls()
            workspace = root / "workspace"
            phase = "workspace"
            Invoke("workspace", ["create", str(workspace), "--id", ASSESSMENT_WORKSPACE_ID,
                                 "--name", "Owned native assessment demo"], "workspace-create.json")
            now = datetime.now(UTC)
            scope = ["create", str(workspace), "--id", ASSESSMENT_SCOPE_ID,
                     "--allow-ip", "127.0.0.1", "--grant-consent", "--owner", ASSESSMENT_OWNER,
                     "--consent-reference", "consent:command-owned-assessment-demo",
                     "--valid-from", (now - timedelta(seconds=1)).isoformat(),
                     "--valid-until", (now + timedelta(seconds=120)).isoformat()]

            for url in urls:
                scope.extend(("--allow-url", url))

            phase = "scope"
            Invoke("scope", scope, "scope-create.json")
            policy = ImpactPolicy("owned-assessment-demo", maximum_impact=ImpactLevel.STANDARD,
                permissions=(CapabilityPermission(NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID,
                                                  ImpactLevel.STANDARD),))
            SaveDemoArtifact(root, "policy.json", json.loads(SerializeContract(policy)), artifacts)
            original: dict[str, object] | None = None
            exposed_scan: dict[str, object] = {}

            for label, url in zip(("exposed", "fixed"), urls, strict=True):
                arguments = ["web", str(workspace), "--check", "git-head-exposure",
                             "--scope", ASSESSMENT_SCOPE_ID, "--owner", ASSESSMENT_OWNER,
                             "--target", url, "--policy", str(root / "policy.json"),
                             "--request-timeout", "2", "--timeout", "10"]
                phase = label + "-plan"
                plan = Invoke("scan", [*arguments, "--plan"], label + "-plan.json")
                policy_plan = plan.get("policy_plan")

                if not isinstance(policy_plan, dict) or not isinstance(
                    policy_plan.get("intent_sha256"), str
                ):
                    raise DemoFailure("plan")

                phase = label + "-scan"
                scan = Invoke("scan", [*arguments, "--confirm-plan", policy_plan["intent_sha256"],
                                       "--confirmation-reference",
                                       "approval:owned-assessment-" + label], label + "-scan.json")
                phase = "assessment"

                if label == "exposed":
                    exposed_scan = scan

                else:
                    ReadAssessmentExecution(workspace, url, scan, matched=False)

                finding = ReadAssessmentFinding(workspace, urls[0], exposed_scan)

                if original is not None and finding != original:
                    raise DemoFailure("assessment")

                original = finding

            phase = "teardown"

            try:
                target.Close()

            except (Exception, KeyboardInterrupt):
                outcome["target_teardown_completed"] = False

                raise DemoFailure("teardown") from None

            outcome["target_teardown_completed"] = target.stopped
            receipt = target.Receipt()
            SaveDemoArtifact(root, "target.json", receipt, artifacts)
            phase = "assessment"

            if receipt["requests"] != [
                {"method": "GET", "path": "/.git/HEAD", "status": 200},
                {"method": "GET", "path": "/fixed/.git/HEAD", "status": 404},
            ]:
                raise DemoFailure("assessment")

            phase = "reopen"
            Invoke("workspace", ["open", str(workspace)], "workspace-open.json")
            phase = "assessment"
            report_input = OpenReportInput(workspace)

            if ReadAssessmentFinding(workspace, urls[0], exposed_scan) != original:
                raise DemoFailure("assessment")

            CheckReportSnapshot(workspace, report_input)
            snapshot = report_input.report.SnapshotDigest()
            revision = report_input.report.state.revision
            checks = {"schema_version": 1, "finding": original, "finding_count": 1,
                      "control": "different endpoint; no additional Finding",
                      "original_finding": "open", "resolution": "not-assessed",
                      "scan_completeness": "not-assessed", "model_revision": revision,
                      "snapshot_sha256": snapshot}
            SaveDemoArtifact(root, "assessment-checks.json", checks, artifacts)
            outcome["assessment"] = checks
            phase = "export"

            for format_name, name in (("json", "model.json"), ("html", "model.html"),
                                      ("sarif", "model.sarif")):
                CheckReportSnapshot(workspace, report_input)
                captured = StringIO()
                status = RunReportCommands(
                    ["export", str(workspace), "--format", format_name,
                     "--output", str(root / "reports" / name)], captured, json_output=True,
                )
                receipt = json.loads(captured.getvalue())
                commands.append({"command": "report.export", "exit_status": status,
                                 "outcome": receipt})

                if receipt["output_published"]:
                    artifacts.append("reports/" + name)

                SaveDemoArtifact(root, f"reports/{format_name}-export.json", receipt, artifacts)

                if status:
                    raise DemoFailure("export", status)

                if (receipt.get("snapshot_sha256") != snapshot
                        or receipt.get("model_revision") != revision):
                    raise ReportFailure("input-changed")

                CheckReportSnapshot(workspace, report_input)

            phase = "index"
            SaveDemoArtifact(root, "evidence-index.json", EvidenceIndex(workspace), artifacts)
            CheckReportSnapshot(workspace, report_input)
            outcome.update({"state": "completed", "exit_status": 0,
                            "phase": "completed", "failure": None})

    except DemoFailure as error:
        outcome.update({"state": "cancelled" if error.status == 130 else (
            "denied" if error.status == 3 else "failed"), "exit_status": error.status,
            "phase": error.phase, "failure": error.phase})

    except ReportFailure as error:
        outcome.update({"state": "cancelled" if error.status == 130 else "failed",
                        "exit_status": error.status, "phase": phase,
                        "failure": error.kind, "artifact_output_published": error.published})

    except KeyboardInterrupt:
        outcome.update({"state": "cancelled", "exit_status": 130,
                        "phase": phase, "failure": "interrupted"})

    except (OSError, ValueError, EvidenceError):
        outcome.update({"state": "failed", "exit_status": 2 if root is None else 4,
                        "phase": phase, "failure": "configuration" if root is None else "storage"})

    except Exception:
        outcome.update({"state": "failed", "exit_status": 4,
                        "phase": phase, "failure": "internal"})

    finally:
        if target is not None and not target.stopped:
            try:
                target.Close()
                outcome["target_teardown_completed"] = target.stopped

            except (Exception, KeyboardInterrupt):
                outcome.update({"state": "failed", "exit_status": 4, "phase": "teardown",
                                "failure": "teardown", "target_teardown_completed": False})

        if target is not None and root is not None and "target.json" not in artifacts:
            try:
                SaveDemoArtifact(root, "target.json", target.Receipt(), artifacts)

            except (Exception, KeyboardInterrupt):
                outcome.update({"state": "failed", "exit_status": 4,
                                "phase": "target-receipt", "failure": "publication"})

    outcome["duration_seconds"] = time.monotonic() - started

    if root is not None:
        try:
            SaveDemoArtifact(root, "demo-summary.json", outcome, [])

        except ReportFailure as error:
            outcome.update({"state": "cancelled" if error.status == 130 else "failed",
                            "exit_status": error.status, "phase": "summary",
                            "failure": error.kind, "summary_output_published": error.published})

        except (Exception, KeyboardInterrupt):
            outcome.update({"state": "failed", "exit_status": 4,
                            "phase": "summary", "failure": "publication"})

    if json_output:
        output.write(json.dumps(outcome, sort_keys=True, allow_nan=False) + "\n")

    elif not approve_standard_http:
        output.write("Assessment demo plan: own 127.0.0.1 on an ephemeral port; run the "
                     "1337Scope STANDARD Git HEAD check once on /.git/HEAD and once on "
                     "/fixed/.git/HEAD, with separate exact confirmations. Stop the fixture, "
                     "reopen retained evidence and export JSON/HTML/SARIF.\n"
                     "Explicit --approve-standard-http is required. No resources were started.\n")

    else:
        output.write(f"Assessment demo {outcome['state']} (exit {outcome['exit_status']}); "
                     f"phase {outcome['phase']}; target teardown "
                     f"{outcome['target_teardown_completed']}.\n")

        if root is not None:
            output.write(f"Retained output: {root}\n")

        if outcome["state"] == "completed":
            output.write("One actual open LOW Finding; the different fixed endpoint adds none. "
                         "Open reports/model.html under the retained output root.\n")

    output.flush()

    return int(str(outcome["exit_status"]))
