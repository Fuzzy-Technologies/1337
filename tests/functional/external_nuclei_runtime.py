# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Retain one installed whole1337 Nuclei workflow and its original persisted evidence.

This container-side source does not provision images, establish target isolation,
or enroll acceptance. The host must supply the independently inspected owned
fixture and immutable acquired provider. Empty matching output remains unproven.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from .external_native_runner import MAX_FILE_BYTES, ExportBundle, WriteJson
from .external_nuclei_runner import (
    MAX_RECORDS,
    PROVIDER_TIMEOUT_SECONDS,
    STDERR_BYTES,
    STDOUT_BYTES,
    TEMPLATE_ID,
    TEMPLATE_SHA256,
    VERSION,
    WRAPPER_TIMEOUT_SECONDS,
    AttemptProvenance,
    EffectiveBudget,
    ExactUrl,
    InstalledInventory,
    ProfileDocument,
    ProjectStandaloneMatches,
    RegularIdentity,
    RequireStandaloneAuthorization,
    StandaloneArguments,
    VerifyBinary,
)


def RunWhole1337(root: Path, path: str, executable: Path, template: Path, configuration: Path,
                 expected_sha256: str, observed_version: str, authorization: dict,
                 source_revision: str, wheel: Path) -> dict:
    """Run actual Plan/confirm/Run and project only verified saved canonical Findings.

    Args:
        root: New absolute private directory on the container's owned writable storage.
        path: One of the three frozen case paths; no discovery or URL rewriting.
        executable: Immutable image-local official binary acquired before target execution.
        template: Singly linked exact reviewed template; copied into this workspace.
        configuration: Singly linked exact empty operator configuration.
        expected_sha256: Actual acquired executable digest, distinct from archive identity.
        observed_version: Previously observed exact pinned local version prerequisite.
        authorization: Explicit owned-target fixture declaration, never a product grant.
        source_revision: Current wheel's exact source revision from image provisioning.
        wheel: Original installed current wheel, retained under the bundle's file ceiling.

    Returns:
        Internal lab outcome, not a complete host v2 observation. A completed product
        job without a saved mapped match is unproven. Custody/export failures are
        unscored; original workspace files remain available after refusal.

    Raises:
        ValueError: Prerequisites, immutable material, or the new workspace are invalid.
        OSError: Required local material or retained storage cannot be accessed.
        BaseException: Cancellation propagates after the product owns its cleanup.
    """

    from fuzzy1337.adapters import ExecutionState, ImpactLevel, SerializeContract
    from fuzzy1337.evidence import LocalEvidenceStore
    from fuzzy1337.executors import InvocationDigest
    from fuzzy1337.findings import Findings
    from fuzzy1337.jobs import JobState
    from fuzzy1337.model import LocalModelStore, ObjectKind
    from fuzzy1337.nucleiscan import (
        NucleiScanLimits,
        PlanNucleiScan,
        ReadNucleiProfile,
        RunNucleiScan,
    )
    from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation
    from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
    from fuzzy1337.scope import (
        AuthorizationState,
        LocalScopeStore,
        ScopeAuthorization,
        ScopeSnapshot,
        Target,
        TargetKind,
    )

    RequireStandaloneAuthorization(authorization, path)
    binary = VerifyBinary(executable, expected_sha256, observed_version)
    ProfileDocument(template, configuration)
    inventory = InstalledInventory(source_revision, wheel)

    if wheel.suffix != ".whl" or not root.is_absolute() or any(
        part == ".." for part in root.parts
    ):
        raise ValueError("Whole1337 requires an original wheel and new absolute owned directory")

    for component in reversed(root.parents):
        if component.is_symlink():
            raise ValueError("Whole1337 workspace cannot traverse symbolic links")

    root.mkdir(mode=0o700)
    shutil.copyfile(template, root / "prometheus-exposition.yaml")
    shutil.copyfile(configuration, root / "operator-config.yaml")
    shutil.copyfile(wheel, root / "installed.whl")
    copied_wheel = RegularIdentity(root / "installed.whl", maximum=MAX_FILE_BYTES)

    if any(copied_wheel[key] != inventory["wheel"][key] for key in ("sha256", "size_bytes")):
        raise ValueError("Whole1337 copied wheel differs from the installed inventory")

    inventory["whole1337_runtime_sha256"] = RegularIdentity(
        Path(__file__), maximum=MAX_FILE_BYTES)["sha256"]
    WriteJson(root / "installed-inventory.json", inventory)
    WriteJson(root / "fixture-authorization.json", authorization)
    profile_document = ProfileDocument(root / "prometheus-exposition.yaml",
                                       root / "operator-config.yaml")
    WriteJson(root / "profile.json", profile_document)
    profile = ReadNucleiProfile(root / "profile.json")
    target = Target(TargetKind.URL, ExactUrl(path))
    address = Target(TargetKind.IP, "127.0.0.1")
    owner = authorization["owner"]
    workspace = root / "workspace"
    started = time.monotonic()
    outcome = {"status": "failed", "exit_code": None, "duration_seconds": 0.0,
               "target_url": target.value, "findings": [], "raw_matches": [],
               "reason": "Whole1337 execution or custody did not complete"}

    try:
        CreateWorkspace(workspace, "external-nuclei", "Owned pinned Nuclei comparison")
        now = datetime.now(UTC)
        scope_store = LocalScopeStore(workspace)
        scope_store.Create(ScopeSnapshot("local", "external-nuclei", ScopeAuthorization(
            AuthorizationState.GRANTED, owner, authorization["authorization_reference"],
            (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=5)).isoformat(),
        ), targets=(target, address), allow=(target, address)))
        WriteJson(root / "scope.json", scope_store.Open("local").ToDict())
        policy = ImpactPolicy("owned-external-nuclei", maximum_impact=ImpactLevel.STANDARD,
            permissions=(CapabilityPermission("web.http-template-check", "native.nuclei",
                                              ImpactLevel.STANDARD),))
        WriteJson(root / "policy.json", json.loads(SerializeContract(policy)))
        readbacks = []

        def Policy():
            """Supply only the explicit policy and retain fresh independent scope readbacks."""

            # These are reader observations, not an invented launch-grant receipt.
            readbacks.append({"observed_at": datetime.now(UTC).isoformat(),
                              "scope": scope_store.Open("local").ToDict(),
                              "policy": json.loads(SerializeContract(policy))})
            WriteJson(root / "authority-readbacks.json", readbacks)

            return policy

        limits = NucleiScanLimits(timeout_seconds=PROVIDER_TIMEOUT_SECONDS, rate_limit=1)
        plan = PlanNucleiScan(workspace, "local", target, owner, profile, str(executable),
                              Policy, limits=limits)
        WriteJson(root / "plan.json", plan.ToDict())

        if plan.invocation.provider_version != VERSION or plan.invocation.argv != (
            StandaloneArguments(executable, path, root / "prometheus-exposition.yaml",
                                root / "operator-config.yaml")
        ):
            raise ValueError("Whole1337 actual plan differs from the pinned comparison invocation")

        confirmation = PolicyConfirmation(plan.policy_plan.intent_sha256,
                                          "approval:owned-external-nuclei-exact-plan")
        WriteJson(root / "confirmation.json", json.loads(SerializeContract(confirmation)))
        WriteJson(root / "attempt-provenance.json", AttemptProvenance(path))
        WriteJson(root / "requests.json", AttemptProvenance(path)["configured_requests"])
        WriteJson(root / "invocation.json", {
            "argv": list(plan.invocation.argv), "scanner_id": plan.invocation.adapter_id,
            "scanner_version": plan.invocation.provider_version,
            "scanner_sha256": binary["sha256"], "rule_sha256": TEMPLATE_SHA256,
            "product_revision": source_revision, "profile_sha256": profile.Digest,
            "effective_budget": EffectiveBudget(),
            "provider_timeout_seconds": plan.invocation.timeout_seconds,
            "wrapper_timeout_seconds": WRAPPER_TIMEOUT_SECONDS,
            "stdout_capture_bytes": STDOUT_BYTES, "stderr_capture_bytes": STDERR_BYTES,
            "original_file_ceiling_bytes": MAX_FILE_BYTES,
        })
        summary = asyncio.run(RunNucleiScan(workspace, "local", target, owner, profile,
            str(executable), Policy, limits=limits, confirmation=confirmation))
        outcome["exit_code"] = summary.ExitCode()
        WriteJson(root / "summary.json", summary.ToDict())
        WriteJson(root / "events.json", json.loads(SerializeContract(summary.events)))
        records = tuple(artifact.evidence for artifact in summary.snapshot.artifacts)
        WriteJson(root / "acquisitions.json", json.loads(SerializeContract(records)))
        evidence = LocalEvidenceStore(workspace / "evidence")
        streams = {}

        for record in records:
            role = record.reference.role

            if role not in {"stdout", "stderr"} or role in streams or (
                evidence.Get(record.evidence_id) != record
                or record.provenance.invocation_sha256 != InvocationDigest(plan.invocation)
                or record.provenance.tool_version != VERSION
                or record.provenance.workspace_id != summary.snapshot.spec.workspace_id
                or record.provenance.scope_reference != summary.snapshot.spec.scope_reference
                or record.provenance.source_id != plan.invocation.adapter_id
            ):
                raise ValueError("Whole1337 original paired acquisition differs from its plan")

            streams[role] = evidence.Read(record.reference)
            (root / (role + ".raw")).write_bytes(streams[role])

        state = LocalModelStore(workspace).Open()
        saved = Findings(state)
        WriteJson(root / "model.json", state.ToDict())
        WriteJson(root / "findings.raw.json", json.loads(SerializeContract(saved)))
        reopened = OpenWorkspace(workspace)
        WriteJson(root / "reopen.json", reopened)

        if LocalModelStore(workspace).Open() != state or (
            reopened["model_revision"] != summary.model_revision
            or summary.snapshot.spec.timeout_seconds != WRAPPER_TIMEOUT_SECONDS
            or set(reopened["workspace"]["evidence_record_references"]) != {
                record.evidence_id for record in records}
            or reopened["workspace"]["job_references"] != [summary.snapshot.spec.job_id]
        ):
            raise ValueError("Whole1337 saved model or wrapper differs after verified reopen")

        if set(streams) != {"stdout", "stderr"} or len(records) != 2 or (
            records[0].provenance != records[1].provenance
        ):
            raise ValueError("Whole1337 requires the original enclosing stdout/stderr pair")

        # Raw identities are diagnostic only; canonical Findings below own projection.
        if len(streams["stdout"]) <= MAX_FILE_BYTES:
            for line in streams["stdout"].splitlines()[:MAX_RECORDS]:
                try:
                    outcome["raw_matches"].extend(ProjectStandaloneMatches(line + b"\n"))

                except (ValueError, UnicodeError):
                    continue

        subjects = {item.Reference(): item for item in state.Objects(ObjectKind.ENDPOINT)}
        saved_references = []

        for finding in saved:
            subject = subjects.get(finding.subject_reference)

            if subject is None or subject.attributes.get("url") != target.value or (
                not finding.provenance or any(
                    item.source_id != "native.nuclei"
                    or item.run_reference != summary.snapshot.spec.job_id
                    or item.scope_reference != summary.snapshot.spec.scope_reference
                    or item.target_reference != target.Reference()
                    or item.provider_version != VERSION
                    or item.execution != records[0].provenance.execution
                    or set(item.evidence_references) != {record.reference for record in records}
                    for item in finding.provenance
                )
            ):
                raise ValueError("Whole1337 saved Finding lost its original enclosing acquisition")

            outcome["findings"].append({"rule_id": finding.check_id,
                "path": urlsplit(subject.attributes["url"]).path,
                "target_url": subject.attributes["url"]})
            saved_references.append({"finding_reference": finding.ToObject(
                state.workspace_id).Reference(), "fingerprint": finding.Fingerprint(),
                "subject_reference": finding.subject_reference,
                "location_key": finding.location_key,
                "acquisition_ids": [record.evidence_id for record in records]})

        WriteJson(root / "saved-finding-references.json", saved_references)
        execution = records[0].provenance.execution
        outcome["provider_duration_seconds"] = execution.duration_seconds if execution else None
        successful = summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0

        if successful and (execution is None or execution.state is not ExecutionState.SUCCEEDED
            or execution.exit_code != 0 or execution.duration_seconds > PROVIDER_TIMEOUT_SECONDS
        ):
            raise ValueError("Whole1337 completion lacks successful bounded original execution")

        mapped = any(item["rule_id"] == "nuclei." + TEMPLATE_ID
                     and item["target_url"] == target.value for item in outcome["findings"])
        outcome["status"] = "completed" if successful and mapped else (
            "unproven" if successful else "failed")
        outcome["reason"] = "Saved exact-input rule match with original paired evidence" if (
            successful and mapped) else (
            "Invocation completed without a saved mapped match; response and contacts unproven"
            if successful else "Product execution failed; retained bytes receive no score")

    except Exception as error:
        outcome.update(status="failed", reason="Whole1337 execution or custody failed; unscored")
        WriteJson(root / "failure.json", {"exception_type": type(error).__name__,
                                         "scanner_completion_claimed": False})

    outcome["whole_product_duration_seconds"] = time.monotonic() - started
    outcome["duration_seconds"] = outcome.get("provider_duration_seconds") or 0.0
    WriteJson(root / "findings.json", outcome["findings"])
    WriteJson(root / "outcome.json", outcome)

    try:
        ExportBundle(root, outcome)

    except ValueError:
        outcome.update(status="failed",
                       reason="Original-byte bundle refused; retained files unscored")
        WriteJson(root / "outcome.json", outcome)

    return outcome
