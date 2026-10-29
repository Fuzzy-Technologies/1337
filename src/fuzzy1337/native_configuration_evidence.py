# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Read-only native configuration replay and fresh source-attributed canonical Finding proposals."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any, cast

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.artifact_inputs import (
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    FreezePhysicalIdentity,
)
from fuzzy1337.artifact_policy import ArtifactPolicyContext, ArtifactPolicyEngine
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.executors import ExecutionAuthorization, ExecutionResources, InvocationDigest
from fuzzy1337.findings import ApplyFindings, Finding, FindingSeverity, Remediation
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.native_configuration import (
    NATIVE_CONFIGURATION_EXECUTABLE_SHA256,
    NativeConfigurationScanRecipe,
    NativeConfigurationSelection,
    PrepareNativeConfigurationVersion,
)
from fuzzy1337.native_configuration_capture import NativeConfigurationOperationCapture
from fuzzy1337.native_configuration_material import (
    NativeConfigurationMaterialObserver,
    NativeConfigurationMaterialProof,
)
from fuzzy1337.native_configuration_policy import (
    ConfigurationEnvironment,
    GrantEnvelope,
    NativeConfigurationExecutionClaim,
    NativeConfigurationOperationPlan,
    NativeConfigurationVersionPrerequisite,
)
from fuzzy1337.native_configuration_report import (
    NATIVE_CONFIGURATION_FAMILY,
    NATIVE_CONFIGURATION_ROLES,
    NativeConfigurationCheck,
    ParseNativeConfigurationReport,
)
from fuzzy1337.policy import Digest
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields


def Detached(value: object) -> dict[str, Any]:
    """Detach finite canonical metadata without retaining aliases to mutable caller containers.

    Args:
        value: Typed first-party metadata or an original bounded decoded receipt.

    Returns:
        Independent JSON object projection.
    """

    return cast(dict[str, Any], json.loads(SerializeContract(value)))


def Fields(value: object, expected: set[str]) -> dict[str, Any]:
    """Require all and only the exact replay consumer-owned fields.

    Args:
        value: Previously bounded decoded JSON object.
        expected: Complete field-name contract for this object.

    Returns:
        Original exact dictionary after closed-world field validation.
    """

    return cast(dict[str, Any], WorkspaceFields(value, expected, "native configuration replay"))


class NativeConfigurationEvidenceStore(LocalEvidenceStore):
    """Preflight exact per-role limits before the canonical evidence owner's eager read."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read bounded original native configuration bytes through canonical integrity guards.

        Args:
            reference: Exact original typed configuration role reference.

        Returns:
            Unchanged original bytes after size/media/integrity verification.
        """

        if type(reference) is not EvidenceReference or reference.role not in (
            NATIVE_CONFIGURATION_ROLES
        ):
            raise ValueError("Native configuration replay requires its exact evidence roles")

        maximum, media = NATIVE_CONFIGURATION_ROLES[reference.role]

        if type(reference.size_bytes) is not int or not 0 <= reference.size_bytes <= maximum or (
            reference.media_type != media
        ):
            raise ValueError("Native configuration evidence exceeds its role contract")

        return super().Read(reference)


@dataclass(frozen=True, slots=True)
class NativeConfigurationReplay:
    """Verified historical source and provider facts with no launch or model-write authority."""

    workspace_id: str
    owner_reference: str
    input_manifest: ArtifactManifest
    selection: NativeConfigurationSelection
    provenance: ModelProvenance
    records: tuple[EvidenceRecord, ...]
    checks: tuple[NativeConfigurationCheck, ...]
    version_capture_sha256: str
    scan_capture_sha256: str


def VerifyFactory(prepared: dict[str, Any]) -> tuple[NativeConfigurationSelection,
                                                  ArtifactManifest, AdapterInvocation]:
    """Rebuild historical fixed native factory grammar without accessing original paths.

    Args:
        prepared: Original bounded exact prepared recipe object from an immutable receipt.

    Returns:
        Syntax-validated selection, input manifest and exact original invocation.
    """

    Fields(prepared, {"schema_version", "family", "operation_id", "operation", "selection",
        "workspace_root", "workspace_id", "owner_reference", "operation_reference",
        "input_manifest", "stage_metadata", "invocation", "scratch", "resources",
        "version_prerequisite_sha256"})

    if type(prepared["schema_version"]) is not int or prepared["schema_version"] != 1 or (
        prepared["family"] != NATIVE_CONFIGURATION_FAMILY
        or prepared["operation"] not in {"version", "scan"}
    ):
        raise ValueError("Native configuration receipt has an unsupported factory family")

    selected = Fields(prepared["selection"], {"profile", "logical_path", "source", "executable",
                                              "read_consent"})
    consent = ArtifactReadConsent(**Fields(selected["read_consent"], {"actor_ref", "record_ref"}))
    selection = NativeConfigurationSelection(ArtifactProfile(selected["profile"]),
        selected["logical_path"], Path(selected["source"]), Path(selected["executable"]), consent)
    manifest = ArtifactManifest.FromDict(prepared["input_manifest"])
    scratch = Path(prepared["scratch"])
    workspace = Path(prepared["workspace_root"])

    if not workspace.is_absolute() or scratch.parent != workspace or not scratch.name.startswith(
        "native-configuration-run-"
    ) or prepared["owner_reference"] != consent.actor_ref:
        raise ValueError("Native configuration original workspace or owner association differs")

    stage = Fields(prepared["stage_metadata"], {"lease_id", "root_identity", "scratch_identity",
                                               "executable_identity", "partitions"})
    partitions = Fields(stage["partitions"], {"input", "scanner", "material"})
    physical = {FreezePhysicalIdentity(stage["root_identity"], 2),
                FreezePhysicalIdentity(stage["scratch_identity"], 2)}
    executable = FreezePhysicalIdentity(stage["executable_identity"], 5)
    physical.add(executable[:2])

    if len(physical) != 3:
        raise ValueError("Native configuration original physical stage identities alias")

    manifests = {}

    for role in ArtifactRole:
        part = Fields(partitions[role.value], {"manifest", "identities", "directory_identity"})
        current = ArtifactManifest.FromDict(part["manifest"])
        directory = FreezePhysicalIdentity(part["directory_identity"], 2)

        if current.role is not role or current.profile is not selection.profile or (
            directory in physical
        ):
            raise ValueError("Native configuration stage partition domains differ")

        physical.add(directory)
        identities = part["identities"]

        if type(identities) is not list or len(identities) != len(current.files):
            raise ValueError("Native configuration staged identity count differs")

        for item, original in zip(current.files, identities, strict=True):
            if type(original) is not list or len(original) != 2 or original[0] != item.name:
                raise ValueError("Native configuration staged file identity order differs")

            identity = FreezePhysicalIdentity(original[1], 5)

            if identity[:2] in physical or identity[2] != item.size_bytes:
                raise ValueError("Native configuration staged physical file identity differs")

            physical.add(identity[:2])

        manifests[role] = current

    scanner = manifests[ArtifactRole.SCANNER]

    if manifests[ArtifactRole.INPUT] != manifest or manifests[ArtifactRole.MATERIAL].files or (
        len(scanner.files) != 1 or scanner.files[0].name != "executable"
        or scanner.files[0].sha256 != NATIVE_CONFIGURATION_EXECUTABLE_SHA256
        or not 1 <= scanner.files[0].size_bytes <= 256 * 1024**2
        or scanner.files[0].size_bytes != executable[2]
    ):
        raise ValueError("Native configuration original pinned material selection differs")

    invocation = Fields(prepared["invocation"], {"adapter_id", "request", "argv",
        "timeout_seconds", "provider_version"})
    operation = prepared["operation"]

    if operation == "version":
        expected = PrepareNativeConfigurationVersion(selection, manifest, scratch / "cache")

        if prepared["version_prerequisite_sha256"] is not None:
            raise ValueError("Native configuration VERSION cannot borrow a prerequisite")

    else:
        arguments = invocation["argv"]

        if type(arguments) is not list or not arguments:
            raise ValueError("Native configuration SCAN argv is absent")

        input_directory = Path(arguments[-1])

        if input_directory.name != "input" or input_directory.parent.parent != workspace or not (
            input_directory.parent.name.startswith("native-configuration-stage-")
        ):
            raise ValueError("Native configuration SCAN selected stage path differs")

        recipe = NativeConfigurationScanRecipe(selection, manifest, input_directory,
                                               scratch / "cache", invocation["timeout_seconds"])
        expected = AdapterInvocation("native.trivy", AdapterRequest(selection.Capability(),
            manifest.Target().Reference(), ImpactLevel.SAFE,
            {"profile": selection.profile.value, "operation": "scan"}), recipe.Arguments(),
            invocation["timeout_seconds"], "0.75.0")

        if type(prepared["version_prerequisite_sha256"]) is not str or len(
            prepared["version_prerequisite_sha256"]
        ) != 64:
            raise ValueError("Native configuration SCAN lacks its original VERSION digest")

    resources = ExecutionResources(**Fields(prepared["resources"],
        {item.name for item in fields(ExecutionResources)}))
    stdout_limit, _ = NATIVE_CONFIGURATION_ROLES["native-configuration-" + operation + "-stdout"]
    stderr_limit, _ = NATIVE_CONFIGURATION_ROLES["native-configuration-" + operation + "-stderr"]

    if Detached(expected) != invocation or resources != ExecutionResources(
        max_stdout_bytes=stdout_limit, max_stderr_bytes=stderr_limit
    ):
        raise ValueError("Native configuration replay differs from its fixed original factory")

    return selection, manifest, expected


def VerifyOperation(envelope: dict[str, Any], stdout: bytes,
                    stderr: bytes) -> tuple[dict[str, Any], ModelProvenance]:
    """Verify one successful original receipt, fixed request, stream chronology and provenance.

    Args:
        envelope: Original bounded decoded operation receipt.
        stdout: Exact original separately retained stdout.
        stderr: Exact original separately retained stderr.

    Returns:
        Exact prepared recipe and historical model provenance without live authority.
    """

    Fields(envelope, {"schema_version", "family", "prepared", "grant", "request", "raw_facts",
        "started_at", "finished_at", "observed_version", "refusal", "cleanup_confirmed"})

    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1 or (
        envelope["family"] != NATIVE_CONFIGURATION_FAMILY or envelope["refusal"] is not None
        or envelope["cleanup_confirmed"] is not True or envelope["observed_version"] != "0.75.0"
    ):
        raise ValueError("Native configuration replay requires confirmed successful custody")

    prepared = envelope["prepared"]
    selection, manifest, invocation = VerifyFactory(prepared)
    grant = Fields(envelope["grant"], {"plan", "authorization", "issued_at", "valid_until",
                                       "approve_safe_configuration"})
    plan_value = Fields(grant["plan"], {item.name for item in
                                       fields(NativeConfigurationOperationPlan)})
    plan = NativeConfigurationOperationPlan(**plan_value)
    authorization = ExecutionAuthorization(**Fields(grant["authorization"], {
        "authorization_id", "scope_reference", "policy_reference", "invocation_sha256",
        "granted_privileges"}))
    bindings = {"operation_id": prepared["operation_id"], "operation": prepared["operation"],
        "operation_reference": prepared["operation_reference"],
        "workspace_id": prepared["workspace_id"], "owner_reference": prepared["owner_reference"],
        "target_reference": manifest.Target().Reference(),
        "input_manifest_sha256": manifest.Digest(), "request_sha256": Digest(prepared),
        "invocation_sha256": InvocationDigest(invocation),
        "material_sha256": Digest(prepared["stage_metadata"]),
        "version_prerequisite_sha256": prepared["version_prerequisite_sha256"],
        "family": NATIVE_CONFIGURATION_FAMILY}

    if any(plan_value[key] != value for key, value in bindings.items()) or (
        grant["approve_safe_configuration"] is not True
        or authorization != GrantEnvelope(plan, grant["issued_at"], grant["valid_until"])
    ):
        raise ValueError("Native configuration original grant or plan binding differs")

    request = Fields(envelope["request"], {"invocation", "capability", "authorization",
                                          "workspace", "environment", "resources"})
    scratch = Path(prepared["scratch"])

    if request["invocation"] != prepared["invocation"] or request["authorization"] != (
        grant["authorization"]
    ) or request["environment"] != ConfigurationEnvironment(scratch) or request["workspace"] != (
        scratch.relative_to(Path(prepared["workspace_root"])).as_posix()
    ) or request["resources"] != prepared["resources"] or request["capability"] != {
        "identifier": selection.Capability(), "adapter_id": "native.trivy",
        "maximum_impact": "SAFE", "required_privileges": []
    }:
        raise ValueError("Native configuration original full execution request differs")

    raw = Fields(envelope["raw_facts"], {"execution", "termination", "stdout_size_bytes",
        "stdout_sha256", "stderr_size_bytes", "stderr_sha256", "events"})
    execution_value = Fields(raw["execution"], {"state", "exit_code", "duration_seconds"})
    execution = AdapterExecution(ExecutionState(execution_value["state"]),
        execution_value["exit_code"], execution_value["duration_seconds"])

    if execution.state is not ExecutionState.SUCCEEDED or execution.exit_code != 0 or (
        raw["termination"] != "process_exit"
        or raw["stdout_size_bytes"] != len(stdout) or raw["stderr_size_bytes"] != len(stderr)
        or raw["stdout_sha256"] != hashlib.sha256(stdout).hexdigest()
        or raw["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
    ):
        raise ValueError("Native configuration original successful stream facts differ")

    events = raw["events"]

    if type(events) is not list or not 2 <= len(events) <= 512 or (
        events[0].get("kind") != "started" or events[-1].get("kind") != "completed"
    ):
        raise ValueError("Native configuration original event lifecycle differs")

    offsets = {"stdout": 0, "stderr": 0}
    streams = {"stdout": stdout, "stderr": stderr}

    for index, original in enumerate(events):
        event = Fields(original, {"sequence", "kind", "size_bytes", "sha256", "termination"})
        kind = event["kind"]
        size = event["size_bytes"]

        if type(event["sequence"]) is not int or event["sequence"] != index or (
            type(size) is not int or size < 0
        ):
            raise ValueError("Native configuration original event order or size differs")

        if kind in streams:
            data = streams[kind][offsets[kind]:offsets[kind] + size]
            offsets[kind] += size

            if not size or len(data) != size or event["termination"] is not None:
                raise ValueError("Native configuration stream event framing differs")

        else:
            data = b""

            if size != 0 or (kind, index) not in {("started", 0), ("completed", len(events) - 1)}:
                raise ValueError("Native configuration event lifecycle contains unknown states")

            if event["termination"] != ("process_exit" if kind == "completed" else None):
                raise ValueError("Native configuration completion event termination differs")

        if event["sha256"] != hashlib.sha256(data).hexdigest():
            raise ValueError("Native configuration original event bytes differ")

    if offsets != {"stdout": len(stdout), "stderr": len(stderr)}:
        raise ValueError("Native configuration event streams are incomplete")

    started = DateTimeFromText(envelope["started_at"])
    finished = DateTimeFromText(envelope["finished_at"])
    issued = DateTimeFromText(grant["issued_at"])
    expiry = DateTimeFromText(grant["valid_until"])

    if not issued <= started < finished < expiry:
        raise ValueError("Native configuration original collection chronology differs")

    provenance = ModelProvenance("native.trivy", prepared["operation_id"],
        envelope["finished_at"], plan.scope_reference, plan.target_reference,
        "0.75.0", (), execution)

    return prepared, provenance


def DateTimeFromText(value: object) -> Any:
    """Validate aware canonical evidence time without consulting the current wall clock.

    Args:
        value: Original single-line aware ISO8601 timestamp.

    Returns:
        Parsed aware datetime for historical chronology comparisons.
    """

    from datetime import datetime

    from fuzzy1337.evidence import NormalizeEvidenceTime

    if type(value) is not str or NormalizeEvidenceTime(value) != value:
        raise ValueError("Native configuration original time is not canonical")

    return datetime.fromisoformat(value)


def VerifyNativeConfigurationReplay(records: tuple[EvidenceRecord, ...],
                                    workspace_root: Path) -> NativeConfigurationReplay:
    """Verify seven owning acquisitions after relocation without current paths or live authority.

    Args:
        records: Exactly seven original typed immutable native configuration acquisitions.
        workspace_root: Existing or relocated canonical owning workspace.

    Returns:
        Verified historical source/check facts; no model mutation, execution or grant is performed.
    """

    if type(records) is not tuple or len(records) != 7 or any(
        type(item) is not EvidenceRecord for item in records
    ):
        raise ValueError("Native configuration replay requires seven original acquisitions")

    by_role = {item.reference.role: item for item in records}

    if set(by_role) != set(NATIVE_CONFIGURATION_ROLES):
        raise ValueError("Native configuration replay requires seven distinct original roles")

    workspace_id = LocalWorkspaceStore(workspace_root).Open().workspace_id
    store = NativeConfigurationEvidenceStore(workspace_root / "evidence")
    raw = {}

    for role, record in by_role.items():
        if store.Get(record.evidence_id) != record or (
            record.provenance.workspace_id != workspace_id
        ):
            raise ValueError("Native configuration acquisition differs from its owning manifest")

        raw[role] = store.Read(record.reference)

    envelopes = {}
    prepared_operations = {}
    provenances = {}

    for operation in ("version", "scan"):
        prefix = "native-configuration-" + operation
        envelope = cast(dict[str, Any], ParseJson(raw[prefix + "-receipt"], max_bytes=256 * 1024))
        prepared, provenance = VerifyOperation(envelope, raw[prefix + "-stdout"],
                                               raw[prefix + "-stderr"])

        if prepared["operation"] != operation or prepared["workspace_id"] != workspace_id:
            raise ValueError("Native configuration original operation/workspace differs")

        execution = provenance.execution
        expected = EvidenceProvenance(workspace_id, provenance.scope_reference,
            "native.trivy", "1", "0.75.0", envelope["started_at"], envelope["finished_at"],
            envelope["grant"]["plan"]["invocation_sha256"], execution)
        roles = [prefix + "-stdout", prefix + "-stderr", prefix + "-receipt"]

        if operation == "scan":
            roles.append("native-configuration-source")

        if any(by_role[role].provenance != expected for role in roles):
            raise ValueError("Native configuration acquisition provenance differs from its receipt")

        envelopes[operation] = envelope
        prepared_operations[operation] = prepared
        provenances[operation] = provenance

    version = prepared_operations["version"]
    scan = prepared_operations["scan"]
    version_digest = Digest({"family": NATIVE_CONFIGURATION_FAMILY, "prepared": version,
        "grant": envelopes["version"]["grant"], "capture_sha256": Digest(envelopes["version"])})

    if scan["version_prerequisite_sha256"] != version_digest or any(
        scan[key] != version[key] for key in ("selection", "workspace_root", "workspace_id",
            "owner_reference", "operation_reference", "input_manifest", "stage_metadata")
    ) or envelopes["version"]["finished_at"] > envelopes["scan"]["started_at"] or (
        provenances["version"].scope_reference != provenances["scan"].scope_reference
        or ParseJson(raw["native-configuration-version-stdout"], max_bytes=16 * 1024).get(
            "Version") != "0.75.0"
    ):
        raise ValueError("Native configuration original VERSION/SCAN association differs")

    selection, manifest, _ = VerifyFactory(scan)
    source = raw["native-configuration-source"]
    selected = manifest.files[0]

    if len(source) != selected.size_bytes or hashlib.sha256(source).hexdigest() != selected.sha256:
        raise ValueError("Native configuration original source differs from its captured manifest")

    checks = ParseNativeConfigurationReport(raw["native-configuration-scan-stdout"],
        raw["native-configuration-scan-stderr"], selection, manifest, source)
    provenance = replace(provenances["scan"], evidence_references=tuple(item.reference for item in
        sorted(records, key=lambda item: item.reference.role)))

    return NativeConfigurationReplay(workspace_id, scan["owner_reference"], manifest, selection,
        provenance, records, checks, Digest(envelopes["version"]), Digest(envelopes["scan"]))


def ApplyVerifiedNativeConfiguration(
    state: ModelState, capture: NativeConfigurationOperationCapture,
    records: tuple[EvidenceRecord, ...], workspace_root: Path, *,
    engine: ArtifactPolicyEngine, version_prerequisite: NativeConfigurationVersionPrerequisite,
    scan_claim: NativeConfigurationExecutionClaim, observer: NativeConfigurationMaterialObserver,
    material_proof: NativeConfigurationMaterialProof,
    context_provider: Callable[[], ArtifactPolicyContext],
) -> tuple[ModelState, ModelDelta]:
    """Propose canonical assets/Findings only from verified history plus original live authority.

    Args:
        state: Original owning immutable model state.
        capture: Exact original successful SCAN capture.
        records: Seven original owning acquisitions for this exact pair.
        workspace_root: Existing owning workspace.
        engine: Original issuing canonical artifact policy owner.
        version_prerequisite: Exact engine-issued original accepted VERSION.
        scan_claim: Original engine-issued SCAN claim.
        observer: Original selected-material owner.
        material_proof: Latest exact original post-SCAN proof.
        context_provider: Fresh synchronous factual authority context source.

    Returns:
        Isolated canonical proposal and delta without saving or emitting events.
    """

    facts = VerifyNativeConfigurationReplay(records, workspace_root)

    if type(capture) is not NativeConfigurationOperationCapture or (
        state.workspace_id != facts.workspace_id or capture.Digest() != facts.scan_capture_sha256
        or capture.refusal is not None
    ):
        raise ValueError("Native configuration model application requires this exact original run")

    selected = facts.input_manifest.files[0]
    asset = SecurityObject(ObjectIdentity(facts.workspace_id, ObjectKind.ASSET,
        "native:configuration:" + facts.input_manifest.Digest() + ":" + selected.name), {
        "asset_type": "native-configuration", "source_family": NATIVE_CONFIGURATION_FAMILY,
        "input_manifest_sha256": facts.input_manifest.Digest(), "logical_path": selected.name,
        "source_sha256": selected.sha256, "size_bytes": selected.size_bytes,
        "configuration_type": facts.selection.Scanner(),
        "profile_id": facts.input_manifest.profile.value, "scan_completeness": "not-assessed"},
        (facts.provenance,))
    findings = []

    for check in facts.checks:
        if check.status != "FAIL":
            continue

        position = {"logical_path": selected.name, "start_line": check.start_line,
                    "end_line": check.end_line, "resource": check.resource,
                    "native_check_id": check.check_id}
        findings.append(Finding(asset.Reference(), "configuration.native." + check.check_id.lower(),
            CanonicalModelJson(position).decode(), check.title, (facts.provenance,),
            severity=FindingSeverity(check.severity.lower()), confidence=1.0,
            remediation=Remediation(check.resolution or None)))

    incoming = {item.Reference() for item in (asset, *(item.ToObject(state.workspace_id)
                                                     for item in findings))}

    for current in state.objects:
        if current.Reference() in incoming and not any(
            item.source_id == "native.trivy" and any(reference.role ==
                "native-configuration-scan-receipt" for reference in item.evidence_references)
            for item in current.provenance
        ):
            raise ValueError("Native configuration cannot overlay a foreign source family")

    observation = Observation("configuration-inventory", asset.Reference(), {
        "source_family": NATIVE_CONFIGURATION_FAMILY, "classification": "native-configuration",
        "processed": True, "finding_count": len(findings), "scan_completeness": "not-assessed"},
        facts.provenance)
    from fuzzy1337.policy import UtcNow

    engine.ValidateNativeConfigurationPairFresh(version_prerequisite, scan_claim, capture,
        context_provider(), observer=observer, material_proof=material_proof, at=UtcNow())
    updated, inventory = state.Apply(objects=(asset,), observations=(observation,))
    updated, detections = ApplyFindings(updated, tuple(findings))
    created = set(inventory.created) | set(detections.created)
    changed = (set(inventory.updated) | set(detections.updated)) - created
    updated = replace(updated, revision=state.revision + bool(created or changed))

    return updated, ModelDelta(state.revision, updated.revision,
                               tuple(sorted(created)), tuple(sorted(changed)))
