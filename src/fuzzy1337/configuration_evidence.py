# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original synthetic configuration capture, read-only replay and fresh typed model proposals."""

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
    ArtifactOperation,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
    ArtifactStage,
)
from fuzzy1337.artifact_policy import (
    ArtifactAcceptance,
    ArtifactArgv,
    ArtifactEnvironment,
    ArtifactExecutionOutcome,
    ArtifactPolicyContext,
    ArtifactStagePayload,
    DetachedReplayBounds,
    DetachedReplayIdentity,
    DetachedReplayPath,
    GovernedArtifactExecutor,
    PreparedArtifact,
    ProfileCapability,
    ValidateArtifactResources,
    VerifyArtifactReplay,
)
from fuzzy1337.evidence import (
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.executors import ExecutionResources, InvocationDigest
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
from fuzzy1337.policy import Digest
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields

CONFIGURATION_SOURCE = "synthetic.trivy"
CONFIGURATION_VERSION = "0.75.0-synthetic"
CONFIGURATION_FAMILY = "owned-synthetic-configuration-wire-v1"
_PROFILES = {ArtifactProfile.SYNTHETIC_DOCKERFILE, ArtifactProfile.SYNTHETIC_KUBERNETES}
_ROLES = {
    "configuration-stdout": (16 * 1024, "application/json"),
    "configuration-stderr": (16 * 1024, "text/plain"),
    "configuration-receipt": (128 * 1024, "application/json"),
    "configuration-source": (4096, "text/plain"),
}
_RULES = {
    "dockerfile": ("synthetic.configuration.dockerfile-root-user",
        "Owned synthetic Dockerfile uses the root user", "Use an explicit non-root user"),
    "kubernetes": ("synthetic.configuration.privileged-container",
        "Owned synthetic Kubernetes container is privileged", "Disable privileged container mode"),
}

__all__ = ["ConfigurationOperationCapture", "ConfigurationReplay",
    "VerifySyntheticConfigurationReplay", "ApplyVerifiedSyntheticConfiguration"]


def Detached(value: object) -> dict[str, Any]:
    """Detach canonical first-party facts without retaining mutable caller aliases."""

    return cast(dict[str, Any], json.loads(SerializeContract(value)))


def Fields(value: object, expected: set[str]) -> dict[str, Any]:
    """Require exact consumer-owned fields without defaults or ignored extensions."""

    return cast(dict[str, Any], WorkspaceFields(value, expected, "configuration capture"))


@dataclass(frozen=True, slots=True)
class ConfigurationOperationCapture:
    """Original SDK run and observed collection window; possession grants no authority."""

    outcome: ArtifactExecutionOutcome
    prepared: PreparedArtifact
    stage: ArtifactStage
    started_at: str
    finished_at: str

    def __post_init__(self) -> None:
        """Require typed originals and a normalized increasing actual collection window."""

        if type(self.outcome) is not ArtifactExecutionOutcome or (
            type(self.prepared) is not PreparedArtifact or type(self.stage) is not ArtifactStage
        ):
            raise ValueError("configuration capture requires original typed SDK facts")

        object.__setattr__(self, "started_at", NormalizeEvidenceTime(self.started_at))
        object.__setattr__(self, "finished_at", NormalizeEvidenceTime(self.finished_at))

        if self.started_at >= self.finished_at:
            raise ValueError("configuration capture requires increasing collection readings")

    def Envelope(self) -> dict[str, object]:
        """Detach original operation metadata and complete request/stage bindings.

        Returns:
            Exact schema-one capture of original SDK schema-two facts and collection readings.
        """

        return Detached({"schema_version": 1, "artifact_metadata": self.outcome.Metadata(),
            "prepared_payload": self.prepared.Payload(),
            "stage_payload": ArtifactStagePayload(self.stage),
            "collection_started_at": self.started_at, "collection_finished_at": self.finished_at})

    def Provenance(self) -> EvidenceProvenance:
        """Attribute raw acquisitions to their exact original executed invocation.

        Returns:
            Original owning workspace, scope, invocation, execution and actual collection window.
        """

        plan = self.outcome.grant.plan

        return EvidenceProvenance(plan.workspace_id, plan.scope_reference,
            CONFIGURATION_SOURCE, "1", CONFIGURATION_VERSION, self.started_at, self.finished_at,
            InvocationDigest(self.prepared.invocation), self.outcome.raw_result.execution)


@dataclass(frozen=True, slots=True)
class ConfigurationReplay:
    """Verified historical operation facts without current launch or model-write authority."""

    workspace_id: str
    owner_reference: str
    acceptance: ArtifactAcceptance
    provenance: ModelProvenance
    input_manifest: ArtifactManifest
    records: tuple[EvidenceRecord, ...]


class ConfigurationEvidenceStore(LocalEvidenceStore):
    """Check consumer budgets before the evidence owner's eager immutable raw verification."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Read one original bounded configuration role through canonical integrity checks."""

        if type(reference) is not EvidenceReference or reference.role not in _ROLES:
            raise ValueError("configuration evidence requires its exact source role")

        limit, media = _ROLES[reference.role]

        if type(reference.size_bytes) is not int or not 0 <= reference.size_bytes <= limit or (
            reference.media_type != media
        ):
            raise ValueError("configuration evidence exceeds its role budget")

        return super().Read(reference)


def VerifyFactory(envelope: dict[str, Any]) -> ArtifactManifest:
    """Verify detached original configuration factory grammar without filesystem access."""

    metadata = envelope["artifact_metadata"]
    prepared = Fields(envelope["prepared_payload"], {
        "workspace_root", "stage_lease", "invocation", "capability", "workspace", "environment",
        "resources", "operation", "producer_family", "version_run_id", "version_grant_id",
        "version_prerequisite_sha256"})
    stage = Fields(envelope["stage_payload"], {"root", "lease", "root_identity", "executable",
        "executable_identity", "version", "partitions"})
    DetachedReplayBounds(envelope)
    plan = metadata["grant"]["plan"]
    profile = ArtifactProfile(plan["profile"])

    if profile not in _PROFILES or plan["producer_family"] != CONFIGURATION_FAMILY or (
        plan["operation"] != "scan" or plan["provider_version"] != CONFIGURATION_VERSION
        or Digest(prepared) != plan["request_sha256"] or Digest(stage) != plan["stage_sha256"]
    ):
        raise ValueError("configuration capture differs from its original closed source family")

    if stage["lease"] != plan["stage_lease"] or stage["lease"] != prepared["stage_lease"] or (
        stage["version"] != CONFIGURATION_VERSION
    ):
        raise ValueError("configuration stage differs from its original lease")

    for key in ("operation", "producer_family", "version_run_id", "version_grant_id",
                "version_prerequisite_sha256"):
        if prepared[key] != plan[key] or (key.startswith("version_") and plan[key] is not None):
            raise ValueError("configuration capture cannot borrow a VERSION prerequisite")

    root = DetachedReplayPath(stage["root"])
    workspace = DetachedReplayPath(prepared["workspace_root"])
    executable = DetachedReplayPath(stage["executable"])

    if type(root) is not type(workspace) or type(root) is not type(executable) or (
        root == workspace or not root.is_relative_to(workspace) or executable.is_relative_to(root)
        or prepared["workspace"] != (root / "scratch").relative_to(workspace).as_posix()
    ):
        raise ValueError("configuration original paths are inconsistent")

    partitions = stage["partitions"]

    if type(partitions) is not list or len(partitions) != 3:
        raise ValueError("configuration requires three original partitions")

    physical = {DetachedReplayIdentity(stage["root_identity"], 2)}
    runtime = DetachedReplayIdentity(stage["executable_identity"], 5)

    if runtime[:2] in physical:
        raise ValueError("configuration runtime aliases its original stage")

    physical.add(runtime[:2])
    manifests = []

    for partition, role in zip(partitions, ArtifactRole, strict=True):
        part = Fields(partition, {"manifest", "consent", "identities", "directory_identity"})
        manifest = ArtifactManifest.FromDict(part["manifest"])
        manifests.append(manifest)
        consent = Fields(part["consent"], {"actor_ref", "record_ref"})
        ArtifactReadConsent(**consent)
        directory = DetachedReplayIdentity(part["directory_identity"], 2)

        if directory in physical or manifest.role is not role or manifest.profile is not profile:
            raise ValueError("configuration partitions have inconsistent roles or identities")

        physical.add(directory)
        identities = part["identities"]

        if type(identities) is not list or len(identities) != len(manifest.files):
            raise ValueError("configuration file identity count differs from its manifest")

        for item, observed in zip(manifest.files, identities, strict=True):
            if type(observed) is not list or len(observed) != 2 or observed[0] != item.name:
                raise ValueError("configuration file observation order is inconsistent")

            identity = DetachedReplayIdentity(observed[1], 5)

            if identity[:2] in physical or identity[2] != item.size_bytes:
                raise ValueError("configuration file observations alias or have wrong sizes")

            physical.add(identity[:2])

    if [item.ToDict() for item in manifests] != metadata["manifests"] or (
        manifests[0].Target().Reference() != plan["target_reference"]
        or runtime[2] != manifests[1].files[0].size_bytes
    ):
        raise ValueError("configuration stage differs from its original source manifests")

    invocation = Fields(prepared["invocation"], {"adapter_id", "request", "argv",
        "timeout_seconds", "provider_version"})
    resources = ExecutionResources(**Fields(prepared["resources"],
        {item.name for item in fields(ExecutionResources)}))
    timeout = invocation["timeout_seconds"]
    ValidateArtifactResources(CONFIGURATION_FAMILY, ArtifactOperation.SCAN, timeout, resources)
    capability = ProfileCapability(profile)
    expected = AdapterInvocation(capability.adapter_id, AdapterRequest(capability.identifier,
        manifests[0].Target().Reference(), ImpactLevel.SAFE, {"profile": profile.value,
            "input_manifest_sha256": manifests[0].Digest(), "operation": "scan",
            "producer_family": CONFIGURATION_FAMILY}),
        ArtifactArgv(root, executable, profile, CONFIGURATION_FAMILY, ArtifactOperation.SCAN,
                     timeout), timeout, CONFIGURATION_VERSION)
    environment = Fields(prepared["environment"], set(ArtifactEnvironment(root, "", "")))

    if invocation != Detached(expected) or prepared["capability"] != Detached(capability) or (
        environment != dict(ArtifactEnvironment(root, environment["SYSTEMROOT"],
                                                environment["WINDIR"]))
        or InvocationDigest(expected) != plan["invocation_sha256"]
    ):
        raise ValueError("configuration request differs from its fixed original factory")

    return manifests[0]


def VerifiedCapture(records: tuple[EvidenceRecord, ...], workspace_root: Path
                    ) -> tuple[ConfigurationReplay, dict[str, Any], dict[str, bytes]]:
    """Verify owning immutable records, original raw receipt and original source attribution."""

    if type(records) is not tuple or len(records) != 4 or any(
        type(item) is not EvidenceRecord for item in records
    ):
        raise ValueError("configuration replay requires four original typed acquisitions")

    by_role = {item.reference.role: item for item in records}

    if set(by_role) != set(_ROLES):
        raise ValueError("configuration replay requires four distinct original source roles")

    workspace = LocalWorkspaceStore(workspace_root)
    workspace_id = workspace.Open().workspace_id
    store = ConfigurationEvidenceStore(workspace.root / "evidence")
    raw = {}

    for role, record in by_role.items():
        store.Read(record.reference)

        if record.provenance.workspace_id != workspace_id or (
            store.Get(record.evidence_id) != record
        ):
            raise ValueError("configuration acquisition differs from its immutable owning manifest")

        raw[role] = store.Read(record.reference)

    try:
        envelope = Fields(ParseJson(raw["configuration-receipt"], 128 * 1024), {
            "schema_version", "artifact_metadata", "prepared_payload", "stage_payload",
            "collection_started_at", "collection_finished_at"})

        if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
            raise ValueError("configuration capture requires schema one")

        metadata = envelope["artifact_metadata"]

        if type(metadata) is not dict or type(metadata.get("schema_version")) is not int or (
            metadata["schema_version"] != 2
        ):
            raise ValueError("configuration requires original SDK schema two")

        acceptance = VerifyArtifactReplay(metadata, raw["configuration-stdout"],
                                           raw["configuration-stderr"])
        manifest = VerifyFactory(envelope)
        selected = manifest.files[0]

        if len(raw["configuration-source"]) != selected.size_bytes or hashlib.sha256(
            raw["configuration-source"]).hexdigest() != selected.sha256:
            raise ValueError("configuration raw source differs from its original input manifest")

        plan = metadata["grant"]["plan"]
        started = NormalizeEvidenceTime(envelope["collection_started_at"])
        finished = NormalizeEvidenceTime(envelope["collection_finished_at"])
        issued = NormalizeEvidenceTime(metadata["grant"]["issued_at"])
        checked = NormalizeEvidenceTime(acceptance.checked_at)

        if started != envelope["collection_started_at"] or finished != (
            envelope["collection_finished_at"]
        ) or not issued <= started <= checked <= finished or started >= finished:
            raise ValueError("configuration collection chronology contradicts original facts")

        actual = metadata["raw_facts"]["execution"]
        execution = AdapterExecution(ExecutionState(actual["state"]), actual["exit_code"],
                                     actual["duration_seconds"])
        expected = EvidenceProvenance(workspace_id, plan["scope_reference"],
            CONFIGURATION_SOURCE, "1", CONFIGURATION_VERSION, started, finished,
            plan["invocation_sha256"], execution)

        if any(record.provenance != expected for record in records):
            raise ValueError("configuration acquisition differs from original run provenance")

        provenance = ModelProvenance(CONFIGURATION_SOURCE, acceptance.run_id, finished,
            plan["scope_reference"], plan["target_reference"], CONFIGURATION_VERSION,
            tuple(item.reference for item in records), execution)
        facts = ConfigurationReplay(workspace_id, plan["owner_ref"], acceptance, provenance,
            manifest, tuple(sorted(records, key=lambda item: item.reference.role)))

        return facts, envelope, raw

    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        raise ValueError("configuration original capture facts are inconsistent") from None


def VerifySyntheticConfigurationReplay(records: tuple[EvidenceRecord, ...],
                                       workspace_root: Path) -> ConfigurationReplay:
    """Verify original successful or refused facts after relocation without reviving authority.

    Args:
        records: Four exact original owning-store acquisitions, including retained source bytes.
        workspace_root: Existing or relocated owning workspace.

    Returns:
        Historical attribution and refusal facts only; no process, grant or model mutation.

    Raises:
        ValueError: Original source, factory, time or provenance bindings are inconsistent.
        OSError: Owning storage is unavailable or evidence integrity fails.
    """

    return VerifiedCapture(records, workspace_root)[0]


def Candidates(facts: ConfigurationReplay, raw: dict[str, bytes]
               ) -> tuple[SecurityObject, Observation, tuple[Finding, ...]]:
    """Normalize exactly the reviewed configuration wire and source-coordinate semantics."""

    payload = Fields(ParseJson(raw["configuration-stdout"], 16 * 1024), {
        "schema_version", "provider_id", "provider_version", "fixture_id", "profile_id",
        "case_id", "scan_completeness", "file_outcomes", "findings"})
    manifest = facts.input_manifest
    selected = manifest.files[0]
    dockerfile = manifest.profile is ArtifactProfile.SYNTHETIC_DOCKERFILE
    kind = "dockerfile" if dockerfile else "kubernetes"
    lines = raw["configuration-source"].decode("utf-8").splitlines()
    document = 0
    expected_findings = []

    for line_number, text in enumerate(lines, 1):
        if text.strip() == "---":
            document += 1

        failed = text.strip() in {"USER 0", "USER root"} if dockerfile else (
            text.strip() == "privileged: true")

        if failed:
            expected_findings.append({"logical_path": selected.name, "check_id": _RULES[kind][0],
                "severity": "HIGH", "outcome": "failed", "start_line": line_number,
                "end_line": line_number, "document_index": None if dockerfile else document,
                "resource_selector": "instruction:USER" if dockerfile else
                    "/spec/containers/0/securityContext/privileged"})

    case_id = ("dockerfile.root-user" if expected_findings else "dockerfile.non-root-user") if (
        dockerfile
    ) else ("kubernetes.second-document" if document == 1 else (
        "kubernetes.privileged-container" if expected_findings else
        "kubernetes.non-privileged-container"))
    expected_files = [{"logical_path": selected.name, "sha256": selected.sha256,
        "size_bytes": selected.size_bytes, "configuration_type": kind,
        "document_count": None if dockerfile else document + 1, "outcome": "processed"}]

    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1 or (
        payload["provider_id"] != CONFIGURATION_SOURCE
        or payload["provider_version"] != CONFIGURATION_VERSION
        or payload["fixture_id"] != CONFIGURATION_FAMILY
        or payload["profile_id"] != manifest.profile.value
        or payload["case_id"] != case_id or payload["scan_completeness"] != "not-assessed"
        or CanonicalModelJson(payload["file_outcomes"]) != CanonicalModelJson(expected_files)
        or CanonicalModelJson(payload["findings"]) != CanonicalModelJson(expected_findings)
    ):
        raise ValueError("configuration wire differs from its exact processed source and checks")

    asset = SecurityObject(ObjectIdentity(facts.workspace_id, ObjectKind.ASSET,
        "synthetic:configuration:" + manifest.Digest() + ":" + selected.name), {
            "asset_type": "synthetic-configuration", "source_family": CONFIGURATION_FAMILY,
            "input_manifest_sha256": manifest.Digest(), "logical_path": selected.name,
            "source_sha256": selected.sha256, "size_bytes": selected.size_bytes,
            "configuration_type": kind, "profile_id": manifest.profile.value,
            "document_count": None if dockerfile else document + 1,
            "scan_completeness": "not-assessed"}, (facts.provenance,))
    findings = []

    for item in expected_findings:
        position = {key: item[key] for key in (
            "start_line", "end_line", "document_index", "resource_selector")}
        findings.append(Finding(asset.Reference(), _RULES[kind][0],
            CanonicalModelJson(position).decode("utf-8"), _RULES[kind][1], (facts.provenance,),
            severity=FindingSeverity.HIGH, confidence=1.0,
            remediation=Remediation(_RULES[kind][2])))

    observation = Observation("configuration-inventory", asset.Reference(), {
        "source_family": CONFIGURATION_FAMILY, "classification": "synthetic-configuration",
        "processed": True, "finding_count": len(findings), "scan_completeness": "not-assessed"},
        facts.provenance)

    return asset, observation, tuple(findings)


def ApplyVerifiedSyntheticConfiguration(state: ModelState, capture: ConfigurationOperationCapture,
    records: tuple[EvidenceRecord, ...], workspace_root: Path, *,
    context_provider: Callable[[], ArtifactPolicyContext],
) -> tuple[ModelState, ModelDelta]:
    """Propose an isolated canonical transition after original-record and fresh live acceptance.

    Args:
        state: Original immutable model snapshot of the owning evidence workspace.
        capture: Exact typed original granted execution, request, physical stage and timings.
        records: Four original immutable acquisitions produced for this exact run.
        workspace_root: Existing workspace owning model, evidence and original physical stage.
        context_provider: Fresh synchronous factual scope, owner and policy lookup.

    Returns:
        In-memory canonical proposal and delta; no save, launch, grant or evidence write.

    Raises:
        ValueError: Original bytes, wire, namespace or ownership bindings disagree.
        ArtifactDeniedError: Current grant, scope, selected material or original stage is refused.
        OSError: Current owning storage or retained evidence cannot be read.
    """

    if type(state) is not ModelState or type(capture) is not ConfigurationOperationCapture:
        raise ValueError("configuration application requires original typed model and capture")

    facts, envelope, raw = VerifiedCapture(records, workspace_root)

    if state.workspace_id != facts.workspace_id or facts.acceptance.refusal is not None or (
        envelope != capture.Envelope()
        or raw["configuration-stdout"] != capture.outcome.raw_result.stdout
        or raw["configuration-stderr"] != capture.outcome.raw_result.stderr
    ):
        raise ValueError("configuration application requires this exact successful owned run")

    asset, observation, findings = Candidates(facts, raw)
    incoming = {item.Reference(): item for item in (asset, *(item.ToObject(state.workspace_id)
                                                           for item in findings))}

    for current in state.objects:
        if current.Reference() not in incoming:
            continue

        if current.identity.kind is ObjectKind.ASSET and (
            current.attributes.get("source_family") != CONFIGURATION_FAMILY
            or current.attributes.get("asset_type") != "synthetic-configuration"
            or any(item.source_id != CONFIGURATION_SOURCE for item in current.provenance)
        ) or current.identity.kind is ObjectKind.FINDING and not any(
            item.source_id == CONFIGURATION_SOURCE and any(
                reference.role == "configuration-receipt" for reference in item.evidence_references
            ) for item in current.provenance
        ):
            raise ValueError("configuration interpretation cannot overlay a foreign source family")

    GovernedArtifactExecutor(workspace_root).ValidateAcceptanceFresh(capture.outcome,
        capture.prepared, capture.stage, context_provider)
    updated, inventory = state.Apply(objects=(asset,), observations=(observation,))
    updated, detections = ApplyFindings(updated, findings)
    created = set(inventory.created) | set(detections.created)
    changed = (set(inventory.updated) | set(detections.updated)) - created
    updated = replace(updated, revision=state.revision + bool(created or changed))

    return updated, ModelDelta(state.revision, updated.revision,
                               tuple(sorted(created)), tuple(sorted(changed)))
