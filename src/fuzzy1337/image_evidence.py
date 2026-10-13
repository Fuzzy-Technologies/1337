# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict original synthetic image capture verification, separate from live authority and writes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import cast

from fuzzy1337.adapters import (
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
    ArtifactStage,
    FreezePhysicalIdentity,
)
from fuzzy1337.artifact_policy import (
    ArtifactExecutionOutcome,
    ArtifactStagePayload,
    PreparedArtifact,
    VerifyArtifactReplay,
)
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceIntegrityError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.executors import ExecutionResources, ExecutionTermination, InvocationDigest
from fuzzy1337.model import CanonicalModelJson, ModelProvenance, ModelState
from fuzzy1337.policy import Digest
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields

SYNTHETIC_IMAGE_FAMILY = "owned-synthetic-image-wire-v1"
SYNTHETIC_IMAGE_SOURCE = "synthetic.trivy"
SYNTHETIC_IMAGE_VERSION = "0.75.0-synthetic"
SYNTHETIC_IMAGE_WORKER_SHA256 = "afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53"
IMAGE_RECEIPT_MAX_BYTES = 1024 * 1024
_DATABASE = {
    "Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z",
    "NextUpdate": "2026-10-02T00:00:00Z", "DownloadedAt": "2026-10-01T01:00:00Z",
}
_ROLE_BOUNDS = {
    "provider-version": 16 * 1024, "provider-version-stderr": 16 * 1024,
    "stdout": 4 * 1024 * 1024, "stderr": 1024 * 1024,
    "artifact-version-receipt": IMAGE_RECEIPT_MAX_BYTES,
    "artifact-scan-receipt": IMAGE_RECEIPT_MAX_BYTES,
}


class ImageEvidenceStore(LocalEvidenceStore):
    """Intercept actual manifest reads with exact role/media limits before eager blob allocation."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Bound actual owner-decoded references even when reached indirectly through Get.

        Args:
            reference: Actual decoded immutable manifest reference or explicit incoming reference.

        Returns:
            Original role-bounded bytes after canonical evidence-owner integrity verification.
        """

        media_type = "text/plain" if reference.role in {"stderr", "provider-version-stderr"} else (
            "application/json"
        )

        if reference.role not in _ROLE_BOUNDS or reference.size_bytes > _ROLE_BOUNDS[
            reference.role
        ] or reference.media_type != media_type:
            raise EvidenceIntegrityError(
                "synthetic image actual acquisition exceeds its role bound"
            )

        return super().Read(reference)


def Detached(value: object) -> dict[str, object]:
    """Copy one first-party payload into canonical finite JSON rather than retaining references.

    Args:
        value: Typed SDK payload or original JSON document.

    Returns:
        Detached canonical object with dataclass and enum fields serialized by their owner.
    """

    return cast(dict[str, object], json.loads(SerializeContract(value)))


@dataclass(frozen=True, slots=True)
class ImageOperationCapture:
    """Original per-operation physical request and outcome plus its observed collection window."""

    outcome: ArtifactExecutionOutcome
    prepared: PreparedArtifact
    stage: ArtifactStage
    started_at: str
    finished_at: str

    def __post_init__(self) -> None:
        """Validate original typed SDK objects and clock readings without filesystem access."""

        if not isinstance(self.outcome, ArtifactExecutionOutcome) or not isinstance(
            self.prepared, PreparedArtifact
        ) or not isinstance(self.stage, ArtifactStage):
            raise ValueError("image capture requires original typed operation facts")

        object.__setattr__(self, "started_at", NormalizeEvidenceTime(self.started_at))
        object.__setattr__(self, "finished_at", NormalizeEvidenceTime(self.finished_at))

        if self.started_at >= self.finished_at:
            raise ValueError("image capture requires an increasing observed collection window")

    def Envelope(self) -> dict[str, object]:
        """Detach the exact original receipt/request/stage facts without changing their schemas.

        Returns:
            Strict schema-1 capture envelope containing the original schema-2 SDK metadata.
        """

        return Detached({
            "schema_version": 1, "artifact_metadata": self.outcome.Metadata(),
            "prepared_payload": self.prepared.Payload(),
            "stage_payload": ArtifactStagePayload(self.stage),
            "collection_started_at": self.started_at, "collection_finished_at": self.finished_at,
        })

    def Provenance(self) -> EvidenceProvenance:
        """Retain this operation's actual invocation/execution, never the other phase's facts.

        Returns:
            Existing immutable acquisition attribution for both streams and the receipt role.
        """

        plan = self.outcome.grant.plan

        return EvidenceProvenance(plan.workspace_id, plan.scope_reference,
            SYNTHETIC_IMAGE_SOURCE, "1", SYNTHETIC_IMAGE_VERSION, self.started_at, self.finished_at,
            InvocationDigest(self.prepared.invocation), self.outcome.raw_result.execution)


@dataclass(frozen=True, slots=True)
class VerifiedImagePair:
    """Verified saved wire facts; this value neither grants authority nor mutates a model."""

    payload: dict[str, object]
    version: dict[str, object]
    database: dict[str, object]
    version_envelope: dict[str, object]
    scan_envelope: dict[str, object]


def SavedImageProvenance(records: tuple[EvidenceRecord, ...],
                         workspace_root: Path) -> ModelProvenance:
    """Derive interpretation attribution from original SCAN records rather than caller claims.

    Args:
        records: Exact six original operation acquisition manifests.
        workspace_root: Owning workspace containing the immutable capture receipt.

    Returns:
        Original SCAN run/time/scope/execution with all six canonically sorted references.
    """

    if not isinstance(records, tuple) or len(records) != 6 or any(
        not isinstance(item, EvidenceRecord) for item in records
    ) or {item.reference.role for item in records} != set(_ROLE_BOUNDS):
        raise ValueError("image provenance requires exact original acquisition roles")

    by_role = {item.reference.role: item for item in records}
    source = by_role["stdout"].provenance
    receipt = by_role["artifact-scan-receipt"]
    store = ImageEvidenceStore(workspace_root / "evidence")

    if receipt.reference.size_bytes > IMAGE_RECEIPT_MAX_BYTES or (
        store.Get(receipt.evidence_id) != receipt
    ):
        raise ValueError("image original capture receipt is inconsistent")

    envelope = ParseJson(store.Read(receipt.reference), IMAGE_RECEIPT_MAX_BYTES)
    metadata = cast(dict[str, object], envelope["artifact_metadata"])
    acceptance = cast(dict[str, object], metadata["acceptance"])
    grant = cast(dict[str, object], metadata["grant"])
    plan = cast(dict[str, object], grant["plan"])

    return ModelProvenance(SYNTHETIC_IMAGE_SOURCE, cast(str, acceptance["run_id"]),
        source.finished_at, source.scope_reference, cast(str, plan["target_reference"]),
        SYNTHETIC_IMAGE_VERSION, tuple(item.reference for item in records), source.execution)


def SavedPath(value: object) -> PurePosixPath | PureWindowsPath:
    """Interpret an original absolute path lexically for portable historical verification only.

    Args:
        value: Original detached stage/request path string.

    Returns:
        Bounded absolute lexical path; no current path or relocated stage is inspected.
    """

    if not isinstance(value, str) or len(value) > 4096 or not value.isprintable():
        raise ValueError("saved image path is invalid")

    path = PureWindowsPath(value) if "\\" in value else PurePosixPath(value)

    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("saved image path is invalid")

    return path


def DecodeInvocation(value: object) -> AdapterInvocation:
    """Decode the exact original SDK invocation shape without consulting any live producer.

    Args:
        value: Detached operation invocation from a bound capture envelope.

    Returns:
        Typed original invocation whose digest remains the SDK's original wire identity.
    """

    record = WorkspaceFields(value,
        {"adapter_id", "request", "argv", "timeout_seconds", "provider_version"},
        "image invocation")
    request = WorkspaceFields(record["request"],
        {"capability", "target_reference", "impact", "parameters", "credential_references"},
        "image request")

    if request["credential_references"] != []:
        raise ValueError("synthetic image request cannot acquire credentials")

    return AdapterInvocation(cast(str, record["adapter_id"]),
        AdapterRequest(cast(str, request["capability"]), cast(str, request["target_reference"]),
            ImpactLevel(cast(str, request["impact"])),
            cast(dict[str, object], request["parameters"])),
        tuple(cast(list[str], record["argv"])), cast(int, record["timeout_seconds"]),
        cast(str, record["provider_version"]))


def VerifyCapture(envelope: dict[str, object], stdout: bytes, stderr: bytes,
                  operation: str) -> tuple[dict[str, object], dict[str, object], AdapterInvocation]:
    """Verify original request/stage hashes, fixed operation wire and saved execution receipt.

    Args:
        envelope: Strict bounded original capture JSON from immutable evidence.
        stdout: Original operation stdout, independently byte-verified.
        stderr: Original operation stderr, independently byte-verified.
        operation: Fixed expected version or scan phase, never inferred from output.

    Returns:
        Original bound plan, stage payload and typed invocation; no current authority is acquired.
    """

    record = WorkspaceFields(envelope, {"schema_version", "artifact_metadata", "prepared_payload",
        "stage_payload", "collection_started_at", "collection_finished_at"}, "image capture")

    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise ValueError("image capture schema is unsupported")

    metadata = WorkspaceFields(record["artifact_metadata"],
        {"schema_version", "grant", "acceptance", "manifests", "raw_facts"}, "image metadata")

    if type(metadata["schema_version"]) is not int or metadata["schema_version"] != 2:
        raise ValueError("synthetic image requires original operation-aware metadata")

    receipt = VerifyArtifactReplay(metadata, stdout, stderr)

    if receipt.refusal is not None:
        raise ValueError("synthetic image original acceptance was refused")

    grant = WorkspaceFields(metadata["grant"],
        {"plan", "authorization", "issued_at", "valid_until"}, "image grant")
    plan = cast(dict[str, object], grant["plan"])
    prepared = WorkspaceFields(record["prepared_payload"], {
        "workspace_root", "stage_lease", "invocation", "capability", "workspace", "environment",
        "resources", "operation", "producer_family",
        "version_run_id", "version_grant_id", "version_prerequisite_sha256",
    }, "image prepared payload")
    stage = WorkspaceFields(record["stage_payload"], {
        "root", "lease", "root_identity", "executable", "executable_identity", "version",
        "partitions",
    }, "image stage payload")

    if any(plan.get(key) != expected or prepared.get(key) != expected for key, expected in (
        ("operation", operation), ("producer_family", SYNTHETIC_IMAGE_FAMILY),
    )) or plan.get("profile") != ArtifactProfile.SYNTHETIC_IMAGE.value or (
        plan.get("provider_version") != SYNTHETIC_IMAGE_VERSION
        or stage["version"] != SYNTHETIC_IMAGE_VERSION
        or Digest(prepared) != plan.get("request_sha256")
        or Digest(stage) != plan.get("stage_sha256")
        or prepared["stage_lease"] != plan.get("stage_lease")
        or stage["lease"] != plan.get("stage_lease")
        or any(prepared[key] != plan.get(key) for key in (
            "version_run_id", "version_grant_id", "version_prerequisite_sha256"))
    ):
        raise ValueError("image capture binding is inconsistent")

    start = NormalizeEvidenceTime(cast(str, record["collection_started_at"]))
    finish = NormalizeEvidenceTime(cast(str, record["collection_finished_at"]))

    if not (NormalizeEvidenceTime(cast(str, grant["issued_at"])) <= start < finish
            and start <= NormalizeEvidenceTime(receipt.checked_at) <= finish):
        raise ValueError("image capture chronology differs from original execution")

    invocation = DecodeInvocation(prepared["invocation"])
    root = SavedPath(stage["root"])
    workspace = SavedPath(prepared["workspace_root"])
    executable = SavedPath(stage["executable"])

    if not root.is_relative_to(workspace) or str((root / "scratch").relative_to(workspace)) != (
        cast(str, prepared["workspace"]).replace("/", "\\")
        if isinstance(root, PureWindowsPath) else prepared["workspace"]
    ):
        raise ValueError("image capture working directory differs from its original stage")

    prefix = (str(executable), "-I", "-S", str(root / "scanner" / "producer.py"),
        "--fixture-policy", str(root / "material" / "policy.json"),
        "--cache-dir", str(root / "scratch" / "cache"), "--config=")
    timeout = invocation.timeout_seconds

    wire: tuple[str, ...]

    if operation == "version":
        wire = ("--version", "--format", "json")
        limits = (16 * 1024, 16 * 1024)

        if type(timeout) is not int or timeout != 3:
            raise ValueError("image version timeout differs from its closed wire")

    else:
        wire = ("image", "--cache-backend", "memory", "--input", str(root / "input" / "image.tar"),
            "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
            "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
            "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs",
            "--exit-code", "0", "--no-progress", "--timeout", f"{timeout}s")
        limits = (4 * 1024 * 1024, 1024 * 1024)

        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ValueError("image scan timeout differs from its closed wire")

    resources = WorkspaceFields(prepared["resources"],
        {"max_stdout_bytes", "max_stderr_bytes", "terminate_grace_seconds"}, "image resources")
    resource_contract = ExecutionResources(cast(int, resources["max_stdout_bytes"]),
        cast(int, resources["max_stderr_bytes"]), cast(float, resources["terminate_grace_seconds"]))
    capability = WorkspaceFields(prepared["capability"],
        {"identifier", "adapter_id", "maximum_impact", "required_privileges"}, "image capability")

    if invocation.argv != prefix + wire or invocation.adapter_id != SYNTHETIC_IMAGE_SOURCE or (
        invocation.provider_version != SYNTHETIC_IMAGE_VERSION
        or invocation.request.capability != "image.archive-vulnerabilities"
        or invocation.request.impact is not ImpactLevel.SAFE
        or invocation.request.target_reference != plan["target_reference"]
        or InvocationDigest(invocation) != plan["invocation_sha256"]
        or (resources["max_stdout_bytes"], resources["max_stderr_bytes"]) != limits
        or any(type(resources[name]) is not int
               for name in ("max_stdout_bytes", "max_stderr_bytes"))
        or resource_contract.terminate_grace_seconds > 5
        or capability != {"identifier": "image.archive-vulnerabilities",
            "adapter_id": SYNTHETIC_IMAGE_SOURCE, "maximum_impact": "SAFE",
            "required_privileges": []}
    ):
        raise ValueError("image capture invocation differs from its original closed wire")

    environment = WorkspaceFields(prepared["environment"], {
        "PATH", "PATHEXT", "LANG", "LC_ALL", "COMSPEC", "HOME", "USERPROFILE", "TMP", "TEMP",
        "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SYSTEMROOT", "WINDIR",
    }, "image controlled environment")
    fixed_environment = {"PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C", "COMSPEC": "",
        "HOME": str(root / "scratch" / "home"), "USERPROFILE": str(root / "scratch" / "home"),
        "TMP": str(root / "scratch" / "temp"), "TEMP": str(root / "scratch" / "temp"),
        "TMPDIR": str(root / "scratch" / "temp"),
        "XDG_CONFIG_HOME": str(root / "scratch" / "config"),
        "XDG_CACHE_HOME": str(root / "scratch" / "cache")}

    if any(environment[key] != value for key, value in fixed_environment.items()) or any(
        not isinstance(environment[key], str) or len(cast(str, environment[key])) > 4096
        for key in ("SYSTEMROOT", "WINDIR")
    ):
        raise ValueError("image capture environment differs from its original controlled stage")

    manifests = tuple(ArtifactManifest.FromDict(item)
                      for item in cast(list[object], metadata["manifests"]))
    VerifySavedStageShape(stage, manifests)

    files = [{item.name: item for item in manifest.files} for manifest in manifests]

    if tuple(manifest.role for manifest in manifests) != (
        ArtifactRole.INPUT, ArtifactRole.SCANNER, ArtifactRole.MATERIAL
    ) or tuple(set(items) for items in files) != (
        {"image.tar"}, {"executable", "producer.py"}, {"policy.json"}
    ) or files[0]["image.tar"].size_bytes > 128 * 1024 or (
        files[1]["producer.py"].sha256 != SYNTHETIC_IMAGE_WORKER_SHA256
        or files[2]["policy.json"].size_bytes > 512
    ):
        raise ValueError("image capture selected bytes differ from the closed family")

    facts = cast(dict[str, object], metadata["raw_facts"])
    execution = cast(dict[str, object], facts["execution"])

    if execution["state"] != ExecutionState.SUCCEEDED.value or execution["exit_code"] != 0 or (
        facts["termination"] != ExecutionTermination.PROCESS_EXIT.value
    ):
        raise ValueError("image capture original process did not succeed")

    return plan, stage, invocation


def VerifySavedStageShape(stage: dict[str, object],
                          manifests: tuple[ArtifactManifest, ...]) -> None:
    """Validate exact saved physical/read-consent field types without touching an original stage.

    Args:
        stage: Original detached stage payload whose complete digest was already checked.
        manifests: SDK-verified original input/scanner/material content manifests.

    Raises:
        ValueError: Saved shape, selected names/lengths or typed physical/read-consent facts differ.
    """

    FreezePhysicalIdentity(stage["root_identity"], 2)
    executable_identity = FreezePhysicalIdentity(stage["executable_identity"], 5)
    partitions = stage["partitions"]

    if not isinstance(partitions, list) or len(partitions) != 3:
        raise ValueError("image capture requires exact original role partitions")

    for partition, manifest in zip(partitions, manifests, strict=True):
        record = WorkspaceFields(partition,
            {"manifest", "consent", "identities", "directory_identity"}, "image partition")
        consent = WorkspaceFields(record["consent"], {"actor_ref", "record_ref"},
            "image read consent")
        ArtifactReadConsent(cast(str, consent["actor_ref"]), cast(str, consent["record_ref"]))
        FreezePhysicalIdentity(record["directory_identity"], 2)
        identities = record["identities"]

        if record["manifest"] != manifest.ToDict() or not isinstance(identities, list) or (
            len(identities) != len(manifest.files)
        ):
            raise ValueError("image capture partitions differ from original selected manifests")

        for item, file in zip(identities, manifest.files, strict=True):
            if not isinstance(item, list) or len(item) != 2 or item[0] != file.name or (
                FreezePhysicalIdentity(item[1], 5)[2] != file.size_bytes
            ):
                raise ValueError("image capture physical observations differ from selected bytes")

            if manifest.role is ArtifactRole.SCANNER and file.name == "executable" and (
                executable_identity[2] != file.size_bytes
            ):
                raise ValueError("image capture selected runtime length differs from scanner bytes")


def VerifySavedSyntheticImagePair(state: ModelState, provenance: ModelProvenance,
                                  records: tuple[EvidenceRecord, ...],
                                  workspace_root: Path) -> VerifiedImagePair:
    """Verify original saved six-role facts read-only, without current stage/grant/model mutation.

    Args:
        state: Existing owning model snapshot, including any retained operator triage.
        provenance: Exact SCAN interpretation attribution linked to all six original records.
        records: Original immutable operation stream and receipt acquisition manifests.
        workspace_root: Current owning workspace whose evidence may have been relocated.

    Returns:
        Verified raw wire and original envelopes; historical verification grants no new authority.

    Raises:
        ValueError: Schema, hashes, raw attribution, chronology or original pairing differs.
    """

    try:
        return VerifySavedPair(state, provenance, records, workspace_root)

    except (EvidenceError, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("synthetic image evidence verification refused") from None


def VerifySavedPair(state: ModelState, provenance: ModelProvenance,
                    records: tuple[EvidenceRecord, ...], workspace_root: Path) -> VerifiedImagePair:
    """Perform the internal read-only verification behind the sanitized public evidence boundary.

    Args:
        state: Typed existing snapshot.
        provenance: Original synthetic SCAN interpretation.
        records: Finite six-role original acquisition manifests.
        workspace_root: Owning current immutable evidence store.

    Returns:
        Original fully verified synthetic wire and operation capture envelopes.
    """

    if not isinstance(state, ModelState) or not isinstance(provenance, ModelProvenance) or (
        not isinstance(records, tuple) or len(records) != 6
        or any(not isinstance(item, EvidenceRecord) for item in records)
        or {item.reference.role for item in records} != set(_ROLE_BOUNDS)
        or LocalWorkspaceStore(workspace_root).Open().workspace_id != state.workspace_id
        or provenance.source_id != SYNTHETIC_IMAGE_SOURCE
        or provenance.provider_version != SYNTHETIC_IMAGE_VERSION
        or provenance.evidence_references != tuple(sorted(
            (item.reference for item in records), key=CanonicalModelJson))
    ):
        raise ValueError("image evidence requires exact original workspace and roles")

    store = ImageEvidenceStore(workspace_root / "evidence")
    raw = {}
    by_role = {item.reference.role: item for item in records}

    for role, record in by_role.items():
        if record.reference.size_bytes > _ROLE_BOUNDS[role] or (
            store.Get(record.evidence_id) != record
        ):
            raise ValueError("image evidence differs from its bounded immutable acquisition")

        raw[role] = store.Read(record.reference)

        if record.reference.media_type == "application/json" and raw[role].startswith(
            b"\xef\xbb\xbf"
        ):
            raise ValueError("synthetic image JSON requires strict UTF-8 without a BOM")

    version_envelope = ParseJson(raw["artifact-version-receipt"], IMAGE_RECEIPT_MAX_BYTES)
    scan_envelope = ParseJson(raw["artifact-scan-receipt"], IMAGE_RECEIPT_MAX_BYTES)
    version_plan, version_stage, version_invocation = VerifyCapture(
        version_envelope, raw["provider-version"], raw["provider-version-stderr"], "version")
    scan_plan, scan_stage, scan_invocation = VerifyCapture(
        scan_envelope, raw["stdout"], raw["stderr"], "scan")

    for key in ("owner_ref", "profile", "provider_version", "workspace_id", "scope_reference",
                "scope_revision", "scope_sha256", "policy_reference", "policy_revision",
                "policy_sha256", "target_reference", "input_manifest_sha256",
                "scanner_manifest_sha256", "material_manifest_sha256", "producer_family",
                "granted_privileges"):
        if version_plan[key] != scan_plan[key]:
            raise ValueError("image pair original authority or selected bytes differ")

    for key in ("root", "lease", "root_identity"):
        if version_stage[key] == scan_stage[key]:
            raise ValueError("image operations reused a physical stage")

    for key in ("executable", "executable_identity", "version"):
        if version_stage[key] != scan_stage[key]:
            raise ValueError("image operations used different selected runtimes")

    version_partitions = cast(list[dict[str, object]], version_stage["partitions"])
    scan_partitions = cast(list[dict[str, object]], scan_stage["partitions"])

    if any(left["consent"] != right["consent"] for left, right in zip(
        version_partitions, scan_partitions, strict=True
    )):
        raise ValueError("image operations used different selected-byte read authority")

    version_metadata = cast(dict[str, object], version_envelope["artifact_metadata"])
    scan_metadata = cast(dict[str, object], scan_envelope["artifact_metadata"])
    version_receipt = cast(dict[str, object], version_metadata["acceptance"])
    scan_receipt = cast(dict[str, object], scan_metadata["acceptance"])
    scan_grant = cast(dict[str, object], scan_metadata["grant"])

    if any(version_plan[key] is not None for key in (
        "version_run_id", "version_grant_id", "version_prerequisite_sha256"
    )) or scan_plan["version_run_id"] != version_receipt["run_id"] or (
        scan_plan["version_grant_id"] != version_receipt["grant_id"]
        or scan_plan["version_prerequisite_sha256"] != Digest({
            "artifact_metadata": version_metadata,
            "prepared_payload": version_envelope["prepared_payload"],
            "stage_payload": version_envelope["stage_payload"],
        })
        or any(cast(dict[str, object], scan_envelope["prepared_payload"])[key] != scan_plan[key]
               for key in ("version_run_id", "version_grant_id", "version_prerequisite_sha256"))
    ):
        raise ValueError("image SCAN lost or replaced its exact original VERSION prerequisite")

    if version_receipt["run_id"] == scan_receipt["run_id"] or (
        version_receipt["grant_id"] == scan_receipt["grant_id"]
        or provenance.run_reference != scan_receipt["run_id"]
        or NormalizeEvidenceTime(cast(str, version_envelope["collection_finished_at"])) >
            NormalizeEvidenceTime(cast(str, scan_envelope["collection_started_at"]))
        or NormalizeEvidenceTime(cast(str, version_envelope["collection_finished_at"])) >
            NormalizeEvidenceTime(cast(str, scan_grant["issued_at"]))
        or provenance.observed_at != NormalizeEvidenceTime(
            cast(str, scan_envelope["collection_finished_at"]))
        or provenance.scope_reference != scan_plan["scope_reference"]
        or provenance.target_reference != scan_plan["target_reference"]
        or state.workspace_id != scan_plan["workspace_id"]
    ):
        raise ValueError("image pair original run or collection chronology differs")

    for roles, envelope, invocation in (
        (("provider-version", "provider-version-stderr", "artifact-version-receipt"),
            version_envelope, version_invocation),
        (("stdout", "stderr", "artifact-scan-receipt"), scan_envelope, scan_invocation),
    ):
        metadata = cast(dict[str, object], envelope["artifact_metadata"])
        facts = cast(dict[str, object], metadata["raw_facts"])

        for role in roles:
            source = by_role[role].provenance
            expected_media = "text/plain" if role in {"stderr", "provider-version-stderr"} else (
                "application/json"
            )

            if by_role[role].reference.media_type != expected_media or (
                source.workspace_id, source.scope_reference, source.source_id,
                source.source_version, source.tool_version, source.started_at,
                source.finished_at, source.invocation_sha256
            ) != (state.workspace_id, provenance.scope_reference, SYNTHETIC_IMAGE_SOURCE, "1",
                SYNTHETIC_IMAGE_VERSION,
                NormalizeEvidenceTime(cast(str, envelope["collection_started_at"])),
                NormalizeEvidenceTime(cast(str, envelope["collection_finished_at"])),
                InvocationDigest(invocation)) or Detached(source.ToDict())["execution"] != (
                    facts["execution"]
                ):
                raise ValueError("image record attribution differs from original operation facts")

    if provenance.execution is None or Detached(scan_metadata["raw_facts"])["execution"] != (
        Detached({"execution": provenance.execution})["execution"]
    ):
        raise ValueError("image interpretation execution differs from original SCAN")

    version = ParseJson(raw["provider-version"], 16 * 1024)
    WorkspaceFields(version, {"Version", "VulnerabilityDB", "Fixture"}, "image version")
    database = WorkspaceFields(version["VulnerabilityDB"], set(_DATABASE), "image database")

    if version["Version"] != SYNTHETIC_IMAGE_VERSION or database != _DATABASE or (
        type(database["Version"]) is not int
        or version["Fixture"] != "synthetic; no Trivy binary or vulnerability database"
    ):
        raise ValueError("image version differs from independently observed supported wire")

    payload = ParseJson(raw["stdout"], 4 * 1024 * 1024)

    return VerifiedImagePair(payload, version, database, version_envelope, scan_envelope)
