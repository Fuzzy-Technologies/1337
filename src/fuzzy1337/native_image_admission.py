# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verified original native Trivy pair replay and canonical in-memory image admission."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
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
from fuzzy1337.adapters.trivy import ParseJson, RelativePath
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import (
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    NormalizeEvidenceTime,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.images import ApplyBatch, Digest, ImageIdentity, Record, Text, TrivyCandidates
from fuzzy1337.model import ModelDelta, ModelProvenance, ModelState
from fuzzy1337.native_image_capture import NativeTrivyOperation, NativeTrivyOperationCapture
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceFields

NATIVE_IMAGE_CONTRACT_VERSION = 1
_ROLE_LIMITS = {
    "provider-version": (16 * 1024, "application/json"),
    "provider-version-stderr": (16 * 1024, "text/plain"),
    "native-version-receipt": (256 * 1024, "application/json"),
    "stdout": (4 * 1024 * 1024, "application/json"),
    "stderr": (1024 * 1024, "text/plain"),
    "native-scan-receipt": (16 * 1024 * 1024, "application/json"),
}
_REFUSALS = {None, "material-changed", "execution-not-successful",
             "material-or-version-unverified", "authority-unverified"}

__all__ = [
    "NATIVE_IMAGE_CONTRACT_VERSION", "NativeImageReplay",
    "VerifyNativeTrivyImageReplay", "ApplyVerifiedNativeTrivyImages",
]


@dataclass(frozen=True, slots=True)
class NativeImageReplay:
    """Verified original pair facts; recorded decisions grant no current authority."""

    workspace_id: str
    owner_reference: str
    version_request: LocalExecutionRequest
    scan_request: LocalExecutionRequest
    version_execution: AdapterExecution
    scan_execution: AdapterExecution
    scan_termination: ExecutionTermination
    scan_refusal: str | None
    version_prerequisite_sha256: str
    provenance: ModelProvenance
    records: tuple[EvidenceRecord, ...]


@dataclass(frozen=True, slots=True)
class Operation:
    """Internal detached original capture with fully reconstructed SDK request and outcome."""

    envelope: dict[str, Any]
    request: LocalExecutionRequest
    outcome: LocalExecutionResult
    receipt_sha256: str


class NativeEvidenceStore(LocalEvidenceStore):
    """Apply role budgets to actual owning manifests before the evidence owner's eager read."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Reopen bounded original bytes through the canonical integrity boundary.

        Args:
            reference: Actual store-owned reference or explicit caller reference.

        Returns:
            Unchanged bytes after role, size, media and content-address verification.

        Raises:
            ValueError: Actual role, media type or byte budget differs from this consumer.
            EvidenceError: Original evidence bytes cannot be verified.
        """

        CheckReference(reference)

        return super().Read(reference)


def CheckReference(reference: EvidenceReference) -> None:
    """Check one original reference's finite role budget before any raw allocation.

    Args:
        reference: Exact typed original source reference.

    Raises:
        ValueError: Role, media or size differs from this consumer's bounded family.
    """

    if type(reference) is not EvidenceReference or reference.role not in _ROLE_LIMITS:
        raise ValueError("native admission requires its bounded original evidence roles")

    limit, media = _ROLE_LIMITS[reference.role]

    if type(reference.size_bytes) is not int or not 0 <= reference.size_bytes <= limit or (
        reference.media_type != media
    ):
        raise ValueError("native admission evidence exceeds its role budget")


def Fields(value: object, expected: set[str]) -> dict[str, Any]:
    """Require exact consumer-owned fields without defaults or ignored extensions.

    Args:
        value: Bounded detached receipt object.
        expected: Complete field-name set.

    Returns:
        Validated dictionary with values checked by the owning field consumers.
    """

    return cast(dict[str, Any], WorkspaceFields(value, expected, "native image receipt"))


def Detached(value: object) -> dict[str, Any]:
    """Compare typed producer facts through the producer's canonical serializer.

    Args:
        value: Original typed SDK or evidence value.

    Returns:
        Detached original dictionary without invoking source-selected serialization.
    """

    return cast(dict[str, Any], json.loads(SerializeContract(value)))


def OriginalPath(value: object) -> PurePath:
    """Validate original absolute path syntax without opening historical material.

    Args:
        value: Original receipt's explicit POSIX or Windows path.

    Returns:
        Original platform path for deterministic argv and selected-file comparisons.
    """

    text = Text(value)
    path = PureWindowsPath(text) if "\\" in text or re.match(r"[A-Za-z]:", text) else (
        PurePosixPath(text))

    if not path.is_absolute() or ".." in path.parts or str(path) != text:
        raise ValueError("native receipt requires canonical original absolute paths")

    return path


def Request(value: object, selection: dict[str, Any], operation: str,
            observed: str | None) -> LocalExecutionRequest:
    """Reconstruct the exact finite producer profile without launching or reading old paths.

    Args:
        value: Original detached executor request.
        selection: Original explicit physical selection syntax.
        operation: Exact version or scan profile.
        observed: Separately observed version; VERSION invocation remains unknown-version.

    Returns:
        Original SDK request after independent finite-profile and digest verification.
    """

    payload = Fields(value, {"invocation", "capability", "authorization", "workspace",
                             "environment", "resources"})
    invocation = Fields(payload["invocation"], {
        "adapter_id", "request", "argv", "timeout_seconds", "provider_version"})
    requested = Fields(invocation["request"], {
        "capability", "target_reference", "impact", "parameters", "credential_references"})
    parameters = Fields(requested["parameters"], {"archive", "timeout_seconds"})
    timeout = parameters["timeout_seconds"]

    if requested["credential_references"] != [] or type(timeout) is not int or not (
        timeout == 3 if operation == "version" else 1 <= timeout <= 3600
    ) or parameters["archive"] != selection["archive"]:
        raise ValueError("native receipt requires the exact finite archive request")

    requested["impact"] = ImpactLevel(requested["impact"])
    request = AdapterRequest(**requested)
    root = OriginalPath(selection["workspace_root"])
    executable = str(OriginalPath(selection["executable"]))
    cache = str(root / RelativePath(selection["cache_directory"]))
    archive = str(root / RelativePath(selection["archive"]))
    prefix = (executable, "--cache-dir", cache, "--config=")
    arguments = prefix + (("--version", "--format", "json") if operation == "version" else (
        "image", "--input", archive, "--format", "json", "--scanners", "vuln",
        "--disable-telemetry", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
        "--skip-check-update", "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=",
        "--list-all-pkgs", "--exit-code", "0", "--no-progress", "--timeout", f"{timeout}s"))
    expected = AdapterInvocation("native.trivy", request, arguments, timeout,
                                 None if operation == "version" else observed)

    if request.capability != "image.archive-vulnerabilities" or request.impact is not (
        ImpactLevel.SAFE
    ) or Detached(expected) != invocation:
        raise ValueError("native receipt differs from its original exact adapter invocation")

    capability = Fields(payload["capability"], {
        "identifier", "adapter_id", "maximum_impact", "required_privileges"})
    authorization = Fields(payload["authorization"], {
        "authorization_id", "scope_reference", "policy_reference", "invocation_sha256",
        "granted_privileges"})

    if capability != {"identifier": request.capability, "adapter_id": "native.trivy",
        "maximum_impact": "SAFE", "required_privileges": []} or (
        authorization["granted_privileges"] != []
    ):
        raise ValueError("native receipt cannot add capabilities or privileges")

    capability["maximum_impact"] = ImpactLevel(capability["maximum_impact"])
    resources = ExecutionResources(**Fields(payload["resources"], {
        "max_stdout_bytes", "max_stderr_bytes", "terminate_grace_seconds"}))
    expected_resources = ExecutionResources(max_stdout_bytes=16 * 1024,
        max_stderr_bytes=16 * 1024) if operation == "version" else (
            ExecutionResources(max_stdout_bytes=4 * 1024 * 1024, max_stderr_bytes=1024 * 1024))
    scratch = payload["workspace"]

    if not isinstance(scratch, str) or not re.fullmatch(r"native-image-[A-Za-z0-9_-]+", scratch):
        raise ValueError("native receipt requires its original single-operation scratch")

    scratch_path = str(root / scratch)
    environment = {key: scratch_path for key in
                   ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP")}
    environment.update({"PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"})

    if resources != expected_resources or payload["environment"] != environment:
        raise ValueError("native receipt differs from original finite execution resources")

    return LocalExecutionRequest(expected, CapabilityDescriptor(**capability),
        ExecutionAuthorization(**authorization), scratch, environment, resources)


def Material(value: object, selection: dict[str, Any]) -> None:
    """Check original ordered physical/byte facts without claiming current file availability.

    Args:
        value: Exact four originally observed selected-file facts.
        selection: Original explicit material selection.

    Raises:
        ValueError: Role, path, byte hash, missing-material or physical identity is inconsistent.
    """

    root = OriginalPath(selection["workspace_root"])
    paths = (root / RelativePath(selection["archive"]), OriginalPath(selection["executable"]),
             root / RelativePath(selection["cache_directory"]) / "db" / "trivy.db",
             root / RelativePath(selection["cache_directory"]) / "db" / "metadata.json")
    roles = ("archive", "executable", "database", "database-metadata")
    limits = (512 * 1024 * 1024, 256 * 1024 * 1024, 2 * 1024**3, 16 * 1024)

    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("native receipt requires four ordered selected-file facts")

    for item, path, role, limit in zip(value, paths, roles, limits, strict=True):
        fact = Fields(item, {"role", "path", "size_bytes", "sha256", "physical_identity"})
        size, digest, identity = fact["size_bytes"], fact["sha256"], fact["physical_identity"]

        if fact["role"] != role or fact["path"] != str(path):
            raise ValueError("native receipt material differs from its explicit selected path")

        if size is None and digest is None and identity is None and role.startswith("database"):
            continue

        if type(size) is not int or not 0 <= size <= limit or not isinstance(digest, str) or (
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ) or not isinstance(identity, list) or len(identity) != 5 or any(
            type(part) is not int or part < 0 for part in identity
        ) or identity[1] == 0 or identity[2] != size:
            raise ValueError("native receipt material has invalid byte or physical identity")


def VerifyOperation(records: dict[str, EvidenceRecord], raw: dict[str, bytes],
                    operation: str) -> Operation:
    """Verify an original operation receipt, exact request, event streams and all manifest facts.

    Args:
        records: Original immutable six-role manifests indexed by role.
        raw: Independently verified bytes for the exact original records.
        operation: Version or scan role family.

    Returns:
        Original bounded detached receipt and reconstructed SDK terminal facts.
    """

    roles = ("provider-version", "provider-version-stderr", "native-version-receipt") if (
        operation == "version") else ("stdout", "stderr", "native-scan-receipt")
    envelope = Fields(ParseJson(raw[roles[2]], _ROLE_LIMITS[roles[2]][0]), {
        "schema_version", "operation", "request", "execution", "termination", "events",
        "selection", "workspace_id", "owner_reference", "read_consent", "material_before",
        "material_after", "started_at", "finished_at", "version_prerequisite_sha256",
        "observed_version", "refusal", "streams"})

    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1 or (
        envelope["operation"] != operation or SerializeContract(envelope).encode() != raw[roles[2]]
    ):
        raise ValueError("native receipt requires its original canonical schema-one operation")

    selection = Fields(envelope["selection"], {
        "workspace_root", "executable", "archive", "cache_directory"})
    consent = ArtifactReadConsent(**Fields(envelope["read_consent"], {"actor_ref", "record_ref"}))

    if consent.actor_ref != envelope["owner_reference"] or envelope["refusal"] not in _REFUSALS:
        raise ValueError("native receipt requires its exact owner and original refusal")

    observed = envelope["observed_version"]

    if observed is not None and (not isinstance(observed, str) or
                                re.fullmatch(r"0\.75\.[0-9]+", observed) is None):
        raise ValueError("native receipt observed version is outside the supported envelope")

    request = Request(envelope["request"], selection, operation, observed)
    Material(envelope["material_before"], selection)

    if envelope["material_after"] is not None:
        Material(envelope["material_after"], selection)

    details = Fields(envelope["execution"], {"state", "exit_code", "duration_seconds"})

    if isinstance(details["duration_seconds"], bool):
        raise ValueError("native receipt execution duration cannot be a boolean")

    execution = AdapterExecution(ExecutionState(details["state"]), details["exit_code"],
                                 details["duration_seconds"])
    events = []

    if not isinstance(envelope["events"], list) or len(envelope["events"]) > 16384:
        raise ValueError("native receipt event history exceeds its finite budget")

    for item in envelope["events"]:
        event = Fields(item, {"sequence", "kind", "data_hex", "termination"})
        encoded = event["data_hex"]

        if not isinstance(encoded, str) or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None:
            raise ValueError("native receipt stream event must use canonical hexadecimal bytes")

        events.append(ExecutionEvent(event["sequence"], ExecutionEventKind(event["kind"]),
            bytes.fromhex(encoded), None if event["termination"] is None else (
                ExecutionTermination(event["termination"]))))

    outcome = LocalExecutionResult(execution, ExecutionTermination(envelope["termination"]),
        raw[roles[0]], raw[roles[1]], tuple(events))
    pre_cancelled = (len(events) == 1 and execution.state is ExecutionState.CANCELLED
        and outcome.termination is ExecutionTermination.CANCELLATION
        and execution.exit_code is None and not outcome.stdout and not outcome.stderr)

    if not pre_cancelled and (
        events[0].kind is not ExecutionEventKind.STARTED or len(events) < 2
        or any(event.kind not in {ExecutionEventKind.STDOUT, ExecutionEventKind.STDERR}
               for event in events[1:-1])
    ):
        raise ValueError("native receipt lifecycle differs from original owned executor history")

    allowed_states = {
        ExecutionTermination.PROCESS_EXIT: {ExecutionState.SUCCEEDED, ExecutionState.FAILED},
        ExecutionTermination.TIMEOUT: {ExecutionState.TIMED_OUT},
        ExecutionTermination.CANCELLATION: {ExecutionState.CANCELLED},
        ExecutionTermination.OUTPUT_LIMIT: {ExecutionState.CANCELLED},
    }

    if execution.state not in allowed_states[outcome.termination]:
        raise ValueError("native receipt termination contradicts original executor state")

    for role, kind in zip(roles[:2], (ExecutionEventKind.STDOUT, ExecutionEventKind.STDERR),
                          strict=True):
        if b"".join(event.data for event in events if event.kind is kind) != raw[role]:
            raise ValueError("native receipt event history differs from original retained streams")

    started, finished = (NormalizeEvidenceTime(envelope[name]) for name in
                         ("started_at", "finished_at"))
    source = EvidenceProvenance(envelope["workspace_id"], request.authorization.scope_reference,
        "native.trivy", "1", observed, started, finished, InvocationDigest(request.invocation),
        execution)

    if started != envelope["started_at"] or finished != envelope["finished_at"] or (
        envelope["streams"] != [Detached(records[role]) for role in roles[:2]]
    ) or any(records[role].provenance != source for role in roles):
        raise ValueError("native receipt differs from original immutable acquisition attribution")

    if envelope["refusal"] is None and (
        execution.state is not ExecutionState.SUCCEEDED
        or outcome.termination is not ExecutionTermination.PROCESS_EXIT
        or envelope["material_before"] != envelope["material_after"]
        or observed is None
        or any(fact["sha256"] is None for fact in envelope["material_before"])
    ):
        raise ValueError("native accepted receipt contradicts original terminal/material facts")

    return Operation(envelope, request, outcome, hashlib.sha256(raw[roles[2]]).hexdigest())


def VerifyRecords(records: tuple[EvidenceRecord, ...], workspace_root: Path
                  ) -> tuple[NativeImageReplay, Operation, Operation]:
    """Verify store ownership and original pair relationships before interpreting any report.

    Args:
        records: Exact six distinct immutable original role manifests.
        workspace_root: Existing or relocated workspace owning the evidence store.

    Returns:
        Descriptive replay facts and original detached VERSION and SCAN operations.
    """

    if not isinstance(records, tuple) or len(records) != 6 or any(
        type(record) is not EvidenceRecord for record in records
    ):
        raise ValueError("native admission requires six original typed evidence records")

    by_role = {record.reference.role: record for record in records}

    if set(by_role) != set(_ROLE_LIMITS):
        raise ValueError("native admission requires its exact six distinct original roles")

    for record in records:
        CheckReference(record.reference)

    workspace = LocalWorkspaceStore(workspace_root)
    workspace_id = workspace.Open().workspace_id
    store = NativeEvidenceStore(workspace.root / "evidence")
    raw = {}

    for role, record in by_role.items():
        store.Read(record.reference)

        if record.provenance.workspace_id != workspace_id or (
            store.Get(record.evidence_id) != record
        ):
            raise ValueError("native source differs from its original owning manifest")

        raw[role] = store.Read(record.reference)

    try:
        version = VerifyOperation(by_role, raw, "version")
        scan = VerifyOperation(by_role, raw, "scan")
        version_envelope, scan_envelope = version.envelope, scan.envelope
        same_fields = ("selection", "workspace_id", "owner_reference", "read_consent",
                       "material_before", "observed_version")

        if version_envelope["refusal"] is not None or any(
            version_envelope[name] != scan_envelope[name] for name in same_fields
        ) or version_envelope["version_prerequisite_sha256"] is not None or (
            scan_envelope["version_prerequisite_sha256"] != version.receipt_sha256
            or version_envelope["finished_at"] > scan_envelope["started_at"]
            or version.request.invocation.request.target_reference != (
                scan.request.invocation.request.target_reference)
            or version.request.workspace == scan.request.workspace
            or version.request.authorization.authorization_id == (
                scan.request.authorization.authorization_id)
            or version.request.authorization.scope_reference != (
                scan.request.authorization.scope_reference)
            or version.request.authorization.policy_reference != (
                scan.request.authorization.policy_reference)
        ):
            raise ValueError("native captures do not form their exact original executed pair")

        wire = ParseJson(raw["provider-version"], 16 * 1024)
        database = Record(wire.get("VulnerabilityDB"))

        if wire.get("Version") != version_envelope["observed_version"] or (
            type(database.get("Version")) is not int or database["Version"] != 2
        ):
            raise ValueError("native pair differs from its original observed version/database")

        NormalizeEvidenceTime(Text(database.get("UpdatedAt")))
        provenance = ModelProvenance("native.trivy", "native-scan:" + scan.receipt_sha256,
            scan_envelope["finished_at"], scan.request.authorization.scope_reference,
            scan.request.invocation.request.target_reference, scan_envelope["observed_version"],
            tuple(record.reference for record in records), scan.outcome.execution)

    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("native original receipt or pair facts are inconsistent") from None

    replay = NativeImageReplay(workspace_id, scan_envelope["owner_reference"], version.request,
        scan.request, version.outcome.execution, scan.outcome.execution, scan.outcome.termination,
        scan_envelope["refusal"], version.receipt_sha256, provenance,
        tuple(sorted(records, key=lambda record: record.reference.role)))

    return replay, version, scan


def VerifyNativeTrivyImageReplay(records: tuple[EvidenceRecord, ...],
                                 workspace_root: Path) -> NativeImageReplay:
    """Verify saved original executed-pair facts without launching or opening historical material.

    Args:
        records: Six original immutable source manifests, including both execution receipts.
        workspace_root: Existing or relocated owning workspace retaining canonical evidence.

    Returns:
        Original version/scan requests and terminal facts, including refused or failed SCAN.
        These descriptive facts establish neither current authorization nor publisher authenticity.

    Raises:
        ValueError: Original request, attribution, pair, time or bounded JSON is inconsistent.
        EvidenceError: Original manifests or raw bytes fail evidence integrity checks.
        OSError: Owning workspace metadata or evidence cannot be read.
    """

    return VerifyRecords(records, workspace_root)[0]


def ApplyVerifiedNativeTrivyImages(state: ModelState, version: NativeTrivyOperationCapture,
                                   scan: NativeTrivyOperationCapture,
                                   workspace_root: Path, *,
                                   expected_image_identity: ImageIdentity | None = None,
                                   ) -> tuple[ModelState, ModelDelta]:
    """Admit original successful native captures into the existing canonical model in memory.

    Args:
        state: Original immutable canonical model snapshot owned by this workspace.
        version: Original independently executed VERSION capture; never a legacy health probe.
        scan: Original SCAN bound to that exact VERSION, material, owner, scope and policy.
        workspace_root: Owning workspace retaining all six immutable original evidence records.
        expected_image_identity: Optional exact config identity selected before workflow approval.

    Returns:
        One canonical image/package/Finding transition with existing triage retained.
        The caller owns the separate model CAS save and workspace reference persistence.

    Raises:
        ValueError: Original typed captures, records, successful custody or package wire disagree.
        EvidenceError: Original immutable manifests or raw bytes cannot be verified.
        OSError: Owning workspace metadata or evidence cannot be read.
    """

    if type(state) is not ModelState or type(version) is not NativeTrivyOperationCapture or (
        type(scan) is not NativeTrivyOperationCapture
        or version.operation is not NativeTrivyOperation.VERSION
        or scan.operation is not NativeTrivyOperation.SCAN
    ):
        raise ValueError("native admission requires the original typed VERSION/SCAN and model")

    if expected_image_identity is not None and (
        type(expected_image_identity) is not ImageIdentity
        or expected_image_identity.digest_kind != "config"
    ):
        raise ValueError("native admission expected image must be an exact config identity")

    facts, original_version, original_scan = VerifyRecords((*version.records, *scan.records),
                                                          workspace_root)

    for capture, original in ((version, original_version), (scan, original_scan)):
        if capture.Envelope() != original.envelope or capture.request != original.request or (
            capture.outcome != original.outcome
        ):
            raise ValueError("native admission original capture differs from retained receipt")

    if state.workspace_id != facts.workspace_id or facts.scan_refusal is not None:
        raise ValueError("native admission requires original successful same-workspace custody")

    store = NativeEvidenceStore(LocalWorkspaceStore(workspace_root).root / "evidence")
    raw = {record.reference.role: store.Read(record.reference) for record in facts.records}
    wire = ParseJson(raw["provider-version"], 16 * 1024)
    payload = ParseJson(raw["stdout"], 4 * 1024 * 1024)
    if expected_image_identity is not None and ImageIdentity(
        Digest(Record(payload.get("Metadata")).get("ImageID"))
    ) != expected_image_identity:
        raise ValueError("native admission report differs from the selected image config identity")

    objects, relations, observations, findings = TrivyCandidates(state.workspace_id, payload,
        wire, Record(wire["VulnerabilityDB"]), facts.provenance)

    return ApplyBatch(state, objects, relations, observations, findings, workspace_root)
