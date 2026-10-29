# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Domain-separated original native configuration authority and persistent single-use claims."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import (
    ArtifactHandleInfo,
    ArtifactManifest,
    ArtifactPathInfo,
    MatchesArtifactReadIdentity,
    PhysicalIdentity,
)
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
)
from fuzzy1337.model import ModelAttributes
from fuzzy1337.native_configuration import (
    NativeConfigurationScanRecipe,
    NativeConfigurationSelection,
    PrepareNativeConfigurationVersion,
)
from fuzzy1337.native_configuration_material import (
    NativeConfigurationMaterialObserver,
    NativeConfigurationMaterialProof,
)
from fuzzy1337.native_configuration_material_worker import SelectionPayload, StagePayload
from fuzzy1337.native_configuration_report import (
    MAX_CONFIGURATION_STDERR_BYTES,
    MAX_CONFIGURATION_STDOUT_BYTES,
    NATIVE_CONFIGURATION_FAMILY,
)
from fuzzy1337.policy import Digest, RequireTime
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore

if TYPE_CHECKING:
    from fuzzy1337.native_configuration_capture import NativeConfigurationOperationCapture

CONTROL_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class PreparedNativeConfigurationOperation:
    """One fixed recipe with stable original material metadata and no process permission."""

    operation_id: str
    operation: str
    selection: NativeConfigurationSelection
    workspace_root: Path
    workspace_id: str
    owner_reference: str
    operation_reference: str
    input_manifest: ArtifactManifest
    stage_metadata: Mapping[str, object]
    invocation: AdapterInvocation
    scratch: Path
    resources: ExecutionResources
    version_prerequisite: NativeConfigurationVersionPrerequisite | None = None

    def __post_init__(self) -> None:
        """Freeze bounded stage metadata so receipt digests cannot retain caller-mutated aliases."""

        object.__setattr__(self, "stage_metadata", ModelAttributes(self.stage_metadata))

    def Payload(self) -> dict[str, object]:
        """Project finite metadata without serializing live engines or original proof handles.

        Returns:
            Domain-separated exact recipe and original VERSION digest where required.
        """

        return {"schema_version": 1, "family": NATIVE_CONFIGURATION_FAMILY,
            "operation_id": self.operation_id, "operation": self.operation,
            "selection": SelectionPayload(self.selection),
            "workspace_root": str(self.workspace_root), "workspace_id": self.workspace_id,
            "owner_reference": self.owner_reference,
            "operation_reference": self.operation_reference,
            "input_manifest": self.input_manifest.ToDict(), "stage_metadata": self.stage_metadata,
            "invocation": self.invocation, "scratch": str(self.scratch),
            "resources": self.resources, "version_prerequisite_sha256": None if
            self.version_prerequisite is None else self.version_prerequisite.Digest()}


@dataclass(frozen=True, slots=True)
class NativeConfigurationOperationPlan:
    """Current descriptive native authority, independent of image or synthetic plan schemas."""

    operation_id: str
    operation: str
    operation_reference: str
    workspace_id: str
    owner_reference: str
    scope_reference: str
    scope_revision: int
    scope_sha256: str
    policy_reference: str
    policy_revision: int
    policy_sha256: str
    target_reference: str
    input_manifest_sha256: str
    request_sha256: str
    invocation_sha256: str
    material_sha256: str
    version_prerequisite_sha256: str | None
    family: str = NATIVE_CONFIGURATION_FAMILY


@dataclass(frozen=True, slots=True)
class NativeConfigurationOperationGrant:
    """Original issuing-engine authority with explicit SAFE workflow approval."""

    plan: NativeConfigurationOperationPlan
    authorization: ExecutionAuthorization
    issued_at: str
    valid_until: str
    approve_safe_configuration: bool


class NativeConfigurationExecutionClaim:
    """Opaque original issuer handle; reconstruction or copying supplies no execution permission."""

    __slots__ = ()

    def __new__(cls) -> NativeConfigurationExecutionClaim:
        """Refuse caller construction of an original execution claim.

        Raises:
            ValueError: Claims may only be issued by successful exclusive reservation.
        """

        raise ValueError("Native configuration claims require their original issuing engine")


@dataclass(frozen=True, slots=True)
class NativeConfigurationVersionPrerequisite:
    """Original accepted VERSION object, retained only by its exact issuing engine."""

    prepared: PreparedNativeConfigurationOperation
    grant: NativeConfigurationOperationGrant
    claim: NativeConfigurationExecutionClaim
    capture: NativeConfigurationOperationCapture

    def Digest(self) -> str:
        """Bind original VERSION authority and capture without granting replay authority.

        Returns:
            Canonical SHA256 of the original finite VERSION association.
        """

        return Digest({"family": NATIVE_CONFIGURATION_FAMILY,
            "prepared": self.prepared.Payload(), "grant": self.grant,
            "capture_sha256": self.capture.Digest()})


@dataclass(slots=True)
class ConfigurationClaimState:
    """Strong original references and physically bound immutable reservation/request files."""

    prepared: PreparedNativeConfigurationOperation
    grant: NativeConfigurationOperationGrant
    observer: NativeConfigurationMaterialObserver
    proof: NativeConfigurationMaterialProof
    controls: tuple[tuple[Path, bytes, tuple[int, ...]], ...]
    directories: tuple[tuple[Path, tuple[int, int]], ...]
    request: LocalExecutionRequest | None = None
    capture: NativeConfigurationOperationCapture | None = None
    prerequisite: NativeConfigurationVersionPrerequisite | None = None
    launched: bool = False
    cleaned_scratch: Path | None = None


@dataclass(slots=True)
class ConfigurationEngineState:
    """Engine-local original object maps, separate from every existing artifact family."""

    grants: dict[str, tuple[NativeConfigurationOperationGrant,
                           NativeConfigurationMaterialObserver]] = field(default_factory=dict)
    claims: dict[NativeConfigurationExecutionClaim, ConfigurationClaimState] = field(
        default_factory=dict)


def EngineState(engine: ArtifactPolicyEngine) -> ConfigurationEngineState:
    """Require the canonical owner and retain separate strong original-object state.

    Args:
        engine: Exact canonical artifact policy engine instance.

    Returns:
        Private configuration-domain state for that one engine.
    """

    if type(engine) is not ArtifactPolicyEngine:
        raise ValueError("Native configuration requires its canonical artifact policy engine")

    state = getattr(engine, "_native_configuration_authority", None)

    if state is None:
        state = ConfigurationEngineState()
        setattr(engine, "_native_configuration_authority", state)

    if type(state) is not ConfigurationEngineState:
        raise ValueError("Native configuration original engine state differs")

    return state


def BoundedControl(value: object) -> bytes:
    """Encode finite canonical control metadata without permitting arbitrary bodies.

    Args:
        value: Fixed first-party contract projection.

    Returns:
        At most 256 KiB canonical UTF-8 JSON.
    """

    raw = SerializeContract(value).encode()

    if len(raw) > CONTROL_BYTES:
        raise ValueError("Native configuration control exceeds its finite bound")

    return raw


def RequireProof(selection: NativeConfigurationSelection,
                 observer: NativeConfigurationMaterialObserver,
                 proof: NativeConfigurationMaterialProof, pair: str) -> None:
    """Require exact original observer-issued proof, selection, owner and current stage facts.

    Args:
        selection: Explicit native selection, never an image or synthetic selection.
        observer: Exact first-party material owner.
        proof: Original same-observer proof object.
        pair: Original whole VERSION/SCAN operation reference.
    """

    if type(selection) is not NativeConfigurationSelection or type(observer) is not (
        NativeConfigurationMaterialObserver
    ) or type(proof) is not NativeConfigurationMaterialProof or observer.selection is not (
        selection
    ) or type(pair) is not str or not re.fullmatch(
        r"native-configuration-pair:[a-f0-9]{32}", pair
    ):
        raise ValueError("Native configuration authority requires its original material owner")

    observer.CheckCurrent(proof, operation_reference=pair)


def PrepareNativeConfigurationOperation(
    operation: str, selection: NativeConfigurationSelection, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    operation_reference: str, timeout_seconds: int = 30,
    version_prerequisite: NativeConfigurationVersionPrerequisite | None = None,
) -> PreparedNativeConfigurationOperation:
    """Prepare only fixed VERSION or original-prerequisite-bound SCAN without process authority.

    Args:
        operation: Closed ``version`` or ``scan`` operation.
        selection: Original explicit native selection.
        observer: Original selected-material owner.
        material_proof: Current original same-pair material proof.
        operation_reference: Whole VERSION/SCAN pair reference.
        timeout_seconds: Integer SCAN deadline from one through sixty seconds.
        version_prerequisite: Exact original accepted VERSION for SCAN, absent for VERSION.

    Returns:
        Finite immutable recipe whose authority still requires a separate decision.
    """

    RequireProof(selection, observer, material_proof, operation_reference)

    if operation not in {"version", "scan"} or type(timeout_seconds) is not int or not (
        1 <= timeout_seconds <= 60
    ) or operation == "version" and version_prerequisite is not None or (
        operation == "scan" and type(version_prerequisite) is not
        NativeConfigurationVersionPrerequisite
    ):
        raise ValueError("Native configuration requires its fixed original operation prerequisite")

    scratch = observer.workspace_root / ("native-configuration-run-" + uuid4().hex)
    manifest = material_proof.stage.input.manifest

    if operation == "version":
        invocation = PrepareNativeConfigurationVersion(selection, manifest, scratch / "cache")
        resources = ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024)

    else:
        recipe = NativeConfigurationScanRecipe(selection, manifest,
            material_proof.stage.input.directory, scratch / "cache", timeout_seconds)
        invocation = AdapterInvocation("native.trivy", AdapterRequest(selection.Capability(),
            manifest.Target().Reference(), ImpactLevel.SAFE,
            {"profile": selection.profile.value, "operation": "scan"}), recipe.Arguments(),
            timeout_seconds, "0.75.0")
        resources = ExecutionResources(max_stdout_bytes=MAX_CONFIGURATION_STDOUT_BYTES,
                                       max_stderr_bytes=MAX_CONFIGURATION_STDERR_BYTES)

    return PreparedNativeConfigurationOperation("native-configuration-operation:" + uuid4().hex,
        operation, selection, observer.workspace_root, observer.workspace_id,
        observer.owner_reference, operation_reference, manifest,
        StagePayload(material_proof.stage), invocation, scratch, resources, version_prerequisite)


def ValidatePrepared(prepared: PreparedNativeConfigurationOperation,
                     observer: NativeConfigurationMaterialObserver,
                     proof: NativeConfigurationMaterialProof) -> None:
    """Rebuild the exact factory facts, preserving only original generated identities.

    Args:
        prepared: Original typed fixed operation recipe.
        observer: Original material owner.
        proof: Latest same-stage issued material proof.
    """

    if type(prepared) is not PreparedNativeConfigurationOperation or not re.fullmatch(
        r"native-configuration-operation:[a-f0-9]{32}", prepared.operation_id
    ) or prepared.scratch.parent != observer.workspace_root or not re.fullmatch(
        r"native-configuration-run-[a-f0-9]{32}", prepared.scratch.name
    ):
        raise ValueError("Native configuration prepared operation has invalid identities")

    rebuilt = PrepareNativeConfigurationOperation(prepared.operation, prepared.selection,
        observer=observer, material_proof=proof, operation_reference=prepared.operation_reference,
        timeout_seconds=prepared.invocation.timeout_seconds,
        version_prerequisite=prepared.version_prerequisite)
    expected = rebuilt.Payload()
    expected["operation_id"] = prepared.operation_id
    expected["scratch"] = str(prepared.scratch)
    invocation = rebuilt.invocation
    argv = tuple(value.replace(str(rebuilt.scratch), str(prepared.scratch))
                 for value in invocation.argv)
    expected["invocation"] = AdapterInvocation(invocation.adapter_id, invocation.request, argv,
                                               invocation.timeout_seconds,
                                               invocation.provider_version)

    if prepared.Payload() != expected:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    BoundedControl(prepared.Payload())


def PlanNativeConfigurationOperation(
    engine: ArtifactPolicyEngine, prepared: PreparedNativeConfigurationOperation,
    context: ArtifactPolicyContext, *, observer: NativeConfigurationMaterialObserver,
    material_proof: NativeConfigurationMaterialProof, at: datetime,
) -> NativeConfigurationOperationPlan:
    """Describe current exact artifact authority without issuing a grant or launching a process.

    Args:
        engine: Canonical issuing artifact policy owner.
        prepared: Exact fixed native configuration recipe.
        context: Current same-store scope, operator policy and executing owner.
        observer: Original material owner.
        material_proof: Current original same-stage material proof.
        at: Explicit aware authority decision time.

    Returns:
        Current scope/policy/material/invocation binding in the configuration domain.
    """

    EngineState(engine)
    RequireTime(at)
    ValidatePrepared(prepared, observer, material_proof)

    if type(context) is not ArtifactPolicyContext:
        raise ValueError("Native configuration requires a typed current policy context")

    workspace = LocalWorkspaceStore(prepared.workspace_root).Open()
    scope = LocalScopeStore(prepared.workspace_root).Open(context.scope.scope_id)

    if workspace.workspace_id != prepared.workspace_id or scope != context.scope or (
        scope.workspace_id != workspace.workspace_id
        or context.owner_ref != prepared.owner_reference
        or context.owner_ref != prepared.selection.read_consent.actor_ref
        or not scope.Check(prepared.input_manifest.Target(), at=at).Allowed()
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    permission = next((item for item in context.policy.permissions if
        item.capability_id == prepared.selection.Capability()
        and item.adapter_id == "native.trivy"),
        None)

    if permission is None or permission.granted_privileges:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    if ImpactLevel.PASSIVE in (context.policy.maximum_impact, permission.maximum_impact):
        raise ArtifactDeniedError(ArtifactDenialReason.IMPACT_DENIED)

    prerequisite = prepared.version_prerequisite

    if prerequisite is not None:
        ValidateVersionPrerequisite(engine, prerequisite, context, observer=observer,
                                   material_proof=material_proof, at=at)

        if prerequisite.prepared.operation_reference != prepared.operation_reference or (
            prerequisite.prepared.input_manifest != prepared.input_manifest
            or prerequisite.prepared.stage_metadata != prepared.stage_metadata
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    return NativeConfigurationOperationPlan(prepared.operation_id, prepared.operation,
        prepared.operation_reference, workspace.workspace_id, context.owner_ref, scope.Reference(),
        scope.revision, Digest(scope.ToDict()), context.policy.Reference(), context.policy.revision,
        Digest(context.policy), prepared.input_manifest.Target().Reference(),
        prepared.input_manifest.Digest(), Digest(prepared.Payload()),
        InvocationDigest(prepared.invocation), Digest(prepared.stage_metadata),
        None if prerequisite is None else prerequisite.Digest())


def GrantEnvelope(plan: NativeConfigurationOperationPlan, issued: str,
                  expiry: str) -> ExecutionAuthorization:
    """Bind exact configuration-domain authority into the existing executor contract.

    Args:
        plan: Original current configuration-domain plan.
        issued: Original aware issuance time.
        expiry: Exclusive recorded expiry.

    Returns:
        Exact-invocation execution authorization, with no granted privileges.
    """

    return ExecutionAuthorization("artifact-authorization:" + Digest({
        "native_configuration": plan, "issued_at": issued, "valid_until": expiry,
        "approve_safe_configuration": True}), plan.scope_reference, plan.policy_reference,
        plan.invocation_sha256)


def GrantExpiry(at: datetime, context: ArtifactPolicyContext) -> str:
    """Bound grant lifetime by both current operator policy and recorded scope consent.

    Args:
        at: Original aware issuance time.
        context: Current typed scope/policy context.

    Returns:
        Canonical exclusive UTC expiry.
    """

    expiry = at + timedelta(seconds=context.policy.max_authorization_seconds)

    if context.scope.authorization.valid_until is not None:
        expiry = min(expiry, datetime.fromisoformat(context.scope.authorization.valid_until))

    return expiry.astimezone(UTC).isoformat()


def AuthorizeNativeConfigurationOperation(
    engine: ArtifactPolicyEngine, prepared: PreparedNativeConfigurationOperation,
    context: ArtifactPolicyContext, *, observer: NativeConfigurationMaterialObserver,
    material_proof: NativeConfigurationMaterialProof, at: datetime,
    approve_safe_configuration: bool = False,
) -> NativeConfigurationOperationGrant:
    """Issue separate original authority after explicit SAFE approval and factual policy checks.

    Args:
        engine: Exact canonical issuing engine.
        prepared: Exact native recipe.
        context: Fresh current factual authority context.
        observer: Original material owner.
        material_proof: Current original proof.
        at: Aware current decision time.
        approve_safe_configuration: Exact True workflow opt-in, independent of policy permission.

    Returns:
        Engine-retained original configuration grant.
    """

    if approve_safe_configuration is not True:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    plan = PlanNativeConfigurationOperation(engine, prepared, context, observer=observer,
                                           material_proof=material_proof, at=at)
    issued = at.astimezone(UTC).isoformat()
    expiry = GrantExpiry(at, context)
    authorization = GrantEnvelope(plan, issued, expiry)
    state = EngineState(engine)

    if authorization.authorization_id in state.grants:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    grant = NativeConfigurationOperationGrant(plan, authorization, issued, expiry, True)
    state.grants[authorization.authorization_id] = grant, observer

    return grant


def ValidateNativeConfigurationOperation(
    engine: ArtifactPolicyEngine, grant: NativeConfigurationOperationGrant,
    prepared: PreparedNativeConfigurationOperation, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> None:
    """Require exact original grant identity and revalidate every current authority binding.

    Args:
        engine: Original issuing engine.
        grant: Exact original grant object.
        prepared: Exact prepared operation.
        context: Fresh same-store current authority.
        observer: Original material owner.
        material_proof: Latest original same-stage proof.
        at: Aware launch or acceptance time.
    """

    RequireTime(at)

    if type(grant) is not NativeConfigurationOperationGrant:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    original = EngineState(engine).grants.get(grant.authorization.authorization_id)

    if original is None or original[0] is not grant or original[1] is not observer or (
        grant.approve_safe_configuration is not True
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    issued = datetime.fromisoformat(grant.issued_at)

    if not issued <= at < datetime.fromisoformat(grant.valid_until):
        raise ArtifactDeniedError(ArtifactDenialReason.GRANT_EXPIRED)

    plan = PlanNativeConfigurationOperation(engine, prepared, context, observer=observer,
                                           material_proof=material_proof, at=at)

    if plan != grant.plan or GrantExpiry(issued, context) != grant.valid_until or (
        GrantEnvelope(plan, grant.issued_at, grant.valid_until) != grant.authorization
        or not context.scope.Check(prepared.input_manifest.Target(), at=issued).Allowed()
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)


def PrivateDirectory(path: Path) -> tuple[int, int]:
    """Require one physical owner-only directory and return its device/inode identity.

    Args:
        path: Explicit original private directory.

    Returns:
        Stable physical identity after canonical artifact path guards.
    """

    info = ArtifactPathInfo(path, directory=True)

    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Native configuration private directory mode changed")

    return info.st_dev, info.st_ino


def WriteControl(path: Path, value: object) -> tuple[Path, bytes, tuple[int, ...]]:
    """Exclusively persist bounded control, fsync it and bind original opened/path identities.

    Args:
        path: New immutable private claim file.
        value: Fixed original contract projection.

    Returns:
        Original path, exact bytes and physical identity for future validation.
    """

    raw = BoundedControl(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)

    try:
        cast(Callable[[int, int], None], getattr(os, "fchmod"))(descriptor, 0o600)
        written = 0

        while written < len(raw):
            count = os.write(descriptor, raw[written:])

            if count <= 0:
                raise OSError("Native configuration claim write was incomplete")

            written += count

        os.fsync(descriptor)
        opened = ArtifactHandleInfo(descriptor)

    finally:
        os.close(descriptor)

    SyncDirectory(path.parent)
    info = ArtifactPathInfo(path)

    if not MatchesArtifactReadIdentity(info, opened):
        raise ValueError("Native configuration claim changed during exclusive write")

    result = path, raw, PhysicalIdentity(info)
    ReadControl(result)

    return result


def SyncDirectory(path: Path) -> None:
    """Acknowledge an original private directory entry through a no-follow directory handle.

    Args:
        path: Explicit original private control directory on the supported Linux owner.
    """

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_NOFOLLOW", 0))

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def ReadControl(control: tuple[Path, bytes, tuple[int, ...]]) -> None:
    """Verify immutable bounded control with before/open/after physical identity checks.

    Args:
        control: Original exclusive-write path, bytes and physical identity.
    """

    path, expected, identity = control
    before = ArtifactPathInfo(path)

    if PhysicalIdentity(before) != identity or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("Native configuration claim identity changed")

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_BINARY", 0))

    try:
        opened = ArtifactHandleInfo(descriptor)

        if not MatchesArtifactReadIdentity(before, opened):
            raise ValueError("Native configuration claim changed before open")

        raw = bytearray()

        while len(raw) <= CONTROL_BYTES:
            chunk = os.read(descriptor, min(4096, CONTROL_BYTES + 1 - len(raw)))

            if not chunk:
                break

            raw.extend(chunk)

        if raw != expected or PhysicalIdentity(ArtifactHandleInfo(descriptor)) != (
            PhysicalIdentity(opened)
        ):
            raise ValueError("Native configuration claim bytes changed")

    finally:
        os.close(descriptor)

    if PhysicalIdentity(ArtifactPathInfo(path)) != identity:
        raise ValueError("Native configuration claim changed after open")


def ClaimNativeConfigurationExecution(
    engine: ArtifactPolicyEngine, grant: NativeConfigurationOperationGrant,
    prepared: PreparedNativeConfigurationOperation, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> NativeConfigurationExecutionClaim:
    """Consume operation and observation once, persist reservations, then issue an opaque handle.

    Args:
        engine: Original issuing canonical engine.
        grant: Original current native grant.
        prepared: Original fixed recipe.
        context: Fresh same-store current authority.
        observer: Original material owner.
        material_proof: Current original proof to consume once.
        at: Aware reservation time.

    Returns:
        Original one-use claim; partial reservations remain consumed after failure.
    """

    engine.ValidateNativeConfigurationOperation(grant, prepared, context, observer=observer,
                                        material_proof=material_proof, at=at)
    namespace = prepared.workspace_root / ".native-configuration-claims"

    try:
        namespace.mkdir(mode=0o700)

    except FileExistsError:
        pass

    namespace_identity = PrivateDirectory(namespace)
    controls = []

    for kind, identity in (("operation", prepared.operation_id),
                           ("observation", material_proof.observation_id)):
        name = hashlib.sha256((kind + ":" + identity).encode()).hexdigest() + ".json"
        controls.append(WriteControl(namespace / name, {"family": NATIVE_CONFIGURATION_FAMILY,
            "kind": kind, "identity": identity, "operation_id": prepared.operation_id,
            "grant": grant}))

    directory = namespace / uuid4().hex
    directory.mkdir(mode=0o700)
    directories = ((prepared.workspace_root, PrivateDirectory(prepared.workspace_root)),
                   (namespace, namespace_identity), (directory, PrivateDirectory(directory)))
    controls.append(WriteControl(directory / "reservation.json", prepared.Payload()))
    claim = object.__new__(NativeConfigurationExecutionClaim)
    EngineState(engine).claims[claim] = ConfigurationClaimState(prepared, grant, observer,
        material_proof, tuple(controls), directories)

    return claim


def OriginalClaim(engine: ArtifactPolicyEngine,
                  claim: NativeConfigurationExecutionClaim) -> ConfigurationClaimState:
    """Require exact original opaque claim identity and unchanged persistent physical controls.

    Args:
        engine: Exact original issuing engine.
        claim: Original opaque handle; copies and reconstructed handles are refused.

    Returns:
        Private original claim state after complete persistent control verification.
    """

    if type(claim) is not NativeConfigurationExecutionClaim:
        raise ValueError("Native configuration requires its original execution claim")

    state = EngineState(engine).claims.get(claim)

    if state is None:
        raise ValueError("Native configuration execution claim is not original")

    for path, identity in state.directories:
        if PrivateDirectory(path) != identity:
            raise ValueError("Native configuration claim directory changed")

    for control in state.controls:
        ReadControl(control)

    if state.cleaned_scratch is not None and os.path.lexists(state.cleaned_scratch):
        raise ValueError("Native configuration original cleaned scratch was replaced")

    return state


def ConfigurationEnvironment(scratch: Path) -> dict[str, str]:
    """Return fixed private environment with no inherited provider or executable search paths.

    Args:
        scratch: Exact newly owned per-operation scratch.

    Returns:
        Closed fixed environment passed to the existing local executor.
    """

    return {"HOME": str(scratch), "XDG_CONFIG_HOME": str(scratch),
        "XDG_CACHE_HOME": str(scratch), "TMPDIR": str(scratch), "TEMP": str(scratch),
        "TMP": str(scratch), "PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"}


def BindNativeConfigurationRequest(
    engine: ArtifactPolicyEngine, claim: NativeConfigurationExecutionClaim,
    request: LocalExecutionRequest, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> None:
    """Bind exactly one fixed full request and fresh private scratch to an original claim.

    Args:
        engine: Original issuing engine.
        claim: Original unbound execution claim.
        request: Exact complete request to be launched.
        context: Fresh authority context.
        observer: Original material owner.
        material_proof: Original proof consumed by this claim.
        at: Aware binding time.
    """

    state = OriginalClaim(engine, claim)
    prepared = state.prepared

    if state.request is not None or state.observer is not observer or state.proof is not (
        material_proof
    ):
        raise ValueError("Native configuration claim cannot bind another request")

    engine.ValidateNativeConfigurationOperation(state.grant, prepared, context,
        observer=observer, material_proof=material_proof, at=at)
    expected = LocalExecutionRequest(prepared.invocation,
        CapabilityDescriptor(prepared.selection.Capability(), "native.trivy", ImpactLevel.SAFE),
        state.grant.authorization, prepared.scratch.relative_to(prepared.workspace_root).as_posix(),
        ConfigurationEnvironment(prepared.scratch), prepared.resources)

    if request != expected:
        raise ValueError("Native configuration request differs from its fixed factory")

    scratch_identity = PrivateDirectory(prepared.scratch)
    directory = state.directories[-1][0]
    control = WriteControl(directory / "request.json", request)
    state.directories = (*state.directories, (prepared.scratch, scratch_identity))
    state.controls = (*state.controls, control)
    state.request = request


def ValidateNativeConfigurationClaim(
    engine: ArtifactPolicyEngine, claim: NativeConfigurationExecutionClaim,
    request: LocalExecutionRequest, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> None:
    """Revalidate exact original full-request identity and current authority before launch.

    Args:
        engine: Original issuing engine.
        claim: Original bound claim.
        request: Exact original request object, never a reconstructed equivalent.
        context: Fresh factual authority context.
        observer: Original material owner.
        material_proof: Current same-stage proof; post-run proof may replace consumed proof.
        at: Aware launch or acceptance time.
    """

    state = OriginalClaim(engine, claim)

    if state.request is not request or state.observer is not observer:
        raise ValueError("Native configuration bound request is not original")

    engine.ValidateNativeConfigurationOperation(state.grant, state.prepared, context,
        observer=observer, material_proof=material_proof, at=at)


def ValidateNativeConfigurationCapture(
    engine: ArtifactPolicyEngine, claim: NativeConfigurationExecutionClaim,
    capture: NativeConfigurationOperationCapture, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> None:
    """Accept only this original successful captured process and original consumed claim.

    Args:
        engine: Original issuing engine.
        claim: Original bound execution claim.
        capture: Exact original capture registered by its collector.
        context: Fresh factual authority context.
        observer: Original material owner.
        material_proof: Latest exact original same-stage proof.
        at: Aware acceptance time.
    """

    state = OriginalClaim(engine, claim)

    if state.capture is not capture or capture.prepared is not state.prepared or (
        capture.grant is not state.grant or capture.refusal is not None
    ):
        raise ValueError("Native configuration capture is not an accepted original process")

    engine.ValidateNativeConfigurationClaim(claim, capture.request, context, observer=observer,
                                    material_proof=material_proof, at=at)


def AcceptNativeConfigurationVersion(
    engine: ArtifactPolicyEngine, claim: NativeConfigurationExecutionClaim,
    capture: NativeConfigurationOperationCapture, context: ArtifactPolicyContext, *,
    observer: NativeConfigurationMaterialObserver, material_proof: NativeConfigurationMaterialProof,
    at: datetime,
) -> NativeConfigurationVersionPrerequisite:
    """Issue one original VERSION prerequisite after actual successful collection and verification.

    Args:
        engine: Original issuing engine.
        claim: Original VERSION claim.
        capture: Original successful VERSION capture.
        context: Fresh current authority context.
        observer: Original material owner.
        material_proof: Fresh proof after original VERSION termination.
        at: Aware acceptance time.

    Returns:
        Original engine-retained VERSION prerequisite; replay cannot recreate it.
    """

    engine.ValidateNativeConfigurationCapture(claim, capture, context, observer=observer,
                                      material_proof=material_proof, at=at)
    state = OriginalClaim(engine, claim)

    if state.prepared.operation != "version" or capture.observed_version != "0.75.0" or (
        state.prerequisite is not None
    ):
        raise ValueError("Native configuration VERSION prerequisite cannot be replaced")

    prerequisite = NativeConfigurationVersionPrerequisite(state.prepared, state.grant,
                                                         claim, capture)
    state.prerequisite = prerequisite

    return prerequisite


def ValidateVersionPrerequisite(
    engine: ArtifactPolicyEngine, prerequisite: NativeConfigurationVersionPrerequisite,
    context: ArtifactPolicyContext, *, observer: NativeConfigurationMaterialObserver,
    material_proof: NativeConfigurationMaterialProof, at: datetime,
) -> None:
    """Require the original engine-issued VERSION association and current whole-pair authority.

    Args:
        engine: Original issuing engine.
        prerequisite: Exact original accepted VERSION object.
        context: Fresh current authority context.
        observer: Original same-pair material owner.
        material_proof: Latest original same-stage material proof.
        at: Aware validation time.
    """

    if type(prerequisite) is not NativeConfigurationVersionPrerequisite:
        raise ValueError("Native configuration SCAN requires its original VERSION prerequisite")

    state = OriginalClaim(engine, prerequisite.claim)

    if state.prerequisite is not prerequisite or prerequisite.capture is not state.capture or (
        prerequisite.prepared is not state.prepared or prerequisite.grant is not state.grant
    ):
        raise ValueError("Native configuration VERSION prerequisite is not original")

    engine.ValidateNativeConfigurationCapture(prerequisite.claim, prerequisite.capture, context,
        observer=observer, material_proof=material_proof, at=at)


def ValidateNativeConfigurationPairFresh(
    engine: ArtifactPolicyEngine, version: NativeConfigurationVersionPrerequisite,
    scan_claim: NativeConfigurationExecutionClaim,
    scan_capture: NativeConfigurationOperationCapture,
    context: ArtifactPolicyContext, *, observer: NativeConfigurationMaterialObserver,
    material_proof: NativeConfigurationMaterialProof, at: datetime,
) -> None:
    """Require original VERSION/SCAN association and current authority before model application.

    Args:
        engine: Original issuing engine.
        version: Original accepted VERSION prerequisite.
        scan_claim: Original SCAN claim.
        scan_capture: Original successful SCAN capture.
        context: Fresh same-store authority context.
        observer: Original same-pair material owner.
        material_proof: Latest original post-SCAN material proof.
        at: Aware application time.
    """

    ValidateVersionPrerequisite(engine, version, context, observer=observer,
                               material_proof=material_proof, at=at)
    engine.ValidateNativeConfigurationCapture(scan_claim, scan_capture, context,
        observer=observer, material_proof=material_proof, at=at)

    if scan_capture.prepared.version_prerequisite is not version or (
        scan_capture.prepared.operation != "scan"
    ):
        raise ValueError("Native configuration SCAN does not belong to its original VERSION")
