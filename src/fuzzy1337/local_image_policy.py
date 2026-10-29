# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal additive local Docker read authority owned by the canonical artifact engine."""

from __future__ import annotations

import hashlib
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fuzzy1337.adapters import AdapterInvocation, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactPathInfo, PhysicalIdentity, ReadArtifactFile
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.executors import (
    ExecutionAuthorization,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
)
from fuzzy1337.local_image_archive import InspectConfigId, LocalImageArchivePin, VerifyDockerSave
from fuzzy1337.local_image_material import LocalImageMaterialObserver, LocalImageMaterialProof
from fuzzy1337.local_image_reference import (
    LOCAL_IMAGE_CAPABILITY,
    LocalImageOperation,
    LocalImageResources,
    PrepareLocalImageInvocation,
)
from fuzzy1337.native_image_policy import PrivateDirectory, ReadControl, WriteControl
from fuzzy1337.policy import Digest, RequireTime
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore


@dataclass(frozen=True, slots=True, eq=False)
class LocalImageResolution:
    """Original accepted inspect association; construction alone supplies no export prerequisite."""

    image_config_id: str
    inspect_sha256: str
    operation_reference: str


@dataclass(frozen=True, slots=True)
class PreparedLocalImageOperation:
    """Exact fixed command and material association, before independent current authorization."""

    operation_id: str
    operation: LocalImageOperation
    observer: LocalImageMaterialObserver
    proof: LocalImageMaterialProof
    scratch: Path
    scratch_identities: tuple[tuple[int, int], tuple[int, int], tuple[int, int]]
    config_identity: tuple[int, int, int, int, int]
    invocation: AdapterInvocation
    resolution: LocalImageResolution | None = None

    def Payload(self) -> dict[str, object]:
        """Detach exact nonauthority recipe facts without serializing an observer or opaque handle.

        Returns:
            Canonical command/material/actor associations used by plans, grants and claims.
        """

        selection = self.observer.selection

        return {"family": "local-image-export-v1", "operation_id": self.operation_id,
            "operation": self.operation.value,
            "operation_reference": self.proof.operation_reference,
            "workspace_root": str(selection.workspace_root),
            "workspace_id": self.proof.workspace_id,
            "owner_reference": self.proof.owner_reference,
            "read_consent": selection.read_consent, "descriptor": selection.Manifest(),
            "material": {"executable": self.proof.executable,
                "socket_identity": self.proof.socket_identity,
                "workspace_identity": self.proof.workspace_identity},
            "invocation": self.invocation, "scratch": str(self.scratch),
            "scratch_identities": self.scratch_identities, "config_identity": self.config_identity,
            "environment": LocalImageEnvironment(self.scratch),
            "resources": LocalImageResources(self.operation), "resolution": self.resolution}


@dataclass(frozen=True, slots=True)
class LocalImageOperationPlan:
    """Descriptive current source authority; no operation is authorized by a plan."""

    prepared_sha256: str
    scope_sha256: str
    policy_sha256: str
    scope_reference: str
    policy_reference: str
    workspace_id: str
    owner_reference: str
    target_reference: str
    invocation_sha256: str


@dataclass(frozen=True, slots=True, eq=False)
class LocalImageOperationGrant:
    """Original engine-held operation permission with an exclusive bounded lifetime."""

    plan: LocalImageOperationPlan
    authorization: ExecutionAuthorization
    issued_at: str
    valid_until: str


class LocalImageExecutionClaim:
    """Opaque original one-use reservation; only the issuing engine retains its full facts."""

    __slots__ = ()


@dataclass(slots=True)
class LocalImageClaimState:
    """Original private claim/request binding retained separately from native image grants."""

    grant: LocalImageOperationGrant
    prepared: PreparedLocalImageOperation
    request: LocalExecutionRequest
    path: Path
    raw: bytes
    identity: tuple[int, ...]
    namespace_identity: tuple[int, int]
    binding: tuple[bytes, tuple[int, ...]] | None = None
    finished: bool = False
    completed: bool = False


@dataclass(slots=True)
class LocalImageEngineState:
    """Original object maps supplement durable claim exclusion, never reconstructed authority."""

    grants: dict[str, tuple[LocalImageOperationGrant, PreparedLocalImageOperation]] = field(
        default_factory=dict)
    claims: dict[LocalImageExecutionClaim, LocalImageClaimState] = field(default_factory=dict)
    resolutions: dict[LocalImageResolution, LocalImageExecutionClaim] = field(default_factory=dict)
    exports: dict[LocalImageExecutionClaim, LocalImageArchivePin] = field(default_factory=dict)


def LocalImageEnvironment(scratch: Path) -> dict[str, str]:
    """Fix the entire inherited executor whitelist plus private Docker configuration locations.

    Args:
        scratch: Original owned private operation directory.

    Returns:
        Explicit nonsecret environment; ambient Docker, proxy or credential settings are absent.
    """

    return {"HOME": str(scratch / "home"), "DOCKER_CONFIG": str(scratch / "docker-config"),
        "XDG_CONFIG_HOME": str(scratch / "home"), "XDG_CACHE_HOME": str(scratch / "home"),
        "TMPDIR": str(scratch / "home"), "TEMP": str(scratch / "home"),
        "TMP": str(scratch / "home"), "PATH": "", "PATHEXT": "", "COMSPEC": "",
        "SYSTEMROOT": "", "WINDIR": "", "LANG": "C", "LC_ALL": "C"}


def EngineState(engine: ArtifactPolicyEngine) -> LocalImageEngineState:
    """Keep this additive authority family on the exact canonical artifact-policy owner.

    Args:
        engine: Original existing artifact policy engine, never a substitute permission store.

    Returns:
        Private original maps for this engine instance only.

    Raises:
        ValueError: The owner or its private state has an incompatible identity.
    """

    if type(engine) is not ArtifactPolicyEngine:
        raise ValueError("local image requires its canonical artifact policy owner")

    state = getattr(engine, "_local_image_authority", None)

    if state is None:
        state = LocalImageEngineState()
        setattr(engine, "_local_image_authority", state)

    if type(state) is not LocalImageEngineState:
        raise ValueError("local image original authority state differs")

    return state


def CheckPrepared(engine: ArtifactPolicyEngine, prepared: PreparedLocalImageOperation) -> None:
    """Rebuild fixed commands and require original material, private config and prior resolution.

    Args:
        engine: Original canonical owner of any prerequisite resolution.
        prepared: Exact current typed fixed operation.

    Raises:
        ValueError: Material, recipe, private storage or original prerequisites differ.
        OSError: Selected private control bytes cannot be verified.
    """

    if type(prepared) is not PreparedLocalImageOperation or (
        type(prepared.observer) is not LocalImageMaterialObserver
        or type(prepared.operation) is not LocalImageOperation
        or type(prepared.operation_id) is not str
        or re.fullmatch("local-image-operation:[0-9a-f]{32}", prepared.operation_id) is None
    ):
        raise ValueError("local image requires its fixed original prepared operation")

    prepared.observer.CheckCurrent(prepared.proof)
    root = prepared.observer.selection.workspace_root

    if not prepared.scratch.is_relative_to(root) or prepared.scratch == root:
        raise ValueError("local image scratch must belong to its exact owning workspace")

    config = prepared.scratch / "docker-config"

    if tuple(PrivateDirectory(path) for path in (
        prepared.scratch, prepared.scratch / "home", config
    )) != prepared.scratch_identities:
        raise ValueError("local image private scratch identity changed")

    if {item.name for item in config.iterdir()} != {"config.json"}:
        raise ValueError("local image config must contain only the explicit empty operator file")

    config_file = config / "config.json"
    info = ArtifactPathInfo(config_file)

    if PhysicalIdentity(info) != prepared.config_identity or (
        stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 3
        or ReadArtifactFile(config_file, "config.json", max_bytes=3).sha256
        != hashlib.sha256(b"{}\n").hexdigest()
    ):
        raise ValueError("local image operator configuration differs from its fixed empty bytes")

    image_id = None

    if prepared.operation is not LocalImageOperation.INSPECT:
        resolution = prepared.resolution
        original_claim = None if resolution is None else EngineState(engine).resolutions.get(
            resolution)
        prior = (EngineState(engine).claims.get(original_claim)
                 if original_claim is not None else None)

        if resolution is None or prior is None or not prior.completed or (
            prior.prepared.operation is not LocalImageOperation.INSPECT
            or resolution.operation_reference != prepared.proof.operation_reference
            or prior.prepared.observer is not prepared.observer
            or prior.prepared.proof is not prepared.proof
        ):
            raise ValueError("local image requires its original completed inspect association")

        if prepared.operation is LocalImageOperation.EXPORT:
            image_id = resolution.image_config_id

        elif not any(EngineState(engine).claims[claim].completed and (
            EngineState(engine).claims[claim].prepared.observer is prepared.observer
            and EngineState(engine).claims[claim].prepared.proof is prepared.proof
            and EngineState(engine).claims[claim].prepared.resolution is resolution
        ) for claim in EngineState(engine).exports):
            raise ValueError("local image recheck requires its original accepted export")

    elif prepared.resolution is not None:
        raise ValueError("local image inspect cannot borrow a prior resolution")

    expected = PrepareLocalImageInvocation(prepared.observer.selection, prepared.operation,
                                          config, image_id=image_id)

    if prepared.invocation != expected:
        raise ValueError("local image prepared invocation differs from the fixed recipe")


def PrepareLocalImageOperation(
    engine: ArtifactPolicyEngine, observer: LocalImageMaterialObserver,
    proof: LocalImageMaterialProof, operation: LocalImageOperation, scratch: Path,
    *, resolution: LocalImageResolution | None = None,
) -> PreparedLocalImageOperation:
    """Describe one fixed operation without issuing a grant or launching a process.

    Args:
        engine: Canonical issuer of any original completed inspect prerequisite.
        observer: Exact selected material owner.
        proof: Original proof issued for the whole export attempt.
        operation: One closed local read operation.
        scratch: Existing private workspace directory with home and empty Docker config.
        resolution: Exact original accepted inspect association for export/recheck only.

    Returns:
        Fresh exact fixed recipe whose future claim cannot be reused.
    """

    image_id = resolution.image_config_id if operation is LocalImageOperation.EXPORT and (
        resolution is not None) else None
    invocation = PrepareLocalImageInvocation(observer.selection, operation,
                                            scratch / "docker-config", image_id=image_id)
    prepared = PreparedLocalImageOperation("local-image-operation:" + uuid4().hex,
        operation, observer, proof, scratch, (PrivateDirectory(scratch),
            PrivateDirectory(scratch / "home"), PrivateDirectory(scratch / "docker-config")),
        PhysicalIdentity(ArtifactPathInfo(scratch / "docker-config/config.json")),
        invocation, resolution)
    CheckPrepared(engine, prepared)

    return prepared


def PlanLocalImageOperation(engine: ArtifactPolicyEngine, prepared: PreparedLocalImageOperation,
                            context: ArtifactPolicyContext, *, at: datetime,
) -> LocalImageOperationPlan:
    """Bind current registered source scope and explicit local-read permission to the fixed recipe.

    Args:
        engine: Existing canonical artifact authority owner.
        prepared: Exact fixed command and original material association.
        context: Fresh same-store scope, typed impact policy and executing actor.
        at: Explicit aware authority clock.

    Returns:
        Descriptive original plan without execution permission.

    Raises:
        ArtifactDeniedError: Current scope, owner, capability, privilege or impact refuses.
        ValueError: Typed recipe, material or clock requirements differ.
    """

    RequireTime(at)
    EngineState(engine)
    CheckPrepared(engine, prepared)

    if type(context) is not ArtifactPolicyContext:
        raise ValueError("local image requires a typed current artifact context")

    selection = prepared.observer.selection
    workspace = LocalWorkspaceStore(selection.workspace_root).Open()
    scope = LocalScopeStore(selection.workspace_root).Open(context.scope.scope_id)
    permission = next((item for item in context.policy.permissions
        if item.capability_id == LOCAL_IMAGE_CAPABILITY.identifier
        and item.adapter_id == LOCAL_IMAGE_CAPABILITY.adapter_id), None)

    if workspace.workspace_id != prepared.proof.workspace_id or scope != context.scope or (
        scope.workspace_id != workspace.workspace_id
        or context.owner_ref != prepared.proof.owner_reference
        or context.owner_ref != selection.read_consent.actor_ref
        or not scope.Check(selection.Target(), at=at).Allowed()
        or permission is None
        or permission.granted_privileges != LOCAL_IMAGE_CAPABILITY.required_privileges
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    if context.policy.maximum_impact is ImpactLevel.PASSIVE or (
        permission.maximum_impact is ImpactLevel.PASSIVE
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.IMPACT_DENIED)

    if prepared.resolution is not None:
        state = EngineState(engine)
        original_inspect = state.claims[state.resolutions[prepared.resolution]]
        ValidateLocalImageOperation(engine, original_inspect.grant, original_inspect.prepared,
                                    context, at=at)

        if prepared.operation is LocalImageOperation.RECHECK:
            for claim in state.exports:
                original_export = state.claims[claim]

                if original_export.prepared.resolution is prepared.resolution:
                    ValidateLocalImageOperation(engine, original_export.grant,
                                                original_export.prepared, context, at=at)

    return LocalImageOperationPlan(Digest(prepared.Payload()), Digest(scope.ToDict()),
        Digest(context.policy), scope.Reference(), context.policy.Reference(),
        workspace.workspace_id,
        context.owner_ref, selection.Target().Reference(), InvocationDigest(prepared.invocation))


def AuthorizeLocalImageOperation(engine: ArtifactPolicyEngine,
    prepared: PreparedLocalImageOperation, context: ArtifactPolicyContext, *, at: datetime,
    approve_local_image: bool = False,
) -> LocalImageOperationGrant:
    """Issue original one-operation permission after independent scope and exact explicit opt-in.

    Args:
        engine: Canonical artifact policy owner.
        prepared: Original exact fixed operation.
        context: Fresh same-store current authority.
        at: Explicit aware issuance clock.
        approve_local_image: Exact True workflow approval, never a substitute for permission.

    Returns:
        Original engine-retained grant with exclusive scope/policy-bounded expiry.

    Raises:
        ArtifactDeniedError: Approval or current independent authority refuses.
    """

    if type(approve_local_image) is not bool or not approve_local_image:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    plan = PlanLocalImageOperation(engine, prepared, context, at=at)
    try:
        expiry = at + timedelta(seconds=context.policy.max_authorization_seconds)

    except OverflowError:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from None

    if context.scope.authorization.valid_until is not None:
        expiry = min(expiry, datetime.fromisoformat(context.scope.authorization.valid_until))

    issued = at.astimezone(timezone.utc).isoformat()
    until = expiry.astimezone(timezone.utc).isoformat()
    identifier = "artifact-authorization:" + Digest({"local_image": plan,
        "issued_at": issued, "valid_until": until, "approval": True})
    authorization = ExecutionAuthorization(identifier, plan.scope_reference, plan.policy_reference,
        plan.invocation_sha256, LOCAL_IMAGE_CAPABILITY.required_privileges)
    grant = LocalImageOperationGrant(plan, authorization, issued, until)
    state = EngineState(engine)

    if identifier in state.grants:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    state.grants[identifier] = grant, prepared

    return grant


def ValidateLocalImageOperation(engine: ArtifactPolicyEngine, grant: LocalImageOperationGrant,
    prepared: PreparedLocalImageOperation, context: ArtifactPolicyContext, *, at: datetime,
) -> None:
    """Revalidate original object identity, current exact authority and exclusive expiry.

    Args:
        engine: Same original canonical grant issuer.
        grant: Exact original retained grant, never a reconstructed value.
        prepared: Exact original prepared operation paired with that grant.
        context: Fresh same-store current authority.
        at: Explicit aware current clock.

    Raises:
        ArtifactDeniedError: Original identity, current scope/policy or lifetime differs.
    """

    RequireTime(at)

    if type(grant) is not LocalImageOperationGrant:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    original = EngineState(engine).grants.get(grant.authorization.authorization_id)

    if original is None or original[0] is not grant or original[1] is not prepared:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    if not (datetime.fromisoformat(grant.issued_at) <= at
            < datetime.fromisoformat(grant.valid_until)):
        raise ArtifactDeniedError(ArtifactDenialReason.GRANT_EXPIRED)

    if PlanLocalImageOperation(engine, prepared, context, at=at) != grant.plan:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)


def ClaimLocalImageExecution(engine: ArtifactPolicyEngine, grant: LocalImageOperationGrant,
    prepared: PreparedLocalImageOperation, context: ArtifactPolicyContext, *, at: datetime,
) -> tuple[LocalImageExecutionClaim, LocalExecutionRequest]:
    """Consume the whole-attempt operation once with a durable exact full-request reservation.

    Args:
        engine: Canonical original grant issuer.
        grant: Exact fresh original operation grant.
        prepared: Exact fixed operation/material association.
        context: Fresh current authority.
        at: Explicit aware claim clock.

    Returns:
        Original opaque claim and its one exact executor request.

    Raises:
        ArtifactDeniedError: Authority is stale or the operation was already consumed.
        OSError: Exclusive immutable claim persistence cannot be confirmed.
    """

    ValidateLocalImageOperation(engine, grant, prepared, context, at=at)
    root = prepared.observer.selection.workspace_root
    namespace = root / "local-image-export-claims"
    namespace.mkdir(mode=0o700, exist_ok=True)
    identity = PrivateDirectory(namespace)
    key = Digest({"operation_reference": prepared.proof.operation_reference,
                  "operation": prepared.operation.value})
    path = namespace / (key + ".json")
    request = LocalExecutionRequest(prepared.invocation, LOCAL_IMAGE_CAPABILITY,
        grant.authorization,
        prepared.scratch.relative_to(root).as_posix(), LocalImageEnvironment(prepared.scratch),
        LocalImageResources(prepared.operation))

    try:
        raw, physical = WriteControl(path, {"family": "local-image-export-v1", "grant": grant,
            "prepared": prepared.Payload(), "request": request,
            "namespace_identity": identity})

    except FileExistsError:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from None

    claim = LocalImageExecutionClaim()
    EngineState(engine).claims[claim] = LocalImageClaimState(grant, prepared, request,
                                                           path, raw, physical, identity)

    return claim, request


def ValidateLocalImageClaim(engine: ArtifactPolicyEngine, claim: LocalImageExecutionClaim,
    request: LocalExecutionRequest, context: ArtifactPolicyContext, *, at: datetime,
    require_binding: bool = True,
) -> None:
    """Recheck full original request/control/material and current authority at launch/publication.

    Args:
        engine: Original canonical claim owner.
        claim: Exact original opaque handle.
        request: Actual original executor request, including environment/resources/cwd.
        context: Fresh same-store current authority.
        at: Explicit aware validation clock.
        require_binding: False only for the one original exclusive bind before executor entry.

    Raises:
        ArtifactDeniedError: Claim, request, control file or current authority differs.
    """

    state = EngineState(engine).claims.get(claim)

    if state is None or state.request != request or state.finished or (
        type(require_binding) is not bool
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateLocalImageOperation(engine, state.grant, state.prepared, context, at=at)

    if PrivateDirectory(state.path.parent) != state.namespace_identity:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ReadControl(state.path, state.raw, state.identity)

    if require_binding:
        if state.binding is None:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        ReadControl(state.path.with_suffix(".launch.json"), *state.binding)


def BindLocalImageExecution(engine: ArtifactPolicyEngine, claim: LocalImageExecutionClaim,
    request: LocalExecutionRequest, context: ArtifactPolicyContext, *, at: datetime,
) -> None:
    """Exclusively bind one original request before the SDK's single executor entry.

    Args:
        engine: Original canonical claim owner.
        claim: Exact original still-unbound claim.
        request: Full original executor request.
        context: Fresh same-store authority immediately before executor entry.
        at: Explicit aware binding clock.

    Raises:
        ArtifactDeniedError: A binding exists or current authority differs.
        OSError: Exclusive immutable binding cannot be durably retained.
    """

    ValidateLocalImageClaim(engine, claim, request, context, at=at, require_binding=False)
    state = EngineState(engine).claims[claim]

    if state.binding is not None:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    try:
        state.binding = WriteControl(state.path.with_suffix(".launch.json"), {
            "family": "local-image-export-launch-v1", "request": request,
            "claim_sha256": hashlib.sha256(state.raw).hexdigest()})

    except FileExistsError:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from None


def AcceptLocalImageExecution(engine: ArtifactPolicyEngine, claim: LocalImageExecutionClaim,
    request: LocalExecutionRequest, result: LocalExecutionResult, context: ArtifactPolicyContext,
    *, at: datetime,
) -> LocalImageResolution | LocalImageArchivePin | None:
    """Accept only a current successful original command and retain its exact phase association.

    Args:
        engine: Original canonical claim owner.
        claim: Exact original opaque claim, consumed regardless of later acceptance.
        request: Original full executor request.
        result: Actual first-party executor result; inert tests replace execution explicitly.
        context: Fresh current authority after process cleanup and original-byte retention.
        at: Explicit aware acceptance clock.

    Returns:
        Original inspect resolution, verified archive pin, or None for a matching recheck.

    Raises:
        ValueError: Execution failed, original bytes are incomplete or reference/config differs.
        ArtifactDeniedError: Current original authority/claim no longer permits acceptance.
    """

    ValidateLocalImageClaim(engine, claim, request, context, at=at)
    state = EngineState(engine).claims[claim]
    prepared = state.prepared
    state.finished = True

    if type(result) is not LocalExecutionResult or result.execution.state is not (
        ExecutionState.SUCCEEDED
    ) or result.execution.exit_code != 0 or result.termination is not (
        ExecutionTermination.PROCESS_EXIT
    ) or len(result.stdout) > request.resources.max_stdout_bytes or (
        len(result.stderr) > request.resources.max_stderr_bytes
    ):
        raise ValueError("local image original command did not complete successfully")

    value: LocalImageResolution | LocalImageArchivePin | None = None

    if prepared.operation is LocalImageOperation.INSPECT:
        config_id = InspectConfigId(result.stdout)
        selected = prepared.observer.selection.reference

        if selected.startswith("sha256:") and selected != config_id:
            raise ValueError("local image original inspect differs from the selected immutable ID")

        value = LocalImageResolution(config_id, hashlib.sha256(result.stdout).hexdigest(),
                                     prepared.proof.operation_reference)
        EngineState(engine).resolutions[value] = claim

    elif prepared.resolution is None:
        raise ValueError("local image original resolution is missing")

    elif prepared.operation is LocalImageOperation.EXPORT:
        value = VerifyDockerSave(result.stdout, prepared.resolution.image_config_id)
        EngineState(engine).exports[claim] = value

    elif InspectConfigId(result.stdout) != prepared.resolution.image_config_id:
        raise ValueError("local image original reference was reassigned during export")

    state.completed = True

    return value


def ValidateCompletedLocalExport(engine: ArtifactPolicyEngine,
    claims: tuple[LocalImageExecutionClaim, ...], resolution: LocalImageResolution,
    pin: LocalImageArchivePin, context: ArtifactPolicyContext, *, at: datetime,
) -> None:
    """Recheck all original accepted phase custody immediately before archive publication.

    Args:
        engine: Original canonical owner of all three one-use claims.
        claims: Exact original inspect, export and recheck handles in that order.
        resolution: Original accepted inspect association.
        pin: Original accepted archive bytes and config identity.
        context: Fresh current same-store authority.
        at: Explicit aware final decision time.

    Raises:
        ArtifactDeniedError: Any original association, persistent control or authority changed.
    """

    authority = EngineState(engine)
    if len(claims) != 3 or authority.resolutions.get(resolution) is not claims[0] or (
        authority.exports.get(claims[1]) is not pin
    ):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    states = [authority.claims.get(claim) for claim in claims]
    for state, operation in zip(states, LocalImageOperation, strict=True):
        if state is None or not state.finished or not state.completed or (
            state.prepared.operation is not operation or state.binding is None
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)
        if operation is not LocalImageOperation.INSPECT and (
            state.prepared.resolution is not resolution
        ):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)
        ValidateLocalImageOperation(engine, state.grant, state.prepared, context, at=at)
        if PrivateDirectory(state.path.parent) != state.namespace_identity:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)
        ReadControl(state.path, state.raw, state.identity)
        ReadControl(state.path.with_suffix(".launch.json"), *state.binding)
