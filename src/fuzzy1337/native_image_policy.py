# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Additive native IMAGE authority and persistent one-use claims owned by artifact policy."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ExecutionState, ImpactLevel
from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactHandleInfo,
    ArtifactManifest,
    ArtifactPathInfo,
    ArtifactProfile,
    ArtifactRole,
    PhysicalIdentity,
)
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
)
from fuzzy1337.executors.contracts import RequireReference
from fuzzy1337.native_image_admission import NativeEvidenceStore, VerifyOperation
from fuzzy1337.native_image_bounded_capture import (
    CheckSelection,
    EncodeBounded,
    FinitePrerequisite,
    PureVersion,
)
from fuzzy1337.native_image_capture import (
    CheckVersion,
    NativeFileFact,
    NativeTrivyOperation,
    NativeTrivyOperationCapture,
    NativeTrivySelection,
)
from fuzzy1337.native_image_observation import NativeImageMaterialObserver, NativeImageMaterialProof
from fuzzy1337.policy import Digest, RequireTime
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore

NATIVE_IMAGE_SCHEMA_VERSION = 1
NATIVE_IMAGE_FAMILY = "native-image-authority-v1"
NATIVE_IMAGE_ENVIRONMENT_PROFILE = "native-image-private-scratch-v1"
NATIVE_IMAGE_CONTROL_BYTES = 64 * 1024
NATIVE_IMAGE_CAPABILITY = CapabilityDescriptor(
    "image.archive-vulnerabilities", "native.trivy", ImpactLevel.SAFE)


@dataclass(frozen=True, slots=True)
class PreparedNativeImageOperation:
    """Fixed native recipe and stable observed material; construction starts no provider."""

    operation_id: str
    operation: NativeTrivyOperation
    selection: NativeTrivySelection
    input_manifest: ArtifactManifest
    workspace_id: str
    owner_reference: str
    operation_reference: str
    invocation: AdapterInvocation
    resources: ExecutionResources
    material: tuple[NativeFileFact, ...]
    version_prerequisite: NativeImageVersionPrerequisite | None = None

    def Payload(self) -> dict[str, object]:
        """Detach only explicit finite recipe facts, never an engine or opaque claim handle.

        Returns:
            Native domain-separated request profile with no scratch chosen yet.
        """

        return {"schema_version": NATIVE_IMAGE_SCHEMA_VERSION, "family": NATIVE_IMAGE_FAMILY,
            "operation_id": self.operation_id, "operation": self.operation,
            "selection": SelectionPayload(self.selection), "input_manifest": self.input_manifest,
            "workspace_id": self.workspace_id, "owner_reference": self.owner_reference,
            "operation_reference": self.operation_reference, "invocation": self.invocation,
            "resources": self.resources, "capability": NATIVE_IMAGE_CAPABILITY,
            "environment_profile": NATIVE_IMAGE_ENVIRONMENT_PROFILE, "material": self.material,
            "version_prerequisite_sha256": None if self.version_prerequisite is None else (
                self.version_prerequisite.Digest())}


@dataclass(frozen=True, slots=True)
class NativeImageOperationPlan:
    """Separate native variant, preserving every existing synthetic schema and guard."""

    operation_id: str
    operation: NativeTrivyOperation
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
    material_sha256: str
    request_profile_sha256: str
    invocation_sha256: str
    provider_version: str | None
    granted_privileges: tuple[str, ...]
    version_prerequisite_sha256: str | None
    schema_version: int = NATIVE_IMAGE_SCHEMA_VERSION
    family: str = NATIVE_IMAGE_FAMILY
    profile: ArtifactProfile = ArtifactProfile.IMAGE
    impact: ImpactLevel = ImpactLevel.SAFE


@dataclass(frozen=True, slots=True)
class NativeImageOperationGrant:
    """Original engine-issued metadata retaining the explicit SAFE workflow approval."""

    plan: NativeImageOperationPlan
    authorization: ExecutionAuthorization
    issued_at: str
    valid_until: str
    approve_safe_image: bool


class NativeImageExecutionClaim:
    """Opaque original engine handle; copied or reconstructed objects grant no execution."""

    __slots__ = ()

    def __new__(cls) -> NativeImageExecutionClaim:
        """Refuse caller construction; only successful exclusive reservation issues a handle.

        Raises:
            ValueError: A caller attempts to construct an execution claim.
        """

        raise ValueError("native execution claims require their original issuing artifact engine")


@dataclass(frozen=True, slots=True)
class NativeImageVersionPrerequisite:
    """Original VERSION authority, claim and canonical capture, never a replay-derived grant."""

    prepared: PreparedNativeImageOperation
    grant: NativeImageOperationGrant
    claim: NativeImageExecutionClaim
    capture: NativeTrivyOperationCapture

    def Payload(self) -> dict[str, object]:
        """Bind explicit original authority and receipt identities without serializing handles.

        Returns:
            Canonical VERSION prerequisite projection independent of internal engine state.
        """

        return {"schema_version": NATIVE_IMAGE_SCHEMA_VERSION, "family": NATIVE_IMAGE_FAMILY,
            "operation_id": self.prepared.operation_id, "grant": self.grant,
            "request": self.capture.request, "capture_sha256": self.capture.Digest(),
            "records": self.capture.records, "observed_version": self.capture.observed_version}

    def Digest(self) -> str:
        """Correlate exact original prerequisite facts without issuing any authority.

        Returns:
            SHA256 of the explicit finite original VERSION prerequisite projection.
        """

        return Digest(self.Payload())


@dataclass(frozen=True, slots=True)
class NativeClaimIndex:
    """Original immutable operation or observation consumption control and physical parent."""

    path: Path
    parent_identity: tuple[int, int]
    raw: bytes
    identity: tuple[int, ...]


@dataclass(slots=True)
class NativeClaimState:
    """Private strong references and immutable persistent reservation/binding identities."""

    grant: NativeImageOperationGrant
    prepared: PreparedNativeImageOperation
    observer: NativeImageMaterialObserver
    proof: NativeImageMaterialProof
    directory: Path
    namespace_identity: tuple[int, int]
    directory_identity: tuple[int, int]
    workspace_identity: tuple[int, int]
    reservation: bytes
    reservation_identity: tuple[int, ...]
    indexes: tuple[NativeClaimIndex, NativeClaimIndex]
    request: LocalExecutionRequest | None = None
    binding: bytes | None = None
    binding_identity: tuple[int, ...] | None = None
    scratch_identity: tuple[int, int] | None = None
    capture: NativeTrivyOperationCapture | None = None
    version_prerequisite: NativeImageVersionPrerequisite | None = None


@dataclass(slots=True)
class NativeEngineState:
    """Strong engine-local original-object maps; persistent markers add cross-process exclusion."""

    grants: dict[str, NativeImageOperationGrant] = field(default_factory=dict)
    observers: dict[str, NativeImageMaterialObserver] = field(default_factory=dict)
    claims: dict[NativeImageExecutionClaim, NativeClaimState] = field(default_factory=dict)


def EngineState(engine: ArtifactPolicyEngine) -> NativeEngineState:
    """Require the canonical engine and retain its original native objects privately.

    Args:
        engine: Exact existing canonical artifact-policy owner.

    Returns:
        Strong original grant and opaque claim maps for this one engine instance.
    """

    if type(engine) is not ArtifactPolicyEngine:
        raise ValueError("native authority requires its original canonical artifact engine")

    state = getattr(engine, "_native_image_authority", None)

    if state is None:
        state = NativeEngineState()
        setattr(engine, "_native_image_authority", state)

    if type(state) is not NativeEngineState:
        raise ValueError("native authority original object map differs")

    return state


def SelectionPayload(selection: NativeTrivySelection) -> dict[str, object]:
    """Detach all selected paths and both original consent fields without selected content reads.

    Args:
        selection: Exact native selected-material declaration.

    Returns:
        Explicit canonical selection metadata independent of dataclass object internals.
    """

    return {"workspace_root": str(selection.workspace_root),
        "executable": str(selection.executable),
        "archive": selection.archive, "cache_directory": selection.cache_directory,
        "read_consent": selection.read_consent}


def NativeResources(operation: NativeTrivyOperation) -> ExecutionResources:
    """Return exactly the existing additive collector's fixed original resource profile.

    Args:
        operation: Closed native VERSION or SCAN operation.

    Returns:
        Existing finite stream and termination-grace bounds, with no caller overrides.
    """

    return ExecutionResources(max_stdout_bytes=16 * 1024, max_stderr_bytes=16 * 1024) if (
        operation is NativeTrivyOperation.VERSION) else ExecutionResources(
            max_stdout_bytes=4 * 1024 * 1024, max_stderr_bytes=1024 * 1024)


def NativeEnvironment(scratch: Path) -> dict[str, str]:
    """Bind the unchanged isolated collector environment to its one actual private scratch.

    Args:
        scratch: Explicit actual same-workspace single-component execution scratch.

    Returns:
        Exact existing native environment profile, with no inherited scanner configuration.
    """

    return {"HOME": str(scratch), "XDG_CONFIG_HOME": str(scratch),
        "XDG_CACHE_HOME": str(scratch), "TMPDIR": str(scratch), "TEMP": str(scratch),
        "TMP": str(scratch), "PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"}


def RequireProof(selection: NativeTrivySelection, observer: NativeImageMaterialObserver,
                 proof: NativeImageMaterialProof, operation_reference: str) -> None:
    """Accept only the original issued proof and cheap current facts for this exact selection.

    Args:
        selection: Exact native factory selection.
        observer: Exact first-party proof issuer, never an arbitrary material callback.
        proof: Original object issued by that observer for this whole VERSION/SCAN pair.
        operation_reference: Same non-secret owner-pair reference, not execution authority.
    """

    if type(selection) is not NativeTrivySelection or type(observer) is not (
        NativeImageMaterialObserver) or type(proof) is not NativeImageMaterialProof:
        raise ValueError("native authority requires original typed selected-material owners")

    RequireReference(operation_reference, "native image pair")

    if len(operation_reference) > 4096:
        raise ValueError("native image pair reference exceeds its bound")

    CheckSelection(observer, selection)
    observer.CheckCurrent(proof, operation_reference=operation_reference)

    if proof.facts[-2].sha256 is None or proof.facts[-1].sha256 is None or (
        proof.Metadata() is None):
        raise ArtifactDeniedError(ArtifactDenialReason.MATERIAL_CHANGED)


def PrepareNativeImageOperation(
    operation: NativeTrivyOperation, selection: NativeTrivySelection, store: LocalEvidenceStore,
    *, observer: NativeImageMaterialObserver, material_proof: NativeImageMaterialProof,
    operation_reference: str, timeout_seconds: int = 30,
    version_prerequisite: NativeImageVersionPrerequisite | None = None,
) -> PreparedNativeImageOperation:
    """Prepare only the original fixed native recipe from read-authorized issued material facts.

    Args:
        operation: Exact native VERSION or prerequisite-bound SCAN.
        selection: Explicit native workspace/archive/executable/cache and read consent.
        store: Existing same-workspace canonical raw evidence owner.
        observer: Original first-party material observer.
        material_proof: Original same-pair issued proof, never a caller hash tuple.
        operation_reference: Whole VERSION/SCAN pair reference.
        timeout_seconds: Selected SCAN deadline; VERSION always retains its three seconds.
        version_prerequisite: Original successful VERSION authority/capture association for SCAN.

    Returns:
        Frozen fixed native recipe; no grant, claim or process is created.
    """

    if type(operation) is not NativeTrivyOperation or not isinstance(store, LocalEvidenceStore):
        raise ValueError("native preparation requires the closed operation and canonical evidence")

    RequireProof(selection, observer, material_proof, operation_reference)

    if store.root != selection.workspace_root / "evidence" or (
        type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600):
        raise ValueError("native preparation workspace or deadline differs")

    if (operation is NativeTrivyOperation.VERSION and version_prerequisite is not None) or (
        operation is NativeTrivyOperation.SCAN
        and type(version_prerequisite) is not NativeImageVersionPrerequisite):
        raise ValueError("native preparation requires its original operation prerequisite")

    archive = material_proof.facts[0]
    manifest = ArtifactManifest(ArtifactProfile.IMAGE, ArtifactRole.INPUT,
        (ArtifactFile("image.tar", cast(int, archive.size_bytes), cast(str, archive.sha256)),))
    request = AdapterRequest(NATIVE_IMAGE_CAPABILITY.identifier, manifest.Target().Reference(),
        ImpactLevel.SAFE, {"archive": selection.archive,
                          "timeout_seconds": 3 if operation is NativeTrivyOperation.VERSION
                          else timeout_seconds})
    observed = (None if version_prerequisite is None else
                version_prerequisite.capture.observed_version)
    adapter = selection.Adapter(store, observed)
    invocation = adapter.PrepareVersionInvocation(request) if operation is (
        NativeTrivyOperation.VERSION) else adapter.PrepareInvocation(request)

    return PreparedNativeImageOperation("native-image-operation:" + uuid.uuid4().hex,
        operation, selection, manifest, observer.workspace_id, observer.owner_reference,
        operation_reference, invocation, NativeResources(operation), material_proof.facts,
        version_prerequisite)


def ValidatePrepared(prepared: PreparedNativeImageOperation,
                     observer: NativeImageMaterialObserver,
                     proof: NativeImageMaterialProof) -> None:
    """Rebuild every fixed factory fact without selected-file content reads.

    Args:
        prepared: Frozen native recipe proposed for authority.
        observer: Original exact selected-material owner.
        proof: Latest exact same-pair issued proof; its nonce may differ when stable facts agree.
    """

    if type(prepared) is not PreparedNativeImageOperation:
        raise ValueError("native authority requires its typed native prepared operation")

    RequireReference(prepared.operation_id, "native image operation")

    if not re.fullmatch(r"native-image-operation:[0-9a-f]{32}", prepared.operation_id):
        raise ValueError("native operation identity differs")

    rebuilt = PrepareNativeImageOperation(prepared.operation, prepared.selection,
        LocalEvidenceStore(prepared.selection.workspace_root / "evidence"), observer=observer,
        material_proof=proof, operation_reference=prepared.operation_reference,
        timeout_seconds=prepared.invocation.timeout_seconds,
        version_prerequisite=prepared.version_prerequisite)
    expected = rebuilt.Payload()
    expected["operation_id"] = prepared.operation_id

    if prepared.Payload() != expected:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    EncodeBounded(prepared.Payload(), NATIVE_IMAGE_CONTROL_BYTES)


def PlanNativeImageOperation(
    engine: ArtifactPolicyEngine, prepared: PreparedNativeImageOperation,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime,
) -> NativeImageOperationPlan:
    """Describe current native authority without execution approval, reservation or launch.

    Args:
        engine: Original canonical artifact policy engine.
        prepared: Exact fixed native recipe and registered archive manifest target.
        context: Fresh same-store scope, explicit executing owner and impact policy.
        observer: Original selected-material observer.
        material_proof: Latest original same-pair proof with unchanged stable facts.
        at: Explicit aware current decision time.

    Returns:
        Native tagged plan with complete current scope/policy and stable recipe bindings.
    """

    EngineState(engine)
    RequireTime(at)

    if type(context) is not ArtifactPolicyContext:
        raise ValueError("native authority requires its original typed policy context")

    ValidatePrepared(prepared, observer, material_proof)
    root = prepared.selection.workspace_root
    workspace = LocalWorkspaceStore(root).Open()
    scope = LocalScopeStore(root).Open(context.scope.scope_id)

    if workspace.workspace_id != prepared.workspace_id or (
        workspace.workspace_id != context.scope.workspace_id or scope != context.scope
        or context.owner_ref != prepared.owner_reference
        or context.owner_ref != prepared.selection.read_consent.actor_ref
        or context.owner_ref != observer.owner_reference
        or not scope.Check(prepared.input_manifest.Target(), at=at).Allowed()):
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    permission = next((item for item in context.policy.permissions
        if item.capability_id == NATIVE_IMAGE_CAPABILITY.identifier
        and item.adapter_id == NATIVE_IMAGE_CAPABILITY.adapter_id), None)

    if permission is None or permission.granted_privileges:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    if any(ceiling is ImpactLevel.PASSIVE for ceiling in (
        context.policy.maximum_impact, permission.maximum_impact)):
        raise ArtifactDeniedError(ArtifactDenialReason.IMPACT_DENIED)

    prerequisite = prepared.version_prerequisite

    if prerequisite is not None:
        ValidateVersionPrerequisite(engine, prerequisite, context, observer=observer,
            material_proof=material_proof, at=at)

        if prerequisite.prepared.operation_reference != prepared.operation_reference or (
            prerequisite.prepared.material != prepared.material
            or SelectionPayload(prerequisite.prepared.selection) != SelectionPayload(
                prepared.selection)):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    return NativeImageOperationPlan(prepared.operation_id, prepared.operation,
        prepared.operation_reference, workspace.workspace_id, context.owner_ref,
        scope.Reference(), scope.revision, Digest(scope.ToDict()), context.policy.Reference(),
        context.policy.revision, Digest(context.policy),
        prepared.input_manifest.Target().Reference(),
        prepared.input_manifest.Digest(), Digest({"selection": SelectionPayload(prepared.selection),
                                                 "material": prepared.material}),
        Digest(prepared.Payload()), InvocationDigest(prepared.invocation),
        prepared.invocation.provider_version, permission.granted_privileges,
        None if prerequisite is None else prerequisite.Digest())


def GrantEnvelope(plan: NativeImageOperationPlan, issued_at: str,
                  valid_until: str) -> ExecutionAuthorization:
    """Use the existing artifact authorization namespace with an explicit native discriminator.

    Args:
        plan: Original native tagged current plan.
        issued_at: Aware original issuance time.
        valid_until: Canonical exclusive expiry bounded by scope and operator policy.

    Returns:
        Exact existing executor authorization for the original invocation.
    """

    return ExecutionAuthorization("artifact-authorization:" + Digest({"native_image": plan,
        "issued_at": issued_at, "valid_until": valid_until, "approve_safe_image": True}),
        plan.scope_reference, plan.policy_reference, plan.invocation_sha256,
        plan.granted_privileges)


def Expiry(issued_at: datetime, context: ArtifactPolicyContext) -> datetime:
    """Compute the original exclusive lifetime without silently extending recorded consent.

    Args:
        issued_at: Original aware issuance time.
        context: Current exact operator policy and recorded consent.

    Returns:
        Earliest policy or consent expiry.
    """

    try:
        expiry = issued_at + timedelta(seconds=context.policy.max_authorization_seconds)

    except OverflowError as error:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from error

    if context.scope.authorization.valid_until is not None:
        expiry = min(expiry, datetime.fromisoformat(context.scope.authorization.valid_until))

    return expiry.astimezone(timezone.utc)


def AuthorizeNativeImageOperation(
    engine: ArtifactPolicyEngine, prepared: PreparedNativeImageOperation,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime, approve_safe_image: bool = False,
) -> NativeImageOperationGrant:
    """Issue original native authority only after independent permission and explicit SAFE approval.

    Args:
        engine: Original canonical artifact policy engine.
        prepared: Exact fixed operation, never a replay or capture-derived permission.
        context: Fresh registered scope, operator policy and executing owner.
        observer: Original selected-material observer.
        material_proof: Latest exact issued same-pair proof.
        at: Explicit aware issuance time.
        approve_safe_image: Exact True opt-in; it supplies no policy permission by itself.

    Returns:
        Original immutable native grant retained by its exact issuing engine.
    """

    if type(approve_safe_image) is not bool or not approve_safe_image:
        raise ArtifactDeniedError(ArtifactDenialReason.AUTHORITY_DENIED)

    plan = PlanNativeImageOperation(engine, prepared, context, observer=observer,
        material_proof=material_proof, at=at)
    issued_at = at.astimezone(timezone.utc).isoformat()
    valid_until = Expiry(at, context).isoformat()
    authorization = GrantEnvelope(plan, issued_at, valid_until)
    state = EngineState(engine)

    if authorization.authorization_id in state.grants:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    grant = NativeImageOperationGrant(plan, authorization, issued_at, valid_until, True)
    state.grants[authorization.authorization_id] = grant
    state.observers[authorization.authorization_id] = observer

    return grant


def ValidateNativeImageOperation(
    engine: ArtifactPolicyEngine, grant: NativeImageOperationGrant,
    prepared: PreparedNativeImageOperation, context: ArtifactPolicyContext,
    *, observer: NativeImageMaterialObserver, material_proof: NativeImageMaterialProof,
    at: datetime,
) -> None:
    """Revalidate original grant identity, current policy/material and exclusive lifetime.

    Args:
        engine: Same exact engine that issued the original grant.
        grant: Exact original native grant, never a reconstructed dataclass.
        prepared: Original fixed native operation recipe.
        context: Fresh same-store current scope/policy and executing owner.
        observer: Original first-party material observer.
        material_proof: Latest original same-pair proof with stable facts.
        at: Explicit aware launch or acceptance time.
    """

    RequireTime(at)

    if type(grant) is not NativeImageOperationGrant or (
        EngineState(engine).grants.get(grant.authorization.authorization_id) is not grant
        or EngineState(engine).observers.get(grant.authorization.authorization_id) is not observer
        or grant.approve_safe_image is not True):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    issued = datetime.fromisoformat(grant.issued_at)

    if not issued <= at < datetime.fromisoformat(grant.valid_until):
        raise ArtifactDeniedError(ArtifactDenialReason.GRANT_EXPIRED)

    plan = PlanNativeImageOperation(engine, prepared, context, observer=observer,
        material_proof=material_proof, at=at)

    if plan != grant.plan or Expiry(issued, context).isoformat() != grant.valid_until or (
        grant.authorization != GrantEnvelope(plan, grant.issued_at, grant.valid_until)
        or not context.scope.Check(prepared.input_manifest.Target(), at=issued).Allowed()):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)


def PrivateDirectory(path: Path) -> tuple[int, int]:
    """Require an existing physical private directory without creating or repairing it.

    Args:
        path: Explicit owned claim namespace, claim directory or execution scratch.

    Returns:
        Original device/inode identity with exact owner-only directory mode.
    """

    info = ArtifactPathInfo(path, directory=True)

    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ArtifactDeniedError(ArtifactDenialReason.STORAGE)

    return info.st_dev, info.st_ino


def SyncDirectory(path: Path) -> None:
    """Synchronize a physical private metadata directory without following a final link.

    Args:
        path: Original private directory whose new entry must be acknowledged.
    """

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_NOFOLLOW", 0))

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def ReadControl(path: Path, expected: bytes, identity: tuple[int, ...]) -> None:
    """Verify the entire bounded canonical control and physical identity, never selected content.

    Args:
        path: Original private reservation or full-request binding.
        expected: Original complete canonical bytes retained by the issuing engine.
        identity: Original device/inode/size/mtime/ctime identity after its exclusive creation.
    """

    before = ArtifactPathInfo(path)

    if PhysicalIdentity(before) != identity or stat.S_IMODE(before.st_mode) != 0o600:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_BINARY", 0))

    try:
        if PhysicalIdentity(ArtifactHandleInfo(descriptor)) != identity:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        raw = bytearray()

        while len(raw) <= NATIVE_IMAGE_CONTROL_BYTES:
            chunk = os.read(descriptor, min(4096, NATIVE_IMAGE_CONTROL_BYTES + 1 - len(raw)))

            if not chunk:
                break

            raw.extend(chunk)

        if raw != expected or PhysicalIdentity(ArtifactHandleInfo(descriptor)) != identity:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    finally:
        os.close(descriptor)

    if PhysicalIdentity(ArtifactPathInfo(path)) != identity:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)


def WriteControl(path: Path, value: object) -> tuple[bytes, tuple[int, ...]]:
    """Exclusively persist one bounded immutable canonical control, with no repair or retry.

    Args:
        path: New private file; any existing or partial file must refuse.
        value: Fixed native reservation or complete original request binding.

    Returns:
        Original canonical bytes and their physical identity after fsync and full readback.
    """

    raw = EncodeBounded(value, NATIVE_IMAGE_CONTROL_BYTES)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)

    try:
        cast(Callable[[int, int], None], getattr(os, "fchmod"))(descriptor, 0o600)
        offset = 0

        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])

            if written <= 0:
                raise OSError("native claim control write was incomplete")

            offset += written

        os.fsync(descriptor)
        identity = PhysicalIdentity(ArtifactHandleInfo(descriptor))

    finally:
        os.close(descriptor)

    SyncDirectory(path.parent)
    ReadControl(path, raw, identity)

    return raw, identity


def ConsumeIndex(
    namespace: Path, kind: str, key: str, grant: NativeImageOperationGrant,
    prepared: PreparedNativeImageOperation, proof: NativeImageMaterialProof,
    workspace_identity: tuple[int, int], namespace_identity: tuple[int, int],
) -> NativeClaimIndex:
    """Consume one operation or observation identity exclusively, never releasing partial state.

    Args:
        namespace: Original private native claim namespace.
        kind: Fixed observations or operations index, never a discovered directory.
        key: Canonical proof digest or hash of the original operation reference.
        grant: Exact original grant consuming this identity.
        prepared: Exact fixed native operation and stable material profile.
        proof: Exact issued observation object specifically consumed by this attempt.
        workspace_identity: Original physical owning workspace identity.
        namespace_identity: Original physical private namespace identity.

    Returns:
        Original bounded canonical index and physical file/parent identities after readback.
    """

    directory = namespace / kind
    directory.mkdir(mode=0o700, exist_ok=True)
    parent_identity = PrivateDirectory(directory)
    SyncDirectory(namespace)
    path = directory / (key + ".json")

    try:
        raw, identity = WriteControl(path, {
            "schema_version": NATIVE_IMAGE_SCHEMA_VERSION, "family": NATIVE_IMAGE_FAMILY,
            "profile": ArtifactProfile.IMAGE, "index_kind": kind, "index_key": key,
            "grant": grant, "prepared": prepared.Payload(), "proof_sha256": proof.Digest(),
            "observation_id": proof.observation_id, "workspace_identity": workspace_identity,
            "namespace_identity": namespace_identity, "index_directory_identity": parent_identity})

    except FileExistsError:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from None

    return NativeClaimIndex(path, parent_identity, raw, identity)


def ClaimNativeImageExecution(
    engine: ArtifactPolicyEngine, grant: NativeImageOperationGrant,
    prepared: PreparedNativeImageOperation, context: ArtifactPolicyContext,
    *, observer: NativeImageMaterialObserver, material_proof: NativeImageMaterialProof,
    at: datetime,
) -> NativeImageExecutionClaim:
    """Consume one authorized grant by durable exclusive reservation before capture/cancellation.

    Args:
        engine: Same original canonical grant issuer.
        grant: Exact original explicit-approval native grant.
        prepared: Exact original fixed operation recipe.
        context: Fresh same-store current owner/scope/policy.
        observer: Exact original proof issuer.
        material_proof: Original same-pair proof bound specifically to this claim.
        at: Explicit aware current decision time.

    Returns:
        New opaque engine handle only after durable verified exclusive reservation.
        Cancellation, setup refusal or crash afterward never releases this consumed grant.
    """

    ValidateNativeImageOperation(engine, grant, prepared, context, observer=observer,
        material_proof=material_proof, at=at)
    root = prepared.selection.workspace_root
    namespace = root / "native-image-claims"
    namespace.mkdir(mode=0o700, exist_ok=True)
    namespace_identity = PrivateDirectory(namespace)
    SyncDirectory(root)
    workspace = ArtifactPathInfo(root, directory=True)
    workspace_identity = (workspace.st_dev, workspace.st_ino)
    observation_index = ConsumeIndex(namespace, "observations", material_proof.Digest(), grant,
        prepared, material_proof, workspace_identity, namespace_identity)
    operation_index = ConsumeIndex(namespace, "operations", Digest(prepared.operation_id), grant,
        prepared, material_proof, workspace_identity, namespace_identity)
    directory = namespace / Digest(grant.authorization.authorization_id)

    try:
        directory.mkdir(mode=0o700)

    except FileExistsError:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED) from None

    directory_identity = PrivateDirectory(directory)
    SyncDirectory(namespace)
    reservation, identity = WriteControl(directory / "reservation.json", {
        "schema_version": NATIVE_IMAGE_SCHEMA_VERSION, "family": NATIVE_IMAGE_FAMILY,
        "claim_id": "native-image-claim:" + uuid.uuid4().hex,
        "grant": grant, "prepared": prepared.Payload(), "proof_sha256": material_proof.Digest(),
        "observation_id": material_proof.observation_id, "workspace_identity": workspace_identity,
        "namespace_identity": namespace_identity, "directory_identity": directory_identity})
    claim = object.__new__(NativeImageExecutionClaim)
    EngineState(engine).claims[claim] = NativeClaimState(grant, prepared, observer, material_proof,
        directory, namespace_identity, directory_identity, workspace_identity, reservation,
        identity, (observation_index, operation_index))

    return claim


def OriginalClaim(engine: ArtifactPolicyEngine,
                  claim: NativeImageExecutionClaim) -> NativeClaimState:
    """Resolve only an original opaque handle retained by this exact issuing engine.

    Args:
        engine: Original canonical owner.
        claim: Exact original object; equality, copied fields and persisted bytes are insufficient.

    Returns:
        Original private strong claim state; no persistent state is inferred as new permission.
    """

    if type(claim) is not NativeImageExecutionClaim:
        raise ValueError("native claim requires its exact original opaque handle")

    state = EngineState(engine).claims.get(claim)

    if state is None:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    return state


def CheckReservation(state: NativeClaimState) -> None:
    """Authenticate original reservation and parent identities without repairing incomplete state.

    Args:
        state: Original engine-private claim association.
    """

    workspace = ArtifactPathInfo(state.prepared.selection.workspace_root, directory=True)

    if (workspace.st_dev, workspace.st_ino) != state.workspace_identity or (
        PrivateDirectory(state.directory.parent) != state.namespace_identity
        or PrivateDirectory(state.directory) != state.directory_identity):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ReadControl(state.directory / "reservation.json", state.reservation,
                state.reservation_identity)

    for index in state.indexes:
        if index.path.parent.parent != state.directory.parent or (
            PrivateDirectory(index.path.parent) != index.parent_identity):
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        ReadControl(index.path, index.raw, index.identity)


def CheckRequest(state: NativeClaimState, request: LocalExecutionRequest,
                 *, live_scratch: bool) -> tuple[int, int] | None:
    """Validate the full actual request against the fixed profile in an explicit lifecycle phase.

    Args:
        state: Original claim and fixed native recipe.
        request: Actual first-party request, including scratch, all environment and resources.
        live_scratch: Explicit launch/READY phase; final capture validation supplies False.

    Returns:
        Physical live scratch identity for launch, otherwise None without requiring old scratch.
    """

    if type(request) is not LocalExecutionRequest or not re.fullmatch(
        r"native-image-[A-Za-z0-9_-]+", request.workspace):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    prepared = state.prepared
    scratch = prepared.selection.workspace_root / request.workspace
    expected = LocalExecutionRequest(prepared.invocation, NATIVE_IMAGE_CAPABILITY,
        state.grant.authorization, request.workspace, NativeEnvironment(scratch),
        prepared.resources)

    if request != expected:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    return PrivateDirectory(scratch) if live_scratch else None


def BindNativeImageRequest(
    engine: ArtifactPolicyEngine, claim: NativeImageExecutionClaim, request: LocalExecutionRequest,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime,
) -> None:
    """Bind a fresh attempt exactly once before its first executor startup, even for equal bytes.

    Args:
        engine: Original canonical grant/claim issuer.
        claim: Original opaque consumed execution handle.
        request: Complete actual original collector request with its private live scratch.
        context: Fresh current scope, policy and executing owner.
        observer: Exact original selected-material issuer for this claim.
        material_proof: Exact proof object captured in the original reservation.
        at: Explicit aware current first-launch time.
    """

    state = OriginalClaim(engine, claim)

    if state.request is not None or observer is not state.observer or (
        material_proof is not state.proof):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateNativeImageOperation(engine, state.grant, state.prepared, context, observer=observer,
        material_proof=material_proof, at=at)
    CheckReservation(state)
    scratch_identity = CheckRequest(state, request, live_scratch=True)
    binding, identity = WriteControl(state.directory / "binding.json", {
        "schema_version": NATIVE_IMAGE_SCHEMA_VERSION, "family": NATIVE_IMAGE_FAMILY,
        "claim_sha256": hashlib.sha256(state.reservation).hexdigest(),
        "request": request, "request_sha256": Digest(request),
        "workspace_identity": state.workspace_identity, "scratch_identity": scratch_identity,
        "proof_sha256": material_proof.Digest(), "observation_id": material_proof.observation_id})
    state.request, state.binding, state.binding_identity = request, binding, identity
    state.scratch_identity = scratch_identity


def CheckBinding(state: NativeClaimState, request: LocalExecutionRequest,
                 *, live_scratch: bool) -> None:
    """Authenticate the original once-bound full request, with an explicit live/final phase.

    Args:
        state: Original private engine claim state.
        request: Same actual request object supplied at the first successful bind.
        live_scratch: True at launch/READY; False only from explicit capture/final validation.
    """

    CheckReservation(state)

    if request is not state.request or state.binding is None or state.binding_identity is None:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    scratch_identity = CheckRequest(state, request, live_scratch=live_scratch)

    if live_scratch and scratch_identity != state.scratch_identity:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ReadControl(state.directory / "binding.json", state.binding, state.binding_identity)


def ValidateNativeImageClaim(
    engine: ArtifactPolicyEngine, claim: NativeImageExecutionClaim, request: LocalExecutionRequest,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime,
) -> None:
    """Validate only an already bound original launch, always requiring its live scratch.

    Args:
        engine: Original canonical authority owner.
        claim: Exact original reserved and bound execution handle.
        request: Exact original complete request from the first successful bind.
        context: Fresh current scope/policy and executing owner.
        observer: Exact original material issuer retained by the claim.
        material_proof: Exact original claim proof, never a reconstructed or replacement object.
        at: Explicit aware launch, READY or collector publication time.
    """

    state = OriginalClaim(engine, claim)

    if observer is not state.observer or material_proof is not state.proof:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateNativeImageOperation(engine, state.grant, state.prepared, context, observer=observer,
        material_proof=material_proof, at=at)
    CheckBinding(state, request, live_scratch=True)


def ValidateNativeImageCapture(
    engine: ArtifactPolicyEngine, claim: NativeImageExecutionClaim,
    capture: NativeTrivyOperationCapture, context: ArtifactPolicyContext,
    *, observer: NativeImageMaterialObserver, material_proof: NativeImageMaterialProof,
    at: datetime,
) -> None:
    """Authenticate an original returned capture explicitly after legitimate scratch cleanup.

    Args:
        engine: Original canonical authority owner.
        claim: Exact original bound claim for this one capture.
        capture: Returned original capture and its canonical three immutable records.
        context: Fresh current scope/policy and executing owner.
        observer: Original selected-material proof issuer.
        material_proof: Latest original same-pair proof; stable facts must still match.
        at: Explicit aware post-capture or final Save time.
    """

    state = OriginalClaim(engine, claim)

    if type(capture) is not NativeTrivyOperationCapture or observer is not state.observer or (
        state.capture is not None and capture is not state.capture):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    prepared = state.prepared
    ValidateNativeImageOperation(engine, state.grant, prepared, context, observer=observer,
        material_proof=material_proof, at=at)
    CheckBinding(state, capture.request, live_scratch=False)

    if capture.operation is not prepared.operation or (
        capture.workspace_id != prepared.workspace_id
        or
        capture.owner_reference != prepared.owner_reference or capture.refusal is not None
        or capture.outcome.execution.state is not ExecutionState.SUCCEEDED
        or capture.outcome.termination is not ExecutionTermination.PROCESS_EXIT
        or SelectionPayload(capture.selection) != SelectionPayload(prepared.selection)
        or capture.material_before != prepared.material
        or capture.material_after != prepared.material
        or capture.observed_version != prepared.invocation.provider_version
        and prepared.operation is NativeTrivyOperation.SCAN
        or capture.version_prerequisite_sha256 != (None if prepared.version_prerequisite is None
            else prepared.version_prerequisite.capture.Digest())):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    if prepared.operation is NativeTrivyOperation.VERSION:
        FinitePrerequisite(capture)
    roles = ("provider-version", "provider-version-stderr", "native-version-receipt") if (
        prepared.operation is NativeTrivyOperation.VERSION) else ("stdout", "stderr",
                                                                  "native-scan-receipt")
    expected_raw = (capture.outcome.stdout, capture.outcome.stderr,
                    EncodeBounded(capture.Envelope(), 256 * 1024 if prepared.operation is (
                        NativeTrivyOperation.VERSION) else 16 * 1024 * 1024))
    store = NativeEvidenceStore(prepared.selection.workspace_root / "evidence")

    if tuple(record.reference.role for record in capture.records) != roles:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    originals = {}

    for record, raw in zip(capture.records, expected_raw, strict=True):
        if store.Get(record.evidence_id) != record or store.Read(record.reference) != raw:
            raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

        originals[record.reference.role] = raw

    verified = VerifyOperation({record.reference.role: record for record in capture.records},
                               originals, prepared.operation.value)

    if verified.request != capture.request or verified.outcome != capture.outcome or (
        verified.envelope != capture.Envelope()):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    if prepared.operation is NativeTrivyOperation.VERSION and (
        PureVersion(capture.outcome.stdout, material_proof) != capture.observed_version):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    state.capture = capture


def ValidateVersionPrerequisite(
    engine: ArtifactPolicyEngine, prerequisite: NativeImageVersionPrerequisite,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime,
) -> None:
    """Require the original successful VERSION grant, exact claim, request and immutable receipt.

    Args:
        engine: Same engine that issued both original operations.
        prerequisite: Frozen association of original VERSION authority and canonical capture.
        context: Fresh same-store current scope/policy and executing owner.
        observer: Original first-party material issuer.
        material_proof: Latest original proof, allowing a different nonce with equal stable facts.
        at: Explicit aware SCAN or final pair time.
    """

    if type(prerequisite) is not NativeImageVersionPrerequisite:
        raise ValueError("native SCAN requires its typed original VERSION prerequisite")

    state = OriginalClaim(engine, prerequisite.claim)

    if state.version_prerequisite is not prerequisite or state.grant is not prerequisite.grant or (
        state.prepared is not prerequisite.prepared
        or prerequisite.prepared.operation is not NativeTrivyOperation.VERSION):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateNativeImageCapture(engine, prerequisite.claim, prerequisite.capture, context,
        observer=observer, material_proof=material_proof, at=at)


def ValidateNativeImagePairFresh(
    engine: ArtifactPolicyEngine, version_prerequisite: NativeImageVersionPrerequisite,
    scan_prepared: PreparedNativeImageOperation, scan_grant: NativeImageOperationGrant,
    scan_claim: NativeImageExecutionClaim, scan_capture: NativeTrivyOperationCapture,
    context: ArtifactPolicyContext, *, observer: NativeImageMaterialObserver,
    material_proof: NativeImageMaterialProof, at: datetime,
) -> None:
    """Revalidate both original authorities and captures immediately before a separate Save.

    Args:
        engine: Original canonical grant/claim issuer for the whole pair.
        version_prerequisite: Exact accepted original VERSION association.
        scan_prepared: Original independently authorized SCAN recipe.
        scan_grant: Exact distinct original SCAN grant.
        scan_claim: Exact original once-bound SCAN handle.
        scan_capture: Returned original SCAN capture and canonical records.
        context: Fresh same-store current scope/policy and executing owner.
        observer: Exact original first-party selected-material issuer.
        material_proof: Latest original issued pair proof with equal stable facts.
        at: Fresh explicit aware final validation time.
    """

    state = OriginalClaim(engine, scan_claim)

    if state.grant is not scan_grant or state.prepared is not scan_prepared or (
        scan_prepared.operation is not NativeTrivyOperation.SCAN
        or scan_prepared.version_prerequisite is not version_prerequisite
        or scan_grant.authorization.authorization_id == (
            version_prerequisite.grant.authorization.authorization_id)):
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateVersionPrerequisite(engine, version_prerequisite, context, observer=observer,
        material_proof=material_proof, at=at)
    ValidateNativeImageCapture(engine, scan_claim, scan_capture, context, observer=observer,
        material_proof=material_proof, at=at)
    CheckVersion(version_prerequisite.capture, scan_prepared.selection,
        LocalEvidenceStore(scan_prepared.selection.workspace_root / "evidence"),
        scan_grant.authorization, scan_prepared.workspace_id, scan_prepared.owner_reference,
        material_proof.facts)


def AcceptNativeImageVersion(
    engine: ArtifactPolicyEngine, claim: NativeImageExecutionClaim,
    capture: NativeTrivyOperationCapture, context: ArtifactPolicyContext,
    *, observer: NativeImageMaterialObserver, material_proof: NativeImageMaterialProof,
    at: datetime,
) -> NativeImageVersionPrerequisite:
    """Register verified original VERSION facts passed by the trusted product capture owner.

    Args:
        engine: Original canonical authority owner.
        claim: Exact original once-bound VERSION claim.
        capture: Actual returned capture supplied by its trusted product owner.
        context: Fresh current scope/policy and executing owner.
        observer: Original first-party proof issuer.
        material_proof: Latest issued same-pair proof with unchanged stable material.
        at: Explicit aware post-capture time.

    Returns:
        Original engine-retained frozen prerequisite. This association does not prove that
        an arbitrary first submitted Python object was constructed inside the collector.
    """

    state = OriginalClaim(engine, claim)

    if state.prepared.operation is not NativeTrivyOperation.VERSION:
        raise ArtifactDeniedError(ArtifactDenialReason.PLAN_CHANGED)

    ValidateNativeImageCapture(engine, claim, capture, context, observer=observer,
        material_proof=material_proof, at=at)

    if state.version_prerequisite is None:
        state.version_prerequisite = NativeImageVersionPrerequisite(
            state.prepared, state.grant, claim, capture)

    return state.version_prerequisite
