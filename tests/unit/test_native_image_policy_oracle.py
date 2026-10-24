# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent native authority contracts with synthetic issuances and no process execution."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import sys
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.artifact_policy import (
    ArtifactDenialReason,
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
    ValidateArtifactProfile,
)
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.native_image_capture import (
    NativeFileFact,
    NativeTrivyOperation,
    NativeTrivyOperationCapture,
    NativeTrivySelection,
)
from fuzzy1337.native_image_observation import NativeImageMaterialObserver, NativeImageMaterialProof
from fuzzy1337.native_image_policy import (
    NativeImageExecutionClaim,
    NativeImageVersionPrerequisite,
    PrepareNativeImageOperation,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

AT = datetime(2026, 10, 23, tzinfo=timezone.utc)
OWNER = "owner:native-oracle"
PAIR = "operation:native-oracle-pair"
METADATA = {"NextUpdate": "2026-06-22T20:30:14Z", "UpdatedAt": "2026-06-22T14:30:14Z", "Version": 2}
VERSION_RAW = (b'{"Version":"0.75.0","VulnerabilityDB":{"Version":2,'
               b'"UpdatedAt":"2026-06-22T14:30:14Z","NextUpdate":"2026-06-22T20:30:14Z"}}\n')
SCAN_RAW = b'{"SchemaVersion":2,"Results":[]}\n'
POSIX_MARKERS = pytest.mark.skipif(sys.platform == "win32",
    reason="Real private POSIX marker modes are not a Windows unit acceptance claim")


def Canonical(value) -> bytes:
    """Encode independent primitive expectations without the production policy serializer.

    Args:
        value: Handwritten JSON-compatible expected facts.

    Returns:
        Sorted compact UTF-8 JSON without a trailing newline.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def Sha(value) -> str:
    """Hash independent primitive expectations with the standard library.

    Args:
        value: Explicit JSON-compatible projection to identify.

    Returns:
        Lowercase SHA-256 of the independent canonical bytes.
    """

    return hashlib.sha256(Canonical(value)).hexdigest()


def Physical(path: Path) -> tuple[int, int, int, int, int]:
    """Read physical metadata of one explicitly owned tiny fixture path.

    Args:
        path: This test's exact physical selected file or private marker.

    Returns:
        Original device, inode, size, modification and change identity.
    """

    info = path.stat(follow_symlinks=False)

    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def IssueSyntheticProof(owned, nonce: str = "initial", *, facts=None):
    """Insert an explicit unit-only issuance into the original observer, without a helper.

    Args:
        owned: Closed fixture with the real observer and independently measured facts.
        nonce: Distinct finite unit observation identity.
        facts: Optional deliberately changed stable facts for negative contracts.

    Returns:
        Exact retained proof object; this does not establish real helper acceptance.
    """

    proof = NativeImageMaterialProof(owned.facts if facts is None else facts,
        Canonical(METADATA), nonce, PAIR, "native-oracle", OWNER,
        Sha({"selection": {key: value for key, value in owned.selection_fields.items()
                            if key != "read_consent"},
             "read_consent": owned.selection_fields["read_consent"],
             "workspace_id": "native-oracle", "owner_reference": OWNER}),
        Sha({"synthetic-unit-control": nonce}), (1, 2, 3, 4, 5), (1, 2),
        Physical(owned.root)[:2], 1.0)
    owned.observer._proofs[nonce] = proof

    return proof


@pytest.fixture
def owned(tmp_path, monkeypatch):
    """Create four tiny files and synthetic proof issuance; forbid processes and rehashing."""

    root = tmp_path.resolve() / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Native authority oracle"),
        "native-oracle")
    material = (("archive", "owned.tar", b"closed image archive\n"),
        ("executable", "never-executed", b"not an executable\n"),
        ("database", "cache/db/trivy.db", b"closed database\n"),
        ("database-metadata", "cache/db/metadata.json", Canonical(METADATA)))
    facts = []

    for role, name, raw in material:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        facts.append(NativeFileFact(role, str(path), len(raw), hashlib.sha256(raw).hexdigest(),
            Physical(path)))

    selection = NativeTrivySelection(root, root / "never-executed", "owned.tar", "cache",
        ArtifactReadConsent(OWNER, "read:four-owned-files"))
    selection_fields = {"workspace_root": str(root), "executable": str(selection.executable),
        "archive": "owned.tar", "cache_directory": "cache",
        "read_consent": {"actor_ref": OWNER, "record_ref": "read:four-owned-files"}}
    manifest = {"schema_version": 1, "profile": "trivy.image-archive-offline.v1",
        "role": "input", "files": [{"name": "image.tar", "size_bytes": facts[0].size_bytes,
                                     "sha256": facts[0].sha256}]}
    target = Target(TargetKind.ARTIFACT, "manifest-sha256:" + Sha(manifest))
    scope = LocalScopeStore(root).Create(ScopeSnapshot("native-oracle", "native-oracle",
        authorization=ScopeAuthorization(AuthorizationState.GRANTED, "attester:distinct-owner",
            "consent:native-oracle", AT.isoformat(), (AT + timedelta(seconds=45)).isoformat()),
        targets=(target,), allow=(target,)))
    policy = ImpactPolicy("native-oracle", maximum_impact=ImpactLevel.SAFE,
        permissions=(CapabilityPermission("image.archive-vulnerabilities", "native.trivy",
            ImpactLevel.SAFE),), max_authorization_seconds=60)
    result = SimpleNamespace(root=root, selection=selection, selection_fields=selection_fields,
        facts=tuple(facts), manifest=manifest, target=target, scope=scope, policy=policy,
        context=ArtifactPolicyContext(scope, policy, OWNER), engine=ArtifactPolicyEngine(),
        store=LocalEvidenceStore(root / "evidence"),
        observer=NativeImageMaterialObserver(selection, "native-oracle", OWNER))
    result.proof = IssueSyntheticProof(result)

    def Forbidden(*_args, **_kwargs):
        """Reject any process, helper observation or selected-content hashing in authority tests."""

        raise AssertionError("The policy oracle may only inspect issued facts and cheap metadata")

    monkeypatch.setattr(LocalExecutor, "Execute", Forbidden)
    monkeypatch.setattr(NativeImageMaterialObserver, "Observe", Forbidden)
    monkeypatch.setattr(NativeTrivySelection, "Material", Forbidden)
    monkeypatch.setattr("fuzzy1337.native_image_capture.SelectedFile", Forbidden)
    result.prepared = PrepareNativeImageOperation(NativeTrivyOperation.VERSION, selection,
        result.store, observer=result.observer, material_proof=result.proof,
        operation_reference=PAIR, timeout_seconds=997)

    return result


def Decision(owned, *, prepared=None, proof=None, at=AT):
    """Issue explicit native SAFE authority through the canonical engine.

    Args:
        owned: Current independent owned fixture.
        prepared: Optional SCAN recipe instead of initial VERSION.
        proof: Latest original synthetic unit proof.
        at: Explicit deterministic decision time.

    Returns:
        Original grant retained by the canonical engine.
    """

    return owned.engine.AuthorizeNativeImageOperation(prepared or owned.prepared, owned.context,
        observer=owned.observer, material_proof=proof or owned.proof, at=at,
        approve_safe_image=True)


def Claim(owned, grant, *, prepared=None, proof=None, at=AT):
    """Consume one grant through the original owner without entering any capture code.

    Args:
        owned: Current independent owned fixture.
        grant: Exact original issued grant.
        prepared: Optional original SCAN recipe.
        proof: Exact original proof reserved by this attempt.
        at: Explicit deterministic reservation time.

    Returns:
        Opaque once-issued claim handle after durable reservation.
    """

    return owned.engine.ClaimNativeImageExecution(grant, prepared or owned.prepared, owned.context,
        observer=owned.observer, material_proof=proof or owned.proof, at=at)


def Request(owned, grant, *, prepared=None, name="native-image-oracle"):
    """Construct the fixed full request independently of production native environment helpers.

    Args:
        owned: Current independent owned fixture.
        grant: Original authorization envelope.
        prepared: Optional SCAN recipe.
        name: Single-component owned private scratch name.

    Returns:
        Exact full request with real private scratch, but no executed process.
    """

    prepared = prepared or owned.prepared
    scratch = owned.root / name
    scratch.mkdir(mode=0o700)
    environment = {key: str(scratch) for key in
        ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP")}
    environment.update({"PATH": "", "PATHEXT": "", "LANG": "C", "LC_ALL": "C"})
    bounds = (16384, 16384) if prepared.operation is NativeTrivyOperation.VERSION else (
        4194304, 1048576)

    return LocalExecutionRequest(prepared.invocation,
        CapabilityDescriptor("image.archive-vulnerabilities", "native.trivy", ImpactLevel.SAFE),
        grant.authorization, name, environment, ExecutionResources(*bounds))


def Bind(owned, claim, request, *, proof=None, at=AT):
    """Bind one actual request through its exact original engine and proof.

    Args:
        owned: Current independent owned fixture.
        claim: Opaque original reserved attempt.
        request: Actual complete original request.
        proof: Exact proof used at reservation time.
        at: Explicit deterministic first-request time.
    """

    owned.engine.BindNativeImageRequest(claim, request, owned.context,
        observer=owned.observer, material_proof=proof or owned.proof, at=at)


def test_LiteralVersionPlanAndEnvelopeBindManifestAndAllStableFacts(owned):
    """Check the native plan against primitive handwritten projections and independent hashes."""

    prepared = owned.prepared
    target_reference = "target:" + Sha({"kind": "artifact",
        "value": "manifest-sha256:" + Sha(owned.manifest)})
    invocation = {"adapter_id": "native.trivy", "request": {
        "capability": "image.archive-vulnerabilities", "target_reference": target_reference,
        "impact": "SAFE", "parameters": {"archive": "owned.tar", "timeout_seconds": 3},
        "credential_references": []}, "argv": [str(owned.selection.executable), "--cache-dir",
        str(owned.root / "cache"), "--config=", "--version", "--format", "json"],
        "timeout_seconds": 3, "provider_version": None}
    material = [asdict(fact) for fact in owned.facts]
    manifest_dataclass = {key: value for key, value in owned.manifest.items()
                          if key != "schema_version"}
    payload = {"schema_version": 1, "family": "native-image-authority-v1",
        "operation_id": prepared.operation_id, "operation": "version",
        "selection": owned.selection_fields, "input_manifest": manifest_dataclass,
        "workspace_id": "native-oracle", "owner_reference": OWNER,
        "operation_reference": PAIR, "invocation": invocation,
        "resources": {"max_stdout_bytes": 16384, "max_stderr_bytes": 16384,
                      "terminate_grace_seconds": 1.0},
        "capability": {"identifier": "image.archive-vulnerabilities", "adapter_id": "native.trivy",
                       "maximum_impact": "SAFE", "required_privileges": []},
        "environment_profile": "native-image-private-scratch-v1", "material": material,
        "version_prerequisite_sha256": None}
    expected = {"operation_id": prepared.operation_id, "operation": "version",
        "operation_reference": PAIR, "workspace_id": "native-oracle", "owner_reference": OWNER,
        "scope_reference": "scope:native-oracle", "scope_revision": 0,
        "scope_sha256": Sha(owned.scope.ToDict()), "policy_reference": "policy:native-oracle",
        "policy_revision": 0, "policy_sha256": Sha({"policy_id": "native-oracle", "revision": 0,
            "maximum_impact": "SAFE", "permissions": [{"capability_id":
                "image.archive-vulnerabilities", "adapter_id": "native.trivy",
                "maximum_impact": "SAFE", "granted_privileges": []}],
            "max_authorization_seconds": 60}), "target_reference": target_reference,
        "input_manifest_sha256": Sha(owned.manifest),
        "material_sha256": Sha({"selection": owned.selection_fields, "material": material}),
        "request_profile_sha256": Sha(payload), "invocation_sha256": Sha(invocation),
        "provider_version": None, "granted_privileges": [],
        "version_prerequisite_sha256": None, "schema_version": 1,
        "family": "native-image-authority-v1", "profile": "trivy.image-archive-offline.v1",
        "impact": "SAFE"}
    plan = owned.engine.PlanNativeImageOperation(prepared, owned.context,
        observer=owned.observer, material_proof=owned.proof, at=AT)
    assert json.loads(SerializeContract(prepared.invocation)) == invocation, (
        "VERSION must remain unknown-version, three seconds and the exact closed native argv"
    )
    assert prepared.input_manifest.ToDict() == owned.manifest, (
        "IMAGE/INPUT identity must use logical image.tar and the original archive bytes"
    )
    assert prepared.input_manifest.Target().Reference() == target_reference, (
        "Scope must use the canonical logical manifest target rather than a selected blob hash"
    )
    assert json.loads(SerializeContract(plan)) == json.loads(Canonical(expected)), (
        "Every native plan field must match the independent material, recipe and authority hashes"
    )
    grant = Decision(owned)
    issued = AT.isoformat()
    expiry = (AT + timedelta(seconds=45)).isoformat()
    assert (grant.issued_at, grant.valid_until, grant.approve_safe_image) == (
        issued, expiry, True), (
        "Grant lifetime must stop at recorded consent before the longer operator policy lifetime"
    )
    assert grant.authorization.authorization_id == "artifact-authorization:" + Sha({
        "native_image": expected, "issued_at": issued, "valid_until": expiry,
        "approve_safe_image": True}), "Native authorization must bind the full tagged approved plan"
    assert not (owned.root / "native-image-claims").exists(), (
        "Pure planning and approval must not consume a reservation or start execution"
    )


@pytest.mark.parametrize("approval", [False, 1, "yes", None])
def test_ExplicitSafeApprovalRequiresTheExactBoolean(owned, approval):
    """A policy allow entry alone and truthy substitutes cannot approve native SAFE work."""

    with pytest.raises(ArtifactDeniedError):
        owned.engine.AuthorizeNativeImageOperation(owned.prepared, owned.context,
            observer=owned.observer, material_proof=owned.proof, at=AT, approve_safe_image=approval)


@pytest.mark.parametrize("change", ["no-permission", "synthetic-permission", "passive", "owner"])
def test_ApprovalCannotReplaceFreshNativePermissionAndExecutingOwner(owned, change):
    """Recorded attester semantics remain separate from the executing read-authorized actor."""

    policy = owned.policy
    owner = OWNER

    if change in {"no-permission", "synthetic-permission"}:
        policy = replace(policy, permissions=() if change == "no-permission" else (
            CapabilityPermission("image.archive-vulnerabilities", "synthetic.artifact",
                ImpactLevel.SAFE),))

    elif change == "passive":
        policy = replace(policy, maximum_impact=ImpactLevel.PASSIVE)

    else:
        owner = "owner:another"

    with pytest.raises(ArtifactDeniedError):
        owned.engine.AuthorizeNativeImageOperation(owned.prepared,
            ArtifactPolicyContext(owned.scope, policy, owner), observer=owned.observer,
            material_proof=owned.proof, at=AT, approve_safe_image=True)


def test_NativePermissionCannotAddPrivilegesOutsideTheOriginalReceiptProfile(owned):
    """Refuse incompatible surplus authority before issuing an unusable native plan or grant."""

    permission = replace(owned.policy.permissions[0], granted_privileges=("filesystem-read",))
    context = replace(owned.context, policy=replace(owned.policy, permissions=(permission,)))

    with pytest.raises(ArtifactDeniedError):
        owned.engine.PlanNativeImageOperation(owned.prepared, context, observer=owned.observer,
            material_proof=owned.proof, at=AT)

    with pytest.raises(ArtifactDeniedError):
        owned.engine.AuthorizeNativeImageOperation(owned.prepared, context, observer=owned.observer,
            material_proof=owned.proof, at=AT, approve_safe_image=True)

    assert not (owned.root / "native-image-claims").exists(), (
        "Incompatible privilege attribution must be refused before any attempt is consumed"
    )


@pytest.mark.parametrize("change", [
    "expiry", "same-revision-policy", "revocation", "scope-content",
])
def test_CurrentContentAndExclusiveExpiryInvalidateOriginalAuthority(owned, change):
    """A valid original grant cannot authorize work after content or recorded authority changes."""

    grant = Decision(owned)
    context = owned.context
    at = AT

    if change == "expiry":
        at += timedelta(seconds=45)

    elif change == "same-revision-policy":
        context = replace(context, policy=replace(owned.policy,
            maximum_impact=ImpactLevel.STANDARD))

    else:
        authorization = replace(owned.scope.authorization, **(
            {"state": AuthorizationState.REVOKED} if change == "revocation" else
            {"record_reference": "consent:changed-at-same-scope"}))
        updated = LocalScopeStore(owned.root).Save(replace(owned.scope,
            authorization=authorization))
        context = replace(context, scope=updated)

        with pytest.raises(ArtifactDeniedError):
            owned.engine.ValidateNativeImageOperation(grant, owned.prepared, owned.context,
                observer=owned.observer, material_proof=owned.proof, at=at)

    with pytest.raises(ArtifactDeniedError):
        owned.engine.ValidateNativeImageOperation(grant, owned.prepared, context,
            observer=owned.observer, material_proof=owned.proof, at=at)


def test_OriginalProofAndGrantIdentityAllowFreshNonceButRejectChangedStableFacts(owned):
    """Fresh observation correlation does not change authority when four stable facts agree."""

    grant = Decision(owned)
    fresh = IssueSyntheticProof(owned, "post-version")
    owned.engine.ValidateNativeImageOperation(grant, owned.prepared, owned.context,
        observer=owned.observer, material_proof=fresh, at=AT)
    assert fresh.Digest() != owned.proof.Digest(), (
        "Fresh issued observations need distinct correlation"
    )

    for proof in (replace(owned.proof), owned.proof.facts):
        with pytest.raises(ValueError):
            owned.engine.ValidateNativeImageOperation(grant, owned.prepared, owned.context,
                observer=owned.observer, material_proof=proof, at=AT)

    changed = IssueSyntheticProof(owned, "changed-material", facts=(
        replace(owned.facts[0], sha256="f" * 64), *owned.facts[1:]))

    with pytest.raises(ArtifactDeniedError):
        owned.engine.ValidateNativeImageOperation(grant, owned.prepared, owned.context,
            observer=owned.observer, material_proof=changed, at=AT)

    for engine, candidate in ((owned.engine, replace(grant)), (ArtifactPolicyEngine(), grant)):
        with pytest.raises(ArtifactDeniedError):
            engine.ValidateNativeImageOperation(candidate, owned.prepared, owned.context,
                observer=owned.observer, material_proof=owned.proof, at=AT)


@POSIX_MARKERS
def test_ReservationIsPrivateDurableAndExclusiveAcrossFreshEngines(owned):
    """Reserve before capture and refuse duplicate, reopened and partially written attempts."""

    grant = Decision(owned)
    claim = Claim(owned, grant)
    namespace = owned.root / "native-image-claims"
    directory = namespace / Sha(grant.authorization.authorization_id)
    marker = directory / "reservation.json"
    raw = marker.read_bytes()
    payload = json.loads(raw)
    assert type(claim) is NativeImageExecutionClaim and raw == Canonical(payload), (
        "Claim must be an opaque owner handle backed by exact canonical persistent bytes"
    )
    assert stat.S_IMODE(namespace.stat().st_mode) == 0o700 and (
        stat.S_IMODE(directory.stat().st_mode) == 0o700
        and stat.S_IMODE(marker.stat().st_mode) == 0o600
    ), "Exclusive authority markers must retain private directory and file permissions"
    assert set(payload) == {"schema_version", "family", "claim_id", "grant", "prepared",
        "proof_sha256", "observation_id", "workspace_identity", "namespace_identity",
        "directory_identity"}, "Reservation control must retain only its closed identity fields"
    assert payload["proof_sha256"] == owned.proof.Digest() and (
        payload["observation_id"] == "initial"
        and payload["workspace_identity"] == list(Physical(owned.root)[:2])
        and payload["namespace_identity"] == list(Physical(namespace)[:2])
        and payload["directory_identity"] == list(Physical(directory)[:2])
    ), "Reservation must bind its exact issued observation and physical owning directories"

    with pytest.raises(ArtifactDeniedError):
        Claim(owned, grant)

    owned.engine = ArtifactPolicyEngine()
    reopened_grant = Decision(owned)
    assert reopened_grant == grant and reopened_grant is not grant, (
        "Equivalent new owner approval must still collide with the durably consumed authorization"
    )

    with pytest.raises(ArtifactDeniedError):
        Claim(owned, reopened_grant)

    assert marker.read_bytes() == raw and not (directory / "binding.json").exists(), (
        "Duplicate or cancelled-before-capture attempts must not repair, reset or bind the marker"
    )
    marker.unlink()

    with pytest.raises(ArtifactDeniedError):
        Claim(owned, reopened_grant)

    assert not marker.exists(), (
        "A partial existing claim directory must never be repaired for retry"
    )


@POSIX_MARKERS
@pytest.mark.parametrize("reuse", ["operation-and-proof", "operation", "proof"])
@pytest.mark.parametrize("fresh_engine", [False, True])
def test_LaterApprovalCannotReuseAConsumedOperationOrObservation(owned, reuse, fresh_engine):
    """Distinct later grants cannot resume consumed attempts, including another engine owner."""

    original_grant = Decision(owned)
    Claim(owned, original_grant)
    namespace = owned.root / "native-image-claims"
    originals = {path: (path.read_bytes(), Physical(path))
        for path in namespace.rglob("*.json")}
    reservation = (namespace / Sha(original_grant.authorization.authorization_id)
        / "reservation.json")
    indexes = {"observations": owned.proof.Digest(), "operations": Sha(owned.prepared.operation_id)}
    assert set(originals) == {reservation, *(namespace / kind / (key + ".json")
        for kind, key in indexes.items())}, (
        "A claim must consume exactly one original grant, operation and issued observation"
    )

    for kind, key in indexes.items():
        path = namespace / kind / (key + ".json")
        raw = originals[path][0]
        payload = json.loads(raw)
        assert len(raw) <= 65536 and raw == Canonical(payload) and set(payload) == {
            "schema_version", "family", "profile", "index_kind", "index_key", "grant",
            "prepared", "proof_sha256", "observation_id", "workspace_identity",
            "namespace_identity", "index_directory_identity",
        }, "Each consumption index must use the exact finite immutable canonical control schema"
        assert (payload["schema_version"], payload["family"], payload["profile"],
            payload["index_kind"], payload["index_key"], payload["proof_sha256"],
            payload["observation_id"]) == (1, "native-image-authority-v1",
            "trivy.image-archive-offline.v1", kind, key, owned.proof.Digest(), "initial"), (
            "Index path and original proof correlation must match the handwritten closed identities"
        )
        assert payload["grant"] == json.loads(SerializeContract(original_grant)) and (
            payload["prepared"] == json.loads(reservation.read_bytes())["prepared"]
            and payload["workspace_identity"] == list(Physical(owned.root)[:2])
            and payload["namespace_identity"] == list(Physical(namespace)[:2])
            and payload["index_directory_identity"] == list(Physical(path.parent)[:2])
        ), "Each index must bind its original decision, recipe and physical owning directories"
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700 and (
            stat.S_IMODE(path.stat().st_mode) == 0o600
        ), "Consumption indexes require private physical parent and file permissions"

    proof = IssueSyntheticProof(owned, "fresh-retry") if reuse == "operation" else owned.proof
    prepared = PrepareNativeImageOperation(NativeTrivyOperation.VERSION, owned.selection,
        owned.store, observer=owned.observer, material_proof=proof, operation_reference=PAIR) if (
            reuse == "proof") else owned.prepared

    if fresh_engine:
        owned.engine = ArtifactPolicyEngine()

    later = AT + timedelta(seconds=1)
    retry_grant = Decision(owned, prepared=prepared, proof=proof, at=later)
    assert retry_grant.authorization.authorization_id != (
        original_grant.authorization.authorization_id), (
        "The refused retry must have a distinct legitimately issued later grant"
    )

    with pytest.raises((ArtifactDeniedError, FileExistsError)):
        Claim(owned, retry_grant, prepared=prepared, proof=proof, at=later)

    for path, (raw, identity) in originals.items():
        assert path.read_bytes() == raw and Physical(path) == identity, (
            "A later grant must not rewrite or replace any consumed original claim control"
        )

    assert not (namespace / Sha(retry_grant.authorization.authorization_id)).exists(), (
        "A reused operation or observation must refuse before a new grant reservation is issued"
    )


@POSIX_MARKERS
@pytest.mark.parametrize("kind", ["observations", "operations"])
def test_PartialConsumptionIndexesAreNeverRepairedOrAdopted(owned, kind):
    """An incomplete observation or operation index stays consumed across newly issued grants."""

    namespace = owned.root / "native-image-claims"
    directory = namespace / kind
    namespace.mkdir(mode=0o700)
    directory.mkdir(mode=0o700)
    key = owned.proof.Digest() if kind == "observations" else Sha(owned.prepared.operation_id)
    marker = directory / (key + ".json")
    raw = b'{"schema_version":'
    marker.write_bytes(raw)
    marker.chmod(0o600)
    identity = Physical(marker)

    for fresh_engine in (False, True):
        if fresh_engine:
            owned.engine = ArtifactPolicyEngine()

        at = AT + timedelta(seconds=int(fresh_engine))
        grant = Decision(owned, at=at)

        with pytest.raises((ArtifactDeniedError, FileExistsError)):
            Claim(owned, grant, at=at)

        assert marker.read_bytes() == raw and Physical(marker) == identity, (
            "An incomplete consumed index must remain untouched, including after a fresh approval"
        )
        assert not (namespace / Sha(grant.authorization.authorization_id)).exists(), (
            "A partial index must refuse authority before publishing any grant reservation"
        )


@POSIX_MARKERS
@pytest.mark.parametrize("change", ["env", "resources", "argv", "authorization", "workspace"])
def test_FirstBindingChecksTheFullActualRequestBeforePersisting(owned, change):
    """Invocation-only identity cannot hide changed environment, resources or actual scratch."""

    grant = Decision(owned)
    claim = Claim(owned, grant)
    request = Request(owned, grant)
    candidate = request

    if change == "env":
        candidate = replace(request, environment={**request.environment,
            "TRIVY_SERVER": "forbidden"})

    elif change == "resources":
        candidate = replace(request, resources=replace(request.resources, max_stdout_bytes=16385))

    elif change == "argv":
        invocation = replace(request.invocation, argv=(*request.invocation.argv, "--debug"))
        candidate = replace(request, invocation=invocation,
            authorization=replace(request.authorization,
                invocation_sha256=InvocationDigest(invocation)))

    elif change == "authorization":
        candidate = replace(request, authorization=replace(request.authorization,
            authorization_id="artifact-authorization:" + "a" * 64))

    else:
        candidate = replace(request, workspace="native-image-parent/child")

    with pytest.raises(ArtifactDeniedError):
        Bind(owned, claim, candidate)

    directory = owned.root / "native-image-claims" / Sha(grant.authorization.authorization_id)
    assert not (directory / "binding.json").exists(), (
        "A refused request must never publish a binding"
    )
    Bind(owned, claim, request)
    binding = json.loads((directory / "binding.json").read_bytes())
    assert binding["request"] == json.loads(SerializeContract(request)) and (
        binding["request_sha256"] == Sha(binding["request"])
        and binding["scratch_identity"] == list(Physical(owned.root / request.workspace)[:2])
    ), "Binding must persist the entire exact actual request and real private scratch identity"


@POSIX_MARKERS
def test_PreexistingIdenticalBindingIsNotAnIdempotentRetry(owned):
    """An existing exact binding marker must refuse first binding without repair or adoption."""

    grant = Decision(owned)
    claim = Claim(owned, grant)
    request = Request(owned, grant)
    directory = owned.root / "native-image-claims" / Sha(grant.authorization.authorization_id)
    reservation = (directory / "reservation.json").read_bytes()
    request_payload = json.loads(SerializeContract(request))
    expected = {"schema_version": 1, "family": "native-image-authority-v1",
        "claim_sha256": hashlib.sha256(reservation).hexdigest(), "request": request_payload,
        "request_sha256": Sha(request_payload),
        "workspace_identity": Physical(owned.root)[:2],
        "scratch_identity": Physical(owned.root / request.workspace)[:2],
        "proof_sha256": owned.proof.Digest(), "observation_id": "initial"}
    marker = directory / "binding.json"
    raw = Canonical(expected)
    marker.write_bytes(raw)
    marker.chmod(0o600)
    original_identity = Physical(marker)

    with pytest.raises(FileExistsError):
        Bind(owned, claim, request)

    assert marker.read_bytes() == raw and Physical(marker) == original_identity, (
        "An existing identical binding must stay untouched and cannot issue live request authority"
    )


@POSIX_MARKERS
def test_BindingIsOnceOnlyAndReadyChecksRequireOriginalLiveScratch(owned):
    """READY authority needs the original handle, request, issuer and live physical scratch."""

    grant = Decision(owned)
    claim = Claim(owned, grant)
    request = Request(owned, grant)
    Bind(owned, claim, request)

    with pytest.raises(ArtifactDeniedError):
        Bind(owned, claim, request)

    owned.engine.ValidateNativeImageClaim(claim, request, owned.context,
        observer=owned.observer, material_proof=owned.proof, at=AT)

    for engine, handle, candidate in (
        (owned.engine, object.__new__(NativeImageExecutionClaim), request),
        (ArtifactPolicyEngine(), claim, request), (owned.engine, claim, replace(request)),
    ):
        with pytest.raises(ArtifactDeniedError):
            engine.ValidateNativeImageClaim(handle, candidate, owned.context,
                observer=owned.observer, material_proof=owned.proof, at=AT)

    fresh = IssueSyntheticProof(owned, "post-request")

    with pytest.raises(ArtifactDeniedError):
        owned.engine.ValidateNativeImageClaim(claim, request, owned.context,
            observer=owned.observer, material_proof=fresh, at=AT)

    shutil.rmtree(owned.root / request.workspace)

    with pytest.raises((ArtifactDeniedError, OSError, ValueError)):
        owned.engine.ValidateNativeImageClaim(claim, request, owned.context,
            observer=owned.observer, material_proof=owned.proof, at=AT)


def SyntheticCapture(owned, prepared, grant, request):
    """Publish closed simulated original records without running any executable or helper.

    Args:
        owned: Current independent fixture and canonical evidence store.
        prepared: Original fixed VERSION or SCAN recipe.
        grant: Exact separately issued authority.
        request: Original once-bound full request.

    Returns:
        Explicitly simulated native capture with original stream and receipt records.
    """

    version = prepared.operation is NativeTrivyOperation.VERSION
    stdout = VERSION_RAW if version else SCAN_RAW
    stderr = b"owned synthetic unit stderr\n"
    outcome = LocalExecutionResult(AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01),
        ExecutionTermination.PROCESS_EXIT, stdout, stderr, (
            ExecutionEvent(0, ExecutionEventKind.STARTED),
            ExecutionEvent(1, ExecutionEventKind.STDOUT, stdout),
            ExecutionEvent(2, ExecutionEventKind.STDERR, stderr),
            ExecutionEvent(3, ExecutionEventKind.COMPLETED,
                termination=ExecutionTermination.PROCESS_EXIT)))
    started = datetime.fromisoformat(grant.issued_at)
    start = started.isoformat(timespec="microseconds")
    end = (started + timedelta(milliseconds=10)).isoformat(timespec="microseconds")
    provenance = EvidenceProvenance("native-oracle", "scope:native-oracle", "native.trivy", "1",
        "0.75.0", start, end, InvocationDigest(prepared.invocation), outcome.execution)
    roles = ("provider-version", "provider-version-stderr", "native-version-receipt") if (
        version) else ("stdout", "stderr", "native-scan-receipt")
    streams = tuple(owned.store.Put(raw, role, media, provenance)
        for role, raw, media in zip(roles[:2], (stdout, stderr),
            ("application/json", "text/plain"), strict=True))
    capture = NativeTrivyOperationCapture(prepared.operation, request, outcome, "native-oracle",
        OWNER, owned.selection, owned.facts, owned.facts, start, end,
        None if version else prepared.version_prerequisite.capture.Digest(),
        "0.75.0", None, streams)
    receipt = owned.store.Put(SerializeContract(capture.Envelope()).encode(), roles[2],
        "application/json", provenance)
    assert grant.authorization is request.authorization, (
        "Synthetic original custody must preserve the exact separately issued original authority"
    )

    return replace(capture, records=(*streams, receipt))


@POSIX_MARKERS
def test_OriginalVersionPrerequisiteAndPairRemainFreshAfterScratchCleanup(owned):
    """Validate simulated original custody across fresh proof nonces and legitimate cleanup."""

    version_grant = Decision(owned)
    version_claim = Claim(owned, version_grant)
    version_request = Request(owned, version_grant, name="native-image-version")
    Bind(owned, version_claim, version_request)
    version_capture = SyntheticCapture(owned, owned.prepared, version_grant, version_request)
    shutil.rmtree(owned.root / version_request.workspace)
    post_version = IssueSyntheticProof(owned, "post-version")
    scan_at = AT + timedelta(seconds=1)
    prerequisite = owned.engine.AcceptNativeImageVersion(version_claim, version_capture,
        owned.context, observer=owned.observer, material_proof=post_version, at=scan_at)

    for substituted in (replace(prerequisite), NativeImageVersionPrerequisite(
        owned.prepared, version_grant, version_claim, version_capture)):
        prepared = PrepareNativeImageOperation(NativeTrivyOperation.SCAN, owned.selection,
            owned.store, observer=owned.observer, material_proof=post_version,
            operation_reference=PAIR, version_prerequisite=substituted, timeout_seconds=3)

        with pytest.raises(ArtifactDeniedError):
            Decision(owned, prepared=prepared, proof=post_version, at=scan_at)

    scan = PrepareNativeImageOperation(NativeTrivyOperation.SCAN, owned.selection, owned.store,
        observer=owned.observer, material_proof=post_version, operation_reference=PAIR,
        version_prerequisite=prerequisite, timeout_seconds=3)
    expected_tail = ("image", "--input", str(owned.root / "owned.tar"), "--format", "json",
        "--scanners", "vuln", "--disable-telemetry", "--offline-scan", "--skip-db-update",
        "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
        "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs", "--exit-code", "0",
        "--no-progress", "--timeout", "3s")
    assert scan.invocation.argv == (str(owned.selection.executable), "--cache-dir",
        str(owned.root / "cache"), "--config=", *expected_tail), (
        "Native SCAN must use the fixed offline original archive recipe and no caller command"
    )
    assert scan.invocation.provider_version == "0.75.0", (
        "SCAN version comes only from the exact original accepted VERSION association"
    )
    scan_grant = Decision(owned, prepared=scan, proof=post_version, at=scan_at)
    scan_claim = Claim(owned, scan_grant, prepared=scan, proof=post_version, at=scan_at)
    scan_request = Request(owned, scan_grant, prepared=scan, name="native-image-scan")
    Bind(owned, scan_claim, scan_request, proof=post_version, at=scan_at)
    scan_capture = SyntheticCapture(owned, scan, scan_grant, scan_request)
    shutil.rmtree(owned.root / scan_request.workspace)
    post_scan = IssueSyntheticProof(owned, "post-scan")
    final_at = AT + timedelta(seconds=2)
    owned.engine.ValidateNativeImagePairFresh(prerequisite, scan, scan_grant, scan_claim,
        scan_capture, owned.context, observer=owned.observer, material_proof=post_scan, at=final_at)
    assert version_grant.authorization.authorization_id != (
        scan_grant.authorization.authorization_id), (
        "VERSION and SCAN must retain distinct original separately consumed authorizations"
    )
    assert tuple(record.reference.role for record in (*version_capture.records,
        *scan_capture.records)) == ("provider-version", "provider-version-stderr",
        "native-version-receipt", "stdout", "stderr", "native-scan-receipt"), (
        "Final authority validation must retain all six original canonical evidence roles"
    )

    with pytest.raises(ArtifactDeniedError):
        owned.engine.ValidateNativeImagePairFresh(prerequisite, scan, scan_grant, scan_claim,
            replace(scan_capture), owned.context, observer=owned.observer,
            material_proof=post_scan, at=final_at)

    directory = owned.root / "native-image-claims" / Sha(scan_grant.authorization.authorization_id)
    (directory / "binding.json").unlink()

    with pytest.raises((ArtifactDeniedError, OSError, ValueError)):
        owned.engine.ValidateNativeImagePairFresh(prerequisite, scan, scan_grant, scan_claim,
            scan_capture, owned.context, observer=owned.observer,
            material_proof=post_scan, at=final_at)


def test_NewNativePreparationCannotEnterTheExistingSyntheticProfileGate(owned):
    """The additive native authority surface leaves the old synthetic profile guard closed."""

    stage = SimpleNamespace(input=SimpleNamespace(manifest=owned.prepared.input_manifest))

    with pytest.raises(ArtifactDeniedError) as failure:
        ValidateArtifactProfile(stage)

    assert failure.value.reason is ArtifactDenialReason.NATIVE_UNAVAILABLE, (
        "The existing synthetic owner must continue rejecting the native IMAGE profile"
    )
