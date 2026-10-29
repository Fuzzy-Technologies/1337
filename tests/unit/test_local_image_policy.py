# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original local Docker authority and one-use claims over explicitly inert execution results."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState, ImpactLevel
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyContext,
    ArtifactPolicyEngine,
)
from fuzzy1337.executors import (
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionTermination,
    LocalExecutionResult,
)
from fuzzy1337.local_image_policy import (
    AcceptLocalImageExecution,
    AuthorizeLocalImageOperation,
    BindLocalImageExecution,
    ClaimLocalImageExecution,
    LocalImageExecutionClaim,
    LocalImageResolution,
    PlanLocalImageOperation,
    PrepareLocalImageOperation,
    ValidateLocalImageClaim,
    ValidateLocalImageOperation,
)
from fuzzy1337.local_image_reference import LOCAL_IMAGE_CAPABILITY, LocalImageOperation
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from tests.unit.test_local_image_archive import CONFIG_ID, OriginalArchive
from tests.unit.test_local_image_material import LINUX
from tests.unit.test_local_image_material import SelectedMaterial as SelectedMaterial

pytestmark = LINUX
NOW = datetime(2026, 10, 29, 12, tzinfo=UTC)


@pytest.fixture(name="original_operation")
def OriginalOperation(selected_material):
    """Prepare real current stores and explicit inert material without running any command."""

    selection, observer, _ = selected_material
    proof = observer.Observe()
    scratch = selection.workspace_root / "local-export"
    scratch.mkdir(mode=0o700)
    (scratch / "home").mkdir(mode=0o700)
    (scratch / "docker-config").mkdir(mode=0o700)
    config = scratch / "docker-config/config.json"
    config.write_bytes(b"{}\n")
    config.chmod(0o600)
    scope = LocalScopeStore(selection.workspace_root).Create(ScopeSnapshot("local",
        proof.workspace_id, ScopeAuthorization(AuthorizationState.GRANTED,
            "attester:separate", "consent:local", (NOW - timedelta(minutes=1)).isoformat(),
            (NOW + timedelta(minutes=10)).isoformat()),
        targets=(selection.Target(),), allow=(selection.Target(),)))
    permission = CapabilityPermission(LOCAL_IMAGE_CAPABILITY.identifier,
        LOCAL_IMAGE_CAPABILITY.adapter_id, ImpactLevel.SAFE,
        LOCAL_IMAGE_CAPABILITY.required_privileges)
    context = ArtifactPolicyContext(scope, ImpactPolicy("local-export", permissions=(permission,)),
                                    "actor:local")
    engine = ArtifactPolicyEngine()
    prepared = PrepareLocalImageOperation(engine, observer, proof, LocalImageOperation.INSPECT,
                                         scratch)

    return engine, prepared, context


def GrantAndBind(engine, prepared, context):
    """Use the actual policy functions while explicitly replacing only provider execution."""

    grant = AuthorizeLocalImageOperation(engine, prepared, context, at=NOW,
                                         approve_local_image=True)
    claim, request = ClaimLocalImageExecution(engine, grant, prepared, context, at=NOW)
    BindLocalImageExecution(engine, claim, request, context, at=NOW)

    return grant, claim, request


def InertResult(raw=b"", state=ExecutionState.SUCCEEDED, code=0,
                termination=ExecutionTermination.PROCESS_EXIT):
    """Create labeled no-process outcomes; they are not genuine Docker or scanner evidence."""

    events = (ExecutionEvent(0, ExecutionEventKind.COMPLETED, termination=termination),)

    return LocalExecutionResult(AdapterExecution(state, code, 0.01), termination, raw, b"", events)


def Resolve(engine, prepared, context):
    """Associate one actual-policy claim with an explicitly inert successful inspect result."""

    _, claim, request = GrantAndBind(engine, prepared, context)
    raw = json.dumps({"Id": CONFIG_ID, "Os": "linux"}).encode()

    return AcceptLocalImageExecution(engine, claim, request, InertResult(raw), context, at=NOW)


def test_ReferencePlanningGrantsNoCommandOrPersistentClaim(original_operation):
    """Descriptive current policy planning must not consume or launch the selected operation."""

    engine, prepared, context = original_operation
    plan = PlanLocalImageOperation(engine, prepared, context, at=NOW)
    assert plan.target_reference == prepared.observer.selection.Target().Reference(), (
        "The exact source descriptor must own local-export scope, never the future archive."
    )
    assert not (
        prepared.observer.selection.workspace_root / "local-image-export-claims"
    ).exists(), (
        "A descriptive reference plan must not create a claim or imply execution permission."
    )


@pytest.mark.parametrize("fault", [
    "no-approval", "no-capability", "no-privilege", "passive", "actor",
])
def test_LocalReadAuthorityRequiresIndependentPermissionAndApproval(original_operation, fault):
    """Material observation never supplies independent scope, privilege or workflow opt-in."""

    engine, prepared, context = original_operation
    approval = fault != "no-approval"

    if fault == "no-capability":
        context = replace(context, policy=replace(context.policy, permissions=()))

    elif fault == "no-privilege":
        context = replace(context, policy=replace(context.policy, permissions=(replace(
            context.policy.permissions[0], granted_privileges=()),)))

    elif fault == "passive":
        context = replace(context, policy=replace(context.policy,
                                                  maximum_impact=ImpactLevel.PASSIVE))

    elif fault == "actor":
        context = replace(context, owner_ref="actor:other")

    with pytest.raises(ArtifactDeniedError):
        AuthorizeLocalImageOperation(engine, prepared, context, at=NOW,
                                     approve_local_image=approval)


@pytest.mark.parametrize("fault", ["reconstructed", "other-engine", "exclusive-expiry", "policy"])
def test_OriginalGrantCannotBeReconstructedExtendedOrReattributed(original_operation, fault):
    """Original identity, current policy and exclusive expiry remain independent requirements."""

    engine, prepared, context = original_operation
    grant = AuthorizeLocalImageOperation(engine, prepared, context, at=NOW,
                                         approve_local_image=True)
    at = NOW

    if fault == "reconstructed":
        grant = replace(grant)

    elif fault == "other-engine":
        engine = ArtifactPolicyEngine()

    elif fault == "exclusive-expiry":
        at += timedelta(seconds=context.policy.max_authorization_seconds)

    else:
        context = replace(context, policy=replace(context.policy, revision=1))

    with pytest.raises(ArtifactDeniedError):
        ValidateLocalImageOperation(engine, grant, prepared, context, at=at)


def test_OriginalOperationAndLaunchBindingAreBothSingleUse(original_operation):
    """A new grant cannot reuse an original operation, and a claim cannot bind two launches."""

    engine, prepared, context = original_operation
    grant, claim, request = GrantAndBind(engine, prepared, context)

    with pytest.raises(ArtifactDeniedError):
        ClaimLocalImageExecution(engine, grant, prepared, context, at=NOW)

    other_grant = AuthorizeLocalImageOperation(engine, prepared, context,
        at=NOW + timedelta(seconds=1), approve_local_image=True)

    with pytest.raises(ArtifactDeniedError):
        ClaimLocalImageExecution(engine, other_grant, prepared, context,
                                 at=NOW + timedelta(seconds=1))

    with pytest.raises(ArtifactDeniedError):
        BindLocalImageExecution(engine, claim, request, context, at=NOW)


@pytest.mark.parametrize("fault", ["new-handle", "environment", "claim-bytes", "config-bytes"])
def test_FullOriginalRequestAndPhysicalControlsMustSurviveLaunch(original_operation, fault):
    """A grant or matching argv alone cannot replace its original cwd/environment/control facts."""

    engine, prepared, context = original_operation
    _, claim, request = GrantAndBind(engine, prepared, context)

    if fault == "new-handle":
        claim = LocalImageExecutionClaim()

    elif fault == "environment":
        request = replace(request, environment={**request.environment, "DOCKER_HOST": "unapproved"})

    elif fault == "claim-bytes":
        path = next((prepared.observer.selection.workspace_root / "local-image-export-claims").glob(
            "*.json"))
        path.write_bytes(b"changed original claim")

    else:
        (prepared.scratch / "docker-config/config.json").write_bytes(b"[]\n")

    with pytest.raises((ArtifactDeniedError, ValueError)):
        ValidateLocalImageClaim(engine, claim, request, context, at=NOW)


def test_OnlyOriginalAcceptedInspectCanSupplyAnImmutableExportId(original_operation):
    """A caller-constructed resolution never substitutes for original accepted inspect custody."""

    engine, prepared, context = original_operation
    forged = LocalImageResolution(CONFIG_ID, "a" * 64, prepared.proof.operation_reference)

    with pytest.raises(ValueError, match="original completed inspect"):
        PrepareLocalImageOperation(engine, prepared.observer, prepared.proof,
            LocalImageOperation.EXPORT, prepared.scratch, resolution=forged)

    resolution = Resolve(engine, prepared, context)
    exported = PrepareLocalImageOperation(engine, prepared.observer, prepared.proof,
        LocalImageOperation.EXPORT, prepared.scratch, resolution=resolution)
    assert exported.invocation.argv[-1] == CONFIG_ID, (
        "The actual export recipe must select only the original resolved immutable config ID."
    )


@pytest.mark.parametrize("fault", ["expired-inspect", "changed-policy"])
def test_NewPhaseCannotReviveExpiredOrChangedOriginalAuthority(original_operation, fault):
    """A fresh export grant cannot hide expired or changed authority for the original inspect."""

    engine, prepared, context = original_operation
    resolution = Resolve(engine, prepared, context)
    exported = PrepareLocalImageOperation(engine, prepared.observer, prepared.proof,
        LocalImageOperation.EXPORT, prepared.scratch, resolution=resolution)
    at = NOW

    if fault == "expired-inspect":
        at += timedelta(seconds=context.policy.max_authorization_seconds + 1)

    else:
        context = replace(context, policy=replace(context.policy, revision=1))

    with pytest.raises(ArtifactDeniedError):
        AuthorizeLocalImageOperation(engine, exported, context, at=at, approve_local_image=True)


@pytest.mark.parametrize("changed", [False, True], ids=["unchanged", "reassigned"])
def test_CompletedExportRequiresOriginalConfigAndFinalReferenceAgreement(
    original_operation, changed,
):
    """Even a valid by-ID archive cannot hide reassignment of the originally approved tag."""

    engine, prepared, context = original_operation
    resolution = Resolve(engine, prepared, context)
    exported = PrepareLocalImageOperation(engine, prepared.observer, prepared.proof,
        LocalImageOperation.EXPORT, prepared.scratch, resolution=resolution)
    _, claim, request = GrantAndBind(engine, exported, context)
    pin = AcceptLocalImageExecution(engine, claim, request, InertResult(OriginalArchive()),
                                    context, at=NOW)
    assert pin.image_config_id == CONFIG_ID, (
        "Only an archive containing the original inspected config bytes may be accepted."
    )
    recheck = PrepareLocalImageOperation(engine, prepared.observer, prepared.proof,
        LocalImageOperation.RECHECK, prepared.scratch, resolution=resolution)
    _, claim, request = GrantAndBind(engine, recheck, context)
    raw = json.dumps({"Id": "sha256:" + "b" * 64 if changed else CONFIG_ID, "Os": "linux"}).encode()

    if changed:
        with pytest.raises(ValueError, match="reassigned"):
            AcceptLocalImageExecution(engine, claim, request, InertResult(raw), context, at=NOW)

    else:
        assert AcceptLocalImageExecution(engine, claim, request, InertResult(raw), context,
            at=NOW) is None, (
            "The final by-reference observation must agree with the original config."
        )


@pytest.mark.parametrize("state, code, termination", [
    (ExecutionState.FAILED, 7, ExecutionTermination.PROCESS_EXIT),
    (ExecutionState.TIMED_OUT, None, ExecutionTermination.TIMEOUT),
    (ExecutionState.CANCELLED, None, ExecutionTermination.CANCELLATION),
])
def test_OriginalExecutionFailuresConsumeTheAttemptWithoutResolution(
    original_operation, state, code, termination,
):
    """Failed, timed-out or cancelled commands cannot supply an immutable export prerequisite."""

    engine, prepared, context = original_operation
    _, claim, request = GrantAndBind(engine, prepared, context)

    with pytest.raises(ValueError, match="did not complete"):
        AcceptLocalImageExecution(engine, claim, request, InertResult(
            state=state, code=code, termination=termination), context, at=NOW)

    with pytest.raises(ArtifactDeniedError):
        AcceptLocalImageExecution(engine, claim, request, InertResult(), context, at=NOW)


def test_CanonicalEngineFacadeRetainsOriginalClaimAndMandatoryBinding(original_operation):
    """All seven facade methods delegate to the same authority owner without a binding bypass."""

    engine, prepared, context = original_operation
    plan = engine.PlanLocalImageOperation(prepared, context, at=NOW)
    grant = engine.AuthorizeLocalImageOperation(prepared, context, at=NOW,
                                                approve_local_image=True)
    assert grant.plan == plan, "Facade planning and authorization must share exact authority."
    engine.ValidateLocalImageOperation(grant, prepared, context, at=NOW)
    claim, request = engine.ClaimLocalImageExecution(grant, prepared, context, at=NOW)
    with pytest.raises(ArtifactDeniedError):
        engine.ValidateLocalImageClaim(claim, request, context, at=NOW)
    engine.BindLocalImageExecution(claim, request, context, at=NOW)
    engine.ValidateLocalImageClaim(claim, request, context, at=NOW)
    result = engine.AcceptLocalImageExecution(claim, request,
        InertResult(json.dumps({"Os": "linux", "Id": CONFIG_ID}).encode()), context, at=NOW)
    assert isinstance(result, LocalImageResolution) and result.image_config_id == CONFIG_ID, (
        "The public facade must preserve original accepted inspect custody."
    )
