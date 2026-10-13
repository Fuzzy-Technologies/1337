# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure artifact authority, closed producer/runtime and exact request binding regressions."""

from __future__ import annotations

import inspect
import stat
from dataclasses import replace
from datetime import timedelta

import pytest
from artifact_helpers import AT, OwnedArtifact

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactSelection, ArtifactStage
from fuzzy1337.artifact_policy import (
    ArtifactDeniedError,
    ArtifactPolicyEngine,
    GovernedArtifactExecutor,
    PrepareArtifact,
    ProfileCapability,
)
from fuzzy1337.executors import ExecutionResources
from fuzzy1337.policy import PolicyContext, PolicyDeniedError, PolicyEngine
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, Target, TargetKind


@pytest.mark.parametrize(
    "change",
    [
        "scope-content",
        "scope-revision",
        "owner",
        "policy-content",
        "policy-revision",
        "permission",
        "excluded",
        "expired",
        "revoked",
    ],
)
def test_FreshGrantRejectsEveryChangedAuthorityBinding(tmp_path, change):
    """Same-revision changes, policy changes and actual stored revocation fail closed."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    changed = context

    if change in {"scope-content", "scope-revision", "excluded", "revoked"}:
        scope = context.scope

        if change == "scope-content":
            scope = replace(
                scope, authorization=replace(scope.authorization, record_reference="consent:other")
            )

        elif change == "scope-revision":
            scope = replace(scope, revision=scope.revision + 1)

        elif change == "excluded":
            scope = replace(scope, exclusions=(stage.input.manifest.Target(),))

        else:
            scope = replace(
                scope, authorization=replace(scope.authorization, state=AuthorizationState.REVOKED)
            )

        changed = replace(context, scope=scope)

    elif change == "owner":
        changed = replace(context, owner_ref="owner:replacement")

    elif change == "policy-content":
        changed = replace(context, policy=replace(context.policy, max_authorization_seconds=10))

    elif change == "policy-revision":
        changed = replace(context, policy=replace(context.policy, revision=1))

    elif change == "permission":
        changed = replace(context, policy=replace(context.policy, permissions=()))

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(
            grant,
            prepared,
            stage,
            changed,
            at=AT + timedelta(hours=2) if change == "expired" else AT,
        )

    assert context.scope.authorization.authority_reference != context.owner_ref, (
        "Fixture must preserve attester-versus-executor distinction"
    )


@pytest.mark.parametrize(
    "change",
    [
        "argv",
        "parameters",
        "env",
        "workspace",
        "stdout-limit",
        "timeout",
        "capability",
        "provider",
        "envelope",
    ],
)
def test_ExactRequestCannotBeSubstituted(tmp_path, change):
    """Fields omitted by legacy InvocationDigest are still in the artifact grant."""

    _, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    invocation = prepared.invocation
    changed = prepared

    if change == "argv":
        changed = replace(
            prepared,
            invocation=replace(invocation, argv=invocation.argv + ("--server=owned-invalid",)),
        )

    elif change == "parameters":
        changed = replace(
            prepared,
            invocation=replace(invocation, request=replace(invocation.request, parameters={})),
        )

    elif change == "env":
        changed = replace(
            prepared, environment={**prepared.environment, "TRIVY_SERVER": "owned-invalid"}
        )

    elif change == "workspace":
        changed = replace(prepared, workspace=".")

    elif change == "stdout-limit":
        changed = replace(prepared, resources=replace(prepared.resources, max_stdout_bytes=1024))

    elif change == "timeout":
        changed = replace(prepared, invocation=replace(invocation, timeout_seconds=1))

    elif change == "capability":
        changed = replace(
            prepared, capability=replace(prepared.capability, identifier="arbitrary.command")
        )

    elif change == "provider":
        changed = replace(prepared, invocation=replace(invocation, adapter_id="native.trivy"))

    else:
        grant = replace(
            grant, authorization=replace(grant.authorization, authorization_id="other:grant")
        )

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, changed, stage, context, at=AT)


@pytest.mark.parametrize(
    "native", [ArtifactProfile.IMAGE, ArtifactProfile.DOCKERFILE, ArtifactProfile.KUBERNETES]
)
def test_NativeMetadataCannotAuthorizeEvenWithPinnedMaterial(tmp_path, native):
    """Attested version strings and copied bytes never substitute for real native acceptance."""

    _, stage, prepared, context, _ = OwnedArtifact(tmp_path)
    stage = replace(
        stage, input=replace(stage.input, manifest=replace(stage.input.manifest, profile=native))
    )

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(stage, prepared.workspace_root)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Authorize(prepared, stage, context, at=AT)

    assert ProfileCapability(native).adapter_id == "native.trivy", "Native metadata was relabeled"


def test_ArbitraryProducerAndExecutableSubstitutionCannotBecomeSafe(tmp_path):
    """Pinned caller code and a caller executable are rejected independently of file hashes."""

    root, stage, prepared, _, _ = OwnedArtifact(tmp_path)
    hostile = tmp_path.resolve() / "arbitrary.py"
    hostile.write_text("raise SystemExit('owned-denied-program')\n")
    original = stage.input.directory / "image.tar"
    material = stage.material.directory / "policy.json"
    alternate = ArtifactStage.Create(
        root / "other-stage",
        stage.input.manifest.profile,
        stage.input.consent,
        (ArtifactSelection("image.tar", original),),
        ArtifactSelection("executable", stage.executable),
        stage.version,
        producer=ArtifactSelection("producer.py", hostile),
        material=(ArtifactSelection("policy.json", material),),
    )

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(alternate, root)

    fake_runtime = tmp_path.resolve() / "fake-runtime"
    fake_runtime.write_bytes(b"owned-invalid-executable")

    with pytest.raises(ArtifactDeniedError):
        PrepareArtifact(replace(stage, executable=fake_runtime), prepared.workspace_root)


def test_NetworkContextAndIssuanceCannotUseArtifactAuthority(tmp_path):
    """Allowed literal IPs cannot turn artifact targets into network authority."""

    _, stage, _, context, _ = OwnedArtifact(tmp_path)
    target = stage.input.manifest.Target()
    ip = Target(TargetKind.IP, "192.0.2.1")

    with pytest.raises(ValueError):
        PolicyContext(context.scope, context.policy, target, (ip,))

    network = PolicyContext(context.scope, context.policy, ip, (ip,))
    object.__setattr__(network, "target", target)
    capability = ProfileCapability(ArtifactProfile.IMAGE)
    invocation = AdapterInvocation(
        "native.trivy",
        AdapterRequest(capability.identifier, target.Reference(), ImpactLevel.SAFE),
        ("not-launched",),
        1,
    )

    with pytest.raises(PolicyDeniedError):
        PolicyEngine().Authorize(invocation, capability, network, at=AT)


def test_PhysicalMaterialReplacementAndSameBytesExtraFileDeny(tmp_path):
    """Equal content at a replaced physical path and unlisted cache files invalidate the lease."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    path = stage.material.directory / "policy.json"
    original = path.read_bytes()
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    path.unlink()
    path.write_bytes(original)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, prepared, stage, context, at=AT)


def test_FinalLaunchRefreshDeniesScopeDriftWithoutContact(tmp_path):
    """Actual pre-launch check uses fresh persisted scope before creating any run marker."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)
    calls = 0

    def Current():
        """Revoke only when the executor calls its final launch boundary."""

        nonlocal calls
        calls += 1

        if calls == 2:
            scope = LocalScopeStore(root).Save(
                replace(
                    context.scope,
                    authorization=replace(
                        context.scope.authorization,
                        state=AuthorizationState.REVOKED,
                    ),
                )
            )

            return replace(context, scope=scope)

        return context

    coroutine = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared, stage, grant, Current
    )

    with pytest.raises(ArtifactDeniedError):
        coroutine.send(None)

    assert not tuple((stage.root / "scratch").iterdir()), "Denied launch created scratch/contact"


def test_CoroutineContextRejectedAndClosedWithoutLaunch(tmp_path):
    """Async callbacks cannot silently skip synchronous final authority validation."""

    root, stage, prepared, context, grant = OwnedArtifact(tmp_path)

    async def Wrong():
        """Provide a deliberately unsupported async authority result."""

        return context

    response = Wrong()
    operation = GovernedArtifactExecutor(root, clock=lambda: AT).Execute(
        prepared,
        stage,
        grant,
        lambda: response,
    )

    with pytest.raises(ValueError):
        operation.send(None)

    assert inspect.getcoroutinestate(response) == inspect.CORO_CLOSED, "Rejected coroutine leaked"


@pytest.mark.parametrize(
    "timeout,resources",
    [
        (0, None),
        (True, None),
        (301, None),
        (1, ExecutionResources(max_stdout_bytes=17 * 1024 * 1024)),
        (1, ExecutionResources(terminate_grace_seconds=6)),
    ],
)
def test_ProfileResourcesRemainFinite(tmp_path, timeout, resources):
    """Caller-selected bounded budgets cannot turn fixed execution into an unbounded command."""

    root, stage, _, _, _ = OwnedArtifact(tmp_path)

    with pytest.raises(ValueError):
        PrepareArtifact(stage, root, timeout_seconds=timeout, resources=resources)


def test_ArtifactGrantCannotBePassedToNetworkPolicy(tmp_path):
    """Distinct grant types fail closed before network issuance/validation can proceed."""

    _, _, _, _, grant = OwnedArtifact(tmp_path)

    with pytest.raises(ValueError):
        PolicyEngine().Validate(grant, None, None, None, at=AT)


@pytest.mark.parametrize("ceiling", ["policy", "permission"])
def test_PassiveCeilingCannotAuthorizeSafeArtifactExecution(tmp_path, ceiling):
    """Accepted PASSIVE policy ceilings remain stricter than SAFE fixed profiles."""

    _, stage, prepared, context, grant = OwnedArtifact(tmp_path)

    if ceiling == "policy":
        policy = replace(context.policy, maximum_impact=ImpactLevel.PASSIVE)

    else:
        policy = replace(
            context.policy,
            permissions=(
                replace(
                    context.policy.permissions[0],
                    maximum_impact=ImpactLevel.PASSIVE,
                ),
            ),
        )

    changed = replace(context, policy=policy)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Authorize(prepared, stage, changed, at=AT)

    with pytest.raises(ArtifactDeniedError):
        ArtifactPolicyEngine().Validate(grant, prepared, stage, changed, at=AT)
