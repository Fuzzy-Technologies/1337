# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic impact, consent, confirmation and exact policy-binding tests."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel
from fuzzy1337.executors import CapabilityDescriptor
from fuzzy1337.policy import (
    CapabilityPermission,
    ImpactPolicy,
    PolicyConfirmation,
    PolicyContext,
    PolicyDenialReason,
    PolicyDeniedError,
    PolicyEngine,
    PolicyGrant,
    UtcNow,
)
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)

AT = datetime(2026, 10, 11, 10, tzinfo=timezone.utc)
TARGET = Target(TargetKind.IP, "127.0.0.1")
OTHER = Target(TargetKind.IP, "127.0.0.2")


def Inputs(impact: ImpactLevel = ImpactLevel.SAFE):
    """Build explicit synthetic policy inputs with all ceilings independently visible."""

    invocation = AdapterInvocation(
        "native.synthetic", AdapterRequest("test.synthetic", TARGET.Reference(), impact),
        ("synthetic", "--target", TARGET.value), 5, "1.0",
    )
    capability = CapabilityDescriptor("test.synthetic", "native.synthetic", ImpactLevel.INTRUSIVE)
    policy = ImpactPolicy("lab", maximum_impact=ImpactLevel.INTRUSIVE, permissions=(
        CapabilityPermission("test.synthetic", "native.synthetic", ImpactLevel.INTRUSIVE),
    ))
    scope = ScopeSnapshot(
        "lab", "workspace", ScopeAuthorization(
            AuthorizationState.GRANTED, "operator:synthetic", "approval:lab"
        ), targets=(TARGET, OTHER), allow=(TARGET, OTHER),
    )

    return invocation, capability, PolicyContext(scope, policy, TARGET, (TARGET,))


def Grant(invocation, capability, context):
    """Approve the exact generated plan before deterministic issuance."""

    engine = PolicyEngine()
    confirmation = PolicyConfirmation(
        engine.Plan(invocation, capability, context, at=AT).intent_sha256, "approval:exact-plan"
    )

    return engine.Authorize(invocation, capability, context, at=AT, confirmation=confirmation)


@pytest.mark.parametrize("impact", list(ImpactLevel))
def test_AllFiveImpactLevelsRequireExplicitPolicyAndHigherImpactConfirmation(impact):
    """Exercise every impact level without an implicit provider or scope grant."""

    invocation, capability, context = Inputs(impact)
    engine = PolicyEngine()
    plan = engine.Plan(invocation, capability, context, at=AT)
    confirmation_required = impact in (
        ImpactLevel.STANDARD, ImpactLevel.ACTIVE, ImpactLevel.INTRUSIVE
    )
    assert plan.confirmation_required == confirmation_required, (
        'Policy invariant failed: plan.confirmation_required == confirmation_required'
    )

    if confirmation_required:
        with pytest.raises(PolicyDeniedError) as denied:
            engine.Authorize(invocation, capability, context, at=AT)

        assert denied.value.reason == PolicyDenialReason.CONFIRMATION_REQUIRED, (
            'Policy boundary did not preserve its expected decision or binding'
        )

    else:
        engine.Authorize(invocation, capability, context, at=AT)

    grant = Grant(invocation, capability, context)
    engine.Validate(grant, invocation, capability, context, at=AT + timedelta(seconds=1))
    assert grant.authorization.invocation_sha256 == plan.invocation_sha256, (
        'Policy boundary did not preserve its expected decision or binding'
    )
    assert grant.authorization.scope_reference == context.scope.Reference(), (
        'Policy boundary did not preserve its expected decision or binding'
    )
    assert grant.authorization.policy_reference == context.policy.Reference(), (
        'Policy boundary did not preserve its expected decision or binding'
    )


def test_DefaultPolicyAllowsNoProviderAndHasSafeCeiling():
    """A default policy cannot turn a registered target into execution authority."""

    invocation, capability, context = Inputs()
    default = ImpactPolicy("default")
    assert default.maximum_impact == ImpactLevel.SAFE, (
        'Policy invariant failed: default.maximum_impact == ImpactLevel.SAFE'
    )
    assert default.permissions == (), (
        'Policy invariant failed: default.permissions == ()'
    )

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, replace(context, policy=default), at=AT)

    assert denied.value.reason == PolicyDenialReason.PROVIDER_DENIED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.PROVIDER_DENIED'
    )
    assert isinstance(denied.value, PermissionError), (
        "Policy denial must expose the standard authorization exception boundary"
    )


@pytest.mark.parametrize("owner", ("policy", "permission", "capability"))
def test_EachIndependentImpactCeilingFailsClosed(owner):
    """No broad permission or capability can bypass another impact ceiling."""

    invocation, capability, context = Inputs(ImpactLevel.ACTIVE)

    if owner == "policy":
        context = replace(context, policy=replace(context.policy, maximum_impact=ImpactLevel.SAFE))

    elif owner == "permission":
        permission = replace(context.policy.permissions[0], maximum_impact=ImpactLevel.STANDARD)
        context = replace(context, policy=replace(context.policy, permissions=(permission,)))

    else:
        capability = replace(capability, maximum_impact=ImpactLevel.PASSIVE)

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.IMPACT_DENIED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.IMPACT_DENIED'
    )


@pytest.mark.parametrize("change", ("adapter", "capability", "permission"))
def test_CapabilityAndProviderMustMatchBothInvocationAndAllowEntry(change):
    """Provider allow entries are exact capability/provider pairs."""

    invocation, capability, context = Inputs()

    if change == "adapter":
        capability = replace(capability, adapter_id="another.provider")

    elif change == "capability":
        capability = replace(capability, identifier="another.capability")

    else:
        permission = replace(context.policy.permissions[0], adapter_id="another.provider")
        context = replace(context, policy=replace(context.policy, permissions=(permission,)))

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.PROVIDER_DENIED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.PROVIDER_DENIED'
    )


def test_PrivilegesRequireAnExplicitPermissionGrant():
    """Privilege metadata does not grant the privilege required by the capability."""

    invocation, capability, context = Inputs()
    capability = replace(capability, required_privileges=("network.raw",))

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.PRIVILEGE_DENIED, (
        'Policy boundary did not preserve its expected decision or binding'
    )
    permission = replace(context.policy.permissions[0], granted_privileges=("network.raw",))
    context = replace(context, policy=replace(context.policy, permissions=(permission,)))
    grant = Grant(invocation, capability, context)
    assert grant.authorization.granted_privileges == ("network.raw",), (
        'Policy boundary did not preserve its expected decision or binding'
    )


@pytest.mark.parametrize("authorization, reason", (
    (ScopeAuthorization(), ScopeDecisionReason.AUTHORIZATION_UNKNOWN),
    (ScopeAuthorization(AuthorizationState.REVOKED), ScopeDecisionReason.AUTHORIZATION_REVOKED),
    (ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:test", "approval:test", valid_from="2026-10-12T00:00Z"
    ), ScopeDecisionReason.AUTHORIZATION_NOT_YET_VALID),
    (ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:test", "approval:test",
        valid_until="2026-10-10T00:00Z"
    ), ScopeDecisionReason.AUTHORIZATION_EXPIRED),
))
def test_UnknownRevokedFutureAndExpiredConsentNeverIssueGrant(authorization, reason):
    """Explicit scope consent remains mandatory even for PASSIVE work."""

    invocation, capability, context = Inputs(ImpactLevel.PASSIVE)
    context = replace(context, scope=replace(context.scope, authorization=authorization))

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Authorize(invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.SCOPE_DENIED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.SCOPE_DENIED'
    )
    assert denied.value.scope_reason == reason, (
        'Policy invariant failed: denied.value.scope_reason == reason'
    )
    assert reason.value in str(denied.value), (
        'Policy invariant failed: reason.value in str(denied.value)'
    )


def test_RequestedTargetIdentityMustMatchInvocation():
    """A grant cannot describe one target while the invocation names another."""

    invocation, capability, context = Inputs()

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, replace(context, target=OTHER), at=AT)

    assert denied.value.reason == PolicyDenialReason.TARGET_MISMATCH, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.TARGET_MISMATCH'
    )


@pytest.mark.parametrize("restriction, reason", (
    ("unregistered", ScopeDecisionReason.UNREGISTERED),
    ("deny", ScopeDecisionReason.DENIED),
    ("exclude", ScopeDecisionReason.EXCLUDED),
    ("not_allowed", ScopeDecisionReason.NOT_ALLOWED),
))
def test_ActualDestinationMustIndependentlyBeRegisteredAndAllowed(restriction, reason):
    """A domain/URL or original target grant cannot bypass an actual denied address."""

    invocation, capability, context = Inputs()
    context = replace(context, destinations=(OTHER,))

    if restriction == "unregistered":
        scope = replace(context.scope, targets=(TARGET,))

    elif restriction == "deny":
        scope = replace(context.scope, deny=(OTHER,))

    elif restriction == "exclude":
        scope = replace(context.scope, exclusions=(OTHER,))

    else:
        scope = replace(context.scope, allow=(TARGET,))

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Plan(invocation, capability, replace(context, scope=scope), at=AT)

    assert denied.value.reason == PolicyDenialReason.DESTINATION_DENIED, (
        'Policy boundary did not preserve its expected decision or binding'
    )
    assert denied.value.scope_reason == reason, (
        'Policy invariant failed: denied.value.scope_reason == reason'
    )


def test_ConfirmationForAnotherExactPlanCannotAuthorizeChangedArgv():
    """An approval record is bound to the original argv, not just a target or impact."""

    invocation, capability, context = Inputs(ImpactLevel.STANDARD)
    engine = PolicyEngine()
    confirmation = PolicyConfirmation(
        engine.Plan(invocation, capability, context, at=AT).intent_sha256, "approval:plan"
    )
    changed = replace(invocation, argv=(*invocation.argv, "--changed"))

    with pytest.raises(PolicyDeniedError) as denied:
        engine.Authorize(changed, capability, context, at=AT, confirmation=confirmation)

    assert denied.value.reason == PolicyDenialReason.CONFIRMATION_CHANGED, (
        'Policy boundary did not preserve its expected decision or binding'
    )


@pytest.mark.parametrize("change", (
    "argv", "timeout", "version", "parameters", "impact", "capability", "scope_revision",
    "scope_content", "policy_revision", "policy_content", "destination", "target",
))
def test_GrantRejectsEveryChangedDecisionInputIncludingUnsavedState(change):
    """Same-revision content changes and allowlisted destination changes still invalidate grants."""

    invocation, capability, context = Inputs()
    grant = Grant(invocation, capability, context)

    if change == "argv":
        invocation = replace(invocation, argv=(*invocation.argv, "--changed"))

    elif change == "timeout":
        invocation = replace(invocation, timeout_seconds=6)

    elif change == "version":
        invocation = replace(invocation, provider_version="1.1")

    elif change == "parameters":
        invocation = replace(invocation, request=replace(invocation.request, parameters={"x": 1}))

    elif change == "impact":
        invocation = replace(invocation, request=replace(
            invocation.request, impact=ImpactLevel.PASSIVE
        ))

    elif change == "capability":
        capability = replace(capability, maximum_impact=ImpactLevel.SAFE)

    elif change == "scope_revision":
        context = replace(context, scope=replace(context.scope, revision=1))

    elif change == "scope_content":
        context = replace(context, scope=replace(context.scope, allow=(TARGET,)))

    elif change == "policy_revision":
        context = replace(context, policy=replace(context.policy, revision=1))

    elif change == "policy_content":
        context = replace(context, policy=replace(context.policy, max_authorization_seconds=100))

    elif change == "destination":
        context = replace(context, destinations=(OTHER,))

    else:
        context = replace(context, target=OTHER)
        invocation = replace(invocation, request=replace(
            invocation.request, target_reference=OTHER.Reference()
        ))

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Validate(grant, invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.CONTEXT_CHANGED'
    )


def test_GrantExpiryIsClampedToEarlierScopeExpiryAndUsesExclusiveEnd():
    """An otherwise allowed invocation never outlives its scope consent."""

    invocation, capability, context = Inputs()
    expiry = AT + timedelta(seconds=3)
    scope = replace(context.scope, authorization=replace(
        context.scope.authorization, valid_until=expiry.isoformat()
    ))
    context = replace(context, scope=scope)
    grant = Grant(invocation, capability, context)
    assert grant.valid_until == expiry.isoformat(), (
        'Policy invariant failed: grant.valid_until == expiry.isoformat()'
    )

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Validate(grant, invocation, capability, context, at=expiry)

    assert denied.value.reason == PolicyDenialReason.GRANT_EXPIRED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.GRANT_EXPIRED'
    )


def test_GrantCannotBeUsedBeforeItsIssueTime():
    """Clock regression does not extend a grant's validity interval."""

    invocation, capability, context = Inputs()

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Validate(
            Grant(invocation, capability, context), invocation, capability, context,
            at=AT - timedelta(seconds=1),
        )

    assert denied.value.reason == PolicyDenialReason.GRANT_NOT_YET_VALID, (
        'Policy boundary did not preserve its expected decision or binding'
    )


@pytest.mark.parametrize("change", ("expiry", "envelope", "privileges", "missing_confirmation"))
def test_TamperedGrantCannotSubstituteEnvelopePrivilegesOrValidity(change):
    """A grant must retain its issued envelope and exact bounded approval metadata."""

    invocation, capability, context = Inputs(ImpactLevel.STANDARD)
    grant = Grant(invocation, capability, context)

    if change == "expiry":
        grant = replace(grant, valid_until=(AT + timedelta(hours=1)).isoformat())

    elif change == "envelope":
        grant = replace(grant, authorization=replace(
            grant.authorization, policy_reference="policy:x"
        ))

    elif change == "privileges":
        grant = replace(grant, authorization=replace(
            grant.authorization, granted_privileges=("network.raw",)
        ))

    else:
        grant = replace(grant, confirmation_reference=None)

    with pytest.raises(PolicyDeniedError) as denied:
        PolicyEngine().Validate(grant, invocation, capability, context, at=AT)

    assert denied.value.reason == PolicyDenialReason.GRANT_CHANGED, (
        'Policy invariant failed: denied.value.reason == PolicyDenialReason.GRANT_CHANGED'
    )


@pytest.mark.parametrize("factory", (
    lambda: CapabilityPermission("Bad", "test", ImpactLevel.SAFE),
    lambda: CapabilityPermission("test", "test", "SAFE"),
    lambda: CapabilityPermission("test", "test", ImpactLevel.SAFE, ("x", "x")),
    lambda: ImpactPolicy("test", revision=True),
    lambda: ImpactPolicy("test", revision=-1),
    lambda: ImpactPolicy("test", maximum_impact="SAFE"),
    lambda: ImpactPolicy("test", max_authorization_seconds=True),
    lambda: ImpactPolicy("test", max_authorization_seconds=0),
    lambda: ImpactPolicy("test", max_authorization_seconds=3601),
    lambda: ImpactPolicy("test", permissions=("test",)),
    lambda: ImpactPolicy("test", permissions=(
        CapabilityPermission("test", "test", ImpactLevel.SAFE),
        CapabilityPermission("test", "test", ImpactLevel.SAFE),
    )),
    lambda: PolicyConfirmation("not-a-digest", "approval:x"),
    lambda: PolicyConfirmation("g" * 64, "approval:x"),
    lambda: PolicyConfirmation("0" * 64, ""),
))
def test_MalformedPolicyAndConfirmationRecordsFailClosed(factory):
    """Malformed enums, duplicate grants and ambiguous approval inputs are rejected."""

    with pytest.raises(ValueError):
        factory()


@pytest.mark.parametrize("destinations", (
    (), (TARGET,) * 65, ("127.0.0.1",), (Target(TargetKind.DOMAIN, "example.invalid"),),
    (Target(TargetKind.URL, "https://example.invalid/"),), (TARGET, TARGET),
))
def test_UnobservedUnboundedAndDuplicateDestinationsAreRejected(destinations):
    """Unresolved names or ranges cannot replace explicit actual-destination observations."""

    _, _, context = Inputs()

    with pytest.raises(ValueError):
        replace(context, destinations=destinations)


@pytest.mark.parametrize("field, value", (("scope", None), ("policy", None), ("target", None)))
def test_ContextRequiresTypedInputs(field, value):
    """A context cannot use opaque unvalidated scope or target values."""

    _, _, context = Inputs()

    with pytest.raises(ValueError):
        replace(context, **{field: value})


def test_DestinationAndPermissionOrderingProducesSameExactIntent():
    """Semantically unordered allow lists and destination observations are deterministic."""

    invocation, capability, context = Inputs()
    extra = CapabilityPermission("test.other", "native.synthetic", ImpactLevel.PASSIVE)
    first = replace(context, policy=replace(
        context.policy, permissions=(extra, *context.policy.permissions)
    ), destinations=(TARGET, OTHER))
    second = replace(context, policy=replace(
        context.policy, permissions=(*context.policy.permissions, extra)
    ), destinations=(OTHER, TARGET))
    engine = PolicyEngine()
    assert engine.Plan(invocation, capability, first, at=AT) == engine.Plan(
        invocation, capability, second, at=AT
    ), (
        'Policy boundary did not preserve its expected decision or binding'
    )


@pytest.mark.parametrize("wrong", (datetime(2026, 10, 11), None))
def test_DecisionTimeMustBeExplicitAndTimezoneAware(wrong):
    """No implicit local time enters the authorization clock boundary."""

    invocation, capability, context = Inputs()
    grant = Grant(invocation, capability, context)

    with pytest.raises(ValueError):
        PolicyEngine().Plan(invocation, capability, context, at=wrong)

    with pytest.raises(ValueError):
        PolicyEngine().Validate(grant, invocation, capability, context, at=wrong)


@pytest.mark.parametrize("field", ("invocation", "capability", "context", "confirmation", "grant"))
def test_EngineRejectsUntypedDecisionInputs(field):
    """Security boundary calls reject untyped values instead of interpreting them loosely."""

    invocation, capability, context = Inputs()
    engine = PolicyEngine()

    if field == "confirmation":
        with pytest.raises(ValueError):
            engine.Authorize(invocation, capability, context, at=AT, confirmation=True)

    elif field == "grant":
        with pytest.raises(ValueError):
            engine.Validate(None, invocation, capability, context, at=AT)

    else:
        args = {"invocation": invocation, "capability": capability, "context": context, "at": AT}
        args[field] = None

        with pytest.raises(ValueError):
            engine.Plan(**args)


@pytest.mark.parametrize("field, value", (
    ("plan", None), ("authorization", None), ("issued_at", "2026-10-11T10:00:00"),
    ("valid_until", "2026-10-11T09:00:00Z"), ("confirmation_reference", ""),
))
def test_GrantStructureRequiresTypedBindingsAndIncreasingAwareValidity(field, value):
    """Invalid grant records cannot reach launch-time revalidation."""

    invocation, capability, context = Inputs()
    grant = Grant(invocation, capability, context)

    with pytest.raises(ValueError):
        PolicyGrant(**{**{
            "plan": grant.plan, "authorization": grant.authorization, "issued_at": grant.issued_at,
            "valid_until": grant.valid_until,
            "confirmation_reference": grant.confirmation_reference,
        }, field: value})


def test_DefaultLaunchClockIsAwareUtc():
    """The production launch clock supplies timezone-aware UTC."""

    assert UtcNow().utcoffset() == timedelta(0), (
        'Policy invariant failed: UtcNow().utcoffset() == timedelta(0)'
    )
