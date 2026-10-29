# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit impact policy, plan-bound confirmation and governed local execution."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, ImpactLevel, SerializeContract
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutionResult,
    LocalExecutor,
)
from fuzzy1337.executors.contracts import RequireIdentifier, RequireReference, UniqueIdentifiers
from fuzzy1337.executors.local import EventCallback
from fuzzy1337.scope import NormalizeTime, ScopeDecisionReason, ScopeSnapshot, Target, TargetKind

POLICY_CONTRACT_VERSION = 1
_IMPACT_ORDER = {impact: index for index, impact in enumerate(ImpactLevel)}
_CONFIRMED_IMPACTS = frozenset((ImpactLevel.STANDARD, ImpactLevel.ACTIVE, ImpactLevel.INTRUSIVE))
_MAX_DESTINATIONS = 64

__all__ = [
    "POLICY_CONTRACT_VERSION",
    "CapabilityPermission",
    "ImpactPolicy",
    "PolicyContext",
    "PolicyDenialReason",
    "PolicyDeniedError",
    "PolicyPlan",
    "PolicyConfirmation",
    "PolicyGrant",
    "PolicyEngine",
    "GovernedLocalExecutor",
]


def Digest(value: object) -> str:
    """Hash deterministic, non-secret contract metadata without importing a provider.

    Args:
        value: JSON-compatible contract metadata.

    Returns:
        Lowercase SHA-256 digest of compact sorted JSON.
    """

    return hashlib.sha256(SerializeContract(value).encode("utf-8")).hexdigest()


def RequireTime(at: datetime) -> None:
    """Require an explicit aware clock value for every authorization decision.

    Args:
        at: Caller-supplied decision time with an explicit UTC offset.

    Raises:
        ValueError: The clock value is not an aware datetime.
    """

    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("policy decision time must be a timezone-aware datetime")


def RequireDigest(value: str) -> None:
    """Reject malformed plan digests before interpreting a confirmation record.

    Args:
        value: Candidate exact-plan SHA-256 digest.

    Raises:
        ValueError: The value is not canonical lowercase SHA-256 text.
    """

    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("plan digest must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class CapabilityPermission:
    """Explicit provider/capability allow entry with impact and privilege ceilings."""

    capability_id: str
    adapter_id: str
    maximum_impact: ImpactLevel
    granted_privileges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate an explicit allow entry without granting any invocation."""

        RequireIdentifier(self.capability_id, "capability_id")
        RequireIdentifier(self.adapter_id, "adapter_id")

        if not isinstance(self.maximum_impact, ImpactLevel):
            raise ValueError("maximum_impact must be an ImpactLevel")

        object.__setattr__(self, "granted_privileges", UniqueIdentifiers(
            self.granted_privileges, "granted_privileges"
        ))


@dataclass(frozen=True, slots=True)
class ImpactPolicy:
    """Bounded operator policy; the default allows no provider and no intrusive work."""

    policy_id: str
    revision: int = 0
    maximum_impact: ImpactLevel = ImpactLevel.SAFE
    permissions: tuple[CapabilityPermission, ...] = ()
    max_authorization_seconds: int = 300

    def __post_init__(self) -> None:
        """Freeze bounded permissions and reject ambiguous or implicit grants."""

        RequireIdentifier(self.policy_id, "policy_id")

        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")

        if not isinstance(self.maximum_impact, ImpactLevel):
            raise ValueError("maximum_impact must be an ImpactLevel")

        if (
            isinstance(self.max_authorization_seconds, bool)
            or not isinstance(self.max_authorization_seconds, int)
            or not 1 <= self.max_authorization_seconds <= 3600
        ):
            raise ValueError("max_authorization_seconds must be between 1 and 3600")

        permissions = tuple(self.permissions)

        if not all(isinstance(permission, CapabilityPermission) for permission in permissions):
            raise ValueError("permissions must contain CapabilityPermission records")

        identifiers = tuple((item.capability_id, item.adapter_id) for item in permissions)

        if len(set(identifiers)) != len(identifiers):
            raise ValueError("permissions must be unique by capability and provider")

        object.__setattr__(self, "permissions", tuple(sorted(
            permissions, key=lambda item: (item.capability_id, item.adapter_id)
        )))

    def Reference(self) -> str:
        """Return a portable policy reference without implying approval.

        Returns:
            Opaque policy identity whose current content is checked separately.
        """

        return "policy:" + self.policy_id


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Current scope/policy and trusted observed destinations of one planned operation."""

    scope: ScopeSnapshot
    policy: ImpactPolicy
    target: Target
    destinations: tuple[Target, ...]

    def __post_init__(self) -> None:
        """Require typed, finite destination observations without resolving aliases."""

        if not isinstance(self.scope, ScopeSnapshot) or not isinstance(self.policy, ImpactPolicy):
            raise ValueError("context requires a ScopeSnapshot and an ImpactPolicy")

        if not isinstance(self.target, Target):
            raise ValueError("target must be a Target")

        if self.target.kind == TargetKind.ARTIFACT:
            raise ValueError("network policy cannot authorize an artifact target")

        destinations = tuple(self.destinations)

        if not 1 <= len(destinations) <= _MAX_DESTINATIONS:
            raise ValueError("destinations must contain between 1 and 64 explicit targets")

        if not all(isinstance(item, Target) for item in destinations):
            raise ValueError("destinations must contain Target records")

        if any(item.kind not in (TargetKind.IP, TargetKind.URL) for item in destinations):
            raise ValueError("actual destinations must be IP or URL literals")

        if not any(item.kind == TargetKind.IP for item in destinations):
            raise ValueError("actual destinations must include explicit resolved IP literals")

        if len(set(destinations)) != len(destinations):
            raise ValueError("destinations must be unique")

        object.__setattr__(self, "destinations", tuple(sorted(
            destinations, key=lambda item: item.Reference()
        )))


class PolicyDenialReason(StrEnum):
    """Explainable fail-closed policy boundary failures."""

    TARGET_MISMATCH = "target_mismatch"
    SCOPE_DENIED = "scope_denied"
    DESTINATION_DENIED = "destination_denied"
    PROVIDER_DENIED = "provider_denied"
    IMPACT_DENIED = "impact_denied"
    PRIVILEGE_DENIED = "privilege_denied"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_CHANGED = "confirmation_changed"
    CONTEXT_CHANGED = "context_changed"
    GRANT_NOT_YET_VALID = "grant_not_yet_valid"
    GRANT_EXPIRED = "grant_expired"
    GRANT_CHANGED = "grant_changed"


class PolicyDeniedError(PermissionError):
    """Reject issuance or launch with a structured reason and optional scope evidence."""

    def __init__(
        self, reason: PolicyDenialReason, *, scope_reason: ScopeDecisionReason | None = None
    ) -> None:
        """Retain machine-readable denial without exposing invocation or secret values.

        Args:
            reason: Structured policy boundary that denied the operation.
            scope_reason: Optional underlying scope membership or consent failure.
        """

        self.reason = reason
        self.scope_reason = scope_reason
        message = f"Policy denied operation: {reason.value}"

        if scope_reason is not None:
            message += f" ({scope_reason.value})"

        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PolicyPlan:
    """Immutable decision inputs; planning grants no execution authority."""

    invocation_sha256: str
    capability_sha256: str
    scope_reference: str
    scope_revision: int
    scope_sha256: str
    policy_reference: str
    policy_revision: int
    policy_sha256: str
    target_reference: str
    destination_references: tuple[str, ...]
    granted_privileges: tuple[str, ...]
    confirmation_required: bool
    intent_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        """Bind an exact confirmation digest to every other immutable plan field."""

        payload = {
            record_field.name: getattr(self, record_field.name)
            for record_field in fields(self) if record_field.name != "intent_sha256"
        }
        object.__setattr__(self, "intent_sha256", Digest(payload))


@dataclass(frozen=True, slots=True)
class PolicyConfirmation:
    """Operator-attested approval of one exact plan, never a generic permission flag."""

    intent_sha256: str
    record_reference: str

    def __post_init__(self) -> None:
        """Require an exact plan digest and a non-secret approval record reference."""

        RequireDigest(self.intent_sha256)
        RequireReference(self.record_reference, "record_reference")


@dataclass(frozen=True, slots=True)
class PolicyGrant:
    """Invocation-bound executor envelope with independent bounded launch validity."""

    plan: PolicyPlan
    authorization: ExecutionAuthorization
    issued_at: str
    valid_until: str
    confirmation_reference: str | None = None

    def __post_init__(self) -> None:
        """Validate grant structure; current authority is rechecked separately at launch."""

        if not isinstance(self.plan, PolicyPlan):
            raise ValueError("plan must be a PolicyPlan")

        if not isinstance(self.authorization, ExecutionAuthorization):
            raise ValueError("authorization must be an ExecutionAuthorization")

        object.__setattr__(self, "issued_at", NormalizeTime(self.issued_at))
        object.__setattr__(self, "valid_until", NormalizeTime(self.valid_until))

        if datetime.fromisoformat(self.issued_at) >= datetime.fromisoformat(self.valid_until):
            raise ValueError("grant validity interval must be increasing")

        if self.confirmation_reference is not None:
            RequireReference(self.confirmation_reference, "confirmation_reference")


class PolicyEngine:
    """Deterministic policy checks shared by human, AI-agent and CI operators."""

    def Plan(
        self,
        invocation: AdapterInvocation,
        capability: CapabilityDescriptor,
        context: PolicyContext,
        *,
        at: datetime,
    ) -> PolicyPlan:
        """Validate current authority and produce the exact intent requiring confirmation.

        Args:
            invocation: Prepared, trusted provider invocation; this method executes nothing.
            capability: Trusted declared capability and privilege requirements.
            context: Current scope, policy, target and pinned actual destinations.
            at: Explicit timezone-aware decision time.

        Returns:
            Immutable plan with confirmation required for STANDARD and higher impact.

        Raises:
            PolicyDeniedError: Scope, destination, provider, impact or privilege is denied.
            ValueError: Inputs lack the explicit typed/time contract.
        """

        RequireTime(at)

        if not isinstance(invocation, AdapterInvocation):
            raise ValueError("invocation must be an AdapterInvocation")

        if (
            not isinstance(capability, CapabilityDescriptor)
            or not isinstance(context, PolicyContext)
        ):
            raise ValueError("planning requires a CapabilityDescriptor and PolicyContext")

        if invocation.request.target_reference != context.target.Reference():
            raise PolicyDeniedError(PolicyDenialReason.TARGET_MISMATCH)

        if context.target.kind == TargetKind.ARTIFACT:
            raise PolicyDeniedError(PolicyDenialReason.TARGET_MISMATCH)

        decision = context.scope.Check(context.target, at=at)

        if not decision.Allowed():
            raise PolicyDeniedError(PolicyDenialReason.SCOPE_DENIED, scope_reason=decision.reason)

        for destination in context.destinations:
            decision = context.scope.Check(destination, at=at)

            if not decision.Allowed():
                raise PolicyDeniedError(
                    PolicyDenialReason.DESTINATION_DENIED, scope_reason=decision.reason
                )

        if (
            invocation.adapter_id != capability.adapter_id
            or invocation.request.capability != capability.identifier
        ):
            raise PolicyDeniedError(PolicyDenialReason.PROVIDER_DENIED)

        permission = next((item for item in context.policy.permissions if (
            item.capability_id == capability.identifier and item.adapter_id == capability.adapter_id
        )), None)

        if permission is None:
            raise PolicyDeniedError(PolicyDenialReason.PROVIDER_DENIED)

        impact = invocation.request.impact

        if any(_IMPACT_ORDER[impact] > _IMPACT_ORDER[ceiling] for ceiling in (
            context.policy.maximum_impact, permission.maximum_impact, capability.maximum_impact
        )):
            raise PolicyDeniedError(PolicyDenialReason.IMPACT_DENIED)

        if not set(capability.required_privileges).issubset(permission.granted_privileges):
            raise PolicyDeniedError(PolicyDenialReason.PRIVILEGE_DENIED)

        return PolicyPlan(
            invocation_sha256=InvocationDigest(invocation), capability_sha256=Digest(capability),
            scope_reference=context.scope.Reference(), scope_revision=context.scope.revision,
            scope_sha256=Digest(context.scope.ToDict()),
            policy_reference=context.policy.Reference(),
            policy_revision=context.policy.revision, policy_sha256=Digest(context.policy),
            target_reference=context.target.Reference(),
            destination_references=tuple(item.Reference() for item in context.destinations),
            granted_privileges=permission.granted_privileges,
            confirmation_required=impact in _CONFIRMED_IMPACTS,
        )

    def Authorize(
        self,
        invocation: AdapterInvocation,
        capability: CapabilityDescriptor,
        context: PolicyContext,
        *,
        at: datetime,
        confirmation: PolicyConfirmation | None = None,
    ) -> PolicyGrant:
        """Issue a short-lived exact-invocation grant after current checks and approval.

        Args:
            invocation: Exact prepared invocation, with no launch or provider side effect.
            capability: Declared provider capability and privilege requirements.
            context: Current scope/policy and pinned observed destinations.
            at: Explicit timezone-aware issuance time.
            confirmation: Exact plan approval, mandatory for STANDARD and higher impact.

        Returns:
            Grant usable only with the same current context before its expiry.

        Raises:
            PolicyDeniedError: Policy fails or required approval is missing/mismatched.
            ValueError: The time or confirmation is malformed.
        """

        plan = self.Plan(invocation, capability, context, at=at)

        if confirmation is not None and not isinstance(confirmation, PolicyConfirmation):
            raise ValueError("confirmation must be a PolicyConfirmation")

        if plan.confirmation_required and confirmation is None:
            raise PolicyDeniedError(PolicyDenialReason.CONFIRMATION_REQUIRED)

        if confirmation is not None and confirmation.intent_sha256 != plan.intent_sha256:
            raise PolicyDeniedError(PolicyDenialReason.CONFIRMATION_CHANGED)

        issued_at = at.astimezone(timezone.utc).isoformat()
        valid_until = self.Expiry(context, at)
        confirmation_reference = confirmation.record_reference if confirmation is not None else None
        authorization = self.Envelope(plan, issued_at, valid_until, confirmation_reference)

        return PolicyGrant(plan, authorization, issued_at, valid_until, confirmation_reference)

    def Expiry(self, context: PolicyContext, at: datetime) -> str:
        """Limit launch validity by policy lifetime and any earlier scope expiry.

        Args:
            context: Validated current scope and policy with bounded lifetime.
            at: Validated aware issuance time.

        Returns:
            Canonical UTC exclusive expiry time.
        """

        valid_until = at + timedelta(seconds=context.policy.max_authorization_seconds)

        if context.scope.authorization.valid_until is not None:
            valid_until = min(valid_until, datetime.fromisoformat(
                context.scope.authorization.valid_until
            ))

        return valid_until.astimezone(timezone.utc).isoformat()

    def Envelope(
        self,
        plan: PolicyPlan,
        issued_at: str,
        valid_until: str,
        confirmation_reference: str | None,
    ) -> ExecutionAuthorization:
        """Build a deterministic envelope identity bound to plan, validity and approval.

        Args:
            plan: Validated exact decision inputs.
            issued_at: Canonical UTC issuance time.
            valid_until: Canonical UTC exclusive expiry time.
            confirmation_reference: Non-secret exact-plan approval record, when required.

        Returns:
            Existing executor SDK envelope bound to every grant metadata field.
        """

        authorization_id = "authorization:" + Digest((
            plan, issued_at, valid_until, confirmation_reference
        ))

        return ExecutionAuthorization(
            authorization_id=authorization_id, scope_reference=plan.scope_reference,
            policy_reference=plan.policy_reference, invocation_sha256=plan.invocation_sha256,
            granted_privileges=plan.granted_privileges,
        )

    def Validate(
        self,
        grant: PolicyGrant,
        invocation: AdapterInvocation,
        capability: CapabilityDescriptor,
        context: PolicyContext,
        *,
        at: datetime,
    ) -> None:
        """Fail closed on expiry, changed decisions or a substituted grant envelope.

        Args:
            grant: Previously issued grant; neither possession nor its digest proves authority.
            invocation: Exact invocation proposed for immediate launch.
            capability: Current trusted capability declaration.
            context: Fresh scope, policy, target and destination observations.
            at: Explicit timezone-aware launch time.

        Raises:
            PolicyDeniedError: The grant is stale, expired, changed or currently denied.
            ValueError: Input structure or decision time is malformed.
        """

        RequireTime(at)

        if not isinstance(grant, PolicyGrant):
            raise ValueError("grant must be a PolicyGrant")

        if at < datetime.fromisoformat(grant.issued_at):
            raise PolicyDeniedError(PolicyDenialReason.GRANT_NOT_YET_VALID)

        if at >= datetime.fromisoformat(grant.valid_until):
            raise PolicyDeniedError(PolicyDenialReason.GRANT_EXPIRED)

        plan = self.Plan(invocation, capability, context, at=at)

        if plan != grant.plan:
            raise PolicyDeniedError(PolicyDenialReason.CONTEXT_CHANGED)

        if (
            plan.confirmation_required and grant.confirmation_reference is None
        ) or grant.valid_until != self.Expiry(context, datetime.fromisoformat(grant.issued_at)):
            raise PolicyDeniedError(PolicyDenialReason.GRANT_CHANGED)

        if grant.authorization != self.Envelope(
            plan, grant.issued_at, grant.valid_until, grant.confirmation_reference
        ):
            raise PolicyDeniedError(PolicyDenialReason.GRANT_CHANGED)


def UtcNow() -> datetime:
    """Read the aware UTC launch clock; planning remains explicitly caller-timed.

    Returns:
        Current timezone-aware UTC time.
    """

    return datetime.now(timezone.utc)


class GovernedLocalExecutor:
    """Policy-enforcing launch facade; legacy SDK execution remains a trusted-issuer API."""

    def __init__(
        self, workspace_root: Path, *, clock: Callable[[], datetime] = UtcNow
    ) -> None:
        """Bind a local executor and an aware clock without loading scope or a provider.

        Args:
            workspace_root: Existing workspace boundary checked by the local executor.
            clock: Launch clock; injectable for deterministic expiry tests.
        """

        self._executor = LocalExecutor(workspace_root)
        self._clock = clock
        self._engine = PolicyEngine()

    async def Execute(
        self,
        request: LocalExecutionRequest,
        *,
        grant: PolicyGrant,
        context_provider: Callable[[], PolicyContext],
        on_event: EventCallback | None = None,
        cancellation: asyncio.Event | None = None,
        own_descendants: bool = False,
    ) -> LocalExecutionResult:
        """Revalidate fresh context immediately before launching the exact approved request.

        The synchronous context provider must read current scope/policy and current pinned
        destination observations. Its failures propagate before launch. Providers must not
        perform unchecked DNS/redirect changes after this boundary; this is not a network
        sandbox or automatic revocation of already-running processes.

        Args:
            request: Existing executor request carrying the grant's exact authorization.
            grant: Previously issued policy grant with plan/approval/validity binding.
            context_provider: Trusted synchronous reader of current authorization inputs.
            on_event: Optional local executor progress observer.
            cancellation: Cooperative cancellation, preserving existing executor behavior.
            own_descendants: Explicit Linux-only stronger child ownership; authorization
                still binds the unchanged original request and invocation.

        Returns:
            The unchanged local executor result with truthful terminal state and output.

        Raises:
            PolicyDeniedError: Envelope substitution or current launch authority is denied.
            LocalExecutionError: The executor cannot validate its workspace or launch.
            asyncio.CancelledError: Cancellation completes owned-process cleanup first.
        """

        if not isinstance(grant, PolicyGrant):
            raise ValueError("grant must be a PolicyGrant")

        if request.authorization != grant.authorization:
            raise PolicyDeniedError(PolicyDenialReason.GRANT_CHANGED)

        def CheckBeforeLaunch(current_request: LocalExecutionRequest) -> None:
            """Re-read authority at the executor's final synchronous launch boundary.

            Args:
                current_request: Exact request immediately about to launch.
            """

            self._engine.Validate(
                grant, current_request.invocation, current_request.capability,
                context_provider(), at=self._clock(),
            )

        if own_descendants:
            return await self._executor.Execute(request, on_event=on_event,
                cancellation=cancellation, pre_launch=CheckBeforeLaunch,
                own_descendants=own_descendants)

        if type(own_descendants) is not bool:
            raise ValueError("own_descendants must be an explicit boolean")

        return await self._executor.Execute(
            request, on_event=on_event, cancellation=cancellation, pre_launch=CheckBeforeLaunch
        )
