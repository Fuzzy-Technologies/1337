# Impact policy and governed execution

`fuzzy1337.policy` is an Experimental Python API at policy contract version `1`.
[ADR 0025](adr/0025-impact-policy-and-governed-issuance.md) defines the bounded
operator guardrail shared by people, external AI agents and CI. This library
adds no scan command, policy language, resolver or approval service.

## Explicit authority and impact

A target must have current granted consent and explicit registration/membership
in its `ScopeSnapshot`. Every actual destination is independently checked with
the same rules. A registered target alone grants nothing.

`ImpactPolicy` defaults to a `SAFE` impact ceiling, a 300-second authorization
lifetime and **no** capability/provider permissions. Configure explicit
`CapabilityPermission` entries. Invocation, capability, permission and overall
policy ceilings must agree; required privileges must be explicitly granted.

| Impact      | Policy behavior                                               |
| ----------- | ------------------------------------------------------------- |
| `PASSIVE`   | Explicit scope and capability/provider permission required    |
| `SAFE`      | Same checks; the default ceiling permits no higher impact     |
| `STANDARD`  | Exact plan confirmation required in addition to all checks    |
| `ACTIVE`    | Explicit higher ceiling and exact plan confirmation required  |
| `INTRUSIVE` | Explicit highest ceiling and exact plan confirmation required |

Impact is trusted provider classification, not a claim that arbitrary argv is
safe. Preparing an invocation, generating a plan or installing a provider does
not authorize execution.

## Plan, confirm, authorize, revalidate

1. Prepare one bounded invocation through a trusted adapter and read its
   capability declaration.
2. Read current scope/policy and supply a `PolicyContext` with the requested
   `Target` and every pinned actual destination. The finite destination list
   contains IP/URL literals and at least one explicit resolved IP. Every
   destination must itself be registered and allowed; no domain/IP alias grants
   are inferred. Resolution/redirect checks remain the consumer's responsibility.
3. Call `PolicyEngine.Plan(invocation, capability, context, at=aware_time)`.
   Present the exact plan, permitted impact and bounded operation to the operator.
4. For `STANDARD` or higher, obtain explicit approval and create
   `PolicyConfirmation(plan.intent_sha256, nonsecret_record_reference)`.
   CI may supply a preapproved exact-plan record through the same boundary.
5. Call `Authorize` with the same inputs and approval. Use its
   `PolicyGrant.authorization` in the existing `LocalExecutionRequest`.
6. Call `GovernedLocalExecutor.Execute` with the grant and a synchronous
   `context_provider` that reads fresh authority/destination state. Scope
   content/revision, policy content/revision, capability, target, destinations
   and exact invocation are checked immediately before process creation.

An exact plan digest binds argv, parameters, impact, timeout, provider version,
capability and privilege metadata plus scope/policy content and revision. A
same-revision unsaved edit still invalidates the plan. Grants expire after the
configured 1–3600 seconds or earlier scope expiry, with an exclusive end time.
Changed or expired grants require fresh planning and any required confirmation.

```python
from datetime import datetime, timezone

from fuzzy1337.executors import LocalExecutionRequest
from fuzzy1337.policy import GovernedLocalExecutor, PolicyConfirmation, PolicyEngine

engine = PolicyEngine()
context = ReadCurrentContext()  # trusted scope/policy and pinned destination reader
at = datetime.now(timezone.utc)
plan = engine.Plan(invocation, capability, context, at=at)
# Present the exact operation and wait for approval before creating this record.
confirmation = PolicyConfirmation(plan.intent_sha256, "approval:operator-record")
grant = engine.Authorize(invocation, capability, context, at=at, confirmation=confirmation)
request = LocalExecutionRequest(invocation, capability, grant.authorization)
result = await GovernedLocalExecutor(workspace_root).Execute(
    request, grant=grant, context_provider=ReadCurrentContext
)
```

The example requires a consumer-provided trusted reader, prepared invocation,
capability and operator approval. It is a library integration pattern, not a
runnable scanner or permission to execute a target.

## Failures and trust limits

`PolicyDeniedError.reason` is a `PolicyDenialReason`; scope/membership failures
also preserve `scope_reason`. Missing/denied consent, unregistered or restricted
destinations, disallowed provider/capability, excess impact, missing privileges,
missing/mismatched confirmation, stale bindings and invalid validity intervals
fail closed. An authority-reader failure propagates before launch. No started or
successful execution event is emitted for launch-time policy denial.

`GovernedLocalExecutor` retains truthful terminal state, streams, event ordering,
resource limits and cancellation from `LocalExecutor`. Concurrent requests own
separate pre-launch hooks. Already-cancelled requests retain the existing no-launch
cancellation result.

The legacy `LocalExecutor` accepts trusted caller-issued SDK envelopes and does
**not** independently load scope or evaluate policy. Its optional synchronous
`pre_launch` hook returns `None` or raises; async/non-void hooks are rejected.
Use the governed facade when the caller needs these policy checks.

Neither envelope nor confirmation references are cryptographic proof of external
consent. The operator and trusted consumer own consent records and destination
observations. Providers must pin resolved destinations or check every later DNS
resolution/redirect before use. The subprocess boundary is not an OS network
sandbox and does not automatically revoke already-running processes. Workspace,
environment and output/resource enforcement remain executor-owned contracts.
