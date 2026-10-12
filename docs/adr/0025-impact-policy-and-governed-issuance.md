# ADR 0025: Bounded impact policy and governed authorization issuance

## Status

Accepted — 2026-10-11

## Context

The executor SDK verifies an immutable invocation binding, but its authorization
record deliberately delegates scope and policy decisions to a trusted caller.
Task #32 requires one explicit guardrail for human, agent and CI operators without
an enterprise approval system or a policy language.

## Decision

Introduce Experimental `fuzzy1337.policy` contract version `1`. An immutable
`ImpactPolicy` starts with a `SAFE` ceiling and no capability/provider grants.
Explicit `CapabilityPermission` records permit one capability/provider pair,
an impact ceiling and named privileges. The existing ordered `ImpactLevel`
values remain `PASSIVE`, `SAFE`, `STANDARD`, `ACTIVE`, and `INTRUSIVE`.

`PolicyEngine.Plan` checks the requested target and every actual destination
against the current scope, then capability/provider, impact and privileges.
A plan binds the complete scope content and revision, policy content and
revision, capability declaration, normalized target/destinations and exact
prepared invocation. `STANDARD`, `ACTIVE` and `INTRUSIVE` always require an
explicit confirmation referring to that exact plan digest. Scope consent is
required for all impact levels. A confirmation record is operator-attested
metadata, not proof of an external signature or ownership.

`Authorize` issues a bounded-lifetime `PolicyGrant` only after those checks.
`Validate` checks the grant against fresh context and time. Any changed scope,
policy, invocation, capability, target or destination fails closed; even an
unsaved same-revision scope/policy edit invalidates the binding. Scope expiry
and grant expiry are independent denial boundaries.

`GovernedLocalExecutor` uses the existing executor's optional synchronous
`pre_launch` hook to read and revalidate context immediately before process
creation. Callers provide trusted current scope/policy and observed destinations;
a callback failure or denial starts no process. Each execution owns its hook,
so concurrent jobs share no mutable authorization state. Existing SDK consumers
and `LocalExecutor` remain compatible: a manually issued SDK envelope still
requires a trusted upstream issuer and is not itself policy evaluation.

## Trust and destination boundary

The policy evaluates explicit normalized literals offline. It performs no DNS,
redirect following, scanner flag parsing, credential access or network I/O.
Consumers must provide every actual resolved address and redirect destination,
register/allow each explicitly, and pin those observations into the prepared
operation. Actual destinations must be IP or URL literals; a URL destination
also requires explicit resolved IP destinations. Domain/network inputs alone
are not an actual-destination observation. No alias or containment grants are
invented by policy; the existing scope rules own membership semantics.

Adapters remain trusted impact classifiers and invocation producers. A declaration
does not sandbox arbitrary provider code. Subprocess revalidation is a launch
boundary, not an OS network sandbox: a provider that performs later resolution
or redirects must use pinned destinations or check each new destination before
use. Already-running subprocesses are not automatically revoked. Environment,
workspace and portable resource bounds remain executor-owned contracts.

## Consequences and validation

- The same deterministic plan/confirmation/grant boundary serves people,
  external AI agents and preapproved CI configurations.
- Empty policy, unknown consent, disallowed providers, excess impact, missing
  privileges and missing/mismatched confirmation cannot issue a grant.
- Contract tests cover all five impact levels and changed authorization inputs.
- Real owned-child execution tests prove launch-time denial, successful streams,
  cancellation and truthful nonzero exit behavior without network scans.
- No general DSL, policy persistence, remote approval service, CLI scan command,
  implicit resolver, OS sandbox or autonomous scanning is introduced.
