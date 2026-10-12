# ADR 0034: Bounded synthetic browser and API journey contract

## Status

Accepted — 2026-10-11

## Context

M4 task #154 needs a portable scenario definition before optional browser and
workload providers exist. Hand-written scenarios must describe finite actions,
assertions, synthetic data bindings, session references, think time, and workload
ceilings. Future UI or AI generation must consume the same contract rather than
introducing executable scripts or a separate authorization model.

[ADR 0009](0009-operator-profiles-and-orthogonal-execution-dimensions.md),
[ADR 0010](0010-live-security-object-model-modular-tooling-and-lenses.md), and
[ADR 0012](0012-human-and-ai-operator-model.md) require explicit scope/policy,
replaceable providers/operators, and one Security Object Model.

## Decision

Introduce Experimental `fuzzy1337.journeys` and
`contracts/journey-scenario.schema.json`, both at schema version `1`.
The library parses immutable bounded declarations and prepares existing scope
membership evidence offline. It performs no browser, HTTP, DNS, session, or
workload operation.

Scenarios bind existing workspace and scope identifiers, declare exact URL
`Target` objects, and contain finite `navigate`, `click`, `fill`, or `api_request`
steps. Reuse schema-v1 `Target` identity and `ScopeSnapshot.Check`; no new target,
identity, authorization, or Security Object Model schema is introduced.

Assertions support explicit HTTP status, literal text containment, and simple DOM
element presence. Selectors use a finite tag/ID/class/data-test grammar. Inline
scripts, templates, request headers/bodies, raw credentials, cookies, and session
state have no fields. External synthetic data and session state are named by
opaque references only; their resolution is outside this library.

Every workload field has a finite integer ceiling. Steps and iterations also have
a combined action ceiling. JSON byte size, identifiers, text, arrays, and think
time are bounded. Unknown versions, fields, duplicate JSON keys, non-finite
numbers, and numeric coercion fail closed. Structural JSON Schema validation is
necessary but insufficient: runtime validation additionally enforces canonical
target spelling, binding relationships, unique steps, exact Python numeric types,
and aggregate limits.

`PrepareJourney` requires explicit aware time and the matching workspace/scope
snapshot. It checks every declared exact URL, including unused declarations,
without registering targets or changing consent. Successful preparation retains
the deeply immutable scenario, canonical content digest, observed scope revision,
check time, and scope decisions. It is membership evidence and issues no executor
authorization. Recreating the evidence record is not an authenticated grant.

## Consequences

- Hand-written browser/API scenarios can be validated and independently consumed
  before providers are implemented. UI and AI generators may later emit the same
  strict schema; generation itself grants no authority.
- A future provider must apply impact policy and obtain invocation-bound executor
  authorization separately. It must recheck current scope and actual destinations,
  including redirects, browser subresources, popups, and action-induced requests.
- Workload ceilings are declarations in this task, not measured or enforced
  runtime throughput. All request limits are aggregate across concurrent users;
  browser request counts cannot be inferred from action counts.
- Existing domain/IP rules do not authorize URLs. Existing denied host/network
  projections continue to restrict allowed exact URLs. No DNS or origin-level
  wildcard expansion is added.
- No CLI, scenario persistence owner, model relation, session store, recorder,
  browser executor, workload engine, runtime result, or timing benchmark is added.
  Preparation is not evidence that a journey actually ran.

## Alternatives considered

Executable browser scripts or arbitrary templated request bodies were rejected:
they expand scope and create code/session handling before a governed runtime
exists. Origin-level allowlists were rejected because existing URL authority is
exact and must not silently widen. Reusing human/AI persona labels as workload
authorization was rejected by the shared-state and operator invariants.

The complete supported interface and units are defined in
[`docs/JOURNEYS.md`](../JOURNEYS.md).
