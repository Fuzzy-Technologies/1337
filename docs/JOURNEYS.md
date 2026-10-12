# Synthetic journey declarations

`fuzzy1337.journeys` is an Experimental Python library and scenario JSON schema at
version `1`, defined by [ADR 0034](adr/0034-bounded-synthetic-journey-contract.md).
It validates hand-written browser/API scenario declarations and prepares
membership evidence against existing [scope](SCOPE.md) records. No browser or
workload engine runs, no session/data reference is resolved, and no executor
authorization is issued.

## Supported API

The Experimental surface consists of `JourneyOperation`, `JourneyAssertionKind`,
`JourneyHttpMethod`, `JourneyAssertion`, `WorkloadLimits`, `JourneyStep`,
`JourneyScenario`, `PreparedJourney`, `PrepareJourney`, `JOURNEY_SCHEMA_VERSION`,
`MAX_JOURNEY_BYTES`, `MAX_JOURNEY_STEPS`, and `MAX_JOURNEY_ACTIONS`.
Supported serialization operations are:

- `JourneyAssertion`, `WorkloadLimits`, and `JourneyStep`: `ToDict` and `FromDict`;
- `JourneyScenario`: `ToDict`, `FromDict`, `ToJson`, `FromJson`, and `Digest`;
- `PrepareJourney(scenario, scope, at=<aware datetime>)`: offline scope preparation.

Other helpers are Internal. Frozen slotted records copy accepted list inputs into
tuples; caller mutation of those collections or serialized output cannot change
the record. Construction and preparation have no filesystem/network side effects.

## Scenario schema and units

Every schema-v1 object requires all its declared fields, including explicit null
for absent optional bindings. Extra fields are rejected at every boundary.
Identifiers are lowercase existing adapter-style identifiers, at most 128
characters. Scenario fields are `schema_version`, `scenario_id`, `workspace_id`,
`scope_id`, `allowed_targets`, `steps`, `workload`, `test_data_reference`, and
`session_reference`.

`allowed_targets` is a nonempty ordered tuple of at most 64 unique existing
`Target(TargetKind.URL, ...)` records. It restricts a scenario to exact URLs and
does not expand scope. Every step target must occur in this list. Existing target
normalization, canonical persisted spelling, and `target:<SHA-256>` identity are
reused without a new target namespace. Schemes, ports, paths, queries, redirects,
and subresources remain separate exact targets; domain or IP allow rules do not
grant URL authority.

Each step requires `step_id`, `operation`, `target`, `assertions`, `think_time_ms`,
`selector`, `method`, and `test_data_key`. Step identifiers must be unique within
the ordered nonempty scenario of at most 64 steps.

| Operation     | Target meaning           | Selector | HTTP method | External test-data key |
| ------------- | ------------------------ | -------- | ----------- | ---------------------- |
| `navigate`    | Exact requested page URL | Null     | Null        | Null                   |
| `click`       | Exact current page URL   | Required | Null        | Null                   |
| `fill`        | Exact current page URL   | Required | Null        | Required               |
| `api_request` | Exact requested API URL  | Null     | Required    | Optional               |

Supported HTTP methods are `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, and
`OPTIONS`. Method declaration does not classify impact or authorize a request.
A selector is one lowercase tag, `#id`, `.class`, or `[data-test="identifier"]`;
combinators, XPath, executable expressions, and templates are unsupported.

Every step has 1–16 assertions, each with exactly `kind` and `expected`:

| Kind              | Expected value                                       |
| ----------------- | ---------------------------------------------------- |
| `http_status`     | Integer HTTP status from 100 through 599             |
| `text_contains`   | Nonempty single-line literal text, at most 256 chars |
| `element_present` | One supported simple selector; unsupported for API   |

Literal assertion text and selectors reject control characters, braces, and
angle brackets; nothing is substituted or evaluated. Text assertions describe
literal containment, without regex, XPath, or arbitrary JavaScript semantics.
`think_time_ms` is an integer from 0 through 60000. Its declared meaning is a
delay after successful assertions for that step, before advancing or finishing
an iteration; it counts toward elapsed duration. This library does not wait.

`test_data_reference` is null or `test-data:<identifier>`; `session_reference` is
null or `session:<identifier>`. Any step data key requires a non-null external
test-data reference. Keys select synthetic values held by the caller for fill or
API input. Request headers, raw bodies, cookies, tokens, usernames/passwords,
credential material, and session state are never embedded in the scenario. A
reference is neither an identity credential nor proof of an authenticated session.
Callers must keep all metadata non-secret; syntax cannot prove that a supplied
reference or URL query does not disclose a secret.

All workload fields are required, with positive integer values and these ceilings:

| Field                  | Meaning                                             | Ceiling |
| ---------------------- | --------------------------------------------------- | ------- |
| `iterations`           | Total complete scenario attempts across all users   | 1000    |
| `concurrency`          | Maximum simultaneously active iterations            | 16      |
| `requests_per_second`  | Aggregate request-rate ceiling across all users     | 100     |
| `max_requests`         | Aggregate request-count stop ceiling                | 100000  |
| `max_duration_seconds` | Total elapsed run-duration stop ceiling, in seconds | 3600    |

Concurrency cannot exceed total iterations. `len(steps) * iterations` cannot
exceed 10000 declared actions. Iterations do not multiply the rate/concurrency
ceilings. An actual provider must stop at any exhausted request/duration ceiling,
even before requested iterations finish, and report partial completion. A browser
action may generate several requests, so action count is not an HTTP request
budget. There is no runtime measurement or enforcement in this initial task.

## Parsing and content binding

The standalone [JSON schema](../contracts/journey-scenario.schema.json) checks
finite structural fields. `JourneyScenario.FromDict` is also required: it checks
canonical existing Target spelling, duplicate step IDs, exact target declarations,
external data bindings, concurrency/iteration relationships, aggregate actions,
and document size. Python rejects booleans/floats in integer fields even though
JSON Schema defines an integral floating-point number as an integer.

`FromJson` additionally rejects duplicate keys, non-finite numeric constants,
malformed UTF-8-compatible text, excessive nesting, and oversized input. Use it
for untrusted serialized JSON; `FromDict` assumes its upstream parser has already
rejected duplicate keys. Unsupported versions fail closed without fallback.
Serialized scenarios are limited to 65536 UTF-8 bytes on input and after canonical
serialization. No file loading, imports, source evaluation, or network resolution
occurs.

`ToJson()` is sorted-key compact `json.dumps(..., ensure_ascii=False,
separators=(",", ":"))`, without a newline. `Digest()` is `sha256:` plus the
lowercase SHA-256 of those UTF-8 bytes. This identifies scenario content; it is
not a signature, authenticity assertion, or executor approval.

## Scope preparation

`PrepareJourney` requires matching `scenario.workspace_id` and `scope.workspace_id`
plus matching scope IDs and explicit timezone-aware time. It calls existing
`ScopeSnapshot.Check` for every exact declared URL, including unused declarations.
Unknown/revoked/invalid-time consent, unregistered URLs, exclusions, denies, and
missing exact allow rules raise `PermissionError` with the existing reason.
Invalid types, owner binding, or time raise `ValueError`. Targets are never
registered, rules rewritten, or consent added during preparation.

The returned `PreparedJourney` retains the immutable scenario, its content digest,
exact checked scope revision, UTC normalized `checked_at`, and ordered decisions.
Direct record construction checks these fields for consistency, but cannot prove
scope/consent authenticity. Membership is preflight evidence only. A later scope
change cannot mutate existing evidence; subsequent preparation must consume the
new snapshot and can be denied.

A future provider must obtain governed invocation-bound authorization, apply
impact/workload policy, and recheck current scope plus every actual destination.
Redirects, subresources, popups, navigation caused by clicking/filling, DNS answers,
and session credentials need separate runtime handling. Prepared records cannot
be treated as persistent permission to send traffic. This library introduces no
workspace or Security Object Model schema, relations, or persisted truth store.

## Reproducible offline example

[`synthetic-journey.v1.json`](../tests/contract/fixtures/synthetic-journey.v1.json)
is an independently schema-tested, hand-written mixed browser/API fixture. Its
loopback URLs are declarations only; no target service is needed for these checks.

```python
from datetime import datetime, timezone

from fuzzy1337.journeys import JourneyScenario, PrepareJourney
from fuzzy1337.scope import (
    AuthorizationState, ScopeAuthorization, ScopeSnapshot,
)

# scenario_json is the synthetic fixture text, supplied by the caller.
scenario = JourneyScenario.FromJson(scenario_json)
scope = ScopeSnapshot(
    scenario.scope_id, scenario.workspace_id,
    ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:synthetic", "consent:synthetic",
    ),
    targets=scenario.allowed_targets,
    allow=scenario.allowed_targets,
)
prepared = PrepareJourney(
    scenario, scope, at=datetime(2026, 10, 11, tzinfo=timezone.utc),
)
assert prepared.scenario_digest == scenario.Digest()
# Preparation is membership evidence only; it does not run or approve traffic.
```

UI/AI generation, recording, providers, actual synthetic traffic, session/data
storage, executor integration, persisted scenarios, and runtime outcomes remain
separate future work. This contract has no dependency on unmerged API operations.
