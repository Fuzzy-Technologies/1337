# ADR 0014: Provider-Neutral ToolAdapter Contract

## Status

Accepted

## Context

1337 needs to integrate familiar security tools, native engines, browsers, and
future private providers without making any provider's output schema part of the
shared Security Object Model. The integration boundary must preserve what a
provider declares, what was requested, how an invocation ended, and which raw
evidence supports its normalized output.

The boundary must also remain subordinate to the Workbench's Scope, Policy,
Impact, Executor, and Evidence contracts. An adapter can describe a capability;
it cannot authorize or directly bypass governed execution.

## Decision

1337 introduces an experimental, versioned Python ToolAdapter SDK under
`fuzzy1337.adapters`.

The SDK defines provider-neutral immutable contracts for:

- adapter identity, declared capabilities, maximum impact, and required
  privilege identifiers;
- health results and observed provider version;
- execution requests and prepared, non-secret invocation metadata;
- executor-owned outcome records and raw-evidence references;
- normalized observations, findings, object enrichments, and relation
  enrichments.

An adapter implements only three provider-facing operations:

1. report health;
2. prepare a declared invocation from an approved request;
3. normalize an executor report into generic Workbench output envelopes.

The SDK records an argument vector, timeout, provider version, exit status, and
raw-evidence references. It does not execute a command, resolve credentials,
apply policy, persist evidence, or mutate the Security Object Model. Credential
references remain opaque and secret values are never part of the contract.

Provider-specific fields may be retained as immutable JSON-like attributes at the
adapter boundary. They must not create provider-specific object or relation types
in the shared model.

## Consequences

Positive:

- Nmap, Nuclei, Trivy, browsers, native engines, and private adapters can share
  one testable integration boundary.
- Raw evidence remains distinct from normalized output, enabling later replay,
  audit, and parser regression analysis.
- Scope, impact, authorization, and executor decisions remain explicit future
  runtime responsibilities.

Negative:

- The first SDK is intentionally an experimental surface until multiple real
  adapters validate its shape.
- Adapter authors must model provider-specific payloads outside the shared core
  and write normalization tests for their own mappings.

## Non-goals

This ADR does not implement a tool executor, policy engine, credential resolver,
Security Object Model store, plugin loader, or a concrete third-party adapter.

## Invariant

> A ToolAdapter declares and normalizes a provider. It never grants authority or
> turns provider output into trusted state without governed execution and
> evidence.
