# ADR 0028: Structural web request contracts

- Status: Accepted
- Date: 2026-10-11
- Decision owners: Fuzzy Technologies
- Related work: #58, #53, #146

## Context

Native web scanning, API imports and browser journeys need one request model.
The existing Security Object Model already owns Endpoint identity, observations
and persistence. Scope, authorization, execution and session acquisition belong
to other contracts. Captured HTTP requests often contain credentials or private
data and are unsuitable as reusable persisted templates.

## Decision

Add an Experimental `fuzzy1337.requests` library with immutable `Endpoint`,
`RequestTemplate`, `InjectionPoint`, `ValueBinding` and `SessionReference`
contracts. An endpoint identifies a canonical HTTP(S) origin, a structural path
template and an uppercase method within a workspace. Its identity is the existing
`ObjectIdentity` with kind `endpoint`, with a canonical JSON natural key. Origin
normalization reuses scope's offline URL canonicalization and grants nothing.
Origins have no userinfo, query, fragment or non-root path. Path variables use
named `{slot}` segments; raw query strings, encoded path material, dot segments
and inline values are rejected.

Templates contain structure and named value bindings, never captured request
values, headers, cookies, bodies, GraphQL documents or credentials. Runtime input
bindings and session bindings are opaque placeholders; neither resolves values.
Session references bind a non-secret session identifier to the same workspace.
Session acquisition, refresh, credential storage and request assembly remain #146
and executor responsibilities. No heuristic can identify every sensitive string:
producers must use structural paths/selectors and non-secret identifiers rather
than encoding a secret in an identifier.

Typed injection locations cover query, body, JSON, cookie, header, path, GraphQL
variables and multipart inputs. Selectors and duplicate-occurrence indexes have
location-specific validation. JSON selectors use RFC 6901 syntax; GraphQL
selectors address variables. Body encodings and optional GraphQL operation names
are explicit. Header selectors canonicalize to lowercase. Path selectors must
resolve to declared path variables; session bindings require a session reference.

Schema version 1 uses strict fields, canonical stored spelling and recomputable
SHA-256 template references. Injection identity is bound to its request template,
location, selector and occurrence. Collection order is deterministic; duplicate
injection coordinates are rejected. Parsing rejects duplicate JSON keys,
non-finite values, unknown versions and oversized envelopes.

## Persistence and authority

`ProjectRequests` groups templates into an Endpoint attribute projection named
`request_templates`; `RequestsFromObject` validates the real consumer boundary.
The existing model store owns revision checks, attributed observations, atomic
writes and relocation. A projection replaces that attribute's complete
collection, so callers compose all current templates before applying a patch.
Unrelated Endpoint attributes survive the model's existing patch semantics.

The library performs no network, browser, filesystem or credential access. It
does not register targets, change scope, authorize requests or execute mutations.
A template and an origin are descriptions, never permission. Downstream runtime
owners must obtain fresh scope/policy approval for concrete substituted targets,
resolved destinations, redirects, methods, request bodies and injection payloads.

## Validation

Unit and schema contracts cover all eight locations, canonical identities,
strict decoding, body/selector coherence, duplicates, bounds and secret-bearing
capture rejection. Integration tests run the actual projection through the
existing workspace/model/evidence stores, reopen and move the workspace, replay
idempotently and prove scope/evidence ownership is unchanged. No HTTP requests or
browser checks are needed. Per-module branch coverage remains above 80%.
