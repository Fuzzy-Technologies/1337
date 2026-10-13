# ADR 0065: Bounded offline GraphQL introspection import

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #145, #143, #58

## Context

Existing request contracts already describe GraphQL variables but have no
source-bound typed operation producer. Introspection availability and permission
cannot be assumed. Supplied descriptions must remain observations, rather than
transport, authentication or execution grants.

## Decision

Add an Experimental offline importer for explicitly supplied UTF-8 introspection
JSON bytes and a caller-selected concrete endpoint URL. Accept a direct
`__schema` object or a successful `data.__schema` envelope, with exact source
byte digests and original JSON Pointer coordinates. Refuse response errors,
unknown consumed semantics, duplicate names/keys, invalid references and
resource excess. Do not open paths, fetch descriptions or infer endpoint URLs.

Produce typed query, mutation and subscription root-field metadata using the
existing POST Endpoint, GraphQL RequestTemplate and variable InjectionPoint
contracts. Preserve type wrappers, argument/default-presence metadata, enums
and input-object definitions without retaining descriptions or default values.
Imported mutations/subscriptions remain descriptive only.

Preview preparation reimports the original bytes and selects an exact operation
reference. Generate only fixed synthetic built-in scalars, declared enum names,
single-member lists and bounded input objects. Refuse custom scalar synthesis,
oneOf input objects and input cycles rather than guessing a value or truncating
a required branch. For object/interface/union output, select only `__typename`,
which avoids output graph traversal; leaf output has no selection set.
Subscription previews are refused because this slice owns no subscription
transport. Generated bodies remain ephemeral. Their references bind source,
operation and the actual synthetic encoding.

Scope preflight consumes the exact caller-selected URL and current existing
same-workspace scope snapshot. It neither approves the operation's impact nor
creates authorization. Projection composes existing model request collections
with typed source metadata and caller-owned evidence provenance. No new truth
store, model schema, target registration or finding is introduced.

## Bounds and compatibility

Bound source bytes to 512 KiB, JSON nodes to 10000 and nesting to 24. Bound named
types to 128, root operations to 32, arguments/input fields and enum members to
32, type wrappers and generated input expansion to depth 8, and synthetic body
and generated nodes to 32 KiB and 2048. Fail explicitly when import metadata or
existing model attributes exceed their owners' serialization limits.

Existing OpenAPI import, request schemas and JSON identities remain unchanged.
Task #145 stays open for SDL and traffic inputs, broader schema validation,
endpoint discovery, authenticated workflows and governed live execution.

## Verification

Use independent hand-authored introspection and request oracles. Exercise actual
model Apply/save/reopen/relocation, exact original evidence replay, typed request
decoding and scope consent/deny checks. Verify recursion, partial/error results,
reference substitution, source byte changes and resource failures. No browser,
remote introspection or live scanner target is needed for this offline slice.

## Primary references

- [GraphQL September 2025 introspection](https://spec.graphql.org/September2025/#sec-Schema-Introspection)
- [GraphQL type references](https://spec.graphql.org/September2025/#sec-Type-References)
- [GraphQL input objects](https://spec.graphql.org/September2025/#sec-Input-Objects)
- [ADR 0028](0028-structural-web-request-contracts.md)
- [ADR 0038](0038-offline-openapi-request-import.md)
