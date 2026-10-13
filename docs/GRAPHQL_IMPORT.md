# Offline GraphQL introspection import

The Experimental `fuzzy1337.graphql_import` module imports explicitly supplied
owned introspection JSON bytes and a caller-selected endpoint. It neither sends
an introspection query nor assumes introspection is enabled. Supply exact source
bytes yourself; descriptions grant no transport, authentication or scope
authority.

```python
from fuzzy1337.graphql_import import ImportGraphQl, GenerateGraphQlRequest

imported = ImportGraphQl(
    owned_introspection_bytes,
    workspace_id="owned-workspace",
    endpoint_url="http://127.0.0.1:8080/graphql",
)
operation = next(item for item in imported.operations if item.field_name == "lookup")
preview = GenerateGraphQlRequest(
    owned_introspection_bytes,
    operation.Reference(),
    workspace_id="owned-workspace",
    endpoint_url="http://127.0.0.1:8080/graphql",
)
```

`owned_introspection_bytes` is caller-owned UTF-8 JSON, never a filename or URL.
Accept a direct `{"__schema": ...}` export or successful
`{"data": {"__schema": ...}}` envelope. Errors, duplicate JSON keys or names,
unknown consumed declaration fields and invalid type bindings fail explicitly.
Source hashes cover original bytes, including whitespace. Original JSON Pointers
address the actual source array positions. Reformatting changes source and
operation/preview identities while equivalent symbolic request identities may
remain equal.

Each root field becomes a typed query, mutation or subscription operation using
the existing POST Endpoint, GraphQL RequestTemplate and `/variables/<name>`
InjectionPoint contracts. Metadata preserves list/non-null wrappers, input-object
definitions, declared enum identifiers and default-presence flags. Descriptions
and default literals are excluded. Root operation kinds produce distinct
operation names even when their fields/arguments have identical names.

Preview preparation reimports the same source and exact caller context. It
renders fixed built-in scalar values, the lexically first declared enum name,
single-member lists and complete input objects. Custom scalar synthesis,
oneOf input objects and input cycles are refused. Required singular non-null
input cycles are invalid and refused during import; nullable/list recursion can
remain finite metadata but has no synthesized preview. Object/interface/union
results select only `__typename`; leaf results have no selection set. Subscription
operations are descriptive only and their previews are refused. Mutation
preparation grants no permission to execute a mutation.

`preview.body` is ephemeral JSON with `query`, `operationName` and `variables`.
Headers contain only `content-type: application/json`. `preview.Metadata()`
exposes source/request/target/operation/body-digest references without concrete
body contents. Imported type definitions describe a structural profile; this
module is neither a complete GraphQL validator nor an SDL/operation parser.

`ProjectGraphQl(imported, provenance=(... ,))` produces an existing Endpoint
patch with complete request collections and typed `graphql_import` metadata.
The caller owns source/metadata acquisition through `LocalEvidenceStore`, exact
evidence references in `ModelProvenance`, model Apply/CAS persistence and
composition with other observations. Preserve source evidence explicitly;
projection does not acquire bytes, register targets or manufacture findings.
Reopen original evidence with its actual store owner and reimport it to replay.

`CheckGraphQlTarget(operation, preview.target, current_scope, at=aware_time)`
checks the exact selected URL and same-workspace existing scope consent/rules.
It returns an existing membership decision. It does not approve operation
impact, a runtime invocation or execution authorization. It mutates no scope or
workspace state. An imported schema cannot create consent or override a deny
rule.

Limits are 512 KiB source, 10000 JSON nodes, depth 24, 128 named types, 32 root
operations, 32 argument/input/enum members, wrapper and generated depth 8,
2048 generated nodes, 32 KiB concrete body and 256 KiB imported metadata.
Existing model attribute limits still apply and can refuse a larger projection.
No URL, reference or scalar declaration is fetched.

SDL and traffic-derived inputs, broader endpoint discovery, authenticated
profiles, active checks and governed live execution remain under Task #145 and
Feature #143. Existing OpenAPI import and request/model schemas are unchanged.

See [ADR 0065](adr/0065-bounded-graphql-introspection-import.md) and the owned
fixture in `tests/contract/fixtures/graphql_introspection.owned.json`. Focused
tests exercise independent JSON/GraphQL preview oracles, real source/evidence
replay and model save/reopen/relocation, exact scope denials and resource failures.
