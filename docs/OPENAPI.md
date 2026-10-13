# Offline OpenAPI import

`fuzzy1337.openapi` is an Experimental library at import contract version `1`.
It accepts supplied **JSON text** by default, or explicitly selected bounded YAML,
producing existing structural request contracts and attributable operation
metadata. It reads no file, contacts no server,
fetches no reference and resolves no session. It emits no concrete request values
and sends no HTTP traffic. This advances the schema-import slice of #144;
[synthetic request previews](API_REQUEST_GENERATION.md) are available separately;
general schema-valid test generation and execution remain open.

## Supported interface

- `ImportOpenApi(text, workspace_id=..., base_url=None, session_reference=None,
  document_format="json")`
  returns an `OpenApiImport` with immutable operation/input/security records.
- `ProjectOpenApi(imported, provenance=...)` returns existing Endpoint model
  patches. Save them through `ModelState.Apply` and `LocalModelStore` with its
  expected revision, using the existing model/evidence owners.
- `CheckOpenApiTarget(operation, concrete_target, scope, at=...)` checks a supplied
  actual URL against endpoint shape and current exact workspace-bound scope.

Result records expose `ToDict`; each operation exposes `Reference` and a real
`RequestTemplate`. Records are outputs of the parser. Direct record constructors
and parsing helpers are Internal; they do not validate source authenticity or
grant execution authority. There is no import-result decoder or independent
source/scenario database.

## Supported descriptions and limits

OpenAPI **3.0.x**, **3.1.x** and Swagger **2.0** are accepted within this subset.
This is not a complete OpenAPI or JSON Schema validator. Descriptions, examples,
defaults, enums, constraint expressions, responses and vendor-extension values
are not copied. Consumed unsupported features fail without returning a partial
import; unconsumed schema/response sections are not independently validated.

| Boundary                      | Limit                  |
| ----------------------------- | ---------------------- |
| Input JSON or YAML            | 1 MiB UTF-8 bytes      |
| JSON-compatible nodes / depth | 20000 / 32             |
| Reference/schema work         | 4096 resolution visits |
| Reference/body nesting        | 16                     |
| Generated operation rows      | 128                    |
| Servers / media variants      | 4 / 8 per operation    |
| Canonical import output       | 512 KiB UTF-8 bytes    |

The existing request contract additionally limits a template to 128 injection
points and 64 KiB; the existing model limits each attribute projection to 64 KiB.
Duplicate JSON keys, non-finite numbers, invalid Unicode and excessive nesting
are rejected, including in ignored source fields. Validation errors do not echo
invalid enum values or duplicate-key text.

## Explicit optional YAML input

Install `1337[openapi-yaml]` and pass `document_format="yaml"`; the optional parser
is pinned to PyYAML 6.0.3. Existing JSON callers do not load or require that
dependency. No format is detected automatically, and invalid JSON never retries
through another parser.

The decoder consumes parser events without constructors or legacy implicit
resolvers. Accept one JSON-compatible YAML document with flow/block collections,
comments, strings, optional BOM/document markers and an optional YAML 1.2
directive. Collection/scalar nodes, including mapping keys, are bounded before
the tree is built. Root depth is zero. Built-in JSON-compatible tags must match
their node type. Refuse custom tag directives, tags/types outside this profile,
anchors/aliases, merge keys, duplicate decoded keys, non-string/complex keys,
multidocument streams, invalid Unicode and non-finite/overflowing numbers, even
in ignored fields. Diagnostics exclude parser marks and original source text.

Plain lowercase `null`, `true`, `false` and finite JSON-number spellings decode
as their JSON types; an empty plain node is null. Quoted/block values are strings
unless an explicitly supported scalar tag declares a matching lexeme. Ordinary
words such as `on`/`yes`, dates and dotted OpenAPI versions remain strings.
Ambiguous numeric forms such as `01`, `+1`, `.5`, `1.`, `0x12`, `1_000` and `1:00`
fail. Quote numeric response codes, Swagger version `'2.0'` and the string schema
type `'null'`. This is a declared bounded subset, not full YAML Core semantics.

```python
from fuzzy1337.openapi import ImportOpenApi

imported = ImportOpenApi(supplied_yaml_text, workspace_id="owned",
                         document_format="yaml")
```

The source digest uses the exact original UTF-8 bytes, including comments/BOM,
without YAML-to-JSON normalization. Equivalent YAML/JSON presentations preserve
the same structural request identities but different operation identities when
their source bytes differ. Strict JSON bytes explicitly parsed as YAML have the
same interpretation and existing identity. All common reference, schema, server,
auth and scope boundaries below apply to either input format. See
[ADR 0061](adr/0061-bounded-openapi-yaml-input.md).

Local `$ref` uses canonical `#/...` JSON Pointers, including `~0`/`~1` escapes
and canonical array indexes. Referenced cycles, external/URI references,
semantic `$ref` siblings, schema compositions/discriminators and dynamic schema
identities fail when consumed. No `$id`, remote schema base or URI anchor changes
the resolver's authority. Schema booleans and server variables are unsupported.

OpenAPI server precedence is operation, path, then root. Absolute literal
HTTP(S) server URLs are normalized offline. Root-relative paths such as `/v1`
need an explicit `base_url` authority; other relative forms are unsupported.
An absent/empty server list uses `/` on the supplied authority. `base_url` is a
resolution context, not a deployment override. Swagger combines host/basePath/
schemes, with host/scheme context supplied explicitly when absent; operation
schemes override root schemes. No source URL implicitly registers a target.

## Symbolic request generation

Endpoints reuse workspace, normalized origin, structural path and method
identity. Source operation IDs are preserved; duplicates are rejected. Every
path variable requires its declared required path parameter. Operation parameters
override path parameters by location/name; header coordinates are lowercase.

Query/path/header/cookie inputs reuse existing injection descriptors. OpenAPI
supports default `form`/`simple` styles and retains `explode` metadata. Other
styles, `allowReserved` and parameter `content` are unsupported. Swagger retains
the declared collection format; it does not serialize its values. Reserved
Authorization/Accept/Content-Type parameter declarations are rejected instead of
being treated as ordinary credentials or values.

Bodies support JSON and `application/*+json`, URL-encoded forms, multipart and
plain text. Fixed JSON object properties become RFC 6901 selectors; arrays,
scalars and unspecified schemas remain whole-value symbolic bindings. Read-only
body properties are omitted. Form/multipart inputs require named properties;
nested form expansion and custom encoding are unsupported. Swagger body and
formData declarations use their original source pointers; they cannot be mixed.

Every input retains type, required/nullable flags, serialization metadata and a
source pointer. `required` means unconditionally required for the declared
request, and `schema_required` records immediate-parent property requirements
when that parent is present. An operation separately retains `body_required`;
an optional body can still contain required properties. These flags do not
replace conditional schema validation. `constrained` reports unrepresented schema constraint keywords;
their values are not retained or evaluated. A false flag does not certify a
complete schema validator. No default/example/enum is selected as a test value.
The runtime must generate, validate and bound actual values separately.

Security annotations preserve **OR alternatives**, each containing **AND scheme
requirements**, including an empty anonymous alternative. Supported annotations
include API keys, basic/bearer HTTP, OAuth2, OpenID Connect and mutual TLS; these
are descriptors, not validated authentication profiles. Credential slots/flows
are not selected, issuer URLs are not retained and no auth request is assembled.
An optional caller-owned session reference remains unresolved in the template.
Callers must use non-secret operation IDs, names, selectors, URLs and references;
syntax cannot recognize every secret disguised as metadata.

## Provenance, persistence and scope

Each record binds the exact supplied input-byte SHA-256 digest, source JSON
pointer, media annotation and request reference. Distinct media annotations may
share one identical structural request. The projection deduplicates such request
identities while preserving both operation records and existing model attribution.
Keep original source material outside public projections; evidence may store the
sanitized import result without its private defaults/examples.

`request_templates` and `openapi_operations` are **complete collections** for
each affected endpoint. Compose all source collections before replacing these
attributes. Unrelated Endpoint attributes survive the existing patch semantics.
Projection itself performs no persistence or scope mutation.

Preflight accepts only a supplied concrete URL of the same origin/route shape,
including the actual query, and the matching workspace. Path slots are not scope
wildcards: the concrete target must already be registered, explicitly allowed
and covered by valid consent. Denies/exclusions still apply. The returned scope
decision proves offline membership in the supplied snapshot only; retain its
revision and operation reference as evidence. It does not approve the method,
payload, session or future destinations. Runtime execution must recheck current
scope and obtain governed invocation authorization, including redirects/DNS.

## Remaining work

OpenAPI 3.2 and other versions, complete schema/auth profile validation,
general test-value solving, file uploads, GraphQL, CLI integration
and live scanner execution remain open. See [ADR 0038](adr/0038-offline-openapi-request-import.md),
[requests](REQUESTS.md), [scope](SCOPE.md) and [model](SECURITY_MODEL.md).
