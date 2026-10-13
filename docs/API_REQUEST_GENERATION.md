# Synthetic API request generation

ADR 0042 defines Experimental generation profile version 1 for #144.
GenerateOpenApiRequest produces one offline synthetic request preview using the
structural capability documented in [OpenAPI import](OPENAPI.md).

## Source and ownership boundary

Profile version 1 takes the exact supplied OpenAPI/Swagger JSON and a canonical
operation reference, with the same workspace/base context as the original
import. Reimport the document, select that actual operation/server/media and
independently validate the original effective schemas. A matching digest or an
ApiInput `constrained=False` summary alone cannot certify validity. Unknown or
unimplemented consumed assertions fail before returning a partial request.

Structural source text remains necessary: server/path components, operation IDs,
parameter/property/header names and source pointers are preserved. Callers must
use non-secret structural metadata; syntax cannot detect a credential disguised
as an otherwise valid name or path. Only source default/example/description
contents and credential value selections are excluded from generated values.

The producer emits one deterministic synthetic baseline per selected operation.
It accepts no captured/caller literal values, session lookup, credential or
authentication override. Every declared supported parameter/property is present;
an optional body is present when declared. Fixed objects are reconstructed from
their actual schema tree, preserving required fields beneath optional parents.

The result is ephemeral method, existing exact URL Target, ordered headers, body
bytes and operation/template/source/profile references. It grants no method,
impact, scope, session or execution permission. Generation does not register scope
targets or persist values in Security Object Model request attributes. Existing
CheckOpenApiTarget must consume the generated actual URL including its query,
the matching current workspace/scope and an explicit aware time. Runtime DNS,
redirects, invocation authorization and network execution remain separate.

GenerateOpenApiRequest accepts source text, a canonical operation reference,
workspace_id and the same optional base_url resolution context as ImportOpenApi.
GeneratedApiRequest exposes operation, target, immutable header pairs and body
bytes. The method remains on operation.template.endpoint.method. Reference binds
the actual target/header encoding and body digest to the original operation and
profile; Metadata returns references/digests without concrete header/body values.
Parsing/rendering helpers and direct record constructors are Internal. Use the
public producer when source binding and validation matter.

## Exact value profile

The type keyword is explicit. Objects require a finite properties map; required
names must be unique declared properties. Arrays require one primitive item
schema and contain two synthetic members. Nested object/array items are excluded.
All emitted properties are validated, including optional ones and optional bodies.

| Type    | Scalar      | Two array members            |
| ------- | ----------- | ---------------------------- |
| string  | `synthetic` | `synthetic-0`, `synthetic-1` |
| integer | `1`         | `1`, `2`                     |
| number  | `1.5`       | `1.5`, `2.5`                 |
| boolean | `true`      | `true`, `false`              |
| null    | JSON `null` | JSON `null`, `null`          |

Standalone null is OpenAPI 3.1 JSON only. A supported nullable base type chooses
its non-null sample. Null in URL/header/cookie/form/text/multipart coordinates is
unsupported. Numeric/boolean textual forms are locale-independent JSON scalar
spellings. JSON objects use sorted property names and standard JSON escaping.

The supported assertions are type, properties, required and homogeneous items,
plus the existing dialect-specific nullable declaration. Local canonical refs
retain cycle/depth/work guards. Unspecified types, format, enum/const, ranges,
patterns, sizes, uniqueness, additionalProperties, dependent/unevaluated rules,
readOnly/writeOnly and other unimplemented assertion keywords are rejected.
Defaults, examples, descriptions and titles remain ignored annotations; private
literal contents never become samples. This is not a complete schema/source
validator, and unconsumed response sections are not validated.
Swagger non-body Items Objects permit default as an ignored annotation; schema
references and other unimplemented Items fields are rejected.

## Serialization profile

URI names and individual scalar components use UTF-8 RFC3986 percent encoding
with only unreserved characters left literal. Array separator commas are emitted
as structural delimiters in path/query values. Headers retain only controlled
synthetic ASCII scalar spellings. Cookies use `name=value`, separated by `; `,
with no RFC6570 question-mark prefix; this is the declared implementation choice
for OpenAPI's scalar form-cookie ambiguity.

| Coordinate       | OpenAPI 3.0/3.1                                                               | Swagger 2.0                                       |
| ---------------- | ----------------------------------------------------------------------------- | ------------------------------------------------- |
| query            | form scalar; primitive array repeated when explode, comma-separated otherwise | scalar; primitive array csv/multi                 |
| path/header      | simple scalar or comma-separated primitive array                              | scalar or primitive array csv                     |
| cookie           | form scalar only                                                              | Unsupported                                       |
| JSON body        | fixed objects, primitives, primitive arrays                                   | Same, with legacy null restrictions               |
| text body        | string                                                                        | string                                            |
| URL-encoded body | flat scalar fields                                                            | flat scalar fields and primitive csv/multi arrays |
| multipart        | flat synthetic scalar text parts                                              | flat synthetic scalar text parts                  |

JSON requires application/json or a valid application subtype ending in +json;
the selected media token is independently validated before header construction.
URL-encoded bodies use standard form encoding. Multipart uses a deterministic
profile/operation-derived ASCII boundary, CRLF framing and form-data disposition
names. No filenames, binary parts, nested encodings or transfer encoding are
generated. Transport/authentication-owned headers, including Host, Cookie,
Authorization, Content-Length, Transfer-Encoding and Connection, are rejected as
ordinary schema input declarations. Generated Content-Type and combined Cookie
headers are owned by the renderer.
TRACE operations with a declared body are rejected according to RFC 9110.
Method-specific server acceptance, HTTP transport and request execution remain
separate from this offline schema/encoding preview.

Only absent security requirements or an explicitly empty anonymous OR
alternative is supported. Authenticated-only operations and session-bound
templates fail; an anonymous alternative never establishes authenticated state.

## Resource profile

| Boundary                  | Limit                                                     |
| ------------------------- | --------------------------------------------------------- |
| Original input/resolution | Existing importer 1 MiB, 20000 nodes, depth 32, 4096 work |
| Generated schema nesting  | 8                                                         |
| Injection coordinates     | Existing request maximum 128                              |
| Symbolic request template | Existing serialized maximum 64 KiB                        |
| Primitive array members   | 2                                                         |
| Encoded actual URL        | 8 KiB UTF-8                                               |
| Encoded headers           | 8 KiB ASCII including framing                             |
| Body                      | 64 KiB                                                    |
| Combined output           | 128 KiB                                                   |

All failures preserve caller-owned stores and use diagnostics that omit source
values, including chained tracebacks. Generation creates no files or state stores.
Byte limits are independent of structural metadata size and use encoded output.
Existing source/template bounds also apply and may reject an oversized source
before the renderer reaches its output bounds.

## Required acceptance evidence

Use hand-written positive sources and independent semantic request oracles,
standard-library query/JSON/MIME readers and real producer interfaces. Verify
exact operation/server/media binding and original constraints, inherited
parameters, nested conditional required fields, arrays and delimiter behavior.
Model projection/save/reopen retains the existing symbolic template without
generated values. Scope tests consume the actual generated URL/query and retain
current deny/consent/workspace checks without inventing execution authority.

Adversarial coverage includes unknown assertions hidden behind false summary
flags, unsupported dialect/item types, source/op mismatches, reference cycles,
resource/byte limits, escaped JSON names, CRLF and reserved headers, multipart
framing and source default/example markers absent from payloads and tracebacks.
The complete canonical locked gate and independent review remain mandatory.

YAML, general schema solving, additional serialization styles, cookie/form
arrays outside this profile, auth/session assembly, files/binary, GraphQL and
live scanner execution remain open. Task #144 stays open for those gaps.
