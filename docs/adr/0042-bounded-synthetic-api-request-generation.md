# ADR 0042: Bounded synthetic API request generation

- Status: Accepted
- Date: 2026-10-12
- Decision owners: Fuzzy Technologies
- Related work: #144, #143, #58

## Context

ADR 0038 provides structural requests and source provenance without retaining
schema assertions or literal values. Its type summaries and `constrained` flag
cannot prove that a generated value satisfies the original schema. The next API
scanner slice needs deterministic concrete synthetic requests, independently
bound to that exact source, without executing them or acquiring credentials.

## Decision

Add Experimental `fuzzy1337.api_request_generation`, generation profile version
1, in a separate module. Preserve the importer, request/model schemas and runtime
owners. The new producer accepts the exact original JSON, a canonical operation
reference and explicit import context. It reimports the source and selects the
actual canonical server/media operation before traversing its original effective
parameters and body. It never accepts fabricated type summaries as validation.

Generate one baseline for a selected operation, with versioned synthetic
constants. Include every declared supported parameter and body property, even
when optional; an optional declared body is present. This satisfies required
properties when their enclosing objects exist, without inventing conditional
requirements from flattened descriptors. No Cartesian scenario expansion occurs.

The source-validation profile permits explicit scalar types, fixed JSON object
properties and homogeneous primitive arrays. Local references remain bounded.
Unimplemented assertion keywords, formats, unspecified types, schema boolean
values, compositions, dynamic references and readOnly/writeOnly flags fail closed.
Descriptions, defaults and examples are annotations only: their values are never
selected, copied into generated values or exposed through error diagnostics.

Structural server/path components, operation IDs, property/parameter/header names
and pointers necessarily preserve original source text. Callers supply non-secret
structural metadata; this profile does not recognize every secret disguised as a
syntactically valid name. Excluding literal sample values does not redact all
source-derived text.

Support default OpenAPI form/simple parameter serialization, scalar cookies,
Swagger csv and query/formData multi, JSON/+json, plain text, URL-encoded scalar
forms and synthetic scalar multipart parts. Swagger URL-encoded formData may
also contain primitive csv/multi arrays. Other form arrays, cookie arrays, binary
parts, uploads and custom encodings remain outside this profile.

For scalar cookies, explicitly choose RFC6265-style `name=value` without a `?`
prefix. OAS 3.0.4 documents the form-cookie comparison with RFC6570 as
implementation-defined; this library declares its choice rather than claiming
portable multi-value cookie behavior. Multiple scalar cookies use `; `.

Only an anonymous security alternative is eligible. Do not resolve sessions,
assemble authentication, import source literal credentials or accept caller value
overrides. Reject transport/authentication-controlled header declarations before
rendering. Validate media tokens and independently bound encoded URL, header,
body and total byte sizes.
Reject a declared TRACE body because HTTP semantics forbid TRACE content. This
does not establish server acceptance or execution authority for other methods.

Return an ephemeral request record containing method, the exact existing URL
Target, ordered header pairs, body bytes and original operation/template/source
references. It is an offline preview. Generation does not register a target,
persist payloads, grant impact/method permission or authorize execution. Callers
can use the existing CheckOpenApiTarget with the actual generated target and
current scope; that decision still grants no invocation authority.

Use existing model and evidence owners for attributable structural templates and
explicit synthetic evidence only. No additional truth store, CLI command,
network/client dependency or runtime interface is introduced.

## Validation and remaining work

Exercise hand-written source and semantic request oracles through the real
importer, independent standard-library URI/JSON/MIME consumers, current scope
checks and model save/reopen. Reject unsupported original assertions even when
their structural summary flag is false. Test dialect-specific arrays, inherited
parameters, conditional required objects, exact operation/source binding,
diagnostic redaction and real byte/resource limits.

The precise types, values, serialization choices and limits are defined in
[API request generation](../API_REQUEST_GENERATION.md). Full schema validation,
YAML, additional assertion/encoding profiles, authentication, uploads and live
execution remain open under #144.

## Primary references

- [OpenAPI 3.0.4](https://spec.openapis.org/oas/v3.0.4.html)
- [OpenAPI 3.1.2](https://spec.openapis.org/oas/v3.1.2.html)
- [Swagger 2.0](https://swagger.io/specification/v2/)
- [RFC 7578](https://www.rfc-editor.org/rfc/rfc7578.txt)
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8)
- [ADR 0038](0038-offline-openapi-request-import.md)
- [ADR 0028](0028-structural-web-request-contracts.md)
