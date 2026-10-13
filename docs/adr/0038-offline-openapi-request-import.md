# ADR 0038: Offline OpenAPI request import

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #144, #143, #58

## Context

The native API scanner needs schema-derived endpoint descriptions before an
active request renderer exists. API documents are untrusted input. They may
contain secrets in examples/defaults, recursive schemas, remote references,
unapproved servers and authenticated operations. Importing a description must
neither fetch references nor grant permission to contact its servers.

## Decision

Add an Experimental `fuzzy1337.openapi` offline JSON importer, contract version 1.
Accept a documented subset of OpenAPI 3.0/3.1 and Swagger 2.0. Unsupported consumed
constructs fail closed; no partial import is returned. This is a structural
importer, not a complete OpenAPI/JSON Schema validator or a request renderer.

Reuse the existing `Endpoint`, `RequestTemplate`, `InjectionPoint`, symbolic
`ValueBinding` and optional caller-owned `SessionReference`. Preserve operation
IDs, source JSON pointers, exact input-byte digest, media types, parameter
serialization metadata, schema type/required flags and OR-of-AND authentication
requirements. No captured values, defaults, examples, enums, descriptions,
credential material, OAuth URLs or raw source document are retained. A flag marks
schema constraints that are not represented by the structural type summary.

OpenAPI server precedence is operation, path, then root. Absolute HTTP(S) servers
and literal relative paths are supported; relative servers require an explicit
caller-supplied base URL. Swagger reuses declared host/basePath/schemes or an
explicit base URL where the document relies on its retrieval location. Server
variables are unsupported. Server descriptions do not create scope entries.

Local JSON Pointer references are resolved only within the supplied document.
External/URI references, reference siblings with executable schema semantics,
reference cycles, dynamic schema identities and schema compositions are rejected
when consumed. Input bytes, JSON depth/nodes, reference work, operation/variant
counts, schema traversal and output bytes have explicit bounds. Duplicate JSON
keys, non-finite numbers and invalid Unicode fail before producing metadata.

The model projection composes existing request collections and a bounded owned
`openapi_operations` metadata attribute on existing Endpoint objects. Existing
model/evidence owners retain persistence, provenance and revision checks. This
module owns no additional truth store and retains no input-file path.

Explicit preparation checks a caller-provided concrete URL against its endpoint
shape and the current workspace-bound exact scope snapshot at an aware time.
Path variables are not scope wildcards. Preparation cannot substitute values,
approve a method, authorize traffic or authenticate a session. Every later
concrete query, destination, redirect, DNS answer and payload still requires
fresh governed runtime checks.

## Validation and remaining work

Use independent hand-written OpenAPI/Swagger fixtures, adversarial bounded-input
tests and real request/model persistence consumers. No browser or network target
is required. The importer must satisfy the per-module branch coverage gate.

YAML, other OpenAPI versions, complete schema validation, concrete test-value
generation, authenticated rendering, GraphQL discovery and execution remain
separate work. Task #144 remains open while these request-generation gaps remain;
this slice does not complete the API Security Scanner feature.

## Primary references

- [OpenAPI 3.1.2](https://spec.openapis.org/oas/v3.1.2.html)
- [Swagger 2.0](https://swagger.io/specification/v2/)
- [ADR 0028](0028-structural-web-request-contracts.md)
