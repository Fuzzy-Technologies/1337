# ADR 0084: Bounded structured JSON mutations

- Status: Accepted
- Date: 2026-10-15
- Decision owners: Fuzzy Technologies
- Related work: #207, #143, #58, #144

## Context

ADR 0028 owns structural requests and injection coordinates. ADR 0042 generates
anonymous synthetic requests after independently validating the exact original
API description. Reusing its request shape for mutation must not imply that a
changed body still satisfies that original schema. A bounded preparatory slice
of #207 can provide reproducible structured candidates before execution,
response analysis and additional serialization formats exist.

## Decision

Add Experimental `fuzzy1337.structured_mutations` as the owner of offline JSON
body transformation. Consume the existing `RequestTemplate`, caller-supplied
synthetic UTF-8 JSON bytes and explicit selections beneath declared JSON input
coordinates. Return ephemeral body candidates, not a second request model.
Template/body association is caller attribution, not proof of origin, schema
validity, authorization or target reachability. Reject non-JSON templates and
session-bearing templates; never resolve bindings or acquire credentials.

Selection uses the existing bounded RFC 6901 grammar. Exact array indexes may
descend from a declared array input; wildcard/append and padded indexes do not
resolve. Each candidate changes one selected scalar in the original tree.
Candidates never accumulate earlier mutations. An explicit outer string pointer
plus an inner pointer selects exactly one JSON-in-string decoding layer.
JSON-looking strings are otherwise ordinary strings. Mixed raw/decoded selection
of the same outer value and duplicate selections fail closed.

Two fixed versioned profiles provide type-preserving scalar boundary values and
deliberate JSON type changes. The first preserves JSON scalar type and surrounding
shape only; it does not assert schema validity. A caller seeking schema validity
must independently validate the actual candidate against the original schema.
Null has no distinct type-preserving value and is rejected in that profile.
String delimiters and NUL remain correctly encoded JSON strings; this slice does
not emit malformed JSON or claim injection detection.

Use a caller-supplied unsigned 64-bit seed to order each finite versioned corpus
by SHA-256 over seed, profile, path and variant. Return the complete configured
corpus or fail, without truncation, retries or partial results. Limits bound input
and output bytes, total decoded nodes/bytes, combined outer/inner depth, candidate
count and aggregate output bytes. Distinct selected JSON strings share the same
aggregate decoding budget; repeated selections inside one string decode it once.

Attribution binds the exact original bytes, full template reference, all
selections, seed, profile, actual limits, selected encoding chain, variant and
output digest. Bodies are excluded from `repr` and metadata. Structural selectors
are necessarily visible and must be non-secret. Public refusal diagnostics do
not echo raw values, duplicate keys or parser details.

Replay accepts the original template/body, candidate and an independently
retained expected mutation reference. It regenerates the complete bounded corpus
and requires exact candidate equality and the original reference. Deriving the
expected reference from an already altered candidate is not an integrity check
against the original. Digests provide content integrity, not authenticity.

## Consumer and authority boundaries

The real API consumer path is `ImportOpenApi` → `GenerateOpenApiRequest` → JSON
mutation → independent JSON consumption. A caller may substitute candidate body
bytes into the existing ephemeral `GeneratedApiRequest`, retaining both original
generation metadata and mutation metadata. The substituted preview is a mutated
candidate; it is not an independently regenerated schema-valid request.

This module performs no I/O, persistence, DNS, HTTP, scope registration, policy
approval, scanning, retry or anomaly classification. Existing model/evidence
owners may explicitly retain synthetic provenance. RequestTemplate and API
schemas remain unchanged. Any future transmission must use the runtime owners'
fresh authorization for the actual request and payload.

## Validation and remaining work

Handwritten oracles check finite corpora, exact changes, escaped pointers, arrays,
explicit string decoding, seed order, complete attribution and replay. Negative
tests cover strict JSON, Unicode, finite numbers, duplicate keys, missing paths,
all resource bounds, session ownership and drift. Real API/model/evidence tests
preserve source/model bytes and reopen explicit provenance after relocation.

This is partial progress on #207. Base64, compression, protobuf, MessagePack,
JWT, recursive multi-layer codecs, broad schema preservation, malformed-structure
profiles, execution/rate control, anomaly evidence and minimized reproducers
remain outside the accepted slice. No scanner coverage or vulnerability detection
claim follows from preparing a mutation corpus.

## Related contracts

- [ADR 0028](0028-structural-web-request-contracts.md)
- [ADR 0042](0042-bounded-synthetic-api-request-generation.md)
- [Structured JSON mutations](../STRUCTURED_MUTATIONS.md)
