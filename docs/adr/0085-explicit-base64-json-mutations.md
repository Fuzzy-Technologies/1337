# ADR 0085: Explicit canonical Base64 JSON mutations

- Status: Accepted
- Date: 2026-10-16
- Decision owners: Fuzzy Technologies
- Related work: #207, ADR 0084

## Decision

Extend the Experimental offline JSON mutation selection with an explicit
`JsonMutationEncoding.BASE64_JSON` (`base64-json-v1`) path. It decodes exactly one
selected outer JSON string as canonical RFC 4648 standard Base64, then strict
UTF-8 JSON, and applies the existing scalar profile at the explicit inner pointer.
There is no format detection, URL-safe alphabet, whitespace tolerance, compression
or recursive codec expansion. Required padding and zero pad bits are canonical:
strict decoding followed by exact standard re-encoding must reproduce the input.

The default `JSON_STRING` encoding retains the existing direct JSON-string path.
Its field is omitted from selection metadata, preserving all previous selection
shapes, seeded order, configuration references and mutation references. Nondefault
encoding requires an inner pointer; the empty pointer still selects the inner
root. One outer coordinate cannot mix raw, direct-JSON or Base64 interpretations.

Base64 decoding preflights the exact decoded length before invoking the decoder.
Individual encoded/decoded bodies retain the existing body ceiling. Aggregate
decoded bytes count the outer body, each distinct selected transport string and
its decoded JSON bytes. Direct JSON strings retain their existing single-layer
charge. Multiple inner selectors share one decode and one charge. Node/depth
budgets count decoded JSON trees as before; a binary codec adds no JSON tree node.
Output re-encoding checks the predicted Base64 length before allocation, charges
both inner JSON and Base64 bytes, and retains individual outer and aggregate
output ceilings. The complete corpus succeeds or no candidate escapes.

Base64 selection/configuration metadata includes the versioned encoding. Its
encoding chain is `json-utf8`, `json-string`, `base64-rfc4648`, `json-utf8`.
Replay regenerates the complete corpus and requires the independently retained
original mutation reference. Original bytes, codec choice, limits and output are
bound without storing body values in reference metadata.

## Validation and boundaries

Tests independently consume Base64 and JSON, pin legacy reference values, exercise
malformed alphabets/padding/pad bits, strict inner JSON/UTF-8, every relevant
resource budget, shared decoding, mixed-codec refusal and replay drift. An actual
API-generated JSON preview supplies exact inner bytes for an explicitly synthetic
Base64 transport envelope under a declared string input; generation does not
claim to produce Base64 values itself. Existing model/evidence owners retain the
synthetic envelope and references and support relocation followed by replay.

This adds no I/O, schema-validity, source-authenticity, scope, authorization or
execution authority. Compression, other serialization formats, recursive codecs,
live anomaly detection and minimized reproducers remain outside this slice.
