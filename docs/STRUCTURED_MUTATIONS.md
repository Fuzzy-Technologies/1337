# Structured JSON mutations

`fuzzy1337.structured_mutations` is an **Experimental offline library** for
preparing reproducible synthetic JSON body candidates, including explicitly
selected canonical standard Base64 JSON strings. It performs no request
transmission, finding creation or authorization. A candidate is not evidence that
a target is vulnerable. This implements a bounded first slice of #207 under
[ADR 0084](adr/0084-bounded-structured-json-mutations.md).

## Existing API preview consumer

Start with an actual anonymous JSON preview from `GenerateOpenApiRequest`, using
the exact original API description and operation reference. Select a concrete
scalar beneath a declared JSON injection coordinate:

```python
from dataclasses import replace

from fuzzy1337.structured_mutations import (
    GenerateJsonMutations,
    JsonMutationSelection,
    ReplayJsonMutation,
)

# `generated` is the original GenerateOpenApiRequest result.
candidates = GenerateJsonMutations(
    generated.operation.template,
    generated.body,
    (JsonMutationSelection("/name"),),
    seed=17,
)
candidate = candidates[0]
reference = candidate.Reference()
mutated_preview = replace(generated, body=candidate.body)
attribution = {
    "baseline": generated.Metadata(),
    "mutation": candidate.Metadata(),
}
replayed = ReplayJsonMutation(
    generated.operation.template,
    generated.body,
    candidate,
    expected_reference=reference,
)
assert replayed == candidate
```

Keep `attribution` alongside the ephemeral candidate. Substituting body bytes in
the existing preview does not revalidate them against the original schema.
The original generation metadata describes the baseline only. The mutation API
also accepts caller-provided synthetic JSON bytes, but their association with a
template is caller attribution, not independently verified source provenance.
Do not supply captured credentials or private request bodies as reusable fixtures.

The module never modifies source API text, request templates, model objects,
triage, scope or evidence stores. Persistence, when explicitly requested, belongs
to the existing model/evidence interfaces. Concrete bodies are omitted from
metadata and `repr`; structural selectors remain visible and must be non-secret.

## Paths and explicit decoding

Pointers reuse `RequestTemplate`'s RFC 6901 syntax. The empty pointer selects the
root; `~1` denotes `/`, and `~0` denotes `~`. Object keys resolve exactly. Array
indexes use canonical decimal spelling such as `/flags/0`; `01`, negative
indexes, `-` and wildcard expansion are rejected. Each selected scalar must be
at or below an input explicitly declared by the template. Session-bearing and
non-JSON templates are rejected.

An optional inner pointer opts into one JSON-in-string layer:

```python
selection = JsonMutationSelection("/encoded", "/flags/0")
```

For a body such as `{"encoded":"{\"flags\":[true,false]}"}`, this selection
changes the first inner boolean and re-encodes the enclosing string. Without the
inner pointer, `/encoded` is an ordinary string. An inner `""` means the decoded
root, while `None` means no decoding. Other strings are never guessed or decoded.
Multiple inner selections share one decode of that outer string. Duplicate
selections and mixing raw/decoded selections for one outer value are rejected.

## Explicit canonical Base64 JSON

Use `JsonMutationEncoding.BASE64_JSON` to decode one selected outer string as
standard RFC 4648 Base64 and then strict UTF-8 JSON:

```python
from fuzzy1337.structured_mutations import JsonMutationEncoding

selection = JsonMutationSelection(
    "/packed", "/flags/0", encoding=JsonMutationEncoding.BASE64_JSON,
)
```

For `{"packed":"eyJmbGFncyI6W3RydWUsZmFsc2VdfQ=="}`, this changes the first
inner boolean and emits canonical Base64 containing `{"flags":[false,false]}`.
The inner empty pointer selects the decoded root. Base64 requires an explicit
inner pointer; choosing the codec with `decoded_pointer=None` is invalid.
Only standard `A-Z`, `a-z`, `0-9`, `+`, `/` and required terminal `=` padding are
accepted. Whitespace, URL-safe characters, missing/excess/interior padding and
nonzero pad bits fail closed. Exact decode/re-encode equality verifies canonical
spelling. The inner bytes retain the same strict UTF-8/JSON checks as direct
JSON-string decoding. No codec is guessed, and inner strings are not decoded again.

`JsonMutationEncoding.JSON_STRING` is the default and retains the original direct
JSON-string behavior. Its field is omitted from `ToDict()` so existing selection
shapes, seeded order and references remain unchanged. Base64 selections include
`"encoding":"base64-json-v1"` in selection/configuration metadata and the complete
chain `["json-utf8","json-string","base64-rfc4648","json-utf8"]`. One outer pointer
cannot mix raw, direct-JSON and Base64 interpretations. Multiple inner selections
using the same codec share one decoded document.

Base64 decoded length is checked before calling the decoder. Aggregate decoded
bytes count the outer body plus each selected Base64 transport string and its
inner JSON bytes; direct JSON strings keep their existing single inner-byte charge.
Candidate re-encoding checks the predicted Base64 size before allocation, charges
both inner layers and retains the outer-body and complete-output bounds. JSON node
and depth accounting remains unchanged: Base64 itself adds no JSON tree node.
See [ADR 0085](adr/0085-explicit-base64-json-mutations.md).

## Profiles and deterministic replay

`JsonMutationProfile.SCALAR_BOUNDARIES` (`scalar-boundaries-v1`) uses these fixed
finite corpora, removing unchanged values:

- strings: empty string, `1337`, quote/backslash delimiters and NUL;
- integers: zero, minus one, signed 32-bit maximum and minimum;
- finite floats: `0.0`, `-1.5` and `1.5`;
- booleans: the inverse value.

Null has no distinct type-preserving value. Selecting an object or array itself
is rejected; select its scalar descendants. All outputs remain strict JSON. Type
preservation does not preserve `minimum`, `enum`, `pattern` or other schema
constraints. The independent schema test demonstrates this distinction.

`JsonMutationProfile.TYPE_CHANGE` (`type-change-v1`) selects from null, false,
zero, `1337`, empty array and empty object, excluding the original JSON type.
Integers and floats both count as JSON numbers for this exclusion. This profile
deliberately changes structure without claiming malformed-JSON support.

The seed is an explicit integer in `[0, 2**64)`, excluding booleans. SHA-256 over
the seed, profile, selected path and variant name determines corpus order;
input selection order remains significant. Every candidate changes exactly one
value in the original body. The complete requested corpus is returned or the
call fails; there is no truncation, automatic retry or partial success.

Metadata version 1 binds exact source-body bytes, complete template reference,
configuration and limits, selection index/path, encoding chain, variant, output
digest and complete mutation reference. Even original-body whitespace changes
invalidate replay. Retain the original `Reference()` independently: recomputing
an expected reference from already changed metadata cannot detect that change.
Replay is a content-integrity check, not source authenticity or permission.

## Resource bounds

`JsonMutationLimits` permits lowering these defaults, never raising them:

- maximum tree depth: 16, counting the root as zero;
- maximum decoded nodes: 4,096, including object keys;
- maximum original, inner or output body: 65,536 UTF-8 bytes;
- maximum aggregate decoded bytes: 131,072;
- maximum complete output candidates: 64;
- maximum aggregate generated body bytes: 1,048,576.

All budgets are positive integers, excluding booleans. Decoded nodes count the
outer tree plus each distinct explicitly decoded inner JSON tree. Decoded bytes
count the outer JSON, each direct JSON string, and both transport/JSON layers for
Base64. Inner depth starts one level beyond its outer-string coordinate. Candidate bytes are checked both
individually and against the aggregate output budget while encoding; candidate
outer/selected inner encodings must also fit the decoded-byte budget. Duplicate
JSON keys, nonfinite values, invalid UTF-8/surrogates and unresolved selections
fail closed with source-free diagnostics.

The input byte ceiling bounds the standard-library decoder's allocation before
the decoded tree is inspected. The node/depth budget is enforced immediately
after decoding; this is not a streaming JSON parser.

## Evidence and limits of this slice

Unit/contract tests use independently written scalar, JSON, provenance and
negative-case oracles. Integration tests consume the actual API generator,
substitute candidate bodies into its existing preview record, preserve source
and persistent model bytes, and explicitly save/reopen reference metadata with
the existing evidence store after workspace relocation. No network service is
needed for this offline capability. The Base64 integration scenario wraps exact
actual API-generated JSON bytes in an explicitly synthetic envelope under a
declared string input. It retains that envelope through existing evidence owners,
relocates the workspace, reopens its original bytes and independent reference, and
replays the candidate. The API generator itself does not claim to generate Base64
or validate the synthetic envelope against the original schema.

URL-safe Base64, gzip and other compression, protobuf, MessagePack, JWT, additional
codec layers, full schema-preserving mutation, malformed JSON, live execution, rate
limits, crash/timeout/anomaly classification and minimized reproducers remain
open under #207. These tests establish preparation/replay behavior, not scanner
attack-vector detection or standards coverage.
