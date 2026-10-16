# Structured JSON mutations

Experimental offline preparation of finite JSON body candidates beneath explicit
request-template input coordinates. The public entry points are
`GenerateJsonMutations` and `ReplayJsonMutation`, with `JsonMutationSelection`,
`JsonMutationProfile`, `JsonMutationEncoding` and `JsonMutationLimits` configuration,
and `JsonMutation` results exposing `Reference` and `Metadata`.

`docs/STRUCTURED_MUTATIONS.md` and ADR 0084 define the scalar-boundary and deliberate
type-change profiles, one explicitly selected JSON-in-string layer, complete
resource bounds, ephemeral body values and independently anchored replay.
ADR 0085 adds explicitly selected canonical standard Base64 JSON strings with
preflight decoded-byte checks and complete encoding provenance. Default selection
metadata and references remain compatible; no format detection is performed.
Type preservation does not establish schema validity. Template/body association
is caller attribution; mutation references establish content integrity only.

Preparation performs no I/O, model/evidence writes, authentication assembly,
network request or authorization. Any future transmission requires the existing
runtime's fresh scope and policy decisions for the actual candidate. Direct
result-record construction and decoding/rendering helpers remain Internal.

::: fuzzy1337.structured_mutations
