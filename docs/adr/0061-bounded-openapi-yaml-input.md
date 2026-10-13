# ADR 0061: Bounded OpenAPI YAML input

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #144, #143, #58

## Context

The offline structural importer and synthetic request generator accept JSON.
OpenAPI descriptions can also use YAML, but YAML constructors, implicit legacy
types, aliases, duplicate keys and unbounded graph expansion must not change the
existing JSON/source/model or authorization contracts.

## Decision

Add explicit `document_format="yaml"` to `ImportOpenApi` and
`GenerateOpenApiRequest`, retaining `document_format="json"` as the default.
Do not detect a format, retry failed JSON as YAML, read a file or fetch a URL.
Use the optional `1337[openapi-yaml]` extra pinned to PyYAML 6.0.3; the development
extra includes that same pin so shared CI actually exercises this path. The core
package retains no mandatory runtime dependency. Verify the upstream release and
lock all selected distribution hashes in `uv.lock`.

The internal decoder consumes the documented PyYAML `parse` event stream with
`BaseLoader`, without calling `load`, `compose`, constructors or implicit
resolvers. It constructs an ordinary JSON-compatible tree iteratively. Enforce
the existing 1 MiB UTF-8 input ceiling before dependency loading/parsing, then
enforce 20000 node and depth 32 ceilings before adding each collection/scalar.
Mapping keys count as nodes; root depth is zero. Validate the resulting tree
again through the unchanged common API validation and resolution pipeline.

Accept one document, block/flow collections, comments, quoted/plain/block strings,
an optional BOM and document markers. A version directive must be 1.2; custom tag
directives are refused. The scalar vocabulary is an explicitly narrow
JSON-compatible profile, not general YAML Core resolution: lowercase `null`,
`true`, `false`, empty plain nodes and finite numbers in JSON number syntax.
Ordinary plain words, including `yes`, `on`, dates and dotted version strings,
remain strings. Quoted/block scalars remain strings unless a supported explicit
scalar tag specifies an accepted lexeme. Built-in `str`, `null`, `bool`, `int`,
`float`, `map` and `seq` tags must match the actual node/type. Explicit float
converts a finite JSON number to float; explicit int requires integer syntax.

Refuse every anchor/alias, merge key, duplicate decoded string key, complex or
non-string mapping key, custom tag, timestamp/binary/set/pairs/ordered-map tag,
multiple document stream, invalid Unicode, non-finite/overflowing numbers and
ambiguous numeric spellings such as `01`, `+1`, `.5`, `1.`, `0x12`, `1_000` and
`1:00`. These checks also apply to ignored response/example/extension sections.
Parser errors are replaced with fixed diagnostic categories without original
source text or exception context. Quote numeric response codes, Swagger `2.0`
and string schema type `null` explicitly.

Preserve exact original UTF-8 byte SHA-256, source JSON Pointer coordinates,
symbolic templates and existing model/evidence projection. Do not reserialize
YAML into JSON before hashing. Equivalent YAML and JSON presentations have
different source/operation/preview references when their bytes differ, while
their structural request references match. Strict JSON bytes explicitly decoded
as YAML produce the same interpretation and existing identity; format selection
does not add an output field or imply source authenticity.

Generation reimports the same exact source using the explicitly selected format,
then validates original schemas through ADR 0042. Auth/session, unsupported
assertion/encoding, scope and resource refusal semantics remain unchanged.
Imports and previews create no network requests, execution grants, registered
targets, findings or additional truth stores. The importer and generation
contract versions remain 1 because existing JSON records and producers retain
their behavior and identity.

## Validation and remaining work

Hand-written YAML counterparts are checked against existing independent JSON
source trees and semantic request oracles, including actual URI/query, JSON,
form and multipart consumers. Exercise actual import, generation, model
Apply/save/reopen/relocation, raw reference evidence and current exact scope
denial/consent checks. Test missing optional dependency, default JSON rejection,
BOM/directives, tags, aliases, duplicate Unicode keys, numeric types, diagnostic
redaction and byte/node/depth refusal. Parser-only fixture success is insufficient.

Task #144 remains open for broader schema solving, authentication, uploads,
additional encodings, CLI and live scanner execution. This syntax extension
does not certify a complete OpenAPI validator or a general YAML processor.

## Primary references

- [YAML 1.2.2 specification](https://yaml.org/spec/1.2.2/)
- [PyYAML event API and BaseLoader](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [PyYAML 6.0.3 upstream release](https://github.com/yaml/pyyaml/releases/tag/6.0.3)
- [OpenAPI 3.1.2 format](https://spec.openapis.org/oas/v3.1.2.html#format)
- [ADR 0038](0038-offline-openapi-request-import.md)
- [ADR 0042](0042-bounded-synthetic-api-request-generation.md)
