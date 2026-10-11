# Structural web requests

`fuzzy1337.requests` is an Experimental library for request descriptions. It
shares the Security Object Model's Endpoint identities and persists through that
model's store. It does not send requests, acquire sessions or grant scope.

## Structural input, without captured values

An `Endpoint` describes a workspace, canonical HTTP(S) origin, path template and
method. Use placeholders such as `/api/users/{user_id}` for runtime path data.
Put query parameters in injection descriptors rather than in the origin/path.
HTTP methods are case-normalized; their presence never implies permission.

A `RequestTemplate` owns typed `InjectionPoint` descriptors and a `BodyKind`.
Each point has a named `ValueBinding`, either `input` or `session`. These are
symbolic names, never values. Captured request data, literal headers/cookies,
GraphQL documents and body bytes are deliberately outside this contract. Even a
valid structural identifier must not contain a credential or private value.

```python
from fuzzy1337.requests import (
    Endpoint, InjectionLocation, InjectionPoint, RequestTemplate, ValueBinding,
)

endpoint = Endpoint("demo", "https://example.test", "/api/users/{user_id}", "GET")
template = RequestTemplate(endpoint, (
    InjectionPoint(InjectionLocation.PATH, "user_id", ValueBinding("user_id")),
    InjectionPoint(InjectionLocation.QUERY, "fields", ValueBinding("fields")),
))
wire_json = template.ToJson()
reopened = RequestTemplate.FromJson(wire_json)
```

This example only constructs and parses offline data. `SessionReference` carries
workspace and session identifiers; session-bound inputs require that reference.
The separate session/runtime owner must resolve it and keep credentials ephemeral.

## Locations and body encodings

| Location  | Selector                          | Body requirement                       |
| --------- | --------------------------------- | -------------------------------------- |
| query     | Parameter name                    | Any                                    |
| body      | Form name, or empty for text body | `form`, or `text` for whole-body input |
| json      | RFC 6901 pointer, including root  | `json`                                 |
| cookie    | Cookie name                       | Any                                    |
| header    | Header name, canonical lowercase  | Any                                    |
| path      | Declared path variable name       | Any                                    |
| graphql   | Pointer beneath `/variables/`     | `graphql`; operation name is optional  |
| multipart | Form-part name                    | `multipart`                            |

`occurrence` selects one repeated query/form/cookie/header/multipart field. It is
zero for path, JSON, GraphQL and whole text-body locations. No descriptor invents
a concrete value, file upload or GraphQL selection. Those runtime operations need
their own impact/scope checks.

## Existing model persistence

`ProjectRequests(templates, provenance=...)` returns one Endpoint `SecurityObject`
patch. All templates must have the same endpoint; duplicates are rejected and
serialization is sorted. `RequestsFromObject` validates and reopens the typed
templates. Apply the patch with `ModelState.Apply`, then save with the existing
`LocalModelStore` and its expected revision.

The `request_templates` attribute is a complete collection. When changing one
template, first reopen existing templates and compose the whole new collection.
Existing model patch behavior preserves other attributes; attribution and
history use `ModelProvenance`. There is no second request database or ownership
of workspace, scope, raw evidence or session state.

## Machine interface and limitations

[`request-template.schema.json`](../contracts/request-template.schema.json)
describes schema version 1. `RequestTemplate.FromDict`/`FromJson` also validate
relationships that JSON Schema cannot express: recomputed references, workspace
ownership, selector/body compatibility and canonical stored spelling. JSON is
bounded, rejects duplicate keys and non-finite values, and serializes deterministically.

The contract is structural, not a raw HTTP/HAR importer or a request renderer.
Concrete inputs can alter target membership and impact. A future executor must
validate substituted URLs and every actual destination against current scope and
policy, including redirects and DNS results, before sending anything.

See [ADR 0028](adr/0028-structural-web-request-contracts.md),
[Security Object Model](SECURITY_MODEL.md), [Scope](SCOPE.md) and
[Evidence](EVIDENCE.md).
