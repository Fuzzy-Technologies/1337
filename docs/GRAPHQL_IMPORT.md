# Offline GraphQL introspection import

The Experimental `fuzzy1337.graphql_import` module imports explicitly supplied
owned introspection JSON bytes and a caller-selected endpoint. It neither sends
an introspection query nor assumes introspection is enabled. Supply exact source
bytes yourself; descriptions grant no transport, authentication or scope
authority.

```python
from fuzzy1337.graphql_import import ImportGraphQl, GenerateGraphQlRequest

imported = ImportGraphQl(
    owned_introspection_bytes,
    workspace_id="owned-workspace",
    endpoint_url="http://127.0.0.1:8080/graphql",
)
operation = next(item for item in imported.operations if item.field_name == "lookup")
preview = GenerateGraphQlRequest(
    owned_introspection_bytes,
    operation.Reference(),
    workspace_id="owned-workspace",
    endpoint_url="http://127.0.0.1:8080/graphql",
)
```

`owned_introspection_bytes` is caller-owned UTF-8 JSON, never a filename or URL.
Accept a direct `{"__schema": ...}` export or successful
`{"data": {"__schema": ...}}` envelope. Errors, duplicate JSON keys or names,
unknown consumed declaration fields and invalid type bindings fail explicitly.
Source hashes cover original bytes, including whitespace. Original JSON Pointers
address the actual source array positions. Reformatting changes source and
operation/preview identities while equivalent symbolic request identities may
remain equal.

Each root field becomes a typed query, mutation or subscription operation using
the existing POST Endpoint, GraphQL RequestTemplate and `/variables/<name>`
InjectionPoint contracts. Metadata preserves list/non-null wrappers, input-object
definitions, declared enum identifiers and default-presence flags. Descriptions
and default literals are excluded. Root operation kinds produce distinct
operation names even when their fields/arguments have identical names.

Preview preparation reimports the same source and exact caller context. It
renders fixed built-in scalar values, the lexically first declared enum name,
single-member lists and complete input objects. Custom scalar synthesis,
oneOf input objects and input cycles are refused. Required singular non-null
input cycles are invalid and refused during import; nullable/list recursion can
remain finite metadata but has no synthesized preview. Object/interface/union
results select only `__typename`; leaf results have no selection set. Subscription
operations are descriptive only and their previews are refused. Mutation
preparation grants no permission to execute a mutation.

`preview.body` is ephemeral JSON with `query`, `operationName` and `variables`.
Headers contain only `content-type: application/json`. `preview.Metadata()`
exposes source/request/target/operation/body-digest references without concrete
body contents. Imported type definitions describe a structural profile; this
module is neither a complete GraphQL validator nor an SDL/operation parser.

`ProjectGraphQl(imported, provenance=(... ,))` produces an existing Endpoint
patch with complete request collections and typed `graphql_import` metadata.
The caller owns source/metadata acquisition through `LocalEvidenceStore`, exact
evidence references in `ModelProvenance`, model Apply/CAS persistence and
composition with other observations. Preserve source evidence explicitly;
projection does not acquire bytes, register targets or manufacture findings.
Reopen original evidence with its actual store owner and reimport it to replay.

`CheckGraphQlTarget(operation, preview.target, current_scope, at=aware_time)`
checks the exact selected URL and same-workspace existing scope consent/rules.
It returns an existing membership decision. It does not approve operation
impact, a runtime invocation or execution authorization. It mutates no scope or
workspace state. An imported schema cannot create consent or override a deny
rule.

Projection and preflight consume closed immutable producer records and check
their internal consistency. Changing an operation target without changing its
concrete template, or changing global workspace/source annotations while leaving
operations unchanged, fails explicitly. These checks preserve attribution;
they do not authenticate supplied source bytes or turn descriptive records into
execution authority.

Limits are 512 KiB source, 10000 JSON nodes, depth 24, 128 named types, 32 root
operations, 32 argument/input/enum members, wrapper and generated depth 8,
2048 generated nodes, 32 KiB concrete body and 256 KiB imported metadata.
Existing model attribute limits still apply and can refuse a larger projection.
No URL, reference or scalar declaration is fetched.

SDL and traffic-derived inputs, broader endpoint discovery, authenticated
profiles, active checks and governed live execution remain under Task #145 and
Feature #143. Existing OpenAPI import and request/model schemas are unchanged.

See [ADR 0065](adr/0065-bounded-graphql-introspection-import.md) and the owned
fixture in `tests/contract/fixtures/graphql_introspection.owned.json`. Focused
tests exercise independent JSON/GraphQL preview oracles, real source/evidence
replay and model save/reopen/relocation, exact scope denials and resource failures.

## Owned original-file product import

The Experimental v1 product route imports structural metadata through existing
workspace, scope, evidence and model owners. Set up an owned workspace/model and
an existing scope with explicit consent, registered exact endpoint and allow
rules before importing. The command neither fetches introspection nor generates
or sends a request.

```text
1337 --json api import graphql-introspection OWNED_WORKSPACE
  --file OWNED_INTROSPECTION.json --owner actor:owned
  --read-consent-reference consent:original-file
  --endpoint http://127.0.0.1:8080/graphql --scope owned
  --run run:owned-graphql
  --expected-revision MODEL_REV --expected-workspace-revision WS_REV
```

This wrapped example describes one command. Quote paths according to your shell
and supply the actual current independent revisions. The endpoint is mandatory,
concrete and query-free; source contents supply no endpoint or scope authority.
Read actor/consent references describe explicit artifact-read consent, separately
from existing endpoint scope consent. These references are not verified
signatures and never become an execution grant.

The selected original file must be regular, singly linked and physically stable
within the 512 KiB SDK limit. Original bytes are retained unredacted: descriptions,
default literals and other unsupported contents can remain in evidence even when
normalization fails. Select only an owned source appropriate for that retention.
Summaries contain digests, counts and storage acknowledgements; they omit source
contents, the physical filename and rejected argument values.

An Endpoint with no API collection can receive its first description. An already
occupied Endpoint requires exactly matching canonical `request_templates` and
`graphql_import` values. Partial/incompatible collections are refused before
model write; the route supplies no refresh or multi-source merge. Unrelated
attributes, provenance and UNKNOWN values are preserved. Structural mutation/
subscription descriptions produce neither findings nor execution permission.

Successful output identifies the original acquisition as `evidence_id`, distinct
from `source_sha256`. Replay selects that exact known original custody:

```text
1337 --json api import graphql-introspection OWNED_WORKSPACE
  --evidence sha256:ORIGINAL_MANIFEST_DIGEST
  --endpoint http://127.0.0.1:8080/graphql --scope owned
  --run run:owned-graphql
  --expected-revision MODEL_REV --expected-workspace-revision WS_REV
```

Replay requires unchanged original endpoint/run/scope and current exact scope
membership. It accepts no file-read/provider/session overrides. A bare compatible
SDK manifest without this product's known original custody is refused. Moving
the workspace and deleting the external input do not affect retained replay.
Equivalent raw bytes from separate acquisitions retain distinct manifests and
custody; exact known-source replay preserves stored owner bytes. Changed original
formatting changes source identity and is refused on an occupied Endpoint.

`acquisition_commit`, `model_commit` and `workspace_commit` are independent:
`confirmed` acknowledges that owner, `not-attempted` means its boundary was not
entered, `not-committed` reports a known lock/revision refusal, and `unknown`
reports a lost acknowledgement. An unknown result may already have committed.
Reopen the real owners and use current revisions; do not assume rollback or retry
as a new acquisition. Known retained custody can complete workspace references
after an earlier model commit. No cross-store atomic transaction is claimed.

See [ADR 0081](adr/0081-owned-offline-graphql-product-import.md). Python command
helpers are Internal; SDK parsing/projection and request schemas are unchanged.
