# ADR 0081: Owned offline GraphQL product import

- Status: Accepted
- Date: 2026-10-14
- Decision owners: Fuzzy Technologies
- Related work: #145, #143, #58

## Context

ADR 0065 supplies bounded original-byte GraphQL introspection parsing, typed
operations, existing request projections and exact current target membership.
The SDK deliberately leaves original acquisition, complete-source composition
and model/workspace persistence with the caller. A product command can compose
these existing owners without adding transport, authentication or execution.

`ProjectRequests` replaces one complete `request_templates` collection.
`ProjectGraphQl` also supplies one `graphql_import` attribute. General refresh
and combining descriptions require a separate composition decision; silently
applying another collection could discard existing requests.

## Decision

Add the Experimental v1 command `1337 api import graphql-introspection` for one
explicit existing workspace and concrete HTTP(S) endpoint. Require an explicit
scope, run, model revision and workspace revision. Supply either an original
file with explicit artifact-read actor/consent references, or an exact retained
manifest identity already bound by this product's original custody fact.

Use existing current scope consent, registration and rules before any original
source read, including retained workspace/report verification. Reject query
components, credentials and symbolic path selections; never infer an endpoint
from source contents. The SDK's `CheckGraphQlTarget` checks every freshly
imported operation with a fresh current decision time before model mutation.
Membership is not permission to execute a query, mutation or subscription.
No scope, target registration, policy, session or grant is created or changed.

Retained selection verifies the owning original manifest's identity, fixed
`graphql-introspection` role, JSON media type, 512 KiB ceiling, workspace, scope,
`graphql-import` source/version `1`, absent provider execution/invocation and
known original endpoint/run/read custody before reading its raw blob. A source
hash identifies bytes; a manifest identifies the independent acquisition.
Retained replay permits no attribution overrides and cannot adopt an unbound
SDK acquisition merely because its bytes match.

Original file reads enforce the same physical contract as owned runtime
acquisition: non-following checked parents and regular file, one hard link in
every observed view, bounded read and full same-view device/inode/size/mtime/
ctime stability. The existing platform helper permits Windows ctime differences
only across path and handle views. The GraphQL reader bounds the read to 512 KiB
before loading bytes; it does not acquire a larger runtime artifact and truncate
it. Neither original bytes nor the selected filename enter summaries.

Publish original unredacted bytes through the existing evidence owner. Reopen
the exact original manifest and verify the raw digest/length before fresh
`ImportGraphQl` and unchanged `ProjectGraphQl`. Do not invoke preview generation.
Descriptions/default literals remain excluded from symbolic metadata, while the
original evidence intentionally retains them. Unsupported or malformed original
JSON can therefore remain acquired evidence after normalization refusal.

Admit a new Endpoint, an existing Endpoint with neither API-owned collection, or
an existing Endpoint whose `request_templates` and `graphql_import` both exactly
equal the proposed canonical values. Refuse partial or incompatible occupied
collections before model write. Preserve unrelated attributes, provenance and
UNKNOWN facts using the existing model's patch behavior. Reformatting source
bytes changes `graphql_import` source identity and is refused on an occupied
Endpoint even when symbolic templates happen to match.

Bind manifest identity, original source hash/version and explicit read actor/
consent to an inert `api-import-source` Observation on the Endpoint. Its existing
ModelProvenance pins original run, endpoint target, scope, observation time and
raw evidence reference. Apply projection and custody together in one model
transition. Save using the selected model CAS, then independently retain model,
scope, original manifest and raw references through the existing workspace CAS.

Report acquisition, model and workspace acknowledgements separately. A lost
acknowledgement is unknown even if the owner actually committed. A known busy/
revision rejection remains not committed. Later failures do not roll back an
earlier confirmed owner. Exact known-source replay is a byte-preserving no-op;
it may finish workspace references after a confirmed model commit whose later
workspace acknowledgement was lost. This is not cross-store atomic isolation.

The controller reuses unchanged Internal runtime path, parser, failure, basis
and reference-proposal helpers. All Python command helpers remain Internal.
No SDK contract, Core schema, request defaults or evidence receipt is added.

## Verification

Use the independently authored introspection fixture's five query/mutation/
subscription templates and handwritten type/pointer/raw-digest oracle. Verify
the actual handler, installed console, original manifest replay, independent
same-byte acquisitions, relocation, retained report verification, exact no-op,
unrelated descriptions/UNKNOWN values, occupied collection refusal and all
three actual storage owners' failures before/after real commit. Exercise exact
current scope denial/expiry, original context substitution, nominal/frozen
manifest mutants, physical source drift and 512 KiB refusals before raw reads.
Tripwire preview generation, sockets and native process execution.

## Deferred work

Task #145 and Feature #143 remain open. General source refresh/composition,
OpenAPI multiple-server and concrete path-target composition, SDL/traffic input,
endpoint discovery, preview product flows, authentication/session handling,
live checks and governed transport require their own accepted contracts.
