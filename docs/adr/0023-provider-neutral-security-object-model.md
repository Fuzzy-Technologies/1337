# ADR 0023: Provider-neutral Security Object Model foundation

- Status: Accepted
- Date: 2026-10-05
- Decision owners: Fuzzy Technologies
- Related work: #54, #51

## Context

ADR 0010 requires one durable operational model. Workspace metadata owns portable
references, the evidence store owns immutable artifacts, and adapters emit
provider-neutral envelopes. None of those boundaries currently owns mutable
security objects or incremental model changes. Scope registration and authorization
remain independent responsibilities.

## Decision

Add an Experimental `fuzzy1337.model` library. One immutable `SecurityObject`
schema uses typed Workspace, Scope, Target, Domain, Host, Asset, Port, Service,
Endpoint, and Technology kinds. Workspace/Scope/Target objects are reference
projections only: importing a projection neither registers nor authorizes a target.
`ObjectIdentity` binds a workspace, kind, and canonical natural key. Domain keys
normalize offline DNS case, IDNA, and a terminal root dot; literal Host keys
normalize through `ipaddress`. Other keys are explicit first-party canonical
strings, independent of provider names, mutable attributes, and installation paths.
SHA-256 references use domain-separated canonical JSON. A collision with different
identity data is rejected, never merged.

Typed relations reference existing model objects. Observation records preserve
individual attributed interpretations. Provenance records retain source, run,
collection time, target/scope context, provider version, terminal execution state,
and typed evidence references. Evidence bytes remain outside model state; a
reference is not evidence-integrity verification. Every object/relation update
also retains its incoming attribute patch as an observation, so changing the
current interpretation does not erase earlier attributable facts.

`ModelState.Apply` returns a new immutable snapshot and an incremental delta of
created/updated references. Exact replay is idempotent. Attribute patches replace
only supplied keys; omitted keys remain. Conflicting supplied values follow
explicit batch order. Queries filter the same snapshot rather than creating
another authoritative model. Generic Asset keys/attributes preserve the future
domain-profile extension path without implementing robotics or reachability.

An explicit adapter boundary accepts SDK `AdapterResult` values and a first-party
mapping of provider references to `ObjectIdentity` values. It rejects unknown
object/relation kinds, mismatched provenance, and unresolved/dangling references.
Adapters do not choose canonical IDs or write model state. Findings remain in their
existing envelope for their future owning subsystem.

## Persistence and ownership

`LocalModelStore` owns only `state/model/model.json` beneath an existing validated
workspace. Its independent strict schema starts at version 1. Opening rejects
unknown/missing fields, duplicate JSON keys, unsupported versions, malformed
references, inconsistent stored IDs, dangling edges, and oversized/corrupt JSON.
Workspace metadata and evidence files are never modified by this store.

Writes use a private same-directory temporary file, flush/fsync, atomic replacement,
and POSIX directory synchronization. A fail-fast directory lock and explicit
expected revision prevent cooperating writers from losing updates. An abandoned
lock is never stolen. A failed write can have committed before a synchronization
failure; callers must reopen before retrying. The store rejects observed links,
reparse points, hard-linked authoritative records, unsafe filesystem types, and
lexical traversal. The operator must
own the tree; hostile concurrent filesystem replacement is outside this portable
path-based implementation's guarantee.

Model snapshots contain no absolute installation paths. Moving the complete
workspace preserves object identity, provenance, evidence locators, and queries.
This foundation introduces no database, index service, provider dependency,
scanner invocation, CLI, TUI, graph analysis, or new authorization semantics.

## Validation

Focused tests cover offline identity canonicalization, idempotent updates,
attribute/provenance history, typed relations, reference projections, explicit
adapter ingestion, failed-execution attribution, schema/collision rejection,
portable round trips, moved workspaces, writer conflicts, unsafe paths, and
write-failure cleanup. Module branch coverage must remain strictly above 80%.
Full product and documentation gates run in PR CI under the owner's development
workflow; local validation remains focused on this subsystem.

## Reopenable publication boundary

The M6 SDK follow-up enforces the existing strict version-one wire shape at
`LocalModelStore.Save` before writer-path preparation, locking or publication.
Ordinary Python dataclass subclasses can add serialized fields, including on
values which also satisfy `isinstance(value, str/int/float)`. The generic JSON
renderer visits dataclass fields before scalar values. Checking only DTO classes
or decoding the original Python dictionary does not prove the final bytes are
readable.

Serialize the proposed `ToDict()` once, bound its complete UTF-8 bytes including
the terminal newline, then apply the same strict JSON and model decoder as
`Open`. Publish those exact admitted bytes without reserialization and return
their concrete decoded snapshot. Correct inherited record/scalar representations
remain accepted; unsupported JSON shapes fail without durable changes. JSON
attributes retain what the existing serializer actually encodes rather than a
guessed runtime type. This adds no schema, public operation or execution authority.

A normal save now decodes the proposed document in addition to the current file.
The 256-object counter regression requires two model decodes and only one payload
serialization. Wall-time/memory cost must be measured in the grouped acceptance;
no unproven runtime-type shortcut is retained. Keep `WriteState(directory, state)`
as an Internal compatibility wrapper while sharing the original atomic publisher.

Verify the original external installed-SDK path, concrete DTOs holding dataclass
scalar values, correct inherited records/scalars, readable attribute wire,
size refusal before deep reconstruction, unchanged prior files and no writer-path
access on refused shapes. Retain original failed-execution metadata and replay/
advance of the previously shipped model fixture.
