# Security Object Model foundation

`fuzzy1337.model` is an **Experimental** library contract implementing
[ADR 0023](adr/0023-provider-neutral-security-object-model.md). It gives native
capabilities and tool adapters one attributable operational model beneath an
existing workspace. It introduces no scanning, TUI, graph analysis, findings
store, or new authorization semantics.

## Identity and typed records

`ObjectIdentity(workspace_id, kind, key)` produces a deterministic
`object:<sha256>` reference. The digest uses domain-separated canonical UTF-8 JSON
with sorted keys and no whitespace or terminal newline. Identity excludes current
attributes, provider IDs, evidence acquisition times, and installation paths.
Moving the workspace or changing the workflow lens does not change an object ID.

| Object kind | Natural key contract                                                            |
| ----------- | ------------------------------------------------------------------------------- |
| Workspace   | Existing workspace ID, matching `workspace_id`                                  |
| Scope       | Exact opaque reference supplied by the scope owner, such as `scope:lab`         |
| Target      | Exact opaque registered `target:<sha256>` reference supplied by the scope owner |
| Domain      | Offline normalized DNS name: IDNA, lowercase, no terminal root dot              |
| Host        | Offline normalized literal IPv4/IPv6 address; machine-specific zones rejected   |
| Asset       | Explicit first-party canonical inventory/domain key                             |
| Port        | Explicit first-party key containing host identity, protocol, and port number    |
| Service     | Explicit first-party key identifying the service attachment                     |
| Endpoint    | Explicit first-party key identifying the service, method, and endpoint          |
| Technology  | Explicit first-party key identifying its subject and technology name            |

No DNS lookup occurs during identity normalization. Port, Service, Endpoint,
Technology, and Asset keys remain opaque to this foundation: their ingestion owner
must choose and consistently reuse a canonical key. Provider-specific names must
not become the canonical key. A technology version or reported service name may
change as an attribute without forcing a new logical object.

One immutable `SecurityObject` uses the typed `ObjectKind` enum. Workspace, Scope,
and Target records are **reference projections**. They neither register a target
nor interpret permission or scope rules. Scope registration owns its own durable
state and remains a separate execution control.

Typed `Relation` values link existing same-workspace objects through
`RelationKind`: `contains`, `resolves-to`, `has-port`, `hosts-service`, `exposes`,
`uses-technology`, and `related-to`. They express reported relationships, not proof
of reachability, exploitability, or authorization. A relation ID uses its kind and
ordered endpoint IDs; mutable edge attributes do not change identity.

`Observation` records are content addressed and retain one attributed fact.
`ModelProvenance` records hold source/run references, an offset-aware observation
time normalized to UTC, opaque target/scope context, an optional provider version,
optional terminal executor outcome, and typed `EvidenceReference` values. Raw
bytes remain with the evidence store. The model does not resolve credentials or
verify artifact bytes; call the evidence owner to verify a referenced artifact.
A run reference may retain the immutable evidence acquisition ID when applicable.

## Updates and incremental queries

`ModelState.Apply` validates the complete proposed snapshot before returning it.
It never mutates the input snapshot. A batch creates or updates typed objects,
relations, and observations. Supplied attribute keys replace their current values;
omitted keys remain. An explicit `null` remains an attribute value rather than
deleting the key. Conflicting supplied values follow batch order.

Attribution is retained as a deterministic union. Every incoming object/relation
patch also produces immutable attributed observations of that patch. Thus a later
provider can update the current interpretation without erasing earlier values or
evidence links. Separate acquisitions can create separate observation records for
one logical object. Replaying the exact acquisition and patch creates nothing.

`ModelDelta` reports the previous and resulting revision plus sorted `created` and
`updated` references. A changed batch advances the revision once; a no-op keeps it.
References include objects, relations, and newly retained observations. Consumers
can query `ModelState.Objects()` or filter by a typed `ObjectKind`. Future TUI,
graph, domain-profile, and index consumers must query the same snapshot; they must
not establish another authoritative model.

The generic Asset identity/attributes and typed relationship boundary leave room
for future domain profiles under [ADR 0011](adr/0011-domain-profiles-for-robotics-and-cyber-physical-systems.md).
Robotics/CPS objects and graph analysis are not implemented by this foundation.
New object/relation kinds require an explicit schema/compatibility decision.
Unknown kind values are rejected rather than silently stored as extensions.

## Portable persistence

`LocalModelStore` operates on an existing `LocalWorkspaceStore` root. Constructing
a store performs no I/O. `Create()` initializes a new `state/model/` namespace and
an empty revision-zero `model.json`; it never overwrites an existing namespace.
Workspace metadata and evidence files remain unchanged.

`Open()` reads strict schema version 1. It rejects unknown/missing fields, duplicate
JSON keys, non-standard numeric constants, malformed or inconsistent stored
references, foreign workspace identities, dangling relationships/subjects, and
invalid provenance. Attributes are limited to 64 KiB per record; the complete
snapshot is limited to 8 MiB. Unsupported versions fail rather than migrate.

`Save(snapshot, expected_revision=previous_revision)` commits exactly one Apply
transition. Exact current-state replay does not write. A stale proposal raises
`WorkspaceConflictError`; a live or abandoned namespace writer lock raises
`WorkspaceBusyError`. Locks are never stolen automatically. Writes use a private
same-directory temporary file, file flush/fsync, atomic replacement, and POSIX
directory synchronization. Windows retains file synchronization and atomic
replacement without claiming POSIX directory durability.

If writing raises after replacement, the new revision may already exist. Reopen
before retrying. Failed saves clean owned temporary files and locks. The store
rejects traversal, observed symlinks/reparse points, hard-linked authoritative
records, and incorrect filesystem types. The operator must own the workspace tree;
hostile concurrent directory replacement is outside the portable path contract.
No database, search service, derived index, or optional cache is required.

```python
from pathlib import Path

from fuzzy1337.model import (
    LocalModelStore, ModelProvenance, ObjectIdentity, ObjectKind, SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

root = Path("synthetic-workspace")
LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic case"), "synthetic")
store = LocalModelStore(root)
initial = store.Create()
provenance = ModelProvenance(
    "native", "run:synthetic", "2026-10-05T20:00:00+00:00",
    "scope:synthetic", "target:" + "a" * 64,
)
host = SecurityObject(
    ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"),
    {"state": "reported"}, (provenance,),
)
updated, delta = initial.Apply(objects=(host,))
store.Save(updated, expected_revision=delta.previous_revision)
assert store.Open().Objects(ObjectKind.HOST) == (host,), "Portable host state changed"
```

This bounded example only writes synthetic state. Its opaque context references
are illustrative and grant no permission to execute a tool.

## Explicit adapter ingestion

`ModelState.ApplyAdapterResult(result, bindings, provenance)` consumes existing
SDK `NormalizedObservation`, `ObjectEnrichment`, and `RelationEnrichment` values.
`bindings` is a first-party mapping from each used provider reference to a validated
`ObjectIdentity`. A model object must exist already or be created by the same
batch before observations or relations can refer to it.

For example, an SDK host reference maps to a Host identity with the reported
literal address. A provider's TCP port reference maps to a Port key built from that
canonical host identity, protocol, and number. Changing the provider's reference
spelling does not change the authoritative object when the mapping stays the same.

The boundary requires provenance to match the executor-owned adapter ID, target,
provider version, raw evidence references, and terminal outcome. Failed acquisition
can retain explicitly reported partial observations with its actual failed outcome;
normalization does not convert it into success. Unsupported kinds, mismatched
bindings, missing subjects, malformed envelopes, and inconsistent attribution fail
without changing the original model. Scope authorization remains upstream.
`NormalizedFinding` values remain in the original SDK result for their future
owning subsystem; this foundation does not interpret or persist them.

## Focused verification

```bash
PYTHONPATH=src python -m pytest -o addopts='' \
  tests/unit/test_model.py \
  tests/contract/test_security_model_contract.py \
  tests/integration/test_security_model_integration.py
```

These suites cover identity normalization, exact replay, attributable patch
history, typed relations/projections, strict schemas, explicit SDK ingestion,
real evidence/workspace persistence, workspace relocation, competing writers,
unsafe paths, corruption, and pre/post-commit failure behavior. They never execute
an external tool or scan a network target. Full product/documentation gates remain
with PR CI under the owner's development workflow.
