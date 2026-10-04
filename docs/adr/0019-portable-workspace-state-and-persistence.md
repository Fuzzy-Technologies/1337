# ADR 0019: Portable workspace state and persistence

- Status: Accepted
- Date: 2026-10-04
- Decision owners: Fuzzy Technologies
- Related work: #20, #22

## Context

The Workbench needs an actual local workspace lifecycle before scanners, reports,
and integrations can share durable context. ADR 0010 separates canonical state
from optional search indexes. The Security Object Model and scope authorization
are still separate implementation tasks; storing a reference cannot claim either
capability or grant permission to execute.

## Decision

Introduce an Experimental `fuzzy1337.workspace` library contract with immutable,
validated configuration and state snapshots. Configuration stores a display name,
one initial lens, and optional non-secret view/report context references. State
owns opaque scope, model-object, and job references plus the existing typed
`EvidenceReference` values. Separate unique `evidence_record_references` retain
immutable acquisition IDs in `sha256:<64 lowercase hex>` format, because the same
raw bytes can belong to distinct provenance records. The workspace does not
interpret or certify those records. It does not accept arbitrary domain payloads, secret
values, executable configuration, or a second provider-owned model.

`WorkspaceStore` separates lifecycle consumers from the first portable
`LocalWorkspaceStore` implementation. Explicit `Create`, `Open`, and `Save`
operations perform I/O; constructing the store performs no filesystem mutation.
The file schema starts at version 1. Unknown versions, fields, duplicate JSON
keys, invalid enum/type values, malformed references, and corrupt documents are
rejected rather than repaired or silently defaulted.

| Partition        | Owner and recovery contract                                              |
| ---------------- | ------------------------------------------------------------------------ |
| `workspace.json` | Authoritative metadata and references; corruption prevents opening       |
| `state/`         | Reserved authoritative domain records; validated by their future owner   |
| `evidence/`      | Independent immutable evidence owner; locators are relative to this root |
| `cache/`         | Disposable derived state; absence does not prevent opening               |
| `indexes/`       | Rebuildable search state; absence does not prevent opening               |

The workspace lifecycle never changes evidence artifacts and never needs a
search service. The reserved `state/` partition belongs to future typed domain
persistence; workspace metadata does not interpret or certify those records.
Evidence references retain their current SDK fields; the raw
artifact and manifest implementation is independently owned by the evidence
store. Missing optional partitions can be recreated by their owners.

## Commit and concurrency contract

Creation requires an existing parent and a new workspace directory. Files and
directories use private permissions where the platform supports them. A failed
creation may leave an incomplete directory; `Open` rejects it rather than claiming
success.

Each save acquires an exclusive, fail-fast directory lock, reads the current
snapshot, checks the immutable workspace identity and expected revision, and
increments the revision exactly once. A stale writer receives an explicit
conflict. Cooperating writers cannot lose updates. Reads remain available while
a writer holds the lock. An abandoned lock blocks further saves; operators must
establish that no writer remains before removing it. Automatic timeout-based
lock stealing is prohibited.

Writes use a private same-directory temporary file, strict deterministic JSON,
file flush and `fsync`, and atomic replacement. POSIX also synchronizes the
workspace directory and creation also synchronizes its parent. Windows retains file synchronization and atomic replacement
without claiming the same directory durability guarantee. A failure after
replacement may mean the new revision is already present; callers must reopen
before retrying. Temporary files and owned locks are cleaned up on failures.

## Path and ownership boundary

Reject lexical traversal, symlinked/reparse-point roots, ancestors, and state files, and
non-directory partition paths. Workspace contents must be owned by the operator
and inaccessible to hostile concurrent filesystem writers. This path-based
implementation does not claim resistance to malicious directory replacement
between checks and operations. Portable paths are derived from the current root;
the state document contains no installation-specific absolute paths.

## Consequences and validation

- Configuration and durable references survive real temporary-directory round
  trips and moving an entire workspace.
- Scope references are context only; governed execution remains independently
  responsible for scope, impact, and authorization.
- No CLI or shell command is introduced by this library foundation.
- Tests cover corrupt/unknown documents, malformed metadata, stale writes,
  competing writers, abandoned locks, unsafe paths, write failure cleanup, and
  absent rebuildable partitions.
- Canonical product, source-documentation, localization, and static installed-wheel
  reference gates must validate the implementation before review.
