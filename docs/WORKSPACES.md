# Portable workspace lifecycle

`fuzzy1337.workspace` is an Experimental library and workspace-document contract
at schema version `1`, defined by
[ADR 0019](adr/0019-portable-workspace-state-and-persistence.md).
It provides explicit local creation, opening, and revision-checked saving without
requiring a database or search service.

`WorkspaceConfiguration` retains a display name, one of `pentest`, `dfir`,
`devsecops`, or `purple`, and optional opaque view/report context references.
`WorkspaceState` owns the durable workspace ID, revision, configuration, ordered
scope/object/job references, existing raw-artifact `EvidenceReference` values, and
unique immutable acquisition IDs in `evidence_record_references`. Record IDs use
`sha256:<64 lowercase hex>` and preserve distinct provenance records even when
raw bytes are shared. Workspace metadata retains both identities without reading
or certifying the evidence records. All
configuration and references must be non-secret. No credential value, executable
configuration, arbitrary model payload, or installation path belongs in this
metadata.

Scope references establish context only. They do not establish authorization or
replace the governed executor's scope/impact checks. Object references do not
claim that a Security Object Model has been implemented. This foundation does not
add workspace commands or automatic configuration loading to the CLI or shell.

## Use the lifecycle boundary

```python
from dataclasses import replace
from pathlib import Path

from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

store = LocalWorkspaceStore(Path("synthetic-workspace"))
initial = store.Create(WorkspaceConfiguration("Synthetic investigation"), "synthetic-case")
saved = store.Save(replace(initial, job_references=("job:synthetic-fixture",)))
reopened = store.Open()
```

The parent directory must already exist and creation rejects an existing root.
Construction performs no filesystem I/O or mutation. `Create`, `Open`, and `Save`
are the supported lifecycle operations behind `WorkspaceStore`; implementation
helpers are internal even though the static reference lists them.

The new root contains `workspace.json` and four separate partitions. `state/` is
reserved for future typed authoritative domain records and is never a cache. Its
domain owner must validate its own records; the metadata lifecycle does not
interpret or certify domain contents. `evidence/` is independently owned immutable
evidence, while `cache/` and `indexes/` contain
rebuildable derived state. Evidence locators are relative to the evidence
partition, not the workspace root. Workspace operations never read, overwrite, or
delete raw artifacts. Empty or absent partitions do not prevent authoritative
metadata from being opened or saved. No accelerated index is required.

Metadata paths are derived from the root passed to the current store. Moving the
whole workspace preserves the same IDs and relative evidence references.

## Validation and writing

Unknown schema versions or fields, absent fields, duplicate JSON keys, incorrect
types, booleans used as integers, unknown lenses, duplicate references, unsafe
locators, non-standard numbers, invalid UTF-8, and corrupt JSON fail closed.
Metadata is limited to 1 MiB; raw evidence size is owned by the evidence store.
State paths must be regular files, partitions must be directories, and observed
symlinks/reparse points or lexical traversal are rejected.

The operator must own the workspace tree and exclude hostile concurrent
filesystem writers. This implementation does not claim protection against
malicious path replacement between validation and use.

`Save` acquires an exclusive `.write-lock` directory and compares the proposed
identity/revision with the current state. A successful commit retains the ID and
increments the revision once. `WorkspaceConflictError` requires reopening before
reapplying a change. `WorkspaceBusyError` preserves an existing writer lock,
including an abandoned lock. Readers can still open the last complete snapshot.
An operator may remove an abandoned lock only after establishing that no writer
remains; the library never steals or expires it automatically.

A private same-directory temporary file is synchronized and atomically replaces
`workspace.json`. POSIX also synchronizes the root directory and, during creation,
its parent. Other platforms retain file synchronization and atomic replacement
without the same directory durability guarantee. Failed creation can leave an
incomplete root. A write failure after replacement may leave the new revision
present: reopen before retrying. Failed commits attempt to remove temporary files
and their owned locks; filesystem failures during cleanup are propagated.
