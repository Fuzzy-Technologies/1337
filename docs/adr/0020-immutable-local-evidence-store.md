# ADR 0020: Immutable local evidence and attributable content identities

## Status

Accepted — 2026-10-04

## Context

Tool adapters already consume immutable `EvidenceReference` values and the local
executor captures raw stdout/stderr before normalization. Task #45 requires a
local durable producer for those references. Raw bytes and their collection
context must survive independently from mutable findings or model interpretations.
The workspace owns a separate evidence partition; it must not need a server,
search index, or heavyweight database to preserve that evidence.

## Decision

Introduce the Experimental `fuzzy1337.evidence` contract, schema version `1`.
`EvidenceProvenance` records explicit workspace, scope, source/version, tool
version, UTC collection times, and optional invocation digest/execution outcome.
These are immutable attribution facts; a scope reference grants no authorization.
The store never collects environment variables, credentials, or invocation
arguments automatically. Callers supply only authorized non-secret bytes and
metadata; hashing is not redaction or encryption.

Each raw payload has its own SHA-256 identity. Each immutable `EvidenceRecord`
contains the unchanged adapter `EvidenceReference`, provenance, and schema
version. Its distinct `sha256:<digest>` identifier hashes the canonical UTF-8 JSON
manifest. Identical bytes collected in different contexts share a blob but retain
different records. Consumers reject unsupported schema versions, unknown fields,
duplicate keys, invalid timestamps, non-finite values, and inconsistent identities.

Within an explicitly existing evidence root, the layout is:

| Path                    | Meaning                                    |
| ----------------------- | ------------------------------------------ |
| `blobs/sha256/<digest>` | Exact raw bytes addressed by their SHA-256 |
| `records/<digest>.json` | Canonical versioned provenance manifest    |

Adapter locators are relative to this root. A workspace may choose its own
`evidence/` partition as the root. Evidence storage does not open workspace state
or derive findings, model updates, or scanner accuracy.

Writes publish fully written, fsynced sibling temporary files by an atomic
no-overwrite hard link. Cooperative concurrent writers may create the same
content idempotently; existing bytes must match exactly. Blobs are published
before manifests. A later failure may leave an unreferenced valid blob, but never
reports success or overwrites an existing record. No automatic orphan deletion is
introduced. Filesystems that cannot perform the required publication operation
fail explicitly. Linux, macOS, and Windows use the same contract.

Reads validate canonical manifests and recompute both manifest and raw-content
hashes and lengths. Missing, malformed, or corrupt evidence fails explicitly;
path aliases cannot substitute another location for a valid digest. Observed
symlinks, Windows reparse points, and non-regular files are rejected throughout
the physical root and owned partitions.

The root is an operator-owned local directory with no hostile concurrent
filesystem writer. Path checks do not provide protection against an attacker
who can replace directory entries between checks. SHA-256 integrity is not
cryptographic proof of the collector's identity, authorization, or acquisition
truth, and it does not prevent an administrator replacing both bytes and records.

## Consequences

- Existing ToolAdapter consumers receive the same five-field `EvidenceReference`.
- Collection metadata is explicit and stays separate from interpretations.
- Local executor integration can persist bounded stdout/stderr without importing
  a scanner, installing a tool, or accessing an external target.
- Cooperative concurrency, publication failures, corruption, missing evidence,
  schema rejection, and unsafe filesystem boundaries require direct tests.
- This first store has no encryption, retention policy, signing, remote backend,
  automatic import, CLI, or authoritative listing/index API. Those require their
  own contracts and actual consumers.
