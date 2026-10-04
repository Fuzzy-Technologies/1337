# Local Evidence Store

`fuzzy1337.evidence` is an Experimental schema-v1 contract defined by
[ADR 0020](adr/0020-immutable-local-evidence-store.md). It produces the existing
[ToolAdapter](TOOL_ADAPTERS.md) `EvidenceReference` without changing that SDK.

The supported Experimental API consists of `EvidenceProvenance`, `EvidenceRecord`,
`LocalEvidenceStore.Put`, `.Read`, `.Get`, `ParseEvidenceManifest`, and the
documented version/limit constants and exception types. Other validation/parser
functions and store path/publication helpers are Internal implementation details
with no consumer compatibility promise.

A caller chooses an existing physical evidence directory, normally a workspace's
`evidence/` partition. `LocalEvidenceStore` construction performs no I/O. `Put`
accepts explicit authorized non-secret bytes, a role/media type, and immutable
collection provenance. It returns an `EvidenceRecord`; `Get(record.evidence_id)`
verifies its canonical manifest and raw bytes. `Read(record.reference)` returns
those exact bytes after digest/length verification. Empty output remains a valid
zero-byte artifact; missing output is a failure.

Raw-content SHA-256 and manifest SHA-256 are separate identities. Equal bytes
share `blobs/sha256/<digest>` while separate collection contexts retain separate
`records/<digest>.json` manifests. The record's `sha256:<digest>` identity covers
schema version, reference, and provenance, rather than mutable interpretations.
References use paths relative to the evidence root, never host absolute paths.

`EvidenceProvenance` stores workspace/scope references, source/version, an explicit
optional tool version, offset-aware collection times normalized to UTC, and
optional invocation SHA-256/immutable `AdapterExecution`. Failed/timed-out/cancelled
execution stays failed/timed-out/cancelled even if evidence storage succeeds.
Scope metadata attributes collection and grants no execution authority. The store
never discovers credentials or records environment variables/arguments implicitly.
Callers must exclude secrets before collection; hashing is neither redaction nor
encryption.

Manifest JSON is strict, compact UTF-8 with sorted keys. Schema version `1`
requires exact fields, rejects duplicate keys and non-finite numbers, and limits
one manifest to 1 MiB including serialized provenance. This limit does not cap
raw artifacts. Raw reads use the reference's expected size as a ceiling; a large
corrupt file cannot force an unbounded read through a small reference. Every read
checks both declared byte length and SHA-256. Unsupported schema, missing files,
invalid manifests, and content mismatches are explicit failures.

Files are fully written and fsynced before atomic no-overwrite hard-link
publication. Linux, macOS, and Windows use the same operation; a filesystem that
cannot publish a hard link fails explicitly. Cooperative concurrent identical
writers are idempotent. Existing conflicting or corrupt bytes are never repaired
by overwrite. The raw blob is published first: a subsequent manifest failure may
leave a valid unreferenced blob, and the operation reports failure. Temporary files
are cleaned after normal exceptions; automatic orphan deletion is not provided.

The operator owns the root and excludes hostile concurrent filesystem writers.
Observed symlinks, Windows reparse points, and non-regular files are rejected in
root ancestors, partitions, and artifacts. These path checks do not prevent an
attacker replacing directory entries between checks. Callers using a platform's
aliased temporary directory select its known physical root explicitly. Integrity
hashes detect inconsistency; they do not establish cryptographic authenticity,
prove acquisition truth, or prevent an administrator replacing both records and
bytes. Power-loss transaction guarantees, encryption, retention, signing, remote
storage, CLI, and interpretation/index APIs are outside this initial contract.
