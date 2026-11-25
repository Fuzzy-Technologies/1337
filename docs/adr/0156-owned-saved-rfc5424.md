# ADR 0156: Owned saved RFC 5424 source records

- Status: Accepted
- Date: 2026-11-25
- Scope: M8 #85, Patch 64; data-only saved-file operation

## Context

The accepted ASCII TSV IOC family handles supplied candidate occurrences and
portable original evidence. It does not satisfy #85's separate saved-log
criterion. General Core Event/Identity and incident/timeline policy remain
owner decisions; normalizing source-only records need not invent them.

The owner selected RFC 5424 version-one saved syslog as the first reversible
engineering format choice. RFC 5424 defines a message, not saved-file framing.
The existing artifact reader and immutable evidence owner already provide local
bounded reads, raw byte identity, portable manifests and acquisition provenance.

## Decision

Add an Experimental source-only version-one pure decoder and owned-file SDK/CLI.
Require explicit original checksum, source declarations, read actor/consent
references, scope attribution and either single-message or LF/CRLF line-export
framing. Preserve RFC header/NIL/time/offset and byte coordinates, ordered
structured data and opaque original message octets. Default output withholds SD
values; explicit JSON record export reveals them. Neither output includes MSG
body. No host identity, incident, compromise, applicability or score is inferred.

Reuse ReadArtifactFile and LocalEvidenceStore without changing their contracts.
Retain the complete exact original with a separate profile receipt that binds
its original manifest, source, parser/version, framing, finite limits, declared
read references, parser state and canonical normalized-document checksum.
Reopen requires independently retained original receipt ID and source SHA-256,
verifies all selected owners before output, then reparses the same retained bytes.
It requires no original filepath, Core model, clock, provider or write.

Publish raw and receipt with separate truthful acknowledgements. Parser refusal
retains a correctly pinned bounded original and refusal receipt with no usable
records. Digest refusal publishes nothing. Later failure preserves earlier
verified records and never promises rollback. Lost-ACK recovery requires an
actually committed original receipt and independently retained pins.

Use finite original/record/SD/document/receipt/presentation budgets independently
from RFC transport guidance. Preserve unknown offset and source timestamp
spelling when derived UTC cannot be represented. Generic diagnostics never copy
source text or rejected arguments. Detailed exact grammar and storage restrictions
are part of the [operator guide](../SYSLOG_SAVED_IMPORT.md).

## Consequences

Operators can reopen a copied saved-log collection after deleting its caller
file and independently inspect original fields, provenance and coordinates.
The store remains the existing custody owner; the new receipt is a local profile,
not a new global custody or Core format. Existing IOC TSV, acquisition receipt v1,
portable IOC bundle and Core model semantics remain unchanged.

This does not close all #85/#83 incident/entity/process/timeline criteria.
There is no live input, remote acquisition/provider, network transport, actor
authentication, signing, retention policy, scanner or operation execution.
The physical owner excludes hostile concurrent writers under the existing
filesystem contract. No new runtime dependency is required.
