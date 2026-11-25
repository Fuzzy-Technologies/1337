# ADR 0159: Combined retained local intelligence enrichment

- Status: Accepted for the owner-authorized M3 implementation
- Date: 2026-11-25
- Related work: #47, #43; ADR 0041, ADR 0069, ADR 0149

## Context

The existing verified enrichment SDK accepts one to sixteen local source
snapshots in one candidate observation, with canonical ordering, source-specific
freshness, explicit identifiers, source provenance and model bounds. The installed
single-source preview/apply commands accept only one original pair. Repeated
single-source saves produce separate observations/revisions rather than that
already supported combined operation.

## Decision

Add Experimental version-one preview-set/apply-set for two to sixteen explicit
unique original successful local snapshot/receipt pairs, one existing Finding
and the same explicit identifier/revision/as-of/freshness/scope/run basis as
single-source apply. Verify every pair through the unchanged local receipt and
original-byte owner. Call ApplyVerifiedEnrichment once, with every original
snapshot and receipt reference. Preview saves nothing; apply independently
rechecks all inputs and performs one existing model CAS.

Preserve existing parser, snapshot/receipt, observation, finding and Core
contracts. The separate selected ZIP/gzip and HTTPS families are not converted
or admitted. Source scores remain source scores, every association remains
candidate/unreviewed, and no source policy, applicability or approval is inferred.
The SDK owns assertion ordering; terminal selection metadata keeps caller order.

Read bounded canonical owning manifests before bodies, summing total snapshots
and receipts. Decode bounded snapshots to sum original sizes before any original
source reparse. This profile caps aggregate snapshots and raw originals separately
at 16 MiB, receipts at 512 KiB total/32 KiB each, preview at 1 MiB and complete
terminal output at 2 MiB. Existing limits remain simultaneous: 64 requested IDs,
64 matched source assertions and 64 KiB model attributes are distinct bounds.
A count-admitted observation can still exceed its byte cap; never truncate it.

Stage and bound the complete successful response before the CAS attempt.
Verification refusal returns no partial selections/preview and saves no valid
prefix. Preserve actual not-attempted/unknown/confirmed/known-not-committed save
acknowledgements without retries or rollback claims, including late output faults.
No new interpretation clock is introduced.

## Consequences

An operator can retain four supported source-shaped documents, delete caller
files, relocate the complete workspace, preview one deterministic multi-feed
candidate and save exactly that observation with one revision check. A bad final
receipt refuses after prior successful reads without publishing their prefix.
A real concurrent triage change wins through the existing CAS; findings are never
patched by enrichment. Original evidence and later operator triage survive replay.

There is no acquisition/provider, scanner, live refresh, authentication, legal
conclusion, applicability or contextual-risk policy change. Synthetic fixtures
establish formats and byte custody, not authentic upstream publications.
The broader #43/#47 source/format/assurance criteria remain open.
