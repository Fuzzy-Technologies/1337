# ADR 0149: Read-only verified finding intelligence preview

- Status: Accepted for the owner-authorized M3 implementation
- Date: 2026-11-25
- Decision owners: Fuzzy Technologies
- Related work: #47, #43; ADR 0041, ADR 0069, ADR 0123

## Context

Selected source inspection explains retained assertions but does not evaluate
the explicit association to an existing saved finding or its operator-selected
freshness budget. The apply command verifies these inputs and immediately saves
its candidate observation. Operators need to review the same interpretation
before deciding to save it.

## Decision

Add Experimental `intel preview` with the same explicit workspace, snapshot,
receipt, finding, identifiers, expected revision, as-of time, freshness budget,
scope and run inputs as `intel apply`. Reopen and verify the exact original
receipt/source/snapshot and saved revision, then call `ApplyVerifiedEnrichment`
with the same attribution as apply. Do not call the model save owner.

The existing terminal summary gains an optional `preview` profile version 1.
It contains the finding reference, proposed revision and complete new candidate
observations with their content references. Their original attributes retain
matched source assertions, canonical URLs, raw evidence, source attribution,
explicit unmatched IDs, freshness time, age and staleness. EPSS freshness uses
the source score clock; other feeds use acquisition time, exactly as apply does.
No wall clock is used for interpretation.

The summary's `model_revision` remains the actual saved revision and
`model_commit` remains `not-attempted`. Exact already-saved interpretation replay
returns `already_applied=true`, an empty new-observation list and the unchanged
proposed revision. An unsaved repeated preview returns the same observation
bytes and reference. The projection is bounded to 1 MiB before any printing;
failure returns no partial preview. Human output escapes terminal controls.

The expected revision check describes the saved state read for this preview.
It reserves no write lock or later revision: apply must independently reopen,
verify and compare-and-save its explicitly selected revision. Preview grants no
source approval, target applicability, finding severity or risk decision.

## Compatibility and verification

Existing import, inspect and apply output, retained snapshots, observations and
receipts remain unchanged. This command accepts only the original local snapshot
family already supported by apply; selected gzip/ZIP and HTTPS custody families
retain their existing separate contracts. There is no discovery, inferred
association, implicit refresh or network access.

Actual CLI subprocess tests cover all four retained feed families, explicit
matched/missing IDs, stale/fresh budgets, source deletion, relocation, identical
preview replay, byte-identical workspace contents and exact observation equality
with subsequent apply. Rehashed/foreign/missing/corrupt custody, invalid finding,
identifier, chronology and expected revision fail without partial preview or
saved-state mutation. Direct dispatcher tests prohibit the save boundary and
exercise bounded refusal and human output. Shared final-head CI remains the
integration gate.
