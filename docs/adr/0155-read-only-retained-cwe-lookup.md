# ADR 0155: Read-only lookup in a retained CWE original

- Status: Accepted for the owner-authorized M3 offline operator continuation
- Date: 2026-11-25
- Decision owners: Fuzzy Technologies
- Related work: #47; ADR 0131, ADR 0133, ADR 0135

## Context

The accepted local CWE import already retains the complete bounded ZIP,
original source/notice declaration, selected envelope and independent receipt.
Exact inspection intentionally returns the original requested selection.
An operator encountering a different CWE ID must otherwise restore and reimport
the external ZIP despite already retaining its complete verified original.

## Decision

Add Experimental `intel cwe lookup WORKSPACE --selection ORIGINAL --receipt ORIGINAL
--identifier ID ...`. Validate one to 64 canonical unique IDs and both immutable
root syntaxes before storage access. First call the existing custody loader:
it verifies source, notices, original manifests and receipt, then reparses the
original selection. Reopen the same bounded original through its existing
evidence owner and call the unchanged selected decoder for the new IDs.

Keep the original verified selection and its acquisition-envelope reference
separate from the ephemeral lookup. The new terminal family
`cwe-local-original-lookup-cli` retains original top-level source/selection/receipt
facts and adds only `lookup.selection`, its pure decoder content reference and
`persistence: not-attempted`. This introduces no persistent family, new source,
provider, clock, notice capture or public Python SDK. Preserve accepted default
import/inspect bytes and grammar. Human presentation labels both selections.

Complete original-custody verification precedes on-demand parsing and any result.
The existing parser still completes ZIP framing, EOF/CRC and XML checks before
returning a bounded result. Preserve distinct Weakness, unsupported source kind
and absent-ID partitions, civil-day precision, exact catalog version and raw hash.
Do not infer applicability, risk, zero scores, legal rights or publisher identity.

Reuse the existing original/expanded/selected/terminal ceilings. Stage complete
output before its one publication attempt. Failures omit both usable selection
projections; actual verified custody handles and acknowledgement basis remain
truthful. An incomplete lookup stream write raises an error after one attempt.
Do not implicitly retry, acquire data or change saved owners.

## Verification boundary

Focused contract tests cover new IDs beyond the original selection, both
accepted catalogs, relocation/input deletion, exact source/notice identity,
mixed roots, corruption, early grammar refusal, three source partitions, bounded
presentation and ordinary module/shell routing. One clean-wheel selector creates
its own synthetic full catalog, imports a different original set, copies and
reopens the workspace after deleting the old root/input, and exercises installed
console plus guarded Main with no network/process/acquisition/write access.
It preserves every saved owner byte and original inspect output.

These are the required fresh checks, not a claim that they have already run.
Final integration and execution evidence remain separate from static review.
