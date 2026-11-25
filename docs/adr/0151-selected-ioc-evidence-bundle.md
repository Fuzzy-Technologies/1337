# ADR 0151: Selected original IOC evidence transfer

- Status: Accepted bounded offline consumer decision
- Date: 2026-11-25
- Related work: #85, #86; ADR 0076, ADR 0080, ADR 0148

## Context

Task #86 asks for transferable original evidence and provenance. Candidate JSON
export contains derived occurrences but cannot independently reparse the original
TSV after removal of the owning workspace. Generic report export intentionally
excludes original evidence bundles. The accepted IOC profile already binds one
successful original source, acquisition receipt and derived snapshot, with an
independently retained receipt anchor. It needs no incident/path or Core model.

## Decision

Add Experimental `trace ioc export-bundle` and `trace ioc verify-bundle`.
Export requires an existing physical workspace, exact original snapshot and
independent original receipt IDs, explicit `--include-originals` opt-in and one
new external output path. It reuses original owning replay, reads exactly those
three records, independently validates the detached bytes and rechecks the
original chain before publication. Other acquisitions and model/scope/history
collections are neither selected nor included. The workspace is never saved.

The deterministic canonical JSON profile `ioc-evidence-bundle-v1` contains schema
version 1, original snapshot/receipt IDs and exactly three ordered records:
`ioc-source`, `ioc-acquisition`, `ioc-snapshot`. Each contains the original
canonical manifest and original payload as canonical base64 strings. There are
no archive paths, extraction operations, new timestamps or new custody actors.

The recipient explicitly selects the delivered file, the original receipt ID
and expected transfer SHA-256 retained separately from the file. Verification
bounds the physical read with the existing artifact reader, checks canonical
JSON/base64 and original manifest hashes, exact roles/media, common parser and
acquisition provenance, original receipt/source/budget/request bindings and
independent source reparse. A candidate bundle cannot choose its own trusted
receipt or transfer digest. It needs no source path or owning workspace and
writes no evidence or model. Its terminal result exposes safe original IDs,
transfer hash/length and candidate count, never original tokens or source text.

## Bounds and publication

The output ceiling is derived from the existing three 1 MiB manifest ceilings,
the original payload ceilings (64 KiB, 8 KiB and 512 KiB), exact base64 padded
lengths and fixed canonical envelope overhead: 4,992,042 bytes. This admits every
existing valid owning profile rather than truncating to an arbitrary bundle cap.
Each decoded part still obeys its original smaller consumer ceiling and the
receipt's caller-selected source budget. No limit is expanded in the IOC owner.

Reuse the report publisher's private complete staging, fsync and atomic
no-clobber link. Existing/conflicting outputs and source-workspace destinations
are refused. Pre-link failure/interruption leaves no selected output; a complete
file linked before acknowledgement fails remains intact and is reported with
`output_published: true` and its verified transfer pins. No partial file, rollback
or hostile concurrent-writer isolation is claimed.

## Consequences

The selected owned non-secret originals and declared attribution can be handed
to another defender and verified after deletion of the source workspace. The
explicit opt-in discloses unredacted original bytes and source/license locators
in the file. Public hashes are integrity pins, not signatures, source truth,
investigator authentication, assessment authority or legal-admissibility proof.
The existing acquisition receipt gains no consent/collector fields. Refused
acquisitions, general workspace bundles, incident timelines, observed paths and
broader Task #85/#86 acceptance remain separate work.
