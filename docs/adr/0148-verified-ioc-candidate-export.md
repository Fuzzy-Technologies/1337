# ADR 0148: Explicit verified IOC candidate export

- Status: Accepted bounded consumer extension
- Date: 2026-11-25
- Related work: Task #85, Feature #83, ADR 0076, ADR 0080

## Context

The installed IOC inspection command verifies retained originals, but its default
summary intentionally excludes tokens and declared source attribution. A consumer
needs a Python SDK script to obtain the already accepted normalized occurrences.
An explicit offline machine handoff can expose that existing schema without
introducing log, incident, identity, process or Core investigation semantics.

## Decision

Add `trace ioc inspect --export-candidates --json`. Both original snapshot and
independently retained original receipt manifest pins remain mandatory. The flag
is an explicit request to disclose the owned non-secret candidates, including
original tokens and declared logical source/license attribution, to stdout.
Import does not accept the flag. Text mode and `--match` cannot be combined with
candidate export; invalid combinations fail before storage access.

The command completes the unchanged receipt-anchored original-byte replay, exact
snapshot reconstruction and final raw owning-record verification before adding
`candidate_export` to a successful schema-one terminal result. The field contains
the unchanged schema-one `IocSnapshot.Serialize()` document: parser/profile,
source/license/digest, original raw/receipt manifest identities, limits and every
candidate occurrence in source order. Original tokens, coordinates, duplicate
occurrences and source-declared timestamp/timezone retain their existing meanings.
The surrounding terminal result preserves the original receiver acquisition times,
selected snapshot/receipt identities and `evidence_commit: not-attempted`.

Default import/inspect summaries retain their original fields and do not include
`candidate_export`. Any configuration, integrity, storage or interruption refusal
also omits the field; no partial candidate list is emitted. Export performs no
acquisition, model/workspace save, output-file creation, network resolution,
process launch or source-file rediscovery. Shell history protection applies to
the existing entire `trace` namespace.

## Consequences

An installed offline consumer can obtain bounded, verifiable normalized data
after workspace relocation and source deletion without reimplementing a parser
or choosing a new trust anchor from candidate metadata. The output contains
explicitly requested source data and attribution and should be handled as such.
Public hashes remain integrity pins, not publisher signatures, maliciousness
judgments or current assessment authority. No acquisition/custody fields, evidence
schema or Core semantics change. Wider Task #85 acceptance remains open under
ADR 0076 and ADR 0080.
