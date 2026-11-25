# fuzzy1337.ioc_bundle

Internal implementation of the Experimental `trace ioc export-bundle` and
`verify-bundle` commands. The closed profile transfers exactly one original
source/receipt/snapshot chain with exact original manifests and payloads.
Export explicitly opts in to original-byte disclosure and never saves the
source workspace. Verification needs the file and independently retained
receipt/transfer pins, reparses original bytes and writes no state.

All functions, helpers and constants remain Internal. The CLI transfer profile
does not establish a Python SDK, investigator authority, publisher signature,
incident timeline, attack path or legal-admissibility contract. Existing owning
record schemas/budgets and atomic no-clobber publication retain their meanings.

See [the bundle guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/IOC_EVIDENCE_BUNDLE.md)
and [ADR 0151](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0151-selected-ioc-evidence-bundle.md).

Explicit `verify-bundle --export-candidates --json` adds the unchanged normalized
snapshot DTO only after the same independent receipt/transfer pins and complete
original reparse. Default summaries and transfer bytes remain unchanged. Invalid
text/matching/export combinations fail before reads; any verification refusal
omits candidate data. Detached presentation writes no source, evidence or Core
state and introduces no new log, identity, process or timeline semantics.

::: fuzzy1337.ioc_bundle
