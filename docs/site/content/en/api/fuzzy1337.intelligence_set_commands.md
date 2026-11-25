# fuzzy1337.intelligence_set_commands

All symbols in this module, including `RunIntelSetCommands`, are Internal
CLI/shell implementation details. No new Python SDK is declared.
Experimental version-one `intel preview-set|apply-set` composes the unchanged
[local original verifier](fuzzy1337.intelligence_commands.md),
[verified enrichment SDK](fuzzy1337.intelligence.md) and
[model CAS owner](fuzzy1337.model.md).

Select two to sixteen unique original successful local snapshot/receipt pairs,
one existing evidence-linked Finding, exact identifiers, revision and
interpretation time/freshness/scope/run. Metadata-only owning manifest reads
sum snapshot/receipt sizes before their bodies. Bounded snapshot decoding sums
original-reference sizes before raw reparse. Aggregates are 16 MiB snapshots,
16 MiB originals and 512 KiB receipts (32 KiB each); preview is 1 MiB and
terminal output 2 MiB. The distinct 64-requested-ID, 64-matched-assertion and
64 KiB model attribute ceilings remain simultaneous; count does not guarantee
byte capacity and overflow never truncates records.

Every original pair then passes the existing complete local receipt/raw verifier.
One SDK call constructs one candidate observation in canonical snapshot-reference
order; terminal selection metadata retains caller order. Preview saves nothing.
Apply reopens/rechecks and calls one existing CAS after complete output preflight.
Exact replay remains idempotent and preserves later triage. A bad final receipt
or other verification refusal exposes no partial selection/proposal and saves
no valid prefix.

CVE source CVSS, CWE descriptions, KEV membership and EPSS probability retain
their distinct attributed meanings, evidence, source clocks and stale/unmatched
facts. No applicability, approval, identity, exploitation or risk verdict follows.
The selected ZIP/gzip and HTTPS families are not converted into legacy snapshots.
Terminal source strings are escaped. One checked write is attempted without
retry; save/output failures preserve actual acknowledgement uncertainty.

See the [operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/INTELLIGENCE_CLI.md#one-combined-preview-and-save-from-several-originals)
and [ADR 0159](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0159-combined-local-intelligence-enrichment.md).

::: fuzzy1337.intelligence_set_commands
