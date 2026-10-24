# Internal native crawl CLI enrollment

This internal module declares the shared installed `scan crawl` action and routes
it to the public planning/execution SDK. It is not a separate scanner provider or
generic extension interface. Canonical seed/selected URL spellings, explicit
scope/owner/current policy, finite limits and independent SAFE approval reach the
SDK unchanged; shell selection supplies no implied inputs or permission.

`--plan` is read-only. `--approve-safe-crawl` selects execution, `--json` selects
one summary and `--events-json` selects original safe events followed by a summary.
Ambiguous intent/output modes refuse. Presentation contains source-only metadata;
the module neither writes raw worker output nor grants a discovered Git check.
See the [public SDK](fuzzy1337.native_crawl_workflow.md) for the owning behavior.

::: fuzzy1337.native_crawl_commands
