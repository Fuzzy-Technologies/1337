# Internal native crawl input and report boundary

This internal first-party adapter/helper module freezes the Experimental version-1
input, report and fixed invocation grammar. It is not a general URL fetcher or
caller-program execution API. `BuildCrawlInput` / `EncodeCrawlInput` bind the exact
selected source/set and finite body/request limits; `ParseCrawlInput` and
`ParseCrawlRecord` independently reject noncanonical bytes and invalid semantic
joins, including source/peer/request identities, hashes and selected-only ordinals.

`NativeCrawlAdapter` prepares only the packaged isolated Python module recipe.
Its descriptor declares the separate SAFE `http.owned-loopback-crawl` capability
under `native.crawl`; the descriptor grants no execution permission. Normalization
uses verified original reports and empty stderr to produce source observations,
without Findings or model writes. Parent authority/custody and ordered saves
remain owned by the [provider](fuzzy1337.native_crawl.md) and
[public SDK](fuzzy1337.native_crawl_workflow.md).

::: fuzzy1337.adapters.native_crawl
