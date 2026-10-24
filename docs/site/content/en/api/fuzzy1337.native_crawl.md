# Owned-loopback native crawl limits and provider

`NativeCrawlLimits` is the Experimental public configuration shared by the
planning and execution SDK. Its defaults are 16 pages, depth 4, concurrency 2,
262144 reserved body bytes, a 0.05-second start interval, one 30-second operation,
16384 bytes per body and a 3000-millisecond complete-request deadline. Quotas
reserve whole waves before dispatch and never refund unused body reservations.

`NativeCrawlProvider` owns first-party scheduling, original report custody and
ordered incremental structural model projection. Prefer the
[SDK entry points](fuzzy1337.native_crawl_workflow.md) for ordinary use.
`CurrentCrawlAuthority` keeps current selected-actor attribution separate from the
scope's consent attester; no default reference authenticates an external identity.
Scope, permission, original grant validity and cancellation still guard each Save.

Private evidence/task helpers are internal implementation details, documented
here for static traceability rather than a supported generic execution framework.
See the [user guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/NATIVE_CONTENT_CRAWL.md)
and [compatibility policy](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/COMPATIBILITY.md).

::: fuzzy1337.native_crawl
