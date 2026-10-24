# Native content crawl SDK

The public Experimental `PlanNativeCrawl` and asynchronous `RunNativeCrawl`
consume an existing workspace, current scope, one canonical seed URL, an exact
sorted tuple of at most sixteen selected same-origin URLs, selected owner and a
synchronous current typed `ImpactPolicy` reader. Only literal-loopback anonymous
HTTP is admitted. Planning contacts no target, creates no execution grant and
returns a `NativeCrawlPlan` with exact invocations, policy plans and revision bases.

Execution additionally requires `approve_safe_crawl=True`. Both entry points
accept `limits=NativeCrawlLimits(...)`, an aware decision `clock`, and optional
`current_owner_provider`. A trusted reader must return the original selected
owner afresh; default selected-owner attribution cannot detect external principal
changes. Neither consent nor permission is inferred from discovered links.

`NativeCrawlSummary` preserves the actual `JobSnapshot`, original `records`,
ordered `completed_urls`, reopened model/workspace revisions, per-page
`model_saves`, `workspace_persistence_status`, `acknowledged_record_ids`,
`custody_status`, events and duration. `ToDict()` exposes safe original IDs and
source metadata. `ExitCode()` returns 0 for completion, 3 for authority denial,
4 for other failure and 130 for cancellation. The CLI uses 2 for invalid
configuration; invalid initial SDK arguments can raise before a job exists.

Earlier original acquisitions and commits survive later failure. Observed
committed state does not create a missing acknowledgement or trigger a retry,
rebase or rollback. Original worker outcomes stay unchanged during cancellation;
unknown cleanup/outcomes cannot become successful source projection. Workspace
retention uses at most one original Save attempt, independently of page model CAS.

The model stores source/link Observations and structural RequestTemplates, with
no security Finding or automatic STANDARD Git-check grant. Body digests attest
worker interpretation without retaining bodies or independently replaying
extraction. See the [operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/NATIVE_CONTENT_CRAWL.md)
for exact CLI selections, limits, explicit authority and verification boundaries.

::: fuzzy1337.native_crawl_workflow
