# ADR 0062: Bounded async traversal of reviewed owned pages

- Status: Accepted for implementation
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #59, #53

## Context

ADR 0050 interprets a verified static HTML capture. ADR 0052 acquires one closed,
reviewed body through the ordinary governed executor, jobs, evidence and model
owners. Neither endpoint discovery nor a link observation authorizes fetching a
candidate. The next useful web-engine step is actual asynchronous traversal of a
finite repository-owned page pack without generalizing transport to arbitrary
response bodies, browser sessions or Internet targets.

## Decision

Add Experimental `fuzzy1337.web_traversal`. A caller explicitly selects a seed and
at most sixteen distinct anonymous, query-free, same-origin literal-loopback HTTP
GET templates paired with reviewed body IDs. Extend the existing closed body
catalog with four handwritten non-secret page bodies: index, alpha, beta and a
shared leaf. The original body's ID, bytes, digest, worker record grammar,
capability ID and provider version remain unchanged. Extend the Experimental
record schema with exact paired catalog ID/size/SHA/base64-shape cases; existing
records remain valid and arbitrary pairings refuse. Callers cannot register
arbitrary hashes, files, returned bytes or additional catalog entries. A catalog
selection is a content admission boundary, never execution permission.

Use `LocalPageCaptureProvider` for every actual request. Each candidate repeats
current owning exact URL/IP scope and separate SAFE capability authorization at
grant and immediately before governed launch. Interpretation and final model Save
retain the existing full launch snapshot, exact revision and fresh consent checks.
No URL registration, allow rule expansion, alternate HTTP client, automatic CLI
registration or standalone unrestricted acquisition path is introduced.

Use deterministic breadth/depth then lexical URL frontier order with deduplication
and cycle suppression. Fetch only selected pages discovered from verified admitted
bodies; a selected page absent from the discovered frontier is never launched.
Allowed unselected candidates are count-only omissions. Scope exclusions remain
fixed parser counters and never enter the execution queue. Explicit finite page,
depth, concurrency, aggregate admitted-body byte, worker-start interval and whole
operation time budgets are independent from existing per-request bounds. Reserve
an entire dispatch wave's page/body quota before starting any worker in it. A
bound that omits reachable selected work fails with OUTPUT_LIMIT; do not report
that partial traversal as successful. Lexical frontier truncation also fails.

Acquire each sorted wave concurrently. An additive internal `Acquire` hook waits
before model Open/composition, then admits the unchanged synchronous composition,
fresh final authorization, expected-revision Save and model event block in sorted
URL order. Existing positional callers keep their one-page behavior. Per-page
progress is suppressed only by this composition; traversal publishes monotonic
committed counts with unknown total, and the actual final total after exhaustion
of the selected reachable frontier. The earlier page's CAS acknowledgement or
post-Save event failure is not success and cannot release a successor as complete.
TaskGroup cancellation drains every owned task, including commit-gate waiters,
and existing executor ownership terminates/drains the workers before terminal
job state. No detached worker, retry, resume or persistent queue is introduced.

Keep the existing strict refusal of all 3xx responses. The worker does not retain
or resolve arbitrary Location values, and never connects to a redirect destination.
The fixed response-policy failure record retains the truthful failed acquisition
where supported by the existing provider. Actual redirect-following, including
separately authorized destinations, requires a future typed transport decision.

Preserve incremental acknowledged canonical page/model transitions and original
immutable acquisition records. Failure or cancellation later in traversal does
not roll back prior pages, erase evidence or convert their worker success to a
failure. Existing storage conflict and ambiguous Save acknowledgement reporting
remain authoritative. A successful run means only that the explicitly selected,
reachable reviewed page subset completed under this bounded lexical profile;
it is not a full website crawl, vulnerability scan, browser run or security verdict.

## Validation

Use handwritten independent page bodies and expected commit/candidate/count
oracles. Actual pytest-owned loopback listeners must exercise multi-page requests,
concurrent acquisition with inverted completion order, deterministic canonical
Save ordering, deduplication/cycles, denied/unselected/off-origin routes, current
scope/policy denial, budget exhaustion, strict no-follow redirects, malformed body
refusal, cancellation/timeout, partial evidence retention, commit-gate failures,
CAS conflict, lost acknowledgement and post-Save event failure. Verify saved model
and raw manifests through independent owner reopen. No browser, public target or
PyPI task is necessary. #59/#53 remain open for browser and broader native web
engine acceptance.

## References

- [Owned traversal guide](../WEB_TRAVERSAL.md)
- [Captured web frontiers](../CAPTURED_WEB.md)
- [Owned page acquisition](../LOCAL_PAGE_CAPTURE.md)
- [Governed page acquisition decision](0052-owned-loopback-html-acquisition.md)
