# ADR 0050: Verified captured HTML frontiers

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #59, #53, #58, #153

## Context

The accepted native HTTP version-1 sensor retains only an approved URL, peer,
port, scheme and status. It deliberately discards headers and bodies and cannot
produce a transport-derived crawler frontier. Requests and journeys already
have structural identities, scope preparation and separate runtime ownership.
The next useful web-engine slice can interpret explicitly supplied static HTML
without adding a second acquisition path or claiming browser execution.

## Decision

Add Experimental `fuzzy1337.captured_web`, frontier profile version 1, in new
source paths. Read one explicit non-secret UTF-8 `text/html` evidence artifact
through the existing workspace/evidence owners. Bind it to a supplied anonymous,
concrete GET `RequestTemplate`. This source/capture association is a caller
declaration: the manifest has no transport URL field and a digest authenticates
neither the collector nor the asserted acquisition. No HTTP-response completeness,
browser visibility, physical endpoint reachability or sensor success is inferred.

Extract only lexical `<a href>` start tags. An owned bounded scanner controls
token admission and script/style raw text; a fresh/reset standard-library parser
interprets one admitted markup token's attributes at a time. Standard-library
HTML callbacks are an attribute interpretation mechanism, not a rendered DOM.
Script/style content
and comments do not contribute anchors; an anchor in an inactive template can
still be a lexical candidate. Reject any parsed `base` tag, duplicate attributes,
unsupported declarations, unclosed markup token or resource overflow. This
bounded static-markup subset does not claim universal HTML or browser parsing.
Do not retain text, script content, arbitrary attributes or original href values
in normalized results or diagnostics.

Canonicalize processed hrefs using the exact declared URI-resolution profile,
existing `Target`, and existing structural `Endpoint`/`RequestTemplate`. Only
query-free, same-origin concrete GET candidates qualify. Remove nonempty link
fragments without retaining their values; count fragment-only references instead
of requeueing the source. Credentials, unsupported protocols, queries, ambiguous
addressing, unsupported paths and other origins are count-only exclusions.
Structural names and paths necessarily preserve source text; callers must keep
the evidence and metadata non-secret. These exclusions are not a secret detector.

Open current persisted scope once, bind workspace/scope/source membership and
check every qualifying exact URL at the explicit aware decision time. Discovery
never registers a target, rewrites consent or expands an allow rule. Retain the
complete scope digest, revision, time and each decision. This is one-read
membership evidence, not an invocation grant or continuous freshness guarantee.

Full bounded lexical admission precedes bounded anchor work, so an unvisited
suffix cannot hide a base tag that changes earlier relative resolution. Return a
deterministic deduplicated frontier with retained source provenance, manifest,
request/target identities, source ordinals, fixed exclusion counts and explicit
work/candidate truncation. `complete` means complete for this artifact and profile
only. It never means the web application was crawled or has no other endpoints.

Provide a pure projection into existing structural request objects and attributed
`web.lexical-link` observations. Compose complete existing request collections
rather than replacing unrelated templates. The original collector provenance,
manifest identity, source target and parser profile remain traceable. Reuse owning
`ProjectRequests`, `ModelState.Apply`, `LocalModelStore` and `ModelDelta`; create no
new schema enum, model/evidence store, queue database, job, CLI or launch path.

The exact profile, API shape, limits, failure categories, projection attribution
and handwritten source/oracle are defined in [Captured web frontiers](../CAPTURED_WEB.md).
The immutable design/oracle checkpoint was independently reviewed before behavior
implementation. The documented bounded profile is accepted for implementation.

## Validation and remaining work

Use an independently written static HTML fixture and expected URL/ordinal/count
oracle. Exercise the actual workspace, evidence Get/Read, current scope, request
projection, model save/reopen and exact replay boundaries. Verify corrupt/missing
and oversized actual artifacts before allocating owner reads, copied wrappers,
source/provenance/time mismatches, unsafe links, malformed markup, every limit,
scope changes, deterministic ordering and I/O tripwires.

No live target, browser, external download or secret/session input is needed.
Canonical locked checks, per-module branch coverage, source/API/locale audits and
independent source review apply to implementation. #59 and #53 remain open for
async governed acquisition, real traversal, browser execution, runtime cancellation,
transport/body capture and native safe-check acceptance against synthetic targets.

## References

- [Structural requests](../REQUESTS.md)
- [Synthetic journeys](../JOURNEYS.md)
- [Native HTTP discovery](../NATIVE_DISCOVERY.md)
- [Evidence](../EVIDENCE.md)
- [Scope](../SCOPE.md)
- [Security Object Model](../SECURITY_MODEL.md)
- [Python HTMLParser](https://docs.python.org/3.12/library/html.parser.html)
