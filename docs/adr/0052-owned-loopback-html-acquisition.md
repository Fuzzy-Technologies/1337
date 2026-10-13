# ADR 0052: Owned loopback HTML acquisition

- Status: Proposed
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #59, #53, #58

## Context

NativeHTTP version 1 intentionally retains only an endpoint, literal peer, port,
scheme and response status. Its discard-only header/body contract remains useful
and must not change. ADR 0050 provides an independently reviewed lexical HTML
frontier consumer, but its source/capture association is supplied by the caller.
An owned localhost acquisition can connect those existing boundaries without a
browser or arbitrary target scan.

The EvidenceStore accepts authorized non-secret bytes. An arbitrary web response
cannot meet that condition merely because its destination is localhost or its
bytes have a hash. This slice must therefore admit only a closed reviewed
non-secret synthetic HTML fixture with an exact predeclared size and SHA-256.
Unexpected response bodies and arbitrary header values are never persisted.

## Proposed decision

Add a separate Experimental version-1 `native.loopback-page` adapter and job
provider, with SAFE capability `http.synthetic-page-capture`. One plan sends one
anonymous GET to one exact supplied structural request. Only plain HTTP and the
literal addresses `127.0.0.1` or `::1` qualify. There is no DNS, TLS bypass,
redirect, retry, authentication, browser, link traversal or additional request.
Localhost and the expected body hash grant no authority and prove no ownership.
An explicit fixture ID selects the reviewed catalog entry; unknown IDs and
arbitrary digest/size declarations reject before any network operation.

Use the existing PolicyEngine and GovernedLocalExecutor. Both the exact URL and
literal IP must be registered and allowed under current explicit consent; the
distinct capability requires an explicit ImpactPolicy permission. Current scope
is read before grant issuance and again at final governed launch. The packaged
worker sends only the prepared request and verifies the connected literal peer.
Calling an internal worker directly establishes no consent or authorization.

Admit a complete bounded HTTP/1.0 or HTTP/1.1 status-200 response with one canonical
Content-Length and UTF-8 `text/html`. Transfer-Encoding and Content-Encoding are
unsupported. Read exactly the declared body and require EOF within one monotonic
deadline. Only after size, SHA-256 and UTF-8 checks succeed may the worker write a
strict bounded record containing that known body. Unsupported, mismatched,
oversized, truncated or timed-out content yields only a fixed failure code.

Discard all raw response headers and reason text. Retain only the exact observed
HTTP version/status, normalized media/declared charset, content length and measured
header byte/field counts. Unknown header values, including cookies, authorization
and Location, do not enter stdout, stderr, evidence, model attributes or events.
The SHA allowlist binds the closed reviewed fixture byte sequence. It is not
general secret detection, a signature, collector authentication or a consent
record; source/URL metadata must still be non-secret caller attribution.

The parent independently validates the exact invocation, terminal execution and
closed output grammar before evidence admission. Reuse the owning evidence
manifests, bounded actual-reference Get/Read verification and job attachments.
Store the admitted stdout record and its exact decoded response body, then call
the accepted ADR-0050 consumer with the same prepared source request. That consumer
continues to describe lexical anchors, not a rendered DOM or actual traversal.

Persist the source request and its attributable observed response together with
the eligible lexical request patches in one existing ModelState.Apply/Save.
Compose every existing source/candidate template collection, preserve unrelated
attributes and history, and publish the existing ModelDelta only after Save.
Do not create Host/Port/Service, connectivity relations, findings or reachability
claims. Link candidates are never described as fetched or checked endpoints.
A pre-Save failure leaves the prior model unchanged. After Save commits, later
cancellation, event failure or a lost acknowledgement can leave model/evidence
persisted without a delivered delta; report actual known/ambiguous state and do
not claim rollback or cross-store atomicity. Actual worker success remains distinct
from the later owning job outcome. Post-capture interpretation must use the same
exact pinned ScopeSnapshot/ToDict and revision used at launch. Verify the launch
policy digest and frontier digest with their respective existing serializers;
valid Unicode consent metadata can yield unequal strings for the same snapshot.
Retain both with explicit owner roles; do not change either serializer or impose
an ASCII-only metadata restriction. After all evidence/model I/O and composition,
recheck the full snapshot/revision, both respective digests, exact source-URL/
literal-IP membership and fresh consent/expiry immediately before owner Save; a changed, revoked or
expired scope fails at that boundary. This is bounded
snapshot checking, not continuous revocation or a cross-store atomic transaction.

The exact API, HTTP grammar, quotas, privacy/failure rules, model attribution and
handwritten HTTP/HTML oracle are in [Owned loopback page capture](../LOCAL_PAGE_CAPTURE.md).
Implementation requires accepted integration of the reviewed ADR-0050 consumer;
it does not copy or modify that source, NativeHTTP version 1 or owner schemas.

## Validation and remaining work

Unit/contract tests must exercise closed typed inputs, framing and wire output,
duplicate/nonfinite JSON, complete body/hash admission, copied nested records and
all byte/time limits. Pytest owns a bounded localhost server/listener and cleanup.
Integration uses actual policy, executor, packaged worker, job, evidence Get/Read,
frontier, request composition and model save/reopen/event interfaces. The hand
oracle specifies ten lexical anchors, three unique eligible candidates and zero
extra network requests. Independent failure probes must prove that unexpected
synthetic secret markers do not leak through any retained channel.

Scope revocation between grant/launch, post-acquisition scope changes, EOF/slow
responses, output overflow, cancellation/reaping, corrupt evidence, optimistic
model conflicts, existing template preservation and exact replay remain explicit
acceptance cases. Include unchanged Unicode consent metadata whose two valid owner
digests differ, and changed snapshot/revision variants; string equality across
different serializers is never the acceptance oracle. Canonical locked gates, strict per-module branch coverage,
documentation/inventory audits and independent source review are required.

Tasks #59 and #53 remain open. This is a useful one-page synthetic acquisition
and lexical projection workflow, not an arbitrary-body collector, autonomous
crawler, browser runtime, authenticated journey or native vulnerability check.
Concurrent/frontier traversal, external targets, HTTPS page capture, arbitrary
response-body privacy policies, browser rendering and safe-check acceptance need
separate decisions and actual evidence.

## References

- [Native HTTP discovery](../NATIVE_DISCOVERY.md)
- [Evidence](../EVIDENCE.md)
- [Structural requests](../REQUESTS.md)
- [Policy](../POLICY.md)
- [Captured HTML decision](0050-verified-captured-html-frontiers.md)
