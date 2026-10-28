# ADR 0103: Bounded native Prometheus exposition observation

- Status: Accepted implementation contract; runtime acceptance remains separately evidenced
- Date: 2026-10-28
- Decision owners: Fuzzy Technologies
- Related work: #40; independent real-application oracle in ADR 0102

## Context

The native web adapter already runs explicit, confirmed STANDARD requests through
current URL/IP scope, policy, governed process, original evidence and model owners.
Its Git and closed file-canary predicates retain only metadata, a body hash and a
boolean. Their fixed Content-Length transport and 4096-byte body limit cannot
observe ordinary Node Prometheus responses that use chunking or connection EOF.

## Decision

Add check `native.prometheus-exposition`, capability
`web.prometheus-exposition-check`, selected by `scan web --check
prometheus-exposition`. Use one exact operator-selected canonical, query-free
literal-IP HTTP(S) URL with existing separate plan/confirmation and current scope.
No DNS, redirect, authentication, session, path enumeration or request expansion
is introduced. HTTPS retains normal certificate validation and TLS 1.2 minimum.

Only this check admits Content-Length, chunked or EOF-delimited identity responses
with a 256 KiB decoded-body bound. Reject Transfer-Encoding plus Content-Length,
duplicate fields, unsupported encodings, chunk extensions/trailers, malformed or
incomplete framing and exhausted limits as unassessed worker failures. Independently
bound headers, wire bytes, chunk count and chunk-size lines. Check the original
shared monotonic deadline before and after every receive and parsing phase,
including final EOF; no read renews it. Close sockets on every path. Existing Git
and canary framing, parameters, record schema/version and 4096-byte cap remain.

The pure predicate requires HTTP 200, normalized `text/plain`, strict UTF-8, a
complete final LF, and whole-line supported legacy Prometheus exposition. Require
at least one same-family HELP and TYPE before its sample, in either metadata order.
Validate every sample and
metadata line, ASCII metric/label names, unique label names and supported escaped
backslash, quote and newline. Counter/gauge/untyped samples use exact family names;
histograms explicitly admit `_bucket`, `_sum`, `_count`, and summaries admit their
base quantiles, `_sum`, `_count`. Values and optional integer timestamps are checked
lexically; NaN and infinities never become nonfinite JSON. Unknown metadata,
OpenMetrics/exemplars, modern quoted UTF-8 names, incomplete documents and trailing
junk are outside this intentionally conservative v1 predicate. This is detection,
not complete Prometheus ingestion validation.

On a match retain one LOW descriptive Finding with existing unknown confidence:
the selected anonymous response exposed supported Prometheus exposition. Do not
claim exploitability or that the deployment intended privacy. Names, labels and
values stay transient; original evidence remains the existing schema-one safe
metadata/hash/boolean. Replay validates those original records, without claiming
to reconstruct or independently rerun the absent response body. The new check has
profile version `1` under its distinct identity; older check records are unchanged.

## Acceptance

Require direct grammar, transport-budget, ambiguity, total-deadline, error and
cleanup tests, old-profile regressions, exact adapter/CLI contracts, and real
installed-worker governed SDK positive and negative local responses. An owned
synthetic target proves this product path, not a Juice Shop scan. Pinned external
target execution and comparative acceptance remain UNRUN until the independent
benchmark can run its actual isolated runtime and preserve genuine evidence.

Primary format reference:
https://prometheus.io/docs/instrumenting/exposition_formats/
