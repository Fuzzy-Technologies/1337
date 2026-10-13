# Bounded owned-page traversal

Experimental `fuzzy1337.web_traversal.LocalWebTraversalProvider` executes actual
asynchronous traversal of an explicitly selected repository-owned page subset.
It composes existing `LocalPageCaptureProvider`, `ScanJob`, policy, governed local
executor, immutable evidence and canonical Security Object Model owners. It adds
no browser, alternate transport, persistent queue or implicit scope permission.

The caller selects a concrete anonymous seed GET and an exact tuple of at most
sixteen `OwnedTraversalPage` records. Each record pairs its existing
`RequestTemplate` with a `KnownSyntheticHtmlBody` closed catalog ID. Sources must
be distinct literal-loopback HTTP URLs in the same origin and workspace. The seed
must match an explicitly selected source. Every URL and literal IP still needs
current persisted consent and the separate `http.synthetic-page-capture` SAFE
permission; selecting known bytes grants neither. Scope is independently reread
at every grant/launch and immediately before each canonical Save.

| Reviewed body ID            | Exact bytes | Purpose                                |
| --------------------------- | ----------- | -------------------------------------- |
| `owned-loopback-html.v1`    | 541         | Existing one-page acquisition contract |
| `owned-traversal-index.v1`  | 220         | Branches, duplicate and excluded links |
| `owned-traversal-alpha.v1`  | 81          | Shared leaf and seed cycle             |
| `owned-traversal-beta.v1`   | 55          | Duplicate shared leaf                  |
| `owned-traversal-shared.v1` | 65          | Leaf without executable content        |

The exact source bodies and handwritten oracle are in
`tests/contract/fixtures/web-traversal.*.v1.html` and
`web-traversal.oracle.v1.json`. Admission compares exact original size and SHA-256
before response body publication. Unexpected body/header values are discarded,
including sensitive transient markers, using the unchanged worker's fixed grammar.

Traversal uses breadth/depth then lexical URL order and suppresses repeated URLs,
shared leaves and cycles. It launches only verified discovered candidates present
in the explicit selection. It counts allowed unselected candidates without
fetching them. The lexical parser retains scope exclusion/off-origin counters
within each attributable capture/frontier. No selected-but-undiscovered URL is
fetched. All redirects remain refused; Location is neither retained nor followed.
Each refused redirect retains the existing fixed failed stdout record and starts
zero destination acquisitions.

| Limit                    | Default | Accepted range | Meaning                          |
| ------------------------ | ------- | -------------- | -------------------------------- |
| `max_pages`              | 16      | 1..16          | Reserved selected requests       |
| `max_depth`              | 4       | 0..4           | Seed depth is zero               |
| `concurrency`            | 2       | 1..4           | Concurrent workers in one wave   |
| `max_total_body_bytes`   | 65536   | 1..1048576     | Sum of selected catalog bodies   |
| `start_interval_seconds` | 0.05    | 0.05..1        | Minimum controller start gap     |
| `timeout_seconds`        | 30      | 0.05..60       | Entire traversal including waits |

Booleans, numeric coercion and nonfinite values refuse. Existing body, header,
stdout, stderr and request/process deadlines independently remain enforced.
Aggregate bytes bound admitted bodies, not socket overhead or total immutable
stdout storage. Whole-wave quotas are reserved before dispatch. Omitted reachable
selected work or a truncated lexical frontier fails explicitly with OUTPUT_LIMIT;
a later timeout/cancellation retains earlier acknowledged pages and actual raw
acquisitions.

Actual acquisition overlaps, while an ordered commit gate serializes model
Open/composition, fresh final authority, expected-revision Save and MODEL_DELTA in
sorted URL order. No asynchronous wait occurs between composition/final authority
and Save. CAS conflicts, lost acknowledgements and post-Save event failures keep
the existing truthful page-owner failure semantics. Inspect the reopened model
and evidence after any failure: a terminal failure alone never proves rollback.
`CompletedUrls` records acknowledged page Save/event transitions; it does not
claim that an ambiguous Save or a failed event left the model unchanged.

Traversal progress starts at zero with unknown total, increases only after
acknowledged commits, and declares its actual final total after selected reachable
frontier exhaustion. Cancellation/error drains all owned tasks, commit waiters
and worker processes before job terminal state. The provider is single-use;
another run requires a fresh provider and ordinary new job authorization.

Focused reproducible acceptance:

```bash
uv run --locked --extra dev pytest tests/unit/test_web_traversal.py tests/integration/test_web_traversal_execution.py -n 2 --no-cov
```

This completes one actual async traversal slice of #59/#53. Browser rendering,
authenticated sessions, arbitrary page bodies, remote targets, redirect following,
unrestricted crawler discovery and native vulnerability checks remain separate.
