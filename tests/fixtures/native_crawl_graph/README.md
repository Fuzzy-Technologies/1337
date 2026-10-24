# Independent mutable native crawl graph

This fixture owns its source bytes and handwritten `oracle.v1.json`. It imports no
production parser, scanner, body catalog or descriptive schema example. Source
checks render responses in memory; they establish no worker/product acceptance.

`MutableCrawlGraph(origin)` performs no I/O. `SetVariant` changes the bytes served
at the exact same `/entry` seed while `SelectedUrls()` remains unchanged. The
positive graph has reversed/duplicate seed anchors, two siblings, shared leaves
and cycles. Fixed removes the live seed edges; decoy retains only comment,
script and style links. Redirect discovers one selected redirect source whose
crawl refusal leaves the original seed commit visible.

`OwnedNativeCrawlGraph()` is the sole listener lifecycle. Its target binds only
an ephemeral literal `127.0.0.1` port, has thirteen declared selected URLs and
four maximum handlers. At most sixty-four accepted contacts receive detailed
records or dispatch; later accepts are counted exactly, refused and immediately
closed with explicit contact/error overflow counts. There are no network control
routes, arbitrary response callbacks, outbound requests, file access, proxying
or shell execution.

A second fixture-owned ephemeral `127.0.0.1` listener is the off-origin sentinel.
The positive seed embeds that actual held origin in its decoy href. It is never
selected or admitted by the main thirteen-URL graph. Its fixed 404 response has
only finite terminal bytes and no links, forwarding or control route. The second
origin reuses the same accept-time ledger, request/slot bounds, absolute deadlines
and cleanup owner. Both origins are settled even if the first cleanup fails.
Combined ceilings are eight active handlers, 128 detailed contacts, and six
seconds across the two original three-second cleanup deadlines. Each origin
keeps its own exact accept/overflow/error totals beyond bounded detail retention.

`sentinel_state`, `sentinel_origin` and `sentinel_thread` stay available on the
returned fixture after context cleanup. Genuine acceptance must require zero
original sentinel accepts and zero sentinel overflow/errors after both owned
listeners and every original socket/handler/slot have settled. Main-origin
success or an empty main ledger never proves an off-origin exclusion. Pure
rendering requires an explicit sentinel binding before rendering positive bytes;
it cannot silently substitute an arbitrary unmeasured port.

Every socket is registered and counted directly after accept, before any handler
thread can be created. Admission closure and thread creation share the same
ownership lock. Teardown releases both fixed gates, stops/joins admission, closes
every remaining original socket and joins explicitly owned non-daemon handlers
under one original three-second cleanup deadline. Each accepted socket has its
own original two-second whole-request deadline covering reads, gate waits, sends
and send-side EOF. Progress does not renew either deadline. Cleanup failure
remains an error and unsettled original owners remain visible.

`state.SetVariant` and the attached renderer's `SetVariant` require all original
accepted sockets and original dispatch slots to be settled, including partial or
invalid requests. The original dispatch owner is registered before thread start
and cleared under the admission lock only after its actual semaphore release.
`state.WaitIdle()` waits once on a bounded settlement event and atomically checks
all original socket, running-handler and dispatch owners; it uses no polling.
`state.InvertSiblingCompletion` makes B wait for actual A entry,
then makes A wait for B's complete response and `SHUT_WR`; teardown releases both
waits. No sleeps choose the order. Later genuine acceptance must assert actual
`maximum_active_handlers >= 2` and B-before-A completion records.
`required_before_b_completion` means both sibling handlers entered before B
completed; it does not require A to arrive before B. Actual within-wave network
arrival order remains evidence. Only model commit order is lexical and fixed.

`Observe` begins at acceptance and retains every bounded original request prefix,
received-byte count/truncation flag, admission/failure/closed state, intended
response, actual successful send count and completion sequence. Empty, partial,
invalid, refused and teardown-interrupted contacts stay visible. `Counters`
exposes exact accepted/error totals separately from retained records and overflow;
`Errors` never suppresses mechanism failures just because admission is closing.
A zero-contact assertion must require `Counters()["contacts"] == 0`, zero overflow
and no retained contacts. Empty valid-response output alone proves no such thing.

## Source API handoff

- `graph.Url(path)` accepts only an explicitly declared selected path.
- `graph.SelectedUrls()` returns the entire sorted admitted URL set.
- `state.SetVariant("positive" | "fixed" | "decoy" | "redirect")` changes seed bytes.
- `state.Observe()` returns immutable original accepted-contact records.
- `state.Counters()` exposes exact totals, bounded retention, overflow and measured overlap.
- `state.WaitIdle()` waits for all original socket, handler and dispatch-slot settlement.
- `state.Errors()` returns fixed fixture mechanism failures.
- `state.InvertSiblingCompletion()` activates deterministic sibling overlap.
- `CrawlGraphOracle()` reads independently authored expected truth.

## Deferred genuine acceptance

Source rendering and fake-socket/state tests start no real socket or thread.
The source checkpoint must run no listener, installed worker, SDK, CLI, scanner,
installation or CI. After immutable production handoffs and execution authority,
ordinary pytest runners must require installed package capabilities and fail if
missing. They must not skip required acceptance or replace workers with mocks.
The integration module will be named `test_native_crawl_worker_execution.py`,
which is distinct from the producer unit-test basename.

Worker acceptance must compare live served body hashes, exact original GET bytes,
handwritten ordinals/counters, terminal/refused responses and rejected-marker
absence. SDK acceptance must compare actual contacts, ordered durable model
transitions, complete request collections, original worker evidence and reopened
state. Repeating fixed/decoy runs against the same seed must fetch only that seed.
Fresh owner/consent/scope/policy denial must receive no contact; supplied trusted
owner drift after acquisition must preserve evidence and prevent model Save.

A caller separately selects the discovered Git positive, fixed and HTML-decoy
Targets, plus the redirect Target discovered by the explicitly failed redirect
variant. Each existing `PlanNativeWebScan`/`RunNativeWebScan` retains its own
`web.git-head-check` STANDARD capability permission and exact-plan confirmation.
The Git check does not gain a redirect follow-up. Score persisted Findings as
TP1/TN3 only after actual completed jobs; failed/unexecuted work stays unassessed.
Verify operator triage survives a rerun and durable workspace reopen, preserve
actual stdout/stderr/invocation and emit capability metadata from the consumer.
The checker uses legacy exact-URL Endpoint identity; crawl uses structural JSON
keys. This fixture authorizes no migration or silent join between those owners.

CLI execution requires the coordinator's real enrolled command and installed
package. Its output must expose truthful failed/refused work and reopenable
state. Until these runners execute, there is no scanner completion claim.
