# ADR 0090: Owned offline browser page rendering

- Status: Accepted for implementation; integration requires ADR 0091 acceptance
- Date: 2026-10-23
- Related work: #59, #53, #155

## Context

The existing synthetic page provider performs one governed literal-loopback GET,
verifies framing, complete EOF, media and an explicit reviewed body digest, then
projects original evidence and a bounded lexical frontier through shared owners.
An optional browser backend can additionally measure the DOM produced from that
same verified non-secret body. This is offline rendering, not browser HTTP
navigation, JavaScript execution, authenticated journeys or a general crawler.

## Proposed bounded profile

Add a finite explicit `playwright-chromium-offline.v1` selection with separate
SAFE capability `http.synthetic-page-browser`. Existing native acquisition
defaults, argv, report grammar and permission behavior remain unchanged.
Select capabilities by identity rather than descriptor position. Do not admit
caller-supplied browser paths, flags, environment overrides, sessions or content.
The initial renderer is explicitly Linux-only and uses the verified opt-in
descendant ownership from ADR 0091. Refuse other platforms before acquisition
or browser launch; the existing native backend remains portable.

Reuse the unchanged `page_capture_worker.Probe` before importing or launching
the renderer. Only its fully verified closed catalog body reaches Playwright.
The optional dependency is pinned to Playwright 1.64.1 and its Chromium
156.0.8078.4; normal package startup must not require the optional dependency.

Render the known body using `set_content` on `about:blank`, with offline context,
page JavaScript disabled, service workers blocked and downloads refused. Abort
every request route, close WebSocket routes and refuse unexpected pages. No
navigation, interaction, caller expression or payload is supplied. Fixed DOM
queries retain only bounded counts, serialized-DOM size/digest, input-body digest,
blocked-request count and actual engine versions. Do not retain arbitrary DOM
text or infer Findings from a successful render.

The renderer has one shared six-second monotonic budget, including startup and
operations. The governed process budget is request time plus seven seconds;
the provider rejects an insufficient total budget. A renderer failure remains
unassessed and cannot create a completed page, frontier or canonical model
transition. Existing authority rechecks, original report/body custody and model
Save owners remain mandatory. Browser reports use a separate closed grammar
binding the exact selected profile, engine pins and native input digest.

The explicit `BrowserPageCaptureLimits` type retains the three familiar fields
with defaults of 16384 body bytes, two request seconds and eighteen provider
seconds. Its provider ceiling is thirty seconds. The browser profile requires
at least three helper-readiness seconds, `ceil(request + 7)` worker seconds,
three owner-cleanup seconds and one custody/Save second: sixteen seconds at the
default request budget. Its job deadline must exceed the selected provider
deadline by at least one second; the genuine fixture uses twenty job seconds.
Native `PageCaptureLimits` defaults and its fifteen-second ceiling remain exact.
The selected renderer and its limit type must match before any acquisition.

## Blocking process-ownership finding

The pinned Playwright launcher creates a separate Chromium process group on
POSIX. Its Node driver handles termination with graceful browser cleanup;
driver pipe closure has a thirty-second fallback. The existing local executor
owns and observes its direct Python worker and original POSIX process group.
Windows termination observes the direct subprocess. These existing guarantees
do not establish that a detached browser group or Node driver has exited before
a cancelled or timed-out browser operation returns.

A Python `finally` block is insufficient when the governed worker is forcibly
terminated. The implementation must first define and verify a bounded owner for
all launched browser descendants, including forced termination and process
identity/reuse handling, on each supported platform. Do not widen the shared
executor or rely on unverified driver cleanup as an incidental part of adding
the renderer. Until this prerequisite is implemented and independently accepted,
do not advertise the capability or treat the browser backend as implemented.
ADR 0091 defines that prerequisite as a separate explicit Linux-only executor
extension with bounded subreaper cleanup and a private verified receipt.
Accepting that implementation is required before this renderer can integrate;
Windows Job Objects and other platform ownership remain separate work.
An isolated implementation branch may compose the reviewed ADR 0091 candidate
while its required Linux acceptance is pending. Do not mark the browser PR ready
for integration until the owner prerequisite is accepted in `develop` and the
browser's own genuine required acceptance is ready to execute.

## Required actual acceptance

The independently handwritten `owned-browser-dom.v1` body has 423 bytes and
SHA-256 `75d60b34385f3c65068edcde7a37da78db796290b95be0ab9beb2cdc03fe3e71`.
Its known image URL is handled by an owned fixed-port sink. Actual acceptance
must observe one verified native GET, one blocked browser request, zero sink
contacts, unchanged expected DOM digest and no executed-script marker. Preserve
actual versions, original streams/body, canonical projection and durable reopen.

Cancellation and timeout acceptance must track only test-owned descendants and
prove bounded Node/Chromium cleanup. Unit fakes may validate deterministic
failure/refusal paths but cannot establish browser execution or cleanup.
The local official Chromium installation failed with an invalid archive; no
usable engine or real-browser acceptance exists from that attempt. A genuine
opt-in CI job must install and run the pinned browser, fail when unavailable,
and pass before integration. Skipping or substituting a fake browser is not
acceptance. No release or publication is part of this decision.
