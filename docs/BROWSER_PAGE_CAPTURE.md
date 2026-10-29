# Owned offline browser page capture

[ADR 0090](adr/0090-owned-offline-browser-page-rendering.md) defines the explicit
Experimental `playwright-chromium-offline.v1` page renderer. It composes the
[owned loopback acquisition](LOCAL_PAGE_CAPTURE.md) with the accepted Linux
descendant owner from [ADR 0091](adr/0091-opt-in-linux-descendant-process-ownership.md).
Integration requires genuine pinned-engine acceptance; optional skips and mocked
browser objects do not establish that acceptance.

## Explicit selection and authority

Construct `LocalPageCaptureProvider` with
`renderer=PageRenderer.PLAYWRIGHT_OFFLINE` and an explicit
`BrowserPageCaptureLimits()` value. The same renderer keyword selects the
corresponding `NativeLoopbackPageAdapter` descriptor. `PageRenderer.NATIVE` remains
the default and requires the existing `PageCaptureLimits` type. Mixing a renderer
and the other profile's limit type is rejected before acquisition.

The browser capability is `http.synthetic-page-browser`, at SAFE impact, under
the existing `native.loopback-page` provider identity and source version `1`.
An explicit permission for this capability is required. A native page or native
HTTP permission supplies no browser authority. Both the exact source URL and its
literal loopback IP must remain registered and allowed under current consent.
Discovered lexical links grant no fetch authority.

The optional package extra is `browser`, with Playwright pinned to `1.64.1` and
its Chromium pinned to `156.0.8078.4`. A trusted deployment provisions the matching
engine separately. Package startup and the native renderer do not import or
require that dependency. Callers cannot supply browser paths, launch flags,
environment overlays, profiles, sessions or arbitrary page content.

Linux ownership primitives are required before the first acquisition. The
governed worker uses `own_descendants=True`; current launch authority is checked
after helper readiness immediately before its private start acknowledgement.
The browser provider also validates its original grant and fresh source scope
immediately before the existing canonical model Save.

## Acquisition and rendering

The isolated installed `fuzzy1337.browser_page_worker` receives the same four
canonical URL/request-timeout/fixture/body-limit tokens as the native worker.
It calls the unchanged native `Probe` exactly once. Complete framing, final EOF,
media, UTF-8 and the selected closed body digest are verified before optional
browser imports or renderer launch. There is no browser HTTP navigation.

Only admitted non-secret bytes reach `set_content` on one `about:blank` page.
The fixed context is offline, with page JavaScript disabled, service workers
blocked and downloads refused. Every HTTP route is aborted, WebSocket routes
are closed and unexpected pages or downloads fail the profile. Fixed DOM queries
measure element, anchor, form and input counts. The serialized DOM supplies only
its bounded byte length and SHA-256; arbitrary DOM text is not retained.

The reviewed `owned-browser-dom.v1` catalog body is exactly 423 bytes, with SHA-256
`75d60b34385f3c65068edcde7a37da78db796290b95be0ab9beb2cdc03fe3e71`.
Its independent oracle expects 11 elements, one anchor, one form, one input,
the unchanged DOM digest, one blocked resource attempt and zero contacts to the
owned resource sink. Its inert script would change that digest if executed.

## Bounds and result truth

`BrowserPageCaptureLimits` has the same three fields as native limits. Defaults
are 16384 body bytes, a two-second request deadline and an eighteen-second provider
deadline. The provider ceiling is thirty seconds. It requires at least
`3 + ceil(request_timeout_seconds + 7) + 3 + 1` seconds for helper readiness,
worker execution, verified cleanup and custody/Save. The owning job deadline must
exceed the selected provider deadline by at least one second; the genuine fixture
uses twenty seconds. Native defaults and its fifteen-second ceiling remain exact.

All renderer startup, operations and normal closure share one six-second monotonic
budget. Limits admit at most 262144 serialized DOM bytes, 8192 elements and 64
blocked browser request attempts. These are provider work bounds, not an OS
network, memory or same-UID sandbox.

The separate flat browser grammar binds the exact profile, admitted input digest,
actual engine versions, DOM digest/size, four counts and blocked request count.
Successful normalized observations use `http.synthetic-page-browser`; provenance
keeps source version `1` and the actual Chromium version as the tool version.
One successful page creates the existing source response and lexical frontier
through shared evidence/model owners. It creates no Finding or fetched-link claim.

A renderer failure retains an available complete verified native body group and
original stdout, with a fixed failure category. It has no completed page, frontier
or model transition and no successful DOM metrics. Partial report groups, unknown
fields, changed pins and inconsistent original evidence are refused. Timeout or
cancellation cannot complete until the Linux owner has verified descendant cleanup;
unknown cleanup remains an executor failure.

## Genuine acceptance

The required Linux CI job provisions the exact optional dependency and matching
Chromium, then sets `FUZZY1337_RUN_PLAYWRIGHT_ACCEPTANCE=1`. Missing engine or kernel
ownership support fails that required run. The independent production-provider
case verifies the actual owned GET, offline DOM oracle, original custody,
canonical projection and relocated reopen after both listeners close.

Separate finite owned-engine fixtures acknowledge readiness after real Node and
Chromium have created an offline blank page. Cancellation and timeout then prove
that the recorded process identities, including zombies, disappear before the
executor returns. They do not add delays, test hooks or arbitrary content to the
production renderer. No release, tag or publication is part of this profile.
