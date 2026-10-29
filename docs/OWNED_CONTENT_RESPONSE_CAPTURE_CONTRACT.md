# Bounded owned content-response capture contract

## Status and identities

**Experimental SDK implemented; bounded installed acceptance verified.** This
profile extends the first-party source acquisition boundary reviewed at `fd2b7838`,
not its target scope or any external engine. Eight installed SDK scenarios cover
positive/negative header assessment, body-decoy handling, denied policy, changed
actor, missing analysis approval, stale model revision and post-model-ACK expiry.
One separate installed IPv6 scenario verifies the worker boundary only. Final
shared integration is required before merge; this profile has no CLI enrollment.
The old [closed catalog contract](OWNED_RESPONSE_CAPTURE_CONTRACT.md), worker,
parser, schema, catalog bytes/hash, defaults and historical replay remain unchanged.
An original body is never inferred from a crawl digest or a matching fixture name.

| Binding                      | New fixed value                                         |
| ---------------------------- | ------------------------------------------------------- |
| Provider/version             | `native.loopback-content-response` / `1`                |
| SAFE capability              | `http.owned-content-response-capture`                   |
| Worker record                | `owned-content-response-capture.v1`, schema integer `1` |
| Receipt                      | `owned-content-response-receipt.v1`, schema integer `1` |
| Source Observation           | `owned-content-response-source`                         |
| Explicit retention selection | `retain_response=True`; default false                   |

The existing `native.loopback-response` / `http.synthetic-response-capture` grant
does not authorize this profile. Neither acquisition capability authorizes the
separate PASSIVE header assessment. Acquisition creates no Finding, security
severity, automatic check grant, browser state or ZAP assertion.

## One exact request, before normalization

Check the caller's original URL before constructing `Target`. It must equal its
existing `scope.NormalizeUrl` / `Target(URL, value)` canonical value and satisfy:

- ASCII URL, at most 2048 bytes; exactly anonymous `http://127.0.0.1:<port><path>`
  or `http://[::1]:<port><path>`. Port is explicit canonical decimal 1024..65535.
- Path is explicit `/`, or `/`-separated concrete unreserved ASCII segments
  `[A-Za-z0-9._~-]+`, with an optional final slash, at most 1024 bytes/64 segments
  as counted by `requests.Endpoint`, including an empty final segment.
  Reject `.`/`..` segments, `//`, percent escapes, backslashes and path variables.
- Reject every `?` or `#`, including an empty query/fragment, user information,
  alternate host/IPv6 spelling, zone IDs, DNS, HTTPS and default/leading-zero ports.

This is an intentional subset of actual `scope.NormalizeUrl` and
`requests.Endpoint`, following `adapters.native_crawl.CrawlEndpoint`'s raw-equality
check. The core can normalize some escapes and queries; this profile refuses them
to avoid retaining inline values or transforming selected request identity. It
does not change the core URL policy. No path catalog or body expectation exists.

Use one literal AF_INET/AF_INET6 socket. Verify actual peer address and port equal
selection before sending; no resolution, proxy, retry, redirect or follow-up.
The complete ASCII request is exactly this template, without a body; `\r\n`
denotes actual CR/LF bytes. Preserve the actual sent bytes, not a synthetic log:

```text
GET <path> HTTP/1.1\r\n
Host: <authority>\r\n
Connection: close\r\n
Accept: text/html, text/plain\r\n
Accept-Encoding: identity\r\n
User-Agent: 1337-owned-content-response/1\r\n
\r\n
```

No caller headers, cookies, credentials, session references or payload generation
are accepted. The selected URL/IP must already be registered and allowed by the
current source scope; discovery or earlier acquisition cannot enroll them.

## Response admission and finite bytes

This is a deliberately narrower project profile than HTTP in general. Framing
decisions follow [RFC9112 sections 6.2/6.3/8](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3);
media parameters follow [RFC9110 section 8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3).
Unsupported valid HTTP remains unassessed, not a malformed-server Finding.

| Part or bound                              | Inclusive ceiling / exact rule                                |
| ------------------------------------------ | ------------------------------------------------------------- |
| Request bytes                              | 2048                                                          |
| Header section                             | 16384 bytes, including status and final CRLFCRLF              |
| Header fields / line                       | 64 fields; each status/field line including CRLF <=4096 bytes |
| Body / wire                                | 65536 / 81920 bytes; body may be empty                        |
| Worker stdout / actual stderr              | 131072 bytes / exactly zero bytes                             |
| Receipt / admitted stage / publication log | 2097152 / 3145728 / 131072 bytes                              |
| Published payload / success roles          | <=3145728 bytes / exactly seven                               |
| Shared socket deadline                     | 5 monotonic seconds for connect/send/read/actual EOF          |

Require exactly `HTTP/1.1 200 OK\r\n`; do not skip informational messages.
The header section has one final CRLFCRLF, no bare CR/LF, folding or whitespace
before a colon. Names are nonempty HTTP token names; values contain only HTAB
or ASCII 32..126. Reject duplicate names case-insensitively, including otherwise
combinable fields. Original order, case, spaces and all accepted bytes are retained.

Require one Content-Length: after trimming surrounding SP/HTAB, its value is `0`
or canonical nonzero decimal without signs, leading zeros, commas or overflow,
and <=65536. Require one Connection whose trimmed value is case-insensitive `close`.
Require one Content-Type: case-insensitive `text/html` or `text/plain`, optionally
followed by exactly one unquoted `charset=utf-8` parameter; allow SP/HTAB around
the semicolon and before the value's end. No other parameters or media sniffing.
Require the complete body to decode as strict UTF-8 without normalization; persist
its original bytes, including any valid BOM. HTML is neither parsed nor executed.

Reject any Transfer-Encoding, Content-Encoding (even identity), Trailer, TE,
Upgrade, Location, Set-Cookie, Set-Cookie2, Cookie, Authorization,
Proxy-Authorization, WWW-Authenticate or Proxy-Authenticate field. Other bounded
valid names/values are admitted, including changing Date/Server/ETag/custom fields
and present, empty or differently cased X-Content-Type-Options. Field presence
is not interpreted during capture. These exclusions do not detect arbitrary
secrets in other fields/body; the operator must select owned non-secret material.

Read exactly the declared body and require actual EOF within the same deadline;
probe for an extra byte under the remaining bound, including at maximum length.
Early EOF, trailing bytes, another response, a held-open connection, compression,
chunking, redirects, non-200 statuses or unsupported media refuse admission.
Do not renew the timer on progress. An expiry after a read still refuses its result.
Rejected bytes stay transient: no stdout, diagnostic, retained hash, private stage,
model attribute or evidence publication contains them.

## Worker record and original custody

The new packaged stdlib worker takes one canonical URL, with no flags/config files:

```text
<absolute-selected-python> -I -B -m fuzzy1337.owned_content_response_worker <url>
```

After complete admission only, emit one canonical `SerializeContract` ASCII JSON
record, without BOM/newline; stderr stays empty. Success exit 0 has exactly
`schema_version`, `profile`, `outcome`, `url`, `address`, `port`, `media_type`,
`request`, `response_headers`, `response_body`, `response`. Outcome is `captured`;
media_type is normalized `text/html` or `text/plain`. Each of the three byte parts
has exactly canonical padded `base64`, integer `size_bytes` and lowercase SHA-256.
`response` has only size/hash of original headers immediately followed by body.
There is no `case_id`, catalog hash, expected header result or repeated wire base64.

Expected refusal exit 2 has only schema/profile, `outcome="refused"` and one code:
`input`, `connection`, `timeout`, `protocol`, `response-policy` or `body-policy`.
Invalid UTF-8 is body-policy; header/status/media exclusions are response-policy;
incomplete/ambiguous framing is protocol. No rejected values or content hashes appear.
Unexpected exit/output cannot be promoted to a valid worker refusal or success.

The independent pure parent parser checks strict canonical JSON, unique keys,
exact types (no booleans as integers, floats or non-finite values), sizes, base64,
digests, URL/peer/request association and the entire admission grammar again.
Bound decoded JSON to depth 8/128 nodes before canonical rendering; do not require
a nonempty base64 string for an admitted zero-byte body.
It is content-driven: no production lookup matches response/body against examples.
The 131072 stdout cap accommodates base64 of <=83968 original part bytes plus
bounded metadata; the old 8192-byte cap is never raised for catalog capture.

Keep these original roles and publication order, with profile-specific read caps:

| Role                   | Media type               | Maximum bytes |
| ---------------------- | ------------------------ | ------------- |
| stdout                 | application/json         | 131072        |
| stderr                 | application/octet-stream | 0             |
| owned-response-request | application/octet-stream | 2048          |
| owned-response-headers | application/octet-stream | 16384         |
| owned-response-body    | application/octet-stream | 65536         |
| owned-response-wire    | application/octet-stream | 81920         |
| owned-response-receipt | application/json         | 2097152       |

Wire equals actual original headers+body; its raw bytes are retained once as that
role. Body media stays octet-stream so no decoded substitute claims original custody.
Every original record has the same actual new-provider execution/workspace/scope
provenance. The receipt uses the existing closed receipt key set and original
request/result/event/ID associations, with the new receipt profile and bindings.
Preserve original stdout/stderr and each executor event exactly; never synthesize
or rechunk a LocalExecutionResult to carry parent metadata. Bound original events
to 8195 and the exact receipt/stage/aggregate limits before the first publication.

Stage admitted originals and candidate manifests, then use existing CaptureEvidence,
intent/ack journal, Get/Read and original Snapshot associations. Candidate IDs or
equal blobs are not original Put/attachment acknowledgements. Require complete
original part acknowledgements before publishing the receipt. On a partial write,
retain admitted stage and actual stored/attached/acknowledged sets separately;
never re-Put, reacquire, repair a journal or attach after terminal to make success.
Keep stage retained in this first profile even after success; no cleanup API is added.

## Authority, process ownership and one persistence attempt

Use existing PolicyEngine/PolicyContext/PolicyGrant, GovernedLocalExecutor, Jobs,
Scope, Target, Evidence, Model and workspace CAS. Do not add an authority store.
Run needs both exact booleans `approve_safe_content_response_capture=True` and
`retain_response=True`, independently of a current typed SAFE permission. Missing
either refuses before grant/private acquisition. Retention selection covers
actual original headers/body/wire and their canonical evidence; it is no privacy
certification. Bind `{"url": url, "retain_response": true}` as the entire
AdapterRequest.parameters; no credentials or extra knobs. Descriptor, Spec provider,
invocation version, capability and all provenance use the new acquisition identity.
Capability requirements and actual authorization privileges are empty; source
retention does not introduce another privilege or credential channel.

Before grant, actual launch and each Save, refresh complete current URL+literal-IP
scope/consent, policy and selected owner; exclusion/deny and exclusive expiry win.
Keep the original grant/deadline and immutable intent; never renew it in an attempt.
Optional trusted current_owner_provider must equal the selected executing actor;
default attribution alone cannot detect external principal changes. The independent
scope attester is not that actor. Current approval/retention selections and the
whole actual immutable request must still match the original local authority.

Reuse the reviewed Linux-only private directory, installed interpreter, exact
nine-key effective environment and physical identity checks of the old parent.
New invocation timeout is 10; ExecutionResources is `(131072, 1, 0.5)` and actual
stderr must be empty. No shell, PATH lookup, editable/PYTHONPATH fallback, arbitrary
executable/flags, descendant opt-in or external engine. Unsupported hosts refuse
before launch. The fixed worker starts no child and writes no file.

Keep one provider monotonic origin: 28 seconds inside JobSpec timeout exactly 30,
max_events 32. Existing cumulative phase ceilings remain 2 prepare +16 execution
(startup 2, invocation 10, cleanup 4) +8 custody +2 final authority/persistence.
No deadline resets at a helper, read, Save or callback. Slow blocking I/O is checked
after return, not claimed forcibly preempted. Event sinks receive safe job events,
not response bytes, paths, body hashes of refused work or raw executor fragments.

Pin and shield the one original governed Execute task; signal its own cooperative
cancellation event and settle it through repeated caller cancellation. Do not
cancel/replace that task to recover a result: LocalExecutor may clean then reraise
CancelledError. A terminal self-cancelled task remains unknown/error, never a busy
loop or invented result. SDK cleanup likewise owns one shielded CancelAndWait task,
retains first-failure precedence and awaits confirmed original cleanup before return.

Finish custody/composition/basis reads before final fresh grant/scope/policy/actor
validation; leave no I/O, await or caller clock callback after that final authority
boundary before Save, then perform a pure cancellation check. Revalidate after each
Save without claiming atomic protection against mutually mutating trusted readers.
Use the original model CAS once and at most one shared workspace attempt across
success/finally; preserve concurrent triage/unrelated state, with no rebase/retry.
Report acknowledged, observed-committed, observed-unchanged or unconfirmed stores
independently. Observe late/lost ACK state without rollback or manufactured ACK.
If authority denies failure retention, retain actual stage/snapshot facts without Save.
ModelChanged occurs only after both required acknowledgements while the job is active.

| State               | Necessary invariant and permitted result                                                                                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Captured complete   | Actual exit 0, timely admitted record, empty stderr, confirmed cleanup and seven original acknowledgements; source success also needs guarded model/workspace acknowledgements                       |
| Worker refused      | Actual exit 2 plus canonical safe refusal; only stdout/stderr/receipt may have complete custody; no captured source or clean assessment                                                              |
| Control-only        | Actual timeout/cancel/output-limit/malformed output; receipt has actual execution/termination and size-only control projection, six null raw IDs; no rejected bytes/hashes or raw-event replay claim |
| No returned result  | Execution/cleanup unavailable or launch never acknowledged; retain actual failure/snapshot, no fabricated execution receipt                                                                          |
| Partial publication | Known actual original IDs and stage retained; missing/unknown attachment or ACK remains incomplete, never replaced by all-null custody                                                               |
| Partial persistence | Actual committed model may coexist with failed reference retention; reopen exact prior/proposed state, report it, do not repair or claim whole success                                               |

## Source association and explicit historical dispatch

Use the legacy exact-URL Endpoint identity needed by the existing original-header
owner. A receipt-bound `owned-content-response-source` Observation has exactly
`schema_version=1`, `profile`, `original_job_id`, `original_receipt_id`,
`original_role_ids`, `request_sha256`, `response_sha256`, `header_size_bytes`,
`body_size_bytes`, `media_type`. Original job, seven role IDs, execution and scope
are independently verified, not guessed from a receipt lacking the job field.
Repeated captures keep separate immutable Observations on the stable exact-URL
Endpoint and preserve older provenance/triage. No catalog/case fields are fabricated.

The crawler's `requests.Endpoint` identity is structural method/origin/path JSON,
not this legacy URL key. Recompute its anonymous RequestTemplate coordinate when
checking an explicit join; never alias the Endpoint references, overwrite one
family with the other or treat their observations as equivalent source custody.
Acquisition need not create structural Endpoint/template objects. A future joined
pipeline must explicitly match workspace, exact URL, GET and structural coordinate.

New ReplayOwnedContentResponse verifies new-profile receipt, full request binding,
all original bytes/IDs/job/source association offline after relocation. Removal
of the original runtime, operation root, listener or current policy/scope inputs
must not affect historical verification. It performs no Put/Save/job/contact and
cannot infer missing original acknowledgements or ownership from equal hashes.

For header application add an explicit `source_profile` keyword defaulting to the
old closed profile. Selecting `owned-content-response-capture.v1` must dispatch
only to this family's bounded parser/replayers and actual source/provenance.
Do not infer a profile from a path, media type, field presence or trial parsing.
The current header v1 assessment/basis key sets are closed: new-family assessments
therefore use schema 2 / `owned-response-header-absence.v2`, adding `source_profile`
to the assessment and immutable authority basis. All other attributes and the
fixed PASSIVE permission/check/predicate are unchanged. Default old-family calls
and v1 historical replay stay byte/meaning compatible. Historical header replay
selects the strict versioned assessment route, requires its recorded source family
and never downgrades/falls back. No acquisition grants automatic interpretation.
New-family Apply/Replay summaries report the v2 profile and selected source_profile;
old-family summary fields/values remain unchanged. The fixed check ID/predicate
version stays 1, preserving Finding fingerprints and operator triage across captures.

## Minimal implementation seams and independent acceptance

Add only a new pure `adapters/owned_content_response.py` and packaged
`owned_content_response_worker.py` for new URL/framing/record rules. Existing
owned_response_capture/custody/workflow owners share the reviewed lifecycle through
closed internal two-family selection with frozen bindings, never caller-injected
callbacks, adapters or generic process authority. Old public entrypoints select
catalog v1; new named PlanOwnedContentResponseCapture/RunOwnedContentResponseCapture/
ReplayOwnedContentResponse select content v1. Run mirrors the old explicit SDK
signature with separate approval/retention booleans default false. Planning describes
the retention requirement without a grant, private work or implied approval.

```text
RunOwnedContentResponseCapture(workspace_root, scope_id, url, owner_reference,
    policy_provider, *, approve_safe_content_response_capture=False,
    retain_response=False, on_event=None, clock=UtcNow, current_owner_provider=None)
ReplayOwnedContentResponse(workspace_root, original_receipt_id)
```

PlanOwnedContentResponseCapture takes the same five selected positional inputs
and optional clock/current-owner reader; it returns descriptive intent with
retention_required=true and execution_authorized=false, never a usable grant.

Keep old parser/worker/schema/catalog files byte-identical. Receipt-first replay
reads a bounded authenticated receipt before selecting profile-specific role/media
limits; LocalEvidenceStore.Get's eager read must not bypass those preflights.
Change native_response_header_workflow only for the explicit family/version join,
keeping native_response_headers.HeaderFieldAbsent and its PASSIVE authority fixed.
Later CLI enrollment must expose the family and both independent execution/retention
selections explicitly; this document implements no command or enrollment.

An independent handwritten mutable owned source freezes the following wider matrix;
its arbitrary new paths/headers/body variants are test expectations, never runtime
admission data. The matrix describes the family acceptance objectives, rather than
claiming that every row has executed as an installed scenario in this SDK slice.

| Independent case                                                               | Required observation                                                                                                 |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Same new URL, missing/fixed/body-decoy headers                                 | Three genuine original captures; native header condition true/false/true from header names, independent of body text |
| Same headers, different valid UTF-8 bodies; second arbitrary path              | Exact differing original body/wire hashes and replay; no catalog or path-based admission                             |
| Header order/case/OWS/Date/Server/custom-value changes; empty body             | Accepted raw originals preserved, same field-presence meaning; no normalized-byte substitution                       |
| IPv4 and IPv6 actual installed isolated worker                                 | Exactly one independently recorded GET and correct peer; no proxy/env/checkout fallback                              |
| Missing SAFE permission/approval or retention; actor/URL/IP/consent drift      | Refusal before contact or before the corresponding Save; no automatic enrollment                                     |
| Boundary sizes, duplicate CL/field, TE/CE, wrong status/media, invalid UTF-8   | Exact bounded admit/refuse decision; refused material/marker/hashes absent from retained roles/stage/events          |
| Truncation, extra byte at maximum, EOF withheld, redirect                      | Incomplete/refused source; no retry/follow-up or completed acquisition                                               |
| Actual cancel/timeout/output-limit and repeated caller cancellation            | Same owned task/socket/process settled; original controls retained, no fabricated streams or positive source         |
| Put/artifact/journal/lost ACK faults and concurrent model/workspace writer     | Original ID/storage/attachment/ACK distinctions, one attempt per store, preserved triage and truthful partial state  |
| Runtime/listener/operation removed; workspace relocated; parts/source tampered | New capture/header replay fully offline, exact old IDs preserved; unknown association/tamper refuses without writes  |
| Old catalog positives/refusals/replays and wrong-family cross-feed             | Old identities/bytes/defaults unchanged; both dispatchers reject foreign profile/receipt/provider/media bindings     |

Pure/mock/schema checks are insufficient for genuine acceptance. This SDK slice
has actual installed capture-to-offline-header-to-relocated-replay evidence for
missing, present and body-decoy headers, plus separate installed refusal, CAS and
partial-persistence cases. The original post-model-ACK expiry case is retained in
[run 40813429726](https://github.com/Fuzzy-Technologies/1337/actions/runs/40813429726);
the separate worker-only IPv6 case is retained in
[run 40819203715](https://github.com/Fuzzy-Technologies/1337/actions/runs/40819203715).
Their independent original-artifact reviews are recorded in
[PR 368](https://github.com/Fuzzy-Technologies/1337/pull/368).

The implemented interface is the explicit SDK above. CLI enrollment, wider
installed custody/lost-ACK/concurrency cases and complete Task 59 acceptance remain
separate work. The IPv6 worker case does not establish IPv6 SDK authority or a
Finding. The expiry case uses a controlled receiver clock after an actual Save
acknowledgement; it does not measure elapsed real time. Final source review and
shared integration remain the merge gate for this bounded slice. No general
scanner, all-engine completion, privacy attestation or clean-target conclusion
follows.
