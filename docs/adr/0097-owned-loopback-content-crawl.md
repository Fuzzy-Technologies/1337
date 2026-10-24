# ADR 0097: Non-retaining content-driven owned-loopback crawl

- Status: Proposed contract for independent review; no runtime implementation
- Date: 2026-10-24
- Decision owners: Fuzzy Technologies
- Related work: #59, #53, #58

## Context

The accepted tree `91a4327c6765870a7ac25ad82dcc8c92018c51d6` at develop
`fc3ab51253b746636d49a5f352a5649f119a74db` supplies bounded concurrent traversal,
structural requests, native response predicates and governed execution. Its page
traversal selects URL/body-catalog pairs. Native HTTP retains status only; native
web checks retain predicate metadata. Original-response capture intentionally
admits three fixed reviewed responses. None is a content-driven page producer
independent of a production body catalog.

## Decision

Propose Experimental provider `native.crawl`, version `1`, capability
`http.owned-loopback-crawl`, maximum impact SAFE. The exact profile is
`owned-loopback-content-crawl.v1`. The [contract guide](../NATIVE_CONTENT_CRAWL_CONTRACT.md)
and [closed worker schema](../../contracts/native-crawl-record.schema.json) are
normative together. This decision adds no production code, enrollment, launch
authority or claim that #59/#53 is complete.

A caller explicitly approves one anonymous canonical HTTP seed and a sorted,
distinct set of at most sixteen same-origin selected URL Targets containing it.
Only literal `127.0.0.1` and `[::1]` are admitted. Every selected exact URL and
the actual literal IP must already be registered and allowed in current scope.
There is no DNS, query, user information, request fragment, redirect, retry,
proxy, session, custom header, mutation or automatic scope enrollment. A selected
URL is fetched only after discovery from an admitted predecessor; selecting it
alone never schedules it. The seed is the sole initial request.

Each page independently uses existing PolicyEngine, GovernedLocalExecutor,
LocalExecutionJob, ScanJob and evidence owners. Recheck executing-owner
attribution, consent, complete selected-set membership and typed capability policy at
grant, final launch and immediately before ordered model Save. Later scope or
policy drift fails closed; a prior grant, lexical link or loopback address does
not authorize another page. Existing authorization algorithms and defaults stay
unchanged. Caller approval is explicit, never inferred from selecting a check.

Follow the accepted owned-response CurrentAuthority precedent: the fixed selected
owner has an optional trusted synchronous `current_owner_provider`. When supplied,
call it afresh at every boundary and require an exact string equal to that owner.
A local immutable authority wrapper carries existing PolicyContext, owner and
workflow approval; PolicyContext gains no actor field. Consent attestation stays
independent from executing-owner attribution. Default/CLI behavior reuses selected
operator attribution, not external authentication, and cannot detect external
principal changes without an actually supplied trusted reader.

## Immutable worker boundary

Existing `AdapterRequest.parameters` recursively freezes JSON metadata;
`AdapterInvocation.argv` is immutable and LocalExecutionRequest has no stdin or
caller-FD input contract. Use exactly one bounded canonical ASCII JSON argument
to the fixed isolated packaged Python worker. Bind that same object in the
adapter request. Accept no caller argv, executable, flags, file, FD, environment
payload or alternate transport. The guide freezes the object, invocation and
byte ceilings. Operating-system launch refusal remains failure.

The input contains only already admitted non-secret selected URLs, the workspace,
seed, current source and two finite per-page limits. The worker recomputes source
request/Endpoint identities and request-wire facts. Its output binds the entire
input digest and exact admitted-set digest. After existing `ParseAnchors` and
`Candidate` interpretation, it emits only candidates in that admitted set.
Unselected, excluded or unregistered same-origin destinations share the closed
`not-admitted` counter; credentials, queries and other origins never leave the
worker as raw hrefs, URLs, diagnostics or hashes of those hrefs.

## Response and model boundary

Bodies and arbitrary header values remain transient. Complete Content-Length
framing, bounded headers/body and actual timely EOF precede any successful body
length/digest publication. HTTP 200 admitted HTML must also pass the existing
bounded UTF-8 lexical grammar in full. It yields selected candidates and closed
counts. Admitted HTTP 200 plain/octet-stream and admitted 4xx responses are
explicit terminal response observations with no frontier, not vulnerability
negatives. Informational, other 2xx, 3xx, 5xx, unsupported media/encoding,
truncation, trailing bytes and invalid HTML refuse. A refusal has only fixed
classification fields and no body, body digest or partial frontier.

Original stdout/stderr and execution provenance are immutable evidence. A body
digest is an attributed worker observation, not original HTTP body custody or
independent replay of extraction. Do not fabricate a response-body EvidenceRecord
or reuse a catalog receipt to make it appear otherwise. Historical replay can
verify retained records, execution bindings and deterministic projection only.

Project source and candidate RequestTemplates through the existing structural
Endpoint identity, merge complete existing request collections and apply one
expected-revision model Save per page. New observations bind original report,
input, source and candidate references. Candidate discovery is not evidence that
the candidate was fetched. Preserve existing attributes, provenance and operator
triage. No provider database, graph schema enum or authority store is introduced.

## Scheduling, failure and separate check consumption

Preserve current breadth/depth then lexical ordering, deduplication, cycle
suppression, bounded overlap and sorted commit gates. Reserve an entire wave's
worst-case body quota before dispatch, without later refund. Bound pages, depth,
concurrency, starts, headers, body, output, candidate work, aggregate bytes and
one whole-operation deadline including waits and cleanup. Time is never renewed
on progress. All task/worker cleanup is awaited even after expiry; late cleanup
does not convert a timed-out operation to success. Unmeasured ceilings are
proposed admission bounds, not demonstrated performance guarantees.

Any bound omitting reachable selected work fails OUTPUT_LIMIT. Cancellation,
timeout, authorization drift, malformed output, CAS conflict, lost acknowledgement
and post-Save event failure retain truthful prior evidence and actual partial
model state. Completion counts only acknowledged ordered Save/event transitions.

A discovered Target can be explicitly passed to existing PlanNativeWebScan and
RunNativeWebScan. The Git check retains its own STANDARD permission and separate
exact-plan confirmation. There is no automatic check launch or inherited grant.
Keep legacy exact-URL Git Endpoint identity separate from structural JSON-key
Endpoint identity; this slice neither migrates nor silently joins them.

## Independent acceptance and ownership

An independent validator owns a mutable synthetic graph and handwritten oracle:
linked-leaf positive, removed-link fixed case, comment/script decoy, cycles,
shared leaves and completion-order inversion. Change graph bytes without changing
production data and prove actual request selection changes. Require zero contact
for scope denial, missing registration, unselected and unsafe links. Exercise
fresh denial at grant/launch/Save, every bound, malformed transport/HTML, cancelled
workers, ordered persistence and reopened partial state. Separately and explicitly
run the existing independent Git positive/fixed/decoy/redirect cases and score
saved Findings. No target labels or detector result generate expected truth.
Caller-owner drift acceptance must supply a trusted reader, prove refusal before
contact and before Save, and retain an independently named consent attester.

The guide assigns disjoint producer, orchestration, independent acceptance and
coordinator paths. Policy/scope/model cores, accepted worker defaults, original
response custody and the separately owned inert/ZAP work remain untouched.
Independent contract review precedes production implementation. Genuine functional
acceptance, installed CLI coverage and shared final integration CI remain unrun.
