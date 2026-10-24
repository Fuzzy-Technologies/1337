# Owned-loopback content crawl contract

## Status and scope

Proposed Experimental profile `owned-loopback-content-crawl.v1` under
[ADR0097](adr/0097-owned-loopback-content-crawl.md), provider `native.crawl`,
version `1`, sole capability `http.owned-loopback-crawl`, maximum impact SAFE.
This is a contract checkpoint, without provider implementation, enrollment or
runtime evidence. [The schema](../contracts/native-crawl-record.schema.json)
describes worker records and its `$defs/input` describes the private fixed input.
Schema cases are examples, not detector oracles or a production body catalog.

## Selection, permission and immutable input

The caller provides an existing workspace/scope, fixed selected executing owner,
synchronous current typed ImpactPolicy reader, explicit workflow approval, one
seed Target and at most sixteen selected URL Targets including the seed. All selected URLs
are distinct, sorted lexically and in the seed's exact origin. Canonical URLs
use `http://127.0.0.1` or `http://[::1]`, canonical decimal ports 1..65535, omitting
the default port 80. Paths use existing concrete `requests.Endpoint` grammar,
at most 1024 ASCII characters; no percent escapes or path variables. Require
already-canonical spelling, not normalization of caller input. No query,
userinfo, fragment, DNS, alternate loopback spelling or HTTPS is admitted.
Selected metadata is explicitly non-secret; this is not a secret classifier.

Current scope must register AND allow every exact selected URL and the actual
literal IP, with exclusion/deny precedence. Validate the workspace, executing-owner
attribution and consent, complete selected set and capability permission at planning,
each page grant, final governed launch and immediately before each model Save.
Planning contacts no target. No discovered link registers a Target or expands a
rule. Explicit workflow approval does not replace per-invocation PolicyEngine
authorization. Complete-set membership is an additional consumer guard; the
canonical PolicyEngine checks for the exact source and actual literal destination
remain unconditional. Grant expiry and scope/policy drift remain authoritative.

Parent-owned actor attribution follows the accepted
[CurrentAuthority precedent](../src/fuzzy1337/owned_response_workflow.py).
Future planning/execution entry points and provider composition accept the same
keyword-only `current_owner_provider: Callable[[], str] | None = None`, passed
unchanged to this local fresh reader:

```text
CurrentCrawlAuthority(
    workspace_root: Path, scope_id: str, source: Target,
    selected_urls: tuple[Target, ...], owner_reference: str,
    policy_provider: Callable[[], ImpactPolicy], workflow_approved: bool,
    *, current_owner_provider: Callable[[], str] | None = None,
) -> NativeCrawlAuthority
```

The local immutable `NativeCrawlAuthority` wrapper has exactly three fields:
`context: PolicyContext`, `owner_reference: str` and `workflow_approved: bool`,
following the existing owned-response wrapper. Require exact valid owner text
and an exact boolean approval. At planning, every grant, final launch and immediately before
Save, call the supplied synchronous reader afresh; require `type(result) is str`
and equality to the original fixed selected owner. A mismatch, invalid return or
reader failure denies the boundary without echoing its value. With no reader,
use the selected owner as attribution. Default/CLI attribution is not external
authentication and cannot detect external principal changes without a trusted
reader supplied by the caller. Never substitute the consent attester for it or
require the attester and executing owner to be equal.

The live parent provider rereads this wrapper at each boundary, binds its owner
to the original JobSpec owner, and validates source/workspace/scope plus explicit
approval before passing its existing `context` to the unconditional PolicyEngine checks.
The executor context-provider closure must repeat that fresh wrapper validation;
it cannot return a cached PolicyContext that bypasses the owner reader. Repeat
the same checks synchronously before ordered Save. Scope consent, including its
independent attester, is checked through its existing owner. Extend neither core
PolicyContext nor worker input/output; actor attribution stays parent-owned.

Per-page input has exactly these fields:

| Field                | Meaning                                                    |
| -------------------- | ---------------------------------------------------------- |
| `schema_version`     | Exact integer 1                                            |
| `profile`            | `owned-loopback-content-crawl.v1`                          |
| `workspace_id`       | Existing lowercase identifier, at most 64 ASCII characters |
| `seed_url`           | Original exact selected seed                               |
| `source_url`         | Current exact selected source                              |
| `selected_urls`      | Entire immutable sorted admitted set, including both above |
| `max_body_bytes`     | Exact integer per-page admission/allocation ceiling        |
| `request_timeout_ms` | Exact integer complete-request deadline in milliseconds    |

Use `SerializeContract(input).encode("ascii")`, at most 24576 bytes, without
newline/BOM/whitespace. The same object is frozen in AdapterRequest.parameters;
the request target_reference is `Target(URL, source_url).Reference()`, capability
is the sole declared capability and impact is SAFE, without credentials.
The adapter prepares exactly:

```text
(sys.executable, "-I", "-m", "fuzzy1337.native_crawl_worker", canonical_input)
```

`canonical_input` is one argument, passed through the existing shell-free
executor. The module/executable prefix is packaged first-party selection, never
caller configurable. Invocation timeout is `ceil(request_timeout_ms / 1000) + 1`
seconds. LocalExecutionRequest has no stdin input field; add no generic file,
stdin, environment or inherited-FD mechanism. Oversized input or operating-system
argument refusal fails before worker success; no file fallback or retry exists.
At launch the complete set must still be allowed. Subsequent authority drift
prevents Save, while the original report can retain only URLs already admitted
and present in its invocation. It can never introduce an unselected raw href.

## Wire and response admission

Use one direct AF_INET/AF_INET6 socket to the exact source literal and selected
port. Verify actual peer address AND port before sending. Request bytes are ASCII:

```text
GET <path> HTTP/1.1\r\n
Host: <canonical-authority>\r\n
Connection: close\r\n
Accept: text/html, text/plain, application/octet-stream\r\n
Accept-Encoding: identity\r\n
\r\n
```

No request body, automatic/custom headers, proxy environment, cookie, retry,
redirect, further connection or session is used. Authority preserves bracketed
IPv6 and a nondefault selected port. Request size/hash describe the actual bytes
sent, independently recomputable by the parent; no raw request body is stored.
The source's anonymous GET RequestTemplate and structural Endpoint reference are
recomputed with existing owners, never accepted as worker-assigned identities.

One monotonic request deadline covers connect, send, headers, body and final EOF;
set socket timeouts from its remaining time and check elapsed time after each
phase. Admit only HTTP/1.0 or HTTP/1.1 status lines with a printable ASCII reason,
CRLF framing, token field names and printable ASCII/HTAB values. Reject folding,
duplicate names case-insensitively, excess lines/counts and missing fields.
Exactly one canonical decimal Content-Length and one Content-Type are required.
Content-Length permits `0` and otherwise no leading zero. Reject Transfer-Encoding
or Content-Encoding presence, including identity. Unknown header values and the
status reason stay transient, without retained text or hashes.

Admitted Content-Type values, case-insensitively and after surrounding OWS removal,
are `text/html`, `text/html; charset=utf-8` with the existing page parser's OWS
grammar, `text/plain` and `application/octet-stream`. Other parameters/media refuse.
The record normalizes these to `text/html`, `text/plain` or
`application/octet-stream`. Complete body bytes must equal Content-Length and be
followed by actual timely EOF. Short, oversized or trailing bytes refuse.

| Complete admitted response  | Outcome        | Interpretation                                         |
| --------------------------- | -------------- | ------------------------------------------------------ |
| 200 HTML                    | `html`         | Full strict UTF-8 lexical admission, then frontier     |
| 200 plain/octet-stream      | `non-html`     | Terminal response observation; no lexical work         |
| 400..499, any admitted type | `client-error` | Terminal response observation; do not interpret markup |
| Any other status/type       | `refused`      | Failed/unassessed page; no response/body metadata      |

Non-HTML and 4xx bodies are admitted as bounded opaque bytes after complete wire
admission; their zero frontier is not a clean-scan or vulnerability-negative
result. In particular, a 404 HTML body does not discover links. HTTP 200 HTML must
also pass `captured_web.ParseAnchors` in full, including UTF-8/no-BOM, token,
attribute, base-tag and script/style closure rules. A malformed body cannot emit
even a digest or an earlier valid prefix. Informational responses, other 2xx,
all 3xx and 5xx refuse, without retaining Location or following it.

## Lexical output and strict records

For HTML only, run existing `Candidate` on source-ordered ParseAnchors slots.
Use one-based ordinals. Existing fragment removal is lexical only: selected
URLs and requests contain no fragment, fragment-only slots are count-only, and
no raw fragment is emitted. Apply its fixed rejection precedence. After a
qualifying same-origin URL is produced, require exact membership in the input's
admitted set; otherwise increment `not-admitted` without emitting the URL.
This counter deliberately combines unselected, unregistered and excluded links;
the worker has no scope-file interface and must not guess a scope reason.

Emit entries sorted by canonical URL, each with recomputed request and structural
Endpoint references and sorted distinct occurrence ordinals. A candidate may
occur once in entries with several ordinals. The source is not a candidate.
Every anchor slot belongs to exactly one emitted ordinal or one closed exclusion
count. No candidate URL/href, snippet, attribute, header value or exception text
outside the admitted set enters output, evidence, progress or diagnostics.

An admitted record has exactly `schema_version`, `profile`, `outcome`,
`input_sha256`, `selected_urls_sha256`, `source`, `response` and `frontier`.
`input_sha256` hashes the exact canonical input bytes; `selected_urls_sha256`
hashes `SerializeContract(selected_urls).encode("ascii")`. `source` binds exact
URL, actual peer address/port, canonical request/Endpoint references and actual
request size/hash. `response` contains only version/status, normalized media,
header byte/field counts and complete admitted body size/hash. `frontier` has
`complete: true`, anchor count, entries and all ten closed counters. Terminal
outcomes require the exact empty frontier. There is no successful truncated
frontier. Retained body length/digest attest the packaged worker's interpretation;
they cannot reconstruct or independently replay the absent HTTP body.

A refusal has exactly `schema_version`, `profile`, `outcome: "refused"` and one
`error`: `input`, `connection`, `timeout`, `protocol`, `response-policy`,
`html-policy`, `output-limit` or `internal`. Input refusal occurs before connect;
the other codes classify the first detected failure without diagnostic reads.
It has no URL, body, digest, counters or partial success. Do not fabricate a
refusal when a worker never launched or was interrupted. Successful exit is 0;
an emitted refusal exits 2. Parent maps timeout/output-limit to existing owning
job failure codes; other provider refusals are failed/unassessed work.

Both branches use `SerializeContract(record).encode("ascii")`, with no newline,
BOM or surrounding/trailing data; stderr is empty. The parser rejects duplicate
keys at every depth, unknown fields/versions, nonfinite numbers, malformed
Unicode, booleans/floats in integer fields and noncanonical serialization.
Bound bytes before decode, then nodes/depth/counts before interpretation. Schema
alone does not enforce exact Python types, serialization, URL/peer joins, hashes,
sorting, selected membership, body size within the input quota, identity
recomputation or ordinal accounting. A zero-byte body must use SHA-256 of empty
bytes. All per-source and candidate references are recomputed from admitted URLs.

## Proposed finite limits and lifecycle

These are proposed admission ceilings pending actual worker and functional
acceptance. Existing page/parser/traversal defaults are reused where shown;
they do not establish new runtime performance or transport guarantees.

| Boundary                      | Default / hard bound                                       |
| ----------------------------- | ---------------------------------------------------------- |
| Selected URLs / fetched pages | 16; configured page limit 1..16                            |
| Depth / concurrency           | 4 / 2; ranges 0..4 / 1..4, as existing traversal           |
| Start gap                     | 0.05 seconds; 0.05..1, as existing traversal               |
| Complete request              | 3000 ms; 50..5000, existing page request ceilings          |
| Request / input bytes         | 2048 / 24576, fixed independent ceilings                   |
| Headers / fields / line       | 16384 bytes / 64 / 4096 bytes including CRLF, as page wire |
| Body allocation/admission     | 16384 bytes; configurable 1..65536, as existing page       |
| Markup token / tokens / attrs | 4096 bytes / 8192 / 64, existing ParseAnchors              |
| Anchor slots / entries        | 1024 / 15; at most 1024 retained ordinals across entries   |
| Output / stderr               | 65536 bytes / 1-byte executor ceiling; actual stderr empty |
| JSON tree                     | At most 4096 nodes, depth 8, input and output separately   |
| Aggregate body reservation    | 262144 bytes; 1..1048576, maximum from existing traversal  |
| Whole operation               | 30 seconds; 0.05..60, as existing traversal                |
| Event bound / terminate grace | 4096 events / 0.1 seconds, existing bounded owners         |

Aggregate default is sixteen default body ceilings rather than catalog sizes.
Reserve `wave_size * max_body_bytes` and every wave's page quota before dispatch;
never refund unused body reservations. This bounds allocation/admission, not
socket overhead, interpreter memory or an OS sandbox. Original stdout storage is
independently bounded by sixteen 65536-byte reports, plus bounded stderr/manifests.
Any bound that would omit reachable selected work fails OUTPUT_LIMIT. Do not
truncate a selection, candidate list or later frontier and report completion.

Use breadth/depth then lexical URL order, cycle suppression and bounded concurrent
acquisition. A sorted gate precedes model Open/composition; perform fresh authority
and one expected-revision Save synchronously after that gate, then ModelChanged,
observations and progress. No awaited work is inserted between composition,
authority and Save. Whole-operation monotonic time includes rate waits, startup,
acquisition, evidence, commit waits, persistence and cleanup; never reset it on
progress. Cleanup always drains tasks, waiters and owned workers, even after
expiry. There is no real-time cleanup promise; late completion remains timeout.

Evidence precedes model projection. Preserve actual original worker streams,
invocation/version, scope and execution metadata through existing owners.
Project source and admitted candidate RequestTemplates through ProjectRequests,
merging current complete collections before Save. Use structural Endpoint keys;
retain unrelated attributes and provenance. Proposed observations
`web.owned-crawl-response` and `web.owned-crawl-link` bind original report reference,
input/set hashes, source Target/request/Endpoint and candidate references/ordinals.
Do not construct a response-body EvidenceRecord, pretend to possess a
CapturedWebFrontier body capture, or rewrite existing body-capture receipt schemas.

Progress counts only acknowledged ordered Save/event transitions; the final total
is known after exhaustion. Earlier commits and acquisitions survive later failure.
CAS conflict, ambiguous acknowledgement and post-Save event failure do not imply
rollback. No retry, resume or persistent queue is introduced. Historical relocated
replay verifies original execution records and projection, without HTTP contact
or a claim to recompute extraction from body digests.

## Explicit native check handoff and acceptance

A discovered admitted Target/RequestTemplate/source-evidence tuple may be shown
to a caller for separate PlanNativeWebScan and RunNativeWebScan. The existing Git
check retains STANDARD permission, exact-plan confirmation and its existing
single-request worker. No crawl result triggers a check automatically. Legacy
exact-URL Git Endpoint identity and structural JSON-key Endpoint identity remain
separate; a later joined check path requires its own explicit binding contract.

An independent validator authors the mutable local target and graph oracle.
Require real seed-to-leaf discovery, a fixed variant removing the link and a
comment/script decoy; changing target bytes must change actual fetches without
production catalog/hash edits. Include cycles, shared leaves and inverted
completion order. Actual server records and independent reopen prove selected
reachability, deterministic commit order, request collections and report custody.
Separately execute existing independent Git positive/fixed/HTML-decoy/redirect
cases from explicit discovered selections and score persisted Findings. Refused
or unexecuted work does not count as a true negative.

Require zero contact for selected-set registration/allow denial, denied literal
IP, owner/consent/policy mismatch and exclusion at planning/grant/launch. Exercise
caller-owner drift with an actually supplied trusted current_owner_provider:
keep the selected owner fixed, change the reader after planning and again between
grant and launch, and prove zero contact. Change it after a successful worker but
before Save and prove no page model Save, retaining actual admitted evidence.
Use a distinct valid consent attester to prove attribution and attestation are
independent. Default/CLI cases establish selected attribution only; they cannot
claim detection of an external principal change without that reader. Exercise
unselected, credential, query, fragment-only, off-origin and malformed links with
sensitive transient markers, proving no rejected href/marker retention. Drift
after launch must prevent Save while preserving actual admitted execution
metadata. Cover all bounds, framing/EOF, HTML/media/status branches, malformed
records, deadline expiry, cancellation, worker cleanup, CAS/lost acknowledgement,
post-Save failure, triage preservation and relocated metadata replay.

## Implementation ownership and remaining gates

| Owner                 | Future source ownership                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| Producer              | New adapters/native_crawl.py, native_crawl_worker.py and focused tests  |
| Orchestration         | New native_crawl.py and integration tests after record review           |
| Independent validator | Handwritten target/graph oracle, functional scenarios and acceptance    |
| Coordinator           | This ADR/guide/schema; any later narrow CLI/registry/documentation hook |

Paths in this table are relative to `src/fuzzy1337` unless clearly tests/docs.
Reuse existing parser/request/job/executor/evidence/model owners; do not alter
policy/scope/model cores, native defaults, body catalogs, original-response
custody or the separately owned inert/ZAP work. Reusing traversal semantics does
not authorize a broad scheduler refactor. The first implementation surface is SDK;
CLI enrollment requires a separate coordinator-owned integration step.

No wire/branch/identity decision is intentionally deferred by this proposal.
Independent review must still accept its new profile, bounds and record semantics.
Actual portability/argument limits, parser/transport behavior, coverage, native
check consumption and genuine functional acceptance remain unmeasured. Shared
full CI runs only after a complete reviewed implementation is marked ready;
this design is not scanner completion or runtime acceptance.
