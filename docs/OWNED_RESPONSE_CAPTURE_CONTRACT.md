# Proposed closed original-response capture contract

## Status and owners

Proposed Experimental contract, 2026-10-23, under [ADR0095](adr/0095-owned-response-zap-passive-profile.md).
This document and [worker record schema](../contracts/owned-response-capture-record.schema.json)
freeze a reviewable acquisition proposal. They do not implement or enroll a
provider, authorize execution, prove original custody or establish a ZAP result.
The existing page/discovery records, non-retention promises and defaults remain
unchanged. Source implementation requires separate approval of this contract.

The provider is `native.loopback-response`; its sole capability is
`http.synthetic-response-capture`, at SAFE impact. Use the existing PolicyEngine,
GovernedLocalExecutor, JobContext, LocalEvidenceStore and model/workspace owners.
There is no additional grant, execution or evidence store. A future `zap` /
`http.synthetic-response-passive` permission cannot substitute for acquisition
permission, or conversely. Acquisition can use the ordinary governed fixed Python
worker; it does not require or establish the separately blocked Java isolation
owner. Descendant ownership, when explicitly selected, retains its existing
platform requirements and truthful cleanup behavior.

Planning contacts no listener. A live attempt needs explicit workflow approval,
current complete source scope/consent, executing owner and current policy for the
exact URL/literal destination. Revalidate them immediately before actual launch,
at any applicable READY boundary and before persistence, with aware exclusive
expiry and cancellation. Historical references and this schema are not grants.

## Selected URL and exact request

The only accepted URLs are `http://127.0.0.1:<port><path>` and
`http://[::1]:<port><path>`. The explicitly selected owned port is a canonical
decimal integer from 1024 through 65535, without leading zeros. `address` stores
`127.0.0.1` or `::1`, without brackets; `port` is the actual connected peer port.
The URL, selected literal socket family, verified peer address/port and record
must agree. Do not resolve DNS or substitute another loopback spelling.

The only paths are `/zap-passive/missing`, `/zap-passive/fixed` and
`/zap-passive/body-decoy`, matching `case_id`. No user information, fragment,
query, percent encoding, path normalization, default port, trailing slash or
alternate authority spelling is accepted. Connect directly to that literal
owned listener, issue exactly one GET, and perform no retry, redirect, proxy,
authentication, cookie/session reuse or provider-originated follow-up request.

The complete original request is ASCII bytes of this template, with the shown
header order/case/spacing. Each `\r\n` denotes two literal CR/LF bytes, not the
four printable escape characters:

```text
GET <path> HTTP/1.1\r\n
Host: <authority>\r\n
Connection: close\r\n
Accept: text/html\r\n
Accept-Encoding: identity\r\n
User-Agent: 1337-owned-response/1\r\n
\r\n
```

`<authority>` is `127.0.0.1:<port>` or `[::1]:<port>`, exactly matching the URL.
Only `<path>`, literal family and canonical selected port are substituted. No
request body or extra CR/LF follows the final blank line. Do not use an HTTP
client that adds, removes, combines or rewrites headers; caller/automatic headers
and environment proxy settings are excluded. The record's request bytes are the
bytes actually sent, not a reconstruction presented as a socket observation.

## Complete original response admission

The independently authored [static catalog](../tests/contract/fixtures/zap-passive.oracle.v1.json)
has SHA-256 `fb57a1e31904e9904ef5501a6dc7721c9263e12ab55672405c5a70fb2c3798d7`.
Only its original `header_section`, `body` and concatenated `response` bytes
define acquisition admission. Freeze those originals in the owning versioned
parser/replayer; changing them requires reviewed contract/version handling.
Never read its expected rule counts as acquisition input, emitted worker data,
proof of a Finding, or a provider result.

All three responses start with exactly `HTTP/1.1 200 OK\r\n`. Headers are exact
catalog bytes, including their order, capitalization, one space after each colon,
one canonical Content-Length and final `\r\n\r\n`. The fixed case alone has the
actual `X-Content-Type-Options: nosniff` field. Bodies are exact UTF-8 catalog
bytes. The complete body must match Content-Length, followed by actual EOF before
the shared request deadline. Do not stop at the declared length and assume EOF.

| Case       | Header bytes | Body bytes | Complete response bytes |
| ---------- | ------------ | ---------- | ----------------------- |
| missing    | 99           | 170        | 269                     |
| fixed      | 132          | 170        | 302                     |
| body-decoy | 99           | 212        | 311                     |

Unknown/different/duplicate/folded headers, alternate status/reason, cookies,
authorization, transfer/content encodings, redirection, informational responses,
partial bodies, wrong catalog bytes and trailing bytes refuse admission. Do not
publish any response bytes or their content hashes until the entire response is
admitted. Rejected material stays transient and must not enter streams retained
as evidence, progress events, exception text, logs, receipts or diagnostic echoes.
Body text is never a source for response-header presence/absence.

## Worker records and finite admission

The root of the JSON Schema validates one worker stdout record. A success has
exactly `schema_version`, `profile`, `outcome`, `catalog_sha256`, `case_id`, `url`,
`address`, `port`, `request`, `response_headers`, `response_body` and `response`.
Version is integer 1, profile is `owned-response-capture.v1` and outcome is
`captured`. The three original byte parts have exactly `base64`, `size_bytes` and
`sha256`; `response` has only `size_bytes` and `sha256`, computed over original
headers followed immediately by original body. It contains no repeated full
response base64, evidence IDs, grant, receipt, timestamp, header interpretation,
rule, severity or expected alert count.

A refused worker record has exactly `schema_version`, `profile`, `outcome` and
`error`, with outcome `refused`. It contains no selected or rejected URL, raw
request/response bytes, hashes of rejected bytes, diagnostics or partial success.
Validated selected request facts belong to the owning request/receipt, not this
failure object. The closed error codes are:

| Error           | Meaning                                                       |
| --------------- | ------------------------------------------------------------- |
| input           | Fixed input/selection contract refused before connection      |
| connection      | Selected literal connection or send/receive operation failed  |
| timeout         | The one shared request deadline expired                       |
| protocol        | Framing, complete body/EOF or finite wire admission failed    |
| response-policy | Complete status/header bytes differ from the selected catalog |
| body-policy     | Complete body bytes differ from the selected catalog          |

Classify the first detected failure without further reads for diagnostics.
Limits/deadline take precedence when hit; code selection never authorizes
retaining the rejected input. If the worker is interrupted or never launched,
do not invent its stdout record. Owner cancellation/startup/storage/authority
failures use existing job failure semantics instead of extending this enum.

Successful worker exit is 0; an emitted closed refusal exits 2. Both records use
`SerializeContract(record).encode("utf-8")` with no newline/BOM or surrounding
whitespace, and stderr must be empty. Strict parsing rejects duplicate keys at
every level, unsupported versions/keys, nonfinite values, noncanonical JSON,
booleans/floats where exact integers are required and malformed Unicode. Base64
must strictly decode and re-encode identically, without whitespace, alternate
alphabet or nonzero padding bits. Check every actual length and lowercase SHA-256
against decoded originals; bind case, path, URL, address and port together.
JSON Schema alone cannot enforce these cross-field/byte/primitive-type rules.

The following are proposed inclusive implementation ceilings, pending root
review and actual fixed-worker acceptance. They are not inherited permissions:

| Boundary                       | Ceiling                                                     |
| ------------------------------ | ----------------------------------------------------------- |
| Original request               | 1024 bytes; additionally exact request grammar              |
| Transient response header read | 16384 bytes including status line and final CR/LF section   |
| Transient response body read   | 65536 bytes; successful body still exactly 170 or 212 bytes |
| Complete worker stdout         | 8192 bytes, JSON depth 4 and 128 total JSON value nodes     |
| Actual retained stderr         | 0 bytes; configure positive executor capture ceiling 1      |
| Request deadline               | 5 monotonic seconds shared by connect/send/read/EOF         |
| Worker invocation timeout      | 10 seconds, with existing bounded awaited cleanup           |
| Full/control receipt           | 2097152 bytes; actual execution events at most 8195         |
| Canonical derived HAR          | 131072 bytes and exactly one admitted source entry          |
| Capture payload publication    | 3145728 total bytes, at most 8 fixed role manifests         |

Do not reset any deadline on progress. Observe stream/event lengths incrementally;
the executor's 8192-byte stdout and 1-byte stderr retention give at most 8193
nonempty stream events plus start/completed. Overflow, truncation, unexpected
stderr, observer failure or missing terminal state cannot be called a complete
record. Counters describe retained observations, not all bytes a peer/child may
have produced or discarded. OS scheduling and blocking filesystem calls do not
turn these budgets into hard real-time guarantees. Evidence manifest limits and
job quotas remain independently enforced by their existing owners.

## Canonical evidence and actual execution receipt

Use only the existing JobContext evidence attachment and immutable canonical
store. Original worker stdout is the actual record; the other wire roles are
byte-exact extractions or concatenations, with those derivations disclosed.
There is no circular evidence ID inside worker stdout. All attached manifests
share exact owning workspace, scope, provider/version, invocation digest,
collection times and actual AdapterExecution provenance. Attributed references
are not verified signatures or renewed execution authority.

| Role                   | Media type               | Bytes and admission                                          |
| ---------------------- | ------------------------ | ------------------------------------------------------------ |
| stdout                 | application/json         | Actual complete admitted success or closed-refusal record    |
| stderr                 | application/octet-stream | Actual empty stderr, only when complete record is admitted   |
| owned-response-request | application/octet-stream | Success: exact original sent request                         |
| owned-response-headers | application/octet-stream | Success: complete original status/header section             |
| owned-response-body    | text/html; charset=utf-8 | Success: complete original admitted body                     |
| owned-response-wire    | application/octet-stream | Success: original headers plus body, no reconstruction claim |
| owned-response-receipt | application/json         | Full admitted receipt or explicitly control-only receipt     |
| owned-response-har     | application/json         | Optional derived single-entry HAR, never original wire       |

Retain full actual admitted stdout/stderr and wire originals before later
semantic normalization, authority revalidation or model Save can fail. Verify
each actual Put/attachment result by its original `EvidenceRecord.evidence_id`:
recompute the canonical manifest digest, check the five-field reference and full
provenance, Get that exact original ID and Read its original reference to confirm
role, media type, byte count, SHA-256, canonical blob locator and exact bytes.
An equal content digest, replacement role/manifest or reconstructed ID is
insufficient. Preserve the actual returned IDs, including for identical content
under distinct roles. Do not silently create replacement evidence during replay.

The later receipt closes the noncircular association. It is canonical
`SerializeContract` UTF-8 JSON. Its closed top-level fields are `schema_version`
(1), `profile` (`owned-response-capture-receipt.v1`), `custody` (`complete` or
`control-only`), `workspace_id`, `owner_reference`, `started_at`, `finished_at`,
`request`, `execution`, `termination`, `events`, `evidence_ids` and `refusal`.
The future fixed parent must validate/bound these non-secret attribution values.
Times use existing aware UTC evidence normalization; finish cannot precede start.

`request` is the full canonical existing LocalExecutionRequest projection,
including invocation/argv/parameters, capability, original authorization,
workspace, environment and resources, not InvocationDigest alone. Admit only
the fixed worker profile and reviewed safe request/environment facts. Do not
serialize arbitrary host environment, credentials or exception text. `execution`
is the exact existing AdapterExecution projection and `termination` the actual
existing ExecutionTermination value, without remapping process status.

For `custody: complete`, `events` preserves every actual original event as the
closed object `sequence`, `kind`, `data_hex`, `termination`. Data hex preserves
each original fragment; do not rechunk. Check contiguous sequence, lifecycle,
stream joins equal actual result.stdout/stderr, and matching terminal outcome.
Only a normal process exit with the matching complete success/closed-refusal
record and empty stderr admits this branch. `evidence_ids` has exactly `stdout`,
`stderr`, `request`, `headers`, `body`, `response`: stream values are original
manifest IDs; all four part values are original IDs on success or all null on a
closed refusal. `refusal` is null on success or the exact worker error code.
The receipt is published last and its own manifest ID is retained by the owning
job, outside its bytes. A later optional HAR points to those original IDs and
receipt ID without rewriting the original receipt.

For invalid/truncated stdout, unexpected stderr, abnormal termination or
unadmitted response, do not publish original streams, extracted wire parts or a
byte-bearing full result/event receipt. A permitted `custody: control-only`
receipt instead contains only the exact already-safe selected request,
attribution, actual terminal control facts, and events as closed objects
`sequence`, `kind`, `data_size_bytes`, `termination`; never `data_hex`, response
bytes or hashes of rejected content. Its six evidence ID values are all null.
`refusal` is exactly one of `record-unadmitted`, `stderr-unadmitted`,
`execution-incomplete`, `output-limit`, `authority-denied`, `cancelled`,
`custody-incomplete`. These are owner classifications, never forged worker errors.
Preserve the first applicable owner failure under existing job precedence.
If no actual result exists, do not fabricate terminal/events: no full receipt
can be produced, and the existing job retains only its safe failure/control
history. A failed control publication creates no acknowledgement of custody.
Null IDs in this unadmitted branch assert no complete stream/part association;
they must not conceal evidence already acknowledged by the job. If publication
of an admitted capture partially succeeds, preserve every actual acknowledged
attachment/ID and its existing job history; do not replace them with a fabricated
all-null receipt or claim that they were rolled back. Recovery must authenticate
those originals before any later complete association is published.

The generic raw-stream-first LocalExecutionJob path cannot be reused unchanged
for unadmitted data. Stage transient executor streams, validate the complete
record/wire before publication, and forward only safe heartbeat/lifecycle control
to job events. An admitted refusal may retain its exact safe stdout and empty
stderr, but contains no response originals and is not a successful acquisition.
Future code must preserve cleanup on caller cancellation without abandoning a
background task. A failed Put or uncertain acknowledgement keeps available
admitted private staging for recovery and truthfully reports incomplete custody;
never claim rollback, invent an evidence ID or publish rejected material to
improve diagnostics. The staging/recovery mechanism needs implementation review.

## Pure historical replay and future derivations

Historical replay is an offline integrity operation. It uses the original owning
job receipt/manifest IDs and retained blobs, including after relocation; it does
not need a current listener, Java/ZAP, executable, current scope approval or
reconstructed launch authority. Reopen through existing canonical owners under
the explicit relocated workspace boundary, using relative hash-addressed blob
locators and original manifest IDs. Never resolve historical request paths as new
permissions to read outside that boundary or launch a process.

Replay must, in this order:

1. Bound and strictly parse original canonical manifests/receipt, independently
   verify IDs/roles/provenance and authenticate all referenced actual bytes.
2. Require `custody: complete` and validate the full fixed request, actual result,
   event fragments and stream/terminal consistency. A control-only receipt can
   explain refusal/incomplete custody, but cannot replay a successful capture.
3. Strictly validate original stdout against this schema and all additional
   canonical/type/association rules. Preserve a closed refusal as refusal.
4. On success, rebuild expected request grammar from the admitted literal URL,
   address, port and case and compare with original sent bytes. Compare original
   headers/body to the frozen version-1 catalog, all part hashes/sizes and exact
   concatenated response. Require all extracted evidence bytes to match stdout.
5. Return only the verified acquisition source facts and original references.
   Do not emit a ZAP result, Finding, renewed grant, Save, replacement evidence or
   silently reinterpret a future schema. A failed verification refuses replay.

An optional derived HAR must declare its transformation and original receipt,
record/request/header/body/response manifest IDs in the owning derivation
metadata. Its single request/response must preserve the source URL/method and
actual header names/values/order and body, without fabricating server timing,
addresses, headers or observations. Unsupported/unobserved HAR facts need an
explicit reviewed encoding rather than plausible invented values. The exact HAR
grammar and ZAP analysis receipt remain a separate blocked contract. No ZAP alert
count or assessment is carried by this acquisition record.

## Remaining approval and acceptance

Root review must approve the new schema/roles/receipt branches and candidate
budgets before acquisition source implementation. Implementation review must
freeze fixed installed worker invocation/environment/resources, canonical
receipt admission and recovery staging; do not claim those bindings exist now.
Future deterministic acquisition acceptance must run each owned fixture through
the shared SDK/installed isolated CLI and prove one selected GET, original byte
custody, refusal non-retention, current authority, cancellation/cleanup and pure
relocated replay. Small schema/static-fixture checks are contract evidence only.
They do not replace actual worker or genuine isolated Java/ZAP acceptance.
