# Owned loopback page capture

This Proposed ADR-0052 profile is an exact bounded next slice of #59/#53. It
preserves NativeHTTP version 1. Behavior implementation begins only after design
review; the reviewed ADR-0050 captured-web consumer is an integration dependency.

## Authority and input

The consumer owns an existing physical workspace, initial durable model, consented
scope and localhost service started for the current authorized operation/test.
Constructor/health/preparation perform no network I/O and grant no authority.
The explicit operation is one anonymous, concrete GET RequestTemplate: actual
typed Endpoint; canonical method `GET`; BodyKind.NONE; an empty tuple of injection
points; no session reference or GraphQL operation. Canonical origin/path reconstruct
the supplied fields exactly. Concrete paths contain no `%`, braces, query,
fragment, credentials, whitespace, backslash or Unicode control characters.
Endpoint/request names and paths remain structural source literals and must be
non-secret. Validate nested types and bounded text before serialization/hashing;
equal enum/string copies and forged nested wrappers are refused.

The only addresses are exact canonical `127.0.0.1` and `::1`, under plain HTTP.
Other loopback aliases, IPv4-mapped/scoped IPv6, names, proxy destinations and
external addresses are unsupported. A default port is allowed only as part of
the explicitly supplied owned-service URL; no port discovery occurs. The worker
uses the literal address family and checks getpeername against that exact address.

Provider `native.loopback-page`, version `1`, declares one SAFE capability,
`http.synthetic-page-capture`, with no privilege requirement. It is not permission
for `native.http` or vice versa. PolicyContext includes the exact URL target and
literal IP destination. Both require exact registration/membership/current consent
under the existing scope/impact checks. An explicit ImpactPolicy permission for
this capability/provider is mandatory. The existing exact-invocation grant and
final synchronous GovernedLocalExecutor context reread remain unconditional.
The job workspace/provider/scope must match the persisted owners. Scope metadata,
hashes, planning, localhost and body equality do not authenticate an owner.

`KnownSyntheticHtmlBody(fixture_id)` selects one closed reviewed non-secret fixture
catalog entry and exposes its immutable derived `sha256` and `size_bytes`.
Version 1 admits only `owned-loopback-html.v1`, exactly 541 bytes with SHA-256
`c0b909f728bdcc098193c1fd268f056eea33c27b6537cd504fa77c3a25afe817`.
The source is the independently authored HTML fixture below. No arbitrary caller
digest/size, unknown fixture ID, boolean/coercion, default/example body selection
or approval shortcut qualifies. Copied records must match all derived catalog
fields exactly. Selection is not permission to acquire a service. The size must
fit the selected acquisition body limit. A digest is neither encryption nor a
general secret detector; URL/metadata non-secret attribution remains the caller's
responsibility. The worker holds only the fixed catalog ID/hash/size and never
loads a caller-selected file or fixture path.

## Experimental consumer shape and limits

The implementation will use new owned adapter, worker and producer paths:
`fuzzy1337.adapters.page_capture`, `fuzzy1337.page_capture_worker` and
`fuzzy1337.page_capture`. The concrete provider shape is
`LocalPageCaptureProvider(workspace_root, source, expected_body, scope_id, policy,
*, limits, frontier_limits, clock)` with existing `JobProvider.Run(context)` and
read-only `Descriptor`. `PageCaptureLimits` and `KnownSyntheticHtmlBody` are the
finite typed input records. Adapter preparation/normalization follow the existing
ToolAdapter contract. Internal wire/parser helpers are not an additional launch
API. No automatic CLI/registry/shell registration or owner-schema changes occur.

| Resource                   | Default         | Exact hard admission                                                      |
| -------------------------- | --------------- | ------------------------------------------------------------------------- |
| Requests/connections       | 1               | One exact GET/connection; zero retry, redirect or subrequest              |
| Body bytes                 | 16384           | Selected actual integer limit 1..65536; selected catalog size must fit    |
| Complete request deadline  | 2 seconds       | Numeric 0.05..5 inclusive, excluding bool/nonfinite/huge values           |
| Provider deadline          | 10 seconds      | Numeric 0.05..15 inclusive; at least request deadline plus 1 second       |
| Executor timeout           | Derived         | Ceiling of request deadline plus 1 second; existing cleanup semantics     |
| Response header bytes      | 16384           | Complete status/header section including final CRLFCRLF                   |
| Header fields              | 64              | Distinct case-insensitive names; duplicate names reject                   |
| Status/header line bytes   | 4096            | Including its final CRLF                                                  |
| Canonical request URL      | Owner limits    | At most 2048 ASCII bytes; structural path at most 1024 characters         |
| Read chunks                | 4096 bytes      | Header/body allocation stays within admitted section/body bounds          |
| Worker stdout              | 98304 bytes     | Strict flat JSON, including base64 body and final LF                      |
| Worker stderr              | 1024 bytes      | Executor bound; no stderr is eligible for persistence or successful input |
| Job heartbeat publications | 2               | Executor STARTED and COMPLETED only; stream chunks are never forwarded    |
| Lexical work/candidates    | ADR 0050        | Existing CapturedWebLimits; full source admission before soft truncation  |
| Evidence reads             | Role-specific   | Actual parsed stdout <=98304/body <=65536 before allocating owner Read    |
| Model/event budgets        | Existing owners | Persisted model <=8 MiB; existing ScanJob event/cancellation bounds       |

Bounds are checked before numeric conversion or input-derived allocations. This
caps the consumer's copies/work, not memory already allocated by a direct caller.
One connection per job is a request-count bound, not a global cross-job rate limiter.
The ordinary executor is not an OS network/memory sandbox. Scheduling/startup and
storage are not guaranteed real-time; the owning job can impose an earlier timeout.

## Exact HTTP admission and privacy

The fixed request bytes are `GET <canonical-path> HTTP/1.1`, `Host: <canonical
authority>`, `Connection: close`, `Accept: text/html`, `Accept-Encoding: identity`,
with CRLF after each line and a final empty CRLF. There is no User-Agent, credential,
cookie, request body, conditional request or caller-selected header. The one
monotonic deadline covers connect, send, complete headers, exact body and final EOF;
partial progress never renews it. No DNS or environment proxy is consulted.

The status line is exactly HTTP/1.0 or HTTP/1.1, one space, three ASCII status
digits, then exactly one required space, zero or more printable ASCII reason
characters, and CRLF. The separator space is required even for an empty reason. Only
status 200 is admitted as a page. Interim responses, redirects and other statuses
fail without following anything. Reason text is transient parser input only.
All section lines use CRLF. A field name is one or more ASCII letters, ASCII
digits or the exact characters ``!#$%&'*+-.^_`|~``; Unicode character predicates do
not admit additional characters. A field is that nonempty token name, colon,
then zero or more ASCII printable characters or horizontal TAB. Leading/trailing
SP/TAB around its value are ignored. Whitespace before colon, folded continuation,
bare LF/CR, non-ASCII/control values, duplicate names after lowercasing, incomplete
lines, more than 64 fields and resource overflow reject. Empty unknown field values
are permitted and discarded. Unknown names/values are not returned or hashed.

There must be exactly one Content-Length with canonical unsigned ASCII decimal
spelling (`0` or a nonzero first digit; at most five digits). It must equal the
declared synthetic-body size and be within the selected body bound. Content-Type
is exactly case-insensitive `text/html`, optionally followed by one `charset=utf-8`
parameter; SP/TAB around semicolon, equals and the parameter is permitted. Quoted
charsets, other parameters/charsets/media types and extra trailing text reject.
Content-Encoding or Transfer-Encoding presence rejects, even identity/empty.
All other fields, including Set-Cookie, Authorization, Location and Server, are
discarded. Their raw values and the complete header-block hash are never retained.

Read exactly Content-Length body bytes, then require EOF. Extra bytes, truncation,
continued keep-alive, reset, unsupported framing and timeout fail. Check exact
expected SHA-256 before output; require strict UTF-8 and no BOM. The worker never
prints a response body unless all admission checks succeed. Mismatched bodies
may contain sensitive content: they stay bounded transient network input and are
discarded, with no exception text or body fragment in any retained channel.
The allowlist does not authorize retrieving a service or accept newly chosen
expected content; actual scope and caller metadata non-secret responsibility remain.

## Version-1 worker record and parent validation

The exact successful flat JSON fields are `schema_version`, `fixture_id`, `url`, `address`,
`port`, `scheme`, `status`, `http_version`, `content_type`, `declared_charset`,
`content_length`, `header_size_bytes`, `header_count`, `body_sha256`, `body_base64`.
Version/status/port/length/counts are actual integers, excluding booleans. Version
is 1, fixture ID is the exact selected closed catalog ID, scheme is `http`, status
is 200, HTTP version is `HTTP/1.0` or `HTTP/1.1`,
content type is `text/html`, declared charset is null or `utf-8`. Header size/count
are measured within the bounds and contain at least the two required fields.
For this 541-byte catalog entry, require `2 <= header_count <= 64` and
`61 + (14 if declared_charset is not null else 0) + 4 * (header_count - 2)
+ max(0, header_count - 53) <= header_size_bytes <= min(16384, 4096 * (header_count + 1) + 2)`.
The lower bound includes the shortest valid status, required fields, final CRLF
and minimum extra token-field lines. Only 51 one-byte field names remain distinct
after case folding, so any extras above 51 require at least one additional byte
each; the two required names have multiple bytes. The upper bound applies every
line budget.
These checks reject logically impossible reports. They do not reconstruct or
authenticate discarded header values. URL,
address and port equal the exact approved canonical destination. Base64 is strict
canonical standard encoding; decoded size/hash equal the explicit declaration.
Preparation accepts only parameters `url`, `timeout_seconds`, `max_body_bytes`
and `fixture_id`, with no credential references. The exact argv is the selected
current interpreter, `-m`, `fuzzy1337.page_capture_worker`, canonical URL, normalized
timeout text, fixture ID, and decimal body limit, in that order. The existing
invocation digest binds all these inputs. Both parent and worker independently
check the closed catalog and bounds before execution/network admission.

The output is sorted compact standards-compliant UTF-8 JSON plus one LF. The
parent requires exact byte equality with that canonical re-encoding for both
successful and fixed failure records; whitespace variants, alternate key order,
extra line endings and equivalent noncanonical encodings reject. No raw
header, reason, original HTML charset text, exception message or unknown field
belongs to this record. The base64 is of already-admitted known non-secret bytes.

A failure record has exactly actual integer `schema_version: 1` and `error` from
`input`, `connection`, `timeout`, `protocol`, `response-policy`, `body-policy`.
Exit is 64 for input, 124 for timeout, 1 for the other errors, and 0 for success.
No stderr is emitted. Input, connection and timeout distinguish local validation,
socket failure and the whole request deadline. Protocol means unsupported/malformed
framing or incomplete/excess body; response-policy means status/media/encoding
refusal; body-policy means declared size/hash mismatch. Parser errors never echo
input-derived response values, including exception causes/context in tracebacks.

The parent checks exact nested typed request/invocation/execution/evidence shapes,
reconstructs the prepared invocation and verifies InvocationDigest, success with
exit 0, finite nonnegative duration and normal process exit. It rejects nonempty
stderr, output overflow, duplicate JSON keys, nonfinite/deep/malformed JSON,
extra/missing fields, unsupported types/versions, mismatched endpoint and any
body/base64/hash/size/UTF-8 inconsistency before evidence publication. Safe fixed
failure output may be retained only with normal process termination and its exact
documented failed state/exit code and finite duration, but cannot
become a page/model observation. Arbitrary malformed output is discarded.

## Evidence, source association and model events

The successful exact stdout record becomes existing `stdout`/`application/json`
evidence. Its exact admitted decoded bytes become `response-body`/`text/html`
evidence. Both share collection workspace/scope/provider, source format version
`1`, worker tool version `1`, aware UTC start/finish, exact invocation SHA and
truthful execution outcome. No implicit environment/arguments are collected.
Actual owner Get and Read validate each full immutable manifest/reference. A
role-specific facade intercepts the actual parsed reference before eager Read
allocation, including Get's internal Read. Expected record equality is required.

The runtime pipeline associates the prepared source request and connected worker
report with those captured bytes. The stdout is an actual worker output artifact
containing derived normalized header metadata; it is not a raw HTTP response
transcript. Discarded response headers/reason are never reconstructed. Retained
hashes/metadata detect consistency;
they are not cryptographic transport or collector authentication. The body
manifest still has no transport URL field. A standalone supplied body retains
ADR 0050's caller-association boundary. Never label a lexical link as acquired.

Pin the full owning ScopeSnapshot used for launch, including its exact revision
and ToDict representation. Call ReadCapturedWebFrontier through its existing
owners/current scope after capture. Require the frontier to bind that same full
snapshot/revision using its existing scope serializer/digest, and independently
require the launch plan's scope digest to match the pinned snapshot using the
existing policy serializer/digest. Do not compare the two digest strings directly:
the policy serializer uses ASCII escaping while the frontier's model serializer
preserves Unicode; valid non-ASCII consent metadata can produce different hashes
for the same snapshot. Retain both hashes with explicit owner roles, without
changing either owner serializer or restricting consent metadata to ASCII.

Reread/check that same full consented snapshot after all evidence reads, model
open/composition and other expensive validation, immediately before owner Save.
Require exact ToDict/revision equality and each respective owning digest, then
recheck exact source-URL/literal-IP membership and current consent/expiry with a
fresh clock reading at that final boundary. No stored earlier check time or launch grant
substitutes for it. A changed,
revoked or expired scope fails; the already admitted artifacts remain inspectable.
No worker already in flight is magically revoked. There is no cross-scope/model
transaction or guarantee against changes after the final snapshot check.

Open the current persisted model once for composition. Find every already-present
source and returned candidate Endpoint object by exact existing identities.
RequestsFromObject plus ProjectRequests union the complete source collection;
ProjectCapturedWebFrontier receives the complete existing candidate collection.
ModelState.Apply uses that source patch and candidate patches together. Preserve
all unrelated attributes and existing templates/provenance; no identity alias with
NativeHTTP exact-URL objects is inferred. Save with the exact prior revision before
publishing MODEL_DELTA. An optimistic conflict fails explicitly, with no overwrite.

One `http.synthetic-page` source Observation is subject to the structural source
Endpoint. Retain normalized HTTP/header metadata, exact body/stdout manifest IDs,
source request/target, closed fixture ID, invocation SHA, launch plan intent, authorization ID,
launch policy scope SHA/revision, policy SHA/revision, and prior model canonical
SHA/revision. Retain the separate frontier scope SHA/revision in its owning role. ModelProvenance
keeps actual provider/worker version, owning job run, source target, both evidence
references, collection finish time and exact execution. Also retain frontier digest,
scope SHA/revision/check time, total/processed anchors, complete/discarded candidate
count and truncation reasons. Existing `web.lexical-link` observations retain their
ADR-0050 source manifest/provenance. Owner-generated object-update history remains.
No findings, relations, Host/Port/Service or pivot/source-host reachability result
is synthesized. Progress `1/1` means the one planned page/interpretation committed.
An explicitly truncated frontier can complete that bounded plan; its measured
partiality remains visible, never web-application coverage or scan completeness.

Evidence survives later lexical, authority, cancellation or persistence failure.
A failure before Save leaves the prior persisted model unchanged and publishes no
model delta. Once owner Save commits, a later cancellation, event-publication
failure or lost acknowledgement can leave the new model and evidence persisted
without a delivered delta. Never claim rollback or rewrite an earlier revision.
An ambiguous Save acknowledgement does not establish that no commit occurred;
report that uncertainty and use owner reopen/verification where available rather
than inventing an atomic cross-store result. The source observation retains the
actual worker execution outcome even if the later owning job fails or is cancelled.
Cancellation uses the existing cooperative signal and governed executor cleanup/
reaping before terminal state. No future request starts. Failures use fixed
JobFailure categories/messages without raw stream/cause text.

## Independent fixture and acceptance

The LF-pinned `tests/contract/fixtures/local-page-capture.v1.html` is independently
written HTML, with ten admitted lexical anchors. Its original response wire is
`local-page-capture.response.v1.http`: CRLF status/headers, LF body, exact byte
Content-Length and EOF. Raw wire is pinned without text conversion. The separate
handwritten `local-page-capture.oracle.v1.json` states expected request/response,
body identity, URL/ordinal/exclusion rules and model counts; it is never derived
from the new producer or modified to match observed behavior.

Use source `/docs/index`, explicit source/IP/alpha/docs-next/zeta scope membership,
and explicitly excluded registered `/blocked`. The expected frontier is `/alpha`
at ordinals 1/2, `/docs/next` at 3, `/zeta` at 9. Six exclusions are fragment-only,
scope.excluded, query, off-origin, source-target and missing-href, one each. Comment
and script anchors are absent. The only actual server request is `/docs/index`;
Location, eligible links and excluded URLs are never fetched. From an empty model,
one save creates four structural Endpoints, three lexical observations, one source
response observation and four owning object-update observations; zero relations,
findings, Host/Port/Service objects. Scope revision/identity and real times/ports
remain runtime bindings, not invented fixture constants.

Acceptance includes the exact original wire/body/oracle plus strict boundary and
failure variants: header/body +/-1, max count, duplicate/folded/non-ASCII headers,
malformed status/length/media/encoding, early EOF/extra byte/keep-alive/slow progress,
wrong SHA/same-length changed body, unexpected synthetic secret markers, valid
Unicode consent authority/reference metadata with distinct owner digests but an
unchanged pinned scope snapshot, changed scope metadata/revision, invalid UTF-8/BOM, IPv6 if the runner can own it, denial at grant/final launch, postcapture
scope change, corrupt/missing/oversized actual evidence, copied wrappers, stderr/
invalid execution, storage conflict, timeout/cancellation and retained artifacts.
Test full template preservation, save/reopen, exact projection replay, event order,
one-connection containment and no unknown bytes in stdout/stderr/model/evidence/
messages/tracebacks. Unit tests have no network; integration fixtures own listeners,
finite readiness and teardown. No browser, Internet target, download or new dependency.

Implementation may add only these three modules, the owned record JSON schema,
subsystem unit/contract/integration fixtures/tests, this ADR/profile, scoped fixture
checkout rules and additive API/locale/compatibility inventories. NativeHTTP v1,
captured_web, SDK/job/policy/model/scope/evidence owners, CLI/registry/shell, protected
files and CHANGELOG remain unchanged. Canonical full gates and independent final
source review are required; #59/#53 stay open for the explicitly absent larger work.
