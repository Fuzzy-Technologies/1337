# Captured web frontiers

This proposed Experimental profile advances #59/#53 with an offline consumer of
explicit static HTML. It is not an HTTP client, async crawler or browser executor.
The accepted native HTTP version-1 evidence cannot supply this input because it
contains no response body. No source code or rules are ported from another engine.

## Proposed API and ownership

`CAPTURED_WEB_PROFILE_VERSION = 1` and `CapturedWebLimits` are Experimental.
Two functions form the proposed producer/consumer boundary:

- `ReadCapturedWebFrontier(workspace_root, source, capture, scope_id, *, at,
  limits=CapturedWebLimits())` returns an immutable frontier. It reads only the
  existing workspace metadata, one current persisted scope, and the explicit
  evidence manifest/blob. It does not write, discover files or consult a clock.
- `ProjectCapturedWebFrontier(frontier, *, existing=())` returns immutable
  `object_patches` and `observations` for existing `ModelState.Apply`. `existing`
  is an explicit tuple of at most 256 current Endpoint objects, covering only
  frontier endpoint identities. Omission means no existing templates. It is pure
  and neither loads nor saves model state.

The caller supplies every already-existing object for a returned Endpoint before
applying its complete request-collection patch. The empty default is appropriate
for new endpoints only; this pure projection cannot discover an omitted current
object. Persistence and expected-revision conflict checks remain with the model
owner, as with existing ProjectRequests.

Result records are readable immutable Experimental output shapes, not separate
serialization/persistence formats or authority tokens. Direct constructors and
all parsing/integrity helpers are Internal. Consistency digests must validate
exact nested record/enum/tuple shapes before hashing; string/enum equality is not
enough. A running Python caller can construct data: hashing does not authenticate
an actor or isolate code in the same process.

The frontier retains `profile_version`, exact source `RequestTemplate`, concrete
source `Target`, full actual `EvidenceRecord`, scope reference/revision/full
canonical snapshot SHA-256, UTC `checked_at`, effective limits, ordered `entries`,
`anchor_count`, `processed_anchors`, fixed `exclusion_counts`, `complete`,
`discarded_candidates`, `truncation_reasons`, and a recomputed `frontier_digest`
over all those fields.
Each entry retains its exact `Target`, anonymous concrete GET `RequestTemplate`,
the exact allowed `ScopeDecision`, and an increasing tuple of source anchor
ordinals. There is no numeric confidence, network outcome or vulnerability state.

## Source and evidence admission

`source` must be a typed existing RequestTemplate with method GET, no injection
points, body kind `none`, no session reference and no GraphQL operation. Its
concrete path contains no variables, queries, fragments or encoded path bytes.
The source URL is exactly endpoint origin plus path, canonicalized using the
existing Target owner. Its request and Endpoint references are retained.

`capture` must be a typed schema-v1 EvidenceRecord with role `response-body`,
media type exactly `text/html`, and raw size at most 262144 bytes. The profile
interprets these bytes as strict UTF-8; it has no charset sniffing, BOM override,
decompression, multipart handling, status/header inference or raw HTTP/HAR parser.
A leading UTF-8 BOM is unsupported. The source/capture association is explicitly
supplied because the evidence manifest itself carries no requested URL.

The opened workspace, source endpoint, capture provenance and opened scope must
share the same workspace ID; the capture scope reference must match exactly.
Retain source ID, source version, optional tool version, start/finish times,
optional invocation digest and exact execution outcome. Format version and tool
version are distinct fields; no join equates them. Metadata text is at most 256
UTF-8 bytes per field. Direct caller records must be bounded and structurally
validated before any full manifest serialization or nested reference computation.

Collection start must be no later than finish; both must be no later than `at`.
Historical captures are allowed and remain historical, without a freshness claim.
When execution is supplied it must be the exact SUCCEEDED enum, exit code zero,
finite nonnegative duration, and have an invocation digest. When execution is
absent an optional digest remains attribution only. Neither case proves transport
truth or invocation authorization. Failed/cancelled/timed-out captures refuse.

Call actual owning `Get(capture.evidence_id)` and require the entire parsed record
to equal the bounded supplied record. A small internal LocalEvidenceStore Read
facade rejects the actual parsed reference size above 262144 before delegating
to the allocating owner Read; a forged small caller size cannot bypass it.
Get retains manifest grammar, immutable identity and raw-byte verification.
The consumer can read the verified raw blob again through that same facade.
The owner already bounds manifests at 1 MiB. No locator is loaded directly.
Missing, corrupt, unsafe or unsupported manifests/blobs remain sanitized
EvidenceError subclasses; source parsing/admission errors use sanitized ValueError.
Normal exception tracebacks must not echo raw source, hrefs or private metadata.

## Static lexical markup profile

The whole admitted artifact is examined before candidate URI work. The bounded
scanner recognizes complete start/end tokens, quoted attribute values, comments
and `<!DOCTYPE html>` (ASCII case-insensitive). Other declarations, processing
instructions, unterminated tokens/comments/quotes and a markup token exceeding
4096 UTF-8 bytes refuse the artifact. Text outside tokens is ignored. A literal
less-than sign that starts unsupported markup refuses rather than guessing a DOM.
No DTD, entity declaration, custom resource or external reference is loaded.

Script/style raw text is skipped through its complete ASCII case-insensitive
closing tag before scanning ordinary markup again; a missing closing tag refuses.
Raw-text contents are subject to the whole-body byte limit, not the markup-token
limit, and embedded tag-like strings are neither tokens nor anchor callbacks.
The opening/closing tags still consume token work. This rule prevents a lexical
preflight from mistaking JavaScript string contents for actual tags.

Use Python HTMLParser with character-reference conversion and its ordinary
script/style handling. Decode attribute character references exactly once.
Every start/start-end tag has at most 64 attributes and unique case-normalized
attribute names; duplicates refuse, including duplicate href spellings.
Any parsed `base` tag refuses even without an href. A base-like string inside
script/style text or a comment is not a parsed tag. Tags need not form a balanced
DOM tree; implicit closing, visibility, user interaction and JavaScript-generated
links are outside the profile. Source markup in an inactive template can produce
lexical candidates and must never be described as a rendered browser link.

Only `<a>` start/start-end callbacks count as anchors. Anchor ordinals are
one-based in source callback order, including anchors with missing/empty href.
Comments and script/style text do not contribute anchor ordinals. Ignore all
other source text/attributes after bounded validation. No label text or source
href is retained in normalized output.

Hard source admission limits are inclusive:

| Resource                   | Maximum          | Exceeding the limit |
| -------------------------- | ---------------- | ------------------- |
| Actual body bytes          | 262144 (256 KiB) | ValueError          |
| Markup token bytes         | 4096             | ValueError          |
| Complete markup tokens     | 8192             | ValueError          |
| Attributes per start tag   | 64               | ValueError          |
| Source anchor callbacks    | 1024             | ValueError          |
| Decoded href UTF-8 bytes   | 2048             | Count invalid-url   |
| Metadata field UTF-8 bytes | 256              | ValueError          |

The source scanner is linear in the admitted byte/character count and stops hard
overflow before feeding an oversized token to the attribute parser. This bounds
consumer copies/work, not already allocated caller memory or an OS sandbox.

## URI resolution and exact scope

Process admitted anchors in ordinal order. Select one exclusion category per
processed anchor in this exact priority:

1. `missing-href`: absent, valueless or empty href.
2. `invalid-url`: oversized href, UTF-8 failure, literal whitespace/control,
   backslash, or malformed URL/address/escape syntax. Reject before URI resolution
   any literal whitespace/control or backslash; do not trim or sanitize it.
3. `fragment-only`: href begins with `#`; fragment content is discarded.
4. `non-http`: an explicit parsed scheme other than HTTP or HTTPS.
5. `credentials`: parsed username/password is present before or after resolution.
6. `query`: a literal question mark anywhere before the fragment, even an empty
   query delimiter. Query values/names never become templates or output text.
7. `off-origin`: the canonical resolved origin differs from the source origin.
8. `unsupported-path`: the canonical concrete path cannot be represented by the
   existing structural Endpoint, including percent-encoded bytes and braces.
9. `source-target`: the canonical target equals the source target.
10. `scope.<reason>`: existing Scope.Check denies the exact candidate.

After the preliminary checks, remove a nonempty fragment and resolve using
standard-library `urllib.parse.urljoin(source_target.value, href)`, then validate
the resulting exact Target. Relative dot segments resolve through urljoin; no
path value is substituted. Target owns scheme, IDNA/literal host, default-port
and percent-spelling normalization and rejects ambiguous separators/credentials.
Relative and network-path references are allowed only if their final canonical
origin matches the source. Default ports compare after Target normalization;
HTTP/HTTPS or nondefault port changes are different origins. There is no DNS.

Percent-encoded query/fragment/control/authority characters are never decoded as
new URI delimiters by this consumer. A percent-bearing concrete path is excluded
as unsupported-path; escaped separators and malformed addressing can instead
fail earlier as invalid-url. HTML character references are decoded before these
checks, so encoded `?`, controls or credentials cannot bypass admission.

The source must pass the opened scope's Check at the explicit aware `at`, otherwise
raise sanitized PermissionError with its fixed ScopeDecisionReason. Every other
qualifying exact candidate is checked separately; same origin does not grant a
path permission. Do not persist candidates denied by scope, and do not retain
their URL, template or target reference in results. Full scope identity is SHA-256
over its owning compact canonical ToDict serialization, not revision alone.
This single current read does not cover changes after preparation or authorize
DNS results, redirects, method/impact permission, sessions or actual traffic.

## Deterministic frontier and truncation

`CapturedWebLimits.max_anchor_work` defaults to 1024 and is an exact integer from
1 through 1024. `max_candidates` defaults to 64 and is an exact integer from
1 through 256. Booleans, coercion, negative/zero values and unknown fields refuse.
Hard source lexical admission is always complete before applying these soft
limits, including base-tag validation. Every processed anchor consumes one work
unit, including missing, rejected and duplicate anchors.

Group allowed candidates by exact canonical target identity and retain every
processed anchor ordinal for that identity. Sort entries by canonical target URL
then request reference. Keep the first `max_candidates` entries after grouping;
the deterministic selection does not depend on hash iteration order. If source
anchors remain unprocessed, add `anchor-work-limit`; if eligible unique entries
are omitted, add `candidate-limit`. Exact exhaustion without any omitted work
or candidate is complete. Both reasons may coexist, sorted lexicographically.
Exclusion counts cover processed anchors only; ordinal tuples cover returned
candidates only. The number of discarded eligible unique entries is retained
as a fixed count, without their identities. Source anchor count covers all
admitted lexical anchors, including the unprocessed suffix.

`complete` is true only when no work/candidate was omitted. An empty frontier is
never a claim that the website has no links/endpoints: it covers only this artifact,
lexical subset, same-origin/query-free profile and exact supplied scope. There is
no recursive traversal, persistent queue, background task or cancellation token.
One synchronous bounded invocation either returns a complete/explicit partial
record or refuses atomically. A future scheduler may cancel between invocations;
this slice makes no runtime-cancellation or async responsiveness promise.

## Existing model projection

Validate the complete retained frontier before projecting, including exact nested
types, source/capture/reference/digest bindings, counts, ordinals, allowed decisions
and limits. Existing objects must be distinct typed Endpoint objects for returned
candidate identities, in the same workspace, and at most 256. Reopen each object's
entire request collection with RequestsFromObject, preserve all distinct existing
templates, add the discovered anonymous template, and call ProjectRequests on the
complete collection. Existing owner attribute/serialized-size limits still apply;
projection overflow refuses rather than dropping existing templates. Unrelated
attributes remain preserved when the caller applies the patch.

Each source attribution uses ModelProvenance with original source_id, manifest
evidence_id as run_reference, original finished_at as observed_at, original scope
reference, declared source Target reference, original tool_version as
provider_version, the exact raw EvidenceReference and exact optional execution.
Do not invent a successful browser/network execution or use the candidate target
as the capture's acquisition target. Source format version is pinned by the full
manifest identity and explicitly retained on the link observation.

One `web.lexical-link` observation per returned candidate records profile version,
parser ID `web.captured-html`, source request/Endpoint/Target references, capture
manifest ID, source format version, frontier digest, exact scope digest/revision,
checked_at, candidate request/Target references and source ordinals. Its subject is
the candidate's existing structural Endpoint identity. These are source-derived
link descriptions, not observed HTTP-response, open-port or vulnerability facts.
Do not create relationships implying connectivity, findings or reachability claims.

The caller owns ModelState.Apply and expected-revision LocalModelStore.Save. Exact
projection replay is idempotent; repeated different captures retain distinct
observations/attribution. The structural request identity and the native sensor's
exact-URL Endpoint natural key are existing distinct representations; this consumer
does not silently merge or alias them. No new truth store/schema is introduced.

## Handwritten oracle and acceptance

The static source is `tests/contract/fixtures/captured-web.v1.html`; the independent
expected URL/count/ordinal/truncation oracle is `captured-web.oracle.v1.json` in
the same directory. All declarations use owned synthetic loopback literals and
are never fetched. The source intentionally distinguishes lexical template content
from ignored script/comment strings and uses relative, duplicate, denied and
unsafe links. Additional independent tests cover default-port origin equivalence,
both soft limits, hard limits, duplicate/malformed tokens, late base tags, source
bindings, collection outcomes/times, hostile UTF-8, copied wrappers and corruption.

Create an actual existing workspace/scope/evidence store; put exact synthetic HTML,
load through this consumer, compose complete existing request templates, save and
reopen the model, inspect attributed link observations and replay. Tripwire socket,
subprocess and writes during read/preparation/projection. Refused actual artifacts
must not reach allocating Read, including a forged small caller reference.
No local web server, browser, real target or raw secret is needed. Full locked
checks and independent review are required after implementation, not claimed for
this design-only checkpoint. #59/#53 remain open for their broader acceptance.

The two owned fixture files have explicit LF checkout attributes; exact evidence
bytes and their content identities must not change under Windows checkout settings.
